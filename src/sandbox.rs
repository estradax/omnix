//! QuickJS sandbox. No network/fs/env: the only host access is `__call` (proxied MCP
//! calls, credentials attached host-side) and `__log`, both captured in a prelude
//! closure and deleted from the global scope. A `state` object persists across runs
//! within a session. Any timeout/interrupt rebuilds the whole runtime.

// rquickjs deprecated `async_with!` in favour of `AsyncContext::async_with`; migrating is
// mechanical but pending, and the macro is still fully supported.
#![allow(deprecated)]

use rquickjs::{
    AsyncContext, AsyncRuntime, CatchResultExt, Function, Promise, async_with, function::Async,
};
use serde_json::Value;
use std::{
    collections::HashSet,
    future::Future,
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

pub type HostFuture = Pin<Box<dyn Future<Output = Result<Value, String>> + Send>>;
/// (server, tool, args) -> result
pub type HostCall = Arc<dyn Fn(String, String, Value) -> HostFuture + Send + Sync>;

#[derive(Clone)]
pub struct Limits {
    pub timeout: Duration,
    pub max_calls: usize,
    pub max_code_bytes: usize,
    pub memory_bytes: usize,
    pub max_result_bytes: usize,
    pub max_log_entries: usize,
    pub max_log_bytes: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            timeout: Duration::from_secs(30),
            max_calls: 200,
            max_code_bytes: 64 * 1024,
            memory_bytes: 64 * 1024 * 1024,
            max_result_bytes: 32 * 1024,
            max_log_entries: 1000,
            max_log_bytes: 64 * 1024,
        }
    }
}

#[derive(Debug, Default)]
pub struct RunOutput {
    pub result: Option<String>,
    pub logs: Vec<String>,
    pub calls: Vec<String>,
    pub error: Option<String>,
    /// True when the session was rebuilt (timeout/interrupt); `state` is lost.
    pub reset: bool,
}

#[derive(Default)]
struct RunState {
    logs: Vec<String>,
    log_bytes: usize,
    log_dropped: bool,
    calls: Vec<String>,
    n_calls: usize,
}

struct Inner {
    // Kept alive for the lifetime of the context.
    _rt: AsyncRuntime,
    ctx: AsyncContext,
}

pub struct Session {
    inner: Inner,
    host: HostCall,
    servers: Vec<String>,
    limits: Limits,
    run_state: Arc<Mutex<RunState>>,
    deadline: Arc<Mutex<Option<Instant>>>,
    expired: Arc<AtomicBool>,
}

const PRELUDE: &str = r#"
(() => {
  const call = globalThis.__call, log = globalThis.__log;
  const J = JSON.stringify, P = JSON.parse, S = String, Px = Proxy, DP = Object.defineProperty;
  const AF = Object.getPrototypeOf(async function () {}).constructor;
  const def = (k, v) => DP(globalThis, k, { value: v, writable: false, configurable: false, enumerable: true });
  const fmt = (a) => a.map(x => typeof x === 'string' ? x : (() => { try { return J(x); } catch { return S(x); } })()).join(' ');
  def('state', {});
  def('console', Object.freeze({
    log: (...a) => log('log', fmt(a)), info: (...a) => log('info', fmt(a)),
    warn: (...a) => log('warn', fmt(a)), error: (...a) => log('error', fmt(a)),
  }));
  for (const server of __SERVERS__) {
    if (server in globalThis) continue;
    def(server, new Px({}, {
      get: (_, tool) => async (args) => {
        const r = P(await call(server, S(tool), J(args ?? {})));
        if (r.error !== undefined) throw new Error(r.error);
        return r.ok;
      }
    }));
  }
  delete globalThis.__call;
  delete globalThis.__log;
  DP(globalThis, '__run', { value: (code) => new AF(code)().then(v => v === undefined ? undefined : J(v)),
    writable: false, configurable: false, enumerable: false });
})()
"#;

fn trunc_str(s: &str, max: usize) -> &str {
    if s.len() <= max {
        return s;
    }
    let mut cut = max;
    while !s.is_char_boundary(cut) {
        cut -= 1;
    }
    &s[..cut]
}

impl Session {
    pub async fn new(
        servers: Vec<String>,
        host: HostCall,
        limits: Limits,
    ) -> anyhow::Result<Session> {
        let run_state = Arc::new(Mutex::new(RunState::default()));
        let deadline = Arc::new(Mutex::new(None));
        let expired = Arc::new(AtomicBool::new(false));
        let inner = Self::build(&servers, &host, &limits, &run_state, &deadline, &expired).await?;
        Ok(Session {
            inner,
            host,
            servers,
            limits,
            run_state,
            deadline,
            expired,
        })
    }

    async fn build(
        servers: &[String],
        host: &HostCall,
        limits: &Limits,
        run_state: &Arc<Mutex<RunState>>,
        deadline: &Arc<Mutex<Option<Instant>>>,
        expired: &Arc<AtomicBool>,
    ) -> anyhow::Result<Inner> {
        let rt = AsyncRuntime::new()?;
        rt.set_memory_limit(limits.memory_bytes).await;
        rt.set_max_stack_size(512 * 1024).await;
        {
            let (d, e) = (deadline.clone(), expired.clone());
            rt.set_interrupt_handler(Some(Box::new(move || {
                let over = d.lock().unwrap().is_some_and(|t| Instant::now() > t);
                if over {
                    e.store(true, Ordering::SeqCst);
                }
                over
            })))
            .await;
        }
        let ctx = AsyncContext::full(&rt).await?;
        let allowed: Arc<HashSet<String>> = Arc::new(servers.iter().cloned().collect());
        let prelude = PRELUDE.replace("__SERVERS__", &serde_json::to_string(servers)?);
        let (host, rs, limits) = (host.clone(), run_state.clone(), limits.clone());

        async_with!(ctx => |ctx| {
            let g = ctx.globals();
            let rs_log = rs.clone();
            let lim = limits.clone();
            g.set("__log", Function::new(ctx.clone(), move |lvl: String, msg: String| {
                let mut st = rs_log.lock().unwrap();
                let msg = trunc_str(&msg, 4096);
                if st.logs.len() >= lim.max_log_entries || st.log_bytes + msg.len() > lim.max_log_bytes {
                    st.log_dropped = true;
                    return;
                }
                st.log_bytes += msg.len();
                st.logs.push(if lvl == "log" { msg.to_string() } else { format!("[{lvl}] {msg}") });
            })?)?;
            let max_calls = limits.max_calls;
            g.set("__call", Function::new(ctx.clone(), Async(move |server: String, tool: String, args: String| {
                let (host, rs, allowed) = (host.clone(), rs.clone(), allowed.clone());
                async move {
                    let fail = |m: String| Ok::<String, rquickjs::Error>(serde_json::json!({"error": m}).to_string());
                    if !allowed.contains(&server) {
                        return fail(format!("unknown server {server}"));
                    }
                    {
                        let mut st = rs.lock().unwrap();
                        if st.n_calls >= max_calls {
                            return fail(format!("call limit ({max_calls}) exceeded"));
                        }
                        st.n_calls += 1;
                        st.calls.push(format!("{server}.{tool}"));
                    }
                    let args: Value = serde_json::from_str(&args).unwrap_or(Value::Null);
                    Ok(match host(server, tool, args).await {
                        Ok(v) => serde_json::json!({"ok": v}).to_string(),
                        Err(e) => serde_json::json!({"error": e}).to_string(),
                    })
                }
            }))?)?;
            ctx.eval::<(), _>(prelude).catch(&ctx).map_err(|e| anyhow::anyhow!("{e}"))?;
            Ok::<_, anyhow::Error>(())
        })
        .await?;
        Ok(Inner { _rt: rt, ctx })
    }

    async fn rebuild(&mut self) {
        *self.deadline.lock().unwrap() = None;
        match Self::build(
            &self.servers,
            &self.host,
            &self.limits,
            &self.run_state,
            &self.deadline,
            &self.expired,
        )
        .await
        {
            Ok(i) => self.inner = i,
            Err(e) => eprintln!("omnix: sandbox rebuild failed: {e:#}"),
        }
        self.expired.store(false, Ordering::SeqCst);
    }

    pub async fn run(&mut self, code: &str) -> RunOutput {
        let mut out = RunOutput::default();
        if code.len() > self.limits.max_code_bytes {
            out.error = Some(format!("code exceeds {} bytes", self.limits.max_code_bytes));
            return out;
        }
        *self.run_state.lock().unwrap() = RunState::default();
        self.expired.store(false, Ordering::SeqCst);
        *self.deadline.lock().unwrap() = Some(Instant::now() + self.limits.timeout);
        let max_result = self.limits.max_result_bytes;
        let code_owned = code.to_string();

        let fut = async_with!(self.inner.ctx => |ctx| {
            let f: Function = ctx.globals().get("__run")?;
            let r: rquickjs::Result<Option<String>> = match f.call::<_, Promise>((code_owned,)) {
                Ok(p) => p.into_future().await,
                Err(e) => Err(e),
            };
            Ok::<_, rquickjs::Error>(r.catch(&ctx).map_err(|e| e.to_string()))
        });

        let res = tokio::time::timeout(self.limits.timeout, fut).await;
        *self.deadline.lock().unwrap() = None;
        {
            let mut st = self.run_state.lock().unwrap();
            out.logs = std::mem::take(&mut st.logs);
            if st.log_dropped {
                out.logs.push("[console output truncated]".into());
            }
            out.calls = std::mem::take(&mut st.calls);
        }
        let interrupted = self.expired.load(Ordering::SeqCst);
        match res {
            Err(_) => out.error = Some("timeout: session reset, `state` lost".into()),
            Ok(_) if interrupted => out.error = Some("timeout: session reset, `state` lost".into()),
            Ok(Err(e)) => out.error = Some(e.to_string()),
            Ok(Ok(Err(e))) => out.error = Some(e),
            Ok(Ok(Ok(v))) => out.result = v.map(|s| truncate(s, max_result)),
        }
        if res_is_timeout(&out) {
            out.reset = true;
            self.rebuild().await;
        }
        out
    }
}

fn res_is_timeout(o: &RunOutput) -> bool {
    o.error
        .as_deref()
        .is_some_and(|e| e.starts_with("timeout:"))
}

fn truncate(mut s: String, max: usize) -> String {
    if s.len() > max {
        let total = s.len();
        let cut = trunc_str(&s, max).len();
        s.truncate(cut);
        s.push_str(&format!("\n...[truncated, {total} bytes total]"));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    fn host() -> HostCall {
        Arc::new(|s, t, a| {
            Box::pin(async move {
                if t == "fail" {
                    return Err("boom".into());
                }
                Ok(serde_json::json!({"server": s, "tool": t, "args": a}))
            })
        })
    }

    async fn sess(l: Limits) -> Session {
        Session::new(vec!["srv".into()], host(), l).await.unwrap()
    }

    #[tokio::test]
    async fn basic_and_state_persist() {
        let mut s = sess(Limits::default()).await;
        let o = s.run("state.n = 41; return state.n + 1").await;
        assert_eq!(o.result.as_deref(), Some("42"), "{o:?}");
        let o = s.run("return state.n").await;
        assert_eq!(o.result.as_deref(), Some("41"));
    }

    #[tokio::test]
    async fn host_call_and_logs() {
        let mut s = sess(Limits::default()).await;
        let o = s
            .run("console.log('hi', 1); const r = await srv.thing({x: 1}); return r.args.x")
            .await;
        assert_eq!(o.result.as_deref(), Some("1"), "{o:?}");
        assert_eq!(o.logs, ["hi 1"]);
        assert_eq!(o.calls, ["srv.thing"]);
        let o = s
            .run("try { await srv.fail({}) } catch (e) { return e.message }")
            .await;
        assert_eq!(o.result.as_deref(), Some("\"boom\""));
    }

    #[tokio::test]
    async fn no_ambient_authority() {
        let mut s = sess(Limits::default()).await;
        let o = s.run("return [typeof fetch, typeof process, typeof require, typeof XMLHttpRequest, typeof std, typeof os, typeof WebSocket].join()").await;
        assert_eq!(
            o.result.as_deref(),
            Some("\"undefined,undefined,undefined,undefined,undefined,undefined,undefined\""),
            "{o:?}"
        );
    }

    #[tokio::test]
    async fn infinite_loop_times_out_and_resets() {
        let mut s = sess(Limits {
            timeout: Duration::from_millis(200),
            ..Default::default()
        })
        .await;
        let o = s.run("while(true){}").await;
        assert!(o.reset, "{o:?}");
    }

    #[tokio::test]
    async fn limits() {
        let mut s = sess(Limits {
            max_calls: 2,
            max_result_bytes: 10,
            memory_bytes: 4 << 20,
            ..Default::default()
        })
        .await;
        let o = s.run("await srv.a(); await srv.a(); await srv.a()").await;
        assert!(
            o.error.as_deref().unwrap_or("").contains("call limit"),
            "{o:?}"
        );
        let o = s.run("return 'x'.repeat(100)").await;
        assert!(o.result.unwrap().contains("truncated"));
        let o = s
            .run("const a=[]; while(true) a.push('x'.repeat(100000))")
            .await;
        assert!(o.error.is_some(), "{o:?}");
    }
}
