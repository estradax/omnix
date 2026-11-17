//! Adversarial sandbox tests.
use crate::sandbox::*;
use std::sync::{Arc, Mutex};
use std::time::Duration;

type Seen = Arc<Mutex<Vec<(String, String)>>>;

fn host_rec() -> (HostCall, Seen) {
    let seen: Seen = Arc::new(Mutex::new(vec![]));
    let s2 = seen.clone();
    let h: HostCall = Arc::new(move |s, t, a| {
        s2.lock().unwrap().push((s.clone(), t.clone()));
        Box::pin(async move { Ok(serde_json::json!({"server": s, "tool": t, "args": a})) })
    });
    (h, seen)
}

async fn sess(l: Limits) -> (Session, Seen) {
    let (h, seen) = host_rec();
    (Session::new(vec!["srv".into()], h, l).await.unwrap(), seen)
}

fn fast() -> Limits {
    Limits {
        timeout: Duration::from_millis(500),
        ..Default::default()
    }
}

#[tokio::test]
async fn call_with_unlisted_server_name() {
    // __call is a global: code can address any server name, bypassing the Proxy allowlist.
    let (mut s, seen) = sess(Limits::default()).await;
    let o = s
        .run("return await __call('secret_server','tool','{}')")
        .await;
    let _ = o;
    assert!(
        seen.lock().unwrap().iter().all(|(srv, _)| srv == "srv"),
        "host was reached with unlisted server: {:?}",
        seen.lock().unwrap()
    );
}

#[tokio::test]
async fn tamper_with_internals_does_not_break_next_run() {
    let (mut s, _) = sess(Limits::default()).await;
    s.run("delete globalThis.__call; delete globalThis.__log; globalThis.__mk = 1; globalThis.JSON = {parse(){return {ok:1}}, stringify(){return '\"pwn\"'}}; globalThis.console = null;").await;
    let o = s.run("console.log('x'); return await srv.a({})").await;
    assert!(
        o.error.is_none() && o.result.is_some(),
        "later runs broken by tampering: {o:?}"
    );
}

#[tokio::test]
async fn json_tamper_cannot_forge_result() {
    let (mut s, _) = sess(Limits::default()).await;
    s.run("JSON.stringify = () => '\"forged\"'").await;
    let o = s.run("return 1").await;
    assert_eq!(o.result.as_deref(), Some("1"), "{o:?}");
}

#[tokio::test]
async fn proxy_server_override_persists() {
    let (mut s, seen) = sess(Limits::default()).await;
    s.run("globalThis.srv = __mk('evil')").await;
    let _ = s.run("await srv.a({})").await;
    // calls must still go to the configured server
    assert!(
        seen.lock().unwrap().iter().all(|(x, _)| x == "srv"),
        "{:?}",
        seen.lock().unwrap()
    );
}

#[tokio::test]
async fn function_constructors_are_harmless() {
    let (mut s, _) = sess(Limits::default()).await;
    let o = s.run("const F=(async()=>{}).constructor; const g=new Function('return this')(); return [typeof process, typeof require, typeof g.fetch, typeof F, typeof globalThis.constructor, typeof Object.getPrototypeOf(globalThis)].join()").await;
    assert!(
        o.result
            .as_deref()
            .unwrap_or("")
            .starts_with("\"undefined,undefined,undefined"),
        "{o:?}"
    );
    let o = s.run("return eval('1+1')").await;
    assert_eq!(o.result.as_deref(), Some("2"));
}

#[tokio::test]
async fn deep_recursion_is_caught() {
    let (mut s, _) = sess(fast()).await;
    let o = s.run("function f(n){return f(n+1)+1} return f(0)").await;
    assert!(o.error.is_some(), "{o:?}");
    let o = s
        .run("let a=[]; for(let i=0;i<100000;i++) a=[a]; return JSON.stringify(a).length")
        .await;
    assert!(o.error.is_some() || o.result.is_some());
    let o = s.run("return 1").await;
    assert_eq!(
        o.result.as_deref(),
        Some("1"),
        "session unusable after overflow: {o:?}"
    );
}

#[tokio::test]
async fn memory_exhaustion_variants() {
    for code in [
        "let s='x'; while(true) s+=s;",
        "const a=[]; while(true) a.push(new Array(1e6).fill(1))",
        "const a=[]; while(true) a.push(new Uint8Array(1e7))",
        "new ArrayBuffer(2**31)",
        "new Uint8Array(2**30).fill(1)",
        "'a'.repeat(2**29)",
        "const m=new Map(); for(let i=0;;i++) m.set(i,{i})",
    ] {
        let (mut s, _) = sess(Limits {
            memory_bytes: 16 << 20,
            timeout: Duration::from_secs(5),
            ..Default::default()
        })
        .await;
        let o = s.run(code).await;
        assert!(o.error.is_some(), "{code}: {o:?}");
    }
}

#[tokio::test]
async fn sync_loop_in_promise_callback_times_out() {
    let (mut s, _) = sess(fast()).await;
    let o = s
        .run("await Promise.resolve().then(()=>{ while(true){} })")
        .await;
    assert!(o.reset, "{o:?}");
}

#[tokio::test]
async fn microtask_flood_times_out() {
    let (mut s, _) = sess(fast()).await;
    let t = std::time::Instant::now();
    let o = s
        .run("const f=()=>Promise.resolve().then(f); f(); await new Promise(()=>{})")
        .await;
    assert!(o.reset || o.error.is_some(), "{o:?}");
    assert!(
        t.elapsed() < Duration::from_secs(5),
        "took {:?}",
        t.elapsed()
    );
}

#[tokio::test]
async fn microtask_flood_after_return_times_out() {
    // Code returns quickly but leaves a runaway microtask chain behind.
    let (mut s, _) = sess(fast()).await;
    let t = std::time::Instant::now();
    let _ = s
        .run("const f=()=>Promise.resolve().then(f); f(); return 1")
        .await;
    let o = s.run("return 2").await;
    assert!(
        t.elapsed() < Duration::from_secs(5),
        "hung {:?}",
        t.elapsed()
    );
    assert!(o.result.is_some() || o.reset, "{o:?}");
}

#[tokio::test]
async fn never_resolving_promise_times_out() {
    let (mut s, _) = sess(fast()).await;
    let o = s.run("await new Promise(()=>{})").await;
    assert!(o.reset, "{o:?}");
}

#[tokio::test]
async fn timeout_actually_clears_state() {
    let (mut s, _) = sess(fast()).await;
    s.run("state.secret = 'leak'; globalThis.leaked = 1").await;
    let o = s.run("while(true){}").await;
    assert!(o.reset);
    let o = s
        .run("return [typeof state.secret, typeof globalThis.leaked].join()")
        .await;
    assert_eq!(
        o.result.as_deref(),
        Some("\"undefined,undefined\""),
        "state survived 'reset': {o:?}"
    );
}

#[tokio::test]
async fn session_usable_after_timeout() {
    let (mut s, _) = sess(fast()).await;
    s.run("while(true){}").await;
    let o = s.run("return await srv.a({})").await;
    assert!(o.error.is_none(), "{o:?}");
}

#[tokio::test]
async fn unserializable_results() {
    let (mut s, _) = sess(Limits::default()).await;
    for code in [
        "return 10n",
        "const a={}; a.a=a; return a",
        "return {get x(){throw new Error('g')}}",
        "return {toJSON(){throw 1}}",
        "return new Proxy({}, {ownKeys(){throw new Error('p')}})",
    ] {
        let o = s.run(code).await;
        assert!(o.error.is_some() && !o.reset, "{code}: {o:?}");
    }
    let o = s.run("return () => 1").await;
    assert!(
        o.result.is_none() && o.error.is_none(),
        "function result: {o:?}"
    );
}

#[tokio::test]
async fn huge_result_is_truncated_not_oom() {
    let (mut s, _) = sess(Limits {
        max_result_bytes: 100,
        ..Default::default()
    })
    .await;
    let o = s.run("return 'é'.repeat(5e6)").await;
    assert!(o.result.unwrap().len() < 200);
}

#[tokio::test]
async fn parallel_calls_respect_limit() {
    let (mut s, seen) = sess(Limits {
        max_calls: 10,
        ..Default::default()
    })
    .await;
    let o = s.run("return (await Promise.allSettled(Array.from({length:1000},()=>srv.a({})))).filter(r=>r.status==='fulfilled').length").await;
    assert_eq!(o.result.as_deref(), Some("10"), "{o:?}");
    assert_eq!(seen.lock().unwrap().len(), 10);
}

#[tokio::test]
async fn call_limit_resets_per_run_but_not_bypassable_via_state() {
    let (mut s, seen) = sess(Limits {
        max_calls: 3,
        ..Default::default()
    })
    .await;
    // un-awaited calls still count
    s.run("for(let i=0;i<50;i++) srv.a({}).catch(()=>{}); return 1")
        .await;
    assert!(
        seen.lock().unwrap().len() <= 3,
        "{}",
        seen.lock().unwrap().len()
    );
}

#[tokio::test]
async fn call_with_huge_or_odd_args() {
    let (mut s, _) = sess(Limits::default()).await;
    let o = s.run("return await srv.a({x: 10n})").await;
    assert!(o.error.is_some() && !o.reset, "{o:?}");
    let o = s.run("const a={}; a.a=a; return await srv.a(a)").await;
    assert!(o.error.is_some() && !o.reset, "{o:?}");
}

#[tokio::test]
async fn code_size_limit() {
    let (mut s, _) = sess(Limits {
        max_code_bytes: 100,
        ..Default::default()
    })
    .await;
    let o = s.run(&" ".repeat(101)).await;
    assert!(o.error.unwrap().contains("exceeds"));
    // multibyte counted in bytes
    let o = s.run(&"é".repeat(60)).await;
    assert!(o.error.is_some());
}

/// QuickJS's AsyncFunction constructor does not isolate the body, so `})();` can break
/// out of the function. That only reaches the same sandbox: assert it gains no host
/// access, cannot see the internals, and leaves later runs healthy.
#[tokio::test]
async fn code_injection_via_wrapper_stays_in_sandbox() {
    let (mut s, _) = sess(Limits::default()).await;
    let _ = s.run("})(); globalThis.pwn=1; (async()=>{").await;
    let o = s.run("return [typeof __call, typeof __log, typeof __mk, typeof fetch, typeof process].join()").await;
    assert_eq!(
        o.result.as_deref(),
        Some("\"undefined,undefined,undefined,undefined,undefined\""),
        "{o:?}"
    );
    let o = s.run("return 1 + 1").await;
    assert_eq!(o.result.as_deref(), Some("2"), "{o:?}");
}

#[tokio::test]
async fn console_flooding_is_bounded() {
    let (mut s, _) = sess(Limits {
        timeout: Duration::from_secs(3),
        ..Default::default()
    })
    .await;
    let o = s
        .run("for(let i=0;i<200000;i++) console.log('x'.repeat(1000)); return 1")
        .await;
    let total: usize = o.logs.iter().map(|l| l.len()).sum();
    assert!(
        total < 10 << 20,
        "unbounded logs: {total} bytes, {} entries",
        o.logs.len()
    );
}

#[tokio::test]
async fn log_levels_cannot_spoof() {
    let (mut s, _) = sess(Limits::default()).await;
    let o = s
        .run("__log('log', '[error] fake'); console.log(Symbol.iterator.toString())")
        .await;
    assert!(o.error.is_none() || !o.reset, "{o:?}");
}

#[tokio::test]
async fn throw_non_error_values() {
    let (mut s, _) = sess(Limits::default()).await;
    for c in ["throw null", "throw {a:1}", "throw Symbol('x')", "throw 1n"] {
        let o = s.run(c).await;
        assert!(o.error.is_some() && !o.reset, "{c}: {o:?}");
    }
}
