//! The gateway's own MCP server: exposes `search` and `describe` (and `execute` in milestone 2).

use crate::catalog::{Catalog, Entry};
use crate::handles::HandleStore;
use crate::policy::{AuditEntry, Decision, PolicyConfig};
use crate::pool::Pool;
use crate::sandbox::{HostCall, Limits, Session};
use rmcp::{ErrorData as McpError, RoleServer, ServerHandler, model::*, service::RequestContext};
use serde_json::{Value, json};
use std::{sync::Arc, time::Duration};

/// Connected upstreams plus the policy-filtered catalog built from them.
pub struct Live {
    pub pool: Arc<Pool>,
    pub catalog: Arc<Catalog>,
}

pub struct Gateway {
    live: tokio::sync::watch::Receiver<Option<Arc<Live>>>,
    /// Catalog loaded from the on-disk cache, used until the upstreams are connected.
    cached: Option<Arc<Catalog>>,
    pub session: tokio::sync::Mutex<Option<Session>>,
    pub limits: Limits,
    pub policy: Arc<PolicyConfig>,
    pub handles: Arc<HandleStore>,
}

const SEARCH_WAIT: Duration = Duration::from_secs(30);
const EXECUTE_WAIT: Duration = Duration::from_secs(60);

/// Convert an upstream tool result into a JSON value for the sandbox. Binary content
/// (image/audio/blob) becomes a host-side handle; its bytes never enter the sandbox.
fn result_to_value(r: &CallToolResult, handles: &HandleStore) -> Result<Value, String> {
    let v = serde_json::to_value(r).map_err(|e| e.to_string())?;
    let items = v["content"].as_array().cloned().unwrap_or_default();
    let texts: Vec<&str> = items.iter().filter_map(|c| c["text"].as_str()).collect();
    let joined = texts.join("\n");
    if r.is_error == Some(true) {
        return Err(joined);
    }
    if let Some(sc) = v.get("structuredContent").filter(|s| !s.is_null()) {
        return Ok(sc.clone());
    }
    let has_binary = items.iter().any(|c| {
        matches!(c["type"].as_str(), Some("image" | "audio")) || c["resource"]["blob"].is_string()
    });
    if !has_binary {
        return Ok(serde_json::from_str(&joined).unwrap_or(Value::String(joined)));
    }
    let mut out = vec![];
    for c in &items {
        match c["type"].as_str() {
            Some("image" | "audio") => {
                let mime = c["mimeType"].as_str().unwrap_or("application/octet-stream");
                out.push(handles.put_base64(c["data"].as_str().unwrap_or(""), mime)?);
            }
            Some("resource") if c["resource"]["blob"].is_string() => {
                let mime = c["resource"]["mimeType"]
                    .as_str()
                    .unwrap_or("application/octet-stream");
                out.push(handles.put_base64(c["resource"]["blob"].as_str().unwrap(), mime)?);
            }
            _ => {
                if let Some(t) = c["text"].as_str() {
                    out.push(json!({"type": "text", "text": t}));
                }
            }
        }
    }
    Ok(json!({ "content": out }))
}

impl Gateway {
    fn base(
        live: tokio::sync::watch::Receiver<Option<Arc<Live>>>,
        cached: Option<Arc<Catalog>>,
        limits: Limits,
        policy: PolicyConfig,
    ) -> Self {
        Gateway {
            live,
            cached,
            session: tokio::sync::Mutex::new(None),
            limits,
            policy: Arc::new(policy),
            handles: Arc::new(HandleStore::default()),
        }
    }

    /// Answer the agent's handshake immediately; connect upstreams in the background.
    /// `search`/`describe` use the on-disk cache until connected; `execute` waits.
    pub fn lazy(cfg: crate::config::Config, limits: Limits) -> Self {
        let policy = cfg.policy.clone();
        let key = crate::cache::key(&cfg);
        let cached = crate::cache::load(&key).map(|e| Arc::new(filter_entries(e, &policy)));
        let (tx, rx) = tokio::sync::watch::channel(None);
        let pol = policy.clone();
        tokio::spawn(async move {
            let pool = Pool::connect(&cfg).await;
            for (n, e) in &pool.failures {
                eprintln!("omnix: skipped {n}: {e}");
            }
            let entries = collect_entries(&pool);
            // Only cache a complete picture: a partial catalog (some upstream down) would hide tools.
            if pool.failures.is_empty() {
                crate::cache::save(&key, &entries);
            }
            let catalog = Arc::new(filter_entries(entries, &pol));
            let _ = tx.send(Some(Arc::new(Live {
                pool: Arc::new(pool),
                catalog,
            })));
        });
        Self::base(rx, cached, limits, policy)
    }

    /// The live state, waiting up to `wait` for the upstreams to connect.
    async fn live(&self, wait: Duration) -> Option<Arc<Live>> {
        let mut rx = self.live.clone();
        if let Some(l) = rx.borrow().clone() {
            return Some(l);
        }
        tokio::time::timeout(wait, rx.wait_for(|v| v.is_some()))
            .await
            .ok()?
            .ok()?
            .clone()
    }

    /// Catalog for search/describe: live if ready, else the cache, else wait a bit.
    /// The bool is true when the answer comes from the cache while upstreams still connect.
    async fn catalog_for_lookup(&self) -> Option<(Arc<Catalog>, bool, Option<Arc<Live>>)> {
        if let Some(l) = self.live.borrow().clone() {
            return Some((l.catalog.clone(), false, Some(l)));
        }
        if let Some(c) = &self.cached {
            return Some((c.clone(), true, None));
        }
        let l = self.live(SEARCH_WAIT).await?;
        Some((l.catalog.clone(), false, Some(l)))
    }

    fn host_call(&self, live: &Live) -> HostCall {
        let (pool, policy, handles, catalog) = (
            live.pool.clone(),
            self.policy.clone(),
            self.handles.clone(),
            live.catalog.clone(),
        );
        Arc::new(move |server, tool, args| {
            let (pool, policy, handles, catalog) = (
                pool.clone(),
                policy.clone(),
                handles.clone(),
                catalog.clone(),
            );
            Box::pin(async move {
                let start = std::time::Instant::now();
                let up = pool
                    .servers
                    .get(&server)
                    .ok_or(format!("unknown server {server}"))?;
                let hint = catalog.get(&server, &tool).map(|e| e.read_only);
                let mut decision = policy.decide(&server, &tool, hint);
                if decision == Decision::Allow {
                    decision = policy.run_hook(&server, &tool, &args).await;
                }
                if let Decision::Block(why) = decision {
                    policy.audit(&AuditEntry {
                        server: &server,
                        tool: &tool,
                        args: &args,
                        decision: "block",
                        ok: false,
                        ms: start.elapsed().as_millis(),
                        result_bytes: 0,
                    });
                    return Err(format!("policy: {why}"));
                }
                let mut args = args;
                handles.resolve(&mut args)?;
                let arg_shape = args.clone();
                let mut req = CallToolRequestParams::new(tool.clone());
                if let Value::Object(m) = args {
                    req = req.with_arguments(m);
                }
                let r = up.client.call_tool(req).await.map_err(|e| {
                    let m = e.to_string();
                    if m.to_lowercase().contains("insufficient") && m.to_lowercase().contains("scope") {
                        format!("{m} -- the token lacks a required scope; run `omnix login {server} --scope <scope>` to step up")
                    } else if m.contains("401") || m.to_lowercase().contains("auth required") {
                        format!("{m} -- authorization failed; run `omnix login {server}`")
                    } else {
                        m
                    }
                });
                let out = r.and_then(|r| result_to_value(&r, &handles));
                let size = out.as_ref().map(|v| v.to_string().len()).unwrap_or(0);
                policy.audit(&AuditEntry {
                    server: &server,
                    tool: &tool,
                    args: &arg_shape,
                    decision: "allow",
                    ok: out.is_ok(),
                    ms: start.elapsed().as_millis(),
                    result_bytes: size,
                });
                out
            })
        })
    }

    pub async fn execute(&self, args: &Value) -> CallToolResult {
        let Some(code) = args.get("code").and_then(|c| c.as_str()) else {
            return err("missing `code`".into());
        };
        let Some(live) = self.live(EXECUTE_WAIT).await else {
            return err("upstream servers are still connecting; try again in a moment (run `omnix doctor` if this persists)".into());
        };
        let mut guard = self.session.lock().await;
        if guard.is_none() {
            let names = live.pool.servers.keys().cloned().collect();
            match Session::new(names, self.host_call(&live), self.limits.clone()).await {
                Ok(s) => *guard = Some(s),
                Err(e) => return err(format!("sandbox init failed: {e:#}")),
            }
        }
        let out = guard.as_mut().unwrap().run(code).await;
        if out.reset {
            *guard = None;
        }
        let mut parts = vec![];
        if let Some(r) = &out.result {
            parts.push(format!("result: {r}"));
        }
        if !out.logs.is_empty() {
            parts.push(format!("console:\n{}", out.logs.join("\n")));
        }
        if !out.calls.is_empty() {
            parts.push(format!("calls: {}", out.calls.join(", ")));
        }
        if let Some(e) = &out.error {
            parts.push(format!("error: {e}"));
        }
        if parts.is_empty() {
            parts.push("ok (no result)".into());
        }
        let body = parts.join("\n\n");
        if out.error.is_some() {
            err(body)
        } else {
            text(body)
        }
    }
}

/// Unfiltered entries from every connected upstream.
pub fn collect_entries(pool: &Pool) -> Vec<Entry> {
    let mut entries = vec![];
    for (server, up) in &pool.servers {
        for t in &up.tools {
            entries.push(Entry {
                server: server.clone(),
                name: t.name.to_string(),
                description: t.description.as_deref().unwrap_or("").to_string(),
                schema: Value::Object((*t.input_schema).clone()),
                read_only: t
                    .annotations
                    .as_ref()
                    .is_some_and(|a| a.read_only_hint == Some(true)),
            });
        }
    }
    entries
}

/// Drop tools the policy blocks (they are hidden from search/describe and fail at call time).
pub fn filter_entries(entries: Vec<Entry>, policy: &PolicyConfig) -> Catalog {
    Catalog::new(
        entries
            .into_iter()
            .filter(|e| policy.decide(&e.server, &e.name, Some(e.read_only)) == Decision::Allow)
            .collect(),
    )
}

pub fn build_catalog(pool: &Pool, policy: &PolicyConfig) -> Catalog {
    let mut entries = vec![];
    for (server, up) in &pool.servers {
        for t in &up.tools {
            let ro = t
                .annotations
                .as_ref()
                .is_some_and(|a| a.read_only_hint == Some(true));
            // Blocked tools are hidden from search/describe (they would also fail at call time).
            if policy.decide(server, &t.name, Some(ro)) != Decision::Allow {
                continue;
            }
            entries.push(Entry {
                server: server.clone(),
                name: t.name.to_string(),
                description: t.description.as_deref().unwrap_or("").to_string(),
                schema: Value::Object((*t.input_schema).clone()),
                read_only: t
                    .annotations
                    .as_ref()
                    .is_some_and(|a| a.read_only_hint == Some(true)),
            });
        }
    }
    Catalog::new(entries)
}

fn tool(name: &'static str, desc: &'static str, schema: Value) -> Tool {
    let Value::Object(m) = schema else {
        unreachable!()
    };
    Tool::new(name, desc, m)
}

fn text(s: String) -> CallToolResult {
    CallToolResult::success(vec![ContentBlock::text(s)])
}

fn err(s: String) -> CallToolResult {
    CallToolResult::error(vec![ContentBlock::text(s)])
}

impl Gateway {
    pub fn tools() -> Vec<Tool> {
        vec![
            tool(
                "search",
                "Search upstream MCP tools by keyword. Returns matching `server.tool` ids with one-line descriptions.",
                json!({"type":"object","required":["query"],"properties":{
                    "query":{"type":"string"},"limit":{"type":"integer"}}}),
            ),
            tool(
                "describe",
                "Get the TypeScript signature and full description for `server.tool` ids.",
                json!({"type":"object","required":["tools"],"properties":{
                    "tools":{"type":"array","items":{"type":"string"}}}}),
            ),
            tool(
                "execute",
                "Run JavaScript in a sandbox. Each upstream server is a global (e.g. `await gdrive.list({})`). `return` a value; a persistent `state` object survives between runs. Only the return value, console output and call list come back.",
                json!({"type":"object","required":["code"],"properties":{"code":{"type":"string"}}}),
            ),
        ]
    }

    pub async fn search(&self, args: &Value) -> CallToolResult {
        let Some(q) = args.get("query").and_then(|q| q.as_str()) else {
            return err("missing `query`".into());
        };
        let limit = args.get("limit").and_then(|l| l.as_u64()).unwrap_or(10) as usize;
        let Some((catalog, stale, live)) = self.catalog_for_lookup().await else {
            return err("upstream servers are still connecting; try again in a moment".into());
        };
        let hits = catalog.search(q, limit);
        let mut lines: Vec<String> = hits
            .iter()
            .map(|(e, _)| {
                format!(
                    "{} - {}",
                    e.id(),
                    e.description.lines().next().unwrap_or("")
                )
            })
            .collect();
        if lines.is_empty() && !stale {
            lines.push("no matches".into());
        }
        if stale {
            lines.push("(from cache; upstream servers are still connecting)".into());
        }
        // Tell the model when part of the catalog is missing, so absence isn't misread as "no such tool".
        if let Some(l) = live
            && !l.pool.failures.is_empty()
        {
            let names: Vec<&str> = l.pool.failures.keys().map(|s| s.as_str()).collect();
            lines.push(format!(
                "(unavailable servers, not searched: {}; the user can run `omnix doctor`)",
                names.join(", ")
            ));
        }
        if hits.is_empty() && stale {
            lines.insert(0, "no matches".into());
        }
        text(lines.join("\n"))
    }

    pub async fn describe(&self, args: &Value) -> CallToolResult {
        let Some(ids) = args.get("tools").and_then(|t| t.as_array()) else {
            return err("missing `tools` array".into());
        };
        let Some((catalog, _, _)) = self.catalog_for_lookup().await else {
            return err("upstream servers are still connecting; try again in a moment".into());
        };
        let mut out = vec![];
        for id in ids.iter().filter_map(|i| i.as_str()) {
            let found = id.split_once('.').and_then(|(s, n)| catalog.get(s, n));
            out.push(match found {
                Some(e) => e.signature(),
                None => format!("// unknown tool: {id}"),
            });
        }
        text(out.join("\n\n"))
    }
}

impl ServerHandler for Gateway {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
    }

    async fn list_tools(
        &self,
        _r: Option<PaginatedRequestParams>,
        _c: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, McpError> {
        Ok(ListToolsResult {
            tools: Self::tools(),
            ..Default::default()
        })
    }

    async fn call_tool(
        &self,
        req: CallToolRequestParams,
        _c: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, McpError> {
        let args = Value::Object(req.arguments.unwrap_or_default());
        let res = match &*req.name {
            "search" => self.search(&args).await,
            "describe" => self.describe(&args).await,
            "execute" => self.execute(&args).await,
            other => err(format!("unknown tool: {other}")),
        };
        Ok(res.into())
    }
}
