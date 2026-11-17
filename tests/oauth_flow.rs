//! E2E: OAuth login (PRM/AS discovery, DCR or pre-registered client, PKCE, resource indicator,
//! iss check) and token refresh with rotation, against a raw-TCP mock OAuth + MCP server.
#![allow(clippy::await_holding_lock)] // std Mutex in single-purpose test mocks
use base64::Engine;
use rmcp::{ServiceExt, model::CallToolRequestParams, transport::TokioChildProcess};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::{HashMap, HashSet},
    path::PathBuf,
    process::Stdio,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    net::TcpListener,
};

#[derive(Default)]
struct State {
    base: String,
    expires_in: u64,
    register_bodies: Vec<Value>,
    codes: HashMap<String, (String, String)>, // code -> (challenge, redirect_uri)
    access: HashMap<String, Instant>,
    refresh_valid: HashSet<String>,
    refresh_used: Vec<String>,
    token_forms: Vec<HashMap<String, String>>,
    authorize_queries: Vec<HashMap<String, String>>,
    counter: usize,
}

type Shared = Arc<Mutex<State>>;

fn form(s: &str) -> HashMap<String, String> {
    url::form_urlencoded::parse(s.as_bytes())
        .into_owned()
        .collect()
}

fn json_resp(code: &str, v: Value) -> String {
    let b = v.to_string();
    format!(
        "HTTP/1.1 {code}\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n{b}",
        b.len()
    )
}

fn handle(st: &Shared, method: &str, target: &str, auth: Option<String>, body: &[u8]) -> String {
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    let mut s = st.lock().unwrap();
    let base = s.base.clone();
    match (method, path) {
        ("POST", "/mcp") | ("GET", "/mcp") => {
            let ok = auth
                .as_deref()
                .and_then(|a| a.strip_prefix("Bearer "))
                .is_some_and(|t| s.access.get(t).is_some_and(|exp| *exp > Instant::now()));
            if !ok {
                let ch = format!(
                    "Bearer resource_metadata=\"{base}/.well-known/oauth-protected-resource/mcp\", scope=\"read\""
                );
                return format!(
                    "HTTP/1.1 401 Unauthorized\r\nwww-authenticate: {ch}\r\ncontent-length: 0\r\n\r\n"
                );
            }
            if method == "GET" {
                return "HTTP/1.1 405 Method Not Allowed\r\ncontent-length: 0\r\n\r\n".into();
            }
            let b: Value = serde_json::from_slice(body).unwrap_or(Value::Null);
            match b["method"].as_str() {
                Some("initialize") => json_resp(
                    "200 OK",
                    json!({"jsonrpc":"2.0","id":b["id"],"result":{
                    "protocolVersion": b["params"]["protocolVersion"],
                    "capabilities":{"tools":{}},"serverInfo":{"name":"mockoauth","version":"0"}}}),
                ),
                Some("tools/list") => json_resp(
                    "200 OK",
                    json!({"jsonrpc":"2.0","id":b["id"],"result":{
                    "tools":[{"name":"ping","description":"Ping the server","inputSchema":{"type":"object"}}]}}),
                ),
                _ => "HTTP/1.1 202 Accepted\r\ncontent-length: 0\r\n\r\n".into(),
            }
        }
        ("GET", "/.well-known/oauth-protected-resource/mcp") => json_resp(
            "200 OK",
            json!({"resource": format!("{base}/mcp"), "authorization_servers":[base], "scopes_supported":["read"]}),
        ),
        ("GET", "/.well-known/oauth-authorization-server") => json_resp(
            "200 OK",
            json!({
                "issuer": base,
                "authorization_endpoint": format!("{base}/authorize"),
                "token_endpoint": format!("{base}/token"),
                "registration_endpoint": format!("{base}/register"),
                "code_challenge_methods_supported": ["S256"],
                "response_types_supported": ["code"],
                "grant_types_supported": ["authorization_code", "refresh_token"],
                "token_endpoint_auth_methods_supported": ["none"],
                "authorization_response_iss_parameter_supported": true,
            }),
        ),
        ("POST", "/register") => {
            let b: Value = serde_json::from_slice(body).unwrap_or(Value::Null);
            s.register_bodies.push(b.clone());
            json_resp(
                "201 Created",
                json!({
                    "client_id": "dcr-client",
                    "redirect_uris": b["redirect_uris"],
                    "token_endpoint_auth_method": "none",
                    "grant_types": ["authorization_code","refresh_token"],
                    "response_types": ["code"],
                }),
            )
        }
        ("GET", "/authorize") => {
            let q = form(query);
            s.authorize_queries.push(q.clone());
            let bad = q.get("code_challenge_method").map(String::as_str) != Some("S256")
                || !q.contains_key("code_challenge")
                || !q.contains_key("resource")
                || !q.contains_key("redirect_uri");
            if bad {
                return json_resp("400 Bad Request", json!({"error":"invalid_request"}));
            }
            s.counter += 1;
            let code = format!("code{}", s.counter);
            s.codes.insert(
                code.clone(),
                (q["code_challenge"].clone(), q["redirect_uri"].clone()),
            );
            let mut loc = url::Url::parse(&q["redirect_uri"]).unwrap();
            loc.query_pairs_mut()
                .append_pair("code", &code)
                .append_pair("state", q.get("state").map(String::as_str).unwrap_or(""))
                .append_pair("iss", &base);
            format!("HTTP/1.1 302 Found\r\nlocation: {loc}\r\ncontent-length: 0\r\n\r\n")
        }
        ("POST", "/token") => {
            let f = form(&String::from_utf8_lossy(body));
            s.token_forms.push(f.clone());
            let err = |e: &str| json_resp("400 Bad Request", json!({"error": e}));
            match f.get("grant_type").map(String::as_str) {
                Some("authorization_code") => {
                    let Some((chal, redir)) = f.get("code").and_then(|c| s.codes.remove(c)) else {
                        return err("invalid_grant");
                    };
                    let v = f.get("code_verifier").cloned().unwrap_or_default();
                    let h = base64::engine::general_purpose::URL_SAFE_NO_PAD
                        .encode(Sha256::digest(v.as_bytes()));
                    if h != chal
                        || f.get("redirect_uri") != Some(&redir)
                        || !f.contains_key("resource")
                    {
                        return err("invalid_grant");
                    }
                }
                Some("refresh_token") => {
                    let rt = f.get("refresh_token").cloned().unwrap_or_default();
                    if !s.refresh_valid.remove(&rt) {
                        return err("invalid_grant");
                    }
                    s.refresh_used.push(rt);
                }
                _ => return err("unsupported_grant_type"),
            }
            s.counter += 1;
            let (at, rt) = (format!("at{}", s.counter), format!("rt{}", s.counter));
            let exp = s.expires_in;
            s.access
                .insert(at.clone(), Instant::now() + Duration::from_secs(exp));
            s.refresh_valid.insert(rt.clone());
            json_resp(
                "200 OK",
                json!({"access_token": at, "token_type":"Bearer",
                "expires_in": exp, "refresh_token": rt, "scope":"read"}),
            )
        }
        _ => "HTTP/1.1 404 Not Found\r\ncontent-length: 0\r\n\r\n".into(),
    }
}

async fn mock(expires_in: u64) -> (String, Shared) {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", l.local_addr().unwrap());
    let st: Shared = Arc::new(Mutex::new(State {
        base: base.clone(),
        expires_in,
        ..Default::default()
    }));
    let st2 = st.clone();
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = l.accept().await else {
                return;
            };
            let st = st2.clone();
            tokio::spawn(async move {
                let mut buf = vec![];
                loop {
                    let mut tmp = [0u8; 4096];
                    let (head_end, cl) = loop {
                        if let Some(p) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                            let head = String::from_utf8_lossy(&buf[..p]).to_lowercase();
                            let cl = head
                                .lines()
                                .find_map(|l| l.strip_prefix("content-length:"))
                                .and_then(|v| v.trim().parse::<usize>().ok())
                                .unwrap_or(0);
                            break (p + 4, cl);
                        }
                        let n = sock.read(&mut tmp).await.unwrap_or(0);
                        if n == 0 {
                            return;
                        }
                        buf.extend_from_slice(&tmp[..n]);
                    };
                    while buf.len() < head_end + cl {
                        let n = sock.read(&mut tmp).await.unwrap_or(0);
                        if n == 0 {
                            return;
                        }
                        buf.extend_from_slice(&tmp[..n]);
                    }
                    let head = String::from_utf8_lossy(&buf[..head_end]).to_string();
                    let body = buf[head_end..head_end + cl].to_vec();
                    buf.drain(..head_end + cl);
                    let mut lines = head.lines();
                    let first: Vec<&str> = lines.next().unwrap_or("").split(' ').collect();
                    let auth = lines
                        .filter_map(|l| l.split_once(':'))
                        .find(|(k, _)| k.eq_ignore_ascii_case("authorization"))
                        .map(|(_, v)| v.trim().to_string());
                    let out = handle(&st, first[0], first.get(1).unwrap_or(&""), auth, &body);
                    if sock.write_all(out.as_bytes()).await.is_err() {
                        return;
                    }
                }
            });
        }
    });
    (base, st)
}

fn uniq() -> usize {
    static N: AtomicUsize = AtomicUsize::new(0);
    N.fetch_add(1, Ordering::SeqCst)
}

struct Env {
    dir: PathBuf,
}

impl Env {
    fn new(base: &str, auth: Value) -> Env {
        let dir =
            std::env::temp_dir().join(format!("omnix-oauth-{}-{}", std::process::id(), uniq()));
        std::fs::create_dir_all(dir.join("cfg")).unwrap();
        std::fs::write(
            dir.join("omnix.json"),
            json!({"servers":{"up":{"url": format!("{base}/mcp"), "auth": auth}}}).to_string(),
        )
        .unwrap();
        Env { dir }
    }

    fn cmd(&self, arg: &str) -> tokio::process::Command {
        let mut c = tokio::process::Command::new(env!("CARGO_BIN_EXE_omnix"));
        c.arg(arg)
            .current_dir(&self.dir)
            .env("HOME", &self.dir)
            .env("OMNIX_CONFIG_DIR", self.dir.join("cfg"))
            .env("OMNIX_CREDENTIAL_STORE", "file")
            .env("OMNIX_CATALOG_CACHE", "off");
        c
    }

    /// Run `omnix serve`, search "ping"; returns (search output, stderr).
    async fn serve(&self) -> (String, String) {
        let errp = self.dir.join(format!("serve-{}.err", uniq()));
        let (t, _) = TokioChildProcess::builder(self.cmd("serve"))
            .stderr(std::fs::File::create(&errp).unwrap())
            .spawn()
            .unwrap();
        let svc = ().serve(t).await.unwrap();
        let r = svc
            .call_tool(
                CallToolRequestParams::new("search")
                    .with_arguments(json!({"query":"ping"}).as_object().unwrap().clone()),
            )
            .await
            .unwrap();
        let out = serde_json::to_value(&r).unwrap()["content"][0]["text"]
            .as_str()
            .unwrap()
            .to_string();
        let _ = svc.cancel().await;
        (out, std::fs::read_to_string(&errp).unwrap_or_default())
    }

    /// Run `omnix login up --no-browser`; `tamper_iss` corrupts the iss in the callback.
    /// Returns (success, stderr).
    async fn login(&self, tamper_iss: bool) -> (bool, String) {
        let mut c = self.cmd("login");
        let mut child = c
            .args(["up", "--no-browser"])
            .stderr(Stdio::piped())
            .stdout(Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        let mut lines = BufReader::new(child.stderr.take().unwrap()).lines();
        let mut log = String::new();
        let mut auth_url = None;
        while let Ok(Some(l)) = lines.next_line().await {
            log.push_str(&l);
            log.push('\n');
            if l.trim().starts_with("http") {
                auth_url = Some(l.trim().to_string());
                break;
            }
        }
        let auth_url = auth_url.unwrap_or_else(|| panic!("no auth url in stderr: {log}"));
        let http = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap();
        let r = http.get(&auth_url).send().await.unwrap();
        assert_eq!(r.status(), 302, "authorize: {auth_url}");
        let mut loc = url::Url::parse(r.headers()["location"].to_str().unwrap()).unwrap();
        if tamper_iss {
            let pairs: Vec<(String, String)> = loc
                .query_pairs()
                .map(|(k, v)| {
                    (
                        k.to_string(),
                        if k == "iss" {
                            "http://evil.example".into()
                        } else {
                            v.to_string()
                        },
                    )
                })
                .collect();
            loc.query_pairs_mut().clear().extend_pairs(pairs);
        }
        let _ = http.get(loc).send().await;
        while let Ok(Some(l)) = lines.next_line().await {
            log.push_str(&l);
            log.push('\n');
        }
        let status = tokio::time::timeout(Duration::from_secs(30), child.wait())
            .await
            .unwrap()
            .unwrap();
        (status.success(), log)
    }
}

impl Drop for Env {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn oauth() -> Value {
    json!({"type":"oauth"})
}

fn cred_files(e: &Env) -> usize {
    std::fs::read_dir(e.dir.join("cfg/credentials"))
        .map(|d| d.count())
        .unwrap_or(0)
}

#[tokio::test]
async fn serve_without_login_skips_server() {
    let (base, _st) = mock(3600).await;
    let e = Env::new(&base, oauth());
    let (out, err) = e.serve().await;
    assert!(out.starts_with("no matches"), "{out}");
    assert!(err.contains("omnix login"), "{err}");
}

#[tokio::test]
async fn login_then_serve() {
    let (base, st) = mock(3600).await;
    let e = Env::new(&base, oauth());
    let (ok, log) = e.login(false).await;
    assert!(ok, "{log}");
    {
        let s = st.lock().unwrap();
        assert_eq!(s.register_bodies.len(), 1);
        let r = &s.register_bodies[0];
        assert_eq!(r["application_type"], "native", "{r}");
        let uri = r["redirect_uris"][0].as_str().unwrap();
        assert!(
            uri.starts_with("http://127.0.0.1:") || uri.starts_with("http://localhost:"),
            "{uri}"
        );
        assert!(
            s.token_forms
                .iter()
                .any(|f| f["grant_type"] == "authorization_code" && f.contains_key("resource"))
        );
        assert_eq!(s.authorize_queries[0]["client_id"], "dcr-client");
    }
    let (out, err) = e.serve().await;
    assert!(out.contains("up.ping"), "{out}\n{err}");
}

#[tokio::test]
async fn expired_access_token_refreshes_and_rotation_is_persisted() {
    let (base, st) = mock(1).await;
    let e = Env::new(&base, oauth());
    let (ok, log) = e.login(false).await;
    assert!(ok, "{log}");
    tokio::time::sleep(Duration::from_millis(2200)).await;
    let (out, err) = e.serve().await;
    assert!(out.contains("up.ping"), "first serve: {out}\n{err}");
    assert!(
        !st.lock().unwrap().refresh_used.is_empty(),
        "expected a refresh"
    );
    let first_n = st.lock().unwrap().refresh_used.len();
    tokio::time::sleep(Duration::from_millis(2200)).await;
    // The original refresh token is now invalid; only the rotated one can work.
    let (out, err) = e.serve().await;
    assert!(out.contains("up.ping"), "second serve: {out}\n{err}");
    let s = st.lock().unwrap();
    // (rmcp may refresh several times per run since a 1s token is always "about to expire")
    assert!(s.refresh_used.len() > first_n);
    let uniq: HashSet<_> = s.refresh_used.iter().collect();
    assert_eq!(
        uniq.len(),
        s.refresh_used.len(),
        "a refresh token was reused"
    );
}

#[tokio::test]
async fn tampered_iss_is_rejected() {
    let (base, st) = mock(3600).await;
    let e = Env::new(&base, oauth());
    let (ok, log) = e.login(true).await;
    assert!(!ok, "login should fail: {log}");
    assert_eq!(cred_files(&e), 0);
    assert!(
        st.lock().unwrap().token_forms.is_empty(),
        "token endpoint must not be hit"
    );
    let (out, _) = e.serve().await;
    assert!(out.starts_with("no matches"), "{out}");
}

#[tokio::test]
async fn preregistered_client_skips_dcr() {
    let (base, st) = mock(3600).await;
    let e = Env::new(&base, json!({"type":"oauth","client_id":"pre"}));
    let (ok, log) = e.login(false).await;
    assert!(ok, "{log}");
    let s = st.lock().unwrap();
    assert!(s.register_bodies.is_empty());
    assert_eq!(s.authorize_queries[0]["client_id"], "pre");
    assert!(s.token_forms.iter().all(|f| f["client_id"] == "pre"));
    drop(s);
    let (out, _) = e.serve().await;
    assert!(out.contains("up.ping"), "{out}");
}
