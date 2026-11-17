//! E2E: client_credentials (secret + private_key_jwt), RFC 8628 device flow, and scope step-up,
//! against a raw-TCP mock OAuth + MCP server.
//!
//! Not covered: timed re-exchange (omnix re-exchanges at 80% of lifetime but never sooner than
//! 30s, so a faithful test would take >30s); we test that every `serve` start exchanges afresh.
#![allow(clippy::await_holding_lock)] // std Mutex in single-purpose test mocks
use base64::Engine;
use rmcp::{ServiceExt, model::CallToolRequestParams, transport::TokioChildProcess};
use serde_json::{Value, json};
use std::{
    collections::HashMap,
    path::{Path, PathBuf},
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

const JWT_BEARER: &str = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

#[derive(Default)]
struct State {
    base: String,
    expires_in: u64,
    auth_methods: Vec<String>,
    // private_key_jwt verification
    pubkey: Option<PathBuf>,
    jwt_headers: Vec<Value>,
    jwt_claims: Vec<Value>,
    jwt_errors: Vec<String>,
    // device flow
    device_endpoint: bool,
    device_seq: Vec<&'static str>, // popped from the front; empty => success
    device_denied: bool,
    device_forms: Vec<HashMap<String, String>>,
    device_polls: usize,
    // generic
    forbid_call: bool,
    codes: HashMap<String, (String, String)>,
    access: HashMap<String, Instant>,
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

fn b64d(s: &str) -> Vec<u8> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(s)
        .unwrap_or_default()
}

fn der_int(b: &[u8]) -> Vec<u8> {
    let mut v: Vec<u8> = b.iter().copied().skip_while(|x| *x == 0).collect();
    if v.is_empty() || v[0] & 0x80 != 0 {
        v.insert(0, 0);
    }
    let mut o = vec![2, v.len() as u8];
    o.extend(v);
    o
}

/// ES256 raw r||s -> DER ECDSA-Sig-Value.
fn es_to_der(raw: &[u8]) -> Vec<u8> {
    let (r, s) = raw.split_at(raw.len() / 2);
    let mut body = der_int(r);
    body.extend(der_int(s));
    let mut o = vec![0x30, body.len() as u8];
    o.extend(body);
    o
}

/// Verify a JWT signature with the openssl CLI. Returns Err(reason).
fn verify_jwt(jwt: &str, pubkey: &Path) -> Result<(Value, Value), String> {
    let parts: Vec<&str> = jwt.split('.').collect();
    if parts.len() != 3 {
        return Err("not a 3-part jwt".into());
    }
    let header: Value =
        serde_json::from_slice(&b64d(parts[0])).map_err(|e| format!("header: {e}"))?;
    let claims: Value =
        serde_json::from_slice(&b64d(parts[1])).map_err(|e| format!("claims: {e}"))?;
    let mut sig = b64d(parts[2]);
    if header["alg"].as_str().is_some_and(|a| a.starts_with("ES")) {
        sig = es_to_der(&sig);
    }
    let d = std::env::temp_dir().join(format!("omnix-jwt-{}-{}", std::process::id(), uniq()));
    std::fs::create_dir_all(&d).unwrap();
    std::fs::write(d.join("data"), format!("{}.{}", parts[0], parts[1])).unwrap();
    std::fs::write(d.join("sig"), sig).unwrap();
    let out = std::process::Command::new("openssl")
        .args(["dgst", "-sha256", "-verify"])
        .arg(pubkey)
        .arg("-signature")
        .arg(d.join("sig"))
        .arg(d.join("data"))
        .output()
        .unwrap();
    let _ = std::fs::remove_dir_all(&d);
    if out.status.success() {
        Ok((header, claims))
    } else {
        Err(format!(
            "bad signature: {}",
            String::from_utf8_lossy(&out.stdout)
        ))
    }
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
                Some("tools/call") => {
                    if s.forbid_call {
                        return "HTTP/1.1 403 Forbidden\r\nwww-authenticate: Bearer error=\"insufficient_scope\", scope=\"write\"\r\ncontent-length: 0\r\n\r\n".into();
                    }
                    json_resp(
                        "200 OK",
                        json!({"jsonrpc":"2.0","id":b["id"],"result":{
                        "content":[{"type":"text","text":"pong"}]}}),
                    )
                }
                _ => "HTTP/1.1 202 Accepted\r\ncontent-length: 0\r\n\r\n".into(),
            }
        }
        ("GET", "/.well-known/oauth-protected-resource/mcp") => json_resp(
            "200 OK",
            json!({"resource": format!("{base}/mcp"), "authorization_servers":[base], "scopes_supported":["read","write"]}),
        ),
        ("GET", "/.well-known/oauth-authorization-server") => {
            let mut m = json!({
                "issuer": base,
                "authorization_endpoint": format!("{base}/authorize"),
                "token_endpoint": format!("{base}/token"),
                "registration_endpoint": format!("{base}/register"),
                "code_challenge_methods_supported": ["S256"],
                "response_types_supported": ["code"],
                "grant_types_supported": ["authorization_code", "refresh_token", "client_credentials"],
                "token_endpoint_auth_methods_supported": s.auth_methods,
                "token_endpoint_auth_signing_alg_values_supported": ["RS256", "ES256"],
                "authorization_response_iss_parameter_supported": true,
            });
            if s.device_endpoint {
                m["device_authorization_endpoint"] = json!(format!("{base}/device"));
            }
            json_resp("200 OK", m)
        }
        ("POST", "/register") => {
            let b: Value = serde_json::from_slice(body).unwrap_or(Value::Null);
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
        ("POST", "/device") => {
            let f = form(&String::from_utf8_lossy(body));
            s.device_forms.push(f);
            json_resp(
                "200 OK",
                json!({"device_code":"dev-code-1","user_code":"WDJB-MJHT",
                "verification_uri": format!("{base}/activate"), "expires_in": 60, "interval": 1}),
            )
        }
        ("GET", "/authorize") => {
            let q = form(query);
            s.authorize_queries.push(q.clone());
            if q.get("code_challenge_method").map(String::as_str) != Some("S256")
                || !q.contains_key("redirect_uri")
            {
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
            let mut f = form(&String::from_utf8_lossy(body));
            if let Some(a) = &auth {
                f.insert("_auth".into(), a.clone());
            }
            s.token_forms.push(f.clone());
            let err = |e: &str| json_resp("400 Bad Request", json!({"error": e}));
            let mut scope = "read".to_string();
            match f.get("grant_type").map(String::as_str) {
                Some("authorization_code") => {
                    if f.get("code").and_then(|c| s.codes.remove(c)).is_none() {
                        return err("invalid_grant");
                    }
                    scope = "read write".into();
                    if s.codes.is_empty() && s.authorize_queries.len() == 1 {
                        scope = "read".into();
                    }
                }
                Some("client_credentials") => {
                    scope = f.get("scope").cloned().unwrap_or_default();
                    if let Some(pk) = s.pubkey.clone() {
                        let res = if f.get("client_assertion_type").map(String::as_str)
                            != Some(JWT_BEARER)
                        {
                            Err("missing/incorrect client_assertion_type".to_string())
                        } else {
                            verify_jwt(
                                f.get("client_assertion").map(String::as_str).unwrap_or(""),
                                &pk,
                            )
                        };
                        match res {
                            Ok((h, c)) => {
                                s.jwt_headers.push(h);
                                s.jwt_claims.push(c);
                            }
                            Err(e) => {
                                s.jwt_errors.push(e);
                                return err("invalid_client");
                            }
                        }
                    }
                }
                Some("urn:ietf:params:oauth:grant-type:device_code") => {
                    s.device_polls += 1;
                    if s.device_denied {
                        return err("access_denied");
                    }
                    if !s.device_seq.is_empty() {
                        let e = s.device_seq.remove(0);
                        return err(e);
                    }
                }
                _ => return err("unsupported_grant_type"),
            }
            s.counter += 1;
            let at = format!("at{}", s.counter);
            let exp = s.expires_in;
            s.access
                .insert(at.clone(), Instant::now() + Duration::from_secs(exp));
            json_resp(
                "200 OK",
                json!({"access_token": at, "token_type":"Bearer", "expires_in": exp, "scope": scope}),
            )
        }
        _ => "HTTP/1.1 404 Not Found\r\ncontent-length: 0\r\n\r\n".into(),
    }
}

async fn mock(expires_in: u64, setup: impl FnOnce(&mut State)) -> (String, Shared) {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", l.local_addr().unwrap());
    let mut init = State {
        base: base.clone(),
        expires_in,
        ..Default::default()
    };
    setup(&mut init);
    let st: Shared = Arc::new(Mutex::new(init));
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
            std::env::temp_dir().join(format!("omnix-oauthmore-{}-{}", std::process::id(), uniq()));
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
            .env("OMNIX_CATALOG_CACHE", "off")
            .env("CC_SECRET", "s3cret-value");
        c
    }

    /// Run `omnix serve`, call a gateway tool; returns (text, stderr).
    async fn gateway(&self, tool: &str, args: Value) -> (String, String) {
        let errp = self.dir.join(format!("serve-{}.err", uniq()));
        let (t, _) = TokioChildProcess::builder(self.cmd("serve"))
            .stderr(std::fs::File::create(&errp).unwrap())
            .spawn()
            .unwrap();
        let svc = ().serve(t).await.unwrap();
        let r = svc
            .call_tool(
                CallToolRequestParams::new(tool.to_string())
                    .with_arguments(args.as_object().unwrap().clone()),
            )
            .await
            .unwrap();
        let out = serde_json::to_value(&r).unwrap()["content"][0]["text"]
            .as_str()
            .unwrap_or("")
            .to_string();
        let _ = svc.cancel().await;
        (out, std::fs::read_to_string(&errp).unwrap_or_default())
    }

    async fn serve(&self) -> (String, String) {
        self.gateway("search", json!({"query":"ping"})).await
    }

    /// `omnix login up <extra...>` (browser-style flow, we play the browser). Returns (success, log).
    async fn login(&self, extra: &[&str]) -> (bool, String) {
        let mut c = self.cmd("login");
        let mut child = c
            .arg("up")
            .arg("--no-browser")
            .args(extra)
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
        let Some(auth_url) = auth_url else {
            let _ = child.wait().await;
            return (false, log);
        };
        let http = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap();
        let r = http.get(&auth_url).send().await.unwrap();
        assert_eq!(r.status(), 302, "authorize: {auth_url}");
        let _ = http
            .get(r.headers()["location"].to_str().unwrap())
            .send()
            .await;
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

    /// `omnix login up --device --no-browser`; nobody needs to approve (the mock decides).
    async fn login_device(&self) -> (bool, String) {
        let out = tokio::time::timeout(
            Duration::from_secs(40),
            self.cmd("login")
                .args(["up", "--device", "--no-browser"])
                .kill_on_drop(true)
                .output(),
        )
        .await
        .expect("device login timed out")
        .unwrap();
        (
            out.status.success(),
            String::from_utf8_lossy(&out.stderr).to_string(),
        )
    }
}

impl Drop for Env {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn cred_files(e: &Env) -> usize {
    std::fs::read_dir(e.dir.join("cfg/credentials"))
        .map(|d| d.count())
        .unwrap_or(0)
}

fn genkey(dir: &Path, alg: &str) -> (PathBuf, PathBuf) {
    let (k, p) = (dir.join("key.pem"), dir.join("pub.pem"));
    let spec: &[&str] = if alg == "RS256" {
        &["-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048"]
    } else {
        &["-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256"]
    };
    let st = std::process::Command::new("openssl")
        .arg("genpkey")
        .args(spec)
        .arg("-out")
        .arg(&k)
        .status()
        .expect("openssl");
    assert!(st.success());
    let st = std::process::Command::new("openssl")
        .args(["pkey", "-pubout", "-in"])
        .arg(&k)
        .arg("-out")
        .arg(&p)
        .status()
        .unwrap();
    assert!(st.success());
    (k, p)
}

fn cc_secret_auth() -> Value {
    json!({"type":"client_credentials","client_id":"m2m","client_secret":"env:CC_SECRET","scopes":["read","extra"]})
}

#[tokio::test]
async fn client_secret_exchange_without_login() {
    let (base, st) = mock(3600, |s| s.auth_methods = vec!["client_secret_post".into()]).await;
    let e = Env::new(&base, cc_secret_auth());
    let (out, err) = e.serve().await;
    assert!(out.contains("up.ping"), "{out}\n{err}");
    let s = st.lock().unwrap();
    let f = s
        .token_forms
        .iter()
        .find(|f| f["grant_type"] == "client_credentials")
        .expect("no cc request");
    assert_eq!(f["resource"], format!("{base}/mcp"));
    let scopes: Vec<&str> = f["scope"].split(' ').collect();
    assert!(
        scopes.contains(&"read") && scopes.contains(&"extra"),
        "{f:?}"
    );
    let basic = f.get("_auth").is_some_and(|a| a.starts_with("Basic "));
    assert!(
        basic || f.get("client_secret").map(String::as_str) == Some("s3cret-value"),
        "{f:?}"
    );
    assert!(basic || f["client_id"] == "m2m", "{f:?}");
    assert!(
        s.authorize_queries.is_empty(),
        "browser flow must not start"
    );
    drop(s);
    assert_eq!(
        cred_files(&e),
        0,
        "client-credentials tokens are in-memory only"
    );
}

#[tokio::test]
async fn client_secret_fresh_exchange_per_serve() {
    // The 30s floor on re-exchange makes the timed path impractical; assert each start exchanges.
    let (base, st) = mock(3600, |s| s.auth_methods = vec!["client_secret_post".into()]).await;
    let e = Env::new(&base, cc_secret_auth());
    for _ in 0..2 {
        let (out, err) = e.serve().await;
        assert!(out.contains("up.ping"), "{out}\n{err}");
    }
    let n = st
        .lock()
        .unwrap()
        .token_forms
        .iter()
        .filter(|f| f["grant_type"] == "client_credentials")
        .count();
    assert_eq!(n, 2);
}

async fn private_key_jwt(alg: &str) {
    let dir = std::env::temp_dir().join(format!("omnix-keys-{}-{}", std::process::id(), uniq()));
    std::fs::create_dir_all(&dir).unwrap();
    let (key, publ) = genkey(&dir, alg);
    let (base, st) = mock(3600, |s| {
        s.auth_methods = vec!["private_key_jwt".into()];
        s.pubkey = Some(publ);
    })
    .await;
    let e = Env::new(
        &base,
        json!({"type":"client_credentials","client_id":"m2m","private_key":format!("file:{}", key.display()),
               "algorithm":alg,"scopes":["read"]}),
    );
    let (out, err) = e.serve().await;
    let s = st.lock().unwrap();
    assert!(s.jwt_errors.is_empty(), "{:?}", s.jwt_errors);
    assert!(out.contains("up.ping"), "{out}\n{err}");
    assert_eq!(s.jwt_claims.len(), 1);
    let (h, c) = (&s.jwt_headers[0], &s.jwt_claims[0]);
    assert_eq!(h["alg"], alg);
    assert_eq!(c["iss"], "m2m");
    assert_eq!(c["sub"], "m2m");
    let aud = c["aud"].to_string();
    assert!(aud.contains(&base), "aud {aud}");
    assert!(
        c["exp"].as_u64().unwrap()
            > std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs()
    );
    let f = s
        .token_forms
        .iter()
        .find(|f| f["grant_type"] == "client_credentials")
        .unwrap();
    assert_eq!(f["client_assertion_type"], JWT_BEARER);
    assert_eq!(f["resource"], format!("{base}/mcp"));
    assert!(!f.contains_key("client_secret"));
    drop(s);
    let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test]
async fn private_key_jwt_rs256() {
    private_key_jwt("RS256").await;
}

#[tokio::test]
async fn private_key_jwt_es256() {
    private_key_jwt("ES256").await;
}

#[tokio::test]
async fn device_flow_pending_slow_down_then_success() {
    let (base, st) = mock(3600, |s| {
        s.auth_methods = vec!["none".into()];
        s.device_endpoint = true;
        s.device_seq = vec![
            "authorization_pending",
            "authorization_pending",
            "slow_down",
        ];
    })
    .await;
    let e = Env::new(
        &base,
        json!({"type":"oauth","client_id":"dev","scopes":["read"]}),
    );
    let t = Instant::now();
    let (ok, log) = e.login_device().await;
    assert!(ok, "{log}");
    assert!(log.contains(&format!("{base}/activate")), "{log}");
    assert!(log.contains("WDJB-MJHT"), "{log}");
    assert!(t.elapsed() < Duration::from_secs(25), "{:?}", t.elapsed());
    {
        let s = st.lock().unwrap();
        assert_eq!(s.device_polls, 4);
        assert_eq!(s.device_forms[0]["client_id"], "dev");
        assert_eq!(s.device_forms[0]["resource"], format!("{base}/mcp"));
        assert_eq!(s.device_forms[0]["scope"], "read");
        assert!(s.authorize_queries.is_empty());
    }
    let (out, err) = e.serve().await;
    assert!(out.contains("up.ping"), "{out}\n{err}");
}

#[tokio::test]
async fn device_flow_requires_endpoint() {
    let (base, _st) = mock(3600, |s| s.auth_methods = vec!["none".into()]).await;
    let e = Env::new(&base, json!({"type":"oauth","client_id":"dev"}));
    let (ok, log) = e.login_device().await;
    assert!(!ok, "{log}");
    assert!(log.contains("device_authorization_endpoint"), "{log}");
    assert_eq!(cred_files(&e), 0);
}

#[tokio::test]
async fn device_flow_access_denied() {
    let (base, _st) = mock(3600, |s| {
        s.auth_methods = vec!["none".into()];
        s.device_endpoint = true;
        s.device_denied = true;
    })
    .await;
    let e = Env::new(&base, json!({"type":"oauth","client_id":"dev"}));
    let (ok, log) = e.login_device().await;
    assert!(!ok, "{log}");
    assert!(log.contains("denied"), "{log}");
    assert_eq!(cred_files(&e), 0);
    let (out, _) = e.serve().await;
    assert!(out.starts_with("no matches"), "{out}");
}

#[tokio::test]
async fn scope_step_up() {
    let (base, st) = mock(3600, |s| s.auth_methods = vec!["none".into()]).await;
    let e = Env::new(
        &base,
        json!({"type":"oauth","client_id":"pre","scopes":["read"]}),
    );
    let (ok, log) = e.login(&[]).await;
    assert!(ok, "{log}");
    st.lock().unwrap().forbid_call = true;
    let (out, err) = e
        .gateway("execute", json!({"code":"return await up.ping({})"}))
        .await;
    assert!(out.contains("omnix login up --scope"), "{out}\n{err}");
    st.lock().unwrap().forbid_call = false;

    let (ok, log) = e.login(&["--scope", "write"]).await;
    assert!(ok, "{log}");
    let s = st.lock().unwrap();
    let q = s.authorize_queries.last().unwrap();
    let scopes: Vec<&str> = q["scope"].split(' ').collect();
    assert!(
        scopes.contains(&"read") && scopes.contains(&"write"),
        "{q:?}"
    );
    drop(s);
    let (out, err) = e
        .gateway("execute", json!({"code":"return await up.ping({})"}))
        .await;
    assert!(out.contains("pong"), "{out}\n{err}");
}
