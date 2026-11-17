//! E2E: static auth reaches an HTTP upstream (headers / query), via `omnix serve`.
use rmcp::{ServiceExt, model::CallToolRequestParams, transport::TokioChildProcess};
use serde_json::{Value, json};
use std::sync::{Arc, Mutex};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};

#[derive(Clone, Debug)]
struct Seen {
    path: String,
    headers: Vec<(String, String)>,
}
impl Seen {
    fn header(&self, n: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(n))
            .map(|(_, v)| v.as_str())
    }
}

/// Minimal MCP-over-HTTP mock. Returns (base url, recorded requests).
async fn mock_http() -> (String, Arc<Mutex<Vec<Seen>>>) {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/mcp", l.local_addr().unwrap());
    let seen = Arc::new(Mutex::new(vec![]));
    let s2 = seen.clone();
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = l.accept().await else {
                return;
            };
            let seen = s2.clone();
            tokio::spawn(async move {
                let mut buf = vec![];
                loop {
                    let mut tmp = [0u8; 4096];
                    let (head_end, content_len) = loop {
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
                    while buf.len() < head_end + content_len {
                        let n = sock.read(&mut tmp).await.unwrap_or(0);
                        if n == 0 {
                            break;
                        }
                        buf.extend_from_slice(&tmp[..n]);
                    }
                    let head = String::from_utf8_lossy(&buf[..head_end]).to_string();
                    let body_bytes = buf[head_end..head_end + content_len].to_vec();
                    buf.drain(..head_end + content_len);
                    let mut lines = head.lines();
                    let first: Vec<&str> = lines.next().unwrap_or("").split(' ').collect();
                    let (method, path) = (
                        first[0].to_string(),
                        first.get(1).unwrap_or(&"").to_string(),
                    );
                    let headers = lines
                        .filter_map(|l| {
                            l.split_once(": ")
                                .map(|(k, v)| (k.to_string(), v.trim().to_string()))
                        })
                        .collect();
                    seen.lock().unwrap().push(Seen { path, headers });
                    let body: Value = serde_json::from_slice(&body_bytes).unwrap_or(Value::Null);
                    let resp = match (method.as_str(), body["method"].as_str()) {
                        ("POST", Some("initialize")) => {
                            Some(json!({"jsonrpc":"2.0","id":body["id"],"result":{
                        "protocolVersion": body["params"]["protocolVersion"],
                        "capabilities":{"tools":{}},"serverInfo":{"name":"mockhttp","version":"0"}}}))
                        }
                        ("POST", Some("tools/list")) => {
                            Some(json!({"jsonrpc":"2.0","id":body["id"],"result":{
                        "tools":[{"name":"ping","description":"Ping the server","inputSchema":{"type":"object"}}]}}))
                        }
                        _ => None,
                    };
                    let out = match (method.as_str(), resp) {
                        (_, Some(r)) => {
                            let b = r.to_string();
                            format!(
                                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n{b}",
                                b.len()
                            )
                        }
                        ("POST", None) => {
                            "HTTP/1.1 202 Accepted\r\ncontent-length: 0\r\n\r\n".into()
                        }
                        ("GET", _) => {
                            "HTTP/1.1 405 Method Not Allowed\r\ncontent-length: 0\r\n\r\n".into()
                        }
                        _ => "HTTP/1.1 200 OK\r\ncontent-length: 0\r\n\r\n".into(),
                    };
                    if sock.write_all(out.as_bytes()).await.is_err() {
                        return;
                    }
                }
            });
        }
    });
    (url, seen)
}

/// Start `omnix serve` with one HTTP server configured; return the `search ping` output.
async fn run_with(server_cfg: Value, token_env: Option<(&str, &str)>) -> String {
    let dir = std::env::temp_dir().join(format!(
        "omnix-auth-{}-{}",
        std::process::id(),
        rand_suffix()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("omnix.json"),
        json!({"servers":{"up": server_cfg}}).to_string(),
    )
    .unwrap();
    let mut c = tokio::process::Command::new(env!("CARGO_BIN_EXE_omnix"));
    c.arg("serve")
        .current_dir(&dir)
        .env("HOME", &dir)
        .env("OMNIX_CONFIG_DIR", dir.join("cfg"))
        .env("OMNIX_CATALOG_CACHE", "off");
    if let Some((k, v)) = token_env {
        c.env(k, v);
    }
    let svc = ().serve(TokioChildProcess::new(c).unwrap()).await.unwrap();
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
    let _ = std::fs::remove_dir_all(&dir);
    out
}

fn rand_suffix() -> usize {
    static N: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    N.fetch_add(1, std::sync::atomic::Ordering::SeqCst)
}

fn any_seen(seen: &Arc<Mutex<Vec<Seen>>>, f: impl Fn(&Seen) -> bool) -> bool {
    seen.lock().unwrap().iter().any(f)
}

#[tokio::test]
async fn bearer_from_env_secret_ref() {
    let (url, seen) = mock_http().await;
    let out = run_with(
        json!({"url": url, "auth": {"type":"bearer","token":"env:UP_TOKEN"}}),
        Some(("UP_TOKEN", "s3cret")),
    )
    .await;
    assert!(out.contains("up.ping"), "{out}");
    assert!(
        any_seen(&seen, |s| s.header("authorization")
            == Some("Bearer s3cret")),
        "{:?}",
        seen.lock().unwrap()
    );
}

#[tokio::test]
async fn custom_header_basic_and_static_headers() {
    let (url, seen) = mock_http().await;
    run_with(json!({"url": url, "headers": {"X-Tenant": "acme"}, "auth": {"type":"header","name":"X-Api-Key","value":"k1"}}), None).await;
    assert!(any_seen(&seen, |s| s.header("x-api-key") == Some("k1")
        && s.header("x-tenant") == Some("acme")));

    let (url, seen) = mock_http().await;
    run_with(
        json!({"url": url, "auth": {"type":"basic","username":"u","password":"p"}}),
        None,
    )
    .await;
    assert!(any_seen(&seen, |s| s.header("authorization") == Some("Basic dTpw")));
}

#[tokio::test]
async fn api_key_in_query() {
    let (url, seen) = mock_http().await;
    run_with(
        json!({"url": url, "auth": {"type":"query","name":"api_key","value":"qk"}}),
        None,
    )
    .await;
    assert!(
        any_seen(&seen, |s| s.path.contains("api_key=qk")),
        "{:?}",
        seen.lock().unwrap()
    );
}

#[tokio::test]
async fn failed_secret_resolution_skips_server_without_leaking() {
    let (url, _seen) = mock_http().await;
    let out = run_with(
        json!({"url": url, "auth": {"type":"bearer","token":"env:OMNIX_DEFINITELY_UNSET"}}),
        None,
    )
    .await;
    assert!(out.starts_with("no matches"), "{out}");
    assert!(
        out.contains("unavailable servers") && out.contains("up"),
        "model must be told a server is unavailable: {out}"
    );
    assert!(!out.contains("OMNIX_DEFINITELY_UNSET"), "{out}");
}
