//! E2E: legacy HTTP+SSE upstream through `omnix serve` (agent -> gateway -> sandbox -> SSE).
use rmcp::{ServiceExt, model::CallToolRequestParams, transport::TokioChildProcess};
use serde_json::{Value, json};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    sync::mpsc,
};

#[derive(Clone, Debug)]
struct Seen {
    method: String,
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

/// Legacy SSE mock. `endpoint` may contain `{base}`. Returns (base url, recorded requests).
async fn mock(endpoint: String) -> (String, Arc<Mutex<Vec<Seen>>>) {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", l.local_addr().unwrap());
    let seen: Arc<Mutex<Vec<Seen>>> = Arc::default();
    let (stx, srx) = mpsc::unbounded_channel::<String>();
    let srx = Arc::new(tokio::sync::Mutex::new(srx));
    let (seen2, base2) = (seen.clone(), base.clone());
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = l.accept().await else {
                return;
            };
            let (seen, stx, srx, base, endpoint) = (
                seen2.clone(),
                stx.clone(),
                srx.clone(),
                base2.clone(),
                endpoint.clone(),
            );
            tokio::spawn(async move {
                let mut buf = vec![];
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
                let mut lines = head.lines();
                let method = lines.next().unwrap().split(' ').next().unwrap().to_string();
                let headers = lines
                    .filter_map(|l| l.split_once(':'))
                    .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
                    .collect();
                seen.lock().unwrap().push(Seen {
                    method: method.clone(),
                    headers,
                });
                if method == "GET" {
                    let _ = sock.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nCache-Control: no-cache\r\n\r\n").await;
                    let ep = endpoint.replace("{base}", &base);
                    let _ = sock
                        .write_all(format!("event: endpoint\ndata: {ep}\n\n").as_bytes())
                        .await;
                    let mut rx = srx.lock().await;
                    while let Some(m) = rx.recv().await {
                        if sock
                            .write_all(format!("event: message\ndata: {m}\n\n").as_bytes())
                            .await
                            .is_err()
                        {
                            return;
                        }
                    }
                } else {
                    let body: Value = serde_json::from_slice(&buf[head_end..head_end + cl])
                        .unwrap_or(Value::Null);
                    if let Some(id) = body.get("id") {
                        let result = match body["method"].as_str() {
                            Some("initialize") => {
                                json!({"protocolVersion":"2025-03-26","capabilities":{"tools":{}},"serverInfo":{"name":"mock","version":"1"}})
                            }
                            Some("tools/list") => {
                                json!({"tools":[{"name":"ping","description":"Ping the server","inputSchema":{"type":"object"}}]})
                            }
                            Some("tools/call") => {
                                json!({"content":[{"type":"text","text":"pong"}]})
                            }
                            _ => json!({}),
                        };
                        let _ =
                            stx.send(json!({"jsonrpc":"2.0","id":id,"result":result}).to_string());
                    }
                    let _ = sock.write_all(b"HTTP/1.1 202 Accepted\r\nContent-Length: 8\r\nConnection: close\r\n\r\nAccepted").await;
                }
            });
        }
    });
    (base, seen)
}

/// Listener that records every connection's request head (the "evil" origin).
async fn evil() -> (String, Arc<Mutex<Vec<String>>>) {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", l.local_addr().unwrap());
    let got: Arc<Mutex<Vec<String>>> = Arc::default();
    let g2 = got.clone();
    tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = l.accept().await else {
                return;
            };
            let g = g2.clone();
            tokio::spawn(async move {
                let mut b = [0u8; 4096];
                let n = s.read(&mut b).await.unwrap_or(0);
                g.lock()
                    .unwrap()
                    .push(String::from_utf8_lossy(&b[..n]).to_string());
                let _ = s
                    .write_all(
                        b"HTTP/1.1 202 Accepted\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                    )
                    .await;
            });
        }
    });
    (base, got)
}

fn tmpdir() -> std::path::PathBuf {
    static N: AtomicUsize = AtomicUsize::new(0);
    let d = std::env::temp_dir().join(format!(
        "omnix-sse-{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::SeqCst)
    ));
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn cmd(dir: &std::path::Path, arg: &str, envs: &[(&str, &str)]) -> tokio::process::Command {
    let mut c = tokio::process::Command::new(env!("CARGO_BIN_EXE_omnix"));
    c.arg(arg)
        .current_dir(dir)
        .env("HOME", dir)
        .env("OMNIX_CONFIG_DIR", dir.join("cfg"))
        .env("OMNIX_CATALOG_CACHE", "off");
    for (k, v) in envs {
        c.env(k, v);
    }
    c
}

fn setup(server: Value) -> std::path::PathBuf {
    let d = tmpdir();
    std::fs::write(
        d.join("omnix.json"),
        json!({"servers":{"legacy": server}}).to_string(),
    )
    .unwrap();
    d
}

async fn call(
    svc: &rmcp::service::RunningService<rmcp::RoleClient, ()>,
    tool: &str,
    args: Value,
) -> String {
    let r = svc
        .call_tool(
            CallToolRequestParams::new(tool.to_string())
                .with_arguments(args.as_object().unwrap().clone()),
        )
        .await
        .unwrap();
    serde_json::to_value(&r).unwrap()["content"][0]["text"]
        .as_str()
        .unwrap()
        .to_string()
}

async fn serve(
    dir: &std::path::Path,
    envs: &[(&str, &str)],
) -> rmcp::service::RunningService<rmcp::RoleClient, ()> {
    ().serve(TokioChildProcess::new(cmd(dir, "serve", envs)).unwrap())
        .await
        .unwrap()
}

#[tokio::test]
async fn search_and_execute_through_sse() {
    let (base, _seen) = mock("/messages?sessionId=abc".into()).await;
    let d = setup(json!({"url": format!("{base}/sse"), "transport": "sse"}));
    let svc = serve(&d, &[]).await;
    let out = call(&svc, "search", json!({"query":"ping"})).await;
    assert!(out.contains("legacy.ping"), "{out}");
    let out = call(
        &svc,
        "execute",
        json!({"code":"return await legacy.ping({})"}),
    )
    .await;
    assert!(out.contains("pong"), "{out}");
    let _ = std::fs::remove_dir_all(&d);
}

#[tokio::test]
async fn bearer_and_header_on_get_and_post() {
    let (base, seen) = mock("/messages?sessionId=abc".into()).await;
    let d = setup(json!({"url": format!("{base}/sse"), "transport": "sse",
        "headers": {"X-Tenant": "acme"}, "auth": {"type":"bearer","token":"env:SSE_TOK"}}));
    let svc = serve(&d, &[("SSE_TOK", "s3cret")]).await;
    let out = call(
        &svc,
        "execute",
        json!({"code":"return await legacy.ping({})"}),
    )
    .await;
    assert!(out.contains("pong"), "{out}");
    {
        let seen = seen.lock().unwrap();
        for m in ["GET", "POST"] {
            let reqs: Vec<_> = seen.iter().filter(|s| s.method == m).collect();
            assert!(!reqs.is_empty(), "no {m}");
            for r in reqs {
                assert_eq!(
                    r.header("authorization"),
                    Some("Bearer s3cret"),
                    "{m} {r:?}"
                );
                assert_eq!(r.header("x-tenant"), Some("acme"), "{m} {r:?}");
            }
        }
    }
    let _ = std::fs::remove_dir_all(&d);
}

#[tokio::test]
async fn oauth_over_sse_rejected() {
    let (base, _seen) = mock("/messages?sessionId=abc".into()).await;
    let d =
        setup(json!({"url": format!("{base}/sse"), "transport": "sse", "auth": {"type":"oauth"}}));
    let svc = serve(&d, &[]).await;
    let out = call(&svc, "search", json!({"query":"ping"})).await;
    assert!(
        out.contains("unavailable servers") && out.contains("legacy"),
        "{out}"
    );
    drop(svc);
    let o = cmd(&d, "doctor", &[]).output().await.unwrap();
    let so = String::from_utf8_lossy(&o.stdout);
    assert!(
        so.contains("OAuth is not supported over legacy SSE"),
        "{so}"
    );
    let _ = std::fs::remove_dir_all(&d);
}

#[tokio::test]
async fn cross_origin_endpoint_skipped_no_token_leak() {
    let (evil_base, got) = evil().await;
    let (base, _seen) = mock(format!("{evil_base}/messages")).await;
    let d = setup(
        json!({"url": format!("{base}/sse"), "transport": "sse", "auth": {"type":"bearer","token":"env:SSE_TOK"}}),
    );
    let svc = serve(&d, &[("SSE_TOK", "s3cret")]).await;
    let out = call(&svc, "search", json!({"query":"ping"})).await;
    assert!(
        out.contains("unavailable servers") && out.contains("legacy"),
        "{out}"
    );
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    let got = got.lock().unwrap();
    assert!(
        got.iter()
            .all(|r| !r.to_lowercase().contains("authorization") && !r.contains("s3cret")),
        "{got:?}"
    );
    assert!(got.is_empty(), "evil origin was contacted: {got:?}");
    let _ = std::fs::remove_dir_all(&d);
}
