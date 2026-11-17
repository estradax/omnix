//! Legacy HTTP+SSE MCP client transport (pre-2025-03 spec).
//!
//! `GET <url>` with `Accept: text/event-stream` opens a long-lived stream. The
//! first event, `endpoint`, carries the URL (often relative) that client->server
//! JSON-RPC messages are POSTed to. Server->client messages arrive as `message`
//! events. Header values are never logged.
use std::{collections::HashMap, io, time::Duration};

use anyhow::{Context, anyhow, bail};
use http::{HeaderName, HeaderValue};
use rmcp::{
    RoleClient,
    service::{RxJsonRpcMessage, TxJsonRpcMessage},
    transport::Transport,
};
use tokio::{sync::mpsc, task::JoinHandle};
use url::Url;

const ENDPOINT_TIMEOUT: Duration = Duration::from_secs(30);

/// A parsed SSE event.
#[derive(Debug, PartialEq, Eq)]
struct Event {
    name: String,
    data: String,
}

/// Incremental SSE parser tolerant of arbitrary chunk boundaries and CR/LF/CRLF.
#[derive(Default)]
struct Parser {
    buf: Vec<u8>,
    name: String,
    data: Vec<String>,
    has_data: bool,
    started: bool,
}

impl Parser {
    fn feed(&mut self, chunk: &[u8]) -> Vec<Event> {
        self.buf.extend_from_slice(chunk);
        if !self.started && self.buf.len() >= 3 {
            self.started = true;
            if self.buf.starts_with(&[0xEF, 0xBB, 0xBF]) {
                self.buf.drain(..3);
            }
        }
        let mut out = vec![];
        let mut pos = 0;
        loop {
            let rest = &self.buf[pos..];
            let Some(i) = rest.iter().position(|&b| b == b'\n' || b == b'\r') else {
                break;
            };
            let mut skip = 1;
            if rest[i] == b'\r' {
                match rest.get(i + 1) {
                    None => break, // might be CRLF split across chunks; wait
                    Some(b'\n') => skip = 2,
                    _ => {}
                }
            }
            let line = String::from_utf8_lossy(&rest[..i]).into_owned();
            pos += i + skip;
            self.line(&line, &mut out);
        }
        self.buf.drain(..pos);
        out
    }

    fn line(&mut self, line: &str, out: &mut Vec<Event>) {
        if line.is_empty() {
            if self.has_data {
                let name = if self.name.is_empty() {
                    "message".to_string()
                } else {
                    std::mem::take(&mut self.name)
                };
                out.push(Event {
                    name,
                    data: self.data.join("\n"),
                });
            }
            self.name.clear();
            self.data.clear();
            self.has_data = false;
            return;
        }
        if line.starts_with(':') {
            return;
        }
        let (field, value) = match line.split_once(':') {
            Some((f, v)) => (f, v.strip_prefix(' ').unwrap_or(v)),
            None => (line, ""),
        };
        match field {
            "event" => self.name = value.to_string(),
            "data" => {
                self.data.push(value.to_string());
                self.has_data = true;
            }
            _ => {}
        }
    }
}

/// Resolve `endpoint` against `base`, requiring the same origin.
fn resolve_endpoint(base: &Url, endpoint: &str) -> anyhow::Result<Url> {
    let u = base
        .join(endpoint.trim())
        .map_err(|_| anyhow!("SSE server sent an invalid endpoint URL"))?;
    if u.origin() != base.origin() {
        bail!(
            "SSE endpoint origin ({}) differs from stream origin ({}); refusing",
            u.origin().ascii_serialization(),
            base.origin().ascii_serialization()
        );
    }
    Ok(u)
}

/// Client transport over legacy HTTP+SSE.
pub struct SseTransport {
    client: reqwest::Client,
    endpoint: Url,
    headers: reqwest::header::HeaderMap,
    rx: mpsc::UnboundedReceiver<RxJsonRpcMessage<RoleClient>>,
    task: JoinHandle<()>,
}

impl Drop for SseTransport {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// Connect to a legacy SSE MCP server. Fails if the `endpoint` event does not
/// arrive within 30s or points at a different origin.
pub async fn connect(
    url: &str,
    headers: HashMap<HeaderName, HeaderValue>,
    bearer: Option<String>,
) -> anyhow::Result<SseTransport> {
    let base = Url::parse(url).context("invalid SSE url")?;
    if !matches!(base.scheme(), "http" | "https") {
        bail!("SSE url must be http or https");
    }
    let mut hm = reqwest::header::HeaderMap::new();
    for (k, v) in headers {
        let mut v = v;
        v.set_sensitive(true);
        hm.insert(k, v);
    }
    if let Some(t) = bearer {
        let mut v = HeaderValue::from_str(&format!("Bearer {t}"))
            .map_err(|_| anyhow!("bearer token contains invalid characters"))?;
        v.set_sensitive(true);
        hm.insert(http::header::AUTHORIZATION, v);
    }
    // Follow redirects only within the same origin, so credentials never leave it.
    let policy = reqwest::redirect::Policy::custom(|attempt| {
        let same = attempt
            .previous()
            .last()
            .is_some_and(|p| p.origin() == attempt.url().origin());
        if same && attempt.previous().len() < 5 {
            attempt.follow()
        } else {
            attempt.stop()
        }
    });
    let client = reqwest::Client::builder()
        .redirect(policy)
        .build()
        .context("building http client")?;

    let (tx, rx) = mpsc::unbounded_channel();
    let (ep_tx, ep_rx) = tokio::sync::oneshot::channel::<anyhow::Result<Url>>();
    let get_client = client.clone();
    let get_headers = hm.clone();
    let get_url = base.clone();
    let task = tokio::spawn(async move {
        let mut ep_tx = Some(ep_tx);
        let fail = |ep_tx: &mut Option<tokio::sync::oneshot::Sender<anyhow::Result<Url>>>,
                    e: anyhow::Error| {
            if let Some(s) = ep_tx.take() {
                let _ = s.send(Err(e));
            }
        };
        let resp = get_client
            .get(get_url)
            .headers(get_headers)
            .header(http::header::ACCEPT, "text/event-stream")
            .send()
            .await;
        let mut resp = match resp {
            Ok(r) if r.status().is_success() => r,
            Ok(r) => {
                return fail(
                    &mut ep_tx,
                    anyhow!("SSE connect failed: HTTP {}", r.status()),
                );
            }
            Err(e) => {
                return fail(
                    &mut ep_tx,
                    anyhow!("SSE connect failed: {}", e.without_url()),
                );
            }
        };
        let stream_url = resp.url().clone();
        let mut parser = Parser::default();
        loop {
            let chunk = match resp.chunk().await {
                Ok(Some(c)) => c,
                _ => break, // stream ended or errored: drop tx so the transport ends
            };
            for ev in parser.feed(&chunk) {
                match ev.name.as_str() {
                    "endpoint" => {
                        if let Some(s) = ep_tx.take() {
                            let r = resolve_endpoint(&stream_url, &ev.data);
                            let bad = r.is_err();
                            let _ = s.send(r);
                            if bad {
                                return;
                            }
                        }
                    }
                    "message" => {
                        if ep_tx.is_some() {
                            continue; // message before endpoint: ignore
                        }
                        if let Ok(m) =
                            serde_json::from_str::<RxJsonRpcMessage<RoleClient>>(&ev.data)
                            && tx.send(m).is_err()
                        {
                            return;
                        }
                    }
                    _ => {}
                }
            }
        }
        fail(
            &mut ep_tx,
            anyhow!("SSE stream closed before endpoint event"),
        );
    });

    let endpoint = match tokio::time::timeout(ENDPOINT_TIMEOUT, ep_rx).await {
        Ok(Ok(Ok(u))) => u,
        Ok(Ok(Err(e))) => return Err(e),
        Ok(Err(_)) => {
            task.abort();
            bail!("SSE stream closed before endpoint event")
        }
        Err(_) => {
            task.abort();
            bail!("timed out waiting for SSE endpoint event")
        }
    };
    Ok(SseTransport {
        client,
        endpoint,
        headers: hm,
        rx,
        task,
    })
}

impl Transport<RoleClient> for SseTransport {
    type Error = io::Error;

    fn send(
        &mut self,
        item: TxJsonRpcMessage<RoleClient>,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send + 'static {
        let req = self
            .client
            .post(self.endpoint.clone())
            .headers(self.headers.clone())
            .json(&item);
        async move {
            let resp = req
                .send()
                .await
                .map_err(|e| io::Error::other(e.without_url().to_string()))?;
            if !resp.status().is_success() {
                return Err(io::Error::other(format!(
                    "SSE POST failed: HTTP {}",
                    resp.status()
                )));
            }
            Ok(())
        }
    }

    fn receive(&mut self) -> impl Future<Output = Option<RxJsonRpcMessage<RoleClient>>> + Send {
        self.rx.recv()
    }

    async fn close(&mut self) -> Result<(), Self::Error> {
        self.task.abort();
        self.rx.close();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rmcp::{ServiceExt, model::CallToolRequestParams};
    use serde_json::{Value, json};
    use std::sync::{Arc, Mutex};
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
        sync::Notify,
    };

    #[derive(Clone, Debug)]
    struct Seen {
        method: String,
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

    #[derive(Clone)]
    struct Opts {
        /// Value of the endpoint event's data (None = `/messages?sessionId=abc`, `{base}` substituted).
        endpoint: String,
        /// Write the stream in tiny pieces with CRLF line endings.
        chunky: bool,
        /// Close the stream right after the endpoint event.
        close_after_endpoint: bool,
    }
    impl Default for Opts {
        fn default() -> Self {
            Opts {
                endpoint: "/messages?sessionId=abc".into(),
                chunky: false,
                close_after_endpoint: false,
            }
        }
    }

    struct Mock {
        base: String,
        seen: Arc<Mutex<Vec<Seen>>>,
        kill: Arc<Notify>,
    }

    async fn mock(o: Opts) -> Mock {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", l.local_addr().unwrap());
        let seen: Arc<Mutex<Vec<Seen>>> = Arc::default();
        let kill = Arc::new(Notify::new());
        let (stx, srx) = mpsc::unbounded_channel::<String>();
        let srx = Arc::new(tokio::sync::Mutex::new(srx));
        let (seen2, kill2, base2) = (seen.clone(), kill.clone(), base.clone());
        tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = l.accept().await else {
                    return;
                };
                let (o, seen, kill, stx, srx, base) = (
                    o.clone(),
                    seen2.clone(),
                    kill2.clone(),
                    stx.clone(),
                    srx.clone(),
                    base2.clone(),
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
                    let mut rl = lines.next().unwrap().split(' ');
                    let (method, path) = (
                        rl.next().unwrap().to_string(),
                        rl.next().unwrap().to_string(),
                    );
                    let headers = lines
                        .filter_map(|l| l.split_once(':'))
                        .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
                        .collect();
                    seen.lock().unwrap().push(Seen {
                        method: method.clone(),
                        path: path.clone(),
                        headers,
                    });
                    if method == "GET" {
                        let _ = sock.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nCache-Control: no-cache\r\n\r\n").await;
                        let nl = if o.chunky { "\r\n" } else { "\n" };
                        let ep = o.endpoint.replace("{base}", &base);
                        let first =
                            format!(": hello comment{nl}event: endpoint{nl}data: {ep}{nl}{nl}");
                        write_pieces(&mut sock, first.as_bytes(), o.chunky).await;
                        if o.close_after_endpoint {
                            return;
                        }
                        let mut rx = srx.lock().await;
                        loop {
                            tokio::select! {
                                _ = kill.notified() => return,
                                m = rx.recv() => {
                                    let Some(m) = m else { return };
                                    // Multi-line data: pretty-print so the JSON spans several data: lines.
                                    let v: Value = serde_json::from_str(&m).unwrap();
                                    let pretty = serde_json::to_string_pretty(&v).unwrap();
                                    let mut ev = format!("event: message{nl}");
                                    for l in pretty.lines() { ev.push_str(&format!("data: {l}{nl}")); }
                                    ev.push_str(nl);
                                    write_pieces(&mut sock, ev.as_bytes(), o.chunky).await;
                                }
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
                                    json!({"tools":[{"name":"ping","description":"p","inputSchema":{"type":"object"}}]})
                                }
                                Some("tools/call") => {
                                    json!({"content":[{"type":"text","text":"pong"}]})
                                }
                                _ => json!({}),
                            };
                            let _ = stx
                                .send(json!({"jsonrpc":"2.0","id":id,"result":result}).to_string());
                        }
                        let _ = sock.write_all(b"HTTP/1.1 202 Accepted\r\nContent-Length: 8\r\nConnection: close\r\n\r\nAccepted").await;
                    }
                });
            }
        });
        Mock { base, seen, kill }
    }

    async fn write_pieces(sock: &mut tokio::net::TcpStream, b: &[u8], chunky: bool) {
        if !chunky {
            let _ = sock.write_all(b).await;
            return;
        }
        for c in b.chunks(3) {
            let _ = sock.write_all(c).await;
            let _ = sock.flush().await;
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    }

    async fn exercise(
        url: &str,
        headers: HashMap<HeaderName, HeaderValue>,
        bearer: Option<String>,
    ) {
        let t = connect(url, headers, bearer).await.unwrap();
        let client = ().serve(t).await.unwrap();
        let tools = client.list_tools(None).await.unwrap();
        assert_eq!(tools.tools[0].name, "ping");
        let r = client
            .call_tool(CallToolRequestParams::new("ping"))
            .await
            .unwrap();
        assert_eq!(r.content[0].as_text().unwrap().text, "pong");
        let _ = client.cancel().await;
    }

    #[tokio::test]
    async fn happy_path_relative_endpoint() {
        let m = mock(Opts::default()).await;
        exercise(&format!("{}/sse", m.base), HashMap::new(), None).await;
        let seen = m.seen.lock().unwrap();
        assert!(
            seen.iter()
                .any(|s| s.method == "POST" && s.path == "/messages?sessionId=abc")
        );
    }

    #[tokio::test]
    async fn absolute_same_origin_endpoint() {
        let m = mock(Opts {
            endpoint: "{base}/messages?sessionId=abs".into(),
            ..Default::default()
        })
        .await;
        exercise(&format!("{}/sse", m.base), HashMap::new(), None).await;
        assert!(
            m.seen
                .lock()
                .unwrap()
                .iter()
                .any(|s| s.method == "POST" && s.path == "/messages?sessionId=abs")
        );
    }

    #[tokio::test]
    async fn cross_origin_endpoint_rejected() {
        for ep in [
            "http://127.0.0.1:1/messages",
            "//evil.example/messages",
            "http://localhost:9/x",
        ] {
            let m = mock(Opts {
                endpoint: ep.into(),
                ..Default::default()
            })
            .await;
            let e = connect(
                &format!("{}/sse", m.base),
                HashMap::new(),
                Some("secret-token".into()),
            )
            .await
            .err()
            .expect(ep);
            assert!(e.to_string().contains("origin"), "{e}");
            assert!(!e.to_string().contains("secret-token"));
            assert!(!m.seen.lock().unwrap().iter().any(|s| s.method == "POST"));
        }
    }

    #[tokio::test]
    async fn headers_and_bearer_on_get_and_post() {
        let m = mock(Opts::default()).await;
        let mut h = HashMap::new();
        h.insert(
            HeaderName::from_static("x-api-key"),
            HeaderValue::from_static("k123"),
        );
        exercise(&format!("{}/sse", m.base), h, Some("tok".into())).await;
        let seen = m.seen.lock().unwrap();
        let get = seen.iter().find(|s| s.method == "GET").unwrap();
        assert_eq!(get.header("authorization"), Some("Bearer tok"));
        assert_eq!(get.header("x-api-key"), Some("k123"));
        assert_eq!(get.header("accept"), Some("text/event-stream"));
        let posts: Vec<_> = seen.iter().filter(|s| s.method == "POST").collect();
        assert!(!posts.is_empty());
        for p in posts {
            assert_eq!(p.header("authorization"), Some("Bearer tok"));
            assert_eq!(p.header("x-api-key"), Some("k123"));
        }
    }

    #[tokio::test]
    async fn chunked_crlf_stream() {
        let m = mock(Opts {
            chunky: true,
            ..Default::default()
        })
        .await;
        exercise(&format!("{}/sse", m.base), HashMap::new(), None).await;
    }

    #[tokio::test]
    async fn stream_close_before_endpoint_errors() {
        let m = mock(Opts {
            close_after_endpoint: true,
            endpoint: "/m".into(),
            ..Default::default()
        })
        .await;
        let t = connect(&format!("{}/sse", m.base), HashMap::new(), None)
            .await
            .unwrap();
        // stream already dropped: initialize must fail, not hang
        let r = tokio::time::timeout(Duration::from_secs(10), ().serve(t))
            .await
            .expect("hung");
        assert!(r.is_err());
    }

    #[tokio::test]
    async fn stream_close_ends_client() {
        let m = mock(Opts::default()).await;
        let t = connect(&format!("{}/sse", m.base), HashMap::new(), None)
            .await
            .unwrap();
        let client = ().serve(t).await.unwrap();
        client.list_tools(None).await.unwrap();
        m.kill.notify_one();
        let r = tokio::time::timeout(Duration::from_secs(10), async {
            // Wait until the client notices the close; calls then fail.
            loop {
                if client.list_tools(None).await.is_err() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await;
        assert!(r.is_ok(), "client hung after stream close");
    }

    #[test]
    fn parser_edge_cases() {
        let mut p = Parser::default();
        let mut evs = vec![];
        for c in b": c\r\nevent: x\r\ndata: a\r\ndata: b\r\n\r\ndata: no-space\rdata:\r\r\n\r\n"
            .chunks(1)
        {
            evs.extend(p.feed(c));
        }
        assert_eq!(
            evs[0],
            Event {
                name: "x".into(),
                data: "a\nb".into()
            }
        );
        assert_eq!(
            evs[1],
            Event {
                name: "message".into(),
                data: "no-space\n".into()
            }
        );
    }

    #[test]
    fn resolve() {
        let b = Url::parse("http://h:80/a/sse").unwrap();
        assert_eq!(
            resolve_endpoint(&b, "m?s=1").unwrap().as_str(),
            "http://h/a/m?s=1"
        );
        assert!(resolve_endpoint(&b, "http://h:81/m").is_err());
        assert!(resolve_endpoint(&b, "https://h/m").is_err());
    }
}
