//! E2E: `serve` answers the agent immediately; the catalog cache serves search/describe
//! while a slow upstream is still starting; execute waits for the upstream.
use rmcp::{ServiceExt, model::CallToolRequestParams, transport::TokioChildProcess};
use serde_json::{Value, json};
use std::{
    path::PathBuf,
    time::{Duration, Instant},
};

type Svc = rmcp::service::RunningService<rmcp::RoleClient, ()>;

fn tmp() -> PathBuf {
    static N: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let d = std::env::temp_dir().join(format!(
        "omnix-lazy-{}-{}",
        std::process::id(),
        N.fetch_add(1, std::sync::atomic::Ordering::SeqCst)
    ));
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// A server that takes ~3s to start: sh sleeps, then execs the mock.
fn config(dir: &std::path::Path, delay: u32) {
    let cmd = format!("sleep {delay}; exec {}", env!("CARGO_BIN_EXE_mock_mcp"));
    let cfg = json!({"servers": {"slow": {"command": "sh", "args": ["-c", cmd]}}});
    std::fs::write(dir.join("omnix.json"), cfg.to_string()).unwrap();
}

async fn start(dir: &PathBuf) -> (Svc, Instant) {
    let t0 = Instant::now();
    let mut c = tokio::process::Command::new(env!("CARGO_BIN_EXE_omnix"));
    c.arg("serve")
        .current_dir(dir)
        .env("HOME", dir)
        .env("OMNIX_CONFIG_DIR", dir.join("cfg"))
        .env_remove("OMNIX_CATALOG_CACHE");
    (
        ().serve(TokioChildProcess::new(c).unwrap()).await.unwrap(),
        t0,
    )
}

async fn call(svc: &Svc, name: &'static str, args: Value) -> String {
    let r = svc
        .call_tool(
            CallToolRequestParams::new(name).with_arguments(args.as_object().unwrap().clone()),
        )
        .await
        .unwrap();
    serde_json::to_value(&r).unwrap()["content"][0]["text"]
        .as_str()
        .unwrap()
        .to_string()
}

#[tokio::test]
async fn handshake_is_immediate_and_cache_answers_while_upstream_starts() {
    let dir = tmp();
    config(&dir, 3);

    // First run: no cache. The handshake must not wait for the 3s upstream.
    let (svc, t0) = start(&dir).await;
    assert!(
        t0.elapsed() < Duration::from_millis(2500),
        "handshake waited for upstreams: {:?}",
        t0.elapsed()
    );
    // search has nothing cached, so it waits for the upstream, then answers (and writes the cache).
    let out = call(&svc, "search", json!({"query": "add"})).await;
    assert!(out.contains("slow.add"), "{out}");
    assert!(
        t0.elapsed() >= Duration::from_secs(2),
        "should have waited for the upstream: {:?}",
        t0.elapsed()
    );
    drop(svc);
    tokio::time::sleep(Duration::from_millis(300)).await;

    // Second run: cache exists. search/describe answer fast, flagged as cached.
    let (svc, t1) = start(&dir).await;
    let out = call(&svc, "search", json!({"query": "add"})).await;
    assert!(
        out.contains("slow.add") && out.contains("from cache"),
        "{out}"
    );
    let d = call(&svc, "describe", json!({"tools": ["slow.add"]})).await;
    assert!(
        d.contains("slow.add(args: { a: number; b: number })"),
        "{d}"
    );
    assert!(
        t1.elapsed() < Duration::from_millis(2500),
        "cache did not answer fast: {:?}",
        t1.elapsed()
    );
    // execute must wait for the real connection, then work.
    let r = call(
        &svc,
        "execute",
        json!({"code": "return await slow.add({a: 2, b: 3})"}),
    )
    .await;
    assert!(r.contains("result:") && r.contains('5'), "{r}");
    assert!(
        t1.elapsed() >= Duration::from_secs(2),
        "execute should have waited for the upstream: {:?}",
        t1.elapsed()
    );
    // Once live, the answer is no longer marked as cached.
    let out = call(&svc, "search", json!({"query": "add"})).await;
    assert!(!out.contains("from cache"), "{out}");
}

#[tokio::test]
async fn cache_is_not_written_when_an_upstream_failed_and_holds_no_secrets() {
    let dir = tmp();
    let cfg = json!({"servers": {
        "ok": {"command": env!("CARGO_BIN_EXE_mock_mcp"), "env": {"API_TOKEN": "s3cr3t-value"}},
        "bad": {"command": "/definitely/not/here"}}});
    std::fs::write(dir.join("omnix.json"), cfg.to_string()).unwrap();
    let (svc, _) = start(&dir).await;
    let out = call(&svc, "search", json!({"query": "add"})).await;
    assert!(
        out.contains("ok.add") && out.contains("unavailable servers") && out.contains("bad"),
        "{out}"
    );
    drop(svc);
    let cache_dir = dir.join("cfg/catalog-cache");
    let n = std::fs::read_dir(&cache_dir)
        .map(|d| d.count())
        .unwrap_or(0);
    assert_eq!(n, 0, "a partial catalog must not be cached");

    // With everything healthy, a cache is written and contains no credentials.
    let cfg = json!({"servers": {"ok": {"command": env!("CARGO_BIN_EXE_mock_mcp"), "env": {"API_TOKEN": "s3cr3t-value"}}}});
    std::fs::write(dir.join("omnix.json"), cfg.to_string()).unwrap();
    let (svc, _) = start(&dir).await;
    let _ = call(&svc, "execute", json!({"code": "return 1"})).await; // forces connect to finish
    tokio::time::sleep(Duration::from_millis(300)).await;
    drop(svc);
    let files: Vec<_> = std::fs::read_dir(&cache_dir).unwrap().collect();
    assert_eq!(files.len(), 1);
    let text = std::fs::read_to_string(files[0].as_ref().unwrap().path()).unwrap();
    assert!(
        !text.contains("s3cr3t-value") && !text.contains("API_TOKEN"),
        "cache leaked credentials: {text}"
    );
}
