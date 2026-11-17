//! E2E: policy (read-only, allow/deny, hook), audit log, binary handles.
use rmcp::{ServiceExt, model::CallToolRequestParams, transport::TokioChildProcess};
use serde_json::{Value, json};
use std::path::PathBuf;

type Svc = rmcp::service::RunningService<rmcp::RoleClient, ()>;

fn tmp() -> PathBuf {
    static N: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let d = std::env::temp_dir().join(format!(
        "omnix-pol-{}-{}",
        std::process::id(),
        N.fetch_add(1, std::sync::atomic::Ordering::SeqCst)
    ));
    std::fs::create_dir_all(&d).unwrap();
    d
}

async fn gateway(policy: Value) -> (Svc, PathBuf) {
    let dir = tmp();
    let cfg =
        json!({"servers": {"mock": {"command": env!("CARGO_BIN_EXE_mock_mcp")}}, "policy": policy});
    std::fs::write(dir.join("omnix.json"), cfg.to_string()).unwrap();
    let mut c = tokio::process::Command::new(env!("CARGO_BIN_EXE_omnix"));
    c.arg("serve").current_dir(&dir).env("HOME", &dir);
    (
        ().serve(TokioChildProcess::new(c).unwrap()).await.unwrap(),
        dir,
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
async fn read_only_hides_and_blocks_writes_and_unannotated() {
    let (svc, _d) = gateway(json!({"read_only": true})).await;
    let found = call(&svc, "search", json!({"query": "item", "limit": 20})).await;
    assert!(found.contains("mock.list_items"), "{found}");
    assert!(!found.contains("delete_item"), "{found}");
    assert_eq!(
        call(&svc, "search", json!({"query": "no_annotations"})).await,
        "no matches"
    );
    // Even though hidden from search, calling it from the sandbox is refused.
    let out = call(
        &svc,
        "execute",
        json!({"code": "return await mock.delete_item({id: 'x'})"}),
    )
    .await;
    assert!(out.contains("error:") && out.contains("policy:"), "{out}");
    let out = call(
        &svc,
        "execute",
        json!({"code": "return (await mock.list_items({})).length"}),
    )
    .await;
    assert!(out.contains("result: 3"), "{out}");
}

#[tokio::test]
async fn explicit_allow_and_deny_patterns() {
    let (svc, _d) =
        gateway(json!({"allow": ["mock.add", "mock.delete*"], "deny": ["mock.delete*"]})).await;
    let out = call(
        &svc,
        "execute",
        json!({"code": "return (await mock.add({a:1,b:2}))"}),
    )
    .await;
    assert!(out.contains("result:"), "{out}");
    let out = call(
        &svc,
        "execute",
        json!({"code": "return await mock.echo({text:'hi'})"}),
    )
    .await;
    assert!(out.contains("not in the policy allowlist"), "{out}");
    let out = call(
        &svc,
        "execute",
        json!({"code": "return await mock.delete_item({id:'1'})"}),
    )
    .await;
    assert!(out.contains("denied by policy"), "{out}");
}

#[tokio::test]
async fn before_call_hook_blocks_and_audit_log_records_without_values() {
    let dir0 = tmp();
    let log = dir0.join("audit.jsonl");
    let (svc, _d) = gateway(json!({"before_call": "grep -q hunter2 && { echo secrets not allowed; exit 1; }; exit 0", "audit_log": log})).await;
    let ok = call(
        &svc,
        "execute",
        json!({"code": "return await mock.echo({text:'fine'})"}),
    )
    .await;
    assert!(ok.contains("result:"), "{ok}");
    let bad = call(
        &svc,
        "execute",
        json!({"code": "return await mock.echo({text:'hunter2'})"}),
    )
    .await;
    assert!(bad.contains("secrets not allowed"), "{bad}");
    let text = std::fs::read_to_string(&log).unwrap();
    assert!(
        text.contains("\"decision\":\"allow\"") && text.contains("\"decision\":\"block\""),
        "{text}"
    );
    assert!(text.contains("\"arg_keys\":[\"text\"]"));
    assert!(
        !text.contains("hunter2") && !text.contains("fine"),
        "audit log leaked argument values: {text}"
    );
}

#[tokio::test]
async fn binary_results_become_handles_and_flow_between_tools() {
    let (svc, _d) = gateway(json!({})).await;
    let shot = call(
        &svc,
        "execute",
        json!({"code": "return await mock.screenshot({})"}),
    )
    .await;
    assert!(shot.contains("$handle"), "{shot}");
    assert!(shot.contains("image/png"), "{shot}");
    assert!(
        !shot.contains("iVBORw0KGgo"),
        "base64 image data leaked to the model: {shot}"
    );
    // The handle is resolved to its bytes host-side when passed to another tool.
    let saved = call(&svc, "execute", json!({"code":
        "const s = await mock.screenshot({}); const img = s.content.find(c => c.$handle); return await mock.save_blob({data: img})"})).await;
    assert!(
        saved.contains("saved ") && saved.contains(" bytes") && !saved.contains("invalid"),
        "{saved}"
    );
    assert!(!saved.contains("iVBORw0KGgo"), "{saved}");
}
