use rmcp::{ServiceExt, model::CallToolRequestParams, transport::TokioChildProcess};
use serde_json::json;

async fn gateway() -> (
    rmcp::service::RunningService<rmcp::RoleClient, ()>,
    tempdir::Dir,
) {
    let dir = tempdir::Dir::new();
    let cfg = json!({"servers": {"mock": {"command": env!("CARGO_BIN_EXE_mock_mcp")}}});
    std::fs::write(dir.path().join("omnix.json"), cfg.to_string()).unwrap();
    let mut c = tokio::process::Command::new(env!("CARGO_BIN_EXE_omnix"));
    c.arg("serve")
        .current_dir(dir.path())
        .env("HOME", dir.path())
        .env("OMNIX_CONFIG_DIR", dir.path().join("cfg"))
        .env("OMNIX_CATALOG_CACHE", "off");
    let svc = ().serve(TokioChildProcess::new(c).unwrap()).await.unwrap();
    (svc, dir)
}

async fn call(
    svc: &rmcp::service::RunningService<rmcp::RoleClient, ()>,
    name: &'static str,
    args: serde_json::Value,
) -> String {
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

mod tempdir {
    pub struct Dir(std::path::PathBuf);
    impl Dir {
        pub fn new() -> Self {
            let p = std::env::temp_dir().join(
                format!(
                    "omnix-e2e-{}-{:?}",
                    std::process::id(),
                    std::thread::current().id()
                )
                .replace(['(', ')', ' '], ""),
            );
            std::fs::create_dir_all(&p).unwrap();
            Dir(p)
        }
        pub fn path(&self) -> &std::path::Path {
            &self.0
        }
    }
    impl Drop for Dir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
}

#[tokio::test]
async fn lists_only_three_gateway_tools() {
    let (svc, _d) = gateway().await;
    let tools = svc.list_all_tools().await.unwrap();
    let mut names: Vec<_> = tools.iter().map(|t| t.name.to_string()).collect();
    names.sort();
    assert_eq!(names, ["describe", "execute", "search"]);
}

#[tokio::test]
async fn search_finds_upstream_tool() {
    let (svc, _d) = gateway().await;
    let out = call(&svc, "search", json!({"query": "delete item"})).await;
    assert!(out.starts_with("mock.delete_item"), "{out}");
    let none = call(&svc, "search", json!({"query": "zzzzz"})).await;
    assert!(none.starts_with("no matches"), "{none}");
}

#[tokio::test]
async fn describe_returns_signature() {
    let (svc, _d) = gateway().await;
    let out = call(
        &svc,
        "describe",
        json!({"tools": ["mock.add", "mock.nope"]}),
    )
    .await;
    assert!(
        out.contains("mock.add(args: { a: number; b: number })"),
        "{out}"
    );
    assert!(out.contains("unknown tool: mock.nope"), "{out}");
}

#[tokio::test]
async fn execute_chains_calls_without_leaking_intermediates() {
    let (svc, _d) = gateway().await;
    let out = call(&svc, "execute", json!({"code":
        "const items = await mock.list_items({}); const s = await mock.add({a: items.length, b: 10}); console.log('n', items.length); return s"})).await;
    assert!(out.contains("result: "), "{out}");
    assert!(out.contains("n 3"), "{out}");
    assert!(out.contains("calls: mock.list_items, mock.add"), "{out}");
}

#[tokio::test]
async fn execute_state_persists_and_big_result_truncates() {
    let (svc, _d) = gateway().await;
    call(&svc, "execute", json!({"code": "state.x = 7"})).await;
    assert!(
        call(&svc, "execute", json!({"code": "return state.x"}))
            .await
            .contains("result: 7")
    );
    let big = call(
        &svc,
        "execute",
        json!({"code": "return await mock.big({n: 100000})"}),
    )
    .await;
    assert!(big.contains("truncated"), "{}", &big[..big.len().min(200)]);
    assert!(big.len() < 40_000);
}

#[tokio::test]
async fn execute_errors_are_reported() {
    let (svc, _d) = gateway().await;
    let out = call(&svc, "execute", json!({"code": "throw new Error('nope')"})).await;
    assert!(out.contains("error:") && out.contains("nope"), "{out}");
}
