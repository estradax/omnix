//! Mock stdio MCP server for tests.
use base64::Engine as _;
use rmcp::model::{CallToolResult, ContentBlock};
use rmcp::{
    ServerHandler, ServiceExt,
    handler::server::{router::tool::ToolRouter, wrapper::Parameters},
    schemars, tool, tool_handler, tool_router,
    transport::stdio,
};
use serde::Deserialize;

#[derive(Deserialize, schemars::JsonSchema)]
struct EchoArgs {
    text: String,
}
#[derive(Deserialize, schemars::JsonSchema)]
struct AddArgs {
    a: f64,
    b: f64,
}
#[derive(Deserialize, schemars::JsonSchema)]
struct IdArgs {
    id: String,
}
#[derive(Deserialize, schemars::JsonSchema)]
struct BigArgs {
    n: u64,
}
#[derive(Deserialize, schemars::JsonSchema)]
struct SlowArgs {
    ms: u64,
}

#[derive(Deserialize, schemars::JsonSchema)]
struct BlobArgs {
    data: String,
}

const PNG_1X1: &str = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==";

#[derive(Clone)]
#[allow(dead_code)]
struct Mock {
    tool_router: ToolRouter<Self>,
}

#[tool_router]
impl Mock {
    fn new() -> Self {
        Self {
            tool_router: Self::tool_router(),
        }
    }

    /// Echo the text back
    #[tool(description = "Echo the text back")]
    async fn echo(&self, Parameters(a): Parameters<EchoArgs>) -> String {
        a.text
    }

    /// Add two numbers
    #[tool(description = "Add two numbers")]
    async fn add(&self, Parameters(a): Parameters<AddArgs>) -> String {
        (a.a + a.b).to_string()
    }

    #[tool(description = "List items", annotations(read_only_hint = true))]
    async fn list_items(&self) -> String {
        r#"[{"id":"1","name":"one"},{"id":"2","name":"two"},{"id":"3","name":"three"}]"#.into()
    }

    #[tool(
        description = "Delete an item",
        annotations(read_only_hint = false, destructive_hint = true)
    )]
    async fn delete_item(&self, Parameters(a): Parameters<IdArgs>) -> String {
        format!("deleted {}", a.id)
    }

    #[tool(description = "Return n 'x' characters")]
    async fn big(&self, Parameters(a): Parameters<BigArgs>) -> String {
        "x".repeat(a.n as usize)
    }

    #[tool(description = "Take a screenshot", annotations(read_only_hint = true))]
    async fn screenshot(&self) -> CallToolResult {
        CallToolResult::success(vec![
            ContentBlock::image(PNG_1X1, "image/png"),
            ContentBlock::text("shot taken"),
        ])
    }

    #[tool(
        description = "Save a base64 blob",
        annotations(read_only_hint = false, destructive_hint = false)
    )]
    async fn save_blob(&self, Parameters(a): Parameters<BlobArgs>) -> String {
        match base64::engine::general_purpose::STANDARD.decode(a.data.as_bytes()) {
            Ok(b) => format!("saved {} bytes", b.len()),
            Err(e) => format!("invalid base64: {e}"),
        }
    }

    #[tool(description = "No annotations")]
    async fn no_annotations(&self) -> String {
        "ok".into()
    }

    #[tool(description = "Sleep ms milliseconds")]
    async fn slow(&self, Parameters(a): Parameters<SlowArgs>) -> String {
        tokio::time::sleep(std::time::Duration::from_millis(a.ms)).await;
        format!("slept {}", a.ms)
    }
}

#[tool_handler]
impl ServerHandler for Mock {}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let service = Mock::new().serve(stdio()).await?;
    service.waiting().await?;
    Ok(())
}
