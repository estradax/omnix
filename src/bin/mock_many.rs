//! Deterministic mock MCP server with a generated tool list, for benchmarking.
//! Usage: mock_many --server-name NAME --tools N --seed S
use rmcp::{
    ErrorData as McpError, RoleServer, ServerHandler, ServiceExt, model::*,
    service::RequestContext, transport::stdio,
};
use serde_json::{Map, Value, json};

/// splitmix64: tiny deterministic PRNG.
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E3779B97F4A7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
        z ^ (z >> 31)
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
    fn pick<'a>(&mut self, xs: &[&'a str]) -> &'a str {
        xs[self.below(xs.len())]
    }
}

const VERBS: &[&str] = &[
    "create", "update", "delete", "fetch", "search", "archive", "export", "import", "sync",
    "validate", "assign", "merge", "tag", "publish", "rename",
];
const NOUNS: &[&str] = &[
    "ticket",
    "invoice",
    "project",
    "customer",
    "document",
    "branch",
    "deployment",
    "comment",
    "workflow",
    "channel",
    "report",
    "milestone",
    "subscription",
    "contact",
    "pipeline",
    "release",
];
const PARAMS: &[&str] = &[
    "title",
    "owner",
    "label",
    "query",
    "priority",
    "limit",
    "offset",
    "dry_run",
    "include_archived",
    "tags",
    "filters",
    "region",
    "format",
    "assignee",
    "due_date",
    "page_size",
    "notify",
    "metadata",
];
const WORDS: &[&str] = &[
    "the",
    "this",
    "operation",
    "returns",
    "a",
    "structured",
    "response",
    "for",
    "given",
    "resource",
    "identifier",
    "within",
    "workspace",
    "supports",
    "optional",
    "filtering",
    "pagination",
    "and",
    "sorting",
    "requires",
    "valid",
    "permissions",
    "on",
    "target",
    "account",
    "records",
    "are",
    "processed",
    "in",
    "order",
    "of",
    "creation",
    "time",
    "unless",
    "specified",
    "otherwise",
    "by",
    "caller",
    "metadata",
    "may",
    "be",
    "attached",
    "to",
    "each",
    "entry",
    "errors",
    "reported",
    "with",
    "details",
    "when",
    "limits",
    "exceeded",
    "use",
    "carefully",
    "changes",
    "propagate",
    "downstream",
    "systems",
    "asynchronously",
    "results",
    "cached",
    "briefly",
    "to",
    "reduce",
    "latency",
];

fn description(r: &mut Rng, verb: &str, noun: &str) -> String {
    let n = 20 + r.below(41);
    let mut s = format!("{} a {}:", verb[..1].to_uppercase() + &verb[1..], noun);
    for _ in 0..n {
        s.push(' ');
        s.push_str(r.pick(WORDS));
    }
    s.push('.');
    s
}

fn param_schema(r: &mut Rng, name: &str) -> Value {
    let d = format!(
        "The {} {} {} {}",
        r.pick(WORDS),
        name.replace('_', " "),
        r.pick(WORDS),
        r.pick(WORDS)
    );
    match r.below(6) {
        0 => json!({"type":"string","description":d}),
        1 => json!({"type":"integer","description":d,"minimum":0,"maximum":1000}),
        2 => json!({"type":"boolean","description":d}),
        3 => {
            let vals: Vec<&str> = (0..2 + r.below(3))
                .map(|_| {
                    r.pick(&[
                        "low", "medium", "high", "urgent", "open", "closed", "pending", "draft",
                    ])
                })
                .collect();
            let mut u: Vec<&str> = vec![];
            for v in vals {
                if !u.contains(&v) {
                    u.push(v);
                }
            }
            json!({"type":"string","enum":u,"description":d})
        }
        4 => json!({"type":"array","items":{"type":"string"},"description":d}),
        _ => json!({"type":"object","description":d,"properties":{
            "key":{"type":"string","description":"Field key"},
            "value":{"type":"string","description":"Field value"},
            "enabled":{"type":"boolean"}},"required":["key"]}),
    }
}

fn gen_tools(seed: u64, n: usize) -> Vec<Tool> {
    let mut r = Rng(seed);
    let mut seen = std::collections::HashSet::new();
    seen.insert("list_records".to_string());
    seen.insert("get_record".to_string());
    let mut tools = vec![];
    while tools.len() < n {
        let (v, no) = (r.pick(VERBS), r.pick(NOUNS));
        let mut name = format!("{v}_{no}");
        let mut k = 2;
        while !seen.insert(name.clone()) {
            name = format!("{v}_{no}_{k}");
            k += 1;
        }
        let desc = description(&mut r, v, no);
        let np = 2 + r.below(7);
        let mut props = Map::new();
        let mut req = vec![];
        let mut pool: Vec<&str> = PARAMS.to_vec();
        for i in 0..np {
            let p = pool.remove(r.below(pool.len()));
            props.insert(p.to_string(), param_schema(&mut r, p));
            if i < 2 {
                req.push(p);
            }
        }
        let schema = json!({"type":"object","properties":props,"required":req});
        let Value::Object(m) = schema else {
            unreachable!()
        };
        let mut t = Tool::new(name, desc, m);
        t.annotations =
            Some(ToolAnnotations::new().read_only(matches!(v, "fetch" | "search" | "validate")));
        tools.push(t);
    }
    tools.push(Tool::new("list_records", "List the first `count` records of the dataset as a JSON array. Each record has id, name, status, email and notes.",
        json!({"type":"object","properties":{"count":{"type":"integer","description":"Number of records to return"}},"required":["count"]}).as_object().unwrap().clone())
        .with_annotations(ToolAnnotations::new().read_only(true)));
    tools.push(Tool::new("get_record", "Get a single record by numeric id.",
        json!({"type":"object","properties":{"id":{"type":"integer","description":"Record id"}},"required":["id"]}).as_object().unwrap().clone())
        .with_annotations(ToolAnnotations::new().read_only(true)));
    tools
}

/// Deterministic ~300 byte record. status is 'active' for ids divisible by 3 or 7... (id%3==0 || id%7==0).
fn record(id: i64) -> Value {
    let status = if id % 3 == 0 || id % 7 == 0 {
        "active"
    } else if id % 2 == 0 {
        "inactive"
    } else {
        "pending"
    };
    let mut r = Rng(id as u64 * 7919 + 1);
    let mut notes = String::new();
    for _ in 0..22 {
        if !notes.is_empty() {
            notes.push(' ');
        }
        notes.push_str(r.pick(WORDS));
    }
    json!({"id": id, "name": format!("Person {:04}", id), "status": status, "email": format!("person{id}@example.com"), "notes": notes})
}

struct Mock {
    tools: Vec<Tool>,
}

impl ServerHandler for Mock {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
    }
    async fn list_tools(
        &self,
        _r: Option<PaginatedRequestParams>,
        _c: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, McpError> {
        Ok(ListToolsResult {
            tools: self.tools.clone(),
            ..Default::default()
        })
    }
    async fn call_tool(
        &self,
        req: CallToolRequestParams,
        _c: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, McpError> {
        let a = req.arguments.unwrap_or_default();
        let int = |k: &str| a.get(k).and_then(|v| v.as_i64()).unwrap_or(0);
        let text = match &*req.name {
            "list_records" => Value::Array((1..=int("count")).map(record).collect()).to_string(),
            "get_record" => record(int("id")).to_string(),
            other => format!("{{\"ok\":true,\"tool\":\"{other}\"}}"),
        };
        Ok(CallToolResult::success(vec![ContentBlock::text(text)]).into())
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let (mut n, mut seed) = (10usize, 1u64);
    let args: Vec<String> = std::env::args().collect();
    let mut i = 1;
    while i + 1 < args.len() {
        match args[i].as_str() {
            "--tools" => n = args[i + 1].parse()?,
            "--seed" => seed = args[i + 1].parse()?,
            "--server-name" => {}
            _ => {}
        }
        i += 2;
    }
    // Mix the server name into the seed so servers differ but stay deterministic.
    let name_hash = args
        .iter()
        .position(|a| a == "--server-name")
        .and_then(|p| args.get(p + 1))
        .map(|s| {
            s.bytes()
                .fold(0u64, |h, b| h.wrapping_mul(31).wrapping_add(b as u64))
        })
        .unwrap_or(0);
    let service = Mock {
        tools: gen_tools(seed ^ name_hash.wrapping_mul(0x9E37), n),
    }
    .serve(stdio())
    .await?;
    service.waiting().await?;
    Ok(())
}
