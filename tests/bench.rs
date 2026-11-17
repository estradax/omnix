//! Offline context-cost benchmark: direct tool loading vs the omnix gateway.
//! Run: cargo test --test bench -- --ignored --nocapture
//! Token estimates are chars/4 (rough). To use a real tokenizer, replace `est_tokens` below
//! (e.g. call a tiktoken/Anthropic count_tokens binding on the same strings).
use rmcp::{
    ServiceExt, model::CallToolRequestParams, service::RunningService, transport::TokioChildProcess,
};
use serde_json::{Value, json};
use std::time::{Duration, Instant};

type Client = RunningService<rmcp::RoleClient, ()>;

const SEED: u64 = 42;

fn est_tokens(s: &str) -> usize {
    s.chars().count().div_ceil(4)
}

struct Dir(std::path::PathBuf);
impl Drop for Dir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

async fn spawn(mut c: tokio::process::Command) -> Client {
    c.stderr(std::process::Stdio::null());
    ().serve(TokioChildProcess::new(c).unwrap()).await.unwrap()
}

fn isolated(bin: &str, dir: &std::path::Path) -> tokio::process::Command {
    let mut c = tokio::process::Command::new(bin);
    c.env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", dir)
        .env("OMNIX_CONFIG_DIR", dir)
        .current_dir(dir);
    c
}

async fn call(c: &Client, name: &str, args: Value) -> (String, String) {
    let r = c
        .call_tool(
            CallToolRequestParams::new(name.to_string())
                .with_arguments(args.as_object().unwrap().clone()),
        )
        .await
        .unwrap();
    let v = serde_json::to_value(&r).unwrap();
    let text = v["content"][0]["text"].as_str().unwrap_or("").to_string();
    // What a client puts in context: the serialized content blocks.
    (text, v["content"].to_string())
}

struct Flow {
    defs: usize,
    task: usize,
    defs_tok: usize,
    task_tok: usize,
    ms: u128,
    answer: Value,
    detail: Vec<(String, usize)>,
}

struct Report {
    n_tools: usize,
    direct: Flow,
    gw: Flow,
    cold_ms: u128,
    md: String,
}

fn ratio(a: usize, b: usize) -> String {
    format!("{:.1}x", a as f64 / b.max(1) as f64)
}

async fn run(n_servers: usize, tools_each: usize, records: usize) -> Report {
    let mock = env!("CARGO_BIN_EXE_mock_many");
    let omnix = env!("CARGO_BIN_EXE_omnix");
    let dir = std::env::temp_dir().join(format!(
        "omnix-bench-{}-{}-{}",
        std::process::id(),
        n_servers,
        tools_each
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let _g = Dir(dir.clone());
    let sargs = |i: usize| {
        vec![
            "--server-name".to_string(),
            format!("s{i}"),
            "--tools".into(),
            tools_each.to_string(),
            "--seed".into(),
            SEED.to_string(),
        ]
    };
    let mut servers = serde_json::Map::new();
    for i in 1..=n_servers {
        servers.insert(format!("s{i}"), json!({"command": mock, "args": sargs(i)}));
    }
    std::fs::write(
        dir.join("omnix.json"),
        json!({"servers": servers}).to_string(),
    )
    .unwrap();

    // ---- (A) DIRECT ----
    let t0 = Instant::now();
    let mut defs_json = vec![];
    let mut s1: Option<Client> = None;
    for i in 1..=n_servers {
        let mut c = tokio::process::Command::new(mock);
        c.args(sargs(i));
        let cl = spawn(c).await;
        for t in cl.list_all_tools().await.unwrap() {
            let v = serde_json::to_value(&t).unwrap();
            // As a client would present it: namespaced name, description, inputSchema.
            defs_json.push(json!({"name": format!("s{i}__{}", t.name), "description": v["description"], "input_schema": v["inputSchema"]}).to_string());
        }
        if i == 1 {
            s1 = Some(cl);
        }
    }
    let n_tools = defs_json.len();
    let defs_str = defs_json.join("\n");
    let s1 = s1.unwrap();
    let call_args = json!({"count": records});
    let (text, content_json) = call(&s1, "list_records", call_args.clone()).await;
    let recs: Vec<Value> = serde_json::from_str(&text).unwrap();
    let active: Vec<&Value> = recs.iter().filter(|r| r["status"] == "active").collect();
    let direct_answer = json!({"count": active.len(), "first3": active.iter().take(3).map(|r| r["name"].clone()).collect::<Vec<_>>()});
    let call_str = json!({"name": "s1__list_records", "arguments": call_args}).to_string();
    let direct_task = call_str.len() + content_json.len();
    let direct = Flow {
        defs: defs_str.len(),
        task: direct_task,
        defs_tok: est_tokens(&defs_str),
        task_tok: est_tokens(&call_str) + est_tokens(&content_json),
        ms: t0.elapsed().as_millis(),
        answer: direct_answer.clone(),
        detail: vec![
            ("list_records call".into(), call_str.len()),
            ("list_records full result".into(), content_json.len()),
        ],
    };

    // ---- (B) GATEWAY ----
    let t0 = Instant::now();
    let mut c = isolated(omnix, &dir);
    c.arg("serve");
    let gw = spawn(c).await;
    let gtools = gw.list_all_tools().await.unwrap();
    let cold_ms = t0.elapsed().as_millis();
    let gdefs: Vec<String> = gtools
        .iter()
        .map(|t| {
            let v = serde_json::to_value(t).unwrap();
            json!({"name": v["name"], "description": v["description"], "input_schema": v["inputSchema"]}).to_string()
        })
        .collect();
    let gdefs_str = gdefs.join("\n");
    let t1 = Instant::now();
    let code = format!(
        "const rs = await s1.list_records({{count: {records}}}); const a = rs.filter(r => r.status === 'active'); return {{count: a.length, first3: a.slice(0, 3).map(r => r.name)}};"
    );
    let steps = [
        ("search", json!({"query": "list records", "limit": 5})),
        ("describe", json!({"tools": ["s1.list_records"]})),
        ("execute", json!({"code": code})),
    ];
    let (mut gtask, mut gtask_tok, mut detail, mut exec_text) = (0, 0, vec![], String::new());
    for (name, args) in steps {
        let a = json!({"name": name, "arguments": args}).to_string();
        let (text, cj) = call(&gw, name, args).await;
        gtask += a.len() + cj.len();
        gtask_tok += est_tokens(&a) + est_tokens(&cj);
        detail.push((format!("{name} call"), a.len()));
        detail.push((format!("{name} result"), cj.len()));
        if name == "search" {
            assert!(
                text.contains("s1.list_records"),
                "search missed target: {text}"
            );
        }
        exec_text = text;
    }
    let gw_ms = t1.elapsed().as_millis();
    let body = exec_text
        .strip_prefix("result: ")
        .unwrap_or_else(|| panic!("unexpected execute output: {exec_text}"));
    let body = body.split("\n\n").next().unwrap();
    let gw_answer: Value = serde_json::from_str(body).unwrap();
    let gateway = Flow {
        defs: gdefs_str.len(),
        task: gtask,
        defs_tok: est_tokens(&gdefs_str),
        task_tok: gtask_tok,
        ms: cold_ms + gw_ms,
        answer: gw_answer,
        detail,
    };

    let d = &direct;
    let g = &gateway;
    let mut md = String::new();
    md += &format!(
        "## omnix benchmark: {n_servers} servers x {tools_each} generated tools (+2 real each) = {n_tools} tools, {records} records\n\n"
    );
    md += "Tokens are estimated as chars/4 (approximation).\n\n";
    md += "| Row | Direct bytes | Gateway bytes | Ratio (B) | Direct ~tokens | Gateway ~tokens | Ratio (tok) |\n|---|---:|---:|---:|---:|---:|---:|\n";
    let rows = [
        ("Definitions only", d.defs, g.defs, d.defs_tok, g.defs_tok),
        ("Task flow", d.task, g.task, d.task_tok, g.task_tok),
        (
            "Total",
            d.defs + d.task,
            g.defs + g.task,
            d.defs_tok + d.task_tok,
            g.defs_tok + g.task_tok,
        ),
    ];
    for (n, db, gb, dt, gt) in rows {
        md += &format!(
            "| {n} | {db} | {gb} | {} | {dt} | {gt} | {} |\n",
            ratio(db, gb),
            ratio(dt, gt)
        );
    }
    md += &format!("\nAnswer (both): `{}`\n\n", d.answer);
    md += "Task-flow breakdown (bytes):\n\n";
    for (n, b) in d
        .detail
        .iter()
        .map(|x| ("direct: ", x))
        .chain(g.detail.iter().map(|x| ("gateway: ", x)))
    {
        md += &format!("- {n}{}: {}\n", b.0, b.1);
    }
    md += &format!(
        "\nWall-clock (informational, not deterministic): direct {} ms (spawn {n_servers} servers + list + call); gateway {} ms (incl. cold start); gateway cold start (spawn + initialize + tools/list) {} ms.\n",
        d.ms, g.ms, cold_ms
    );
    let _ = Duration::ZERO;
    Report {
        n_tools,
        direct,
        gw: gateway,
        cold_ms,
        md,
    }
}

fn check(r: &Report) {
    assert_eq!(
        r.direct.answer, r.gw.answer,
        "gateway answer differs from direct computation"
    );
    assert!(
        r.gw.defs + r.gw.task < r.direct.defs + r.direct.task,
        "gateway total context not smaller than direct"
    );
    let _ = (r.n_tools, r.cold_ms);
}

#[tokio::test]
async fn benchmark_smoke() {
    let r = run(2, 5, 50).await;
    println!("{}", r.md);
    check(&r);
}

#[tokio::test]
#[ignore]
async fn benchmark() {
    let r = run(5, 20, 500).await;
    println!("{}", r.md);
    check(&r);
    std::fs::create_dir_all("target").unwrap();
    std::fs::write("target/bench-report.md", &r.md).unwrap();
}
