//! `omnix setup`: point coding agents at the gateway.
//!
//! For each detected agent config: show a diff, ask, back up, then replace the agent's MCP
//! servers with a single `omnix` entry and move the originals into omnix's native config so
//! no tool is lost. `setup --remove` surgically restores the moved servers (it does not
//! overwrite the file from a backup, so later edits by the agent survive).
//!
//! Safety rules: never write without confirmation (`--yes` to skip the prompt, `--dry-run`
//! to only print); skip files that contain comments (JSONC) instead of destroying them,
//! printing a snippet to paste; preserve every unknown key; write atomically.
//!
//! NOTE: agent schemas below are from documentation recall and are NOT all verified against
//! current vendor docs (see `Spec::verified`). The diff + backup + undo flow exists for that reason.

use crate::{config, store};
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use std::{
    io::{BufRead, IsTerminal, Write},
    path::{Path, PathBuf},
};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Fmt {
    Json,
    Toml,
}

#[derive(Clone, Debug)]
pub struct Target {
    pub path: PathBuf,
    /// Path to the servers map inside the document, e.g. ["mcpServers"] or ["projects", "/abs", "mcpServers"].
    pub key: Vec<String>,
    pub fmt: Fmt,
    /// Servers from this file go to the project's omnix.json (true) or the global config (false).
    pub project: bool,
}

pub struct Spec {
    pub id: &'static str,
    pub label: &'static str,
    /// Whether the schema was confirmed against current vendor docs.
    pub verified: bool,
    pub targets: fn(&Env) -> Vec<Target>,
    /// The `omnix` entry in this agent's schema.
    pub entry: fn(exe: &str) -> Value,
    /// Normalise one of this agent's server objects into the generic shape `config::server_from_value` reads.
    pub pre: fn(&Value) -> Value,
}

pub struct Env {
    pub home: PathBuf,
    pub cwd: PathBuf,
}

fn t(path: PathBuf, key: &[&str], fmt: Fmt, project: bool) -> Target {
    Target {
        path,
        key: key.iter().map(|s| s.to_string()).collect(),
        fmt,
        project,
    }
}

fn stdio_entry(exe: &str) -> Value {
    json!({"command": exe, "args": ["serve"]})
}
fn id(v: &Value) -> Value {
    v.clone()
}

fn vscode_user_dir(e: &Env) -> PathBuf {
    if cfg!(target_os = "macos") {
        e.home.join("Library/Application Support/Code/User")
    } else {
        e.home.join(".config/Code/User")
    }
}

pub fn specs() -> Vec<Spec> {
    vec![
        Spec {
            id: "claude-code",
            label: "Claude Code",
            verified: false,
            targets: |e| {
                let mut v = vec![
                    t(
                        e.home.join(".claude.json"),
                        &["mcpServers"],
                        Fmt::Json,
                        false,
                    ),
                    t(e.cwd.join(".mcp.json"), &["mcpServers"], Fmt::Json, true),
                ];
                // Local-scope servers live under projects["<abs cwd>"].mcpServers.
                v.push(Target {
                    path: e.home.join(".claude.json"),
                    key: vec![
                        "projects".into(),
                        e.cwd.display().to_string(),
                        "mcpServers".into(),
                    ],
                    fmt: Fmt::Json,
                    project: true,
                });
                v
            },
            entry: |exe| json!({"type": "stdio", "command": exe, "args": ["serve"]}),
            pre: id,
        },
        Spec {
            id: "cursor",
            label: "Cursor",
            verified: false,
            targets: |e| {
                vec![
                    t(
                        e.home.join(".cursor/mcp.json"),
                        &["mcpServers"],
                        Fmt::Json,
                        false,
                    ),
                    t(
                        e.cwd.join(".cursor/mcp.json"),
                        &["mcpServers"],
                        Fmt::Json,
                        true,
                    ),
                ]
            },
            entry: stdio_entry,
            pre: id,
        },
        Spec {
            id: "vscode",
            label: "VS Code / Copilot",
            verified: false,
            targets: |e| {
                vec![
                    t(
                        vscode_user_dir(e).join("mcp.json"),
                        &["servers"],
                        Fmt::Json,
                        false,
                    ),
                    t(
                        e.cwd.join(".vscode/mcp.json"),
                        &["servers"],
                        Fmt::Json,
                        true,
                    ),
                ]
            },
            entry: |exe| json!({"type": "stdio", "command": exe, "args": ["serve"]}),
            pre: id,
        },
        Spec {
            id: "codex",
            label: "OpenAI Codex CLI",
            verified: false,
            targets: |e| {
                let base = std::env::var("CODEX_HOME")
                    .map(PathBuf::from)
                    .unwrap_or_else(|_| e.home.join(".codex"));
                vec![t(
                    base.join("config.toml"),
                    &["mcp_servers"],
                    Fmt::Toml,
                    false,
                )]
            },
            entry: stdio_entry,
            pre: id,
        },
        Spec {
            id: "opencode",
            label: "OpenCode",
            verified: false,
            targets: |e| {
                vec![
                    t(
                        e.home.join(".config/opencode/opencode.json"),
                        &["mcp"],
                        Fmt::Json,
                        false,
                    ),
                    t(e.cwd.join("opencode.json"), &["mcp"], Fmt::Json, true),
                ]
            },
            entry: |exe| json!({"type": "local", "command": [exe, "serve"], "enabled": true}),
            pre: id,
        },
        Spec {
            id: "windsurf",
            label: "Windsurf",
            verified: false,
            targets: |e| {
                vec![t(
                    e.home.join(".codeium/windsurf/mcp_config.json"),
                    &["mcpServers"],
                    Fmt::Json,
                    false,
                )]
            },
            entry: stdio_entry,
            pre: id,
        },
        Spec {
            id: "gemini",
            label: "Gemini CLI",
            verified: false,
            targets: |e| {
                vec![
                    t(
                        e.home.join(".gemini/settings.json"),
                        &["mcpServers"],
                        Fmt::Json,
                        false,
                    ),
                    t(
                        e.cwd.join(".gemini/settings.json"),
                        &["mcpServers"],
                        Fmt::Json,
                        true,
                    ),
                ]
            },
            entry: stdio_entry,
            // In Gemini, a bare `url` means SSE (streamable HTTP uses `httpUrl`).
            pre: |v| {
                let mut v = v.clone();
                if let Some(o) = v.as_object_mut()
                    && o.contains_key("url")
                    && !o.contains_key("httpUrl")
                    && !o.contains_key("type")
                {
                    o.insert("type".into(), "sse".into());
                }
                v
            },
        },
        Spec {
            id: "zed",
            label: "Zed",
            verified: false,
            targets: |e| {
                vec![t(
                    e.home.join(".config/zed/settings.json"),
                    &["context_servers"],
                    Fmt::Json,
                    false,
                )]
            },
            entry: |exe| json!({"source": "custom", "command": exe, "args": ["serve"]}),
            pre: id,
        },
        Spec {
            id: "kiro",
            label: "Kiro",
            verified: false,
            targets: |e| {
                vec![
                    t(
                        e.home.join(".kiro/settings/mcp.json"),
                        &["mcpServers"],
                        Fmt::Json,
                        false,
                    ),
                    t(
                        e.cwd.join(".kiro/settings/mcp.json"),
                        &["mcpServers"],
                        Fmt::Json,
                        true,
                    ),
                ]
            },
            entry: stdio_entry,
            pre: id,
        },
        Spec {
            id: "amp",
            label: "Amp",
            verified: false,
            targets: |e| {
                vec![t(
                    e.home.join(".config/amp/settings.json"),
                    &["amp.mcpServers"],
                    Fmt::Json,
                    false,
                )]
            },
            entry: stdio_entry,
            pre: id,
        },
        Spec {
            id: "cline",
            label: "Cline (VS Code)",
            verified: false,
            targets: |e| {
                vec![t(
                    vscode_user_dir(e).join(
                        "globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json",
                    ),
                    &["mcpServers"],
                    Fmt::Json,
                    false,
                )]
            },
            entry: stdio_entry,
            pre: id,
        },
    ]
}

// ---------------------------------------------------------------- document model

enum Doc {
    Json(Value),
    Toml(toml_edit::DocumentMut),
}

#[derive(Debug)]
enum Load {
    /// File has comments / non-strict JSON: refuse to rewrite.
    Lossy,
    Ok,
}

fn parse(t: &Target, text: &str) -> Result<(Doc, Load)> {
    match t.fmt {
        Fmt::Json => match serde_json::from_str::<Value>(text) {
            Ok(v) => Ok((Doc::Json(v), Load::Ok)),
            Err(_) => {
                json5::from_str::<Value>(text).context("not valid JSON/JSONC")?;
                Ok((Doc::Json(Value::Null), Load::Lossy))
            }
        },
        Fmt::Toml => Ok((Doc::Toml(text.parse().context("not valid TOML")?), Load::Ok)),
    }
}

fn json_servers<'a>(v: &'a Value, key: &[String]) -> Option<&'a Map<String, Value>> {
    let mut cur = v;
    for k in key {
        cur = cur.get(k)?;
    }
    cur.as_object()
}

fn json_servers_mut<'a>(
    v: &'a mut Value,
    key: &[String],
    create: bool,
) -> Option<&'a mut Map<String, Value>> {
    let mut cur = v;
    for k in key {
        if !cur.is_object() {
            return None;
        }
        if create && cur.get(k).is_none() {
            cur.as_object_mut()?.insert(k.clone(), json!({}));
        }
        cur = cur.get_mut(k)?;
    }
    cur.as_object_mut()
}

fn toml_table<'a>(
    d: &'a mut toml_edit::DocumentMut,
    key: &[String],
    create: bool,
) -> Option<&'a mut toml_edit::Table> {
    let mut cur = d.as_table_mut();
    for k in key {
        if create && !cur.contains_key(k) {
            let mut t = toml_edit::Table::new();
            t.set_implicit(true);
            cur.insert(k, toml_edit::Item::Table(t));
        }
        cur = cur.get_mut(k)?.as_table_mut()?;
    }
    Some(cur)
}

/// Read the servers map out of a TOML document as JSON (comments are irrelevant here).
fn toml_servers(d: &toml_edit::DocumentMut, key: &[String]) -> Map<String, Value> {
    let Ok(v) = toml::from_str::<toml::Value>(&d.to_string()) else {
        return Map::new();
    };
    let mut cur = &v;
    for k in key {
        match cur.get(k) {
            Some(n) => cur = n,
            None => return Map::new(),
        }
    }
    serde_json::to_value(cur)
        .ok()
        .and_then(|v| v.as_object().cloned())
        .unwrap_or_default()
}

fn json_to_toml_value(v: &Value) -> Result<toml_edit::Value> {
    Ok(match v {
        Value::String(s) => s.as_str().into(),
        Value::Bool(b) => (*b).into(),
        Value::Number(n) => match n.as_i64() {
            Some(i) => i.into(),
            None => n
                .as_f64()
                .context("number not representable in TOML")?
                .into(),
        },
        Value::Array(a) => {
            let mut arr = toml_edit::Array::new();
            for x in a {
                arr.push(json_to_toml_value(x)?);
            }
            toml_edit::Value::Array(arr)
        }
        Value::Object(m) => {
            let mut t = toml_edit::InlineTable::new();
            for (k, x) in m {
                t.insert(k, json_to_toml_value(x)?);
            }
            toml_edit::Value::InlineTable(t)
        }
        Value::Null => bail!("null is not representable in TOML"),
    })
}

/// A server object becomes a regular `[servers.name]` table (nested objects stay inline).
fn json_to_toml_item(v: &Value) -> Result<toml_edit::Item> {
    let Value::Object(m) = v else {
        return Ok(toml_edit::Item::Value(json_to_toml_value(v)?));
    };
    let mut t = toml_edit::Table::new();
    for (k, x) in m.iter().filter(|(_, x)| !x.is_null()) {
        t.insert(k, toml_edit::Item::Value(json_to_toml_value(x)?));
    }
    Ok(toml_edit::Item::Table(t))
}

fn render(doc: &Doc) -> String {
    match doc {
        Doc::Json(v) => serde_json::to_string_pretty(v).unwrap() + "\n",
        Doc::Toml(d) => d.to_string(),
    }
}

// ---------------------------------------------------------------- manifest

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ManifestEntry {
    pub agent: String,
    pub path: PathBuf,
    pub key: Vec<String>,
    pub toml: bool,
    pub backup: PathBuf,
    /// Original raw server objects removed from the agent file, by name.
    pub moved: Map<String, Value>,
    /// Native config the servers were merged into, and the names we added there.
    pub native: PathBuf,
    pub added_native: Vec<String>,
}

fn manifest_path() -> PathBuf {
    store::config_dir().join("setup-manifest.json")
}

fn load_manifest() -> Vec<ManifestEntry> {
    std::fs::read_to_string(manifest_path())
        .ok()
        .and_then(|t| serde_json::from_str(&t).ok())
        .unwrap_or_default()
}

fn save_manifest(m: &[ManifestEntry]) -> Result<()> {
    let p = manifest_path();
    std::fs::create_dir_all(p.parent().unwrap())?;
    write_atomic(&p, serde_json::to_string_pretty(m)?.as_bytes(), true)
}

// ---------------------------------------------------------------- io helpers

fn write_atomic(p: &Path, data: &[u8], private: bool) -> Result<()> {
    let tmp = p.with_extension(format!("omnix-tmp-{}", std::process::id()));
    #[cfg(unix)]
    {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        let mode = if private {
            0o600
        } else {
            std::fs::metadata(p)
                .map(|m| m.permissions().mode() & 0o777)
                .unwrap_or(0o644)
        };
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(mode)
            .open(&tmp)?;
        f.write_all(data)?;
        f.sync_all()?;
    }
    #[cfg(not(unix))]
    {
        let _ = private;
        std::fs::write(&tmp, data)?;
    }
    std::fs::rename(&tmp, p)?;
    Ok(())
}

fn unified_diff(path: &Path, old: &str, new: &str) -> String {
    let d = similar::TextDiff::from_lines(old, new);
    d.unified_diff()
        .context_radius(2)
        .header(
            &format!("a/{}", path.display()),
            &format!("b/{}", path.display()),
        )
        .to_string()
}

fn confirm(prompt: &str, yes: bool) -> Result<bool> {
    if yes {
        return Ok(true);
    }
    if !std::io::stdin().is_terminal() {
        bail!(
            "refusing to edit files without confirmation: stdin is not a terminal (use --yes or --dry-run)"
        );
    }
    eprint!("{prompt} [y/N] ");
    std::io::stderr().flush().ok();
    let mut l = String::new();
    std::io::stdin().lock().read_line(&mut l)?;
    Ok(matches!(l.trim().to_lowercase().as_str(), "y" | "yes"))
}

fn clean(v: &mut Value) {
    if let Value::Object(m) = v {
        m.retain(|_, x| {
            !(x.is_null()
                || x.as_array().is_some_and(|a| a.is_empty())
                || x.as_object().is_some_and(|o| o.is_empty())
                || *x == Value::Bool(false))
        });
    }
}

fn native_path(project: bool, e: &Env) -> PathBuf {
    if project {
        e.cwd.join("omnix.json")
    } else {
        store::config_dir().join("config.json")
    }
}

fn read_native(p: &Path) -> Result<Value> {
    match std::fs::read_to_string(p) {
        Ok(t) => json5::from_str(&t).with_context(|| format!("parsing {}", p.display())),
        Err(_) => Ok(json!({})),
    }
}

// ---------------------------------------------------------------- setup

pub struct Opts {
    pub agents: Vec<String>,
    pub yes: bool,
    pub dry_run: bool,
    pub keep_existing: bool,
    pub env: Env,
}

fn is_ours(name: &str, raw: &Value) -> bool {
    name == "omnix"
        || raw
            .get("command")
            .and_then(|c| c.as_str())
            .is_some_and(|c| Path::new(c).file_name().is_some_and(|f| f == "omnix"))
        || raw
            .get("command")
            .and_then(|c| c.as_array())
            .and_then(|a| a.first())
            .and_then(|c| c.as_str())
            .is_some_and(|c| Path::new(c).file_name().is_some_and(|f| f == "omnix"))
}

pub fn list(env: &Env) {
    for s in specs() {
        for tg in (s.targets)(env) {
            let state = match std::fs::read_to_string(&tg.path) {
                Err(_) => "not found".to_string(),
                Ok(text) => match parse(&tg, &text) {
                    Ok((_, Load::Lossy)) => "has comments (will be skipped)".into(),
                    Ok((Doc::Json(v), _)) => format!(
                        "{} server(s)",
                        json_servers(&v, &tg.key).map_or(0, |m| m.len())
                    ),
                    Ok((Doc::Toml(mut d), _)) => format!(
                        "{} server(s)",
                        toml_table(&mut d, &tg.key, false).map_or(0, |t| t.len())
                    ),
                    Err(e) => format!("unreadable: {e}"),
                },
            };
            println!("{:<18} {:<60} {state}", s.id, tg.path.display());
        }
    }
}

pub fn setup(o: &Opts) -> Result<()> {
    let exe = std::env::current_exe()?.display().to_string();
    let mut manifest = load_manifest();
    let mut changed_any = false;
    for spec in specs() {
        if !o.agents.is_empty() && !o.agents.iter().any(|a| a == spec.id) {
            continue;
        }
        for tg in (spec.targets)(&o.env) {
            let Ok(text) = std::fs::read_to_string(&tg.path) else {
                continue;
            };
            let (mut doc, load) = parse(&tg, &text)
                .with_context(|| format!("{} ({})", tg.path.display(), spec.label))?;
            if matches!(load, Load::Lossy) {
                eprintln!(
                    "\n{}: {} contains comments or non-strict JSON; editing it would lose them, so it was skipped.\n  Add this entry by hand under {:?}:\n  \"omnix\": {}",
                    spec.label,
                    tg.path.display(),
                    tg.key,
                    (spec.entry)(&exe)
                );
                continue;
            }
            // Collect the agent's existing servers.
            let existing: Map<String, Value> = match &mut doc {
                Doc::Json(v) => json_servers(v, &tg.key).cloned().unwrap_or_default(),
                Doc::Toml(d) => toml_servers(d, &tg.key),
            };
            if existing.get("omnix").is_some_and(|r| is_ours("omnix", r)) && existing.len() == 1 {
                eprintln!(
                    "{}: {} already points at omnix",
                    spec.label,
                    tg.path.display()
                );
                continue;
            }
            // Servers that will move into omnix's native config.
            let moved: Map<String, Value> = if o.keep_existing {
                Map::new()
            } else {
                existing
                    .iter()
                    .filter(|(n, r)| !is_ours(n, r))
                    .map(|(n, r)| (n.clone(), r.clone()))
                    .collect()
            };
            // Build the new agent doc.
            let entry = (spec.entry)(&exe);
            match &mut doc {
                Doc::Json(v) => {
                    let m = json_servers_mut(v, &tg.key, true)
                        .context("servers key is not an object")?;
                    for n in moved.keys() {
                        m.shift_remove(n);
                    }
                    m.insert("omnix".into(), entry);
                }
                Doc::Toml(d) => {
                    let t = toml_table(d, &tg.key, true).context("servers key is not a table")?;
                    for n in moved.keys() {
                        t.remove(n);
                    }
                    t.insert("omnix", json_to_toml_item(&entry)?);
                }
            }
            let new_text = render(&doc);
            // Native config merge (computed now so the user sees everything).
            let native = native_path(tg.project, &o.env);
            let mut nv = read_native(&native)?;
            let mut added = vec![];
            let mut notes = vec![];
            for (name, raw) in &moved {
                let mut sc = config::server_from_value(&(spec.pre)(raw))
                    .map(|s| serde_json::to_value(s).unwrap())
                    .unwrap_or_else(|| raw.clone());
                clean(&mut sc);
                let servers = nv
                    .as_object_mut()
                    .context("native config root must be an object")?
                    .entry("servers")
                    .or_insert_with(|| json!({}))
                    .as_object_mut()
                    .context("`servers` must be an object")?;
                let mut final_name = name.clone();
                match servers.get(name) {
                    Some(prev) if *prev == sc => continue, // identical, already there
                    Some(_) => {
                        final_name = format!("{name}-{}", spec.id);
                        notes.push(format!("`{name}` already exists in {} with a different definition; imported as `{final_name}`", native.display()));
                    }
                    None => {}
                }
                servers.insert(final_name.clone(), sc);
                added.push(final_name);
            }
            // Show everything.
            println!("\n=== {} — {} ===", spec.label, tg.path.display());
            if !spec.verified {
                println!(
                    "(note: this agent's config schema is not verified against current vendor docs; review the diff)"
                );
            }
            print!("{}", unified_diff(&tg.path, &text, &new_text));
            if !added.is_empty() {
                println!(
                    "\n{} server(s) will be moved into {}: {}",
                    added.len(),
                    native.display(),
                    added.join(", ")
                );
                println!(
                    "(env values and headers move as-is; that file is created with 0600 permissions)"
                );
            }
            for n in &notes {
                println!("note: {n}");
            }
            if o.dry_run {
                continue;
            }
            if !confirm(&format!("Apply to {}?", tg.path.display()), o.yes)? {
                println!("skipped");
                continue;
            }
            // Re-read right before writing: agents (esp. Claude Code) rewrite their files often.
            let fresh = std::fs::read_to_string(&tg.path)?;
            if fresh != text {
                eprintln!(
                    "{} changed while we were preparing; aborting this file (re-run setup)",
                    tg.path.display()
                );
                continue;
            }
            let ts = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_secs();
            let backup = PathBuf::from(format!("{}.omnix-backup-{ts}", tg.path.display()));
            std::fs::copy(&tg.path, &backup)
                .with_context(|| format!("backing up to {}", backup.display()))?;
            if !added.is_empty() {
                if let Some(d) = native.parent() {
                    std::fs::create_dir_all(d)?;
                }
                write_atomic(
                    &native,
                    (serde_json::to_string_pretty(&nv)? + "\n").as_bytes(),
                    true,
                )?;
            }
            write_atomic(&tg.path, new_text.as_bytes(), false)?;
            manifest.push(ManifestEntry {
                agent: spec.id.into(),
                path: tg.path.clone(),
                key: tg.key.clone(),
                toml: tg.fmt == Fmt::Toml,
                backup: backup.clone(),
                moved,
                native,
                added_native: added,
            });
            save_manifest(&manifest)?;
            changed_any = true;
            println!("done. backup: {}", backup.display());
        }
    }
    if !changed_any && !o.dry_run {
        println!("\nnothing changed.");
    } else if changed_any {
        println!(
            "\nRestart your agent(s) to pick up the change. Undo with `omnix setup --remove`."
        );
    }
    Ok(())
}

// ---------------------------------------------------------------- remove

pub fn remove(o: &Opts) -> Result<()> {
    let manifest = load_manifest();
    if manifest.is_empty() {
        println!(
            "nothing to undo (no setup manifest at {})",
            manifest_path().display()
        );
        return Ok(());
    }
    let mut keep = vec![];
    for m in manifest {
        if !o.agents.is_empty() && !o.agents.contains(&m.agent) {
            keep.push(m);
            continue;
        }
        let Ok(text) = std::fs::read_to_string(&m.path) else {
            eprintln!("{} no longer exists; dropping its record", m.path.display());
            continue;
        };
        let tg = Target {
            path: m.path.clone(),
            key: m.key.clone(),
            fmt: if m.toml { Fmt::Toml } else { Fmt::Json },
            project: false,
        };
        let (mut doc, load) = parse(&tg, &text)?;
        if matches!(load, Load::Lossy) {
            eprintln!(
                "{} now contains comments; restore by hand from {}",
                m.path.display(),
                m.backup.display()
            );
            keep.push(m);
            continue;
        }
        match &mut doc {
            Doc::Json(v) => {
                if let Some(s) = json_servers_mut(v, &tg.key, false) {
                    s.shift_remove("omnix");
                    for (n, raw) in &m.moved {
                        s.entry(n.clone()).or_insert(raw.clone());
                    }
                }
            }
            Doc::Toml(d) => {
                if let Some(t) = toml_table(d, &tg.key, true) {
                    t.remove("omnix");
                    for (n, raw) in &m.moved {
                        if !t.contains_key(n) {
                            t.insert(n, json_to_toml_item(raw)?);
                        }
                    }
                }
            }
        }
        let new_text = render(&doc);
        println!("\n=== restore {} — {} ===", m.agent, m.path.display());
        print!("{}", unified_diff(&m.path, &text, &new_text));
        if o.dry_run {
            keep.push(m);
            continue;
        }
        if !confirm(&format!("Restore {}?", m.path.display()), o.yes)? {
            keep.push(m);
            continue;
        }
        write_atomic(&m.path, new_text.as_bytes(), false)?;
        // Remove the servers we added to the native config (only if still present).
        if let Ok(mut nv) = read_native(&m.native)
            && let Some(s) = nv.get_mut("servers").and_then(|s| s.as_object_mut())
        {
            for n in &m.added_native {
                s.shift_remove(n);
            }
            let _ = write_atomic(
                &m.native,
                (serde_json::to_string_pretty(&nv)? + "\n").as_bytes(),
                true,
            );
        }
        println!("restored. (backup kept at {})", m.backup.display());
    }
    save_manifest(&keep)
}
