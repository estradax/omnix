//! Native config schema plus importers for other agents' MCP configs.
//!
//! Native file: `omnix.json` (JSON5) in the project dir, or `config.json` in the omnix config
//! directory (`$OMNIX_CONFIG_DIR`, else the platform config dir, e.g. `~/.config/omnix` on Linux
//! and `~/Library/Application Support/omnix` on macOS):
//! `{ "servers": { "name": { "command": "...", "args": [], "env": {}, "auth": {...} }
//!                          | { "url": "https://...", "transport": "http"|"sse", "headers": {}, "auth": {...} } } }`

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Config {
    #[serde(default)]
    pub servers: BTreeMap<String, ServerConfig>,
    /// Only read from native config files (`omnix.json`), never from imported agent configs.
    #[serde(default)]
    pub policy: crate::policy::PolicyConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ServerConfig {
    pub command: Option<String>,
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(default)]
    pub env: BTreeMap<String, String>,
    pub url: Option<String>,
    /// "http" (streamable HTTP, default) or "sse" (legacy).
    pub transport: Option<String>,
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
    /// Auth config; interpreted by the auth module (milestone 3).
    pub auth: Option<serde_json::Value>,
    #[serde(default)]
    pub disabled: bool,
}

impl ServerConfig {
    pub fn is_stdio(&self) -> bool {
        self.command.is_some()
    }
}

/// Expand `${VAR}` and `${VAR:-default}` using the process environment.
pub fn expand(s: &str) -> String {
    let re = regex::Regex::new(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-([^}]*))?\}").unwrap();
    re.replace_all(s, |c: &regex::Captures| match std::env::var(&c[1]) {
        Ok(v) if !v.is_empty() => v,
        _ => c.get(2).map_or(String::new(), |m| m.as_str().to_string()),
    })
    .into_owned()
}

fn expand_server(mut s: ServerConfig) -> ServerConfig {
    s.command = s.command.map(|c| expand(&c));
    s.args = s.args.iter().map(|a| expand(a)).collect();
    s.url = s.url.map(|u| expand(&u));
    for v in s.env.values_mut().chain(s.headers.values_mut()) {
        *v = expand(v);
    }
    s
}

/// Parse the common `{ "mcpServers": {..} }` / `{ "servers": {..} }` shape
/// (Claude Code, .mcp.json, Cursor, VS Code, native).
fn parse_json_servers(text: &str) -> Result<BTreeMap<String, ServerConfig>> {
    let v: serde_json::Value = json5::from_str(text)?;
    let mut out = BTreeMap::new();
    for key in [
        "mcpServers",
        "servers",
        "mcp",
        "context_servers",
        "amp.mcpServers",
    ] {
        if let Some(map) = v.get(key).and_then(|m| m.as_object()) {
            for (name, raw) in map {
                if let Some(s) = server_from_value(raw) {
                    out.insert(name.clone(), s);
                }
            }
        }
    }
    Ok(out)
}

pub fn server_from_value(raw: &serde_json::Value) -> Option<ServerConfig> {
    let mut raw = raw.clone();
    let o = raw.as_object_mut()?;
    // Normalise variants: OpenCode uses command as an array, type "remote"/"local".
    if let Some(arr) = o.get("command").and_then(|c| c.as_array()).cloned() {
        let mut it = arr.into_iter();
        o.insert("command".into(), it.next()?);
        o.insert("args".into(), serde_json::Value::Array(it.collect()));
    }
    if let Some(t) = o.get("type").and_then(|t| t.as_str()).map(str::to_string) {
        match t.as_str() {
            "sse" => {
                o.insert("transport".into(), "sse".into());
            }
            "http" | "streamable-http" | "remote" => {
                o.insert("transport".into(), "http".into());
            }
            _ => {}
        }
    }
    // Variant URL keys: Windsurf `serverUrl`, Gemini `httpUrl` (streamable HTTP).
    if let Some(u) = o.get("serverUrl").cloned() {
        o.entry("url").or_insert(u);
    }
    if let Some(u) = o.get("httpUrl").cloned() {
        o.insert("url".into(), u);
        o.insert("transport".into(), "http".into());
    }
    // OpenCode uses `environment` for env vars.
    if let Some(e) = o.get("environment").cloned() {
        o.entry("env").or_insert(e);
    }
    if let Some(en) = o.get("enabled").and_then(|e| e.as_bool()) {
        o.insert("disabled".into(), (!en).into());
    }
    serde_json::from_value(raw).ok()
}

fn parse_codex_toml(text: &str) -> Result<BTreeMap<String, ServerConfig>> {
    let v: toml::Value = toml::from_str(text)?;
    let mut out = BTreeMap::new();
    if let Some(t) = v.get("mcp_servers").and_then(|t| t.as_table()) {
        for (name, raw) in t {
            let json = serde_json::to_value(raw)?;
            if let Some(s) = server_from_value(&json) {
                out.insert(name.clone(), s);
            }
        }
    }
    Ok(out)
}

/// The global native config, shared with `setup`, `add --global` and the credential store.
pub fn global_config_path() -> PathBuf {
    crate::store::config_dir().join("config.json")
}

/// Candidate files, lowest priority first (later entries override earlier ones).
fn candidates(cwd: &Path) -> Vec<PathBuf> {
    let home = dirs::home_dir().unwrap_or_default();
    vec![
        home.join(".codex/config.toml"),
        home.join(".cursor/mcp.json"),
        home.join(".config/opencode/opencode.json"),
        home.join(".claude.json"),
        home.join(".codeium/windsurf/mcp_config.json"),
        home.join(".gemini/settings.json"),
        home.join(".kiro/settings/mcp.json"),
        home.join(".config/amp/settings.json"),
        cwd.join(".gemini/settings.json"),
        cwd.join(".kiro/settings/mcp.json"),
        cwd.join(".vscode/mcp.json"),
        cwd.join(".cursor/mcp.json"),
        cwd.join(".mcp.json"),
        global_config_path(),
        cwd.join("omnix.json"),
    ]
}

/// Discover and merge all configs. Our own entry (named `omnix`, or whose command
/// runs this binary) is skipped to avoid recursion.
pub fn load(cwd: &Path) -> Result<(Config, Vec<String>)> {
    let mut cfg = Config::default();
    let mut sources = vec![];
    for p in candidates(cwd) {
        let Ok(text) = std::fs::read_to_string(&p) else {
            continue;
        };
        let parsed = if p.extension().is_some_and(|e| e == "toml") {
            parse_codex_toml(&text)
        } else {
            parse_json_servers(&text)
        }
        .with_context(|| format!("parsing {}", p.display()))?;
        if !parsed.is_empty() {
            sources.push(p.display().to_string());
        }
        cfg.servers.extend(parsed);
        if p.file_name()
            .is_some_and(|f| f == "omnix.json" || f == "config.json")
            && (p == global_config_path() || p == cwd.join("omnix.json"))
            && let Ok(v) = json5::from_str::<serde_json::Value>(&text)
            && let Some(pol) = v.get("policy")
        {
            cfg.policy = serde_json::from_value(pol.clone())
                .with_context(|| format!("invalid `policy` in {}", p.display()))?;
        }
    }
    cfg.servers.retain(|name, s| {
        let me = name == "omnix"
            || s.command
                .as_deref()
                .is_some_and(|c| Path::new(c).file_name().is_some_and(|f| f == "omnix"));
        !me && !s.disabled
    });
    cfg.servers = cfg
        .servers
        .into_iter()
        .map(|(k, v)| (k, expand_server(v)))
        .collect();
    Ok((cfg, sources))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expands_vars() {
        unsafe { std::env::set_var("OMNIX_T1", "x") };
        assert_eq!(expand("a-${OMNIX_T1}-${OMNIX_NOPE:-d}"), "a-x-d");
    }

    #[test]
    fn parses_mcp_json_and_opencode() {
        let m = parse_json_servers(
            r#"{"mcpServers":{"a":{"command":"npx","args":["-y","x"]},
                "b":{"type":"sse","url":"http://h/sse"}},
               "mcp":{"c":{"type":"local","command":["bin","--f"],"enabled":false}}}"#,
        )
        .unwrap();
        assert_eq!(m["a"].args, ["-y", "x"]);
        assert_eq!(m["b"].transport.as_deref(), Some("sse"));
        assert_eq!(m["c"].command.as_deref(), Some("bin"));
        assert!(m["c"].disabled);
    }

    #[test]
    fn parses_codex() {
        let m = parse_codex_toml("[mcp_servers.x]\ncommand=\"foo\"\nargs=[\"a\"]\n").unwrap();
        assert_eq!(m["x"].args, ["a"]);
    }
}
