//! E2E for `omnix setup` against temp copies of agent configs. Never touches real files:
//! HOME and cwd are temp dirs.
use serde_json::{Value, json};
use std::{path::PathBuf, process::Command};

struct Sandbox {
    home: PathBuf,
    cwd: PathBuf,
}

fn sandbox() -> Sandbox {
    static N: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let root = std::env::temp_dir().join(format!(
        "omnix-setup-{}-{}",
        std::process::id(),
        N.fetch_add(1, std::sync::atomic::Ordering::SeqCst)
    ));
    let (home, cwd) = (root.join("home"), root.join("proj"));
    std::fs::create_dir_all(&home).unwrap();
    std::fs::create_dir_all(&cwd).unwrap();
    Sandbox { home, cwd }
}

impl Sandbox {
    fn run(&self, args: &[&str]) -> (bool, String, String) {
        let o = Command::new(env!("CARGO_BIN_EXE_omnix"))
            .args(args)
            .current_dir(&self.cwd)
            .env("HOME", &self.home)
            .env("OMNIX_CONFIG_DIR", self.home.join("omnixcfg"))
            .env_remove("CODEX_HOME")
            .output()
            .unwrap();
        (
            o.status.success(),
            String::from_utf8_lossy(&o.stdout).into(),
            String::from_utf8_lossy(&o.stderr).into(),
        )
    }
    fn write(&self, rel: &str, text: &str) -> PathBuf {
        let p = if let Some(r) = rel.strip_prefix("~/") {
            self.home.join(r)
        } else {
            self.cwd.join(rel)
        };
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(&p, text).unwrap();
        p
    }
    fn json(&self, p: &PathBuf) -> Value {
        serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap()
    }
}

#[test]
fn project_mcp_json_migrates_and_restores() {
    let s = sandbox();
    let orig = json!({"mcpServers": {
        "fs": {"command": "npx", "args": ["-y", "server-fs"], "env": {"K": "v"}},
        "remote": {"type": "http", "url": "https://h/mcp", "headers": {"X-A": "b"}}}, "other": 1});
    let p = s.write(".mcp.json", &orig.to_string());
    let (ok, out, err) = s.run(&["setup", "--yes", "--agent", "claude-code"]);
    assert!(ok, "{out}\n{err}");
    let now = s.json(&p);
    assert_eq!(now["other"], 1, "unknown keys must be preserved");
    let servers = now["mcpServers"].as_object().unwrap();
    assert_eq!(servers.len(), 1, "{now}");
    assert_eq!(servers["omnix"]["args"], json!(["serve"]));
    // originals moved to ./omnix.json, normalised
    let native = s.json(&s.cwd.join("omnix.json"));
    assert_eq!(native["servers"]["fs"]["command"], "npx");
    assert_eq!(native["servers"]["fs"]["env"]["K"], "v");
    assert_eq!(native["servers"]["remote"]["url"], "https://h/mcp");
    assert_eq!(native["servers"]["remote"]["transport"], "http");
    // backup exists
    assert!(std::fs::read_dir(&s.cwd).unwrap().any(|e| {
        e.unwrap()
            .file_name()
            .to_string_lossy()
            .contains("omnix-backup")
    }));
    // idempotent
    let (_, out2, _) = s.run(&["setup", "--yes", "--agent", "claude-code"]);
    assert!(
        out2.contains("nothing changed") || out2.contains("already points"),
        "{out2}"
    );
    // undo
    let (ok, out, err) = s.run(&["setup", "--remove", "--yes"]);
    assert!(ok, "{out}\n{err}");
    let back = s.json(&p);
    assert_eq!(
        back["mcpServers"], orig["mcpServers"],
        "restored servers must match the originals"
    );
    assert_eq!(back["other"], 1);
    assert!(back["mcpServers"].get("omnix").is_none());
    assert!(
        s.json(&s.cwd.join("omnix.json"))["servers"]
            .as_object()
            .unwrap()
            .is_empty()
    );
}

#[test]
fn dry_run_and_noninteractive_never_write() {
    let s = sandbox();
    let text = json!({"mcpServers": {"a": {"command": "x"}}}).to_string();
    let p = s.write(".mcp.json", &text);
    let (ok, out, _) = s.run(&["setup", "--dry-run", "--agent", "claude-code"]);
    assert!(ok && out.contains("+") && out.contains("omnix"), "{out}");
    assert_eq!(std::fs::read_to_string(&p).unwrap(), text);
    // no --yes and no terminal: must refuse rather than edit
    let (ok, _, err) = s.run(&["setup", "--agent", "claude-code"]);
    assert!(!ok && err.contains("without confirmation"), "{err}");
    assert_eq!(std::fs::read_to_string(&p).unwrap(), text);
}

#[test]
fn jsonc_with_comments_is_skipped_not_destroyed() {
    let s = sandbox();
    let text = "{\n  // my servers\n  \"servers\": { \"a\": { \"command\": \"x\" } }\n}\n";
    let p = s.write(".vscode/mcp.json", text);
    let (ok, out, err) = s.run(&["setup", "--yes", "--agent", "vscode"]);
    assert!(ok, "{out}\n{err}");
    assert!(
        err.contains("contains comments") && err.contains("\"omnix\""),
        "{err}"
    );
    assert_eq!(
        std::fs::read_to_string(&p).unwrap(),
        text,
        "file with comments must be untouched"
    );
}

#[test]
fn claude_json_user_and_local_scope_preserve_everything_else() {
    let s = sandbox();
    // macOS temp dirs are symlinked (/var -> /private/var); the CLI sees the canonical cwd.
    let cwd = s.cwd.canonicalize().unwrap().display().to_string();
    let orig = json!({"numStartups": 42, "oauthAccount": {"emailAddress": "x"},
        "mcpServers": {"u1": {"command": "u"}},
        "projects": {cwd.clone(): {"allowedTools": [], "mcpServers": {"l1": {"command": "l"}}},
                     "/other": {"mcpServers": {"keep": {"command": "k"}}}}});
    let p = s.write("~/.claude.json", &orig.to_string());
    let (ok, out, err) = s.run(&["setup", "--yes", "--agent", "claude-code"]);
    assert!(ok, "{out}\n{err}");
    let now = s.json(&p);
    assert_eq!(now["numStartups"], 42);
    assert_eq!(now["oauthAccount"], orig["oauthAccount"]);
    assert_eq!(
        now["projects"]["/other"], orig["projects"]["/other"],
        "other projects must be untouched"
    );
    assert!(now["mcpServers"].get("omnix").is_some() && now["mcpServers"].get("u1").is_none());
    assert!(
        now["projects"][&cwd]["mcpServers"].get("omnix").is_some()
            && now["projects"][&cwd]["mcpServers"].get("l1").is_none()
    );
    assert_eq!(now["projects"][&cwd]["allowedTools"], json!([]));
    let (ok, _, e) = s.run(&["setup", "--remove", "--yes"]);
    assert!(ok, "{e}");
    assert_eq!(s.json(&p), orig, "undo must restore ~/.claude.json exactly");
}

#[test]
fn codex_toml_keeps_comments_and_other_settings() {
    let s = sandbox();
    let text = "# my codex config\nmodel = \"o3\"\n\n[mcp_servers.files]\ncommand = \"npx\"\nargs = [\"-y\", \"fs\"]\n\n[profiles.fast]\nmodel = \"mini\"\n";
    let p = s.write("~/.codex/config.toml", text);
    let (ok, out, err) = s.run(&["setup", "--yes", "--agent", "codex"]);
    assert!(ok, "{out}\n{err}");
    let now = std::fs::read_to_string(&p).unwrap();
    assert!(
        now.contains("# my codex config")
            && now.contains("model = \"o3\"")
            && now.contains("[profiles.fast]"),
        "{now}"
    );
    assert!(
        now.contains("mcp_servers.omnix") && now.contains("serve"),
        "{now}"
    );
    assert!(
        !now.contains("server-fs") && !now.contains("\"fs\""),
        "{now}"
    );
    let native = s.json(&s.home.join("omnixcfg/config.json"));
    assert_eq!(native["servers"]["files"]["command"], "npx");
    assert_eq!(native["servers"]["files"]["args"], json!(["-y", "fs"]));
    // Regression: servers moved into the GLOBAL config must actually be loaded afterwards
    // (the loader once read a hard-coded ~/.config path that differs on macOS).
    let (_, list, _) = s.run(&["list"]);
    assert!(
        list.contains("files\tstdio"),
        "global config was not loaded: {list}"
    );
    let (ok, _, e) = s.run(&["setup", "--remove", "--yes"]);
    assert!(ok, "{e}");
    let back = std::fs::read_to_string(&p).unwrap();
    assert!(
        back.contains("[mcp_servers.files]") || back.contains("mcp_servers.files"),
        "{back}"
    );
    assert!(
        back.contains("command = \"npx\"") && !back.contains("omnix"),
        "{back}"
    );
    assert!(back.contains("# my codex config"));
}

#[test]
fn name_collision_is_imported_under_a_new_name() {
    let s = sandbox();
    s.write(
        "omnix.json",
        &json!({"servers": {"a": {"command": "existing"}}}).to_string(),
    );
    s.write(
        ".mcp.json",
        &json!({"mcpServers": {"a": {"command": "different"}}}).to_string(),
    );
    let (ok, out, err) = s.run(&["setup", "--yes", "--agent", "claude-code"]);
    assert!(ok, "{out}\n{err}");
    assert!(out.contains("imported as `a-claude-code`"), "{out}");
    let native = s.json(&s.cwd.join("omnix.json"));
    assert_eq!(native["servers"]["a"]["command"], "existing");
    assert_eq!(native["servers"]["a-claude-code"]["command"], "different");
}

#[test]
fn opencode_and_gemini_shapes_are_normalised() {
    let s = sandbox();
    s.write("opencode.json", &json!({"mcp": {"x": {"type": "local", "command": ["bin", "--f"], "environment": {"E": "1"}, "enabled": true},
        "r": {"type": "remote", "url": "https://r/mcp"}}}).to_string());
    s.write(".gemini/settings.json", &json!({"theme": "dark", "mcpServers": {"g": {"httpUrl": "https://g/mcp"}, "s": {"url": "https://s/sse"}}}).to_string());
    let (ok, out, err) = s.run(&["setup", "--yes", "--agent", "opencode", "--agent", "gemini"]);
    assert!(ok, "{out}\n{err}");
    let n = s.json(&s.cwd.join("omnix.json"));
    assert_eq!(n["servers"]["x"]["command"], "bin");
    assert_eq!(n["servers"]["x"]["args"], json!(["--f"]));
    assert_eq!(n["servers"]["x"]["env"]["E"], "1");
    assert_eq!(n["servers"]["r"]["url"], "https://r/mcp");
    assert_eq!(n["servers"]["g"]["transport"], "http");
    assert_eq!(
        n["servers"]["s"]["transport"], "sse",
        "a bare url in Gemini is SSE"
    );
    assert_eq!(
        s.json(&s.cwd.join(".gemini/settings.json"))["theme"],
        "dark"
    );
    // gateway still sees every migrated server after setup
    let (_, list, _) = s.run(&["list"]);
    for n in ["x", "r", "g", "s"] {
        assert!(list.contains(&format!("{n}\t")), "{list}");
    }
}
