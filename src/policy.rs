//! Policy: per-method allow/deny, read-only mode, an optional `before_call` hook, audit log.
//!
//! Decision order for `server.tool`:
//!   1. matches a `deny` pattern                       -> blocked
//!   2. `allow` is non-empty:
//!      matches                                        -> allowed (explicit rule beats annotations)
//!      no match                                       -> blocked
//!   3. `read_only`: allowed only if upstream sets readOnlyHint=true (unannotated = blocked)
//!   4. otherwise allowed.
//!
//! Patterns are `server.tool` with `*` wildcards (e.g. `gdrive.*`, `*.delete*`).

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{io::Write, path::PathBuf, time::Duration};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct PolicyConfig {
    pub read_only: bool,
    pub allow: Vec<String>,
    pub deny: Vec<String>,
    /// Command run before each call with `{server,tool,args}` JSON on stdin.
    /// Exit 0 allows; non-zero blocks (stdout, if any, is the reason).
    pub before_call: Option<String>,
    /// JSONL audit log path. Arguments and results are never written, only their shape.
    pub audit_log: Option<PathBuf>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Decision {
    Allow,
    Block(String),
}

pub fn glob(pat: &str, s: &str) -> bool {
    let parts: Vec<&str> = pat.split('*').collect();
    if parts.len() == 1 {
        return pat == s;
    }
    let mut rest = s;
    for (i, p) in parts.iter().enumerate() {
        if i == 0 {
            let Some(r) = rest.strip_prefix(p) else {
                return false;
            };
            rest = r;
        } else if i == parts.len() - 1 {
            return rest.ends_with(p) && rest.len() >= p.len();
        } else if let Some(pos) = rest.find(p) {
            rest = &rest[pos + p.len()..];
        } else {
            return false;
        }
    }
    true
}

/// One audit-log record. Argument *values* are never written, only their keys.
pub struct AuditEntry<'a> {
    pub server: &'a str,
    pub tool: &'a str,
    pub args: &'a Value,
    pub decision: &'a str,
    pub ok: bool,
    pub ms: u128,
    pub result_bytes: usize,
}

impl PolicyConfig {
    /// Static decision (no hook). `read_only_hint` is the upstream annotation.
    pub fn decide(&self, server: &str, tool: &str, read_only_hint: Option<bool>) -> Decision {
        let id = format!("{server}.{tool}");
        if let Some(p) = self.deny.iter().find(|p| glob(p, &id)) {
            return Decision::Block(format!("{id} is denied by policy ({p})"));
        }
        if !self.allow.is_empty() {
            return if self.allow.iter().any(|p| glob(p, &id)) {
                Decision::Allow
            } else {
                Decision::Block(format!("{id} is not in the policy allowlist"))
            };
        }
        if self.read_only && read_only_hint != Some(true) {
            return Decision::Block(format!("{id} is not marked read-only (read-only mode)"));
        }
        Decision::Allow
    }

    /// Run the `before_call` hook, if configured.
    pub async fn run_hook(&self, server: &str, tool: &str, args: &Value) -> Decision {
        let Some(cmd) = &self.before_call else {
            return Decision::Allow;
        };
        let input = json!({"server": server, "tool": tool, "args": args}).to_string();
        let run = async {
            let mut child = tokio::process::Command::new("sh")
                .arg("-c")
                .arg(cmd)
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::null())
                .kill_on_drop(true)
                .spawn()?;
            use tokio::io::AsyncWriteExt;
            if let Some(mut si) = child.stdin.take() {
                let _ = si.write_all(input.as_bytes()).await;
            }
            child.wait_with_output().await
        };
        match tokio::time::timeout(Duration::from_secs(5), run).await {
            Ok(Ok(o)) if o.status.success() => Decision::Allow,
            Ok(Ok(o)) => {
                let why = String::from_utf8_lossy(&o.stdout).trim().to_string();
                Decision::Block(if why.is_empty() {
                    "blocked by before_call hook".into()
                } else {
                    format!("blocked by before_call hook: {why}")
                })
            }
            // Fail closed: a broken or slow hook must not silently allow calls.
            _ => Decision::Block("before_call hook failed or timed out".into()),
        }
    }

    pub fn audit(&self, e: &AuditEntry) {
        let Some(path) = &self.audit_log else { return };
        let keys: Vec<&String> = e
            .args
            .as_object()
            .map(|m| m.keys().collect())
            .unwrap_or_default();
        let line = json!({
            "ts": std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0),
            "server": e.server, "tool": e.tool, "arg_keys": keys,
            "decision": e.decision, "ok": e.ok, "ms": e.ms, "result_bytes": e.result_bytes,
        });
        if let Some(dir) = path.parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        let mut o = std::fs::OpenOptions::new();
        o.create(true).append(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            o.mode(0o600);
        }
        if let Ok(mut f) = o.open(path) {
            let _ = writeln!(f, "{line}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(f: impl FnOnce(&mut PolicyConfig)) -> PolicyConfig {
        let mut c = PolicyConfig::default();
        f(&mut c);
        c
    }

    #[test]
    fn globbing() {
        assert!(glob("gdrive.*", "gdrive.list"));
        assert!(glob("*.delete*", "x.delete_item"));
        assert!(glob("a.b", "a.b"));
        assert!(!glob("a.b", "a.bc"));
        assert!(!glob("gdrive.*", "slack.list"));
        assert!(glob("*", "anything"));
        assert!(glob("a*c*e", "abcde"));
        assert!(!glob("a*c", "ab"));
    }

    #[test]
    fn deny_beats_allow() {
        let c = p(|c| {
            c.allow = vec!["mock.*".into()];
            c.deny = vec!["mock.delete*".into()];
        });
        assert_eq!(c.decide("mock", "add", None), Decision::Allow);
        assert!(matches!(
            c.decide("mock", "delete_item", None),
            Decision::Block(_)
        ));
        assert!(matches!(c.decide("other", "add", None), Decision::Block(_)));
    }

    #[test]
    fn read_only_fails_closed_and_allow_overrides_annotations() {
        let c = p(|c| c.read_only = true);
        assert_eq!(c.decide("s", "t", Some(true)), Decision::Allow);
        assert!(matches!(
            c.decide("s", "t", Some(false)),
            Decision::Block(_)
        ));
        assert!(matches!(c.decide("s", "t", None), Decision::Block(_)));
        // Explicit allowlist wins even for a tool the upstream does not mark read-only.
        let c = p(|c| {
            c.read_only = true;
            c.allow = vec!["s.write_ok".into()];
        });
        assert_eq!(c.decide("s", "write_ok", Some(false)), Decision::Allow);
        // ...and a lying "readOnlyHint" cannot bypass a deny rule.
        let c = p(|c| {
            c.read_only = true;
            c.deny = vec!["s.sneaky".into()];
        });
        assert!(matches!(
            c.decide("s", "sneaky", Some(true)),
            Decision::Block(_)
        ));
    }

    #[tokio::test]
    async fn hook_allows_blocks_and_fails_closed() {
        let ok = p(|c| c.before_call = Some("cat >/dev/null; exit 0".into()));
        assert_eq!(ok.run_hook("s", "t", &json!({})).await, Decision::Allow);
        let no = p(|c| c.before_call = Some("cat >/dev/null; echo nope; exit 1".into()));
        assert_eq!(
            no.run_hook("s", "t", &json!({})).await,
            Decision::Block("blocked by before_call hook: nope".into())
        );
        let seen = p(|c| c.before_call = Some("grep -q '\"tool\":\"t\"'".into()));
        assert_eq!(seen.run_hook("s", "t", &json!({})).await, Decision::Allow);
        let bad = p(|c| c.before_call = Some("/definitely/not/a/cmd".into()));
        assert!(matches!(
            bad.run_hook("s", "t", &json!({})).await,
            Decision::Block(_)
        ));
    }

    #[test]
    fn audit_never_logs_values() {
        let d = std::env::temp_dir().join(format!("omnix-audit-{}", std::process::id()));
        let path = d.join("a.jsonl");
        let c = p(|c| c.audit_log = Some(path.clone()));
        c.audit(&AuditEntry {
            server: "s",
            tool: "t",
            args: &json!({"password": "hunter2"}),
            decision: "allow",
            ok: true,
            ms: 3,
            result_bytes: 10,
        });
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.contains("\"arg_keys\":[\"password\"]"));
        assert!(!text.contains("hunter2"));
        let _ = std::fs::remove_dir_all(&d);
    }
}
