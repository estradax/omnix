//! Non-serving CLI commands: doctor, find, sdk, add, remove.

use crate::{auth, catalog::Catalog, config, pool::Pool, server};
use anyhow::{Context, Result, bail};
use serde_json::{Value, json};
use std::path::PathBuf;

async fn connect(cwd: &std::path::Path) -> Result<(config::Config, Pool)> {
    let (cfg, _) = config::load(cwd)?;
    let pool = Pool::connect(&cfg).await;
    Ok((cfg, pool))
}

fn auth_kind(s: &config::ServerConfig) -> String {
    match auth::parse_auth(s) {
        Ok(auth::AuthConfig::None) => "none".into(),
        Ok(auth::AuthConfig::Bearer { .. }) => "bearer".into(),
        Ok(auth::AuthConfig::Basic { .. }) => "basic".into(),
        Ok(auth::AuthConfig::Header { .. }) => "header".into(),
        Ok(auth::AuthConfig::Query { .. }) => "query".into(),
        Ok(auth::AuthConfig::Oauth(_)) => "oauth".into(),
        Ok(auth::AuthConfig::ClientCredentials { .. }) => "client_credentials".into(),
        Ok(auth::AuthConfig::Unsupported) => "unknown".into(),
        Err(_) => "invalid".into(),
    }
}

pub async fn doctor() -> Result<()> {
    let cwd = std::env::current_dir()?;
    println!("omnix {}", env!("CARGO_PKG_VERSION"));
    let (cfg, sources) = config::load(&cwd)?;
    println!("\nconfig sources:");
    if sources.is_empty() {
        println!("  (none found)");
    }
    for s in &sources {
        println!("  {s}");
    }
    println!(
        "\npolicy: read_only={} allow={} deny={} before_call={} audit_log={}",
        cfg.policy.read_only,
        cfg.policy.allow.len(),
        cfg.policy.deny.len(),
        cfg.policy.before_call.is_some(),
        cfg.policy
            .audit_log
            .as_ref()
            .map_or("off".into(), |p| p.display().to_string())
    );

    let kc = tokio::task::spawn_blocking(|| {
        match keyring::Entry::new("omnix", "doctor-probe").and_then(|e| e.get_password()) {
            Ok(_) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(e) => Err(e.to_string()),
        }
    })
    .await?;
    match kc {
        Ok(()) => println!("credential store: OS keychain available"),
        Err(e) => println!(
            "credential store: keychain unavailable ({e}); using encrypted file in {}",
            crate::store::config_dir().display()
        ),
    }

    println!("\nconnecting to {} server(s)...", cfg.servers.len());
    let pool = Pool::connect(&cfg).await;
    println!("\n{:<20} {:<8} {:<18} status", "server", "kind", "auth");
    for (name, s) in &cfg.servers {
        let kind = if s.is_stdio() {
            "stdio"
        } else {
            s.transport.as_deref().unwrap_or("http")
        };
        let status = match (pool.servers.get(name), pool.failures.get(name)) {
            (Some(u), _) => format!("ok, {} tools", u.tools.len()),
            (_, Some(e)) => format!("FAILED: {e}"),
            _ => "unknown".into(),
        };
        println!("{:<20} {:<8} {:<18} {status}", name, kind, auth_kind(s));
    }
    if !pool.failures.is_empty() {
        println!(
            "\n{} server(s) failed; they are skipped by `omnix serve`.",
            pool.failures.len()
        );
    }
    Ok(())
}

pub async fn find(query: &str, limit: usize) -> Result<()> {
    let (cfg, pool) = connect(&std::env::current_dir()?).await?;
    let cat = server::build_catalog(&pool, &cfg.policy);
    let hits = cat.search(query, limit);
    if hits.is_empty() {
        println!("no matches");
    }
    for (e, _) in hits {
        println!(
            "{} - {}",
            e.id(),
            e.description.lines().next().unwrap_or("")
        );
    }
    Ok(())
}

pub async fn sdk(out: Option<PathBuf>) -> Result<()> {
    let (cfg, pool) = connect(&std::env::current_dir()?).await?;
    let cat: Catalog = server::build_catalog(&pool, &cfg.policy);
    let d = cat.dts();
    match out {
        Some(p) => {
            std::fs::write(&p, d).with_context(|| format!("writing {}", p.display()))?;
            eprintln!("wrote {}", p.display());
        }
        None => print!("{d}"),
    }
    Ok(())
}

fn native_path(global: bool) -> Result<PathBuf> {
    Ok(if global {
        crate::store::config_dir().join("config.json")
    } else {
        std::env::current_dir()?.join("omnix.json")
    })
}

fn read_native(p: &std::path::Path) -> Result<Value> {
    match std::fs::read_to_string(p) {
        Ok(t) => json5::from_str(&t).with_context(|| format!("parsing {}", p.display())),
        Err(_) => Ok(json!({})),
    }
}

fn write_native(p: &std::path::Path, v: &Value) -> Result<()> {
    if let Some(d) = p.parent() {
        std::fs::create_dir_all(d)?;
    }
    std::fs::write(p, serde_json::to_string_pretty(v)? + "\n")
        .with_context(|| format!("writing {}", p.display()))
}

pub struct AddArgs {
    pub name: String,
    pub command: Option<String>,
    pub args: Vec<String>,
    pub env: Vec<String>,
    pub url: Option<String>,
    pub transport: Option<String>,
    pub bearer: Option<String>,
    pub oauth: bool,
    pub global: bool,
}

pub fn add(a: AddArgs) -> Result<()> {
    if a.command.is_some() == a.url.is_some() {
        bail!("give exactly one of --command or --url");
    }
    let p = native_path(a.global)?;
    let mut v = read_native(&p)?;
    let mut s = serde_json::Map::new();
    if let Some(c) = a.command {
        s.insert("command".into(), c.into());
        if !a.args.is_empty() {
            s.insert("args".into(), a.args.into());
        }
        let mut env = serde_json::Map::new();
        for kv in a.env {
            let (k, val) = kv
                .split_once('=')
                .with_context(|| format!("--env expects KEY=VALUE, got `{kv}`"))?;
            env.insert(k.into(), val.into());
        }
        if !env.is_empty() {
            s.insert("env".into(), env.into());
        }
    }
    if let Some(u) = a.url {
        s.insert("url".into(), u.into());
        if let Some(t) = a.transport {
            s.insert("transport".into(), t.into());
        }
        if let Some(b) = a.bearer {
            if !(b.starts_with("env:")
                || b.starts_with("file:")
                || b.starts_with("cmd:")
                || b.starts_with("${"))
            {
                eprintln!(
                    "warning: --bearer looks like a literal token and will be stored in plain text; prefer `env:VAR`, `file:PATH` or `cmd:...`"
                );
            }
            s.insert("auth".into(), json!({"type": "bearer", "token": b}));
        } else if a.oauth {
            s.insert("auth".into(), json!({"type": "oauth"}));
        }
    }
    v.as_object_mut()
        .context("config root must be an object")?
        .entry("servers")
        .or_insert_with(|| json!({}))
        .as_object_mut()
        .context("`servers` must be an object")?
        .insert(a.name.clone(), s.into());
    write_native(&p, &v)?;
    eprintln!(
        "added `{}` to {} (note: comments in this file are not preserved)",
        a.name,
        p.display()
    );
    if a.oauth {
        eprintln!("next: run `omnix login {}`", a.name);
    }
    Ok(())
}

pub fn remove(name: &str, global: bool) -> Result<()> {
    let p = native_path(global)?;
    let mut v = read_native(&p)?;
    let removed = v
        .get_mut("servers")
        .and_then(|s| s.as_object_mut())
        .and_then(|s| s.remove(name));
    if removed.is_none() {
        bail!("`{name}` not found in {}", p.display());
    }
    write_native(&p, &v)?;
    eprintln!("removed `{name}` from {}", p.display());
    Ok(())
}
