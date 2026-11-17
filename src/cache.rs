//! On-disk catalog cache so `search`/`describe` work instantly while upstreams connect.
//!
//! Keyed by a hash of the server *shape* (names, commands, args, urls, transports) and the
//! omnix version. Credentials (env values, headers, auth blocks) are never part of the key
//! or the cache: only tool names, descriptions and schemas, which the upstream already
//! exposes to anyone who connects. Stale or corrupt caches are ignored.

use crate::{catalog::Entry, config::Config, store};
use sha2::{Digest, Sha256};
use std::path::PathBuf;

pub fn key(cfg: &Config) -> String {
    let shape: Vec<_> = cfg
        .servers
        .iter()
        .map(|(n, s)| serde_json::json!([n, s.command, s.args, s.url, s.transport]))
        .collect();
    let mut h = Sha256::new();
    h.update(env!("CARGO_PKG_VERSION").as_bytes());
    h.update(serde_json::to_vec(&shape).unwrap_or_default());
    hex::encode(&h.finalize()[..12])
}

fn path(key: &str) -> PathBuf {
    store::config_dir()
        .join("catalog-cache")
        .join(format!("{key}.json"))
}

fn disabled() -> bool {
    std::env::var("OMNIX_CATALOG_CACHE").is_ok_and(|v| v == "off" || v == "0")
}

pub fn load(key: &str) -> Option<Vec<Entry>> {
    if disabled() {
        return None;
    }
    serde_json::from_slice(&std::fs::read(path(key)).ok()?).ok()
}

pub fn save(key: &str, entries: &[Entry]) {
    if disabled() {
        return;
    }
    let p = path(key);
    let Some(dir) = p.parent() else { return };
    if std::fs::create_dir_all(dir).is_err() {
        return;
    }
    // Keep only the most recent few caches.
    if let Ok(rd) = std::fs::read_dir(dir) {
        let mut files: Vec<_> = rd
            .filter_map(|e| e.ok())
            .filter_map(|e| Some((e.metadata().ok()?.modified().ok()?, e.path())))
            .collect();
        files.sort();
        for (_, f) in files.iter().rev().skip(8) {
            let _ = std::fs::remove_file(f);
        }
    }
    if let Ok(bytes) = serde_json::to_vec(entries) {
        let tmp = p.with_extension("tmp");
        if std::fs::write(&tmp, bytes).is_ok() {
            let _ = std::fs::rename(&tmp, &p);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ServerConfig;

    #[test]
    fn key_ignores_credentials_but_tracks_shape() {
        let mk = |tok: &str, url: &str| {
            let mut c = Config::default();
            let mut s = ServerConfig {
                url: Some(url.into()),
                ..Default::default()
            };
            s.headers.insert("Authorization".into(), tok.into());
            s.env.insert("K".into(), tok.into());
            s.auth = Some(serde_json::json!({"type": "bearer", "token": tok}));
            c.servers.insert("a".into(), s);
            c
        };
        assert_eq!(key(&mk("one", "http://x")), key(&mk("two", "http://x")));
        assert_ne!(key(&mk("one", "http://x")), key(&mk("one", "http://y")));
    }
}
