//! Shared test helpers. The mock MCP servers live in `examples/` (so `cargo install` does not
//! ship them). We ask cargo for the example's executable instead of guessing a path: it builds
//! the example if needed (a no-op when it is current) and reports where the artifact is, which
//! works for any target/build-dir layout and when a single test target is run on its own.
#![allow(dead_code)]

use std::{
    collections::HashMap,
    process::Command,
    sync::{Mutex, OnceLock},
};

/// Absolute path of a built example binary, e.g. `example_bin("mock_mcp")`.
pub fn example_bin(name: &str) -> String {
    static CACHE: OnceLock<Mutex<HashMap<String, String>>> = OnceLock::new();
    let cache = CACHE.get_or_init(Default::default);
    if let Some(p) = cache.lock().unwrap().get(name) {
        return p.clone();
    }
    let exe = std::env::current_exe().expect("current_exe");
    let release = exe
        .ancestors()
        .any(|p| p.file_name().is_some_and(|n| n == "release"));
    let mut cmd = Command::new(option_env!("CARGO").unwrap_or("cargo"));
    cmd.args([
        "build",
        "--example",
        name,
        "--message-format=json",
        "--quiet",
    ])
    .arg("--manifest-path")
    .arg(concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml"));
    if release {
        cmd.arg("--release");
    }
    let out = cmd.output().expect("failed to run cargo build --example");
    assert!(
        out.status.success(),
        "building example {name} failed:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let path = String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
        .filter(|m| m["reason"] == "compiler-artifact" && m["target"]["name"] == name)
        .filter_map(|m| m["executable"].as_str().map(str::to_string))
        .next_back()
        .unwrap_or_else(|| panic!("cargo did not report an executable for example {name}"));
    cache.lock().unwrap().insert(name.to_string(), path.clone());
    path
}
