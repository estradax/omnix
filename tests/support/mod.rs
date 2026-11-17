//! Shared test helpers. The mock MCP servers live in `examples/` (so `cargo install` does not
//! ship them); this finds the built example, building it first if the test was run on its own.
#![allow(dead_code)]

use std::{path::PathBuf, process::Command};

/// Absolute path of a built example binary, e.g. `example_bin("mock_mcp")`.
pub fn example_bin(name: &str) -> String {
    let exe = std::env::current_exe().expect("current_exe");
    // target/<profile>/deps/<test-binary>  ->  target/<profile>
    let profile_dir: PathBuf = exe
        .parent()
        .and_then(|p| p.parent())
        .expect("target dir")
        .into();
    let bin = profile_dir
        .join("examples")
        .join(format!("{name}{}", std::env::consts::EXE_SUFFIX));
    if !bin.exists() {
        // `cargo test --test x` does not build examples; build the one we need.
        let mut cmd = Command::new(option_env!("CARGO").unwrap_or("cargo"));
        cmd.args(["build", "--example", name, "--quiet"]);
        if profile_dir.file_name().is_some_and(|p| p == "release") {
            cmd.arg("--release");
        }
        let status = cmd.status().expect("failed to run cargo build --example");
        assert!(status.success(), "building example {name} failed");
    }
    assert!(
        bin.exists(),
        "example binary not found at {}",
        bin.display()
    );
    bin.display().to_string()
}
