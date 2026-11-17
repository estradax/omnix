//! E2E: add / remove / list / doctor / find / sdk.
use std::{path::PathBuf, process::Command};

fn tmp() -> PathBuf {
    static N: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let d = std::env::temp_dir().join(format!(
        "omnix-cli-{}-{}",
        std::process::id(),
        N.fetch_add(1, std::sync::atomic::Ordering::SeqCst)
    ));
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn omnix(dir: &PathBuf, args: &[&str]) -> (bool, String, String) {
    let o = Command::new(env!("CARGO_BIN_EXE_omnix"))
        .args(args)
        .current_dir(dir)
        .env("HOME", dir)
        .env("OMNIX_CONFIG_DIR", dir.join("cfg"))
        .env("OMNIX_CREDENTIAL_STORE", "file")
        .output()
        .unwrap();
    (
        o.status.success(),
        String::from_utf8_lossy(&o.stdout).into(),
        String::from_utf8_lossy(&o.stderr).into(),
    )
}

fn with_mock() -> PathBuf {
    let d = tmp();
    let (ok, _, e) = omnix(
        &d,
        &["add", "mock", "--command", env!("CARGO_BIN_EXE_mock_mcp")],
    );
    assert!(ok, "{e}");
    d
}

#[test]
fn add_list_remove_roundtrip() {
    let d = with_mock();
    let (_, out, _) = omnix(&d, &["list"]);
    assert!(out.contains("mock\tstdio"), "{out}");
    // adding with both command and url is rejected
    let (ok, _, e) = omnix(&d, &["add", "bad", "--command", "x", "--url", "http://y"]);
    assert!(!ok && e.contains("exactly one"), "{e}");
    let (ok, _, e) = omnix(
        &d,
        &[
            "add",
            "web",
            "--url",
            "https://h/mcp",
            "--bearer",
            "plain-token",
        ],
    );
    assert!(
        ok && e.contains("plain text"),
        "literal tokens must warn: {e}"
    );
    let (ok, _, _) = omnix(&d, &["remove", "web"]);
    assert!(ok);
    let (ok, _, e) = omnix(&d, &["remove", "web"]);
    assert!(!ok && e.contains("not found"), "{e}");
    let (_, out, _) = omnix(&d, &["list"]);
    assert!(out.contains("mock") && !out.contains("web"), "{out}");
}

#[test]
fn doctor_reports_ok_and_failures() {
    let d = with_mock();
    omnix(
        &d,
        &["add", "broken", "--command", "/definitely/not/a/binary"],
    );
    let (ok, out, _) = omnix(&d, &["doctor"]);
    assert!(ok, "{out}");
    assert!(out.contains("mock") && out.contains("ok, "), "{out}");
    assert!(out.contains("broken") && out.contains("FAILED"), "{out}");
    assert!(out.contains("credential store:"), "{out}");
}

#[test]
fn find_and_sdk() {
    let d = with_mock();
    let (_, out, _) = omnix(&d, &["find", "add numbers"]);
    assert!(out.contains("mock.add"), "{out}");
    let (ok, dts, _) = omnix(&d, &["sdk"]);
    assert!(ok);
    assert!(
        dts.contains("declare const mock: {")
            && dts.contains("add(args: { a: number; b: number }): Promise<any>;"),
        "{dts}"
    );
    let f = d.join("omnix.d.ts");
    let (ok, _, _) = omnix(&d, &["sdk", "--out", f.to_str().unwrap()]);
    assert!(
        ok && std::fs::read_to_string(&f)
            .unwrap()
            .contains("declare const mock")
    );
}
