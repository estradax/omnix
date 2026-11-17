# Contributing

Thanks for your interest. omnix is alpha software and the most useful contributions right now are bug reports
from real-world use (a real MCP server or OAuth provider that misbehaves) and verified fixes to the agent config
formats in `src/setup.rs`.

## Setup

```sh
cargo test                  # unit + end-to-end tests (spawns child processes; takes ~30 s)
cargo clippy --all-targets  # must be warning-free
cargo fmt
```

The end-to-end tests need `sh` and the `openssl` CLI (used to generate JWT test keys). They never touch your real
agent configs: every test runs with a temporary `HOME` and `OMNIX_CONFIG_DIR`.

## Layout

| Path | |
|---|---|
| `src/server.rs` | The gateway's MCP server: `search`, `describe`, `execute`, lazy upstream connection. |
| `src/sandbox.rs` | QuickJS sandbox, limits, host-call bridge. `src/sandbox_tests.rs` are the adversarial tests. |
| `src/pool.rs`, `src/sse.rs` | Upstream connections (stdio, streamable HTTP, legacy SSE). |
| `src/auth.rs`, `src/oauth.rs`, `src/store.rs` | Credentials, OAuth flows, keychain / encrypted-file storage. |
| `src/policy.rs`, `src/handles.rs` | Allow/deny, read-only mode, hooks, audit log, binary handles. |
| `src/setup.rs` | `omnix setup`: agent config adapters, diff/confirm/backup/undo. |
| `examples/mock_*.rs` | Mock MCP servers used by the tests and the benchmark (examples, so `cargo install` does not ship them). |
| `tests/` | End-to-end tests, including mock OAuth and legacy-SSE servers. |

## Guidelines

- Keep changes focused, and add a test. For anything touching auth, the sandbox, policy or `setup`, a test that
  fails without your change is expected.
- **Never** log or print credentials, tokens or argument values. There are tests that check this; keep them green.
- If you change an agent's config format in `setup.rs`, link the vendor documentation in the PR and set that
  agent's `verified` flag only if you checked the current docs.
- By contributing you agree your work is licensed under the project's `MIT OR Apache-2.0` terms.
