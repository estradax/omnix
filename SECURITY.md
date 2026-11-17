# Security policy

omnix handles credentials and runs model-written code, so security reports are taken seriously.

## Reporting a vulnerability

Please **do not open a public issue**. Use GitHub's private reporting instead:
**Security → Report a vulnerability** on this repository
(<https://github.com/estradax/omnix/security/advisories/new>).

Include what you found, how to reproduce it, and the impact you think it has. You will get an acknowledgement as
soon as the maintainer sees it; this is a small project, so please allow some time.

## Scope

Things that are in scope and welcome:

- Escaping the JavaScript sandbox, or reaching host capabilities (network, filesystem, environment, credentials).
- Credential leaks: into logs, error messages, the audit log, the catalog cache, or the sandbox.
- Bypassing `policy` (allow/deny, read-only mode, `before_call`).
- OAuth flow flaws: redirect/`iss` handling, token storage, sending tokens to the wrong origin.
- `omnix setup` modifying files without confirmation, or losing data in an agent's config.

Out of scope: vulnerabilities in the upstream MCP servers you connect, and the model-side risks described in the
README's security model (prompt injection is mitigated with `policy`, not eliminated).

## Supported versions

Only the latest commit on `main` is supported while the project is alpha.
