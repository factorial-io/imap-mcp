# CLAUDE.md

Rust MCP server bridging claude.ai to IMAP email via OIDC auth.

## Build & Test

```bash
cargo build
cargo test
cargo fmt -- --check
cargo clippy -- -D warnings
```

## Version Control

We use `jj` (Jujutsu) when available, otherwise plain `git`.

## Project Layout

- `src/main.rs` — entrypoint, Axum server setup
- `src/lib.rs` — app config, shared state
- `src/auth.rs` — OAuth/OIDC flow, dynamic client registration, token exchange
- `src/mcp.rs` — MCP tool definitions (list_folders, list_emails, get_email, search_emails, mark_read, mark_unread)
- `src/imap.rs` — IMAP client operations
- `src/session.rs` — Redis session storage, encryption
- `src/error.rs` — error types
- `tests/integration.rs` — integration tests
