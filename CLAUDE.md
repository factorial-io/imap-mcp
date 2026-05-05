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

## Error Handling

Never suppress errors with `.unwrap()`, `.expect()`, or silent `let _ =`. Propagate errors using `?` and return meaningful errors as late as possible. Use `thiserror` for typed domain errors and `anyhow` for ad-hoc context.

## Project Layout

- `src/main.rs` — entrypoint, Axum server setup
- `src/lib.rs` — app config, shared state
- `src/auth.rs` — OAuth/OIDC flow, dynamic client registration, token exchange
- `src/mcp.rs` — MCP tool definitions (list_folders, create_folder, list_emails, get_email, search_emails, mark_read, mark_unread, move_email, delete_email)
- `src/imap.rs` — IMAP client operations
- `src/session.rs` — Redis session storage, encryption
- `src/error.rs` — error types
- `src/extract.rs` — text extraction for attachments (PDF, DOCX, XLSX, PPTX)
- `tests/integration.rs` — integration tests

## Recent Changes

- 001-limit-attachment-size: Added attachment size limiting and text extraction
- 002-move-delete-tools: Added `move_email` and `delete_email` MCP tools with Trash folder resolution and IMAP MOVE/COPY fallback
- 003-create-folder: Added `create_folder` MCP tool for creating IMAP folders
