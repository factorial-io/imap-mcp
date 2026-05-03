## 1. IMAP Client Layer

- [x] 1.1 Add `create_folder` method to `ImapConnection` in `src/imap.rs`
  - Validate `folder_name` with `validate_imap_input`
  - Call `self.session.create(folder_name).await`
  - Map errors to `AppError::Imap`
- [x] 1.2 Run `cargo test` and `cargo clippy` to verify no regressions

## 2. MCP Tool Layer

- [x] 2.1 Add `CreateFolderParams` struct in `src/mcp.rs` with `folder_name: String` and optional `account: Option<String>`
- [x] 2.2 Add `create_folder` tool handler in the `#[tool_router]` impl block
  - Call `self.connect_with(params.account.as_deref()).await?`
  - Call `conn.create_folder(&params.folder_name).await`
  - Return success text: "Folder '{folder_name}' created"
- [x] 2.3 Update `ServerHandler::get_info` instructions string to mention `create_folder`
- [x] 2.4 Run `cargo test` and `cargo clippy`

## 3. Tests

- [x] 3.1 Add `create_folder_params_defaults` test in `tests/integration.rs`
- [x] 3.2 Add `create_folder_params_custom` test in `tests/integration.rs`
- [x] 3.3 Run `cargo test` to verify all tests pass

## 4. Documentation

- [x] 4.1 Add `create_folder` row to README.md tool table
- [x] 4.2 Update CLAUDE.md tool list and recent changes
- [x] 4.3 Run `cargo fmt -- --check`
