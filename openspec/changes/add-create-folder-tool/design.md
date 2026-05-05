## Context

The IMAP MCP server already supports listing folders (`list_folders`), moving emails between folders (`move_email`), and deleting/marking emails. Folder creation is missing, forcing users to switch to a native email client to set up new folders before they can use them with the MCP tools.

The codebase uses `async-imap` (v0.11.2) which exposes `session.create(mailbox_name)` implementing RFC 3501 `CREATE`. Existing validation (`validate_imap_input`) guards against CRLF/NUL injection in folder names.

## Goals / Non-Goals

**Goals:**
- Expose an MCP tool `create_folder` that creates an IMAP folder via `session.create()`.
- Reuse existing patterns: parameter struct with `schemars::JsonSchema`, `account` selector, input validation, error propagation via `AppError::Imap`.
- Update documentation strings so the new tool is discoverable by the LLM.

**Non-Goals:**
- Recursive folder creation (the server already auto-creates parent hierarchies via IMAP `CREATE` semantics).
- Setting special-use attributes (e.g., `\Trash`, `\Drafts`) on creation.
- Renaming or deleting folders.

## Decisions

- **Parameter name `folder_name`** instead of `folder` to avoid confusion with `folder` used as a source/target in other tools (where it refers to an existing folder).
- **No `parent` parameter**: IMAP `CREATE` with hierarchy separators (e.g., `Project/Invoices`) naturally creates nested folders. Users pass the full path as `folder_name`.
- **Success returns text, not JSON**: Consistent with `mark_read`, `mark_unread`, `move_email`, `delete_email` which return plain text success messages.

## Risks / Trade-offs

- [Risk] Some IMAP servers reject `CREATE` for folders that already exist → mapped to `AppError::Imap` and surfaced as a clear error message.
- [Risk] Hierarchy separator varies by server (`/`, `.`, `\`) → no mitigation; the user is responsible for knowing their server's separator (same as they already must for `move_email`).
