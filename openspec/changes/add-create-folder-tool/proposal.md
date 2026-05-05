## Why

Claude.ai users currently can list IMAP folders but cannot create new ones. Adding a `create_folder` MCP tool lets users create custom folders (e.g., project-specific inboxes, archives, or labels) directly through the AI interface without switching to a separate email client.

## What Changes

- Add a new `create_folder` MCP tool that creates an IMAP mailbox folder via the standard RFC 3501 `CREATE` command.
- The tool accepts a `folder_name` parameter and an optional `account` selector.
- Folder name is validated for IMAP injection safety (same validation as existing folder parameters).
- The tool returns a success message or an error if the folder already exists or creation fails.
- No breaking changes to existing tools or APIs.

## Capabilities

### New Capabilities
- `create-folder-mcp-tool`: New MCP tool for creating IMAP folders, including parameter schema, IMAP client integration, error handling, and tests.

### Modified Capabilities
- (none — existing tool behavior is unchanged)

## Impact

- `src/mcp.rs`: New `CreateFolderParams` struct and `create_folder` tool handler.
- `src/imap.rs`: New `create_folder` method on `ImapConnection`.
- `tests/integration.rs`: New parameter deserialization test.
- `README.md`: Tool table update.
- `CLAUDE.md`: Server instructions string update to mention the new tool.
