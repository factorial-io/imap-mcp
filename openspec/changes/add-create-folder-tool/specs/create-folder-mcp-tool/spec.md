## ADDED Requirements

### Requirement: create_folder MCP tool creates an IMAP folder
The system SHALL expose an MCP tool named `create_folder` that creates a new mailbox folder on the connected IMAP server using the RFC 3501 CREATE command.

#### Scenario: Successful folder creation
- **WHEN** the MCP tool `create_folder` is called with `folder_name` set to "Projects"
- **THEN** the IMAP server creates the folder "Projects"
- **AND** the tool returns a success message "Folder 'Projects' created"

#### Scenario: Folder creation with account selector
- **WHEN** the MCP tool `create_folder` is called with `folder_name` set to "Work" and `account` set to a valid account_id
- **THEN** the folder is created on the selected account's IMAP server
- **AND** the tool returns a success message

#### Scenario: Folder name with hierarchy separator
- **WHEN** the MCP tool `create_folder` is called with `folder_name` set to "Archive/2024"
- **THEN** the IMAP server creates the folder path using its hierarchy separator
- **AND** the tool returns a success message

### Requirement: create_folder validates input and propagates errors
The system SHALL validate the folder name for IMAP injection safety and surface server-side errors to the user.

#### Scenario: Invalid folder name characters
- **WHEN** the MCP tool `create_folder` is called with `folder_name` containing a newline character
- **THEN** the tool returns an error indicating invalid characters in the folder name

#### Scenario: Folder already exists
- **WHEN** the MCP tool `create_folder` is called with `folder_name` for a folder that already exists on the server
- **THEN** the IMAP server's error response is propagated as a tool error
