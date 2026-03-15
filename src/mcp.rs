use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{CallToolResult, Content, ServerCapabilities, ServerInfo};
use rmcp::schemars;
use rmcp::{tool, tool_handler, tool_router, ServerHandler};
use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;

use crate::imap::{self, ImapConnection};

/// MCP server instance — one per request, holds session context.
pub struct ImapMcpServer {
    pub email: String,
    imap_password: SecretString,
    pub imap_host: String,
    pub imap_port: u16,
    tool_router: rmcp::handler::server::tool::ToolRouter<Self>,
}

impl ImapMcpServer {
    pub fn new(email: String, imap_password: String, imap_host: String, imap_port: u16) -> Self {
        Self {
            email,
            imap_password: SecretString::from(imap_password),
            imap_host,
            imap_port,
            tool_router: Self::tool_router(),
        }
    }

    /// Open a fresh IMAP connection using this server's credentials.
    async fn connect(&self) -> Result<ImapConnection, rmcp::ErrorData> {
        ImapConnection::connect(
            &self.imap_host,
            self.imap_port,
            &self.email,
            self.imap_password.expose_secret(),
        )
        .await
        .map_err(|e| rmcp::ErrorData::internal_error(format!("IMAP connection failed: {e}"), None))
    }
}

// --- Tool parameter types ---

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ListEmailsParams {
    /// IMAP folder name (default: INBOX)
    #[serde(default = "default_inbox")]
    pub folder: String,
    /// Maximum number of emails to return (default: 20)
    #[serde(default = "default_limit")]
    pub limit: u32,
    /// Number of emails to skip from newest (default: 0)
    #[serde(default)]
    pub offset: u32,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct GetEmailParams {
    /// Email UID to fetch
    pub uid: u32,
    /// IMAP folder name (default: INBOX)
    #[serde(default = "default_inbox")]
    pub folder: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct SearchEmailsParams {
    /// IMAP SEARCH criteria string (e.g. "FROM \"user@example.com\"", "SUBJECT \"hello\"", "UNSEEN")
    pub query: String,
    /// IMAP folder name (default: INBOX)
    #[serde(default = "default_inbox")]
    pub folder: String,
    /// Maximum number of results (default: 20)
    #[serde(default = "default_limit")]
    pub limit: u32,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct GetAttachmentParams {
    /// Email UID
    pub uid: u32,
    /// Zero-based attachment index (from the attachments list in get_email)
    pub attachment_index: usize,
    /// IMAP folder name (default: INBOX)
    #[serde(default = "default_inbox")]
    pub folder: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct MarkParams {
    /// Email UID
    pub uid: u32,
    /// IMAP folder name (default: INBOX)
    #[serde(default = "default_inbox")]
    pub folder: String,
}

fn default_inbox() -> String {
    "INBOX".to_string()
}
fn default_limit() -> u32 {
    20
}

// --- Tool implementations ---

#[tool_router]
impl ImapMcpServer {
    #[tool(description = "List all IMAP mailbox folders")]
    async fn list_folders(&self) -> Result<CallToolResult, rmcp::ErrorData> {
        let mut conn = self.connect().await?;
        let folders = conn
            .list_folders()
            .await
            .map_err(|e| rmcp::ErrorData::internal_error(format!("{e}"), None))?;
        conn.logout().await.ok();
        let json = Content::json(&folders)
            .map_err(|e| rmcp::ErrorData::internal_error(format!("JSON error: {e}"), None))?;
        Ok(CallToolResult::success(vec![json]))
    }

    #[tool(
        description = "List emails in a folder with pagination. Returns uid, date, from, subject, and seen status."
    )]
    async fn list_emails(
        &self,
        Parameters(params): Parameters<ListEmailsParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let mut conn = self.connect().await?;
        let emails = conn
            .list_emails(&params.folder, params.limit, params.offset)
            .await
            .map_err(|e| rmcp::ErrorData::internal_error(format!("{e}"), None))?;
        conn.logout().await.ok();
        let json = Content::json(&emails)
            .map_err(|e| rmcp::ErrorData::internal_error(format!("JSON error: {e}"), None))?;
        Ok(CallToolResult::success(vec![json]))
    }

    #[tool(description = "Fetch a full email by UID. Returns headers, plain-text body, and a list of attachments with metadata (filename, mime_type, size, index). Use get_attachment with the index to fetch attachment content.")]
    async fn get_email(
        &self,
        Parameters(params): Parameters<GetEmailParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let mut conn = self.connect().await?;
        let email = conn
            .get_email(&params.folder, params.uid)
            .await
            .map_err(|e| rmcp::ErrorData::internal_error(format!("{e}"), None))?;
        conn.logout().await.ok();
        let json = Content::json(&email)
            .map_err(|e| rmcp::ErrorData::internal_error(format!("JSON error: {e}"), None))?;
        Ok(CallToolResult::success(vec![json]))
    }

    #[tool(
        description = "Fetch an email attachment by UID and attachment index. Use get_email first to see the list of attachments. Returns image content for images (visible to the LLM), text for text-based files, or base64-encoded data for binary files."
    )]
    async fn get_attachment(
        &self,
        Parameters(params): Parameters<GetAttachmentParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let mut conn = self.connect().await?;
        let attachment = conn
            .get_attachment(&params.folder, params.uid, params.attachment_index)
            .await
            .map_err(|e| rmcp::ErrorData::internal_error(format!("{e}"), None))?;
        conn.logout().await.ok();

        let mime = &attachment.info.mime_type;
        let filename = attachment
            .info
            .filename
            .clone()
            .unwrap_or_else(|| format!("attachment_{}", params.attachment_index));

        // Images: return as image content so the LLM can see them
        if mime.starts_with("image/") {
            let b64 = imap::base64_encode(&attachment.data);
            return Ok(CallToolResult::success(vec![
                Content::text(format!(
                    "Image attachment: {filename} ({mime}, {} bytes)",
                    attachment.info.size
                )),
                Content::image(b64, mime.clone()),
            ]));
        }

        // Text-based content types: return as text
        if mime.starts_with("text/")
            || mime == "application/json"
            || mime == "application/xml"
            || mime == "application/javascript"
            || mime == "application/csv"
        {
            let text = String::from_utf8_lossy(&attachment.data).to_string();
            return Ok(CallToolResult::success(vec![
                Content::text(format!(
                    "Text attachment: {filename} ({mime}, {} bytes)\n\n{text}",
                    attachment.info.size
                )),
            ]));
        }

        // Everything else: return as base64-encoded blob with metadata
        let b64 = imap::base64_encode(&attachment.data);
        Ok(CallToolResult::success(vec![Content::text(format!(
            "Binary attachment: {filename} ({mime}, {} bytes)\nBase64-encoded data:\n{b64}",
            attachment.info.size
        ))]))
    }

    #[tool(
        description = "Search emails using IMAP SEARCH criteria. Examples: UNSEEN, FROM \"user@example.com\", SUBJECT \"hello\", SINCE 01-Jan-2024"
    )]
    async fn search_emails(
        &self,
        Parameters(params): Parameters<SearchEmailsParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let mut conn = self.connect().await?;
        let emails = conn
            .search_emails(&params.folder, &params.query, params.limit)
            .await
            .map_err(|e| rmcp::ErrorData::internal_error(format!("{e}"), None))?;
        conn.logout().await.ok();
        let json = Content::json(&emails)
            .map_err(|e| rmcp::ErrorData::internal_error(format!("JSON error: {e}"), None))?;
        Ok(CallToolResult::success(vec![json]))
    }

    #[tool(description = "Mark an email as read (set \\Seen flag) by UID")]
    async fn mark_read(
        &self,
        Parameters(params): Parameters<MarkParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let mut conn = self.connect().await?;
        conn.mark_read(&params.folder, params.uid)
            .await
            .map_err(|e| rmcp::ErrorData::internal_error(format!("{e}"), None))?;
        conn.logout().await.ok();
        Ok(CallToolResult::success(vec![Content::text(format!(
            "Email UID {} marked as read",
            params.uid
        ))]))
    }

    #[tool(description = "Mark an email as unread (unset \\Seen flag) by UID")]
    async fn mark_unread(
        &self,
        Parameters(params): Parameters<MarkParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let mut conn = self.connect().await?;
        conn.mark_unread(&params.folder, params.uid)
            .await
            .map_err(|e| rmcp::ErrorData::internal_error(format!("{e}"), None))?;
        conn.logout().await.ok();
        Ok(CallToolResult::success(vec![Content::text(format!(
            "Email UID {} marked as unread",
            params.uid
        ))]))
    }
}

#[tool_handler]
impl ServerHandler for ImapMcpServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(
            ServerCapabilities::builder().enable_tools().build(),
        )
        .with_instructions(
            "IMAP email server. Use the tools to list folders, read emails, search, manage read status, and fetch attachments. When reading an email with get_email, attachment metadata is included. Use get_attachment with the attachment index to fetch the actual content — images are returned as visible image content, text files as text, and other formats as base64.".to_string(),
        )
    }
}
