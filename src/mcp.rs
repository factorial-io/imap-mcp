use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{CallToolResult, Content, ServerCapabilities, ServerInfo};
use rmcp::schemars;
use rmcp::{tool, tool_handler, tool_router, ServerHandler};
use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;

use crate::extract;
use crate::imap::{self, DraftContent, ImapConnection, MAX_LLM_CONTENT_SIZE};

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

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct CreateDraftParams {
    /// Recipient email address(es), comma-separated for multiple
    pub to: String,
    /// Email subject line
    pub subject: String,
    /// Plain text email body
    pub body: String,
    /// CC recipient(s), comma-separated (optional)
    #[serde(default)]
    pub cc: Option<String>,
    /// BCC recipient(s), comma-separated (optional)
    #[serde(default)]
    pub bcc: Option<String>,
    /// IMAP folder to save the draft in (default: Drafts)
    #[serde(default = "default_drafts")]
    pub folder: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct UpdateDraftParams {
    /// UID of the existing draft to update
    pub uid: u32,
    /// Recipient email address(es), comma-separated for multiple
    pub to: String,
    /// Email subject line
    pub subject: String,
    /// Plain text email body
    pub body: String,
    /// CC recipient(s), comma-separated (optional)
    #[serde(default)]
    pub cc: Option<String>,
    /// BCC recipient(s), comma-separated (optional)
    #[serde(default)]
    pub bcc: Option<String>,
    /// IMAP folder containing the draft (default: Drafts)
    #[serde(default = "default_drafts")]
    pub folder: String,
}

fn default_inbox() -> String {
    "INBOX".to_string()
}
fn default_drafts() -> String {
    "Drafts".to_string()
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

    #[tool(
        description = "Fetch a full email by UID. Returns headers, plain-text body, and a list of attachments with metadata (filename, mime_type, size, index). Use get_attachment with the index to fetch attachment content."
    )]
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
        description = "Fetch an email attachment by UID and attachment index. Use get_email first to see the list of attachments. For PDFs and Office documents (DOCX, XLSX, PPTX), returns extracted text content. For text files, returns content directly. Large content is truncated to 200 KB. Images under 200 KB are returned visually; larger images and unsupported binary formats return metadata only."
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
        let size = attachment.info.size;
        let filename = attachment
            .info
            .filename
            .clone()
            .unwrap_or_else(|| format!("attachment_{}", params.attachment_index));

        // 1. Try text extraction for supported document formats (PDF, DOCX, XLSX, PPTX)
        match extract::extract_text(&attachment.data, mime) {
            Ok(Some(raw_text)) => {
                let extracted = extract::build_extracted(raw_text, mime);
                let mut header = format!(
                    "Text content extracted from: {filename} ({mime}, {size} bytes, {})",
                    extracted.source_format
                );
                if extracted.truncated {
                    header.push_str(&format!(
                        "\nNOTE: Extracted text truncated to {} KB (full text: {} KB). Showing first portion only.",
                        extracted.included_bytes / 1024,
                        extracted.total_bytes / 1024,
                    ));
                }
                return Ok(CallToolResult::success(vec![Content::text(format!(
                    "{header}\n\n{}",
                    extracted.text
                ))]));
            }
            Err(err_msg) => {
                // Extraction failed — return metadata with error explanation
                return Ok(CallToolResult::success(vec![Content::text(format!(
                    "Attachment: {filename} ({mime}, {size} bytes)\nText extraction failed: {err_msg}. Content cannot be displayed."
                ))]));
            }
            Ok(None) => {
                // Not an extractable format — fall through to other handlers
            }
        }

        // 2. Images: return as image content if within size limit
        if mime.starts_with("image/") {
            if size > MAX_LLM_CONTENT_SIZE {
                let human_size = format_size(size);
                return Ok(CallToolResult::success(vec![Content::text(format!(
                    "Image attachment: {filename} ({mime}, {size} bytes)\nNOTE: Image too large to include ({human_size}). Only metadata is shown."
                ))]));
            }
            let b64 = imap::base64_encode(&attachment.data);
            return Ok(CallToolResult::success(vec![
                Content::text(format!(
                    "Image attachment: {filename} ({mime}, {size} bytes)"
                )),
                Content::image(b64, mime.clone()),
            ]));
        }

        // 3. Text-based content types: return with truncation if needed
        if is_text_mime(mime) {
            let text = String::from_utf8_lossy(&attachment.data);
            let (content, truncated) = extract::truncate_to_limit(&text, MAX_LLM_CONTENT_SIZE);
            let mut header = format!("Text attachment: {filename} ({mime}, {size} bytes)");
            if truncated {
                header.push_str(&format!(
                    "\nNOTE: Content truncated to {} KB (full size: {} KB). Showing first portion only.",
                    content.len() / 1024,
                    text.len() / 1024,
                ));
            }
            return Ok(CallToolResult::success(vec![Content::text(format!(
                "{header}\n\n{content}"
            ))]));
        }

        // 4. Unsupported binary: metadata only
        Ok(CallToolResult::success(vec![Content::text(format!(
            "Binary attachment: {filename} ({mime}, {size} bytes)\nText extraction is not supported for this format. Only metadata is shown."
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

    #[tool(
        description = "Create a new draft email. The draft is saved to the specified folder (default: Drafts) and can be edited later with update_draft or sent from your email client."
    )]
    async fn create_draft(
        &self,
        Parameters(params): Parameters<CreateDraftParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let mut conn = self.connect().await?;
        let draft = DraftContent {
            from: &self.email,
            to: &params.to,
            subject: &params.subject,
            body: &params.body,
            cc: params.cc.as_deref(),
            bcc: params.bcc.as_deref(),
        };
        let uid = conn
            .create_draft(&params.folder, &draft)
            .await
            .map_err(|e| rmcp::ErrorData::internal_error(format!("{e}"), None))?;
        conn.logout().await.ok();

        let uid_info = match uid {
            Some(uid) => format!(" (UID: {uid})"),
            None => String::new(),
        };
        Ok(CallToolResult::success(vec![Content::text(format!(
            "Draft created in folder '{}'{uid_info}",
            params.folder
        ))]))
    }

    #[tool(
        description = "Update an existing draft email by UID. Replaces the old draft with the new content in the same folder."
    )]
    async fn update_draft(
        &self,
        Parameters(params): Parameters<UpdateDraftParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let mut conn = self.connect().await?;
        let draft = DraftContent {
            from: &self.email,
            to: &params.to,
            subject: &params.subject,
            body: &params.body,
            cc: params.cc.as_deref(),
            bcc: params.bcc.as_deref(),
        };
        let new_uid = conn
            .update_draft(&params.folder, params.uid, &draft)
            .await
            .map_err(|e| rmcp::ErrorData::internal_error(format!("{e}"), None))?;
        conn.logout().await.ok();

        let new_uid_info = match new_uid {
            Some(uid) => format!(" New UID: {uid}"),
            None => String::new(),
        };
        Ok(CallToolResult::success(vec![Content::text(format!(
            "Draft UID {} updated in folder '{}'.{new_uid_info}",
            params.uid, params.folder
        ))]))
    }
}

/// Check if a MIME type is text-based (returned as-is, not extracted).
fn is_text_mime(mime: &str) -> bool {
    mime.starts_with("text/")
        || mime == "application/json"
        || mime == "application/xml"
        || mime == "application/javascript"
        || mime == "application/csv"
}

/// Format a byte size as a human-readable string.
fn format_size(bytes: usize) -> String {
    if bytes >= 1024 * 1024 {
        format!("{:.1} MB", bytes as f64 / (1024.0 * 1024.0))
    } else if bytes >= 1024 {
        format!("{:.0} KB", bytes as f64 / 1024.0)
    } else {
        format!("{bytes} bytes")
    }
}

#[tool_handler]
impl ServerHandler for ImapMcpServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(
            ServerCapabilities::builder().enable_tools().build(),
        )
        .with_instructions(
            "IMAP email server. Use the tools to list folders, read emails, search, manage read status, fetch attachments, and create or edit drafts. When reading an email with get_email, attachment metadata is included. Use get_attachment with the attachment index to fetch the actual content — for PDFs and Office documents, extracted text is returned. Text files are returned directly. Large content is truncated to 200 KB. Images under 200 KB are shown visually. Larger images and unsupported binary formats return metadata only. Use create_draft to compose a new draft and update_draft to modify an existing one.".to_string(),
        )
    }
}
