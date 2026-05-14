use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{CallToolResult, Content, ServerCapabilities, ServerInfo};
use rmcp::schemars;
use rmcp::{tool, tool_handler, tool_router, ServerHandler};
use serde::Deserialize;

use crate::error::AppError;
use crate::extract;
use crate::imap::{
    self, AttachmentData, DraftContent, ExtractionHint, ImapConnection, MAX_LLM_CONTENT_SIZE,
    MAX_RAW_BYTES_SIZE,
};
use crate::manage::{AccountSummary, ListAccountsResult};
use crate::session::{Account, DownloadTicket, DOWNLOAD_TICKET_TTL};
use crate::{AccountResolver, ResolveError};

/// MCP server instance — one per request, holds session context.
pub struct ImapMcpServer {
    resolver: AccountResolver,
}

impl ImapMcpServer {
    pub fn new(resolver: AccountResolver) -> Self {
        Self { resolver }
    }

    /// Resolve an account, connect, record success on login. The returned
    /// connection has already passed IMAP login.
    async fn connect_with(
        &self,
        selector: Option<&str>,
    ) -> Result<(Account, ImapConnection), rmcp::ErrorData> {
        let account = self
            .resolver
            .resolve(selector)
            .await
            .map_err(resolve_to_rmcp)?;
        let password = self
            .resolver
            .store
            .decrypt_account_password(&account)
            .map_err(|e| rmcp::ErrorData::internal_error(format!("decrypt failed: {e}"), None))?;

        match ImapConnection::connect(
            &account.imap_host,
            account.imap_port,
            &account.imap_email,
            &password,
        )
        .await
        {
            Ok(conn) => {
                // Login succeeded — clear the failure counter and bump last_used_at.
                if let Err(e) = self
                    .resolver
                    .store
                    .record_account_success(&self.resolver.oidc_sub, &account.account_id)
                    .await
                {
                    tracing::warn!("failed to record account success: {e}");
                }
                tracing::info!(
                    oidc_sub = %self.resolver.oidc_sub,
                    account_id = %account.account_id,
                    imap_email = %account.imap_email,
                    imap_host = %account.imap_host,
                    "IMAP login ok"
                );
                Ok((account, conn))
            }
            Err(AppError::ImapAuth) => {
                // Don't suppress Redis errors silently: log and proceed with
                // `false` (we'll still surface a "login failed" error to the
                // caller, just won't be able to mark the account auto-disabled
                // until Redis recovers).
                let just_disabled = match self
                    .resolver
                    .store
                    .record_account_auth_failure(&self.resolver.oidc_sub, &account.account_id)
                    .await
                {
                    Ok(v) => v,
                    Err(e) => {
                        tracing::warn!(
                            oidc_sub = %self.resolver.oidc_sub,
                            account_id = %account.account_id,
                            error = %e,
                            "failed to record auth failure"
                        );
                        false
                    }
                };
                let manage_url = self
                    .resolver
                    .fresh_manage_url()
                    .await
                    .map_err(resolve_to_rmcp)?;
                let msg = if just_disabled {
                    format!(
                        "IMAP login failed; account '{}' is now disabled after repeated failures. Re-validate at {manage_url}",
                        account.label
                    )
                } else {
                    format!(
                        "IMAP login failed for account '{}'. If the password changed, re-validate at {manage_url}",
                        account.label
                    )
                };
                Err(rmcp::ErrorData::invalid_request(msg, None))
            }
            Err(e) => Err(rmcp::ErrorData::internal_error(
                format!("IMAP connection failed: {e}"),
                None,
            )),
        }
    }
}

fn resolve_to_rmcp(err: ResolveError) -> rmcp::ErrorData {
    match err {
        ResolveError::NoAccounts { manage_url } => rmcp::ErrorData::invalid_request(
            format!(
                "No mailboxes connected. Open {manage_url} in your browser to add one."
            ),
            None,
        ),
        ResolveError::AccountRequired => rmcp::ErrorData::invalid_params(
            "Multiple mailboxes are connected — pass `account` (account_id or label). Call list_accounts to see them.",
            None,
        ),
        ResolveError::NotFound(s) => {
            rmcp::ErrorData::invalid_params(format!("Account '{s}' not found."), None)
        }
        ResolveError::Ambiguous(s) => rmcp::ErrorData::invalid_params(
            format!("Label '{s}' matches multiple accounts — pass account_id instead."),
            None,
        ),
        ResolveError::Disabled { manage_url } => rmcp::ErrorData::invalid_request(
            format!(
                "Account is disabled (too many failed logins). Re-validate at {manage_url}"
            ),
            None,
        ),
        ResolveError::ProviderRemoved {
            host,
            port,
            manage_url,
        } => rmcp::ErrorData::invalid_request(
            format!(
                "This mailbox uses provider {host}:{port} which is no longer in the operator's allowlist. Remove the account and reconnect at {manage_url}"
            ),
            None,
        ),
        ResolveError::Internal(s) => rmcp::ErrorData::internal_error(s, None),
    }
}

// --- Shared `account` parameter ---

/// Optional `account` selector applied to every IMAP-touching tool. Accepts
/// either an `account_id` (preferred, unambiguous) or a `label`. Required
/// when the user has more than one connected mailbox.
#[derive(Debug, Default, Deserialize, schemars::JsonSchema)]
pub struct AccountSelector {
    /// Account id or label. If you have only one mailbox, leave this off.
    /// If you have more than one, call list_accounts to see them and pass
    /// the account_id of the one you want.
    #[serde(default)]
    pub account: Option<String>,
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
    /// Optional account selector (account_id or label). Required if you have
    /// more than one mailbox connected.
    #[serde(default)]
    pub account: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct GetEmailParams {
    /// Email UID to fetch
    pub uid: u32,
    /// IMAP folder name (default: INBOX)
    #[serde(default = "default_inbox")]
    pub folder: String,
    /// Optional account selector (account_id or label).
    #[serde(default)]
    pub account: Option<String>,
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
    /// Optional account selector (account_id or label).
    #[serde(default)]
    pub account: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct GetAttachmentParams {
    /// Email UID
    pub uid: u32,
    /// Path to the attachment from the email root, taken verbatim from the
    /// `index` field returned by `get_email`. Top-level attachments are a
    /// single-element array like `[0]`; an attachment nested inside a
    /// forwarded `.eml` looks like `[0, 1]` ("the second attachment inside the
    /// first attachment of the parent email"). Paths can descend through up
    /// to five levels of `message/rfc822` parts.
    pub attachment_index: Vec<usize>,
    /// IMAP folder name (default: INBOX)
    #[serde(default = "default_inbox")]
    pub folder: String,
    /// Optional account selector (account_id or label).
    #[serde(default)]
    pub account: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct DownloadAttachmentParams {
    /// Email UID
    pub uid: u32,
    /// Path to the attachment (same syntax as `get_attachment`).
    pub attachment_index: Vec<usize>,
    /// IMAP folder name (default: INBOX)
    #[serde(default = "default_inbox")]
    pub folder: String,
    /// Optional account selector (account_id or label).
    #[serde(default)]
    pub account: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct MarkParams {
    /// Email UID
    pub uid: u32,
    /// IMAP folder name (default: INBOX)
    #[serde(default = "default_inbox")]
    pub folder: String,
    /// Optional account selector (account_id or label).
    #[serde(default)]
    pub account: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct CreateDraftParams {
    /// Recipient email address(es), comma-separated for multiple
    pub to: String,
    /// Email subject line
    pub subject: String,
    /// Plain text email body. IMPORTANT: Use newline characters to separate paragraphs and lines — do not put everything on a single line.
    pub body: String,
    /// Optional HTML body. When provided, the email is sent as multipart/alternative with both plain text and HTML parts. Use a safe subset of HTML (paragraphs, headings, lists, bold/italic, links). The plain text body is always required as fallback for clients that don't render HTML.
    #[serde(default)]
    pub html_body: Option<String>,
    /// CC recipient(s), comma-separated (optional)
    #[serde(default)]
    pub cc: Option<String>,
    /// BCC recipient(s), comma-separated (optional)
    #[serde(default)]
    pub bcc: Option<String>,
    /// Single Message-ID of the email being replied to (sets In-Reply-To header). Get this from the message_id field of get_email. Must be exactly one Message-ID (e.g. "<abc@example.com>"), not multiple.
    #[serde(default)]
    pub in_reply_to: Option<String>,
    /// Space-separated Message-IDs for the References header (threading chain). Build this by appending the original email's message_id to its references field.
    #[serde(default)]
    pub references: Option<String>,
    /// IMAP folder to save the draft in (default: Drafts)
    #[serde(default = "default_drafts")]
    pub folder: String,
    /// Optional account selector (account_id or label).
    #[serde(default)]
    pub account: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct UpdateDraftParams {
    /// UID of the existing draft to update
    pub uid: u32,
    /// Recipient email address(es), comma-separated for multiple
    pub to: String,
    /// Email subject line
    pub subject: String,
    /// Plain text email body. IMPORTANT: Use newline characters to separate paragraphs and lines — do not put everything on a single line.
    pub body: String,
    /// Optional HTML body. When provided, the email is sent as multipart/alternative with both plain text and HTML parts. Use a safe subset of HTML (paragraphs, headings, lists, bold/italic, links). The plain text body is always required as fallback for clients that don't render HTML.
    #[serde(default)]
    pub html_body: Option<String>,
    /// CC recipient(s), comma-separated (optional)
    #[serde(default)]
    pub cc: Option<String>,
    /// BCC recipient(s), comma-separated (optional)
    #[serde(default)]
    pub bcc: Option<String>,
    /// Single Message-ID of the email being replied to (sets In-Reply-To header). Must be exactly one Message-ID (e.g. "<abc@example.com>"), not multiple.
    #[serde(default)]
    pub in_reply_to: Option<String>,
    /// Space-separated Message-IDs for the References header (threading chain).
    #[serde(default)]
    pub references: Option<String>,
    /// IMAP folder containing the draft (default: Drafts)
    #[serde(default = "default_drafts")]
    pub folder: String,
    /// Optional account selector (account_id or label).
    #[serde(default)]
    pub account: Option<String>,
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
    #[tool(
        description = "List the mailboxes (IMAP accounts) connected to this MCP server for the current user. Returns each account's id, label, IMAP login email, host, last-used time, disabled flag, and is_default flag, plus a short-lived signed manage_url the user can open in their browser to add, remove, or change the default. Tool calls that omit `account` resolve to the account marked is_default; pass `account` (account_id or label) to target a specific one."
    )]
    async fn list_accounts(&self) -> Result<CallToolResult, rmcp::ErrorData> {
        let accounts = self.resolver.list().await.map_err(resolve_to_rmcp)?;
        let default_id = self
            .resolver
            .store
            .get_default_account_id(&self.resolver.oidc_sub)
            .await
            .map_err(|e| rmcp::ErrorData::internal_error(format!("default lookup: {e}"), None))?;
        let manage_url = crate::manage::issue_manage_url(
            &self.resolver.store,
            &self.resolver.base_url,
            &self.resolver.oidc_sub,
            &self.resolver.oidc_email,
        )
        .await
        .map_err(|e| rmcp::ErrorData::internal_error(format!("manage_url: {e}"), None))?;

        let summaries: Vec<AccountSummary> = accounts
            .iter()
            .map(|a| AccountSummary::from_account(a, default_id.as_deref()))
            .collect();
        let result = ListAccountsResult {
            accounts: summaries,
            manage_url,
        };
        let json = Content::json(&result)
            .map_err(|e| rmcp::ErrorData::internal_error(format!("JSON error: {e}"), None))?;
        Ok(CallToolResult::success(vec![json]))
    }

    #[tool(
        description = "Return a fresh, short-lived (15 minute) signed URL the user can open in their browser to add a new mailbox to this MCP server. Use this when the user says something like 'connect my Gmail' or 'add my work email' — surface the URL to them. After they finish in the browser, call list_accounts to confirm."
    )]
    async fn add_account_url(&self) -> Result<CallToolResult, rmcp::ErrorData> {
        let manage_url = crate::manage::issue_manage_url(
            &self.resolver.store,
            &self.resolver.base_url,
            &self.resolver.oidc_sub,
            &self.resolver.oidc_email,
        )
        .await
        .map_err(|e| rmcp::ErrorData::internal_error(format!("manage_url: {e}"), None))?;
        let json = Content::json(&manage_url)
            .map_err(|e| rmcp::ErrorData::internal_error(format!("JSON error: {e}"), None))?;
        Ok(CallToolResult::success(vec![json]))
    }

    #[tool(description = "List all IMAP mailbox folders for the selected account.")]
    async fn list_folders(
        &self,
        Parameters(params): Parameters<AccountSelector>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let (_account, mut conn) = self.connect_with(params.account.as_deref()).await?;
        let folders = conn
            .list_folders()
            .await
            .map_err(|e| rmcp::ErrorData::internal_error(format!("{e}"), None))?;
        conn.logout_or_warn().await;
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
        let (_account, mut conn) = self.connect_with(params.account.as_deref()).await?;
        let emails = conn
            .list_emails(&params.folder, params.limit, params.offset)
            .await
            .map_err(|e| rmcp::ErrorData::internal_error(format!("{e}"), None))?;
        conn.logout_or_warn().await;
        let json = Content::json(&emails)
            .map_err(|e| rmcp::ErrorData::internal_error(format!("JSON error: {e}"), None))?;
        Ok(CallToolResult::success(vec![json]))
    }

    #[tool(
        description = "Fetch a full email by UID. Returns headers (including message_id, cc, and references for threading), plain-text body, and a list of attachments with metadata (filename, mime_type, size, index). Use get_attachment with the index to fetch attachment content. To reply to an email, use the message_id and references fields with create_draft."
    )]
    async fn get_email(
        &self,
        Parameters(params): Parameters<GetEmailParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let (_account, mut conn) = self.connect_with(params.account.as_deref()).await?;
        let email = conn
            .get_email(&params.folder, params.uid)
            .await
            .map_err(|e| rmcp::ErrorData::internal_error(format!("{e}"), None))?;
        conn.logout_or_warn().await;
        let json = Content::json(&email)
            .map_err(|e| rmcp::ErrorData::internal_error(format!("JSON error: {e}"), None))?;
        Ok(CallToolResult::success(vec![json]))
    }

    #[tool(
        description = "Fetch an email attachment by UID and attachment_index (a path-array, e.g. [0] for the first top-level attachment or [0, 1] for the second attachment inside the first forwarded .eml). The response shape is hinted in get_email's `extraction` field: PDFs and Office documents return extracted text (truncated at 200 KB); message/rfc822 attachments are parsed natively into headers, body, and nested attachments; text files are returned verbatim; images under ~150 KB are returned visually; anything else under 5 MB is returned as base64-encoded raw_bytes; over 5 MB use `download_attachment` instead."
    )]
    async fn get_attachment(
        &self,
        Parameters(params): Parameters<GetAttachmentParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let (_account, mut conn) = self.connect_with(params.account.as_deref()).await?;
        let attachment = conn
            .get_attachment(&params.folder, params.uid, &params.attachment_index)
            .await
            .map_err(|e| rmcp::ErrorData::internal_error(format!("{e}"), None))?;
        conn.logout_or_warn().await;

        render_attachment(attachment, &params.attachment_index).await
    }

    #[tool(
        description = "Stage an attachment for download via a one-shot signed URL and return the URL. Use this for attachments larger than 5 MB (which `get_attachment` refuses to inline) and for any binary the user wants to save to disk. The link is valid for 15 minutes, redeems exactly once, and writes the file to the user's browser with the original filename. The MCP client should surface the URL to the user as a clickable link — Claude itself cannot fetch it. Use the same `attachment_index` path you'd pass to `get_attachment`."
    )]
    async fn download_attachment(
        &self,
        Parameters(params): Parameters<DownloadAttachmentParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let (_account, mut conn) = self.connect_with(params.account.as_deref()).await?;
        let attachment = conn
            .get_attachment(&params.folder, params.uid, &params.attachment_index)
            .await
            .map_err(|e| rmcp::ErrorData::internal_error(format!("{e}"), None))?;
        conn.logout_or_warn().await;

        let filename = attachment
            .info
            .filename
            .clone()
            .unwrap_or_else(|| format!("attachment_{}", format_path(&params.attachment_index)));
        let ticket = DownloadTicket {
            filename: filename.clone(),
            mime_type: attachment.info.mime_type.clone(),
            size: attachment.info.size,
            oidc_sub: self.resolver.oidc_sub.clone(),
        };
        let token = self
            .resolver
            .store
            .stage_download(&ticket, &attachment.data)
            .await
            .map_err(|e| rmcp::ErrorData::internal_error(format!("{e}"), None))?;

        let url = format!("{}/download/{}", self.resolver.base_url, token);
        let payload = DownloadAttachmentResponse {
            url,
            filename,
            mime_type: attachment.info.mime_type,
            size: attachment.info.size,
            expires_in_seconds: DOWNLOAD_TICKET_TTL,
        };
        let json = Content::json(&payload)
            .map_err(|e| rmcp::ErrorData::internal_error(format!("JSON error: {e}"), None))?;
        Ok(CallToolResult::success(vec![json]))
    }

    #[tool(
        description = "Search emails using IMAP SEARCH criteria. Examples: UNSEEN, FROM \"user@example.com\", SUBJECT \"hello\", SINCE 01-Jan-2024"
    )]
    async fn search_emails(
        &self,
        Parameters(params): Parameters<SearchEmailsParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let (_account, mut conn) = self.connect_with(params.account.as_deref()).await?;
        let emails = conn
            .search_emails(&params.folder, &params.query, params.limit)
            .await
            .map_err(|e| rmcp::ErrorData::internal_error(format!("{e}"), None))?;
        conn.logout_or_warn().await;
        let json = Content::json(&emails)
            .map_err(|e| rmcp::ErrorData::internal_error(format!("JSON error: {e}"), None))?;
        Ok(CallToolResult::success(vec![json]))
    }

    #[tool(description = "Mark an email as read (set \\Seen flag) by UID")]
    async fn mark_read(
        &self,
        Parameters(params): Parameters<MarkParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let (_account, mut conn) = self.connect_with(params.account.as_deref()).await?;
        conn.mark_read(&params.folder, params.uid)
            .await
            .map_err(|e| rmcp::ErrorData::internal_error(format!("{e}"), None))?;
        conn.logout_or_warn().await;
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
        let (_account, mut conn) = self.connect_with(params.account.as_deref()).await?;
        conn.mark_unread(&params.folder, params.uid)
            .await
            .map_err(|e| rmcp::ErrorData::internal_error(format!("{e}"), None))?;
        conn.logout_or_warn().await;
        Ok(CallToolResult::success(vec![Content::text(format!(
            "Email UID {} marked as unread",
            params.uid
        ))]))
    }

    #[tool(
        description = "Create a new draft email. The body MUST contain newline characters (\\n) to separate paragraphs and lines — never send the entire body as a single line. Optionally provide html_body for formatted emails (the plain text body is always required as fallback). The draft is saved to the specified folder (default: Drafts) and can be edited later with update_draft or sent from your email client. To create a reply, first use get_email to fetch the original email, then pass its message_id as in_reply_to, and set references to the original references value (if any) plus the original message_id appended. If the original email has no references (thread root), use only its message_id as the references value."
    )]
    async fn create_draft(
        &self,
        Parameters(params): Parameters<CreateDraftParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let (account, mut conn) = self.connect_with(params.account.as_deref()).await?;
        let body = normalize_body(&params.body);
        reject_flat_body(&body)?;
        let draft = DraftContent {
            from: &account.imap_email,
            to: &params.to,
            subject: &params.subject,
            body: &body,
            html_body: params.html_body.as_deref(),
            cc: params.cc.as_deref(),
            bcc: params.bcc.as_deref(),
            in_reply_to: params.in_reply_to.as_deref(),
            references: params.references.as_deref(),
        };
        let uid = conn
            .create_draft(&params.folder, &draft)
            .await
            .map_err(|e| rmcp::ErrorData::internal_error(format!("{e}"), None))?;
        conn.logout_or_warn().await;

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
        description = "Update an existing draft email by UID. Replaces the old draft with the new content in the same folder. The body MUST contain newline characters (\\n) to separate paragraphs and lines. Optionally provide html_body for formatted emails."
    )]
    async fn update_draft(
        &self,
        Parameters(params): Parameters<UpdateDraftParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let (account, mut conn) = self.connect_with(params.account.as_deref()).await?;
        let body = normalize_body(&params.body);
        reject_flat_body(&body)?;
        let draft = DraftContent {
            from: &account.imap_email,
            to: &params.to,
            subject: &params.subject,
            body: &body,
            html_body: params.html_body.as_deref(),
            cc: params.cc.as_deref(),
            bcc: params.bcc.as_deref(),
            in_reply_to: params.in_reply_to.as_deref(),
            references: params.references.as_deref(),
        };
        let new_uid = conn
            .update_draft(&params.folder, params.uid, &draft)
            .await
            .map_err(|e| rmcp::ErrorData::internal_error(format!("{e}"), None))?;
        conn.logout_or_warn().await;

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

/// Normalize literal escape sequences in the email body.
///
/// LLMs sometimes emit literal `\n` (two-character backslash + n) in JSON
/// string values instead of actual newline characters. This converts those
/// literal sequences to real newlines so drafts preserve intended line breaks.
///
/// Only applies when the body contains no real newlines at all — that pattern
/// strongly indicates the LLM collapsed everything onto one line. When real
/// newlines are already present, the body is well-formed and replacing `\n`
/// would corrupt intentional backslash-n sequences (e.g. in code snippets).
fn normalize_body(body: &str) -> String {
    if !body.contains('\n') {
        body.replace("\\n", "\n")
    } else {
        body.to_string()
    }
}

/// Maximum length (in Unicode scalar values) for a single-line body before we reject it.
/// Bodies shorter than this are likely intentionally single-line (e.g. "Thanks!").
const FLAT_BODY_THRESHOLD: usize = 100;

/// Reject email bodies that appear to be a single long line with no formatting.
fn reject_flat_body(body: &str) -> Result<(), rmcp::ErrorData> {
    if !body.contains('\n') && body.chars().count() > FLAT_BODY_THRESHOLD {
        return Err(rmcp::ErrorData::invalid_params(
            "The email body is a single long line with no newline characters. \
             Please reformat the body with \\n characters to separate the greeting, \
             paragraphs, and sign-off onto separate lines.",
            None,
        ));
    }
    Ok(())
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

/// Format an attachment path for human-readable error messages and fallback
/// filenames: `[0, 1]` → `"0.1"`.
fn format_path(path: &[usize]) -> String {
    path.iter()
        .map(|n| n.to_string())
        .collect::<Vec<_>>()
        .join(".")
}

/// Payload returned when an attachment is delivered as base64 raw bytes.
#[derive(Debug, serde::Serialize)]
struct RawBytesResponse {
    filename: String,
    mime_type: String,
    size: usize,
    extraction: &'static str,
    raw_base64: String,
}

/// Payload returned by `download_attachment` after staging the bytes in Redis.
/// The client should render `url` as a clickable link for the user.
#[derive(Debug, serde::Serialize)]
struct DownloadAttachmentResponse {
    url: String,
    filename: String,
    mime_type: String,
    size: usize,
    expires_in_seconds: u64,
}

/// Render a fetched attachment into the appropriate MCP `Content` based on the
/// classified `ExtractionHint`. Centralised so `get_attachment` stays a thin
/// dispatcher.
async fn render_attachment(
    attachment: AttachmentData,
    requested_path: &[usize],
) -> Result<CallToolResult, rmcp::ErrorData> {
    let mime = attachment.info.mime_type.clone();
    let size = attachment.info.size;
    let filename = attachment
        .info
        .filename
        .clone()
        .unwrap_or_else(|| format!("attachment_{}", format_path(requested_path)));

    match attachment.info.extraction {
        ExtractionHint::Text => render_text_attachment(&attachment.data, &mime, &filename, size).await,
        ExtractionHint::EmbeddedMessage => {
            let embedded = imap::parse_embedded_message(&attachment.data, requested_path)
                .map_err(|e| rmcp::ErrorData::internal_error(format!("{e}"), None))?;
            let json = Content::json(&embedded)
                .map_err(|e| rmcp::ErrorData::internal_error(format!("JSON error: {e}"), None))?;
            Ok(CallToolResult::success(vec![json]))
        }
        ExtractionHint::Image => {
            let b64 = imap::base64_encode(&attachment.data);
            Ok(CallToolResult::success(vec![
                Content::text(format!(
                    "Image attachment: {filename} ({mime}, {size} bytes)"
                )),
                Content::image(b64, mime.clone()),
            ]))
        }
        ExtractionHint::RawBytes => {
            let payload = RawBytesResponse {
                filename,
                mime_type: mime,
                size,
                extraction: "raw_bytes",
                raw_base64: imap::base64_encode(&attachment.data),
            };
            let json = Content::json(&payload)
                .map_err(|e| rmcp::ErrorData::internal_error(format!("JSON error: {e}"), None))?;
            Ok(CallToolResult::success(vec![json]))
        }
        ExtractionHint::TooLarge => Ok(CallToolResult::success(vec![Content::text(format!(
            "Attachment {filename} ({mime}, {size} bytes / {human}) exceeds the {cap} inline cap. \
             Call download_attachment with the same uid and attachment_index to get a one-shot signed URL.",
            human = format_size(size),
            cap = format_size(MAX_RAW_BYTES_SIZE),
        ))])),
    }
}

/// Inner dispatch for `ExtractionHint::Text`: tries the in-process and
/// subprocess extractors for binary document formats, falling back to a
/// verbatim UTF-8 decode for plain-text MIME types.
async fn render_text_attachment(
    data: &[u8],
    mime: &str,
    filename: &str,
    size: usize,
) -> Result<CallToolResult, rmcp::ErrorData> {
    if extract::is_extractable_mime(mime) {
        let extraction = match extract::extract_text(data, mime) {
            Ok(None) => extract::extract_text_subprocess(data, mime).await,
            other => other,
        };
        return match extraction {
            Ok(Some(raw_text)) => {
                let format_label = extract::mime_to_format_label(mime);
                let extracted = extract::build_extracted(raw_text, format_label);
                let mut header = format!(
                    "Text content extracted from: {filename} ({format_label}, {size} bytes)"
                );
                if extracted.truncated {
                    header.push_str(&format!(
                        "\nNOTE: Extracted text truncated to {} KB (full text: {} KB). Showing first portion only.",
                        extracted.included_bytes / 1024,
                        extracted.total_bytes / 1024,
                    ));
                }
                Ok(CallToolResult::success(vec![Content::text(format!(
                    "{header}\n\n{}",
                    extracted.text
                ))]))
            }
            Err(err_msg) => Ok(CallToolResult::success(vec![Content::text(format!(
                "Attachment: {filename} ({mime}, {size} bytes)\nText extraction failed: {err_msg}. Content cannot be displayed."
            ))])),
            Ok(None) => Ok(CallToolResult::success(vec![Content::text(format!(
                "Attachment: {filename} ({mime}, {size} bytes)\nText extraction is not supported for this format."
            ))])),
        };
    }

    // Plain-text MIMEs (text/*, JSON, XML, etc.): return verbatim with the
    // standard 200 KB cap.
    let text = String::from_utf8_lossy(data);
    let (content, truncated) = extract::truncate_to_limit(&text, MAX_LLM_CONTENT_SIZE);
    let mut header = format!("Text attachment: {filename} ({mime}, {size} bytes)");
    if truncated {
        header.push_str(&format!(
            "\nNOTE: Content truncated to {} KB (full size: {} KB). Showing first portion only.",
            content.len() / 1024,
            text.len() / 1024,
        ));
    }
    Ok(CallToolResult::success(vec![Content::text(format!(
        "{header}\n\n{content}"
    ))]))
}

#[tool_handler]
impl ServerHandler for ImapMcpServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(
            ServerCapabilities::builder().enable_tools().build(),
        )
        .with_instructions(
            "IMAP email server with multi-account support. One MCP install can hold multiple mailboxes per user (personal, shared team boxes, etc.). Use list_accounts to see what's connected and to get a manage_url the user can open to add or remove mailboxes; use add_account_url for an 'add a new mailbox' link without first listing. If only one account is connected, IMAP tools default to it; if more than one, pass `account` (account_id from list_accounts, or label) on every IMAP call. Tools: list_folders, list_emails, get_email, search_emails, mark_read, mark_unread, get_attachment, download_attachment, create_draft, update_draft. When get_email returns attachment metadata, each attachment has an `extraction` field telling you what get_attachment will return: `text` (PDFs, Office docs, plain text — server extracts text, truncated to 200 KB); `embedded_message` (the attachment is itself an email — server parses it natively and returns headers, body, and its own attachments); `image` (returned visually if small enough); `raw_bytes` (returned as base64 for binary formats under 5 MB); `too_large` (call download_attachment instead). The `index` field is a path array: top-level attachments are like [0], an attachment inside a forwarded .eml is [0, 1], and so on up to 5 levels deep. Use the same array as `attachment_index` for get_attachment and download_attachment. download_attachment returns a one-shot signed URL valid for 15 minutes — surface it to the user as a clickable link; Claude cannot fetch it directly. To reply to an email, first fetch it with get_email, then use create_draft with in_reply_to set to the original message_id, and references set to the original references value (if any) plus the original message_id appended. If the original has no references (thread root), use only its message_id as references. IMPORTANT: When composing email bodies for create_draft or update_draft, always include newline characters (\\n) to separate paragraphs, after greetings, and before sign-offs. Never send the entire body as one long line.".to_string(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_body_converts_literal_backslash_n() {
        assert_eq!(
            normalize_body("Hello,\\n\\nParagraph one.\\n\\nBest,\\nAlice"),
            "Hello,\n\nParagraph one.\n\nBest,\nAlice"
        );
    }

    #[test]
    fn normalize_body_preserves_real_newlines() {
        assert_eq!(
            normalize_body("Hello,\n\nAlready has newlines."),
            "Hello,\n\nAlready has newlines."
        );
    }

    #[test]
    fn normalize_body_skips_when_real_newlines_present() {
        assert_eq!(
            normalize_body("Line1\nLine2\\nLine3"),
            "Line1\nLine2\\nLine3"
        );
    }

    #[test]
    fn reject_flat_body_allows_short_single_line() {
        assert!(reject_flat_body("Thanks for the update!").is_ok());
    }

    #[test]
    fn reject_flat_body_allows_body_with_newlines() {
        let body = "Hi Alice,\n\nThis is a properly formatted email body that has paragraphs separated by newlines. It is longer than the threshold.\n\nBest,\nBob";
        assert!(reject_flat_body(body).is_ok());
    }

    #[test]
    fn reject_flat_body_rejects_long_single_line() {
        let body = "Hi Alice, I wanted to follow up on our conversation from yesterday about the project timeline and make sure we are aligned on the next steps for the deliverables.";
        assert!(body.len() > FLAT_BODY_THRESHOLD);
        let err = reject_flat_body(body).unwrap_err();
        assert!(err.message.contains("single long line"));
    }
}
