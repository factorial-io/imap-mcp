use async_native_tls::TlsConnector;
use base64::Engine;
use futures::TryStreamExt;
use serde::Serialize;

use crate::error::AppError;

/// Fields for composing a draft email.
pub struct DraftContent<'a> {
    pub from: &'a str,
    pub to: &'a str,
    pub subject: &'a str,
    pub body: &'a str,
    pub cc: Option<&'a str>,
    pub bcc: Option<&'a str>,
    /// Message-ID of the email being replied to (sets In-Reply-To header).
    pub in_reply_to: Option<&'a str>,
    /// Space-separated Message-IDs for the References header (threading chain).
    pub references: Option<&'a str>,
}

/// Maximum attachment size we'll return (25 MB).
const MAX_ATTACHMENT_SIZE: usize = 25 * 1024 * 1024;

/// Maximum text content size returned to the LLM (200 KB).
pub const MAX_LLM_CONTENT_SIZE: usize = 200 * 1024;

/// Summary of an email for list views.
#[derive(Debug, Serialize)]
pub struct EmailSummary {
    pub uid: u32,
    pub date: Option<String>,
    pub from: Option<String>,
    pub subject: Option<String>,
    pub seen: bool,
}

/// Metadata about an email attachment.
#[derive(Debug, Clone, Serialize)]
pub struct AttachmentInfo {
    /// Zero-based index of this attachment within the email.
    pub index: usize,
    /// Filename if available.
    pub filename: Option<String>,
    /// MIME type (e.g. "image/png", "application/pdf").
    pub mime_type: String,
    /// Size in bytes of the decoded content.
    pub size: usize,
}

/// A fetched attachment with its data.
#[derive(Debug)]
pub struct AttachmentData {
    pub info: AttachmentInfo,
    /// Raw decoded bytes of the attachment.
    pub data: Vec<u8>,
}

/// Full email content.
#[derive(Debug, Serialize)]
pub struct EmailDetail {
    pub uid: u32,
    pub date: Option<String>,
    pub from: Option<String>,
    pub to: Option<String>,
    pub cc: Option<String>,
    pub subject: Option<String>,
    /// Message-ID of this email (use for In-Reply-To when replying).
    pub message_id: Option<String>,
    /// References header value (threading chain of Message-IDs).
    pub references: Option<String>,
    pub body: String,
    /// Metadata for each attachment (use get_attachment to fetch content).
    pub attachments: Vec<AttachmentInfo>,
}

/// IMAP folder info.
#[derive(Debug, Serialize)]
pub struct FolderInfo {
    pub name: String,
    pub attributes: Vec<String>,
    pub delimiter: Option<String>,
}

/// Short-lived IMAP connection wrapper. Opened per-request, not pooled.
pub struct ImapConnection {
    session: async_imap::Session<async_native_tls::TlsStream<tokio::net::TcpStream>>,
}

impl ImapConnection {
    /// Connect and authenticate via IMAP over TLS (port 993).
    pub async fn connect(
        host: &str,
        port: u16,
        email: &str,
        password: &str,
    ) -> Result<Self, AppError> {
        let tcp = tokio::net::TcpStream::connect((host, port))
            .await
            .map_err(|e| AppError::Imap(format!("TCP connect failed: {e}")))?;
        let tls = TlsConnector::new();
        let tls_stream = tls
            .connect(host, tcp)
            .await
            .map_err(|e| AppError::Imap(format!("TLS handshake failed: {e}")))?;
        let client = async_imap::Client::new(tls_stream);
        let session = client
            .login(email, password)
            .await
            .map_err(|e| AppError::Imap(format!("IMAP login failed: {}", e.0)))?;
        Ok(Self { session })
    }

    /// Validate that an IMAP string does not contain injection characters.
    fn validate_imap_input(input: &str, field: &str) -> Result<(), AppError> {
        if input.contains('\r') || input.contains('\n') || input.contains('\0') {
            return Err(AppError::Imap(format!("invalid characters in {field}")));
        }
        Ok(())
    }

    /// List all mailbox folders.
    pub async fn list_folders(&mut self) -> Result<Vec<FolderInfo>, AppError> {
        let names: Vec<async_imap::types::Name> = self
            .session
            .list(Some(""), Some("*"))
            .await
            .map_err(|e| AppError::Imap(format!("LIST failed: {e}")))?
            .try_collect()
            .await
            .map_err(|e| AppError::Imap(format!("LIST stream failed: {e}")))?;

        let mut result = Vec::new();
        for folder in &names {
            result.push(FolderInfo {
                name: folder.name().to_string(),
                attributes: folder
                    .attributes()
                    .iter()
                    .map(|a| format!("{a:?}"))
                    .collect(),
                delimiter: folder.delimiter().map(|c| c.to_string()),
            });
        }
        Ok(result)
    }

    /// List emails in a folder with pagination.
    pub async fn list_emails(
        &mut self,
        folder: &str,
        limit: u32,
        offset: u32,
    ) -> Result<Vec<EmailSummary>, AppError> {
        Self::validate_imap_input(folder, "folder name")?;
        let mailbox = self
            .session
            .select(folder)
            .await
            .map_err(|e| AppError::Imap(format!("SELECT {folder} failed: {e}")))?;

        let total = mailbox.exists;
        if total == 0 {
            return Ok(Vec::new());
        }

        // Calculate sequence range (IMAP sequences are 1-based, newest last)
        let end = total.saturating_sub(offset);
        if end == 0 {
            return Ok(Vec::new());
        }
        let start = end.saturating_sub(limit).max(1);
        let range = format!("{start}:{end}");

        let fetches: Vec<async_imap::types::Fetch> = self
            .session
            .fetch(&range, "(UID FLAGS ENVELOPE)")
            .await
            .map_err(|e| AppError::Imap(format!("FETCH failed: {e}")))?
            .try_collect()
            .await
            .map_err(|e| AppError::Imap(format!("FETCH stream failed: {e}")))?;

        let mut summaries: Vec<EmailSummary> = fetches.iter().map(parse_summary).collect();
        // Return newest first
        summaries.reverse();
        Ok(summaries)
    }

    /// Fetch full email by UID.
    pub async fn get_email(&mut self, folder: &str, uid: u32) -> Result<EmailDetail, AppError> {
        Self::validate_imap_input(folder, "folder name")?;
        self.session
            .select(folder)
            .await
            .map_err(|e| AppError::Imap(format!("SELECT {folder} failed: {e}")))?;

        let fetches: Vec<async_imap::types::Fetch> = self
            .session
            .uid_fetch(uid.to_string(), "(UID FLAGS ENVELOPE BODY[])")
            .await
            .map_err(|e| AppError::Imap(format!("UID FETCH failed: {e}")))?
            .try_collect()
            .await
            .map_err(|e| AppError::Imap(format!("UID FETCH stream failed: {e}")))?;

        let fetch = fetches
            .first()
            .ok_or_else(|| AppError::Imap(format!("email UID {uid} not found")))?;

        let body_raw = fetch.body().unwrap_or(b"");
        // Parse the raw message once and reuse for body, attachments, and headers.
        let (body, attachments, references) = match mailparse::parse_mail(body_raw) {
            Ok(parsed) => {
                let body = extract_body_from_parsed(&parsed);
                let mut att_infos = Vec::new();
                collect_attachment_infos(&parsed, &mut att_infos);
                let refs = extract_header_from_parsed(&parsed.headers, "References");
                (body, att_infos, refs)
            }
            Err(_) => (
                String::from_utf8_lossy(body_raw).to_string(),
                Vec::new(),
                None,
            ),
        };

        let envelope = fetch.envelope();
        Ok(EmailDetail {
            uid: fetch.uid.unwrap_or(uid),
            date: envelope.and_then(|e| {
                e.date
                    .as_ref()
                    .map(|d| String::from_utf8_lossy(d).to_string())
            }),
            from: envelope.and_then(|e| format_addresses(e.from.as_deref())),
            to: envelope.and_then(|e| format_addresses(e.to.as_deref())),
            cc: envelope.and_then(|e| format_addresses(e.cc.as_deref())),
            subject: envelope.and_then(|e| e.subject.as_ref().map(|s| decode_header_value(s))),
            message_id: envelope.and_then(|e| {
                e.message_id
                    .as_ref()
                    .map(|m| String::from_utf8_lossy(m).to_string())
            }),
            references,
            body,
            attachments,
        })
    }

    /// Fetch a specific attachment from an email by UID and attachment index.
    pub async fn get_attachment(
        &mut self,
        folder: &str,
        uid: u32,
        attachment_index: usize,
    ) -> Result<AttachmentData, AppError> {
        Self::validate_imap_input(folder, "folder name")?;
        self.session
            .select(folder)
            .await
            .map_err(|e| AppError::Imap(format!("SELECT {folder} failed: {e}")))?;

        let fetches: Vec<async_imap::types::Fetch> = self
            .session
            .uid_fetch(uid.to_string(), "(UID BODY[])")
            .await
            .map_err(|e| AppError::Imap(format!("UID FETCH failed: {e}")))?
            .try_collect()
            .await
            .map_err(|e| AppError::Imap(format!("UID FETCH stream failed: {e}")))?;

        let fetch = fetches
            .first()
            .ok_or_else(|| AppError::Imap(format!("email UID {uid} not found")))?;

        let body_raw = fetch.body().unwrap_or(b"");
        extract_attachment_data(body_raw, attachment_index)
    }

    /// Search emails using IMAP SEARCH criteria.
    pub async fn search_emails(
        &mut self,
        folder: &str,
        query: &str,
        limit: u32,
    ) -> Result<Vec<EmailSummary>, AppError> {
        Self::validate_imap_input(folder, "folder name")?;
        Self::validate_imap_input(query, "search query")?;

        self.session
            .select(folder)
            .await
            .map_err(|e| AppError::Imap(format!("SELECT {folder} failed: {e}")))?;

        let uids = self
            .session
            .uid_search(query)
            .await
            .map_err(|e| AppError::Imap(format!("SEARCH failed: {e}")))?;

        if uids.is_empty() {
            return Ok(Vec::new());
        }

        // Take the last `limit` UIDs (newest)
        let mut uid_vec: Vec<u32> = uids.into_iter().collect();
        uid_vec.sort();
        let start = uid_vec.len().saturating_sub(limit as usize);
        let selected: Vec<String> = uid_vec[start..].iter().map(|u| u.to_string()).collect();
        let uid_set = selected.join(",");

        let fetches: Vec<async_imap::types::Fetch> = self
            .session
            .uid_fetch(&uid_set, "(UID FLAGS ENVELOPE)")
            .await
            .map_err(|e| AppError::Imap(format!("UID FETCH failed: {e}")))?
            .try_collect()
            .await
            .map_err(|e| AppError::Imap(format!("UID FETCH stream failed: {e}")))?;

        let mut summaries: Vec<EmailSummary> = fetches.iter().map(parse_summary).collect();
        summaries.reverse();
        Ok(summaries)
    }

    /// Set \Seen flag on email by UID.
    pub async fn mark_read(&mut self, folder: &str, uid: u32) -> Result<(), AppError> {
        Self::validate_imap_input(folder, "folder name")?;
        self.session
            .select(folder)
            .await
            .map_err(|e| AppError::Imap(format!("SELECT {folder} failed: {e}")))?;
        // Consume the stream to complete the command
        let _: Vec<async_imap::types::Fetch> = self
            .session
            .uid_store(uid.to_string(), "+FLAGS (\\Seen)")
            .await
            .map_err(|e| AppError::Imap(format!("STORE +FLAGS failed: {e}")))?
            .try_collect()
            .await
            .map_err(|e| AppError::Imap(format!("STORE stream failed: {e}")))?;
        Ok(())
    }

    /// Unset \Seen flag on email by UID.
    pub async fn mark_unread(&mut self, folder: &str, uid: u32) -> Result<(), AppError> {
        Self::validate_imap_input(folder, "folder name")?;
        self.session
            .select(folder)
            .await
            .map_err(|e| AppError::Imap(format!("SELECT {folder} failed: {e}")))?;
        let _: Vec<async_imap::types::Fetch> = self
            .session
            .uid_store(uid.to_string(), "-FLAGS (\\Seen)")
            .await
            .map_err(|e| AppError::Imap(format!("STORE -FLAGS failed: {e}")))?
            .try_collect()
            .await
            .map_err(|e| AppError::Imap(format!("STORE stream failed: {e}")))?;
        Ok(())
    }

    /// Build an RFC 5322 message from draft content using `mail-builder`.
    /// Handles RFC 2047 encoding, CRLF normalization, and MIME structure automatically.
    fn build_rfc2822_message(draft: &DraftContent<'_>) -> Result<String, AppError> {
        let message_id = format!(
            "<{}.{}@imap-mcp>",
            uuid::Uuid::new_v4(),
            chrono::Utc::now().timestamp()
        );
        let mut builder = mail_builder::MessageBuilder::new();
        builder = builder
            .message_id(message_id)
            .from(Self::parse_address(draft.from))
            .to(Self::parse_address(draft.to))
            .subject(draft.subject)
            .text_body(draft.body);
        if let Some(cc) = draft.cc {
            builder = builder.cc(Self::parse_address(cc));
        }
        if let Some(bcc) = draft.bcc {
            builder = builder.bcc(Self::parse_address(bcc));
        }
        if let Some(in_reply_to) = draft.in_reply_to {
            builder = builder.in_reply_to(in_reply_to.to_string());
        }
        if let Some(references) = draft.references {
            let refs: Vec<String> = references
                .split_whitespace()
                .map(|s| s.to_string())
                .collect();
            builder = builder.references(refs);
        }
        builder
            .write_to_string()
            .map_err(|e| AppError::Imap(format!("failed to build RFC 5322 message: {e}")))
    }

    /// Parse an address string into a `mail_builder::headers::address::Address`.
    /// Supports "Display Name <email>" and bare "email" formats, including
    /// comma-separated lists. Uses angle-bracket and quote-aware splitting
    /// to handle display names containing commas (e.g. `"Smith, John" <j@x.com>`).
    fn parse_address(value: &str) -> mail_builder::headers::address::Address<'static> {
        let parts = split_address_list(value);
        if parts.len() == 1 {
            Self::parse_single_address_owned(&parts[0])
        } else {
            let addrs: Vec<mail_builder::headers::address::Address<'static>> = parts
                .iter()
                .map(|p| Self::parse_single_address_owned(p))
                .collect();
            mail_builder::headers::address::Address::new_list(addrs)
        }
    }

    fn parse_single_address_owned(addr: &str) -> mail_builder::headers::address::Address<'static> {
        if let Some(angle_start) = addr.rfind('<') {
            let raw_name = addr[..angle_start].trim();
            // Strip surrounding RFC 5322 quote delimiters if present,
            // and unescape internal sequences, so mail-builder doesn't double-quote.
            let display_name =
                if raw_name.starts_with('"') && raw_name.ends_with('"') && raw_name.len() >= 2 {
                    raw_name[1..raw_name.len() - 1]
                        .replace("\\\"", "\"")
                        .replace("\\\\", "\\")
                } else {
                    raw_name.to_string()
                };
            let email = addr[angle_start..]
                .trim_start_matches('<')
                .trim_end_matches('>')
                .to_string();
            if display_name.is_empty() {
                mail_builder::headers::address::Address::new_address(None::<String>, email)
            } else {
                mail_builder::headers::address::Address::new_address(Some(display_name), email)
            }
        } else {
            mail_builder::headers::address::Address::new_address(None::<String>, addr.to_string())
        }
    }

    /// Validate draft content fields for IMAP injection.
    fn validate_draft_content(draft: &DraftContent<'_>) -> Result<(), AppError> {
        Self::validate_imap_input(draft.from, "from address")?;
        Self::validate_imap_input(draft.to, "to address")?;
        Self::validate_imap_input(draft.subject, "subject")?;
        if let Some(cc) = draft.cc {
            Self::validate_imap_input(cc, "cc address")?;
        }
        if let Some(bcc) = draft.bcc {
            Self::validate_imap_input(bcc, "bcc address")?;
        }
        if let Some(in_reply_to) = draft.in_reply_to {
            Self::validate_imap_input(in_reply_to, "in_reply_to")?;
        }
        if let Some(references) = draft.references {
            Self::validate_imap_input(references, "references")?;
        }
        Ok(())
    }

    /// Create a new draft email by APPENDing to the given folder with \Draft flag.
    /// Returns the UID of the newly created draft (best-effort; may be approximate
    /// without UIDPLUS/APPENDUID support from the server).
    pub async fn create_draft(
        &mut self,
        folder: &str,
        draft: &DraftContent<'_>,
    ) -> Result<Option<u32>, AppError> {
        Self::validate_imap_input(folder, "folder name")?;
        Self::validate_draft_content(draft)?;

        let message = Self::build_rfc2822_message(draft)?;

        // Get UIDNEXT before APPEND to identify the new message
        let mailbox = self
            .session
            .select(folder)
            .await
            .map_err(|e| AppError::Imap(format!("SELECT {folder} failed: {e}")))?;
        let uid_next_before = mailbox.uid_next;

        self.session
            .append(folder, Some("(\\Draft \\Seen)"), None, message.as_bytes())
            .await
            .map_err(|e| AppError::Imap(format!("APPEND failed: {e}")))?;

        // Re-select to get updated state and find the new UID
        let mailbox = self
            .session
            .select(folder)
            .await
            .map_err(|e| AppError::Imap(format!("SELECT {folder} failed: {e}")))?;

        // If we know UIDNEXT, the new message should have that UID
        if let Some(uid_next) = uid_next_before {
            return Ok(Some(uid_next));
        }

        // Fallback: search for the most recent draft
        if mailbox.exists > 0 {
            let fetches: Vec<async_imap::types::Fetch> = self
                .session
                .fetch(mailbox.exists.to_string(), "(UID)")
                .await
                .map_err(|e| AppError::Imap(format!("FETCH failed: {e}")))?
                .try_collect()
                .await
                .map_err(|e| AppError::Imap(format!("FETCH stream failed: {e}")))?;
            if let Some(fetch) = fetches.first() {
                return Ok(fetch.uid);
            }
        }

        Ok(None)
    }

    /// Update an existing draft: append the new version first, then delete the old one.
    /// This ordering ensures no data loss if the APPEND fails.
    /// Returns the UID of the new draft (best-effort; may be approximate without UIDPLUS).
    pub async fn update_draft(
        &mut self,
        folder: &str,
        uid: u32,
        draft: &DraftContent<'_>,
    ) -> Result<Option<u32>, AppError> {
        Self::validate_imap_input(folder, "folder name")?;
        Self::validate_draft_content(draft)?;

        // Verify the old draft exists
        self.session
            .select(folder)
            .await
            .map_err(|e| AppError::Imap(format!("SELECT {folder} failed: {e}")))?;

        let fetches: Vec<async_imap::types::Fetch> = self
            .session
            .uid_fetch(uid.to_string(), "(UID FLAGS)")
            .await
            .map_err(|e| AppError::Imap(format!("UID FETCH failed: {e}")))?
            .try_collect()
            .await
            .map_err(|e| AppError::Imap(format!("UID FETCH stream failed: {e}")))?;

        if fetches.is_empty() {
            return Err(AppError::Imap(format!("draft UID {uid} not found")));
        }

        // Append the new draft FIRST to avoid data loss if APPEND fails
        let message = Self::build_rfc2822_message(draft)?;

        let mailbox = self
            .session
            .select(folder)
            .await
            .map_err(|e| AppError::Imap(format!("SELECT {folder} failed: {e}")))?;
        let uid_next_before = mailbox.uid_next;

        self.session
            .append(folder, Some("(\\Draft \\Seen)"), None, message.as_bytes())
            .await
            .map_err(|e| AppError::Imap(format!("APPEND failed: {e}")))?;

        // Now delete the old draft (safe — new draft already exists)
        self.session
            .select(folder)
            .await
            .map_err(|e| AppError::Imap(format!("SELECT {folder} failed: {e}")))?;

        let _: Vec<async_imap::types::Fetch> = self
            .session
            .uid_store(uid.to_string(), "+FLAGS (\\Deleted)")
            .await
            .map_err(|e| AppError::Imap(format!("STORE +FLAGS failed: {e}")))?
            .try_collect()
            .await
            .map_err(|e| AppError::Imap(format!("STORE stream failed: {e}")))?;

        // Prefer UID EXPUNGE (RFC 4315 / UIDPLUS) to only remove the target UID.
        // Plain expunge() removes ALL \Deleted messages, which could destroy
        // messages deleted by other clients. Fall back to expunge() only when
        // the server doesn't support UIDPLUS.
        let has_uidplus = self
            .session
            .capabilities()
            .await
            .map_err(|e| AppError::Imap(format!("CAPABILITY failed: {e}")))?
            .has_str("UIDPLUS");

        if has_uidplus {
            self.session
                .uid_expunge(uid.to_string())
                .await
                .map_err(|e| AppError::Imap(format!("UID EXPUNGE failed: {e}")))?
                .try_collect::<Vec<u32>>()
                .await
                .map_err(|e| AppError::Imap(format!("EXPUNGE stream failed: {e}")))?;
        } else {
            self.session
                .expunge()
                .await
                .map_err(|e| AppError::Imap(format!("EXPUNGE failed: {e}")))?
                .try_collect::<Vec<u32>>()
                .await
                .map_err(|e| AppError::Imap(format!("EXPUNGE stream failed: {e}")))?;
        }

        // Re-select to find the new UID
        let mailbox = self
            .session
            .select(folder)
            .await
            .map_err(|e| AppError::Imap(format!("SELECT {folder} failed: {e}")))?;

        // Best-effort UID: UIDNEXT captured before APPEND.
        // For exact UID, UIDPLUS (RFC 4315) APPENDUID would be needed.
        if let Some(uid_next) = uid_next_before {
            return Ok(Some(uid_next));
        }

        if mailbox.exists > 0 {
            let fetches: Vec<async_imap::types::Fetch> = self
                .session
                .fetch(mailbox.exists.to_string(), "(UID)")
                .await
                .map_err(|e| AppError::Imap(format!("FETCH failed: {e}")))?
                .try_collect()
                .await
                .map_err(|e| AppError::Imap(format!("FETCH stream failed: {e}")))?;
            if let Some(fetch) = fetches.first() {
                return Ok(fetch.uid);
            }
        }

        Ok(None)
    }

    /// Logout cleanly.
    pub async fn logout(mut self) -> Result<(), AppError> {
        self.session
            .logout()
            .await
            .map_err(|e| AppError::Imap(format!("logout failed: {e}")))?;
        Ok(())
    }
}

/// Split an address list on commas that are outside angle-bracket and quoted-string groups.
/// Handles display names containing commas, e.g. `"Smith, John" <john@example.com>`.
fn split_address_list(value: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let mut angle_depth: usize = 0;
    let mut in_quotes = false;
    let mut escaped = false;
    let mut current = String::new();
    for ch in value.chars() {
        match ch {
            '\\' => {
                escaped = !escaped;
                current.push(ch);
                continue;
            }
            '"' if !escaped => {
                in_quotes = !in_quotes;
                current.push(ch);
            }
            '<' if !in_quotes && !escaped => {
                angle_depth += 1;
                current.push(ch);
            }
            '>' if !in_quotes && !escaped => {
                angle_depth = angle_depth.saturating_sub(1);
                current.push(ch);
            }
            ',' if angle_depth == 0 && !in_quotes && !escaped => {
                parts.push(current.trim().to_string());
                current = String::new();
            }
            _ => {
                current.push(ch);
            }
        }
        escaped = false;
    }
    if !current.trim().is_empty() {
        parts.push(current.trim().to_string());
    }
    parts
}

fn parse_summary(fetch: &async_imap::types::Fetch) -> EmailSummary {
    let envelope = fetch.envelope();
    let seen = fetch
        .flags()
        .any(|f| matches!(f, async_imap::types::Flag::Seen));
    EmailSummary {
        uid: fetch.uid.unwrap_or(0),
        date: envelope.and_then(|e| {
            e.date
                .as_ref()
                .map(|d| String::from_utf8_lossy(d).to_string())
        }),
        from: envelope.and_then(|e| format_addresses(e.from.as_deref())),
        subject: envelope.and_then(|e| e.subject.as_ref().map(|s| decode_header_value(s))),
        seen,
    }
}

pub(crate) fn format_addresses(addrs: Option<&[imap_proto::types::Address]>) -> Option<String> {
    let addrs = addrs?;
    let formatted: Vec<String> = addrs
        .iter()
        .map(|a| {
            let name = a
                .name
                .as_ref()
                .map(|n| decode_header_value(n))
                .unwrap_or_default();
            let mailbox = a
                .mailbox
                .as_ref()
                .map(|m| String::from_utf8_lossy(m).to_string())
                .unwrap_or_default();
            let host = a
                .host
                .as_ref()
                .map(|h| String::from_utf8_lossy(h).to_string())
                .unwrap_or_default();
            if name.is_empty() {
                format!("{mailbox}@{host}")
            } else {
                format!("{name} <{mailbox}@{host}>")
            }
        })
        .collect();
    if formatted.is_empty() {
        None
    } else {
        Some(formatted.join(", "))
    }
}

pub(crate) fn decode_header_value(raw: &[u8]) -> String {
    let s = String::from_utf8_lossy(raw).to_string();
    // Attempt RFC2047 decoding via mailparse
    match mailparse::parse_header(format!("Subject: {s}").as_bytes()) {
        Ok((header, _)) => header.get_value(),
        Err(_) => s,
    }
}

/// Check whether a parsed MIME part is an attachment (not an inline body part).
fn is_attachment(part: &mailparse::ParsedMail) -> bool {
    let disposition = part.get_content_disposition();
    // Explicit attachment disposition
    if disposition.disposition == mailparse::DispositionType::Attachment {
        return true;
    }
    // A non-text, non-multipart leaf part with a filename is an attachment
    let ct = part.ctype.mimetype.to_lowercase();
    if ct.starts_with("multipart/") {
        return false;
    }
    if ct == "text/plain" || ct == "text/html" {
        // Only treat as attachment if explicitly marked with a filename in disposition
        return disposition.params.contains_key("filename");
    }
    // Any other content type that's a leaf (image, application, audio, video, etc.)
    // is an attachment, even without explicit disposition
    !ct.starts_with("multipart/")
}

/// Get the filename for an attachment from Content-Disposition or Content-Type params.
fn attachment_filename(part: &mailparse::ParsedMail) -> Option<String> {
    let disposition = part.get_content_disposition();
    if let Some(name) = disposition.params.get("filename") {
        return Some(name.clone());
    }
    // Fallback: "name" parameter on Content-Type
    part.ctype.params.get("name").cloned()
}

/// Recursively collect attachment metadata from a parsed email.
fn collect_attachment_infos(part: &mailparse::ParsedMail, out: &mut Vec<AttachmentInfo>) {
    if part.ctype.mimetype.to_lowercase().starts_with("multipart/") {
        for sub in &part.subparts {
            collect_attachment_infos(sub, out);
        }
        return;
    }
    if is_attachment(part) {
        let size = part.get_body_raw().map(|b| b.len()).unwrap_or(0);
        out.push(AttachmentInfo {
            index: out.len(),
            filename: attachment_filename(part),
            mime_type: part.ctype.mimetype.to_lowercase(),
            size,
        });
    }
}

/// Extract attachment metadata from raw email bytes.
#[cfg(test)]
fn extract_attachment_infos(raw: &[u8]) -> Vec<AttachmentInfo> {
    match mailparse::parse_mail(raw) {
        Ok(parsed) => {
            let mut infos = Vec::new();
            collect_attachment_infos(&parsed, &mut infos);
            infos
        }
        Err(_) => Vec::new(),
    }
}

/// Recursively collect actual attachment parts from a parsed email.
fn collect_attachment_parts<'a>(
    part: &'a mailparse::ParsedMail<'a>,
    out: &mut Vec<&'a mailparse::ParsedMail<'a>>,
) {
    if part.ctype.mimetype.to_lowercase().starts_with("multipart/") {
        for sub in &part.subparts {
            collect_attachment_parts(sub, out);
        }
        return;
    }
    if is_attachment(part) {
        out.push(part);
    }
}

/// Extract a specific attachment's data by index.
pub(crate) fn extract_attachment_data(
    raw: &[u8],
    index: usize,
) -> Result<AttachmentData, AppError> {
    let parsed =
        mailparse::parse_mail(raw).map_err(|e| AppError::Imap(format!("parse error: {e}")))?;

    let mut parts = Vec::new();
    collect_attachment_parts(&parsed, &mut parts);

    let part = parts
        .get(index)
        .ok_or_else(|| AppError::Imap(format!("attachment index {index} not found")))?;

    let data = part
        .get_body_raw()
        .map_err(|e| AppError::Imap(format!("failed to decode attachment: {e}")))?;

    if data.len() > MAX_ATTACHMENT_SIZE {
        return Err(AppError::Imap(format!(
            "attachment too large ({} bytes, max {})",
            data.len(),
            MAX_ATTACHMENT_SIZE
        )));
    }

    Ok(AttachmentData {
        info: AttachmentInfo {
            index,
            filename: attachment_filename(part),
            mime_type: part.ctype.mimetype.to_lowercase(),
            size: data.len(),
        },
        data,
    })
}

/// Encode raw bytes as a base64 string.
pub(crate) fn base64_encode(data: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(data)
}

/// Extract plain-text body from raw email bytes.
/// Prefers text/plain; falls back to converting text/html.
/// Extract a header value from parsed email headers.
fn extract_header_from_parsed(
    headers: &[mailparse::MailHeader<'_>],
    header_name: &str,
) -> Option<String> {
    for header in headers {
        if header.get_key().eq_ignore_ascii_case(header_name) {
            let val = header.get_value().trim().to_string();
            if val.is_empty() {
                return None;
            }
            return Some(val);
        }
    }
    None
}

/// Extract a header value from raw RFC 5322 message bytes.
#[cfg(test)]
fn extract_header_value(raw: &[u8], header_name: &str) -> Option<String> {
    let parsed = mailparse::parse_mail(raw).ok()?;
    extract_header_from_parsed(&parsed.headers, header_name)
}

#[cfg(test)]
fn extract_body(raw: &[u8]) -> String {
    match mailparse::parse_mail(raw) {
        Ok(parsed) => extract_body_from_parsed(&parsed),
        Err(_) => String::from_utf8_lossy(raw).to_string(),
    }
}

fn extract_body_from_parsed(parsed: &mailparse::ParsedMail) -> String {
    let ct = parsed.ctype.mimetype.to_lowercase();

    // Leaf node: return text content directly
    if !ct.starts_with("multipart/") {
        if ct == "text/plain" {
            if let Ok(body) = parsed.get_body() {
                return body;
            }
        }
        if ct == "text/html" {
            if let Ok(body) = parsed.get_body() {
                return html2text::from_read(body.as_bytes(), 80);
            }
        }
        // Skip non-text parts (signatures, attachments, etc.)
        return String::new();
    }

    // Multipart: recurse into subparts, prefer text/plain over text/html
    let mut plain = String::new();
    let mut html = String::new();

    for sub in &parsed.subparts {
        let sub_ct = sub.ctype.mimetype.to_lowercase();
        if sub_ct == "text/plain" && plain.is_empty() {
            if let Ok(body) = sub.get_body() {
                plain = body;
            }
        } else if sub_ct == "text/html" && html.is_empty() {
            if let Ok(body) = sub.get_body() {
                html = body;
            }
        } else if sub_ct.starts_with("multipart/") {
            // Recurse into nested multipart (e.g. multipart/signed → multipart/alternative)
            let nested = extract_body_from_parsed(sub);
            if !nested.is_empty() && plain.is_empty() {
                plain = nested;
            }
        }
    }

    if !plain.is_empty() {
        return plain;
    }
    if !html.is_empty() {
        return html2text::from_read(html.as_bytes(), 80);
    }

    // Last resort: top-level body (preamble text)
    if let Ok(body) = parsed.get_body() {
        if !body.trim().is_empty() && !body.contains("S/MIME") {
            return body;
        }
    }

    "(no text content)".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use mailparse::MailHeaderMap;
    use std::borrow::Cow;

    #[test]
    fn decode_header_value_plain_ascii() {
        let result = decode_header_value(b"Hello World");
        assert_eq!(result, "Hello World");
    }

    #[test]
    fn decode_header_value_utf8() {
        let result = decode_header_value("Héllo Wörld".as_bytes());
        assert_eq!(result, "Héllo Wörld");
    }

    #[test]
    fn format_addresses_none_returns_none() {
        assert_eq!(format_addresses(None), None);
    }

    #[test]
    fn format_addresses_empty_returns_none() {
        assert_eq!(format_addresses(Some(&[])), None);
    }

    #[test]
    fn format_addresses_single_no_name() {
        let addr = imap_proto::types::Address {
            name: None,
            adl: None,
            mailbox: Some(Cow::Borrowed(b"alice")),
            host: Some(Cow::Borrowed(b"example.com")),
        };
        let result = format_addresses(Some(&[addr]));
        assert_eq!(result, Some("alice@example.com".to_string()));
    }

    #[test]
    fn format_addresses_single_with_name() {
        let addr = imap_proto::types::Address {
            name: Some(Cow::Borrowed(b"Alice Smith")),
            adl: None,
            mailbox: Some(Cow::Borrowed(b"alice")),
            host: Some(Cow::Borrowed(b"example.com")),
        };
        let result = format_addresses(Some(&[addr]));
        assert_eq!(result, Some("Alice Smith <alice@example.com>".to_string()));
    }

    #[test]
    fn format_addresses_multiple() {
        let addrs = vec![
            imap_proto::types::Address {
                name: None,
                adl: None,
                mailbox: Some(Cow::Borrowed(b"alice")),
                host: Some(Cow::Borrowed(b"a.com")),
            },
            imap_proto::types::Address {
                name: Some(Cow::Borrowed(b"Bob")),
                adl: None,
                mailbox: Some(Cow::Borrowed(b"bob")),
                host: Some(Cow::Borrowed(b"b.com")),
            },
        ];
        let result = format_addresses(Some(&addrs));
        assert_eq!(result, Some("alice@a.com, Bob <bob@b.com>".to_string()));
    }

    #[test]
    fn extract_body_plain_text() {
        let raw = b"Content-Type: text/plain\r\n\r\nHello, world!";
        let body = extract_body(raw);
        assert_eq!(body, "Hello, world!");
    }

    #[test]
    fn extract_body_html_fallback() {
        let raw = b"Content-Type: text/html\r\n\r\n<p>Hello</p>";
        let body = extract_body(raw);
        assert!(body.contains("Hello"));
    }

    #[test]
    fn extract_body_multipart_prefers_plain() {
        let raw = b"Content-Type: multipart/alternative; boundary=bound\r\n\r\n\
--bound\r\n\
Content-Type: text/plain\r\n\r\n\
Plain text body\r\n\
--bound\r\n\
Content-Type: text/html\r\n\r\n\
<p>HTML body</p>\r\n\
--bound--";
        let body = extract_body(raw);
        assert!(body.contains("Plain text body"));
        assert!(!body.contains("<p>"));
    }

    #[test]
    fn extract_body_multipart_html_only() {
        let raw = b"Content-Type: multipart/alternative; boundary=bound\r\n\r\n\
--bound\r\n\
Content-Type: text/html\r\n\r\n\
<p>Only HTML</p>\r\n\
--bound--";
        let body = extract_body(raw);
        assert!(body.contains("Only HTML"));
    }

    #[test]
    fn extract_body_empty_does_not_panic() {
        // Empty input should not panic; returning empty string is acceptable
        let _body = extract_body(b"");
    }

    #[test]
    fn extract_body_smime_signed_plain() {
        // S/MIME signed: multipart/signed containing text/plain + signature
        let raw = b"Content-Type: multipart/signed; boundary=sig; protocol=\"application/pkcs7-signature\"\r\n\r\n\
This is an S/MIME signed message\r\n\r\n\
--sig\r\n\
Content-Type: text/plain\r\n\r\n\
Actual email body here\r\n\
--sig\r\n\
Content-Type: application/pkcs7-signature\r\n\r\n\
BINARYSIGNATUREDATA\r\n\
--sig--";
        let body = extract_body(raw);
        assert!(
            body.contains("Actual email body"),
            "Should extract body from signed message, got: {body}"
        );
        assert!(!body.contains("S/MIME"));
    }

    #[test]
    fn extract_body_smime_signed_with_nested_multipart() {
        // S/MIME signed: multipart/signed → multipart/alternative → text/plain + text/html
        let raw = b"Content-Type: multipart/signed; boundary=sig; protocol=\"application/pkcs7-signature\"\r\n\r\n\
This is an S/MIME signed message\r\n\r\n\
--sig\r\n\
Content-Type: multipart/alternative; boundary=alt\r\n\r\n\
--alt\r\n\
Content-Type: text/plain\r\n\r\n\
Plain text from signed email\r\n\
--alt\r\n\
Content-Type: text/html\r\n\r\n\
<p>HTML from signed email</p>\r\n\
--alt--\r\n\
--sig\r\n\
Content-Type: application/pkcs7-signature\r\n\r\n\
BINARYSIGNATUREDATA\r\n\
--sig--";
        let body = extract_body(raw);
        assert!(
            body.contains("Plain text from signed email"),
            "Should recurse into nested multipart, got: {body}"
        );
    }

    // --- Attachment tests ---

    #[test]
    fn no_attachments_in_plain_text_email() {
        let raw = b"Content-Type: text/plain\r\n\r\nHello, world!";
        let infos = extract_attachment_infos(raw);
        assert!(infos.is_empty());
    }

    #[test]
    fn no_attachments_in_multipart_alternative() {
        let raw = b"Content-Type: multipart/alternative; boundary=bound\r\n\r\n\
--bound\r\n\
Content-Type: text/plain\r\n\r\n\
Plain text body\r\n\
--bound\r\n\
Content-Type: text/html\r\n\r\n\
<p>HTML body</p>\r\n\
--bound--";
        let infos = extract_attachment_infos(raw);
        assert!(infos.is_empty());
    }

    #[test]
    fn detect_image_attachment() {
        let raw = b"Content-Type: multipart/mixed; boundary=bound\r\n\r\n\
--bound\r\n\
Content-Type: text/plain\r\n\r\n\
See attached image.\r\n\
--bound\r\n\
Content-Type: image/png\r\n\
Content-Disposition: attachment; filename=\"photo.png\"\r\n\
Content-Transfer-Encoding: base64\r\n\r\n\
iVBORw0KGgo=\r\n\
--bound--";
        let infos = extract_attachment_infos(raw);
        assert_eq!(infos.len(), 1);
        assert_eq!(infos[0].index, 0);
        assert_eq!(infos[0].filename, Some("photo.png".to_string()));
        assert_eq!(infos[0].mime_type, "image/png");
        assert!(infos[0].size > 0);
    }

    #[test]
    fn detect_multiple_attachments() {
        let raw = b"Content-Type: multipart/mixed; boundary=bound\r\n\r\n\
--bound\r\n\
Content-Type: text/plain\r\n\r\n\
Email body.\r\n\
--bound\r\n\
Content-Type: application/pdf\r\n\
Content-Disposition: attachment; filename=\"report.pdf\"\r\n\
Content-Transfer-Encoding: base64\r\n\r\n\
JVBER\r\n\
--bound\r\n\
Content-Type: image/jpeg\r\n\
Content-Disposition: attachment; filename=\"photo.jpg\"\r\n\
Content-Transfer-Encoding: base64\r\n\r\n\
/9j/4A\r\n\
--bound--";
        let infos = extract_attachment_infos(raw);
        assert_eq!(infos.len(), 2);
        assert_eq!(infos[0].filename, Some("report.pdf".to_string()));
        assert_eq!(infos[0].mime_type, "application/pdf");
        assert_eq!(infos[0].index, 0);
        assert_eq!(infos[1].filename, Some("photo.jpg".to_string()));
        assert_eq!(infos[1].mime_type, "image/jpeg");
        assert_eq!(infos[1].index, 1);
    }

    #[test]
    fn extract_attachment_data_by_index() {
        let raw = b"Content-Type: multipart/mixed; boundary=bound\r\n\r\n\
--bound\r\n\
Content-Type: text/plain\r\n\r\n\
Email body.\r\n\
--bound\r\n\
Content-Type: text/csv\r\n\
Content-Disposition: attachment; filename=\"data.csv\"\r\n\r\n\
name,age\r\nAlice,30\r\n\
--bound--";
        let result = extract_attachment_data(raw, 0);
        assert!(result.is_ok());
        let att = result.unwrap();
        assert_eq!(att.info.filename, Some("data.csv".to_string()));
        assert_eq!(att.info.mime_type, "text/csv");
        let text = String::from_utf8_lossy(&att.data);
        assert!(text.contains("Alice,30"));
    }

    #[test]
    fn extract_attachment_data_invalid_index() {
        let raw = b"Content-Type: text/plain\r\n\r\nNo attachments here.";
        let result = extract_attachment_data(raw, 0);
        assert!(result.is_err());
    }

    #[test]
    fn detect_inline_image_without_disposition() {
        // Images without explicit Content-Disposition should still be detected
        let raw = b"Content-Type: multipart/mixed; boundary=bound\r\n\r\n\
--bound\r\n\
Content-Type: text/plain\r\n\r\n\
Body text.\r\n\
--bound\r\n\
Content-Type: image/gif\r\n\
Content-Transfer-Encoding: base64\r\n\r\n\
R0lGODlh\r\n\
--bound--";
        let infos = extract_attachment_infos(raw);
        assert_eq!(infos.len(), 1);
        assert_eq!(infos[0].mime_type, "image/gif");
    }

    #[test]
    fn smime_signature_not_counted_as_attachment() {
        // pkcs7-signature parts should be detected as attachments (they are non-text leaf parts)
        // but in practice the S/MIME signature is binary cruft — we still report it
        // so users know about it, but the body extraction ignores it
        let raw = b"Content-Type: multipart/signed; boundary=sig; protocol=\"application/pkcs7-signature\"\r\n\r\n\
--sig\r\n\
Content-Type: text/plain\r\n\r\n\
Signed body\r\n\
--sig\r\n\
Content-Type: application/pkcs7-signature\r\n\r\n\
SIGNATUREDATA\r\n\
--sig--";
        let infos = extract_attachment_infos(raw);
        // The pkcs7-signature is a non-text leaf, so it's detected
        assert_eq!(infos.len(), 1);
        assert_eq!(infos[0].mime_type, "application/pkcs7-signature");
    }

    // --- Draft / RFC 2822 message building tests ---

    #[test]
    fn build_rfc2822_basic_message() {
        let draft = DraftContent {
            from: "alice@example.com",
            to: "bob@example.com",
            subject: "Test Subject",
            body: "Hello, Bob!",
            cc: None,
            bcc: None,
            in_reply_to: None,
            references: None,
        };
        let msg = ImapConnection::build_rfc2822_message(&draft).unwrap();
        assert!(msg.contains("alice@example.com"));
        assert!(msg.contains("bob@example.com"));
        assert!(msg.contains("Subject: Test Subject\r\n"));
        assert!(msg.contains("MIME-Version: 1.0\r\n"));
        assert!(msg.contains("\r\n\r\n"));
        assert!(msg.contains("Hello, Bob!"));
        // Should NOT contain Cc or Bcc headers
        assert!(!msg.contains("Cc:"));
        assert!(!msg.contains("Bcc:"));
    }

    #[test]
    fn build_rfc2822_with_cc_and_bcc() {
        let draft = DraftContent {
            from: "alice@example.com",
            to: "bob@example.com",
            subject: "With CC",
            body: "Body text",
            cc: Some("carol@example.com"),
            bcc: Some("dave@example.com"),
            in_reply_to: None,
            references: None,
        };
        let msg = ImapConnection::build_rfc2822_message(&draft).unwrap();
        assert!(msg.contains("carol@example.com"));
        assert!(msg.contains("dave@example.com"));
    }

    #[test]
    fn build_rfc2822_header_body_separator() {
        let draft = DraftContent {
            from: "a@b.com",
            to: "c@d.com",
            subject: "Sub",
            body: "The body",
            cc: None,
            bcc: None,
            in_reply_to: None,
            references: None,
        };
        let msg = ImapConnection::build_rfc2822_message(&draft).unwrap();
        // Must have \r\n\r\n separating headers from body
        assert!(msg.contains("\r\n\r\n"));
        let parts: Vec<&str> = msg.splitn(2, "\r\n\r\n").collect();
        assert_eq!(parts.len(), 2);
        assert!(parts[1].contains("The body"));
    }

    #[test]
    fn build_rfc2822_parseable_by_mailparse() {
        let draft = DraftContent {
            from: "sender@test.com",
            to: "recipient@test.com",
            subject: "Parse Test",
            body: "Can mailparse handle this?",
            cc: Some("cc@test.com"),
            bcc: None,
            in_reply_to: None,
            references: None,
        };
        let msg = ImapConnection::build_rfc2822_message(&draft).unwrap();
        let parsed = mailparse::parse_mail(msg.as_bytes()).expect("should parse as valid email");
        let body = parsed.get_body().expect("should extract body");
        assert!(body.contains("Can mailparse handle this?"));
    }

    #[test]
    fn validate_draft_rejects_crlf_in_from() {
        let draft = DraftContent {
            from: "evil@example.com\r\nBcc: victim@example.com",
            to: "bob@example.com",
            subject: "Test",
            body: "Body",
            cc: None,
            bcc: None,
            in_reply_to: None,
            references: None,
        };
        let result = ImapConnection::validate_draft_content(&draft);
        assert!(result.is_err(), "from field with CRLF should be rejected");
    }

    #[test]
    fn validate_draft_accepts_clean_from() {
        let draft = DraftContent {
            from: "alice@example.com",
            to: "bob@example.com",
            subject: "Test",
            body: "Body",
            cc: None,
            bcc: None,
            in_reply_to: None,
            references: None,
        };
        let result = ImapConnection::validate_draft_content(&draft);
        assert!(result.is_ok());
    }

    #[test]
    fn build_rfc2822_non_ascii_subject_is_encoded() {
        let draft = DraftContent {
            from: "sender@test.com",
            to: "recipient@test.com",
            subject: "Ünïcödé Subject",
            body: "Body",
            cc: None,
            bcc: None,
            in_reply_to: None,
            references: None,
        };
        let msg = ImapConnection::build_rfc2822_message(&draft).unwrap();
        // Subject must not contain raw non-ASCII bytes
        let subject_line = msg
            .lines()
            .find(|l| l.starts_with("Subject:"))
            .expect("Subject header missing");
        assert!(
            subject_line.is_ascii(),
            "Subject header must be 7-bit ASCII after encoding, got: {subject_line}"
        );
        // The encoded form should be parseable by mailparse and round-trip correctly
        let parsed = mailparse::parse_mail(msg.as_bytes()).expect("should parse");
        let headers = parsed.get_headers();
        let subject = headers.get_first_value("Subject").unwrap();
        assert_eq!(subject, "Ünïcödé Subject");
    }

    #[test]
    fn build_rfc2822_ascii_subject_not_encoded() {
        let draft = DraftContent {
            from: "sender@test.com",
            to: "recipient@test.com",
            subject: "Plain ASCII",
            body: "Body",
            cc: None,
            bcc: None,
            in_reply_to: None,
            references: None,
        };
        let msg = ImapConnection::build_rfc2822_message(&draft).unwrap();
        assert!(msg.contains("Subject: Plain ASCII\r\n"));
    }

    #[test]
    fn build_rfc2822_non_ascii_from_preserves_addr_spec() {
        let draft = DraftContent {
            from: "Müller <muller@example.com>",
            to: "bob@example.com",
            subject: "Test",
            body: "Body",
            cc: None,
            bcc: None,
            in_reply_to: None,
            references: None,
        };
        let msg = ImapConnection::build_rfc2822_message(&draft).unwrap();
        let from_line = msg
            .lines()
            .find(|l| l.starts_with("From:"))
            .expect("From header missing");
        assert!(
            from_line.contains("muller@example.com"),
            "Addr-spec must be plain ASCII in From header, got: {from_line}"
        );
        // From header should be 7-bit ASCII (display name encoded)
        assert!(
            from_line.is_ascii(),
            "From header must be 7-bit ASCII after encoding, got: {from_line}"
        );
    }

    #[test]
    fn build_rfc2822_body_bare_lf_normalized() {
        let draft = DraftContent {
            from: "a@b.com",
            to: "c@d.com",
            subject: "Sub",
            body: "line1\nline2\nline3",
            cc: None,
            bcc: None,
            in_reply_to: None,
            references: None,
        };
        let msg = ImapConnection::build_rfc2822_message(&draft).unwrap();
        // Body should not contain bare LF (LF not preceded by CR)
        let body_start = msg.find("\r\n\r\n").unwrap() + 4;
        let body = &msg[body_start..];
        let has_bare_lf = body
            .as_bytes()
            .windows(2)
            .any(|w| w[1] == b'\n' && w[0] != b'\r');
        assert!(!has_bare_lf, "Body must not contain bare LF, got: {body:?}");
        assert!(body.contains("line1"), "Body should contain original text");
        assert!(body.contains("line2"), "Body should contain original text");
        assert!(body.contains("line3"), "Body should contain original text");
    }

    #[test]
    fn build_rfc2822_with_reply_headers() {
        let draft = DraftContent {
            from: "alice@example.com",
            to: "bob@example.com",
            subject: "Re: Original Subject",
            body: "Reply body",
            cc: None,
            bcc: None,
            in_reply_to: Some("<original-msg-id@example.com>"),
            references: Some("<earlier@example.com> <original-msg-id@example.com>"),
        };
        let msg = ImapConnection::build_rfc2822_message(&draft).unwrap();
        assert!(
            msg.contains("In-Reply-To:"),
            "Should contain In-Reply-To header"
        );
        assert!(
            msg.contains("original-msg-id@example.com"),
            "In-Reply-To should reference original message"
        );
        assert!(
            msg.contains("References:"),
            "Should contain References header"
        );
        assert!(
            msg.contains("earlier@example.com"),
            "References should include earlier message"
        );
        // Verify it's parseable
        let parsed = mailparse::parse_mail(msg.as_bytes()).expect("should parse");
        let headers = parsed.get_headers();
        let in_reply_to = headers.get_first_value("In-Reply-To").unwrap();
        assert!(in_reply_to.contains("original-msg-id@example.com"));
    }

    #[test]
    fn build_rfc2822_without_reply_headers() {
        let draft = DraftContent {
            from: "alice@example.com",
            to: "bob@example.com",
            subject: "New Email",
            body: "Fresh message",
            cc: None,
            bcc: None,
            in_reply_to: None,
            references: None,
        };
        let msg = ImapConnection::build_rfc2822_message(&draft).unwrap();
        assert!(
            !msg.contains("In-Reply-To:"),
            "Should not contain In-Reply-To header"
        );
        assert!(
            !msg.contains("References:"),
            "Should not contain References header"
        );
    }

    #[test]
    fn extract_header_value_from_raw_message() {
        let raw = b"Message-ID: <test@example.com>\r\nReferences: <a@x.com> <b@x.com>\r\nSubject: Test\r\n\r\nBody";
        let refs = extract_header_value(raw, "References");
        assert_eq!(refs, Some("<a@x.com> <b@x.com>".to_string()));
        let missing = extract_header_value(raw, "X-Custom");
        assert_eq!(missing, None);
    }

    #[test]
    fn text_file_attachment_with_disposition() {
        // A text/plain part with Content-Disposition: attachment should be an attachment
        let raw = b"Content-Type: multipart/mixed; boundary=bound\r\n\r\n\
--bound\r\n\
Content-Type: text/plain\r\n\r\n\
Email body.\r\n\
--bound\r\n\
Content-Type: text/plain\r\n\
Content-Disposition: attachment; filename=\"notes.txt\"\r\n\r\n\
These are my notes.\r\n\
--bound--";
        let infos = extract_attachment_infos(raw);
        assert_eq!(infos.len(), 1);
        assert_eq!(infos[0].filename, Some("notes.txt".to_string()));
        assert_eq!(infos[0].mime_type, "text/plain");
    }

    // --- Address list splitting tests ---

    #[test]
    fn split_address_list_simple() {
        let parts = split_address_list("alice@example.com, bob@example.com");
        assert_eq!(parts.len(), 2);
        assert_eq!(parts[0], "alice@example.com");
        assert_eq!(parts[1], "bob@example.com");
    }

    #[test]
    fn split_address_list_quoted_comma_in_display_name() {
        let input = r#""Smith, John" <john@example.com>, alice@example.com"#;
        let parts = split_address_list(input);
        assert_eq!(parts.len(), 2);
        assert_eq!(parts[0], r#""Smith, John" <john@example.com>"#);
        assert_eq!(parts[1], "alice@example.com");
    }

    #[test]
    fn split_address_list_single_address() {
        let parts = split_address_list("Alice <alice@example.com>");
        assert_eq!(parts.len(), 1);
        assert_eq!(parts[0], "Alice <alice@example.com>");
    }
}
