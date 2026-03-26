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
    /// Optional HTML body. When provided, the message is sent as
    /// `multipart/alternative` with both plain-text and HTML parts.
    /// The plain-text `body` is always required as the fallback.
    pub html_body: Option<&'a str>,
    pub cc: Option<&'a str>,
    pub bcc: Option<&'a str>,
    /// Single Message-ID of the email being replied to (sets In-Reply-To header).
    /// Must be exactly one Message-ID, not multiple.
    pub in_reply_to: Option<&'a str>,
    /// Space-separated Message-IDs for the References header (threading chain).
    pub references: Option<&'a str>,
}

/// Sanitize HTML for use in outgoing draft emails.
///
/// Uses an explicit allowlist: only safe, human-visible tags are permitted.
/// No `<img>` tags (prevents tracking pixels), no `<style>`/`<script>`,
/// no event handlers. Links keep their `href` for clickability.
pub fn sanitize_html_for_draft(html: &str) -> String {
    let stripped = strip_hidden_elements(html);
    ammonia::Builder::empty()
        .add_tags([
            "p",
            "br",
            "h1",
            "h2",
            "h3",
            "h4",
            "h5",
            "h6",
            "ul",
            "ol",
            "li",
            "em",
            "strong",
            "b",
            "i",
            "a",
            "blockquote",
            "pre",
            "code",
            "table",
            "thead",
            "tbody",
            "tr",
            "th",
            "td",
            "div",
            "span",
        ])
        .add_tag_attributes("a", ["href"])
        .add_url_schemes(["https", "http", "mailto"])
        .clean(&stripped)
        .to_string()
}

/// Remove HTML elements whose inline `style` attribute hides them from humans.
///
/// Targets `display:none` and `visibility:hidden` patterns commonly used in
/// prompt-injection attacks. Must run *before* ammonia, which strips `style`
/// attributes but preserves the text content of hidden elements.
///
/// Uses a state-machine parser rather than regex to correctly handle nested tags,
/// quoted attributes, and self-closing elements.
fn strip_hidden_elements(html: &str) -> String {
    let mut result = String::with_capacity(html.len());
    let mut chars = html.char_indices().peekable();

    while let Some(&(i, c)) = chars.peek() {
        if c == '<' {
            // Find the end of this opening tag
            if let Some(tag_end) = find_tag_end(html, i) {
                let tag = &html[i..=tag_end];
                // Check if this is an opening tag (not closing/comment/doctype)
                if has_hidden_style(tag) {
                    if let Some(tag_name) = extract_tag_name(tag) {
                        // Self-closing tags or void elements have no closing tag
                        let after_close = if tag.ends_with("/>") || is_void_element(&tag_name) {
                            tag_end + 1
                        } else {
                            skip_to_closing_tag(html, tag_end + 1, &tag_name)
                        };
                        // Advance the iterator past the entire element
                        while chars.peek().is_some_and(|&(j, _)| j < after_close) {
                            chars.next();
                        }
                        continue;
                    }
                }
            }
        }
        result.push(c);
        chars.next();
    }

    result
}

/// Find the index of the `>` that closes a tag starting at `start`.
/// Handles quoted attribute values correctly.
fn find_tag_end(html: &str, start: usize) -> Option<usize> {
    let bytes = html.as_bytes();
    let mut i = start + 1; // skip the '<'
    let mut in_quote: Option<u8> = None;
    while i < bytes.len() {
        let b = bytes[i];
        match in_quote {
            Some(q) if b == q => in_quote = None,
            Some(_) => {}
            None if b == b'"' || b == b'\'' => in_quote = Some(b),
            None if b == b'>' => return Some(i),
            _ => {}
        }
        i += 1;
    }
    None
}

/// Check whether an opening tag's `style` attribute uses CSS that hides content.
///
/// Matches known hiding patterns: `display:none`, `visibility:hidden`, `opacity:0`,
/// `font-size:0`, `height:0` with `overflow:hidden`, and off-screen positioning.
/// Legitimate styling (`color:red`, `font-size:14px`, `max-width:600px`, etc.)
/// is preserved so real email content is not lost.
fn has_hidden_style(tag: &str) -> bool {
    // Must be an opening tag (not </..., <!..., etc.)
    if tag.starts_with("</") || tag.starts_with("<!") || tag.starts_with("<?") {
        return false;
    }
    if let Some(style_value) = extract_style_value(tag) {
        // Strip all whitespace for reliable matching regardless of formatting
        let no_ws: String = style_value
            .to_lowercase()
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect();
        // display:none — element and contents are completely removed from layout
        if no_ws.contains("display:none") {
            return true;
        }
        // visibility:hidden — element is invisible but still takes up space
        if no_ws.contains("visibility:hidden") {
            return true;
        }
        // opacity:0 — fully transparent (catches 0, 0.0, 0.00, etc.)
        if let Some(pos) = no_ws.find("opacity:") {
            let after = &no_ws[pos + 8..];
            // Parse the numeric value: 0, 0.0, 0.00, etc. are all zero
            let val_end = after
                .find(|c: char| c != '.' && !c.is_ascii_digit())
                .unwrap_or(after.len());
            if let Ok(v) = after[..val_end].parse::<f64>() {
                if v == 0.0 {
                    return true;
                }
            }
        }
        // font-size:0 / font-size:0px — text rendered at zero size
        if no_ws.contains("font-size:0px")
            || no_ws.contains("font-size:0;")
            || no_ws.ends_with("font-size:0")
        {
            return true;
        }
        // height:0 or max-height:0 with overflow:hidden — content clipped away.
        // Anchored to property boundaries to avoid matching min-height:0 (legitimate).
        if (has_css_property(&no_ws, "height:0") || no_ws.contains("max-height:0"))
            && no_ws.contains("overflow:hidden")
        {
            return true;
        }
        // Off-screen positioning — only flag large negative offsets (>= 200px)
        // to avoid false-positives on centering patterns like left:50%;margin-left:-100px
        if (no_ws.contains("position:absolute") || no_ws.contains("position:fixed"))
            && has_large_negative_offset(&no_ws)
        {
            return true;
        }
        // text-indent with large negative value (common spam/SEO trick)
        if has_large_negative_value(&no_ws, "text-indent:") {
            return true;
        }
    }
    false
}

/// Check if a CSS property appears at a property boundary in a whitespace-stripped
/// style string. Prevents `"height:0"` from matching inside `"min-height:0"`.
fn has_css_property(no_ws: &str, prop: &str) -> bool {
    no_ws == prop
        || no_ws.starts_with(&format!("{prop};"))
        || no_ws.contains(&format!(";{prop};"))
        || no_ws.ends_with(&format!(";{prop}"))
}

/// Check if any positioning property (left, top, margin-left) has a large negative
/// value (>= 200px). Small negative values are legitimate centering patterns.
fn has_large_negative_offset(no_ws: &str) -> bool {
    for prop in &["left:-", "top:-", "margin-left:-"] {
        if let Some(pos) = no_ws.find(prop) {
            if parse_negative_px_value(&no_ws[pos + prop.len()..]) >= 200 {
                return true;
            }
        }
    }
    false
}

/// Check if a CSS property has a large negative value (>= 200px).
fn has_large_negative_value(no_ws: &str, prop: &str) -> bool {
    if let Some(pos) = no_ws.find(prop) {
        let after = &no_ws[pos + prop.len()..];
        if let Some(rest) = after.strip_prefix('-') {
            return parse_negative_px_value(rest) >= 200;
        }
    }
    false
}

/// Parse leading digits from a string as a pixel value.
fn parse_negative_px_value(s: &str) -> u32 {
    let digits: String = s.chars().take_while(|c| c.is_ascii_digit()).collect();
    digits.parse().unwrap_or(0)
}

/// Extract the value of the `style` attribute from a tag string, if present.
/// Matches `style` as a full attribute name (not `data-style`, etc.).
///
/// Uses ASCII case-insensitive matching directly on the original string to
/// avoid byte-offset mismatches between `tag` and a Unicode-lowercased copy.
fn extract_style_value(tag: &str) -> Option<&str> {
    let bytes = tag.as_bytes();
    let mut i = 0;
    while i + 5 <= bytes.len() {
        // Find "style" (case-insensitive, ASCII only)
        if bytes[i..i + 5].eq_ignore_ascii_case(b"style") {
            // Check preceding byte is whitespace (attribute boundary)
            let preceded_by_ws = i == 0 || matches!(bytes[i - 1], b' ' | b'\t' | b'\n' | b'\r');
            // Check followed by '=' (possibly with whitespace)
            let rest = &tag[i + 5..];
            let followed_by_eq = rest.starts_with('=') || rest.trim_start().starts_with('=');

            if preceded_by_ws && followed_by_eq {
                let eq = rest.find('=')?;
                let after_eq = rest[eq + 1..].trim_start();
                let first = *after_eq.as_bytes().first()?;
                if first == b'"' || first == b'\'' {
                    // Quoted value
                    let end = after_eq[1..].find(first as char)?;
                    return Some(&after_eq[1..1 + end]);
                }
                // Unquoted value: extends to next whitespace or '>'
                let end = after_eq
                    .find(|c: char| c.is_whitespace() || c == '>')
                    .unwrap_or(after_eq.len());
                return Some(&after_eq[..end]);
            }
        }
        i += 1;
    }
    None
}

/// Check if a tag name is an HTML void element (no closing tag).
fn is_void_element(tag_name: &str) -> bool {
    matches!(
        tag_name,
        "area"
            | "base"
            | "br"
            | "col"
            | "embed"
            | "hr"
            | "img"
            | "input"
            | "link"
            | "meta"
            | "param"
            | "source"
            | "track"
            | "wbr"
    )
}

/// Extract the tag name from an opening tag string like `<span ...>`.
fn extract_tag_name(tag: &str) -> Option<String> {
    let inner = tag.strip_prefix('<')?.trim_start();
    let name_end = inner
        .find(|c: char| c.is_whitespace() || c == '>' || c == '/')
        .unwrap_or(inner.len());
    let name = &inner[..name_end];
    if name.is_empty() {
        None
    } else {
        Some(name.to_lowercase())
    }
}

/// Skip past the matching closing tag for `tag_name`, handling nesting.
/// Returns the byte index after the closing tag. If no closing tag is found
/// (malformed HTML), returns `start` so only the opening tag is skipped —
/// this prevents an unclosed hidden element from silently dropping all
/// remaining content.
fn skip_to_closing_tag(html: &str, start: usize, tag_name: &str) -> usize {
    let mut depth: usize = 1;
    let mut i = start;
    let bytes = html.as_bytes();
    while i < bytes.len() && depth > 0 {
        if bytes[i] == b'<' {
            if let Some(tag_end) = find_tag_end(html, i) {
                let tag = &html[i..=tag_end];
                let lower = tag.to_lowercase();
                if lower.starts_with(&format!("<{}", tag_name))
                    && lower.as_bytes().get(1 + tag_name.len()).is_some_and(|&b| {
                        b == b' ' || b == b'>' || b == b'/' || b == b'\t' || b == b'\n'
                    })
                    && !lower.starts_with("</")
                    && !lower.ends_with("/>")
                {
                    depth += 1;
                } else if lower.starts_with(&format!("</{}", tag_name))
                    && lower
                        .as_bytes()
                        .get(2 + tag_name.len())
                        .is_some_and(|&b| b == b'>' || b == b' ' || b == b'\t' || b == b'\n')
                {
                    depth -= 1;
                }
                i = tag_end + 1;
                continue;
            }
        }
        i += 1;
    }
    // If the closing tag was never found, fall back to `start` so only the
    // opening tag is removed and the rest of the content is preserved.
    if depth > 0 {
        start
    } else {
        i
    }
}

/// Sanitize HTML from incoming emails for AI consumption.
///
/// More restrictive than [`sanitize_html_for_draft`]: strips all attributes
/// (including `style`) and only keeps structural/text tags. This is a separate
/// policy from draft composition so the two can evolve independently.
fn sanitize_html_for_reading(html: &str) -> String {
    ammonia::Builder::empty()
        .add_tags([
            "p",
            "br",
            "h1",
            "h2",
            "h3",
            "h4",
            "h5",
            "h6",
            "ul",
            "ol",
            "li",
            "em",
            "strong",
            "b",
            "i",
            "a",
            "blockquote",
            "pre",
            "code",
            "table",
            "thead",
            "tbody",
            "tr",
            "th",
            "td",
            "div",
            "span",
        ])
        .add_tag_attributes("a", ["href"])
        .add_url_schemes(["https", "http", "mailto"])
        .clean(html)
        .to_string()
}

/// Convert HTML to plain text safely for AI consumption.
///
/// First removes elements hidden via CSS (`display:none`, `visibility:hidden`,
/// `opacity:0`, etc.) which are a common prompt-injection vector in emails.
/// Then sanitizes remaining HTML through a restrictive ammonia policy (strips
/// scripts, event handlers, style attributes) before converting to plain text
/// via `html2text`.
fn html_to_safe_text(html: &str) -> String {
    let stripped = strip_hidden_elements(html);
    let sanitized = sanitize_html_for_reading(&stripped);
    html2text::from_read(sanitized.as_bytes(), 80)
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
        // Falls back gracefully for malformed emails (spam, old messages, etc.).
        let (body, attachments, references, message_id) = match mailparse::parse_mail(body_raw) {
            Ok(parsed) => {
                let extracted = extract_body_from_parsed(&parsed);
                let mut attachments = Vec::new();
                collect_attachment_infos(&parsed, &mut attachments);
                let references = extract_header_from_parsed(&parsed.headers, "References");
                let message_id = extract_header_from_parsed(&parsed.headers, "Message-ID");
                (extracted.text, attachments, references, message_id)
            }
            Err(e) => {
                tracing::warn!("failed to parse email UID {uid}: {e}");
                (
                    String::from_utf8_lossy(body_raw).to_string(),
                    Vec::new(),
                    None,
                    None,
                )
            }
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
            message_id,
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
        if let Some(html) = draft.html_body {
            let sanitized = sanitize_html_for_draft(html);
            builder = builder.html_body(sanitized);
        }
        if let Some(cc) = draft.cc {
            builder = builder.cc(Self::parse_address(cc));
        }
        if let Some(bcc) = draft.bcc {
            builder = builder.bcc(Self::parse_address(bcc));
        }
        if let Some(in_reply_to) = draft.in_reply_to {
            // Strip angle brackets — mail_builder adds its own.
            let id = in_reply_to
                .strip_prefix('<')
                .and_then(|s| s.strip_suffix('>'))
                .unwrap_or(in_reply_to);
            builder = builder.in_reply_to(id.to_string());
        }
        if let Some(references) = draft.references {
            let refs: Vec<String> = references
                .split_whitespace()
                .map(|s| {
                    // Strip angle brackets — mail_builder adds its own.
                    s.strip_prefix('<')
                        .and_then(|s| s.strip_suffix('>'))
                        .unwrap_or(s)
                        .to_string()
                })
                .collect();
            if !refs.is_empty() {
                builder = builder.references(refs);
            }
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
            if in_reply_to.contains(|c: char| c.is_ascii_whitespace()) {
                return Err(AppError::Imap(
                    "in_reply_to must be a single Message-ID with no whitespace".to_string(),
                ));
            }
            if !is_valid_message_id(in_reply_to) {
                return Err(AppError::Imap(
                    "in_reply_to must be a Message-ID enclosed in angle brackets, e.g. <id@example.com>".to_string(),
                ));
            }
        }
        if let Some(references) = draft.references {
            Self::validate_imap_input(references, "references")?;
            for token in references.split_whitespace() {
                if !is_valid_message_id(token) {
                    return Err(AppError::Imap(format!(
                        "each Message-ID in references must be enclosed in angle brackets, got: {token}"
                    )));
                }
            }
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

/// Check if a string is a valid RFC 5322 Message-ID token: `<local@domain>`.
/// Must start with `<`, end with `>`, and contain no interior angle brackets.
fn is_valid_message_id(s: &str) -> bool {
    s.len() >= 3
        && s.starts_with('<')
        && s.ends_with('>')
        && !s[1..s.len() - 1].contains(['<', '>', ' ', '\t'])
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

/// Extract a header value from parsed email headers.
/// Uses `get_value()` which performs RFC 2822 unfolding (removing CRLF+whitespace
/// from folded headers) and RFC 2047 decoding. For structured headers like
/// `References`, Message-IDs are not RFC 2047-encoded in practice, so decoding
/// is a no-op, while unfolding is essential for long headers with many Message-IDs.
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

/// Extracted email body parts.
struct ExtractedBody {
    /// Plain text body (converted from HTML if no plain text part exists).
    text: String,
    /// Raw, unsanitized HTML body from the email. Only populated in tests to
    /// verify extraction logic. Gated behind `#[cfg(test)]` to avoid needless
    /// allocation and cloning in production.
    #[cfg(test)]
    raw_html: Option<String>,
}

#[cfg(test)]
fn extract_body(raw: &[u8]) -> String {
    match mailparse::parse_mail(raw) {
        Ok(parsed) => extract_body_from_parsed(&parsed).text,
        Err(_) => String::from_utf8_lossy(raw).to_string(),
    }
}

fn extract_body_from_parsed(parsed: &mailparse::ParsedMail) -> ExtractedBody {
    let ct = parsed.ctype.mimetype.to_lowercase();

    // Leaf node: return text content directly
    if !ct.starts_with("multipart/") {
        if ct == "text/plain" {
            if let Ok(body) = parsed.get_body() {
                return ExtractedBody {
                    text: body,
                    #[cfg(test)]
                    raw_html: None,
                };
            }
        }
        if ct == "text/html" {
            if let Ok(body) = parsed.get_body() {
                let text = html_to_safe_text(&body);
                return ExtractedBody {
                    text,
                    #[cfg(test)]
                    raw_html: Some(body),
                };
            }
        }
        // Skip non-text parts (signatures, attachments, etc.)
        return ExtractedBody {
            text: String::new(),
            #[cfg(test)]
            raw_html: None,
        };
    }

    // Multipart: recurse into subparts, prefer text/plain over text/html
    let mut plain = String::new();
    let mut html_raw = String::new();

    for sub in &parsed.subparts {
        let sub_ct = sub.ctype.mimetype.to_lowercase();
        if sub_ct == "text/plain" && plain.is_empty() {
            if let Ok(body) = sub.get_body() {
                plain = body;
            }
        } else if sub_ct == "text/html" && html_raw.is_empty() {
            if let Ok(body) = sub.get_body() {
                html_raw = body;
            }
        } else if sub_ct.starts_with("multipart/") {
            // Recurse into nested multipart (e.g. multipart/signed → multipart/alternative)
            let nested = extract_body_from_parsed(sub);
            if !nested.text.is_empty() && plain.is_empty() {
                plain = nested.text;
            }
        }
    }

    if !plain.is_empty() {
        return ExtractedBody {
            text: plain,
            #[cfg(test)]
            raw_html: if html_raw.is_empty() {
                None
            } else {
                Some(html_raw)
            },
        };
    }
    if !html_raw.is_empty() {
        let text = html_to_safe_text(&html_raw);
        return ExtractedBody {
            text,
            #[cfg(test)]
            raw_html: Some(html_raw),
        };
    }

    // Last resort: top-level body (preamble text)
    if let Ok(body) = parsed.get_body() {
        if !body.trim().is_empty() && !body.contains("S/MIME") {
            return ExtractedBody {
                text: body,
                #[cfg(test)]
                raw_html: None,
            };
        }
    }

    ExtractedBody {
        text: "(no text content)".to_string(),
        #[cfg(test)]
        raw_html: None,
    }
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
            html_body: None,
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
            html_body: None,
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
            html_body: None,
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
            html_body: None,
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
            html_body: None,
            cc: None,
            bcc: None,
            in_reply_to: None,
            references: None,
        };
        let result = ImapConnection::validate_draft_content(&draft);
        assert!(result.is_err(), "from field with CRLF should be rejected");
    }

    #[test]
    fn validate_draft_rejects_whitespace_in_in_reply_to() {
        let draft = DraftContent {
            from: "a@example.com",
            to: "b@example.com",
            subject: "Re: X",
            body: "Body",
            html_body: None,
            cc: None,
            bcc: None,
            in_reply_to: Some("<id1@x.com> <id2@x.com>"),
            references: None,
        };
        let result = ImapConnection::validate_draft_content(&draft);
        assert!(
            result.is_err(),
            "in_reply_to with whitespace should be rejected"
        );
    }

    #[test]
    fn validate_draft_accepts_clean_from() {
        let draft = DraftContent {
            from: "alice@example.com",
            to: "bob@example.com",
            subject: "Test",
            body: "Body",
            html_body: None,
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
            html_body: None,
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
            html_body: None,
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
            html_body: None,
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
            html_body: None,
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
            html_body: None,
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
        // Verify it's parseable and headers have exact expected values
        let parsed = mailparse::parse_mail(msg.as_bytes()).expect("should parse");
        let headers = parsed.get_headers();
        let in_reply_to = headers.get_first_value("In-Reply-To").unwrap();
        assert_eq!(in_reply_to.trim(), "<original-msg-id@example.com>");
        let references = headers.get_first_value("References").unwrap();
        assert_eq!(
            references.trim(),
            "<earlier@example.com> <original-msg-id@example.com>"
        );
    }

    #[test]
    fn build_rfc2822_without_reply_headers() {
        let draft = DraftContent {
            from: "alice@example.com",
            to: "bob@example.com",
            subject: "New Email",
            body: "Fresh message",
            html_body: None,
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
    fn extract_header_value_unfolds_folded_references() {
        // RFC 5322 folded header: CRLF followed by whitespace
        let raw =
            b"References: <a@x.com>\r\n\t<b@x.com>\r\n <c@x.com>\r\nSubject: Test\r\n\r\nBody";
        let refs = extract_header_value(raw, "References");
        assert!(refs.is_some(), "should parse folded References header");
        let refs = refs.unwrap();
        // Should not contain CRLF after unfolding
        assert!(
            !refs.contains('\r') && !refs.contains('\n'),
            "unfolded References should not contain CRLF, got: {refs:?}"
        );
        assert!(refs.contains("<a@x.com>"));
        assert!(refs.contains("<b@x.com>"));
        assert!(refs.contains("<c@x.com>"));
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

    // --- HTML body tests ---

    #[test]
    fn build_rfc2822_with_html_body() {
        let draft = DraftContent {
            from: "alice@example.com",
            to: "bob@example.com",
            subject: "Formatted Email",
            body: "Hello, Bob!",
            html_body: Some("<p>Hello, <strong>Bob</strong>!</p>"),
            cc: None,
            bcc: None,
            in_reply_to: None,
            references: None,
        };
        let msg = ImapConnection::build_rfc2822_message(&draft).unwrap();
        // Should be multipart/alternative
        assert!(
            msg.contains("multipart/alternative"),
            "Should produce multipart/alternative, got:\n{msg}"
        );
        assert!(msg.contains("text/plain"), "Should contain text/plain part");
        assert!(msg.contains("text/html"), "Should contain text/html part");
        assert!(
            msg.contains("Hello, Bob!"),
            "Should contain plain text body"
        );
        assert!(
            msg.contains("<strong>Bob</strong>"),
            "Should contain HTML body"
        );
    }

    #[test]
    fn build_rfc2822_html_body_parseable() {
        let draft = DraftContent {
            from: "sender@test.com",
            to: "recipient@test.com",
            subject: "HTML Test",
            body: "Plain text version",
            html_body: Some("<h1>HTML version</h1>"),
            cc: None,
            bcc: None,
            in_reply_to: None,
            references: None,
        };
        let msg = ImapConnection::build_rfc2822_message(&draft).unwrap();
        let parsed = mailparse::parse_mail(msg.as_bytes()).expect("should parse as valid email");
        // Should be multipart with both text and html subparts
        assert!(
            parsed.ctype.mimetype.contains("multipart"),
            "Top-level should be multipart"
        );
        let extracted = extract_body_from_parsed(&parsed);
        assert!(
            extracted.text.contains("Plain text version"),
            "Should extract plain text body"
        );
        assert!(extracted.raw_html.is_some(), "Should have HTML body");
        assert!(
            extracted
                .raw_html
                .unwrap()
                .contains("<h1>HTML version</h1>"),
            "Should extract HTML body"
        );
    }

    #[test]
    fn extract_html_from_multipart_alternative() {
        let raw = b"Content-Type: multipart/alternative; boundary=bound\r\n\r\n\
--bound\r\n\
Content-Type: text/plain\r\n\r\n\
Plain text body\r\n\
--bound\r\n\
Content-Type: text/html\r\n\r\n\
<p>HTML body</p>\r\n\
--bound--";
        let parsed = mailparse::parse_mail(raw).unwrap();
        let extracted = extract_body_from_parsed(&parsed);
        assert!(extracted.text.contains("Plain text body"));
        assert!(extracted.raw_html.is_some());
        assert!(extracted.raw_html.unwrap().contains("<p>HTML body</p>"));
    }

    #[test]
    fn extract_html_from_html_only_email() {
        let raw = b"Content-Type: text/html\r\n\r\n<p>Only HTML</p>";
        let parsed = mailparse::parse_mail(raw).unwrap();
        let extracted = extract_body_from_parsed(&parsed);
        assert!(extracted.raw_html.is_some());
        assert!(extracted
            .raw_html
            .as_ref()
            .unwrap()
            .contains("<p>Only HTML</p>"));
        // Plain text should be derived from HTML
        assert!(extracted.text.contains("Only HTML"));
    }

    #[test]
    fn extract_no_html_from_plain_only_email() {
        let raw = b"Content-Type: text/plain\r\n\r\nJust plain text";
        let parsed = mailparse::parse_mail(raw).unwrap();
        let extracted = extract_body_from_parsed(&parsed);
        assert!(extracted.text.contains("Just plain text"));
        assert!(extracted.raw_html.is_none());
    }

    // --- HTML sanitization tests ---

    #[test]
    fn sanitize_draft_strips_script_tags() {
        let html = r#"<p>Hello</p><script>alert('xss')</script><p>World</p>"#;
        let sanitized = sanitize_html_for_draft(html);
        assert!(!sanitized.contains("<script>"));
        assert!(!sanitized.contains("alert"));
        assert!(sanitized.contains("<p>Hello</p>"));
        assert!(sanitized.contains("<p>World</p>"));
    }

    #[test]
    fn sanitize_draft_strips_style_tags() {
        let html = r#"<p>Hello</p><style>body { display: none; }</style>"#;
        let sanitized = sanitize_html_for_draft(html);
        assert!(!sanitized.contains("<style>"));
        assert!(!sanitized.contains("display"));
        assert!(sanitized.contains("<p>Hello</p>"));
    }

    #[test]
    fn sanitize_draft_strips_style_attributes() {
        let html = r#"<span style="display:none">hidden injection</span><p>visible</p>"#;
        let sanitized = sanitize_html_for_draft(html);
        assert!(!sanitized.contains("display:none"));
        assert!(sanitized.contains("visible"));
    }

    #[test]
    fn sanitize_draft_preserves_safe_tags() {
        let html = "<h1>Title</h1><p>Paragraph with <strong>bold</strong> and <em>italic</em></p><ul><li>item</li></ul><a href=\"https://example.com\">link</a>";
        let sanitized = sanitize_html_for_draft(html);
        assert!(sanitized.contains("<h1>"));
        assert!(sanitized.contains("<strong>"));
        assert!(sanitized.contains("<em>"));
        assert!(sanitized.contains("<ul>"));
        assert!(sanitized.contains("<li>"));
        assert!(
            sanitized.contains(r#"href="https://example.com""#),
            "href should be preserved on links, got: {sanitized:?}"
        );
    }

    #[test]
    fn html_to_safe_text_strips_scripts() {
        let html = r#"<p>Hello</p><script>evil()</script>"#;
        let text = html_to_safe_text(html);
        assert!(text.contains("Hello"));
        assert!(!text.contains("evil"));
        assert!(!text.contains("<script>"));
    }

    #[test]
    fn html_to_safe_text_strips_hidden_elements() {
        let html = r#"<p>Visible</p><span style="display:none">hidden injection</span>"#;
        let text = html_to_safe_text(html);
        assert!(text.contains("Visible"));
        assert!(
            !text.contains("hidden injection"),
            "Hidden text should be stripped entirely, got: {text:?}"
        );
    }

    #[test]
    fn html_to_safe_text_strips_visibility_hidden() {
        let html =
            r#"<p>Hello</p><div style="visibility: hidden">secret payload</div><p>World</p>"#;
        let text = html_to_safe_text(html);
        assert!(text.contains("Hello"));
        assert!(text.contains("World"));
        assert!(
            !text.contains("secret payload"),
            "visibility:hidden text should be stripped, got: {text:?}"
        );
    }

    #[test]
    fn html_to_safe_text_strips_nested_hidden_elements() {
        let html = r#"<div style="display:none"><p>Nested <strong>hidden</strong> content</p></div><p>Visible</p>"#;
        let text = html_to_safe_text(html);
        assert!(text.contains("Visible"));
        assert!(
            !text.contains("hidden"),
            "Nested hidden content should be stripped, got: {text:?}"
        );
    }

    #[test]
    fn strip_hidden_preserves_visible_styled_content() {
        // Legitimate styling (color, font-size, etc.) should be preserved
        let html = r#"<p style="color:red">Styled text</p><span style="display:none">hidden</span><p>Normal</p>"#;
        let result = strip_hidden_elements(html);
        assert!(
            result.contains("Styled text"),
            "Visible styled content should be preserved, got: {result:?}"
        );
        assert!(result.contains("Normal"));
        assert!(!result.contains("hidden"));
    }

    #[test]
    fn strip_hidden_catches_opacity_zero() {
        let html = r#"<span style="opacity:0">invisible</span><p>Visible</p>"#;
        let result = strip_hidden_elements(html);
        assert!(
            !result.contains("invisible"),
            "opacity:0 should be stripped, got: {result:?}"
        );
        assert!(result.contains("Visible"));
    }

    #[test]
    fn strip_hidden_allows_nonzero_opacity() {
        let html = r#"<span style="opacity:0.5">half visible</span>"#;
        let result = strip_hidden_elements(html);
        assert!(
            result.contains("half visible"),
            "opacity:0.5 should be kept, got: {result:?}"
        );
    }

    #[test]
    fn strip_hidden_catches_opacity_zero_point_zero() {
        let html = r#"<span style="opacity:0.0">hidden</span><p>Visible</p>"#;
        let result = strip_hidden_elements(html);
        assert!(
            !result.contains("hidden"),
            "opacity:0.0 should be stripped, got: {result:?}"
        );
        assert!(result.contains("Visible"));
    }

    #[test]
    fn strip_hidden_catches_font_size_zero() {
        let html = r#"<span style="font-size:0px">tiny</span><p>Normal</p>"#;
        let result = strip_hidden_elements(html);
        assert!(
            !result.contains("tiny"),
            "font-size:0px should be stripped, got: {result:?}"
        );
        assert!(result.contains("Normal"));
    }

    #[test]
    fn strip_hidden_catches_offscreen_positioning() {
        let html = r#"<div style="position:absolute;left:-9999px">offscreen</div><p>Visible</p>"#;
        let result = strip_hidden_elements(html);
        assert!(
            !result.contains("offscreen"),
            "off-screen should be stripped, got: {result:?}"
        );
        assert!(result.contains("Visible"));
    }

    #[test]
    fn strip_hidden_catches_text_indent() {
        let html = r#"<div style="text-indent:-9999px">hidden</div><p>Visible</p>"#;
        let result = strip_hidden_elements(html);
        assert!(
            !result.contains("hidden"),
            "text-indent should be stripped, got: {result:?}"
        );
        assert!(result.contains("Visible"));
    }

    #[test]
    fn strip_hidden_catches_overflow_hidden_with_zero_height() {
        let html = r#"<div style="height:0;overflow:hidden">clipped</div><p>Visible</p>"#;
        let result = strip_hidden_elements(html);
        assert!(
            !result.contains("clipped"),
            "height:0+overflow:hidden should be stripped, got: {result:?}"
        );
        assert!(result.contains("Visible"));
    }

    #[test]
    fn strip_hidden_not_tricked_by_data_style_attribute() {
        // "data-style" should not be confused with "style"
        let html =
            r#"<div data-style="display:none" style="display:none">hidden</div><p>Visible</p>"#;
        let result = strip_hidden_elements(html);
        assert!(result.contains("Visible"));
        assert!(
            !result.contains("hidden"),
            "Real style=display:none should still be caught, got: {result:?}"
        );
    }

    #[test]
    fn strip_hidden_ignores_data_style_only() {
        // Only "data-style" attribute, no real "style" — should NOT strip
        let html = r#"<div data-style="display:none">keep this</div><p>Also keep</p>"#;
        let result = strip_hidden_elements(html);
        assert!(
            result.contains("keep this"),
            "data-style should not trigger stripping, got: {result:?}"
        );
        assert!(result.contains("Also keep"));
    }

    #[test]
    fn strip_hidden_handles_void_elements() {
        // Void element with hidden style should not consume following content
        let html = r#"<input style="display:none"><p>Visible after void element</p>"#;
        let result = strip_hidden_elements(html);
        assert!(
            result.contains("Visible after void element"),
            "Content after void element should be preserved, got: {result:?}"
        );
    }

    #[test]
    fn strip_hidden_handles_self_closing_tags() {
        let html = r#"<img style="display:none"/><p>Still visible</p>"#;
        let result = strip_hidden_elements(html);
        assert!(
            result.contains("Still visible"),
            "Content after self-closing tag should be preserved, got: {result:?}"
        );
    }

    #[test]
    fn strip_hidden_closing_tag_word_boundary() {
        // </divider> should not match when tag_name is "div"
        let html = r#"<div style="display:none"><divider>keep</divider></div><p>After</p>"#;
        let result = strip_hidden_elements(html);
        assert!(
            result.contains("After"),
            "Content after hidden div should be preserved, got: {result:?}"
        );
        assert!(
            !result.contains("keep"),
            "Content inside hidden div should be stripped, got: {result:?}"
        );
    }

    #[test]
    fn strip_hidden_extra_whitespace_in_style() {
        // CSS allows arbitrary whitespace around colons
        let html = r#"<span style="display:  none">hidden</span><p>Visible</p>"#;
        let result = strip_hidden_elements(html);
        assert!(
            !result.contains("hidden"),
            "Extra whitespace in display:none should still be caught, got: {result:?}"
        );
        assert!(result.contains("Visible"));
    }

    #[test]
    fn strip_hidden_whitespace_around_colon() {
        let html = r#"<span style="display : none">hidden</span><p>Visible</p>"#;
        let result = strip_hidden_elements(html);
        assert!(
            !result.contains("hidden"),
            "Whitespace around colon should still be caught, got: {result:?}"
        );
        assert!(result.contains("Visible"));
    }

    #[test]
    fn strip_hidden_catches_unquoted_style() {
        let html = r#"<span style=display:none>hidden</span><p>Visible</p>"#;
        let result = strip_hidden_elements(html);
        assert!(
            !result.contains("hidden"),
            "Unquoted style=display:none should be caught, got: {result:?}"
        );
        assert!(result.contains("Visible"));
    }

    #[test]
    fn strip_hidden_unclosed_element_preserves_remaining() {
        // Unclosed hidden div should not swallow all remaining content
        let html = r#"<div style="display:none">hidden start<p>Visible after unclosed</p>"#;
        let result = strip_hidden_elements(html);
        assert!(
            result.contains("Visible after unclosed"),
            "Content after unclosed hidden element should be preserved, got: {result:?}"
        );
    }

    #[test]
    fn sanitize_draft_strips_img_tags() {
        let html = r#"<p>Hello</p><img src="https://tracker.evil/pixel.gif"><p>World</p>"#;
        let sanitized = sanitize_html_for_draft(html);
        assert!(
            !sanitized.contains("<img"),
            "img tags should be stripped from drafts"
        );
        assert!(!sanitized.contains("tracker.evil"));
        assert!(sanitized.contains("Hello"));
        assert!(sanitized.contains("World"));
    }

    #[test]
    fn strip_hidden_preserves_min_height_zero() {
        // min-height:0 with overflow:hidden is a legitimate animation pattern
        let html =
            r#"<div style="min-height:0;overflow:hidden">accordion content</div><p>After</p>"#;
        let result = strip_hidden_elements(html);
        assert!(
            result.contains("accordion content"),
            "min-height:0 should not be stripped, got: {result:?}"
        );
    }

    #[test]
    fn strip_hidden_preserves_small_negative_offset() {
        // Small negative margin-left is a centering pattern, not hiding
        let html = r#"<div style="position:absolute;left:50%;margin-left:-100px">centered</div><p>After</p>"#;
        let result = strip_hidden_elements(html);
        assert!(
            result.contains("centered"),
            "Small negative offset should not be stripped, got: {result:?}"
        );
    }

    #[test]
    fn strip_hidden_catches_large_negative_offset() {
        let html = r#"<div style="position:absolute;left:-9999px">hidden</div><p>Visible</p>"#;
        let result = strip_hidden_elements(html);
        assert!(
            !result.contains("hidden"),
            "Large negative offset should be stripped, got: {result:?}"
        );
        assert!(result.contains("Visible"));
    }

    #[test]
    fn strip_hidden_preserves_small_text_indent() {
        let html = r#"<div style="text-indent:-10px">slightly indented</div>"#;
        let result = strip_hidden_elements(html);
        assert!(
            result.contains("slightly indented"),
            "Small text-indent should not be stripped, got: {result:?}"
        );
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
