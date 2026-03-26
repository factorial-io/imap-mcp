use async_native_tls::TlsConnector;
use base64::Engine;
use futures::TryStreamExt;
use lol_html::{element, rewrite_str, RewriteStrSettings};
use serde::Serialize;

use crate::error::AppError;

/// Fields for composing a draft email.
pub struct DraftContent<'a> {
    pub from: &'a str,
    pub to: &'a str,
    pub subject: &'a str,
    pub body: &'a str,
    /// Optional raw HTML body. When provided, the message is sent as
    /// `multipart/alternative` with both plain-text and HTML parts.
    /// The plain-text `body` is always required as the fallback.
    ///
    /// Accepts **raw, unsanitized** HTML — [`build_rfc2822_message`] runs it
    /// through [`sanitize_html_for_draft`] before embedding in the message.
    /// Callers do not need to pre-sanitize.
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
/// First removes elements hidden via CSS (prompt-injection vector), then
/// sanitizes through ammonia's allowlist. No `<img>` (tracking pixels),
/// no `<style>`/`<script>`, no event handlers.
pub fn sanitize_html_for_draft(html: &str) -> Result<String, AppError> {
    let stripped = strip_hidden_elements(html)?;
    Ok(ammonia_draft().clean(&stripped).to_string())
}

/// Remove elements hidden via CSS and strip `<style>`/`<script>` blocks.
///
/// Uses `lol_html` for proper HTML parsing instead of hand-rolled tokenization.
/// Targets `display:none`, `visibility:hidden`, `opacity:0`, `font-size:0`,
/// `height:0`+`overflow:hidden`, off-screen positioning, and `text-indent`
/// hiding — common prompt-injection vectors in emails.
fn strip_hidden_elements(html: &str) -> Result<String, AppError> {
    rewrite_str(
        html,
        RewriteStrSettings {
            element_content_handlers: vec![
                element!("style", |el| {
                    el.remove();
                    Ok(())
                }),
                element!("script", |el| {
                    el.remove();
                    Ok(())
                }),
                // Strip class attributes so CSS class-based hiding
                // (e.g. .h{display:none}) cannot target elements after
                // the <style> block is removed.
                element!("*[class]", |el| {
                    el.remove_attribute("class");
                    Ok(())
                }),
                element!("*[style]", |el| {
                    if let Some(style) = el.get_attribute("style") {
                        if is_style_hidden(&style) {
                            el.remove();
                        }
                    }
                    Ok(())
                }),
            ],
            ..Default::default()
        },
    )
    .map_err(|e| AppError::Imap(format!("failed to sanitize HTML: {e}")))
}

/// Decode HTML entities (numeric and named) in a string.
///
/// lol_html returns attribute values without entity decoding, so we need
/// this to catch obfuscated style values like `display&#58;none` or
/// `display&colon;none`.
fn decode_html_entities_simple(s: &str) -> String {
    if !s.contains('&') {
        return s.to_string();
    }
    let mut result = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    'outer: while let Some(c) = chars.next() {
        if c != '&' {
            result.push(c);
            continue;
        }
        let mut entity = String::new();
        let mut found_semi = false;
        for ec in chars.by_ref() {
            if ec == ';' {
                found_semi = true;
                break;
            }
            entity.push(ec);
            if entity.len() > 32 {
                // Too long — not a real entity. Emit raw and drain to ';'.
                result.push('&');
                result.push_str(&entity);
                for ec2 in chars.by_ref() {
                    result.push(ec2);
                    if ec2 == ';' {
                        break;
                    }
                }
                continue 'outer;
            }
        }
        if found_semi {
            if let Some(ch) = decode_entity(&entity) {
                result.push(ch);
                continue;
            }
        }
        result.push('&');
        result.push_str(&entity);
        if found_semi {
            result.push(';');
        }
    }
    result
}

/// Decode a single HTML entity reference (without `&` and `;`).
fn decode_entity(entity: &str) -> Option<char> {
    if let Some(rest) = entity.strip_prefix('#') {
        let code = if let Some(hex) = rest.strip_prefix('x').or_else(|| rest.strip_prefix('X')) {
            u32::from_str_radix(hex, 16).ok()
        } else {
            rest.parse().ok()
        };
        return code.and_then(char::from_u32);
    }
    match entity {
        "colon" => Some(':'),
        "semi" => Some(';'),
        "comma" => Some(','),
        "period" => Some('.'),
        "hyphen" | "minus" => Some('-'),
        "sol" => Some('/'),
        "lpar" => Some('('),
        "rpar" => Some(')'),
        "equals" => Some('='),
        "num" => Some('#'),
        "percnt" => Some('%'),
        "amp" => Some('&'),
        "lt" => Some('<'),
        "gt" => Some('>'),
        "quot" => Some('"'),
        "apos" => Some('\''),
        "nbsp" => Some(' '),
        _ => None,
    }
}

/// Check whether a CSS style value uses techniques to hide content from humans.
///
/// Decodes HTML entities first since lol_html returns raw attribute values
/// without entity decoding (e.g. `display&#58;none` stays as-is).
fn is_style_hidden(style: &str) -> bool {
    let decoded = decode_html_entities_simple(style);
    let no_ws: String = decoded
        .to_lowercase()
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();

    if no_ws.contains("display:none") || no_ws.contains("visibility:hidden") {
        return true;
    }
    if has_zero_css_value(&no_ws, "opacity:") {
        return true;
    }
    // font-size < 2px is effectively invisible — catches 0, 0.1px, 1px, etc.
    if has_small_css_value(&no_ws, "font-size:", 2.0) {
        return true;
    }
    // height:0 / max-height:0 — zero-height elements serve no legitimate purpose.
    // Strip unconditionally (previously required overflow:hidden, but zero-height
    // elements can hide content in many email clients regardless).
    if has_zero_css_value(&no_ws, "height:") || has_zero_css_value(&no_ws, "max-height:") {
        return true;
    }
    if (has_property_at_boundary(&no_ws, "position:absolute")
        || has_property_at_boundary(&no_ws, "position:fixed"))
        && has_large_negative_offset(&no_ws)
    {
        return true;
    }
    if has_large_negative_value(&no_ws, "text-indent:") {
        return true;
    }
    false
}

/// Check if a CSS property has a zero (or zero-equivalent) numeric value at a
/// property boundary (start of string or after `;`).
fn has_zero_css_value(no_ws: &str, prop: &str) -> bool {
    let mut from = 0;
    while let Some(pos) = no_ws[from..].find(prop) {
        let abs = from + pos;
        if abs == 0 || no_ws.as_bytes()[abs - 1] == b';' {
            let value = &no_ws[abs + prop.len()..];
            let num_end = value
                .find(|c: char| c != '.' && !c.is_ascii_digit())
                .unwrap_or(value.len());
            if num_end > 0 {
                if let Ok(v) = value[..num_end].parse::<f64>() {
                    if v == 0.0 {
                        return true;
                    }
                }
            }
        }
        from = abs + prop.len();
    }
    false
}

/// Like `has_zero_css_value` but uses a threshold instead of exact zero.
/// Catches near-zero values like `font-size:0.1px` or `font-size:1px` that are
/// effectively invisible to humans but render as text in `html2text`.
fn has_small_css_value(no_ws: &str, prop: &str, threshold: f64) -> bool {
    let mut from = 0;
    while let Some(pos) = no_ws[from..].find(prop) {
        let abs = from + pos;
        if abs == 0 || no_ws.as_bytes()[abs - 1] == b';' {
            let value = &no_ws[abs + prop.len()..];
            let num_end = value
                .find(|c: char| c != '.' && !c.is_ascii_digit())
                .unwrap_or(value.len());
            if num_end > 0 {
                if let Ok(v) = value[..num_end].parse::<f64>() {
                    if v < threshold {
                        return true;
                    }
                }
            }
        }
        from = abs + prop.len();
    }
    false
}

/// Check if any positioning property has a large negative value (>= 200px).
fn has_large_negative_offset(no_ws: &str) -> bool {
    for prop in &[
        "left:-",
        "top:-",
        "right:-",
        "bottom:-",
        "margin-left:-",
        "margin-top:-",
    ] {
        let mut search = 0;
        while let Some(pos) = no_ws[search..].find(prop) {
            let abs = search + pos;
            if (abs == 0 || no_ws.as_bytes()[abs - 1] == b';')
                && parse_px_digits(&no_ws[abs + prop.len()..]) >= 200
            {
                return true;
            }
            search = abs + prop.len();
        }
    }
    false
}

/// Check if a CSS property has a large negative value (>= 200px).
fn has_large_negative_value(no_ws: &str, prop: &str) -> bool {
    let mut search = 0;
    while let Some(pos) = no_ws[search..].find(prop) {
        let abs = search + pos;
        if abs == 0 || no_ws.as_bytes()[abs - 1] == b';' {
            let after = &no_ws[abs + prop.len()..];
            if let Some(rest) = after.strip_prefix('-') {
                if parse_px_digits(rest) >= 200 {
                    return true;
                }
            }
        }
        search = abs + prop.len();
    }
    false
}

/// Check if a CSS property:value pair appears at a property boundary.
/// Prevents `text-overflow:hidden` from matching a check for `overflow:hidden`.
fn has_property_at_boundary(no_ws: &str, prop_value: &str) -> bool {
    let mut search = 0;
    while let Some(pos) = no_ws[search..].find(prop_value) {
        let abs = search + pos;
        if abs == 0 || no_ws.as_bytes()[abs - 1] == b';' {
            return true;
        }
        search = abs + prop_value.len();
    }
    false
}

/// Parse leading digits from a string as a pixel value.
fn parse_px_digits(s: &str) -> u32 {
    let digits: String = s.chars().take_while(|c| c.is_ascii_digit()).collect();
    digits.parse().unwrap_or(0)
}

/// Tags allowed in both draft and reading sanitization.
const ALLOWED_TAGS: [&str; 22] = [
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
    "tr",
    "td",
];

/// Ammonia allowlist for reading: strips all attributes except `href` on links.
/// Used by `html_to_safe_text` where everything becomes plain text anyway.
fn ammonia_reading() -> ammonia::Builder<'static> {
    let mut builder = ammonia::Builder::empty();
    builder
        .add_tags(ALLOWED_TAGS)
        .add_tags(["thead", "tbody", "th", "div", "span"])
        .add_tag_attributes("a", ["href"])
        .add_url_schemes(["https", "http", "mailto"]);
    builder
}

/// Ammonia allowlist for outgoing drafts: uses `attribute_filter` to sanitize
/// CSS `style` values down to safe visual properties only. Hidden styles are
/// already stripped by `strip_hidden_elements`, but this also blocks tracking
/// pixels via `background-image:url(...)`, overlays, `color:transparent`, etc.
fn ammonia_draft() -> ammonia::Builder<'static> {
    let mut builder = ammonia::Builder::empty();
    let styled_tags = [
        "p",
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
        "tr",
        "td",
        "thead",
        "tbody",
        "th",
        "div",
        "span",
    ];
    builder
        .add_tags(ALLOWED_TAGS)
        .add_tags(["thead", "tbody", "th", "div", "span"])
        .add_tag_attributes("a", ["href"])
        .add_url_schemes(["https", "http", "mailto"])
        .attribute_filter(|_element, attribute, value| {
            if attribute != "style" {
                return Some(value.into());
            }
            let filtered = filter_css_properties(value);
            if filtered.is_empty() {
                None
            } else {
                Some(filtered.into())
            }
        });
    for tag in styled_tags {
        builder.add_tag_attributes(tag, ["style"]);
    }
    builder
}

/// CSS properties safe for email formatting. No `background-image` (tracking),
/// no `position`/`opacity`/`display`/`visibility` (hiding/overlays), no `color`
/// with transparent values.
const SAFE_CSS_PROPERTIES: &[&str] = &[
    "color",
    "background-color",
    "font-family",
    "font-size",
    "font-weight",
    "font-style",
    "line-height",
    "text-align",
    "text-decoration",
    "text-transform",
    "letter-spacing",
    "word-spacing",
    "border",
    "border-top",
    "border-right",
    "border-bottom",
    "border-left",
    "border-collapse",
    "border-spacing",
    "border-color",
    "border-style",
    "border-width",
    "border-radius",
    "margin",
    "margin-top",
    "margin-right",
    "margin-bottom",
    "margin-left",
    "padding",
    "padding-top",
    "padding-right",
    "padding-bottom",
    "padding-left",
    "width",
    "max-width",
    "min-width",
    "height",
    "max-height",
    "min-height",
    "vertical-align",
    "white-space",
    "list-style",
    "list-style-type",
];

/// Check if a CSS color value is transparent (alpha channel == 0).
/// Handles `transparent`, `rgba(...)`, `rgb(... / alpha)`, `hsla(...)`.
fn is_transparent_color(value: &str) -> bool {
    let compact: String = value.chars().filter(|c| !c.is_whitespace()).collect();
    if compact == "transparent" {
        return true;
    }
    // Extract the last numeric value (alpha channel) from color functions.
    // Patterns: rgba(r,g,b,A) or rgba(r g b / A) or hsla(h,s,l,A)
    let alpha = if let Some(pos) = compact.rfind(',') {
        &compact[pos + 1..compact.len().saturating_sub(1)]
    } else if let Some(pos) = compact.rfind('/') {
        &compact[pos + 1..compact.len().saturating_sub(1)]
    } else {
        return false;
    };
    // Parse alpha as f64 — catches 0, 0.0, 0.00, etc.
    alpha.parse::<f64>().ok().is_some_and(|v| v == 0.0)
}

/// Check if a CSS value is zero (0, 0px, 0em, 0.0, etc.).
fn is_zero_value(value: &str) -> bool {
    let lower = value.trim().to_lowercase();
    let num_end = lower
        .find(|c: char| c != '.' && !c.is_ascii_digit())
        .unwrap_or(lower.len());
    if num_end == 0 {
        return false;
    }
    lower[..num_end]
        .parse::<f64>()
        .ok()
        .is_some_and(|v| v == 0.0)
}

/// Filter CSS style value to only permit safe properties.
/// Returns a sanitized CSS string with only allowed properties.
fn filter_css_properties(style: &str) -> String {
    let mut safe = Vec::new();
    for declaration in style.split(';') {
        let declaration = declaration.trim();
        if declaration.is_empty() {
            continue;
        }
        if let Some((prop, value)) = declaration.split_once(':') {
            let prop = prop.trim().to_lowercase();
            let value = value.trim();
            if SAFE_CSS_PROPERTIES.contains(&prop.as_str()) {
                // Block url() in any property value (tracking pixels)
                let lower_value = value.to_lowercase();
                if lower_value.contains("url(") || lower_value.contains("expression(") {
                    continue;
                }
                // Block transparent colors — parse the alpha channel numerically
                // to catch 0, 0.0, 0.00, etc. regardless of CSS syntax variant.
                if (prop == "color" || prop == "background-color")
                    && is_transparent_color(&lower_value)
                {
                    continue;
                }
                // Block zero height/max-height — elements with no height serve
                // no legitimate formatting purpose and can hide content.
                if (prop == "height" || prop == "max-height") && is_zero_value(value) {
                    continue;
                }
                safe.push(format!("{prop}: {value}"));
            }
        }
    }
    safe.join("; ")
}

/// Convert HTML to plain text safely for AI consumption.
///
/// Removes hidden elements (prompt-injection vector), sanitizes through ammonia,
/// then converts to plain text via `html2text`.
fn html_to_safe_text(html: &str) -> String {
    let stripped = match strip_hidden_elements(html) {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!("HTML sanitization failed: {e}");
            return "(HTML body could not be processed)".to_string();
        }
    };
    let sanitized = ammonia_reading().clean(&stripped).to_string();
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
            let sanitized = sanitize_html_for_draft(html)?;
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
        let sanitized = sanitize_html_for_draft(html).unwrap();
        assert!(!sanitized.contains("<script>"));
        assert!(!sanitized.contains("alert"));
        assert!(sanitized.contains("<p>Hello</p>"));
        assert!(sanitized.contains("<p>World</p>"));
    }

    #[test]
    fn sanitize_draft_strips_style_tags() {
        let html = r#"<p>Hello</p><style>body { display: none; }</style>"#;
        let sanitized = sanitize_html_for_draft(html).unwrap();
        assert!(!sanitized.contains("<style>"));
        assert!(!sanitized.contains("display"));
        assert!(sanitized.contains("<p>Hello</p>"));
    }

    #[test]
    fn sanitize_draft_strips_style_attributes() {
        let html = r#"<span style="display:none">hidden injection</span><p>visible</p>"#;
        let sanitized = sanitize_html_for_draft(html).unwrap();
        assert!(!sanitized.contains("display:none"));
        assert!(sanitized.contains("visible"));
    }

    #[test]
    fn sanitize_draft_preserves_safe_tags() {
        let html = "<h1>Title</h1><p>Paragraph with <strong>bold</strong> and <em>italic</em></p><ul><li>item</li></ul><a href=\"https://example.com\">link</a>";
        let sanitized = sanitize_html_for_draft(html).unwrap();
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
        let result = strip_hidden_elements(html).unwrap();
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
        let result = strip_hidden_elements(html).unwrap();
        assert!(
            !result.contains("invisible"),
            "opacity:0 should be stripped, got: {result:?}"
        );
        assert!(result.contains("Visible"));
    }

    #[test]
    fn strip_hidden_allows_nonzero_opacity() {
        let html = r#"<span style="opacity:0.5">half visible</span>"#;
        let result = strip_hidden_elements(html).unwrap();
        assert!(
            result.contains("half visible"),
            "opacity:0.5 should be kept, got: {result:?}"
        );
    }

    #[test]
    fn strip_hidden_catches_opacity_zero_point_zero() {
        let html = r#"<span style="opacity:0.0">hidden</span><p>Visible</p>"#;
        let result = strip_hidden_elements(html).unwrap();
        assert!(
            !result.contains("hidden"),
            "opacity:0.0 should be stripped, got: {result:?}"
        );
        assert!(result.contains("Visible"));
    }

    #[test]
    fn strip_hidden_catches_font_size_zero() {
        let html = r#"<span style="font-size:0px">tiny</span><p>Normal</p>"#;
        let result = strip_hidden_elements(html).unwrap();
        assert!(
            !result.contains("tiny"),
            "font-size:0px should be stripped, got: {result:?}"
        );
        assert!(result.contains("Normal"));
    }

    #[test]
    fn strip_hidden_catches_offscreen_positioning() {
        let html = r#"<div style="position:absolute;left:-9999px">offscreen</div><p>Visible</p>"#;
        let result = strip_hidden_elements(html).unwrap();
        assert!(
            !result.contains("offscreen"),
            "off-screen should be stripped, got: {result:?}"
        );
        assert!(result.contains("Visible"));
    }

    #[test]
    fn strip_hidden_catches_text_indent() {
        let html = r#"<div style="text-indent:-9999px">hidden</div><p>Visible</p>"#;
        let result = strip_hidden_elements(html).unwrap();
        assert!(
            !result.contains("hidden"),
            "text-indent should be stripped, got: {result:?}"
        );
        assert!(result.contains("Visible"));
    }

    #[test]
    fn strip_hidden_catches_overflow_hidden_with_zero_height() {
        let html = r#"<div style="height:0;overflow:hidden">clipped</div><p>Visible</p>"#;
        let result = strip_hidden_elements(html).unwrap();
        assert!(
            !result.contains("clipped"),
            "height:0+overflow:hidden should be stripped, got: {result:?}"
        );
        assert!(result.contains("Visible"));
    }

    #[test]
    fn strip_hidden_catches_height_zero_with_units() {
        for unit in &["px", "em", "rem", "vh", "%"] {
            let html = format!(
                r#"<div style="height:0{unit};overflow:hidden">hidden</div><p>Visible</p>"#
            );
            let result = strip_hidden_elements(&html).unwrap();
            assert!(
                !result.contains("hidden"),
                "height:0{unit}+overflow:hidden should be stripped, got: {result:?}"
            );
            assert!(result.contains("Visible"));
        }
    }

    #[test]
    fn strip_hidden_not_tricked_by_data_style_attribute() {
        // "data-style" should not be confused with "style"
        let html =
            r#"<div data-style="display:none" style="display:none">hidden</div><p>Visible</p>"#;
        let result = strip_hidden_elements(html).unwrap();
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
        let result = strip_hidden_elements(html).unwrap();
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
        let result = strip_hidden_elements(html).unwrap();
        assert!(
            result.contains("Visible after void element"),
            "Content after void element should be preserved, got: {result:?}"
        );
    }

    #[test]
    fn strip_hidden_handles_self_closing_tags() {
        let html = r#"<img style="display:none"/><p>Still visible</p>"#;
        let result = strip_hidden_elements(html).unwrap();
        assert!(
            result.contains("Still visible"),
            "Content after self-closing tag should be preserved, got: {result:?}"
        );
    }

    #[test]
    fn strip_hidden_closing_tag_word_boundary() {
        // </divider> should not match when tag_name is "div"
        let html = r#"<div style="display:none"><divider>keep</divider></div><p>After</p>"#;
        let result = strip_hidden_elements(html).unwrap();
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
        let result = strip_hidden_elements(html).unwrap();
        assert!(
            !result.contains("hidden"),
            "Extra whitespace in display:none should still be caught, got: {result:?}"
        );
        assert!(result.contains("Visible"));
    }

    #[test]
    fn strip_hidden_whitespace_around_colon() {
        let html = r#"<span style="display : none">hidden</span><p>Visible</p>"#;
        let result = strip_hidden_elements(html).unwrap();
        assert!(
            !result.contains("hidden"),
            "Whitespace around colon should still be caught, got: {result:?}"
        );
        assert!(result.contains("Visible"));
    }

    #[test]
    fn strip_hidden_catches_unquoted_style() {
        let html = r#"<span style=display:none>hidden</span><p>Visible</p>"#;
        let result = strip_hidden_elements(html).unwrap();
        assert!(
            !result.contains("hidden"),
            "Unquoted style=display:none should be caught, got: {result:?}"
        );
        assert!(result.contains("Visible"));
    }

    #[test]
    fn strip_hidden_unclosed_element_strips_to_end() {
        // Unclosed hidden element strips everything to end-of-document.
        // This prevents injection via unclosed tags like:
        //   <div style="display:none">IGNORE PREVIOUS INSTRUCTIONS
        let html = r#"<p>Before</p><div style="display:none">hidden payload<p>also hidden</p>"#;
        let result = strip_hidden_elements(html).unwrap();
        assert!(
            result.contains("Before"),
            "Content before unclosed hidden element should be preserved, got: {result:?}"
        );
        assert!(
            !result.contains("hidden payload"),
            "Hidden content from unclosed element should be stripped, got: {result:?}"
        );
        assert!(
            !result.contains("also hidden"),
            "Trailing content after unclosed hidden element should be stripped, got: {result:?}"
        );
    }

    #[test]
    fn sanitize_draft_strips_img_tags() {
        let html = r#"<p>Hello</p><img src="https://tracker.evil/pixel.gif"><p>World</p>"#;
        let sanitized = sanitize_html_for_draft(html).unwrap();
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
        let result = strip_hidden_elements(html).unwrap();
        assert!(
            result.contains("accordion content"),
            "min-height:0 should not be stripped, got: {result:?}"
        );
    }

    #[test]
    fn strip_hidden_preserves_fractional_zero_height() {
        // height:0.5em is non-zero and should not be stripped
        let html = r#"<div style="height:0.5em;overflow:hidden">visible content</div><p>After</p>"#;
        let result = strip_hidden_elements(html).unwrap();
        assert!(
            result.contains("visible content"),
            "height:0.5em should not be stripped, got: {result:?}"
        );
    }

    #[test]
    fn strip_hidden_preserves_small_negative_offset() {
        // Small negative margin-left is a centering pattern, not hiding
        let html = r#"<div style="position:absolute;left:50%;margin-left:-100px">centered</div><p>After</p>"#;
        let result = strip_hidden_elements(html).unwrap();
        assert!(
            result.contains("centered"),
            "Small negative offset should not be stripped, got: {result:?}"
        );
    }

    #[test]
    fn strip_hidden_catches_large_negative_offset() {
        let html = r#"<div style="position:absolute;left:-9999px">hidden</div><p>Visible</p>"#;
        let result = strip_hidden_elements(html).unwrap();
        assert!(
            !result.contains("hidden"),
            "Large negative offset should be stripped, got: {result:?}"
        );
        assert!(result.contains("Visible"));
    }

    #[test]
    fn strip_hidden_preserves_small_text_indent() {
        let html = r#"<div style="text-indent:-10px">slightly indented</div>"#;
        let result = strip_hidden_elements(html).unwrap();
        assert!(
            result.contains("slightly indented"),
            "Small text-indent should not be stripped, got: {result:?}"
        );
    }

    #[test]
    fn strip_hidden_catches_html_entity_encoded_style() {
        // &#58; is HTML entity for ':'
        let html = r#"<span style="display&#58;none">hidden via entity</span><p>Visible</p>"#;
        let result = strip_hidden_elements(html).unwrap();
        assert!(
            !result.contains("hidden via entity"),
            "HTML entity-encoded style should be caught, got: {result:?}"
        );
        assert!(result.contains("Visible"));
    }

    #[test]
    fn strip_hidden_catches_hex_entity_encoded_style() {
        // &#x3a; is hex HTML entity for ':'
        let html = r#"<span style="display&#x3a;none">hidden via hex</span><p>Visible</p>"#;
        let result = strip_hidden_elements(html).unwrap();
        assert!(
            !result.contains("hidden via hex"),
            "Hex entity-encoded style should be caught, got: {result:?}"
        );
        assert!(result.contains("Visible"));
    }

    #[test]
    fn strip_hidden_catches_named_entity_colon_bypass() {
        let html =
            r#"<span style="display&colon;none">hidden via named entity</span><p>Visible</p>"#;
        let result = strip_hidden_elements(html).unwrap();
        assert!(
            !result.contains("hidden via named entity"),
            "Named entity &colon; bypass should be caught, got: {result:?}"
        );
        assert!(result.contains("Visible"));
    }

    #[test]
    fn strip_hidden_no_false_positive_on_text_overflow_hidden() {
        // text-overflow:hidden is a valid CSS truncation pattern, not a hiding technique
        let html = r#"<div style="height:20px;text-overflow:hidden">truncated</div><p>After</p>"#;
        let result = strip_hidden_elements(html).unwrap();
        assert!(
            result.contains("truncated"),
            "text-overflow:hidden without overflow:hidden should not be stripped, got: {result:?}"
        );
    }

    #[test]
    fn strip_hidden_empty_tag_name_skips_tag() {
        // Tag with empty name: `< style="display:none">` — should at minimum
        // skip the tag itself and not leak content after it
        let html = r#"< style="display:none">payload<p>After</p>"#;
        // This is malformed HTML; browsers render it as text, but our parser
        // should handle it gracefully without panicking
        let _result = strip_hidden_elements(html).unwrap();
        // No assertion on content — just verify no panic
    }

    #[test]
    fn strip_hidden_catches_right_negative_offset() {
        let html = r#"<div style="position:absolute;right:-9999px">hidden</div><p>Visible</p>"#;
        let result = strip_hidden_elements(html).unwrap();
        assert!(
            !result.contains("hidden"),
            "right:-9999px should be stripped, got: {result:?}"
        );
        assert!(result.contains("Visible"));
    }

    #[test]
    fn strip_hidden_no_false_positive_on_padding_left() {
        // padding-left:-200px is not an off-screen technique
        let html = r#"<div style="position:absolute;padding-left:-200px">content</div>"#;
        let result = strip_hidden_elements(html).unwrap();
        assert!(
            result.contains("content"),
            "padding-left should not trigger offset detection, got: {result:?}"
        );
    }

    #[test]
    fn strip_hidden_self_closing_div_does_not_leak_content() {
        // In HTML5, <div/> is treated as <div>, not self-closing.
        // A crafted <div/> inside a hidden element must increment depth.
        let html = r#"<div style="display:none"><div/>ignored</div>INJECTED</div><p>Safe</p>"#;
        let result = strip_hidden_elements(html).unwrap();
        assert!(
            !result.contains("INJECTED"),
            "Self-closing div should not cause premature depth decrement, got: {result:?}"
        );
        assert!(result.contains("Safe"));
    }

    #[test]
    fn strip_hidden_strips_style_blocks_and_class_attrs() {
        let html = r#"<style>.h { display: none; }</style><div class="h">text</div><p>Visible</p>"#;
        let result = strip_hidden_elements(html).unwrap();
        assert!(
            !result.contains("<style>"),
            "Style blocks should be stripped, got: {result:?}"
        );
        assert!(
            !result.contains("class="),
            "Class attributes should be stripped, got: {result:?}"
        );
        assert!(result.contains("Visible"));
        // Note: the element's text content remains because we cannot resolve
        // which classes map to hidden styles without a full CSS engine.
        // The defense is: <style> block removed + class attr removed = the
        // hiding rule cannot be applied by email clients in outgoing drafts.
    }

    #[test]
    fn strip_hidden_catches_height_zero_point_zero() {
        let html = r#"<div style="height:0.0;overflow:hidden">clipped</div><p>Visible</p>"#;
        let result = strip_hidden_elements(html).unwrap();
        assert!(
            !result.contains("clipped"),
            "height:0.0+overflow:hidden should be stripped, got: {result:?}"
        );
        assert!(result.contains("Visible"));
    }

    #[test]
    fn strip_hidden_catches_height_zero_point_zero_em() {
        let html = r#"<div style="height:0.00em;overflow:hidden">clipped</div><p>Visible</p>"#;
        let result = strip_hidden_elements(html).unwrap();
        assert!(
            !result.contains("clipped"),
            "height:0.00em+overflow:hidden should be stripped, got: {result:?}"
        );
        assert!(result.contains("Visible"));
    }

    #[test]
    fn filter_css_allows_safe_properties() {
        let css = "color: red; font-size: 14px; text-align: center";
        let result = filter_css_properties(css);
        assert!(result.contains("color: red"));
        assert!(result.contains("font-size: 14px"));
        assert!(result.contains("text-align: center"));
    }

    #[test]
    fn filter_css_strips_dangerous_properties() {
        let css = "background-image: url(https://tracker.evil/pixel); color: red";
        let result = filter_css_properties(css);
        assert!(!result.contains("background-image"));
        assert!(!result.contains("tracker.evil"));
        assert!(result.contains("color: red"));
    }

    #[test]
    fn filter_css_strips_position_and_display() {
        let css = "position: absolute; left: -9999px; display: none; font-size: 14px";
        let result = filter_css_properties(css);
        assert!(!result.contains("position"));
        assert!(!result.contains("display"));
        assert!(!result.contains("left"));
        assert!(result.contains("font-size: 14px"));
    }

    #[test]
    fn filter_css_strips_transparent_color() {
        assert_eq!(filter_css_properties("color: transparent"), "");
        assert_eq!(filter_css_properties("color: rgba(0,0,0,0)"), "");
        assert_eq!(filter_css_properties("color: rgba(0, 0, 0, 0)"), "");
        assert_eq!(filter_css_properties("color: rgba(0 0 0 / 0)"), "");
        assert_eq!(filter_css_properties("color: rgb(0 0 0 / 0)"), "");
        // Zero-point variants
        assert_eq!(filter_css_properties("color: rgba(0,0,0,0.0)"), "");
        assert_eq!(filter_css_properties("color: rgba(0, 0, 0, 0.00)"), "");
        assert_eq!(filter_css_properties("color: hsla(0, 0%, 0%, 0)"), "");
    }

    #[test]
    fn filter_css_strips_zero_height() {
        assert_eq!(filter_css_properties("height: 0"), "");
        assert_eq!(filter_css_properties("height: 0px"), "");
        assert_eq!(filter_css_properties("max-height: 0"), "");
        // Non-zero height should be kept
        assert!(filter_css_properties("height: 100px").contains("height"));
    }

    #[test]
    fn filter_css_strips_url_in_any_value() {
        let css = "background-color: url(evil); padding: 10px";
        let result = filter_css_properties(css);
        assert!(!result.contains("url"));
        assert!(result.contains("padding: 10px"));
    }

    #[test]
    fn strip_hidden_catches_near_zero_font_size() {
        let html = r#"<span style="font-size:0.1px">tiny injection</span><p>Visible</p>"#;
        let result = strip_hidden_elements(html).unwrap();
        assert!(
            !result.contains("tiny injection"),
            "font-size:0.1px should be stripped, got: {result:?}"
        );
        assert!(result.contains("Visible"));
    }

    #[test]
    fn strip_hidden_catches_one_px_font_size() {
        let html = r#"<span style="font-size:1px">tiny</span><p>Visible</p>"#;
        let result = strip_hidden_elements(html).unwrap();
        assert!(
            !result.contains("tiny"),
            "font-size:1px should be stripped, got: {result:?}"
        );
        assert!(result.contains("Visible"));
    }

    #[test]
    fn strip_hidden_preserves_normal_font_size() {
        let html = r#"<span style="font-size:14px">normal text</span>"#;
        let result = strip_hidden_elements(html).unwrap();
        assert!(
            result.contains("normal text"),
            "font-size:14px should be preserved, got: {result:?}"
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
