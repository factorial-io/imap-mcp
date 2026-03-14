use async_native_tls::TlsConnector;
use futures::TryStreamExt;
use serde::Serialize;

use crate::error::AppError;

/// Summary of an email for list views.
#[derive(Debug, Serialize)]
pub struct EmailSummary {
    pub uid: u32,
    pub date: Option<String>,
    pub from: Option<String>,
    pub subject: Option<String>,
    pub seen: bool,
}

/// Full email content.
#[derive(Debug, Serialize)]
pub struct EmailDetail {
    pub uid: u32,
    pub date: Option<String>,
    pub from: Option<String>,
    pub to: Option<String>,
    pub subject: Option<String>,
    pub body: String,
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
        let body = extract_body(body_raw);

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
            subject: envelope.and_then(|e| e.subject.as_ref().map(|s| decode_header_value(s))),
            body,
        })
    }

    /// Search emails using IMAP SEARCH criteria.
    pub async fn search_emails(
        &mut self,
        folder: &str,
        query: &str,
        limit: u32,
    ) -> Result<Vec<EmailSummary>, AppError> {
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

    /// Logout cleanly.
    pub async fn logout(mut self) -> Result<(), AppError> {
        self.session
            .logout()
            .await
            .map_err(|e| AppError::Imap(format!("logout failed: {e}")))?;
        Ok(())
    }
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

/// Extract plain-text body from raw email bytes.
/// Prefers text/plain; falls back to converting text/html.
pub(crate) fn extract_body(raw: &[u8]) -> String {
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
            if !nested.is_empty() {
                if plain.is_empty() {
                    plain = nested;
                }
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
}
