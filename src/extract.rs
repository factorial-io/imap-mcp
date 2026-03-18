use std::io::Read;

use crate::imap::MAX_LLM_CONTENT_SIZE;

/// Maximum decompressed size for a single ZIP entry (50 MB).
/// Prevents zip-bomb-style DoS where a small compressed archive inflates to gigabytes.
const MAX_ZIP_ENTRY_SIZE: u64 = 50 * 1024 * 1024;

/// Maximum total decompressed size across all ZIP entries (100 MB).
/// Prevents aggregate memory exhaustion from many smaller entries.
const MAX_ZIP_TOTAL_SIZE: u64 = 100 * 1024 * 1024;

/// Typed errors for text extraction, per CLAUDE.md `thiserror` requirement.
#[derive(Debug, thiserror::Error)]
pub enum ExtractError {
    #[error("document is password-protected")]
    PasswordProtected,
    #[error("ZIP entry too large ({0} bytes, max {MAX_ZIP_ENTRY_SIZE})")]
    ZipEntryTooLarge(u64),
    #[error("total decompressed ZIP size too large ({0} bytes, max {MAX_ZIP_TOTAL_SIZE})")]
    ZipTotalTooLarge(u64),
    #[error("too many ZIP entries ({0}, max 4096)")]
    TooManyZipEntries(usize),
    #[error("no text content found")]
    NoContent,
    #[error("{0}")]
    Other(String),
}

/// Result of text extraction from a document attachment.
pub struct ExtractedText {
    /// The extracted (and possibly truncated) text.
    pub text: String,
    /// Total size of the full extracted text in bytes.
    pub total_bytes: usize,
    /// Whether the text was truncated to fit the context limit.
    pub truncated: bool,
    /// Number of bytes actually included.
    pub included_bytes: usize,
    /// Original format label (e.g., "PDF", "DOCX").
    pub source_format: String,
}

/// Map a MIME type to a short human-readable format label.
pub fn mime_to_format_label(mime: &str) -> &str {
    match mime {
        "application/pdf" => "PDF",
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document" => "DOCX",
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet" => "XLSX",
        "application/vnd.openxmlformats-officedocument.presentationml.presentation" => "PPTX",
        other => other,
    }
}

/// Attempt to extract text from a binary attachment based on its MIME type.
///
/// - `Ok(Some(text))` — extraction succeeded
/// - `Ok(None)` — format not supported for extraction
/// - `Err(message)` — extraction failed (corrupt, password-protected, etc.)
pub fn extract_text(data: &[u8], mime_type: &str) -> Result<Option<String>, ExtractError> {
    match mime_type {
        "application/pdf" => extract_pdf(data).map(Some),
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document" => {
            extract_docx(data).map(Some)
        }
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet" => {
            extract_xlsx(data).map(Some)
        }
        "application/vnd.openxmlformats-officedocument.presentationml.presentation" => {
            extract_pptx(data).map(Some)
        }
        _ => Ok(None),
    }
}

/// Truncate text to at most `max_bytes`, ensuring the cut happens at a valid
/// UTF-8 character boundary. Returns the (possibly shortened) slice and whether
/// truncation occurred.
pub fn truncate_to_limit(text: &str, max_bytes: usize) -> (&str, bool) {
    if text.len() <= max_bytes {
        return (text, false);
    }
    // Walk backwards from max_bytes to find a char boundary.
    let mut end = max_bytes;
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    (&text[..end], true)
}

/// Build an `ExtractedText` from raw extracted text, applying the 200 KB limit.
pub fn build_extracted(text: String, source_format: &str) -> ExtractedText {
    let total_bytes = text.len();
    let (slice, truncated) = truncate_to_limit(&text, MAX_LLM_CONTENT_SIZE);
    let included_bytes = slice.len();
    ExtractedText {
        text: slice.to_owned(),
        total_bytes,
        truncated,
        included_bytes,
        source_format: source_format.to_owned(),
    }
}

// ---------------------------------------------------------------------------
// Format-specific extractors
// ---------------------------------------------------------------------------

fn extract_pdf(data: &[u8]) -> Result<String, ExtractError> {
    pdf_extract::extract_text_from_mem(data).map_err(|e| {
        let msg = e.to_string();
        if msg.contains("password") || msg.contains("encrypted") {
            ExtractError::PasswordProtected
        } else {
            ExtractError::Other(format!("failed to extract text: {msg}"))
        }
    })
}

/// Read a ZIP entry into a String with a hard decompression limit.
///
/// The `file.size()` check is advisory only (the ZIP header value is attacker-controlled).
/// The actual DoS protection is `.take(MAX_ZIP_ENTRY_SIZE)` which hard-caps bytes read
/// regardless of what the header claims.
fn read_zip_entry_to_string(
    file: &mut zip::read::ZipFile<'_, impl std::io::Read>,
) -> Result<String, ExtractError> {
    let uncompressed = file.size();
    // Fast-path rejection for honestly-sized files; not a security boundary.
    if uncompressed > MAX_ZIP_ENTRY_SIZE {
        return Err(ExtractError::ZipEntryTooLarge(uncompressed));
    }
    // Use conservative initial capacity; the String will grow as needed.
    // Don't trust uncompressed size from ZIP header (attacker-controlled).
    let mut buf = String::with_capacity(65536);
    // Read one byte more than the limit so we can detect oversized entries.
    // If we read > MAX_ZIP_ENTRY_SIZE bytes, the entry is too large.
    let bytes_read = file
        .take(MAX_ZIP_ENTRY_SIZE + 1)
        .read_to_string(&mut buf)
        .map_err(|e| ExtractError::Other(format!("failed to read ZIP entry: {e}")))?;
    if bytes_read as u64 > MAX_ZIP_ENTRY_SIZE {
        return Err(ExtractError::ZipEntryTooLarge(bytes_read as u64));
    }
    Ok(buf)
}

fn extract_docx(data: &[u8]) -> Result<String, ExtractError> {
    use quick_xml::events::Event;
    use quick_xml::reader::Reader;
    let cursor = std::io::Cursor::new(data);
    let mut archive = zip::ZipArchive::new(cursor)
        .map_err(|e| ExtractError::Other(format!("invalid DOCX: {e}")))?;

    const MAX_ZIP_ENTRIES: usize = 4096;
    if archive.len() > MAX_ZIP_ENTRIES {
        return Err(ExtractError::TooManyZipEntries(archive.len()));
    }

    let xml_data = {
        let mut file = archive
            .by_name("word/document.xml")
            .map_err(|e| ExtractError::Other(format!("missing word/document.xml: {e}")))?;
        read_zip_entry_to_string(&mut file)?
    };

    let mut reader = Reader::from_str(&xml_data);
    let mut text = String::new();
    let mut in_w_t = false;
    let mut in_w_p = false;

    loop {
        match reader.read_event() {
            Ok(Event::Start(ref e)) => {
                let local = e.local_name();
                if local.as_ref() == b"p" && e.name().prefix().is_some_and(|p| p.as_ref() == b"w") {
                    in_w_p = true;
                }
                if local.as_ref() == b"t" && e.name().prefix().is_some_and(|p| p.as_ref() == b"w") {
                    in_w_t = true;
                }
            }
            Ok(Event::Empty(ref e)) => {
                // Self-closing elements like <w:p/> — handle without setting
                // in_w_t since Event::End won't fire to reset it.
                let local = e.local_name();
                if local.as_ref() == b"p"
                    && e.name().prefix().is_some_and(|p| p.as_ref() == b"w")
                    && !text.is_empty()
                    && !text.ends_with('\n')
                {
                    text.push('\n');
                }
            }
            Ok(Event::End(ref e)) => {
                let local = e.local_name();
                if local.as_ref() == b"t" && e.name().prefix().is_some_and(|p| p.as_ref() == b"w") {
                    in_w_t = false;
                }
                if local.as_ref() == b"p" && e.name().prefix().is_some_and(|p| p.as_ref() == b"w") {
                    if in_w_p && !text.is_empty() && !text.ends_with('\n') {
                        text.push('\n');
                    }
                    in_w_p = false;
                }
            }
            Ok(Event::Text(ref e)) => {
                if in_w_t {
                    if let Ok(t) = e.unescape() {
                        text.push_str(&t);
                    }
                }
                // Stop accumulating once we exceed the LLM content limit;
                // build_extracted will truncate anyway.
                if text.len() >= MAX_LLM_CONTENT_SIZE {
                    break;
                }
            }
            Ok(Event::Eof) => break,
            Err(e) => return Err(ExtractError::Other(format!("XML parse error: {e}"))),
            _ => {}
        }
    }

    if text.trim().is_empty() {
        return Err(ExtractError::NoContent);
    }

    Ok(text)
}

fn extract_xlsx(data: &[u8]) -> Result<String, ExtractError> {
    use calamine::{Reader, Xlsx};
    use std::io::Cursor;
    use std::io::Write;

    // Re-pack the ZIP through our size-limited reader before giving it to calamine.
    // calamine reads ZIP entries internally with no byte limit, so we can't rely on
    // header-based pre-scans (the size field is attacker-controlled). Instead, read
    // each entry through read_zip_entry_to_string's .take() guard and write the
    // verified contents into a new in-memory ZIP that calamine can safely consume.
    let safe_data = {
        let mut src = zip::ZipArchive::new(Cursor::new(data))
            .map_err(|e| ExtractError::Other(format!("invalid XLSX: {e}")))?;
        let mut buf = Cursor::new(Vec::new());
        {
            const MAX_ZIP_ENTRIES: usize = 4096;
            if src.len() > MAX_ZIP_ENTRIES {
                return Err(ExtractError::TooManyZipEntries(src.len()));
            }
            let mut writer = zip::ZipWriter::new(&mut buf);
            let mut total_decompressed: u64 = 0;
            for i in 0..src.len() {
                let mut entry = src
                    .by_index(i)
                    .map_err(|e| ExtractError::Other(format!("invalid XLSX entry: {e}")))?;
                let name = entry.name().to_string();
                let options = zip::write::SimpleFileOptions::default()
                    .compression_method(zip::CompressionMethod::Stored);
                // Read and validate content before starting the ZIP entry,
                // so a failed size check doesn't leave an unterminated entry.
                let mut limited = entry.by_ref().take(MAX_ZIP_ENTRY_SIZE + 1);
                let mut content = Vec::new();
                limited.read_to_end(&mut content).map_err(|e| {
                    ExtractError::Other(format!("failed to read XLSX entry '{name}': {e}"))
                })?;
                if content.len() as u64 > MAX_ZIP_ENTRY_SIZE {
                    return Err(ExtractError::ZipEntryTooLarge(content.len() as u64));
                }
                total_decompressed += content.len() as u64;
                if total_decompressed > MAX_ZIP_TOTAL_SIZE {
                    return Err(ExtractError::ZipTotalTooLarge(total_decompressed));
                }
                writer
                    .start_file(&name, options)
                    .map_err(|e| ExtractError::Other(format!("failed to write ZIP entry: {e}")))?;
                writer
                    .write_all(&content)
                    .map_err(|e| ExtractError::Other(format!("failed to write ZIP entry: {e}")))?;
            }
            writer
                .finish()
                .map_err(|e| ExtractError::Other(format!("failed to finalize ZIP: {e}")))?;
        }
        buf.into_inner()
    };
    let cursor = Cursor::new(safe_data);
    let mut workbook: Xlsx<_> =
        Xlsx::new(cursor).map_err(|e| ExtractError::Other(format!("invalid XLSX: {e}")))?;

    let sheet_names: Vec<String> = workbook.sheet_names().to_vec();
    let mut text = String::new();

    for name in &sheet_names {
        let range = workbook
            .worksheet_range(name)
            .map_err(|e| ExtractError::Other(format!("failed to read sheet '{name}': {e}")))?;
        if !text.is_empty() {
            text.push('\n');
        }
        text.push_str(&format!("--- Sheet: {name} ---\n"));
        for row in range.rows() {
            let cells: Vec<String> = row.iter().map(|c| c.to_string()).collect();
            text.push_str(&cells.join("\t"));
            text.push('\n');
        }
    }

    if text.trim().is_empty() {
        return Err(ExtractError::NoContent);
    }

    Ok(text)
}

fn extract_pptx(data: &[u8]) -> Result<String, ExtractError> {
    use quick_xml::events::Event;
    use quick_xml::reader::Reader;
    let cursor = std::io::Cursor::new(data);
    let mut archive = zip::ZipArchive::new(cursor)
        .map_err(|e| ExtractError::Other(format!("invalid PPTX: {e}")))?;

    const MAX_ZIP_ENTRIES: usize = 4096;
    if archive.len() > MAX_ZIP_ENTRIES {
        return Err(ExtractError::TooManyZipEntries(archive.len()));
    }

    // Collect slide file names and sort them.
    let mut slide_names: Vec<String> = (0..archive.len())
        .filter_map(|i| {
            let name = archive.by_index(i).ok()?.name().to_string();
            if name.starts_with("ppt/slides/slide") && name.ends_with(".xml") {
                Some(name)
            } else {
                None
            }
        })
        .collect();
    slide_names.sort_by(|a, b| {
        let num = |s: &str| -> u32 {
            s.trim_end_matches(".xml")
                .rsplit("slide")
                .next()
                .and_then(|n| n.parse().ok())
                .unwrap_or(0)
        };
        num(a).cmp(&num(b))
    });

    let mut text = String::new();
    let mut total_decompressed: u64 = 0;

    for (slide_num, slide_name) in slide_names.iter().enumerate() {
        // Stop accumulating once we've exceeded the LLM content limit;
        // build_extracted will truncate anyway, so no point reading more slides.
        if text.len() >= MAX_LLM_CONTENT_SIZE {
            break;
        }

        let xml_data = {
            let mut file = archive
                .by_name(slide_name)
                .map_err(|e| ExtractError::Other(format!("failed to read {slide_name}: {e}")))?;
            read_zip_entry_to_string(&mut file)?
        };
        total_decompressed += xml_data.len() as u64;
        if total_decompressed > MAX_ZIP_TOTAL_SIZE {
            return Err(ExtractError::ZipTotalTooLarge(total_decompressed));
        }

        if !text.is_empty() {
            text.push('\n');
        }
        text.push_str(&format!("--- Slide {} ---\n", slide_num + 1));

        let mut reader = Reader::from_str(&xml_data);
        let mut in_a_t = false;

        loop {
            match reader.read_event() {
                Ok(Event::Start(ref e)) => {
                    let local = e.local_name();
                    if local.as_ref() == b"t"
                        && e.name().prefix().is_some_and(|p| p.as_ref() == b"a")
                    {
                        in_a_t = true;
                    }
                }
                Ok(Event::End(ref e)) => {
                    let local = e.local_name();
                    if local.as_ref() == b"t"
                        && e.name().prefix().is_some_and(|p| p.as_ref() == b"a")
                    {
                        in_a_t = false;
                    }
                }
                Ok(Event::Text(ref e)) => {
                    if in_a_t {
                        if let Ok(t) = e.unescape() {
                            text.push_str(&t);
                            text.push('\n');
                        }
                    }
                }
                Ok(Event::Eof) => break,
                Err(e) => {
                    return Err(ExtractError::Other(format!(
                        "XML parse error in {slide_name}: {e}"
                    )))
                }
                _ => {}
            }
        }
    }

    if text.trim().is_empty() {
        return Err(ExtractError::NoContent);
    }

    Ok(text)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn truncate_within_limit() {
        let (result, truncated) = truncate_to_limit("hello", 10);
        assert_eq!(result, "hello");
        assert!(!truncated);
    }

    #[test]
    fn truncate_exact_boundary() {
        let (result, truncated) = truncate_to_limit("hello", 5);
        assert_eq!(result, "hello");
        assert!(!truncated);
    }

    #[test]
    fn truncate_over_limit() {
        let (result, truncated) = truncate_to_limit("hello world", 5);
        assert_eq!(result, "hello");
        assert!(truncated);
    }

    #[test]
    fn truncate_multibyte_boundary() {
        // 'ä' is 2 bytes in UTF-8. Cutting at byte 1 should back up.
        let (result, truncated) = truncate_to_limit("ä", 1);
        assert_eq!(result, "");
        assert!(truncated);
    }

    #[test]
    fn truncate_multibyte_safe() {
        // "aä" = 3 bytes ('a' = 1, 'ä' = 2). Limit 2 should include only 'a'.
        let (result, truncated) = truncate_to_limit("aä", 2);
        assert_eq!(result, "a");
        assert!(truncated);
    }

    #[test]
    fn extract_text_unsupported_format() {
        let result = extract_text(b"some data", "application/zip");
        assert!(result.unwrap().is_none());
    }

    #[test]
    fn extract_text_invalid_pdf() {
        let result = extract_text(b"not a pdf", "application/pdf");
        assert!(result.is_err());
    }

    #[test]
    fn extract_text_invalid_docx() {
        let result = extract_text(
            b"not a zip",
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        );
        assert!(result.is_err());
    }

    #[test]
    fn extract_text_invalid_xlsx() {
        let result = extract_text(
            b"not a zip",
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        );
        assert!(result.is_err());
    }

    #[test]
    fn extract_text_invalid_pptx() {
        let result = extract_text(
            b"not a zip",
            "application/vnd.openxmlformats-officedocument.presentationml.presentation",
        );
        assert!(result.is_err());
    }
}
