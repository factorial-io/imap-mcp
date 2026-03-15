use crate::imap::MAX_LLM_CONTENT_SIZE;

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

/// Attempt to extract text from a binary attachment based on its MIME type.
///
/// - `Ok(Some(text))` — extraction succeeded
/// - `Ok(None)` — format not supported for extraction
/// - `Err(message)` — extraction failed (corrupt, password-protected, etc.)
pub fn extract_text(data: &[u8], mime_type: &str) -> Result<Option<String>, String> {
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

fn extract_pdf(data: &[u8]) -> Result<String, String> {
    pdf_extract::extract_text_from_mem(data).map_err(|e| {
        let msg = e.to_string();
        if msg.contains("password") || msg.contains("encrypted") {
            "document is password-protected".to_string()
        } else {
            format!("failed to extract text: {msg}")
        }
    })
}

fn extract_docx(data: &[u8]) -> Result<String, String> {
    use quick_xml::events::Event;
    use quick_xml::reader::Reader;
    use std::io::Read;

    let cursor = std::io::Cursor::new(data);
    let mut archive = zip::ZipArchive::new(cursor).map_err(|e| format!("invalid DOCX: {e}"))?;

    let mut xml_data = String::new();
    {
        let mut file = archive
            .by_name("word/document.xml")
            .map_err(|e| format!("missing word/document.xml: {e}"))?;
        file.read_to_string(&mut xml_data)
            .map_err(|e| format!("failed to read document.xml: {e}"))?;
    }

    let mut reader = Reader::from_str(&xml_data);
    let mut text = String::new();
    let mut in_w_t = false;
    let mut in_w_p = false;

    loop {
        match reader.read_event() {
            Ok(Event::Start(ref e) | Event::Empty(ref e)) => {
                let local = e.local_name();
                if local.as_ref() == b"p" && e.name().prefix().is_some_and(|p| p.as_ref() == b"w") {
                    in_w_p = true;
                }
                if local.as_ref() == b"t" && e.name().prefix().is_some_and(|p| p.as_ref() == b"w") {
                    in_w_t = true;
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
            }
            Ok(Event::Eof) => break,
            Err(e) => return Err(format!("XML parse error: {e}")),
            _ => {}
        }
    }

    if text.trim().is_empty() {
        return Err("no text content found in document".to_string());
    }

    Ok(text)
}

fn extract_xlsx(data: &[u8]) -> Result<String, String> {
    use calamine::{Reader, Xlsx};
    use std::io::Cursor;

    let cursor = Cursor::new(data);
    let mut workbook: Xlsx<_> = Xlsx::new(cursor).map_err(|e| format!("invalid XLSX: {e}"))?;

    let sheet_names: Vec<String> = workbook.sheet_names().to_vec();
    let mut text = String::new();

    for name in &sheet_names {
        if let Ok(range) = workbook.worksheet_range(name) {
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
    }

    if text.trim().is_empty() {
        return Err("no text content found in spreadsheet".to_string());
    }

    Ok(text)
}

fn extract_pptx(data: &[u8]) -> Result<String, String> {
    use quick_xml::events::Event;
    use quick_xml::reader::Reader;
    use std::io::Read;

    let cursor = std::io::Cursor::new(data);
    let mut archive = zip::ZipArchive::new(cursor).map_err(|e| format!("invalid PPTX: {e}"))?;

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
    slide_names.sort();

    let mut text = String::new();

    for (slide_num, slide_name) in slide_names.iter().enumerate() {
        let mut xml_data = String::new();
        {
            let mut file = archive
                .by_name(slide_name)
                .map_err(|e| format!("failed to read {slide_name}: {e}"))?;
            file.read_to_string(&mut xml_data)
                .map_err(|e| format!("failed to read {slide_name}: {e}"))?;
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
                Err(e) => return Err(format!("XML parse error in {slide_name}: {e}")),
                _ => {}
            }
        }
    }

    if text.trim().is_empty() {
        return Err("no text content found in presentation".to_string());
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
