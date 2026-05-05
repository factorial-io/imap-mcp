# Data Model: Smart Attachment Handling

## Entities

### AttachmentInfo (existing — unchanged)

| Field     | Type            | Description                              |
|-----------|-----------------|------------------------------------------|
| index     | usize           | Zero-based index within the email        |
| filename  | Option\<String> | Filename from Content-Disposition        |
| mime_type | String          | MIME type (lowercased)                    |
| size      | usize           | Raw attachment size in bytes              |

### AttachmentData (existing — unchanged)

| Field | Type           | Description                       |
|-------|----------------|-----------------------------------|
| info  | AttachmentInfo | Metadata about the attachment     |
| data  | Vec\<u8>       | Raw decoded bytes of the attachment |

### ExtractedText (new)

Represents the result of text extraction from a document attachment.

| Field          | Type            | Description                                              |
|----------------|-----------------|----------------------------------------------------------|
| text           | String          | Extracted text content (may be truncated)                |
| total_bytes    | usize           | Total size of the full extracted text in bytes           |
| truncated      | bool            | Whether the text was truncated to fit the context limit  |
| included_bytes | usize           | Number of bytes actually included                        |
| source_format  | String          | Original format (e.g., "PDF", "DOCX", "XLSX", "PPTX")  |

## Constants

| Name                    | Value          | Description                                          |
|-------------------------|----------------|------------------------------------------------------|
| MAX_ATTACHMENT_SIZE     | 25 MB          | Existing: max bytes to fetch from IMAP               |
| MAX_LLM_CONTENT_SIZE   | 200 KB         | New: max text content returned to the LLM            |

## Content Type Classification

```
MIME type → Classification → Behavior
─────────────────────────────────────────────────────
application/pdf                    → Extractable  → extract text, truncate if > 200 KB
application/vnd.openxml...word...  → Extractable  → extract text, truncate if > 200 KB
application/vnd.openxml...sheet... → Extractable  → extract text, truncate if > 200 KB
application/vnd.openxml...pres...  → Extractable  → extract text, truncate if > 200 KB
text/*, application/json, etc.     → Text         → return as-is, truncate if > 200 KB
image/*                            → Image        → return if ≤ 200 KB, metadata if over
*                                  → Unsupported  → metadata only
```

## State Transitions

None — this feature is stateless. Each `get_attachment` call is independent.
