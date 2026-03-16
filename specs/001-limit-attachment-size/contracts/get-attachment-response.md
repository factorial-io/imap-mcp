# Contract: get_attachment MCP Tool Response

The `get_attachment` tool response format changes based on attachment type and size.

## Input (unchanged)

```json
{
  "uid": 123,
  "attachment_index": 0,
  "folder": "INBOX"
}
```

## Response Variants

### 1. Extracted Text (PDF, DOCX, XLSX, PPTX) — fits within limit

```
Text content extracted from: report.pdf (application/pdf, 245382 bytes, PDF)

[extracted text content here]
```

### 2. Extracted Text (PDF, DOCX, XLSX, PPTX) — truncated

```
Text content extracted from: report.pdf (application/pdf, 245382 bytes, PDF)
NOTE: Extracted text truncated to 200 KB (full text: 523 KB). Showing first portion only.

[first 200 KB of extracted text]
```

### 3. Extraction Failed (corrupt, password-protected, image-only PDF)

```
Attachment: report.pdf (application/pdf, 245382 bytes)
Text extraction failed: document is password-protected. Content cannot be displayed.
```

### 4. Text Attachment — fits within limit (unchanged behavior)

```
Text attachment: log.txt (text/plain, 8432 bytes)

[full text content]
```

### 5. Text Attachment — truncated

```
Text attachment: log.txt (text/plain, 524288 bytes)
NOTE: Content truncated to 200 KB (full size: 512 KB). Showing first portion only.

[first 200 KB of text]
```

### 6. Image — within limit (unchanged behavior)

Returns `Content::text` metadata + `Content::image` with base64 data.

### 7. Image — over limit

```
Image attachment: photo.jpg (image/jpeg, 8388608 bytes)
NOTE: Image too large to include (8.0 MB). Only metadata is shown.
```

### 8. Unsupported Binary

```
Binary attachment: archive.zip (application/zip, 15728640 bytes)
Text extraction is not supported for this format. Only metadata is shown.
```
