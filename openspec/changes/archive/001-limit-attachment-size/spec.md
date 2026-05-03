# Feature Specification: Smart Attachment Handling for LLM Context

**Feature Branch**: `001-limit-attachment-size`
**Created**: 2026-03-15
**Status**: Draft
**Input**: User description: "the newly added find_attachment has a problem: When the attachment is too big, the context get filled and the LLM cant use the data."

## User Scenarios & Testing *(mandatory)*

### User Story 1 - PDF attachment returns extracted text (Priority: P1)

An LLM client uses `get_attachment` to fetch a PDF attached to an email. Instead of receiving a useless base64-encoded blob, the LLM receives the extracted text content from the PDF. If the extracted text exceeds 200 KB, it is truncated with metadata indicating the total and included sizes.

**Why this priority**: PDFs are among the most common email attachments. Base64-encoded PDFs are completely unreadable by LLMs. Text extraction makes them useful.

**Independent Test**: Can be tested by fetching a PDF attachment and verifying the response contains readable extracted text (not base64), with truncation metadata if the text exceeds 200 KB.

**Acceptance Scenarios**:

1. **Given** a PDF attachment, **When** the LLM calls `get_attachment`, **Then** the response contains the extracted text content of the PDF with metadata (filename, MIME type, original size, page count if available).
2. **Given** a PDF whose extracted text exceeds 200 KB, **When** the LLM calls `get_attachment`, **Then** the response contains a truncated preview of the extracted text with an indication of total size, included size, and truncation status.
3. **Given** a PDF that cannot be parsed (e.g., image-only/scanned PDF), **When** the LLM calls `get_attachment`, **Then** the response returns metadata only with a message explaining that text could not be extracted.

---

### User Story 2 - Office document attachment returns extracted text (Priority: P1)

An LLM client uses `get_attachment` to fetch a Word document (.docx), spreadsheet (.xlsx), or presentation (.pptx). The system extracts readable text content and returns it instead of raw binary data. If the extracted text exceeds 200 KB, it is truncated.

**Why this priority**: Office documents are the second most common email attachment type after PDFs. Text extraction makes their content accessible to the LLM.

**Independent Test**: Can be tested by fetching DOCX/XLSX/PPTX attachments and verifying the response contains readable extracted text.

**Acceptance Scenarios**:

1. **Given** a DOCX attachment, **When** the LLM calls `get_attachment`, **Then** the response contains the extracted text content of the document.
2. **Given** an XLSX attachment, **When** the LLM calls `get_attachment`, **Then** the response contains the extracted cell data in a readable text format.
3. **Given** a PPTX attachment, **When** the LLM calls `get_attachment`, **Then** the response contains the extracted text from all slides.
4. **Given** an Office document whose extracted text exceeds 200 KB, **When** the LLM calls `get_attachment`, **Then** the response is truncated with size metadata.

---

### User Story 3 - Large text attachment returns truncated preview (Priority: P1)

An LLM client uses `get_attachment` to fetch a large text file (e.g., a 500 KB log file or CSV). Instead of receiving the entire file contents, the LLM receives a truncated preview with metadata indicating the full size and how much was omitted.

**Why this priority**: Large plain-text attachments can fill the context window just as effectively as binary files. Truncation preserves usability.

**Independent Test**: Can be tested by fetching a text attachment larger than 200 KB and verifying the response contains a truncated preview with size metadata.

**Acceptance Scenarios**:

1. **Given** a text attachment exceeding 200 KB, **When** the LLM calls `get_attachment`, **Then** the response contains a truncated preview with a clear indication of the total size, included size, and truncation status.
2. **Given** a text attachment within 200 KB, **When** the LLM calls `get_attachment`, **Then** the full content is returned as it is today (no change in behavior).

---

### User Story 4 - Large image attachment returns metadata only (Priority: P2)

An LLM client uses `get_attachment` to fetch a large image. Instead of receiving the full base64-encoded image that consumes significant context, the LLM receives metadata with a note that it was too large to include.

**Why this priority**: Images consume context tokens. Very large images should be handled gracefully, though typical email images tend to be smaller.

**Independent Test**: Can be tested by fetching an image attachment exceeding 200 KB and verifying metadata-only response.

**Acceptance Scenarios**:

1. **Given** an image attachment exceeding 200 KB, **When** the LLM calls `get_attachment`, **Then** the response contains metadata (filename, MIME type, size) and a message that the image was too large to include.
2. **Given** an image attachment within 200 KB, **When** the LLM calls `get_attachment`, **Then** the full image content is returned as it is today.

---

### User Story 5 - Unsupported binary format returns metadata only (Priority: P3)

An LLM client uses `get_attachment` to fetch an attachment in an unsupported binary format (e.g., ZIP, EXE, proprietary format). The system returns metadata only, since no text can be extracted and base64 is useless to the LLM.

**Why this priority**: These formats cannot be made useful through text extraction. Metadata at least informs the LLM and user about what's there.

**Independent Test**: Can be tested by fetching a ZIP attachment and verifying only metadata is returned.

**Acceptance Scenarios**:

1. **Given** a binary attachment in an unsupported format, **When** the LLM calls `get_attachment`, **Then** the response contains only metadata (filename, MIME type, size) and a message indicating text extraction is not supported for this format.

---

### Edge Cases

- What happens when a PDF is password-protected? The system returns metadata only with a message that the document is protected and text could not be extracted.
- What happens when a DOCX file is corrupted or not a valid ZIP archive? The system returns metadata only with an error message.
- What happens when extracted text is empty (e.g., a spreadsheet with only charts)? The system returns metadata with a note that no text content was found.
- How does the system handle multi-byte text encodings during truncation? Truncation occurs at a valid character boundary, never mid-character.
- What happens when an attachment is exactly at the 200 KB boundary? The system includes the full content (limit is exclusive).

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: System MUST enforce a hardcoded 200 KB context-safe size limit for text content returned to the LLM.
- **FR-002**: For PDF attachments, the system MUST extract text content and return it instead of base64-encoded binary data. If the extracted text exceeds 200 KB, it MUST be truncated with size metadata.
- **FR-003**: For Office document attachments (DOCX, XLSX, PPTX), the system MUST extract text content and return it instead of base64-encoded binary data. If the extracted text exceeds 200 KB, it MUST be truncated with size metadata.
- **FR-004**: For text-based attachments exceeding 200 KB, the system MUST return a truncated preview containing the beginning of the content, along with metadata indicating total size, included size, and truncation status.
- **FR-005**: For image attachments exceeding 200 KB, the system MUST return only metadata (filename, MIME type, size) without the image data.
- **FR-006**: For binary attachments in unsupported formats (not PDF, Office, text, or image), the system MUST return only metadata (filename, MIME type, size) without any content data, regardless of size.
- **FR-007**: Attachments within the size limit that do not require text extraction (text, small images) MUST continue to be returned in full, preserving current behavior.
- **FR-008**: When text extraction fails (corrupt file, password-protected, unsupported internal format), the system MUST return metadata with a clear error message explaining why text could not be extracted.
- **FR-009**: The response for oversized or metadata-only attachments MUST clearly communicate to the LLM that the content was omitted or truncated and why.
- **FR-010**: The `get_email` tool's attachment metadata listing MUST continue to show the size of each attachment so the LLM can make informed decisions about which attachments to fetch.
- **FR-011**: Text extraction MUST use lightweight, Rust-native libraries — no external services, OCR engines, or heavy runtimes.

### Supported extraction formats

| Format               | MIME Types                                                                                          | Extraction behavior                  |
|----------------------|-----------------------------------------------------------------------------------------------------|--------------------------------------|
| PDF                  | `application/pdf`                                                                                   | Extract embedded text                |
| Word                 | `application/vnd.openxmlformats-officedocument.wordprocessingml.document`                           | Extract document text                |
| Excel                | `application/vnd.openxmlformats-officedocument.spreadsheetml.sheet`                                 | Extract cell data as readable text   |
| PowerPoint           | `application/vnd.openxmlformats-officedocument.presentationml.presentation`                         | Extract slide text                   |
| Plain text / code    | `text/*`, `application/json`, `application/xml`, `application/javascript`, `application/csv`        | Return as-is (truncate if over limit)|
| Images               | `image/*`                                                                                           | Return as image content if under limit, metadata only if over |
| Unsupported binary   | Everything else                                                                                     | Metadata only                        |

### Key Entities

- **Attachment Response**: The data returned when fetching an attachment — contains extracted/original text content (full or truncated) or metadata-only, plus size information and truncation/extraction status.
- **Text Extractor**: A component that converts supported binary document formats (PDF, DOCX, XLSX, PPTX) into readable plain text.
- **Context-Safe Size Limit**: The 200 KB threshold applied to the final text representation returned to the LLM.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: PDF and Office document attachments return readable text content that the LLM can reason about, instead of unusable base64 data.
- **SC-002**: Text responses from `get_attachment` never exceed 200 KB, regardless of the original attachment size or extracted text length.
- **SC-003**: The LLM can successfully process the response from `get_attachment` for any attachment size without context overflow.
- **SC-004**: Existing behavior for small text and image attachments (under 200 KB) remains unchanged — no regressions.
- **SC-005**: When text extraction fails, the LLM receives a clear explanation and can inform the user, rather than receiving corrupt or empty data.

## Clarifications

### Session 2026-03-15

- Q: What should the default context-safe size limit be? → A: 200 KB
- Q: Should the limit be configurable at runtime? → A: No, hardcoded at 200 KB
- Q: How to handle large binary attachments (PDFs, Office docs) that are useless as base64? → A: Server-side text extraction using lightweight Rust-native libraries. Kreuzberg was evaluated and rejected as overkill for this use case.

## Assumptions

- The context-safe size limit of 200 KB is applied to the final text output (extracted or original), not the raw attachment size.
- The existing `MAX_ATTACHMENT_SIZE` (25 MB) fetch limit remains as a separate concern — it controls what the server will download from IMAP, while the 200 KB limit controls the text returned to the LLM.
- Text extraction is best-effort: scanned/image-only PDFs cannot be processed without OCR, which is explicitly out of scope. The system gracefully falls back to metadata-only.
- Text truncation happens at a clean character boundary, never mid-character in multi-byte encodings.
- The `get_email` tool already provides attachment metadata including size, so the LLM can pre-screen attachments before fetching.
- Only modern Office formats (OOXML: .docx, .xlsx, .pptx) are supported for extraction. Legacy formats (.doc, .xls, .ppt) fall back to metadata-only.
