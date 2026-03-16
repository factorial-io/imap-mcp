# Implementation Plan: Smart Attachment Handling for LLM Context

**Branch**: `001-limit-attachment-size` | **Date**: 2026-03-15 | **Spec**: [spec.md](spec.md)
**Input**: Feature specification from `/specs/001-limit-attachment-size/spec.md`

## Summary

The `get_attachment` MCP tool currently returns raw attachment content regardless of size — base64 for binary, full text for text files. Large attachments overflow the LLM context window, making responses unusable. This plan adds server-side text extraction for PDF and Office documents (DOCX, XLSX, PPTX) using lightweight Rust crates, and enforces a hardcoded 200 KB limit on all text content returned to the LLM. Unsupported binary formats and oversized images return metadata only.

## Technical Context

**Language/Version**: Rust (edition 2021)
**Primary Dependencies**: axum 0.8, rmcp 1.2, async-imap 0.9, mailparse 0.15; new: pdf-extract, calamine, zip, quick-xml
**Storage**: Redis (sessions only — not affected by this feature)
**Testing**: cargo test (unit tests in src/, integration tests in tests/)
**Target Platform**: Linux server (Docker)
**Project Type**: Web service (MCP server)
**Performance Goals**: Text extraction should complete within a few seconds for typical email attachments (< 25 MB)
**Constraints**: 200 KB hardcoded limit on text returned to LLM; pure Rust dependencies only (no C/system deps, no OCR)
**Scale/Scope**: Single-user per session; attachment processing is per-request, no caching needed

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

Constitution is not configured for this project (template placeholders only). No gates to evaluate. Proceeding.

**Post-Phase 1 re-check**: N/A — no constitution gates defined.

## Project Structure

### Documentation (this feature)

```text
specs/001-limit-attachment-size/
├── plan.md              # This file
├── spec.md              # Feature specification
├── research.md          # Phase 0: crate research and decisions
├── data-model.md        # Phase 1: entity definitions
├── quickstart.md        # Phase 1: implementation quick reference
├── contracts/
│   └── get-attachment-response.md  # Phase 1: response format contract
├── checklists/
│   └── requirements.md  # Spec quality checklist
└── tasks.md             # Phase 2 output (created by /speckit.tasks)
```

### Source Code (repository root)

```text
src/
├── auth.rs              # OAuth/OIDC (unchanged)
├── error.rs             # Error types (unchanged)
├── extract.rs           # NEW: text extraction module (PDF, DOCX, XLSX, PPTX)
├── imap.rs              # IMAP logic (add MAX_LLM_CONTENT_SIZE constant)
├── lib.rs               # Router/AppState (unchanged)
├── main.rs              # Entry point (unchanged)
├── mcp.rs               # MCP tools (rewrite get_attachment response logic)
└── session.rs           # Session management (unchanged)

tests/
└── integration.rs       # Add extraction + truncation tests
```

**Structure Decision**: Single flat `src/` layout, matching existing project structure. New `src/extract.rs` module added for text extraction logic, keeping it separate from IMAP protocol concerns.

## Design Decisions

### 1. New module: `src/extract.rs`

Responsible for all text extraction logic. Exposes a single public function:

```rust
pub fn extract_text(data: &[u8], mime_type: &str) -> Result<Option<String>, String>
```

- Returns `Ok(Some(text))` for successful extraction
- Returns `Ok(None)` for unsupported formats (caller handles as metadata-only)
- Returns `Err(message)` for extraction failures (corrupt, password-protected, etc.)

Internal helpers:
- `extract_pdf(data: &[u8]) -> Result<String, String>` — uses `pdf_extract::extract_text_from_mem`
- `extract_docx(data: &[u8]) -> Result<String, String>` — zip + quick-xml, reads `word/document.xml`, extracts `<w:t>` text
- `extract_xlsx(data: &[u8]) -> Result<String, String>` — calamine, iterates sheets and rows
- `extract_pptx(data: &[u8]) -> Result<String, String>` — zip + quick-xml, reads `ppt/slide*.xml`, extracts `<a:t>` text

### 2. Truncation utility

```rust
pub fn truncate_to_limit(text: &str, max_bytes: usize) -> (&str, bool)
```

Returns a UTF-8-safe slice up to `max_bytes` and whether truncation occurred. Used by `mcp.rs` for all text responses.

### 3. Changes to `src/mcp.rs` get_attachment

The response logic becomes a pipeline:

1. Fetch raw attachment (existing)
2. Classify by MIME type → Extractable / Text / Image / Unsupported
3. For Extractable: call `extract::extract_text()`, then apply truncation
4. For Text: apply truncation directly
5. For Image: check size, return image content or metadata
6. For Unsupported: return metadata only

### 4. Constants

- `MAX_LLM_CONTENT_SIZE: usize = 200 * 1024` — in `src/imap.rs` alongside existing `MAX_ATTACHMENT_SIZE`

### 5. New dependencies in Cargo.toml

```toml
pdf-extract = "0.10"
calamine = "0.34"
zip = "2"
quick-xml = "0.39"
```

Note: `zip` and `quick-xml` are transitive deps of `calamine` but we declare them explicitly since `extract.rs` uses them directly for DOCX/PPTX parsing.

## Complexity Tracking

No constitution violations to justify — no complexity gates defined.
