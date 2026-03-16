# Quickstart: Smart Attachment Handling

## What's Changing

The `get_attachment` MCP tool currently returns raw content for all attachments (text as-is, binary/images as base64). Large attachments fill the LLM context window, making the response unusable.

After this change:
- **PDF/Office docs**: Text is extracted and returned as readable text (truncated at 200 KB)
- **Text files**: Truncated at 200 KB if oversized
- **Images**: Metadata-only if over 200 KB
- **Other binary**: Metadata-only (no more useless base64 blobs)

## Files to Modify

1. **`Cargo.toml`** — Add `pdf-extract` and `calamine` dependencies
2. **`src/extract.rs`** (new) — Text extraction module for PDF, DOCX, XLSX, PPTX
3. **`src/mcp.rs`** — Rewrite `get_attachment` response logic to use extraction + truncation
4. **`src/imap.rs`** — Add `MAX_LLM_CONTENT_SIZE` constant (200 KB)
5. **`tests/integration.rs`** — Add tests for extraction and truncation behavior

## Key Implementation Notes

- `pdf-extract` provides `extract_text_from_mem(&[u8])` — one-line PDF text extraction
- `calamine` provides `Cursor`-based XLSX reading — no temp files needed
- DOCX/PPTX extraction is DIY: `zip` + `quick-xml` to parse XML from the archive
- `zip` and `quick-xml` are already transitive deps of `calamine` — no new dep tree
- Truncation must happen at a valid UTF-8 character boundary
- All extraction is fallible — errors return metadata-only with explanation

## Build & Test

```bash
cargo build        # verify new deps compile
cargo test         # run existing + new tests
cargo clippy       # lint check
```
