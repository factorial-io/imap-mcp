# Research: Smart Attachment Handling for LLM Context

## PDF Text Extraction

**Decision**: Use `pdf-extract` crate

**Rationale**: Pure Rust, simple one-line API (`extract_text_from_mem(&bytes)`), well-maintained (~150K downloads/month, 573 GitHub stars), zero C/system dependencies. Uses `lopdf` internally.

**Alternatives considered**:
- `lopdf`: Lower-level PDF manipulation library — would require writing custom text extraction logic on top. `pdf-extract` already does this.
- `pdf_oxide`: Newer, faster, but only ~2.9K downloads/month. Too young for production use.
- `extractous`: Wraps Apache Tika via JNI. Requires GraalVM. Heavyweight, rejected.
- `pdftotext`: Binds to Poppler (C library). Not pure Rust, rejected.

## DOCX Text Extraction

**Decision**: DIY with `zip` + `quick-xml` (~40 lines of code)

**Rationale**: DOCX is ZIP containing XML. Open archive, read `word/document.xml`, extract text from `<w:t>` elements. Both `zip` and `quick-xml` are already transitive dependencies of `calamine`, so this adds zero new dependencies. Most reliable and lightest approach.

**Alternatives considered**:
- `dotext`: Unmaintained since 2017, uses obsolete dependency versions. Rejected.
- `undoc`: Only ~33 downloads/month, too new. Worth watching but not production-ready.
- `docx-rs`/`docx-rust`: Focused on creating/writing DOCX, not reading/extraction.
- `docx-parser`: Adds unnecessary weight, uses `docx-rust` internally.

## XLSX Text Extraction

**Decision**: Use `calamine` crate

**Rationale**: Dominant Rust crate for spreadsheet reading (~735K downloads/month). Pure Rust, supports xlsx/xlsm/xlsb/xls/ods. Lightweight dependencies (`quick-xml`, `zip`, `encoding_rs`). Simple API with worksheet iteration.

**Alternatives considered**:
- `rust-excel-core`: Wrapper combining calamine + rust_xlsxwriter. Unnecessary overhead for read-only use.
- No other serious contenders exist in the Rust ecosystem.

## PPTX Text Extraction

**Decision**: DIY with `zip` + `quick-xml` (~50 lines of code)

**Rationale**: PPTX is ZIP containing XML. Slides in `ppt/slide1.xml`, `ppt/slide2.xml`, etc. Text in `<a:t>` elements. Same approach as DOCX, same dependencies (already present via calamine).

**Alternatives considered**:
- `pptx-to-md`: Adds `image` and `rayon` dependencies. Overkill for plain text extraction.
- `msoffice_pptx`: Low-level deserializer, not text extraction focused.

## Dependency Impact Summary

| New Dependency | Purpose | Transitive via calamine? |
|----------------|---------|--------------------------|
| `pdf-extract`  | PDF text extraction | No (new) |
| `calamine`     | XLSX reading | No (new) |
| `zip`          | DOCX/PPTX archive reading | Yes (via calamine) |
| `quick-xml`    | DOCX/PPTX XML parsing | Yes (via calamine) |

**Net new crate additions**: `pdf-extract` and `calamine`. The `zip` and `quick-xml` crates come for free as transitive dependencies of `calamine`.
