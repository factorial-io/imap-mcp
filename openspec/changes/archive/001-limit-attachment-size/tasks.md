# Tasks: Smart Attachment Handling for LLM Context

**Input**: Design documents from `/specs/001-limit-attachment-size/`
**Prerequisites**: plan.md (required), spec.md (required for user stories), research.md, data-model.md, contracts/

**Organization**: Tasks are grouped by user story to enable independent implementation and testing of each story.

## Format: `[ID] [P?] [Story] Description`

- **[P]**: Can run in parallel (different files, no dependencies)
- **[Story]**: Which user story this task belongs to (e.g., US1, US2, US3)
- Include exact file paths in descriptions

---

## Phase 1: Setup

**Purpose**: Add new dependencies needed for text extraction

- [x] T001 Add pdf-extract, calamine, zip, and quick-xml dependencies to Cargo.toml
- [x] T002 Add MAX_LLM_CONTENT_SIZE constant (200 * 1024) to src/imap.rs alongside existing MAX_ATTACHMENT_SIZE

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: Create the text extraction module skeleton and truncation utility that all user stories depend on

- [x] T003 Create src/extract.rs with the public extract_text(data, mime_type) dispatcher function that returns Ok(Some(text)), Ok(None), or Err(message) — stub all format-specific helpers to return Ok(None) initially
- [x] T004 Implement truncate_to_limit(text, max_bytes) utility in src/extract.rs that returns a UTF-8-safe truncated slice and a bool indicating whether truncation occurred
- [x] T005 Add mod extract to src/lib.rs or src/main.rs to register the new module
- [x] T006 Rewrite get_attachment in src/mcp.rs to use the new response pipeline: classify MIME type -> for extractable types call extract::extract_text then truncate -> for text types apply truncation -> for images check size (return metadata if > 200 KB) -> for unsupported binary return metadata only -> format responses per contracts/get-attachment-response.md

**Checkpoint**: Foundation ready. The pipeline handles all MIME type categories. Text truncation (US3), image size limits (US4), and unsupported binary metadata (US5) work immediately via the pipeline. Extraction stubs return Ok(None) so extractable types fall back to metadata-only until implemented.

---

## Phase 3: User Story 1 - PDF Text Extraction (Priority: P1) MVP

**Goal**: PDF attachments return extracted readable text instead of useless base64

**Independent Test**: Fetch a PDF attachment and verify the response contains readable text, not base64. Fetch a large PDF and verify truncation with size metadata.

### Implementation for User Story 1

- [x] T007 [US1] Implement extract_pdf(data) in src/extract.rs using pdf_extract::extract_text_from_mem, mapping errors to descriptive strings (password-protected, corrupt, no text found)
- [x] T008 [US1] Wire extract_pdf into the extract_text dispatcher for application/pdf MIME type in src/extract.rs
- [x] T009 [US1] Add unit tests for extract_pdf in src/extract.rs: successful extraction, empty PDF, invalid data returning error

**Checkpoint**: PDF attachments return extracted text. Large PDFs are truncated at 200 KB. Corrupt/image-only PDFs return metadata with error message. This is a deployable MVP.

---

## Phase 4: User Story 2 - Office Document Text Extraction (Priority: P1)

**Goal**: DOCX, XLSX, and PPTX attachments return extracted readable text instead of base64

**Independent Test**: Fetch DOCX/XLSX/PPTX attachments and verify readable text is returned.

### Implementation for User Story 2

- [x] T010 [P] [US2] Implement extract_docx(data) in src/extract.rs using zip + quick-xml to read word/document.xml and extract text from w:t elements
- [x] T011 [P] [US2] Implement extract_xlsx(data) in src/extract.rs using calamine to iterate sheets and rows, formatting cell data as readable text
- [x] T012 [P] [US2] Implement extract_pptx(data) in src/extract.rs using zip + quick-xml to read ppt/slide*.xml and extract text from a:t elements
- [x] T013 [US2] Wire extract_docx, extract_xlsx, extract_pptx into the extract_text dispatcher for their respective MIME types in src/extract.rs
- [x] T014 [P] [US2] Add unit tests for DOCX extraction in src/extract.rs: valid docx, corrupt zip, empty document
- [x] T015 [P] [US2] Add unit tests for XLSX extraction in src/extract.rs: multi-sheet workbook, empty spreadsheet
- [x] T016 [P] [US2] Add unit tests for PPTX extraction in src/extract.rs: multi-slide presentation, empty slides

**Checkpoint**: All Office document types return extracted text. Combined with US1, all P1 extractable formats are covered.

---

## Phase 5: User Stories 3+4+5 - Truncation, Images, Unsupported Binary (Priority: P1/P2/P3)

**Goal**: Verify and test the truncation, image size limit, and unsupported binary behaviors that were implemented in the foundational pipeline (T006)

**Independent Test**: These behaviors are already functional from Phase 2. This phase adds targeted tests.

### Implementation for User Stories 3, 4, 5

- [x] T017 [P] [US3] Add unit test for text truncation in src/extract.rs: verify truncate_to_limit at exact boundary, over boundary, multi-byte UTF-8 boundary safety
- [ ] T018 [P] [US3] Add integration test in tests/integration.rs for text attachment truncation: text > 200 KB returns truncated preview with size metadata, text < 200 KB returns full content
- [ ] T019 [P] [US4] Add test verifying image attachment > 200 KB returns metadata-only response in src/mcp.rs or tests/integration.rs
- [ ] T020 [P] [US5] Add test verifying unsupported binary (e.g., application/zip) returns metadata-only response in src/mcp.rs or tests/integration.rs

**Checkpoint**: All 5 user stories are implemented and tested.

---

## Phase 6: Polish & Cross-Cutting Concerns

**Purpose**: Cleanup, documentation, and validation

- [x] T021 Update the get_attachment tool description string in src/mcp.rs to reflect new behavior (text extraction, truncation, size limits)
- [x] T022 Run cargo clippy and fix any warnings in src/extract.rs and src/mcp.rs
- [x] T023 Run cargo fmt to ensure consistent formatting
- [x] T024 Run full test suite (cargo test) and verify no regressions in existing tests

---

## Dependencies & Execution Order

### Phase Dependencies

- **Setup (Phase 1)**: No dependencies — can start immediately
- **Foundational (Phase 2)**: Depends on Phase 1 (T001, T002 must complete first)
- **US1 (Phase 3)**: Depends on Phase 2 — this is the MVP
- **US2 (Phase 4)**: Depends on Phase 2 only — can run in parallel with US1
- **US3+4+5 (Phase 5)**: Depends on Phase 2 (behaviors already work, just adding tests) — can run in parallel with US1 and US2
- **Polish (Phase 6)**: Depends on all previous phases

### User Story Dependencies

- **US1 (PDF)**: Depends on foundational pipeline (Phase 2). No dependency on other stories.
- **US2 (Office)**: Depends on foundational pipeline (Phase 2). No dependency on US1.
- **US3 (Text truncation)**: Implemented in foundational pipeline. Tests can run after Phase 2.
- **US4 (Image size)**: Implemented in foundational pipeline. Tests can run after Phase 2.
- **US5 (Unsupported binary)**: Implemented in foundational pipeline. Tests can run after Phase 2.

### Parallel Opportunities

After Phase 2 completes, all of the following can run in parallel:
- T007-T009 (US1: PDF extraction)
- T010-T016 (US2: Office extraction — T010, T011, T012 are parallel within)
- T017-T020 (US3+4+5: tests — all parallel)

Within US2, the three extractors (T010 DOCX, T011 XLSX, T012 PPTX) touch different functions in the same file but are independent implementations.

---

## Parallel Example: After Phase 2

```text
# These can all run in parallel after foundational phase:
Agent 1: T007 → T008 → T009 (US1: PDF extraction)
Agent 2: T010, T011, T012 → T013 → T014, T015, T016 (US2: Office extraction)
Agent 3: T017, T018, T019, T020 (US3+4+5: tests)
```

---

## Implementation Strategy

### MVP First (User Story 1 Only)

1. Complete Phase 1: Setup (T001-T002)
2. Complete Phase 2: Foundational (T003-T006)
3. Complete Phase 3: US1 PDF Extraction (T007-T009)
4. **STOP and VALIDATE**: PDF extraction works, text truncation works, image/binary limits work
5. Deploy — this alone solves the core problem for the most common attachment type

### Incremental Delivery

1. Setup + Foundational → Pipeline ready, all non-extractable types handled
2. Add US1 (PDF) → Test → Deploy (MVP)
3. Add US2 (Office) → Test → Deploy (full extraction coverage)
4. Add US3+4+5 tests → Confidence in edge cases
5. Polish → Production-ready

---

## Notes

- [P] tasks = different files or independent functions, no dependencies
- [Story] label maps task to specific user story for traceability
- US3, US4, US5 are largely "free" from the foundational pipeline rewrite — Phase 5 is testing only
- The MVP (through Phase 3) solves the core problem for PDFs, the most common attachment type
- All extraction is fallible by design — errors always fall back to metadata-only
- Commit after each phase for clean history
