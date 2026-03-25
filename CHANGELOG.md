# Changelog

All notable changes to this project will be documented in this file.

## [0.1.2](https://github.com/factorial-io/imap-mcp/compare/imap-mcp-v0.1.1...imap-mcp-v0.1.2) (2026-03-25)


### Features

* add reply support to create_draft and update_draft ([09f172f](https://github.com/factorial-io/imap-mcp/commit/09f172f01fd803b19c19a3725665dc464ce5574a))


### Bug Fixes

* reject draft bodies with no newlines ([8dc4fc0](https://github.com/factorial-io/imap-mcp/commit/8dc4fc0c646d8bb2b6ce1db509e550f146adff5c))

## [imap-mcp-v0.1.1] - 2026-03-21

### Features

- Add automated release pipeline ([3e2cb22](https://github.com/factorial-io/imap-mcp/commit/3e2cb22333aa604e3095698983eef21f30ed986b))
- Add smart attachment handling with text extraction and context size limits ([56cd935](https://github.com/factorial-io/imap-mcp/commit/56cd935b823ab4da82ed6cedab965b9d0178aa5f))
- Add create_draft and update_draft MCP tools ([963751f](https://github.com/factorial-io/imap-mcp/commit/963751f572e7e07d883dbc6b6b5256e252cd69e7))
- Expose mail attachments via MCP tools ([5d47a9d](https://github.com/factorial-io/imap-mcp/commit/5d47a9d1394daca6aa65a44d97eb15b31ddeb811))
- Add OAuth 2.0 dynamic client registration, rmcp 1.2.0, S/MIME support, and local dev setup ([c9fe000](https://github.com/factorial-io/imap-mcp/commit/c9fe0005ffeb43bae77f058bd6571735fbf1be57))

### Bug Fixes

- *(deps)* Update rust crate schemars to v1 ([41577a1](https://github.com/factorial-io/imap-mcp/commit/41577a186acceda8de5c72a946c0c50055fbb0f5))
- Only normalize literal \n when body has no real newlines ([8598494](https://github.com/factorial-io/imap-mcp/commit/8598494a54a14d9860c6dc31f8bd9ca167d9b17b))
- Update quick-xml 0.39 API usage, replace unescape() with decode() ([a86586b](https://github.com/factorial-io/imap-mcp/commit/a86586b52a30b4cc9a28008914cbbd2f5ee31874))
- *(deps)* Update rust crate quick-xml to 0.39 ([55dbfc6](https://github.com/factorial-io/imap-mcp/commit/55dbfc674fb5555eed49932869095b095c96fd47))
- *(deps)* Update rust crate redis to v1 ([ebb4184](https://github.com/factorial-io/imap-mcp/commit/ebb41847b6401e365a4eb9813e72740132d730ba))
- *(deps)* Update rust crate mail-builder to 0.4 ([2319b3a](https://github.com/factorial-io/imap-mcp/commit/2319b3a2fe798167199c02ab4a04fc5f3d1b894a))
- *(deps)* Update rust crate redis to 0.32.0 ([f8bc669](https://github.com/factorial-io/imap-mcp/commit/f8bc6699796a5efd6e19b39e2efb28c675937291))
- *(deps)* Update rust crate async-native-tls to 0.6.0 ([6889378](https://github.com/factorial-io/imap-mcp/commit/68893789a5b91eac4d87061dd722aa52f6013ff9))
- Propagate CAPABILITY error and add PPTX aggregate decompression limit ([51c33bc](https://github.com/factorial-io/imap-mcp/commit/51c33bc3c676bdc7830786982429d29476a79b89))
- Address remaining review issues on PR 18 ([1e873a9](https://github.com/factorial-io/imap-mcp/commit/1e873a9ea5ef0ff00000348019c23f354a7403f3))
- *(deps)* Update rust crate mailparse to 0.16.0 ([6f602fc](https://github.com/factorial-io/imap-mcp/commit/6f602fccba00df56573a6fd60f34b39f0ee266af))
- *(deps)* Update rust crate async-imap to 0.11.0 ([3c2ed7e](https://github.com/factorial-io/imap-mcp/commit/3c2ed7e88d9cf65254ee298ace94b4f807c8d7c7))

### Refactor

- Use DraftContent struct to fix clippy too-many-arguments lint ([1e6a633](https://github.com/factorial-io/imap-mcp/commit/1e6a6334de547c3f5c0684798cd291265211de56))

### Documentation

- Add release automation proposal ([c73dd0a](https://github.com/factorial-io/imap-mcp/commit/c73dd0a8b26a5e82b03964ab9c0625304e3ae458))
- Add Kubernetes deployment section to README ([239960a](https://github.com/factorial-io/imap-mcp/commit/239960a7a9fc3000382a62f610ac809480f67eee))

### Dependencies

- *(deps)* Update actions/checkout action to v6 ([d9bd8c2](https://github.com/factorial-io/imap-mcp/commit/d9bd8c28dc3445154edb075c308f63b9af9316b6))
- *(deps)* Update docker/build-push-action action to v7 ([e7a304e](https://github.com/factorial-io/imap-mcp/commit/e7a304ea58c05b098777dc3b02110d0b82c6b46d))
- *(deps)* Update docker/login-action action to v4 ([da72c86](https://github.com/factorial-io/imap-mcp/commit/da72c8628579885fdac3dbc8044bf7c04e69b29d))
- *(deps)* Update docker/metadata-action action to v6 ([633e595](https://github.com/factorial-io/imap-mcp/commit/633e5956a062d0f038554f4772524d968fc162e7))
- *(deps)* Update docker/setup-buildx-action action to v4 ([fc60ff4](https://github.com/factorial-io/imap-mcp/commit/fc60ff40dffd82106036f5862b5ed588fb871b87))
- *(deps)* Update redis docker tag to v8 ([120f057](https://github.com/factorial-io/imap-mcp/commit/120f0570a8c4a5497459c135df8ccf5012325065))
- *(deps)* Update rust crate tracing-subscriber to v0.3.23 ([008f450](https://github.com/factorial-io/imap-mcp/commit/008f450543f59a1e598d24d9c6858d12206bfdd0))

### Miscellaneous

- *(main)* Release imap-mcp 0.1.1 ([e5de874](https://github.com/factorial-io/imap-mcp/commit/e5de8748b14144df811d6bcca2468f1653a2fd8f))
- Add allowed_bots configuration to code review workflow ([9692fd9](https://github.com/factorial-io/imap-mcp/commit/9692fd959e6b35e1d3b203edde19eed3c9a19ebb))
- Enhance CLAUDE code review workflow ([dc097dc](https://github.com/factorial-io/imap-mcp/commit/dc097dc8b512bdfa29268e9c15ff4e93224a6ba9))
- Change pull-requests permission from read to write ([4274594](https://github.com/factorial-io/imap-mcp/commit/4274594818950bc7c8b8a7ee847d0d9e187fc0d0))
- Update renovate.json with new package rules ([9e12f8c](https://github.com/factorial-io/imap-mcp/commit/9e12f8c6d92c7fd39ff88299717ce4b1fc8e08c3))
- Increase attachment size guard from 10MB to 25MB ([8ddbfea](https://github.com/factorial-io/imap-mcp/commit/8ddbfea50930cae48d9f5582641e32c7ae2771db))
- Rename env vars to OIDC_*, security hardening, license, and docs ([583e04e](https://github.com/factorial-io/imap-mcp/commit/583e04e1746292641f9fcf59c3ac85c2c3b287eb))
- Add GitHub Actions for CI and Docker image build with GitLab trigger ([9882388](https://github.com/factorial-io/imap-mcp/commit/9882388875786a4df6f0613a373fc57c53362b26))

### Styling

- Apply rustfmt formatting ([40f18e5](https://github.com/factorial-io/imap-mcp/commit/40f18e55493582868043255f6b46ffc2887d573b))

### Merge

- Integrate 001-limit-attachment-size into PR branch ([92b47d7](https://github.com/factorial-io/imap-mcp/commit/92b47d7bc60f22b05460225c02eba107c973caf1))
- Integrate main into 001-limit-attachment-size ([1b9861f](https://github.com/factorial-io/imap-mcp/commit/1b9861f9343fb5658741e9b83d3910ea5cab50cb))
- Integrate main into claude/merge-main-conflicts-HgwCq ([a16967e](https://github.com/factorial-io/imap-mcp/commit/a16967eb14688393beeaf88e029b88f1127ed9af))
