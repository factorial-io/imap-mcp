# Changelog

All notable changes to this project will be documented in this file.

## [0.1.3](https://github.com/factorial-io/imap-mcp/compare/imap-mcp-v0.1.2...imap-mcp-v0.1.3) (2026-05-03)


### Features

* add HTML body support for multipart/alternative emails ([f54be99](https://github.com/factorial-io/imap-mcp/commit/f54be99fca05beb197ed7c18b3d559ffa9bb22d0))
* add HTML email support for drafts and reading ([1e5cd1d](https://github.com/factorial-io/imap-mcp/commit/1e5cd1de569592eeafae6405ef2a71c8ee3ec5af))
* extract text from legacy .doc attachments via antiword ([65251e8](https://github.com/factorial-io/imap-mcp/commit/65251e89329a7a85bc8971fe3f29c12ab5f6d3b5))


### Bug Fixes

* [@media](https://github.com/media) brace nesting, relative unit thresholds ([6c4b7e6](https://github.com/factorial-io/imap-mcp/commit/6c4b7e6e243454a61bd4e56c2611e0665b7f95f8))
* accurate docstring, tag names in class set from compound selectors ([3890a04](https://github.com/factorial-io/imap-mcp/commit/3890a04396c351cbedbf300f41475745f10f663b))
* add url_schemes to ammonia builders so href values are preserved ([5659ce7](https://github.com/factorial-io/imap-mcp/commit/5659ce743d55202a67a57e013f7fc09bf4b6c8e6))
* boundary checks in has_large_negative_value, UTF-8 safe css comment stripping ([8ec7a45](https://github.com/factorial-io/imap-mcp/commit/8ec7a451ae9cdadd217ba8b29995f0b51338eec4))
* boundary-aware color check, clip-path last-wins, hex color detection ([c9ee13b](https://github.com/factorial-io/imap-mcp/commit/c9ee13b8b05b5ba8756e1d708cbf36c15788f245))
* brace-less at-rules absorbing adjacent class selectors ([7e5885b](https://github.com/factorial-io/imap-mcp/commit/7e5885b41ba2f7935c5776fb7a91d9ec35ec34f7))
* clip-path dual-declaration bypass, margin-left/top backstop ([03c28e2](https://github.com/factorial-io/imap-mcp/commit/03c28e256facad3045ee26b0e178c454b9b66c7e))
* clip-path:none false positive, drop background-color from allowlist ([d175f2a](https://github.com/factorial-io/imap-mcp/commit/d175f2ae396da0eafebc445b91be98db710e0789))
* closing tag word-boundary check and whitespace normalization bypass ([9a0cfb7](https://github.com/factorial-io/imap-mcp/commit/9a0cfb7955fe1b4a8c92f7d8ecf58b43e01fc37e))
* CSS comment bypass in filter_css_properties, fractional px threshold bypass ([ea2e9ad](https://github.com/factorial-io/imap-mcp/commit/ea2e9ad35a76eabc3be5e698bc5244215a2c8e2a))
* CSS comment bypass, missing right/bottom offsets, property boundaries ([18b640d](https://github.com/factorial-io/imap-mcp/commit/18b640df6c5f760c5be8a4f1238f8d1cd3ebaa9e))
* CSS comment bypass, unit-aware thresholds for non-px values ([9c62e57](https://github.com/factorial-io/imap-mcp/commit/9c62e57f33be3433a70c9ebfe36c9e74fd02249b))
* CSS escape in filter values, parse_px_digits edge cases, clip-path boundaries ([bb8e713](https://github.com/factorial-io/imap-mcp/commit/bb8e713c9e96adbecf3520c10b9092a853f15157))
* CSS property allowlist for drafts, return empty on parse failure ([de19c34](https://github.com/factorial-io/imap-mcp/commit/de19c34f8b54af0c8325d9a111a076c75571baaf))
* decode CSS escapes and strip comments in style block class detection ([6035e76](https://github.com/factorial-io/imap-mcp/commit/6035e76f8d27139f8d7c17afde9a3a3fc2fb7cab))
* decode HTML entities in style values, handle empty tag names ([c7027a6](https://github.com/factorial-io/imap-mcp/commit/c7027a6c268f3f79116def91cf218f977f153894))
* decode_html_entities control flow for long zero-padded entities ([312041d](https://github.com/factorial-io/imap-mcp/commit/312041dd4e9b44561da954a9814692c6899956e3))
* **deps:** update rust crate html2text to 0.16.0 ([20cc8e8](https://github.com/factorial-io/imap-mcp/commit/20cc8e828908fcaf1b42705a8b276a31c788314f))
* **deps:** update rust crate html2text to 0.16.0 ([b9f2855](https://github.com/factorial-io/imap-mcp/commit/b9f285535109aa987d92de8be8a3cd83eab1ab0e))
* **deps:** update rust crate sha2 to 0.11.0 ([40638e9](https://github.com/factorial-io/imap-mcp/commit/40638e925c025cca24636d6083a74549ac0ebfa7))
* detect and strip class-based CSS hiding in incoming emails ([983148f](https://github.com/factorial-io/imap-mcp/commit/983148f3a290204160c66ce8239e540505e3a7f6))
* detect transform:translate and transparent color in reading path ([33c1cf2](https://github.com/factorial-io/imap-mcp/commit/33c1cf2f9a6b8abdc95aa04a321416ce6c11248d))
* **docker:** pin builder to rust:bookworm to match runtime glibc ([fc60a0c](https://github.com/factorial-io/imap-mcp/commit/fc60a0c09d5aaa5cd78ab2db0f025ac3fa058975))
* duplicate doc comment, CSS-aware declaration splitting ([b3eeeec](https://github.com/factorial-io/imap-mcp/commit/b3eeeec51b2f10b8bd49b223acab13a44b159b38))
* exclude fractional values from zero-property detection ([7693422](https://github.com/factorial-io/imap-mcp/commit/769342264d7803f245fb0428815723d117bc3108))
* get_email degrades gracefully on HTML sanitization failure ([cdda075](https://github.com/factorial-io/imap-mcp/commit/cdda075e5641c0fc45c76739adce51d557fd59cd))
* hex alpha colors, sub-pixel height threshold ([b563ea6](https://github.com/factorial-io/imap-mcp/commit/b563ea67813db5b726da270522059b6d0abfa050))
* ID selector hiding bypass, named whitespace entity bypass ([324da2d](https://github.com/factorial-io/imap-mcp/commit/324da2d00b788c2fb723f56af88202b0f73fade9))
* inclusive threshold comparisons, font-size guard in filter_css_properties ([d7ef839](https://github.com/factorial-io/imap-mcp/commit/d7ef8398514ffc6c46edb4adf8c99bb58e2cd9b5))
* log html2text conversion errors instead of silently suppressing them ([fedc18e](https://github.com/factorial-io/imap-mcp/commit/fedc18e6c154af93ddb379f0441415130efd4a4d))
* near-transparent alpha threshold, transform:matrix translation bypass ([b601905](https://github.com/factorial-io/imap-mcp/commit/b60190533a3ec104551da5660608dde10e4a0575))
* opacity:0.0 bypass, unquoted style, unclosed elements, img tracking ([b8e6730](https://github.com/factorial-io/imap-mcp/commit/b8e6730fcf6a98cdb4a1c71e93c4c202b337c4ae))
* parse alpha numerically, guard zero-height, placeholder on failure ([5d0c054](https://github.com/factorial-io/imap-mcp/commit/5d0c05477774b83a6d13322845f7035dbc6508e7))
* precise style attribute matching and void element handling ([c1d1380](https://github.com/factorial-io/imap-mcp/commit/c1d138005f45cf6c3baced74c7cfb4bc0bd3d3a9))
* precise transform checks, lol_html style extraction, matrix/scale false positives ([a721e45](https://github.com/factorial-io/imap-mcp/commit/a721e4517e1ff9f104c3fc3482e4a8d5b9bed8b6))
* preserve non-hidden styles in draft path, make filter_css_properties reachable ([de05503](https://github.com/factorial-io/imap-mcp/commit/de0550334c6a384025b7c4912a31f16238351ecd))
* propagate errors from html_to_safe_text and extract_body_from_parsed ([2bc792e](https://github.com/factorial-io/imap-mcp/commit/2bc792ebdccd0e12582bc5593966de46aebec676))
* propagate extract_hidden_classes error, unify hiding detection ([54a02ff](https://github.com/factorial-io/imap-mcp/commit/54a02ff5ac28b36e154472ced82bc7ed6fcf502b))
* propagate lol_html errors, entity overflow drain, position boundary checks ([25da441](https://github.com/factorial-io/imap-mcp/commit/25da441435680882bedaa7032a19c01888ec0d79))
* property boundary matching, offset thresholds, and defense-in-depth ([31b7c83](https://github.com/factorial-io/imap-mcp/commit/31b7c83c01aae07bf097c8689d8a8baaddb92e12))
* remove color from CSS allowlist, update transparent checks ([a45cd13](https://github.com/factorial-io/imap-mcp/commit/a45cd13713e82c39984862c882c742632197666a))
* remove dead CSS parser loop, fix descendant selector false positives ([83da627](https://github.com/factorial-io/imap-mcp/commit/83da6274aefa39bb911065de9d580ba19a242c52))
* remove html_body from get_email response, sanitize before html2text ([af7ecd6](https://github.com/factorial-io/imap-mcp/commit/af7ecd69e112c2fdd586ae7a73794caaab9c8557))
* require overflow:hidden for height stripping, decode CSS backslash escapes ([bc31aae](https://github.com/factorial-io/imap-mcp/commit/bc31aae3a99071ae9e5130bebf53763210b08368))
* restore full hiding detection in is_style_hidden, bump em/rem threshold ([29ecd9a](https://github.com/factorial-io/imap-mcp/commit/29ecd9add35d0dff3d452af0ae3bf6353902b66e))
* return u32::MAX on overflow in parse_px_digits ([c1ca56d](https://github.com/factorial-io/imap-mcp/commit/c1ca56dea8b7a8917ffee8781dfc15d9453325bb))
* run strip_hidden_elements before ammonia in draft sanitization ([ac89dde](https://github.com/factorial-io/imap-mcp/commit/ac89dde9c7a90358447a0395db72792749b97d75))
* sanitize HTML with ammonia to prevent prompt injection and XSS ([528154a](https://github.com/factorial-io/imap-mcp/commit/528154af228ff3505d2facbece172980a301437b))
* scale/matrix transforms, near-zero opacity, duplicate doc comment ([ac316b9](https://github.com/factorial-io/imap-mcp/commit/ac316b94155f252d1701c5bec11638645b3a9923))
* self-closing non-void tags must increment depth in skip_to_closing_tag ([4961771](https://github.com/factorial-io/imap-mcp/commit/496177142cc23a45a5d8943b91112e99ad413bd4))
* strip all styled elements and gate raw_html behind cfg(test) ([4ad4b18](https://github.com/factorial-io/imap-mcp/commit/4ad4b18a03ae78f69cdb27799dd9f034a38ef5ce))
* strip class attrs to block CSS hiding, split draft/reading sanitizers ([74b3dcd](https://github.com/factorial-io/imap-mcp/commit/74b3dcd1f89d3632dacf4a70b828ffad1099af40))
* strip hidden HTML elements before text conversion to block prompt injection ([fd3c2b3](https://github.com/factorial-io/imap-mcp/commit/fd3c2b3c442a01b99119000665c033486479109c))
* strip style blocks, decode CSS escapes, parse zero values with f64 ([4a9b163](https://github.com/factorial-io/imap-mcp/commit/4a9b16338ed813f0a40988f8f325bb4f8a96d00c))
* targeted CSS hiding patterns instead of stripping all styled elements ([54a467b](https://github.com/factorial-io/imap-mcp/commit/54a467b27dd804aadc0c324372e308f069c81de8))
* transparent color whitespace variants, near-zero font-size threshold ([25d178a](https://github.com/factorial-io/imap-mcp/commit/25d178a2879c948a009625ee38bf70e9642d0454))
* unclosed hidden elements strip to end, remove double sanitization ([33d87ea](https://github.com/factorial-io/imap-mcp/commit/33d87ea6085c84ae21961fb3defe999079097bb4))
* Unicode byte-offset mismatch in extract_hidden_classes ([6db08ee](https://github.com/factorial-io/imap-mcp/commit/6db08ee9d6cac4880434953a111b3642b61fb5e6))
* use ASCII case-insensitive matching in extract_style_value ([a70efb6](https://github.com/factorial-io/imap-mcp/commit/a70efb6284a149a169870d36ef54f0ceda292b62))
* use decoded HTML body as fallback on html2text conversion failure ([592adc5](https://github.com/factorial-io/imap-mcp/commit/592adc518ddbed703e551d2f057b510604ed1934))
* use decoded HTML body as fallback on html2text conversion failure ([0c5e601](https://github.com/factorial-io/imap-mcp/commit/0c5e601879a276e7818cfa3e6bddd576b5349db1))
* width:0 hiding, clip-path bypass, percentage alpha notation ([e5a2540](https://github.com/factorial-io/imap-mcp/commit/e5a2540bae1839fce1a72b71610b60e5ae3cce60))
* zero-value CSS matching with units, fix doc comment ([7097bc2](https://github.com/factorial-io/imap-mcp/commit/7097bc261879d37fda03624e078072258f931492))

## [imap-mcp-v0.1.2] - 2026-03-25

### Dependencies

- *(deps)* Update rust crate redis to v1.1.0 ([33c0d35](https://github.com/factorial-io/imap-mcp/commit/33c0d35495fdfa12e0d8375b211dca61afef7202))

### Miscellaneous

- *(main)* Release imap-mcp 0.1.2 ([ccc6769](https://github.com/factorial-io/imap-mcp/commit/ccc676954938876f53a2a637fe7f02cec360180b))
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
