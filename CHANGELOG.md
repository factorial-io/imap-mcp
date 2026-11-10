# Changelog

All notable changes to this project will be documented in this file.

## [0.1.5](https://github.com/factorial-io/imap-mcp/compare/imap-mcp-v0.1.4...imap-mcp-v0.1.5) (2026-11-10)


### Features

* add move_email, delete_email and create_folder MCP tools ([#101](https://github.com/factorial-io/imap-mcp/issues/101)) ([7dd6cce](https://github.com/factorial-io/imap-mcp/commit/7dd6ccee7b56979608cecd0cc4797aeb4e08c736))

## [imap-mcp-v0.1.4] - 2026-11-10

### Features

- Make unknown attachments usable to LLMs ([3bedab6](https://github.com/factorial-io/imap-mcp/commit/3bedab6dff556ae6a4c4652a22ad4b0318eb8986))
- Default account + fourth-round PR review fixes ([4762d16](https://github.com/factorial-io/imap-mcp/commit/4762d1668f129e8028e4388263d38dd7f4dd0f20))
- Multi-account support ([498bcf6](https://github.com/factorial-io/imap-mcp/commit/498bcf611918d79739158fc58e620da841f0bd83))

### Bug Fixes

- Honour BASE_URL path prefix in HTML forms and manage cookie (#99) ([c0da4cb](https://github.com/factorial-io/imap-mcp/commit/c0da4cbd5b51b745cd870c3acc80a1e46776f141))
- *(deps)* Update rust crate pdf-extract to 0.12 ([d7c16ed](https://github.com/factorial-io/imap-mcp/commit/d7c16ed8986904c3fb69af8b40fd1e76b5c37122))
- *(deps)* Update rust crate tower-http to 0.7.0 ([0084418](https://github.com/factorial-io/imap-mcp/commit/008441899509e46597b1185eade13b6884503201))
- *(deps)* Update rust crate calamine to 0.35 ([d135ac2](https://github.com/factorial-io/imap-mcp/commit/d135ac220c8075fc3591362c94e772b8b93af44c))
- *(deps)* Update rust crate html2text to 0.17.0 ([f426438](https://github.com/factorial-io/imap-mcp/commit/f426438dca9a4104355fee93cc240f2f66b6179f))
- *(deps)* Update rust crate quick-xml to 0.40 ([1b1fdae](https://github.com/factorial-io/imap-mcp/commit/1b1fdae8a3702c1c32cd33001821672ee9995e50))
- Address second round of PR #70 review ([d243b5a](https://github.com/factorial-io/imap-mcp/commit/d243b5a828bd9477ca384964453234eaf0e51444))
- Address PR #70 review feedback ([ae04b07](https://github.com/factorial-io/imap-mcp/commit/ae04b07f46efd8320583bf74b985039c159dbc0f))
- Allowlist public host for rmcp DNS rebinding protection ([8188d58](https://github.com/factorial-io/imap-mcp/commit/8188d586e513bf49f3ea458d040d4fa8688d41e6))
- Address fifth-round PR review feedback ([3c683e4](https://github.com/factorial-io/imap-mcp/commit/3c683e41deb265afe11baa4f2c6df613cc5aa5b5))
- Address third-round PR review feedback ([5b60803](https://github.com/factorial-io/imap-mcp/commit/5b60803674b1adc0b04b0214c09cdd8ee5d34bcc))
- Address second-round PR review feedback ([fd2ff58](https://github.com/factorial-io/imap-mcp/commit/fd2ff58f11c874abc7be6706c3288d0dd6655092))
- Address PR review feedback ([1019f91](https://github.com/factorial-io/imap-mcp/commit/1019f916884cdae38ade5c3c16642047c3d81e78))

### Refactor

- Restrict html_to_safe_text visibility to pub(crate) ([53d0355](https://github.com/factorial-io/imap-mcp/commit/53d0355e42ce180152f8fabe2e1db5f48e8c51a0))
- Extract HTML sanitization from imap.rs ([ac51a66](https://github.com/factorial-io/imap-mcp/commit/ac51a6669e8161ad6984b96adf71c57338bb0035))

### Documentation

- Resolve five open questions on multi-account plan ([49b26c1](https://github.com/factorial-io/imap-mcp/commit/49b26c1dcd45cee3ed64df7380423e79ec36b030))
- Lock in product decisions on multi-account plan ([ea88d98](https://github.com/factorial-io/imap-mcp/commit/ea88d9814a44f1b8d905d7c4b1cf6f0d458e724e))
- Revise multi-account plan for Team-plan connector constraint ([ae84906](https://github.com/factorial-io/imap-mcp/commit/ae849065573ae53c64cee840e5ff321561d2e3bc))
- Add multi-account support plan ([7131192](https://github.com/factorial-io/imap-mcp/commit/713119261970b3ba814f09480cbbbb2d0f5545d2))

### Dependencies

- *(deps)* Update rust dependencies auto-merge (patch) ([86a5ba0](https://github.com/factorial-io/imap-mcp/commit/86a5ba081cca5ecb328f3df287d1bcd66adebb23))
- *(deps)* Update rust crate http to v1.5.0 ([dcd2a3b](https://github.com/factorial-io/imap-mcp/commit/dcd2a3b47b78b254403786e24660e02f6bec2501))
- *(deps)* Update rust crate tokio to v1.54.1 ([5ec40f1](https://github.com/factorial-io/imap-mcp/commit/5ec40f14c83b7742e5933daafa35a111d2ca48d7))
- *(deps)* Update rust crate rmcp to v1.8.0 ([487b087](https://github.com/factorial-io/imap-mcp/commit/487b08773885d802aa846a8dd8c907843c40f6e7))
- *(deps)* Update actions/checkout action to v7 ([fa66d52](https://github.com/factorial-io/imap-mcp/commit/fa66d52357282566bde754c308e9942bb42abe53))
- *(deps)* Update rust crate redis to v1.8.1 ([22be4f4](https://github.com/factorial-io/imap-mcp/commit/22be4f46cd0a77b8acbe4128dc24d39eb39d8f94))
- *(deps)* Update rust crate ammonia to v4.2.4 ([2717dc4](https://github.com/factorial-io/imap-mcp/commit/2717dc4d11958409bfb10587a8f4bdee360bd7b7))
- *(deps)* Update rust dependencies auto-merge (patch) (#93) ([fd7e351](https://github.com/factorial-io/imap-mcp/commit/fd7e351fd482b0fc6014919dba6e781453265802))
- *(deps)* Update rust dependencies auto-merge (patch) (#91) ([e2a50af](https://github.com/factorial-io/imap-mcp/commit/e2a50af56f0254dbd46b3ad80a164f075f972978))
- *(deps)* Update rust crate anyhow to v1.0.103 (#86) ([ecc63a9](https://github.com/factorial-io/imap-mcp/commit/ecc63a9818f2e74e1f11f05a079e917e2c12440a))
- *(deps)* Update rust dependencies auto-merge (patch) (#85) ([b1b731c](https://github.com/factorial-io/imap-mcp/commit/b1b731c713b6b4ff7023543ef8a7e022ce90e55a))
- *(deps)* Update rust dependencies auto-merge (patch) to v1.2.4 (#83) ([cdb663f](https://github.com/factorial-io/imap-mcp/commit/cdb663fe11ea152bb81e35a8e469349d415162fb))
- *(deps)* Update rust dependencies auto-merge (patch) to v1.2.3 (#80) ([f947cdc](https://github.com/factorial-io/imap-mcp/commit/f947cdc5348a0c1c1f1dc2ae4143dc4476916881))
- *(deps)* Update rust dependencies auto-merge (patch) to v1.23.3 (#79) ([0e0b82b](https://github.com/factorial-io/imap-mcp/commit/0e0b82b230dd6ccc29d19bda5d5e5bf43e8194cc))
- *(deps)* Update rust dependencies auto-merge (patch) to v1.4.2 (#78) ([3334d90](https://github.com/factorial-io/imap-mcp/commit/3334d90cd47e7cb3b238a90f10d2ce0c738bf614))
- *(deps)* Update rust dependencies auto-merge (patch) to v0.4.45 (#77) ([49ef06a](https://github.com/factorial-io/imap-mcp/commit/49ef06a8144cac2a4b40bc32aafca1448f6eed77))
- *(deps)* Update rust dependencies auto-merge (patch) (#75) ([0559cc2](https://github.com/factorial-io/imap-mcp/commit/0559cc28c61067ce55cb4fb7d0b1d44fbd42479a))
- *(deps)* Update rust crate http to v1.4.1 (#74) ([ce0b9f3](https://github.com/factorial-io/imap-mcp/commit/ce0b9f349f4c0d37315b473d0f673f7b41ad10f8))
- *(deps)* Update rust crate serde_json to v1.0.150 (#73) ([16b20ca](https://github.com/factorial-io/imap-mcp/commit/16b20ca3759b50c9f2ada9f1e65e725b9f782cee))
- *(deps)* Update rust crate tower-http to v0.6.11 (#72) ([69a51cd](https://github.com/factorial-io/imap-mcp/commit/69a51cdf20543ded802fa52a5125f4b34fd5c24e))
- *(deps)* Update rust crate quick-xml to v0.40.1 (#71) ([130b062](https://github.com/factorial-io/imap-mcp/commit/130b0628bc01727556c593d5159275c445d93106))
- *(deps)* Update rust crate rmcp to v1.7.0 ([f50bb2e](https://github.com/factorial-io/imap-mcp/commit/f50bb2e2ea67c478a2e1daa7e52d8e481fa79329))
- *(deps)* Update rust crate lol_html to v2.9.0 ([4413df2](https://github.com/factorial-io/imap-mcp/commit/4413df22e1ba0ec314deffd8b1a8d3534653a65d))
- *(deps)* Update rust crate quick-xml to v0.39.4 (#66) ([03ed514](https://github.com/factorial-io/imap-mcp/commit/03ed51495e13a2d5021c9f014f00da57d8a1650e))
- *(deps)* Update rust crate tokio to v1.52.3 (#65) ([4f85db2](https://github.com/factorial-io/imap-mcp/commit/4f85db2667bb9fd989f771c79e76ebaf18ee05e6))
- *(deps)* Update rust crate tower-http to v0.6.10 (#64) ([16b7640](https://github.com/factorial-io/imap-mcp/commit/16b7640e45ea2320bb231bfa41719b523959ed4a))
- *(deps)* Update rust crate tower-http to v0.6.9 (#62) ([6979a74](https://github.com/factorial-io/imap-mcp/commit/6979a74a4a36110aa715921e0f28249ca10e4b78))
- *(deps)* Update rust dependencies auto-merge (patch) (#61) ([348d34c](https://github.com/factorial-io/imap-mcp/commit/348d34ccb9803dc5f45b048798fe5c8c315f4f94))

### Miscellaneous

- *(main)* Release imap-mcp 0.1.4 (#58) ([aeb3687](https://github.com/factorial-io/imap-mcp/commit/aeb368780765f6d4d408696a122209dd2f51486d))

### Merge

- Main into multi-account-support-plan ([cd706ba](https://github.com/factorial-io/imap-mcp/commit/cd706baeb066e7d65f6fe873d275cf9ef2f05d68))
## [imap-mcp-v0.1.3] - 2026-05-03

### Features

- Extract text from legacy .doc attachments via antiword ([65251e8](https://github.com/factorial-io/imap-mcp/commit/65251e89329a7a85bc8971fe3f29c12ab5f6d3b5))
- Add HTML email support for drafts and reading ([1e5cd1d](https://github.com/factorial-io/imap-mcp/commit/1e5cd1de569592eeafae6405ef2a71c8ee3ec5af))

### Bug Fixes

- Adapt to rmcp 1.6.0 API changes ([5806362](https://github.com/factorial-io/imap-mcp/commit/5806362e4c01a5e8ef8539c36351cb578dfc5dbf))
- *(docker)* Pin builder to rust:bookworm to match runtime glibc ([fc60a0c](https://github.com/factorial-io/imap-mcp/commit/fc60a0c09d5aaa5cd78ab2db0f025ac3fa058975))
- ID selector hiding bypass, named whitespace entity bypass ([324da2d](https://github.com/factorial-io/imap-mcp/commit/324da2d00b788c2fb723f56af88202b0f73fade9))
- Brace-less at-rules absorbing adjacent class selectors ([7e5885b](https://github.com/factorial-io/imap-mcp/commit/7e5885b41ba2f7935c5776fb7a91d9ec35ec34f7))
- Restore full hiding detection in is_style_hidden, bump em/rem threshold ([29ecd9a](https://github.com/factorial-io/imap-mcp/commit/29ecd9add35d0dff3d452af0ae3bf6353902b66e))
- Accurate docstring, tag names in class set from compound selectors ([3890a04](https://github.com/factorial-io/imap-mcp/commit/3890a04396c351cbedbf300f41475745f10f663b))
- Preserve non-hidden styles in draft path, make filter_css_properties reachable ([de05503](https://github.com/factorial-io/imap-mcp/commit/de0550334c6a384025b7c4912a31f16238351ecd))
- Propagate extract_hidden_classes error, unify hiding detection ([54a02ff](https://github.com/factorial-io/imap-mcp/commit/54a02ff5ac28b36e154472ced82bc7ed6fcf502b))
- Precise transform checks, lol_html style extraction, matrix/scale false positives ([a721e45](https://github.com/factorial-io/imap-mcp/commit/a721e4517e1ff9f104c3fc3482e4a8d5b9bed8b6))
- @media brace nesting, relative unit thresholds ([6c4b7e6](https://github.com/factorial-io/imap-mcp/commit/6c4b7e6e243454a61bd4e56c2611e0665b7f95f8))
- Decode CSS escapes and strip comments in style block class detection ([6035e76](https://github.com/factorial-io/imap-mcp/commit/6035e76f8d27139f8d7c17afde9a3a3fc2fb7cab))
- Unicode byte-offset mismatch in extract_hidden_classes ([6db08ee](https://github.com/factorial-io/imap-mcp/commit/6db08ee9d6cac4880434953a111b3642b61fb5e6))
- Remove dead CSS parser loop, fix descendant selector false positives ([83da627](https://github.com/factorial-io/imap-mcp/commit/83da6274aefa39bb911065de9d580ba19a242c52))
- Detect and strip class-based CSS hiding in incoming emails ([983148f](https://github.com/factorial-io/imap-mcp/commit/983148f3a290204160c66ce8239e540505e3a7f6))
- Near-transparent alpha threshold, transform:matrix translation bypass ([b601905](https://github.com/factorial-io/imap-mcp/commit/b60190533a3ec104551da5660608dde10e4a0575))
- Duplicate doc comment, CSS-aware declaration splitting ([b3eeeec](https://github.com/factorial-io/imap-mcp/commit/b3eeeec51b2f10b8bd49b223acab13a44b159b38))
- Scale/matrix transforms, near-zero opacity, duplicate doc comment ([ac316b9](https://github.com/factorial-io/imap-mcp/commit/ac316b94155f252d1701c5bec11638645b3a9923))
- Get_email degrades gracefully on HTML sanitization failure ([cdda075](https://github.com/factorial-io/imap-mcp/commit/cdda075e5641c0fc45c76739adce51d557fd59cd))
- Propagate errors from html_to_safe_text and extract_body_from_parsed ([2bc792e](https://github.com/factorial-io/imap-mcp/commit/2bc792ebdccd0e12582bc5593966de46aebec676))
- CSS comment bypass in filter_css_properties, fractional px threshold bypass ([ea2e9ad](https://github.com/factorial-io/imap-mcp/commit/ea2e9ad35a76eabc3be5e698bc5244215a2c8e2a))
- Boundary-aware color check, clip-path last-wins, hex color detection ([c9ee13b](https://github.com/factorial-io/imap-mcp/commit/c9ee13b8b05b5ba8756e1d708cbf36c15788f245))
- Detect transform:translate and transparent color in reading path ([33c1cf2](https://github.com/factorial-io/imap-mcp/commit/33c1cf2f9a6b8abdc95aa04a321416ce6c11248d))
- Clip-path dual-declaration bypass, margin-left/top backstop ([03c28e2](https://github.com/factorial-io/imap-mcp/commit/03c28e256facad3045ee26b0e178c454b9b66c7e))
- Clip-path:none false positive, drop background-color from allowlist ([d175f2a](https://github.com/factorial-io/imap-mcp/commit/d175f2ae396da0eafebc445b91be98db710e0789))
- CSS escape in filter values, parse_px_digits edge cases, clip-path boundaries ([bb8e713](https://github.com/factorial-io/imap-mcp/commit/bb8e713c9e96adbecf3520c10b9092a853f15157))
- Return u32::MAX on overflow in parse_px_digits ([c1ca56d](https://github.com/factorial-io/imap-mcp/commit/c1ca56dea8b7a8917ffee8781dfc15d9453325bb))
- Require overflow:hidden for height stripping, decode CSS backslash escapes ([bc31aae](https://github.com/factorial-io/imap-mcp/commit/bc31aae3a99071ae9e5130bebf53763210b08368))
- Width:0 hiding, clip-path bypass, percentage alpha notation ([e5a2540](https://github.com/factorial-io/imap-mcp/commit/e5a2540bae1839fce1a72b71610b60e5ae3cce60))
- CSS comment bypass, unit-aware thresholds for non-px values ([9c62e57](https://github.com/factorial-io/imap-mcp/commit/9c62e57f33be3433a70c9ebfe36c9e74fd02249b))
- Inclusive threshold comparisons, font-size guard in filter_css_properties ([d7ef839](https://github.com/factorial-io/imap-mcp/commit/d7ef8398514ffc6c46edb4adf8c99bb58e2cd9b5))
- Remove color from CSS allowlist, update transparent checks ([a45cd13](https://github.com/factorial-io/imap-mcp/commit/a45cd13713e82c39984862c882c742632197666a))
- Hex alpha colors, sub-pixel height threshold ([b563ea6](https://github.com/factorial-io/imap-mcp/commit/b563ea67813db5b726da270522059b6d0abfa050))
- Parse alpha numerically, guard zero-height, placeholder on failure ([5d0c054](https://github.com/factorial-io/imap-mcp/commit/5d0c05477774b83a6d13322845f7035dbc6508e7))
- Transparent color whitespace variants, near-zero font-size threshold ([25d178a](https://github.com/factorial-io/imap-mcp/commit/25d178a2879c948a009625ee38bf70e9642d0454))
- CSS property allowlist for drafts, return empty on parse failure ([de19c34](https://github.com/factorial-io/imap-mcp/commit/de19c34f8b54af0c8325d9a111a076c75571baaf))
- Strip class attrs to block CSS hiding, split draft/reading sanitizers ([74b3dcd](https://github.com/factorial-io/imap-mcp/commit/74b3dcd1f89d3632dacf4a70b828ffad1099af40))
- Propagate lol_html errors, entity overflow drain, position boundary checks ([25da441](https://github.com/factorial-io/imap-mcp/commit/25da441435680882bedaa7032a19c01888ec0d79))
- Strip style blocks, decode CSS escapes, parse zero values with f64 ([4a9b163](https://github.com/factorial-io/imap-mcp/commit/4a9b16338ed813f0a40988f8f325bb4f8a96d00c))
- Self-closing non-void tags must increment depth in skip_to_closing_tag ([4961771](https://github.com/factorial-io/imap-mcp/commit/496177142cc23a45a5d8943b91112e99ad413bd4))
- Boundary checks in has_large_negative_value, UTF-8 safe css comment stripping ([8ec7a45](https://github.com/factorial-io/imap-mcp/commit/8ec7a451ae9cdadd217ba8b29995f0b51338eec4))
- CSS comment bypass, missing right/bottom offsets, property boundaries ([18b640d](https://github.com/factorial-io/imap-mcp/commit/18b640df6c5f760c5be8a4f1238f8d1cd3ebaa9e))
- Exclude fractional values from zero-property detection ([7693422](https://github.com/factorial-io/imap-mcp/commit/769342264d7803f245fb0428815723d117bc3108))
- Decode_html_entities control flow for long zero-padded entities ([312041d](https://github.com/factorial-io/imap-mcp/commit/312041dd4e9b44561da954a9814692c6899956e3))
- Decode HTML entities in style values, handle empty tag names ([c7027a6](https://github.com/factorial-io/imap-mcp/commit/c7027a6c268f3f79116def91cf218f977f153894))
- Zero-value CSS matching with units, fix doc comment ([7097bc2](https://github.com/factorial-io/imap-mcp/commit/7097bc261879d37fda03624e078072258f931492))
- Unclosed hidden elements strip to end, remove double sanitization ([33d87ea](https://github.com/factorial-io/imap-mcp/commit/33d87ea6085c84ae21961fb3defe999079097bb4))
- Property boundary matching, offset thresholds, and defense-in-depth ([31b7c83](https://github.com/factorial-io/imap-mcp/commit/31b7c83c01aae07bf097c8689d8a8baaddb92e12))
- Add url_schemes to ammonia builders so href values are preserved ([5659ce7](https://github.com/factorial-io/imap-mcp/commit/5659ce743d55202a67a57e013f7fc09bf4b6c8e6))
- Opacity:0.0 bypass, unquoted style, unclosed elements, img tracking ([b8e6730](https://github.com/factorial-io/imap-mcp/commit/b8e6730fcf6a98cdb4a1c71e93c4c202b337c4ae))
- Use ASCII case-insensitive matching in extract_style_value ([a70efb6](https://github.com/factorial-io/imap-mcp/commit/a70efb6284a149a169870d36ef54f0ceda292b62))
- Run strip_hidden_elements before ammonia in draft sanitization ([ac89dde](https://github.com/factorial-io/imap-mcp/commit/ac89dde9c7a90358447a0395db72792749b97d75))
- Targeted CSS hiding patterns instead of stripping all styled elements ([54a467b](https://github.com/factorial-io/imap-mcp/commit/54a467b27dd804aadc0c324372e308f069c81de8))
- Strip all styled elements and gate raw_html behind cfg(test) ([4ad4b18](https://github.com/factorial-io/imap-mcp/commit/4ad4b18a03ae78f69cdb27799dd9f034a38ef5ce))
- Closing tag word-boundary check and whitespace normalization bypass ([9a0cfb7](https://github.com/factorial-io/imap-mcp/commit/9a0cfb7955fe1b4a8c92f7d8ecf58b43e01fc37e))
- Precise style attribute matching and void element handling ([c1d1380](https://github.com/factorial-io/imap-mcp/commit/c1d138005f45cf6c3baced74c7cfb4bc0bd3d3a9))
- Strip hidden HTML elements before text conversion to block prompt injection ([fd3c2b3](https://github.com/factorial-io/imap-mcp/commit/fd3c2b3c442a01b99119000665c033486479109c))
- Remove html_body from get_email response, sanitize before html2text ([af7ecd6](https://github.com/factorial-io/imap-mcp/commit/af7ecd69e112c2fdd586ae7a73794caaab9c8557))
- Sanitize HTML with ammonia to prevent prompt injection and XSS ([528154a](https://github.com/factorial-io/imap-mcp/commit/528154af228ff3505d2facbece172980a301437b))
- *(deps)* Update rust crate sha2 to 0.11.0 ([4e18725](https://github.com/factorial-io/imap-mcp/commit/4e187259f6fb4e39c31ec1057078c78fca23fffb))
- Use decoded HTML body as fallback on html2text conversion failure ([0c5e601](https://github.com/factorial-io/imap-mcp/commit/0c5e601879a276e7818cfa3e6bddd576b5349db1))
- Log html2text conversion errors instead of silently suppressing them ([fedc18e](https://github.com/factorial-io/imap-mcp/commit/fedc18e6c154af93ddb379f0441415130efd4a4d))
- *(deps)* Update rust crate html2text to 0.16.0 ([caaf65e](https://github.com/factorial-io/imap-mcp/commit/caaf65e8315811470af7b96e21d34963c97135e4))

### Refactor

- Strip all style attributes instead of parsing CSS values ([e5a7a55](https://github.com/factorial-io/imap-mcp/commit/e5a7a550b73fc7097193845c90aad86fd3a8c49f))
- Replace hand-rolled HTML parser with lol_html ([051f153](https://github.com/factorial-io/imap-mcp/commit/051f1539da1687f4dc041832be3e05cdd6672e8b))

### Dependencies

- *(deps)* Update rust crate rmcp to v1.6.0 ([53ade11](https://github.com/factorial-io/imap-mcp/commit/53ade116d78f041f4a26bd7134dfb96fae80b086))
- *(deps)* Update googleapis/release-please-action action to v5 ([7cd82a0](https://github.com/factorial-io/imap-mcp/commit/7cd82a06c9fa40629dbdeaa7f1c7eee7ca6c3307))
- *(deps)* Update rust crate lol_html to v2.8.1 ([4e84ba5](https://github.com/factorial-io/imap-mcp/commit/4e84ba5e5355f0b3ff8cea291346abcbceac4163))
- *(deps)* Update rust crate tokio to v1.52.1 ([3c0518f](https://github.com/factorial-io/imap-mcp/commit/3c0518fd77b0c8decd324f49c10224a81853c384))
- *(deps)* Update rust crate redis to v1.2.1 (#55) ([3a58fd2](https://github.com/factorial-io/imap-mcp/commit/3a58fd2cde8c8d10a662b0073ef89ad1a2da8c40))
- *(deps)* Update rust crate imap-proto to v0.16.7 (#50) ([8234b20](https://github.com/factorial-io/imap-mcp/commit/8234b209b1b8b64b7c5ea313393b36bad4865f3b))
- *(deps)* Update rust crate redis to v1.2.0 ([9722aa8](https://github.com/factorial-io/imap-mcp/commit/9722aa869ad218b5ad7f589fb5acba4e51299e9c))
- *(deps)* Update rust crate uuid to v1.23.1 (#49) ([0df6ef1](https://github.com/factorial-io/imap-mcp/commit/0df6ef1daa9adf784bb8f4b037eb0da682075e06))
- *(deps)* Update rust crate axum to v0.8.9 (#48) ([4c4d545](https://github.com/factorial-io/imap-mcp/commit/4c4d545b4b0403380f264598bbdedf064c919cee))
- *(deps)* Update rust crate uuid to v1.23.0 ([3088d10](https://github.com/factorial-io/imap-mcp/commit/3088d10fc08f1a1ba9cba37a322e71be4d0d9a0c))
- *(deps)* Update amannn/action-semantic-pull-request action to v6 ([9e85555](https://github.com/factorial-io/imap-mcp/commit/9e855552452e396406eadef2188d11f3e9f9346c))

### Miscellaneous

- *(main)* Release imap-mcp 0.1.3 ([60ad3c6](https://github.com/factorial-io/imap-mcp/commit/60ad3c679989d4d07948d2b57615f8c5b55d0ad0))

### Styling

- Fix rustfmt ([7f7bbe3](https://github.com/factorial-io/imap-mcp/commit/7f7bbe3bc3fdb554558cbac4f230b7a380d759dd))
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
