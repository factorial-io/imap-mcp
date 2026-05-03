use lol_html::{element, rewrite_str, RewriteStrSettings};

use crate::error::AppError;

/// Fields for composing a draft email.
pub struct DraftContent<'a> {
    pub from: &'a str,
    pub to: &'a str,
    pub subject: &'a str,
    pub body: &'a str,
    /// Optional raw HTML body. When provided, the message is sent as
    /// `multipart/alternative` with both plain-text and HTML parts.
    /// The plain-text `body` is always required as the fallback.
    ///
    /// Accepts **raw, unsanitized** HTML — [`build_rfc2822_message`] runs it
    /// through [`sanitize_html_for_draft`] before embedding in the message.
    /// Callers do not need to pre-sanitize.
    pub html_body: Option<&'a str>,
    pub cc: Option<&'a str>,
    pub bcc: Option<&'a str>,
    /// Single Message-ID of the email being replied to (sets In-Reply-To header).
    /// Must be exactly one Message-ID, not multiple.
    pub in_reply_to: Option<&'a str>,
    /// Space-separated Message-IDs for the References header (threading chain).
    pub references: Option<&'a str>,
}

/// Sanitize HTML for use in outgoing draft emails.
///
/// First removes elements hidden via CSS (prompt-injection vector), then
/// sanitizes through ammonia's allowlist. No `<img>` (tracking pixels),
/// no `<style>`/`<script>`, no event handlers.
pub fn sanitize_html_for_draft(html: &str) -> Result<String, AppError> {
    let stripped = strip_hidden_elements(html, false)?;
    Ok(ammonia_draft().clean(&stripped).to_string())
}

/// Remove elements hidden via CSS and strip `<style>`/`<script>` blocks.
///
/// **Elements removed entirely** (including text content):
/// - Inline `display:none` or `visibility:hidden/collapse`
/// - Elements with classes/IDs that map to hiding rules in `<style>` blocks
///
/// **Attributes stripped** (text content preserved):
/// - `class` attributes (after checking against hidden class set)
/// - `style` attributes on non-hidden elements (when `strip_all_styles` is true)
///
/// Other CSS hiding techniques (`opacity:0`, `font-size:0`, `height:0`, etc.)
/// are handled by `ammonia_draft`'s `filter_css_properties` on the draft path.
/// On the reading path, all styles are stripped and `ammonia_reading` handles
/// the rest — the text becomes visible to the AI regardless.
///
/// When `strip_all_styles` is true (reading path), all `style` attributes are
/// removed from non-hidden elements. When false (draft path), non-hidden styles
/// are preserved so `ammonia_draft`'s `filter_css_properties` can filter them.
fn strip_hidden_elements(html: &str, strip_all_styles: bool) -> Result<String, AppError> {
    // Two-pass approach: first extract hidden class names from <style> blocks,
    // then strip those elements in a second pass.
    // Hidden set contains class names and IDs (prefixed with #) from <style> blocks.
    let hidden = std::sync::Arc::new(extract_hidden_classes(html)?);
    let hc = hidden.clone();
    let hi = hidden.clone();

    let result = rewrite_str(
        html,
        RewriteStrSettings {
            element_content_handlers: vec![
                element!("style", |el| {
                    el.remove();
                    Ok(())
                }),
                element!("script", |el| {
                    el.remove();
                    Ok(())
                }),
                // If the element has any class associated with a hiding rule
                // in a <style> block, remove the entire element (content included).
                // Otherwise just strip the class attribute.
                element!("*[class]", |el| {
                    if !hc.is_empty() {
                        if let Some(class_attr) = el.get_attribute("class") {
                            if class_attr
                                .split_whitespace()
                                .any(|c| hc.contains(&c.to_lowercase()))
                            {
                                el.remove();
                                return Ok(());
                            }
                        }
                    }
                    el.remove_attribute("class");
                    Ok(())
                }),
                // If the element has an ID associated with a hiding rule, remove it.
                element!("*[id]", |el| {
                    if let Some(id_attr) = el.get_attribute("id") {
                        if hi.contains(&format!("#{}", id_attr.to_lowercase())) {
                            el.remove();
                            return Ok(());
                        }
                    }
                    Ok(())
                }),
                element!("*[style]", |el| {
                    if let Some(style) = el.get_attribute("style") {
                        if is_style_hidden(&style) {
                            el.remove();
                            return Ok(());
                        }
                    }
                    // In reading mode, strip all styles (ammonia would anyway).
                    // In draft mode, preserve non-hidden styles for filter_css_properties.
                    if strip_all_styles {
                        el.remove_attribute("style");
                    }
                    Ok(())
                }),
            ],
            ..Default::default()
        },
    );
    // Drop Arc before returning so the temporary outlives the closures
    drop(hidden);
    result.map_err(|e| AppError::Imap(format!("failed to sanitize HTML: {e}")))
}

/// Extract class names that are associated with CSS hiding rules in `<style>` blocks.
/// Uses simple pattern matching (not a full CSS parser) to find rules like
/// `.hidden { display: none }` and returns the set of class names.
fn extract_hidden_classes(html: &str) -> Result<std::collections::HashSet<String>, AppError> {
    use lol_html::text;
    let mut classes = std::collections::HashSet::new();
    let css_chunks = std::sync::Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
    let css_ref = css_chunks.clone();

    // Use lol_html's text handler to correctly extract <style> content,
    // avoiding false matches on `<style` appearing in attribute values.
    rewrite_str(
        html,
        RewriteStrSettings {
            element_content_handlers: vec![text!("style", move |chunk| {
                if let Ok(mut chunks) = css_ref.lock() {
                    chunks.push(chunk.as_str().to_string());
                }
                Ok(())
            })],
            ..Default::default()
        },
    )
    .map_err(|e| AppError::Imap(format!("failed to extract style blocks: {e}")))?;

    if let Ok(chunks) = css_chunks.lock() {
        let all_css = chunks.join("");
        let lower = all_css.to_lowercase();
        extract_hidden_classes_from_css(&lower, &mut classes);
    }
    Ok(classes)
}

/// Parse CSS text to find class selectors associated with hiding rules.
/// Only extracts the class from the *simple selector* directly before `{`,
/// not ancestor/compound selectors earlier in the rule.
/// Input `css` is expected to be already lowercased (from `extract_hidden_classes`).
///
/// Handles `@media` and other at-rules by recursively processing the nested
/// content rather than treating the first `{...}` as declarations.
fn extract_hidden_classes_from_css(css: &str, classes: &mut std::collections::HashSet<String>) {
    let mut rest = css;
    while let Some(brace_pos) = rest.find('{') {
        let raw_selector = rest[..brace_pos].trim();
        let after_brace = &rest[brace_pos + 1..];

        // Find matching '}' accounting for nesting depth
        let close_pos = match find_matching_brace(after_brace) {
            Some(p) => p,
            None => break,
        };
        let block_content = &after_brace[..close_pos];
        rest = &after_brace[close_pos + 1..];

        // Strip any brace-less at-rule statements (@charset, @import, @namespace)
        // that end with ';' and may have been absorbed into the selector.
        // E.g. `@charset"utf-8";.inject` → selector is `.inject`.
        let selector = if let Some(pos) = raw_selector.rfind(';') {
            raw_selector[pos + 1..].trim()
        } else {
            raw_selector
        };

        // If this is an at-rule (@media, @supports, etc.), recursively parse
        // the nested rules inside rather than treating the block as declarations.
        if selector.starts_with('@') {
            extract_hidden_classes_from_css(block_content, classes);
            continue;
        }

        // Check if declarations use any hiding technique. Reuse is_style_hidden
        // to ensure the same patterns are checked for both inline styles and
        // stylesheet rules — prevents bypass via techniques only checked in one path.
        if !is_style_hidden(block_content) {
            continue;
        }

        // Extract class names from the selector. Handle comma-separated selectors
        // (e.g. `.a, .b { display:none }`) and only take the last class in each
        // compound/descendant selector to avoid false positives on ancestor classes.
        for simple_selector in selector.split(',') {
            // Take the last segment after whitespace (the targeted element, not ancestors)
            let last_segment = simple_selector.split_whitespace().last().unwrap_or("");
            // Extract class names from this segment (could be `.foo.bar`)
            // Extract class names from this segment (could be `.foo.bar` or `div.foo`).
            // Skip the first part if it's a tag name (not preceded by '.').
            let skip = if last_segment.starts_with('.') { 0 } else { 1 };
            for part in last_segment.split('.').skip(skip) {
                let name_end = part
                    .find(|c: char| !c.is_ascii_alphanumeric() && c != '-' && c != '_')
                    .unwrap_or(part.len());
                let name = &part[..name_end];
                if !name.is_empty() {
                    classes.insert(name.to_string());
                }
            }
            // Extract IDs (#foo)
            for part in last_segment.split('#').skip(1) {
                let name_end = part
                    .find(|c: char| !c.is_ascii_alphanumeric() && c != '-' && c != '_')
                    .unwrap_or(part.len());
                let name = &part[..name_end];
                if !name.is_empty() {
                    classes.insert(format!("#{name}"));
                }
            }
        }
    }
}

/// Find the position of the `}` that matches the opening brace, accounting
/// for nested `{...}` pairs (e.g. inside `@media` blocks).
fn find_matching_brace(s: &str) -> Option<usize> {
    let mut depth: usize = 0;
    for (i, c) in s.char_indices() {
        match c {
            '{' => depth += 1,
            '}' if depth == 0 => return Some(i),
            '}' => depth -= 1,
            _ => {}
        }
    }
    None
}

/// Decode HTML entities (numeric and named) in a string.
///
/// lol_html returns attribute values without entity decoding, so we need
/// this to catch obfuscated style values like `display&#58;none` or
/// `display&colon;none`.
fn decode_html_entities_simple(s: &str) -> String {
    if !s.contains('&') {
        return s.to_string();
    }
    let mut result = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    'outer: while let Some(c) = chars.next() {
        if c != '&' {
            result.push(c);
            continue;
        }
        let mut entity = String::new();
        let mut found_semi = false;
        for ec in chars.by_ref() {
            if ec == ';' {
                found_semi = true;
                break;
            }
            entity.push(ec);
            if entity.len() > 32 {
                // Too long — not a real entity. Emit raw and drain to ';'.
                result.push('&');
                result.push_str(&entity);
                for ec2 in chars.by_ref() {
                    result.push(ec2);
                    if ec2 == ';' {
                        break;
                    }
                }
                continue 'outer;
            }
        }
        if found_semi {
            if let Some(ch) = decode_entity(&entity) {
                result.push(ch);
                continue;
            }
        }
        result.push('&');
        result.push_str(&entity);
        if found_semi {
            result.push(';');
        }
    }
    result
}

/// Decode a single HTML entity reference (without `&` and `;`).
fn decode_entity(entity: &str) -> Option<char> {
    if let Some(rest) = entity.strip_prefix('#') {
        let code = if let Some(hex) = rest.strip_prefix('x').or_else(|| rest.strip_prefix('X')) {
            u32::from_str_radix(hex, 16).ok()
        } else {
            rest.parse().ok()
        };
        return code.and_then(char::from_u32);
    }
    match entity {
        "colon" => Some(':'),
        "semi" => Some(';'),
        "comma" => Some(','),
        "period" => Some('.'),
        "hyphen" | "minus" => Some('-'),
        "sol" => Some('/'),
        "lpar" => Some('('),
        "rpar" => Some(')'),
        "equals" => Some('='),
        "num" => Some('#'),
        "percnt" => Some('%'),
        "amp" => Some('&'),
        "lt" => Some('<'),
        "gt" => Some('>'),
        "quot" => Some('"'),
        "apos" => Some('\''),
        "nbsp" | "ensp" | "emsp" | "thinsp" => Some(' '),
        "Tab" | "tab" => Some('\t'),
        "NewLine" | "newline" => Some('\n'),
        _ => None,
    }
}

/// Strip CSS block comments (`/* ... */`) from a string.
/// Decode CSS backslash escape sequences.
///
/// CSS allows `\HH` (1-6 hex digits, optionally followed by one whitespace)
/// to encode characters. E.g. `d\69splay:none` = `display:none`.
/// Also handles `\<non-hex>` → literal character (e.g. `\:` → `:`).
fn decode_css_escapes(s: &str) -> String {
    if !s.contains('\\') {
        return s.to_string();
    }
    let mut result = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '\\' {
            result.push(c);
            continue;
        }
        // Collect 1-6 hex digits
        let mut hex = String::new();
        while hex.len() < 6 {
            match chars.peek() {
                Some(nc) if nc.is_ascii_hexdigit() => {
                    hex.push(*nc);
                    chars.next();
                }
                _ => break,
            }
        }
        if hex.is_empty() {
            // \<non-hex> → literal next char
            if let Some(nc) = chars.next() {
                result.push(nc);
            } else {
                result.push('\\');
            }
        } else {
            if let Some(decoded) = u32::from_str_radix(&hex, 16).ok().and_then(char::from_u32) {
                result.push(decoded);
            } else {
                result.push('\\');
                result.push_str(&hex);
            }
            // CSS spec: optional single whitespace after hex escape is consumed
            if chars.peek().is_some_and(|c| c.is_whitespace()) {
                chars.next();
            }
        }
    }
    result
}

fn strip_css_comments(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    let mut chars = s.char_indices().peekable();
    while let Some(&(i, c)) = chars.peek() {
        if c == '/' && s.as_bytes().get(i + 1) == Some(&b'*') {
            chars.next();
            chars.next();
            loop {
                match chars.next() {
                    Some((_, '*')) if chars.peek().map(|&(_, c)| c) == Some('/') => {
                        chars.next();
                        break;
                    }
                    None => break,
                    _ => {}
                }
            }
        } else {
            result.push(c);
            chars.next();
        }
    }
    result
}

/// Check whether a CSS style value uses techniques to hide content.
///
/// Checks `display:none`, `visibility:hidden/collapse`, `opacity` near zero,
/// `font-size` near zero, `height`/`width` near zero with `overflow:hidden`,
/// off-screen positioning, `text-indent` with large negative values,
/// `transform:scale(0)`/large `translate`, and `color:transparent`.
fn is_style_hidden(style: &str) -> bool {
    let decoded = decode_html_entities_simple(style);
    let decoded = decode_css_escapes(&decoded);
    let s: String = decoded
        .to_lowercase()
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    let s = strip_css_comments(&s);

    // Parse into property map for exact key matching
    let mut props = std::collections::HashMap::new();
    for decl in split_css_declarations(&s) {
        if let Some((prop, value)) = decl.split_once(':') {
            if !prop.is_empty() {
                let value = value.strip_suffix("!important").unwrap_or(value);
                props.insert(prop, value);
            }
        }
    }

    // display:none / visibility:hidden|collapse
    if props.get("display").is_some_and(|v| *v == "none") {
        return true;
    }
    if props
        .get("visibility")
        .is_some_and(|v| *v == "hidden" || *v == "collapse")
    {
        return true;
    }

    // opacity <= 0.05
    if let Some(v) = props.get("opacity") {
        if let Ok(f) = v.parse::<f64>() {
            if f <= 0.05 {
                return true;
            }
        }
    }

    // font-size near zero
    if props.get("font-size").is_some_and(|v| is_near_zero(v, 2.0)) {
        return true;
    }

    // height/max-height/width/max-width near zero WITH overflow:hidden/clip
    let has_overflow_hidden = props
        .get("overflow")
        .is_some_and(|v| *v == "hidden" || *v == "clip")
        || props
            .get("overflow-x")
            .is_some_and(|v| *v == "hidden" || *v == "clip")
        || props
            .get("overflow-y")
            .is_some_and(|v| *v == "hidden" || *v == "clip");
    if has_overflow_hidden {
        for prop in ["height", "max-height", "width", "max-width"] {
            if props.get(prop).is_some_and(|v| is_near_zero(v, 1.0)) {
                return true;
            }
        }
    }

    // Off-screen positioning
    let is_positioned = props
        .get("position")
        .is_some_and(|v| *v == "absolute" || *v == "fixed");
    if is_positioned {
        for prop in [
            "left",
            "top",
            "right",
            "bottom",
            "margin-left",
            "margin-top",
        ] {
            if props.get(prop).is_some_and(|v| is_large_negative(v)) {
                return true;
            }
        }
    }

    // text-indent with large negative value
    if props
        .get("text-indent")
        .is_some_and(|v| is_large_negative(v))
    {
        return true;
    }

    // transform: scale(0) or large translate
    if let Some(v) = props.get("transform") {
        if v.contains("scale(0)") || v.contains("scalex(0)") || v.contains("scaley(0)") {
            return true;
        }
        // Check for large translate values
        for func in ["translate(", "translatex(", "translatey("] {
            if let Some(start) = v.find(func) {
                let args_start = start + func.len();
                if let Some(paren_end) = v[args_start..].find(')') {
                    let args = &v[args_start..args_start + paren_end];
                    for arg in args.split(',') {
                        let arg = arg.trim_start_matches('-');
                        if parse_px_digits(arg) >= 200 {
                            return true;
                        }
                    }
                }
            }
        }
    }

    // Transparent text color
    if let Some(v) = props.get("color") {
        if *v == "transparent" || is_transparent_alpha(v) {
            return true;
        }
    }

    false
}

/// Check if a CSS numeric value is near zero, accounting for units.
/// Threshold applies to px/unitless; em/rem use 0.25; vh/vw/% use 0.5.
fn is_near_zero(value: &str, threshold_px: f64) -> bool {
    let num_end = value
        .find(|c: char| c != '.' && c != '-' && !c.is_ascii_digit())
        .unwrap_or(value.len());
    if num_end == 0 {
        return false;
    }
    let v: f64 = match value[..num_end].parse() {
        Ok(v) => v,
        Err(_) => return false,
    };
    if v <= 0.0 {
        return true;
    }
    let unit = &value[num_end..];
    match unit {
        "" | "px" => v <= threshold_px,
        "em" | "rem" => v <= 0.25,
        "vh" | "vw" | "%" => v <= 0.5,
        _ => false,
    }
}

/// Check if a CSS color function has near-zero alpha.
fn is_transparent_alpha(value: &str) -> bool {
    // Check hex alpha
    if let Some(hex) = value.strip_prefix('#') {
        if hex.len() == 8 && hex.chars().all(|c| c.is_ascii_hexdigit()) {
            return &hex[6..] == "00";
        }
        if hex.len() == 4 && hex.chars().all(|c| c.is_ascii_hexdigit()) {
            return &hex[3..] == "0";
        }
    }
    // Extract alpha from rgba/hsla/rgb (last value after , or /)
    let alpha = if let Some(pos) = value.rfind(',') {
        &value[pos + 1..value.len().saturating_sub(1)]
    } else if let Some(pos) = value.rfind('/') {
        &value[pos + 1..value.len().saturating_sub(1)]
    } else {
        return false;
    };
    let alpha_clean = alpha.trim_end_matches('%');
    alpha_clean.parse::<f64>().ok().is_some_and(|v| {
        if alpha.ends_with('%') {
            v <= 5.0
        } else {
            v <= 0.05
        }
    })
}

/// Parse leading digits (including '.') as a pixel value. Returns u32::MAX on overflow.
fn parse_px_digits(s: &str) -> u32 {
    let num_end = s
        .find(|c: char| c != '.' && !c.is_ascii_digit())
        .unwrap_or(s.len());
    if num_end == 0 {
        return 0;
    }
    s[..num_end]
        .parse::<f64>()
        .map(|v| v.ceil() as u32)
        .unwrap_or(u32::MAX)
}

/// Tags allowed in both draft and reading sanitization.
const ALLOWED_TAGS: [&str; 22] = [
    "p",
    "br",
    "h1",
    "h2",
    "h3",
    "h4",
    "h5",
    "h6",
    "ul",
    "ol",
    "li",
    "em",
    "strong",
    "b",
    "i",
    "a",
    "blockquote",
    "pre",
    "code",
    "table",
    "tr",
    "td",
];

/// Ammonia allowlist for reading: strips all attributes except `href` on links.
/// Used by `html_to_safe_text` where everything becomes plain text anyway.
fn ammonia_reading() -> ammonia::Builder<'static> {
    let mut builder = ammonia::Builder::empty();
    builder
        .add_tags(ALLOWED_TAGS)
        .add_tags(["thead", "tbody", "th", "div", "span"])
        .add_tag_attributes("a", ["href"])
        .add_url_schemes(["https", "http", "mailto"]);
    builder
}

/// Ammonia allowlist for outgoing drafts: uses `attribute_filter` to sanitize
/// CSS `style` values down to safe visual properties only. Hidden styles are
/// already stripped by `strip_hidden_elements`, but this also blocks tracking
/// pixels via `background-image:url(...)`, overlays, `color:transparent`, etc.
fn ammonia_draft() -> ammonia::Builder<'static> {
    let mut builder = ammonia::Builder::empty();
    let styled_tags = [
        "p",
        "h1",
        "h2",
        "h3",
        "h4",
        "h5",
        "h6",
        "ul",
        "ol",
        "li",
        "em",
        "strong",
        "b",
        "i",
        "a",
        "blockquote",
        "pre",
        "code",
        "table",
        "tr",
        "td",
        "thead",
        "tbody",
        "th",
        "div",
        "span",
    ];
    builder
        .add_tags(ALLOWED_TAGS)
        .add_tags(["thead", "tbody", "th", "div", "span"])
        .add_tag_attributes("a", ["href"])
        .add_url_schemes(["https", "http", "mailto"])
        .attribute_filter(|_element, attribute, value| {
            if attribute != "style" {
                return Some(value.into());
            }
            let filtered = filter_css_properties(value);
            if filtered.is_empty() {
                None
            } else {
                Some(filtered.into())
            }
        });
    for tag in styled_tags {
        builder.add_tag_attributes(tag, ["style"]);
    }
    builder
}

/// CSS properties safe for email formatting. No `background-image` (tracking),
/// no `position`/`opacity`/`display`/`visibility` (hiding/overlays).
/// `color` and `background-color` are both excluded to prevent same-color
/// text hiding (e.g. black text on black background, white on white).
const SAFE_CSS_PROPERTIES: &[&str] = &[
    "font-family",
    "font-size",
    "font-weight",
    "font-style",
    "line-height",
    "text-align",
    "text-decoration",
    "text-transform",
    "letter-spacing",
    "word-spacing",
    "border",
    "border-top",
    "border-right",
    "border-bottom",
    "border-left",
    "border-collapse",
    "border-spacing",
    "border-color",
    "border-style",
    "border-width",
    "border-radius",
    "margin",
    "margin-top",
    "margin-right",
    "margin-bottom",
    "margin-left",
    "padding",
    "padding-top",
    "padding-right",
    "padding-bottom",
    "padding-left",
    "width",
    "max-width",
    "min-width",
    "height",
    "max-height",
    "min-height",
    "vertical-align",
    "white-space",
    "list-style",
    "list-style-type",
];

/// Check if a CSS value is effectively zero/tiny (at or below 1px threshold).
/// Only applies the threshold for `px` or unitless values. For other units
/// (`em`, `rem`, etc.), only exact zero is caught.
fn is_zero_value(value: &str) -> bool {
    let lower = value.trim().to_lowercase();
    let num_end = lower
        .find(|c: char| c != '.' && !c.is_ascii_digit())
        .unwrap_or(lower.len());
    if num_end == 0 {
        return false;
    }
    if let Ok(v) = lower[..num_end].parse::<f64>() {
        if v == 0.0 {
            return true;
        }
        let unit = &lower[num_end..];
        let is_small = match unit {
            "" | "px" => v <= 1.0,
            "em" | "rem" => v <= 0.25,
            "vh" | "vw" | "%" => v <= 0.5,
            _ => false,
        };
        if is_small {
            return true;
        }
    }
    false
}

/// Check if a CSS value is a large negative number (>= 200 in magnitude).
/// Used as a backstop in filter_css_properties for margin-left/margin-top.
fn is_large_negative(value: &str) -> bool {
    let trimmed = value.trim().to_lowercase();
    if let Some(rest) = trimmed.strip_prefix('-') {
        let num_end = rest
            .find(|c: char| c != '.' && !c.is_ascii_digit())
            .unwrap_or(rest.len());
        if num_end > 0 {
            return rest[..num_end]
                .parse::<f64>()
                .ok()
                .is_some_and(|v| v >= 200.0);
        }
    }
    false
}

/// Split CSS declarations on `;`, respecting quoted strings and parentheses.
/// `font-family: 'My Font; Other'` stays as one declaration.
fn split_css_declarations(style: &str) -> Vec<&str> {
    let mut declarations = Vec::new();
    let mut start = 0;
    let mut in_quote: Option<char> = None;
    let mut paren_depth: usize = 0;

    for (i, c) in style.char_indices() {
        match in_quote {
            Some(q) if c == q => in_quote = None,
            Some(_) => {}
            None if c == '\'' || c == '"' => in_quote = Some(c),
            None if c == '(' => paren_depth += 1,
            None if c == ')' && paren_depth > 0 => paren_depth -= 1,
            None if c == ';' && paren_depth == 0 => {
                declarations.push(&style[start..i]);
                start = i + 1;
            }
            _ => {}
        }
    }
    if start < style.len() {
        declarations.push(&style[start..]);
    }
    declarations
}

/// Filter CSS style value to only permit safe properties.
/// Returns a sanitized CSS string with only allowed properties.
fn filter_css_properties(style: &str) -> String {
    let mut safe = Vec::new();
    for declaration in split_css_declarations(style) {
        let declaration = declaration.trim();
        if declaration.is_empty() {
            continue;
        }
        if let Some((prop, value)) = declaration.split_once(':') {
            let prop = prop.trim().to_lowercase();
            let value = value.trim();
            if SAFE_CSS_PROPERTIES.contains(&prop.as_str()) {
                // Block url() and expression() in any property value (tracking pixels).
                // Decode CSS escapes first so \75rl() doesn't bypass the check.
                let lower_value = strip_css_comments(&decode_css_escapes(&value.to_lowercase()));
                if lower_value.contains("url(") || lower_value.contains("expression(") {
                    continue;
                }
                // Block zero/tiny height/max-height and font-size as secondary
                // defense (backstop for strip_hidden_elements bypass).
                if (prop == "height" || prop == "max-height" || prop == "font-size")
                    && is_zero_value(value)
                {
                    continue;
                }
                // Block large negative margins (off-screen positioning backstop).
                if (prop == "margin-left" || prop == "margin-top") && is_large_negative(value) {
                    continue;
                }
                safe.push(format!("{prop}: {value}"));
            }
        }
    }
    safe.join("; ")
}

/// Convert HTML to plain text safely for AI consumption.
///
/// Removes hidden elements (prompt-injection vector), sanitizes through ammonia,
/// then converts to plain text via `html2text`.
pub fn html_to_safe_text(html: &str) -> Result<String, AppError> {
    let stripped = strip_hidden_elements(html, true)?;
    let sanitized = ammonia_reading().clean(&stripped).to_string();
    Ok(
        html2text::from_read(sanitized.as_bytes(), 80).unwrap_or_else(|e| {
            tracing::warn!("Failed to convert HTML to text: {e}");
            sanitized
        }),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_draft_strips_script_tags() {
        let html = r#"<p>Hello</p><script>alert('xss')</script><p>World</p>"#;
        let sanitized = sanitize_html_for_draft(html).unwrap();
        assert!(!sanitized.contains("<script>"));
        assert!(!sanitized.contains("alert"));
        assert!(sanitized.contains("<p>Hello</p>"));
        assert!(sanitized.contains("<p>World</p>"));
    }

    #[test]
    fn sanitize_draft_strips_style_tags() {
        let html = r#"<p>Hello</p><style>body { display: none; }</style>"#;
        let sanitized = sanitize_html_for_draft(html).unwrap();
        assert!(!sanitized.contains("<style>"));
        assert!(!sanitized.contains("display"));
        assert!(sanitized.contains("<p>Hello</p>"));
    }

    #[test]
    fn sanitize_draft_strips_style_attributes() {
        let html = r#"<span style="display:none">hidden injection</span><p>visible</p>"#;
        let sanitized = sanitize_html_for_draft(html).unwrap();
        assert!(!sanitized.contains("display:none"));
        assert!(sanitized.contains("visible"));
    }

    #[test]
    fn sanitize_draft_preserves_safe_tags() {
        let html = "<h1>Title</h1><p>Paragraph with <strong>bold</strong> and <em>italic</em></p><ul><li>item</li></ul><a href=\"https://example.com\">link</a>";
        let sanitized = sanitize_html_for_draft(html).unwrap();
        assert!(sanitized.contains("<h1>"));
        assert!(sanitized.contains("<strong>"));
        assert!(sanitized.contains("<em>"));
        assert!(sanitized.contains("<ul>"));
        assert!(sanitized.contains("<li>"));
        assert!(
            sanitized.contains(r#"href="https://example.com""#),
            "href should be preserved on links, got: {sanitized:?}"
        );
    }

    #[test]
    fn html_to_safe_text_strips_scripts() {
        let html = r#"<p>Hello</p><script>evil()</script>"#;
        let text = html_to_safe_text(html).unwrap();
        assert!(text.contains("Hello"));
        assert!(!text.contains("evil"));
        assert!(!text.contains("<script>"));
    }

    #[test]
    fn html_to_safe_text_strips_hidden_elements() {
        let html = r#"<p>Visible</p><span style="display:none">hidden injection</span>"#;
        let text = html_to_safe_text(html).unwrap();
        assert!(text.contains("Visible"));
        assert!(
            !text.contains("hidden injection"),
            "Hidden text should be stripped entirely, got: {text:?}"
        );
    }

    #[test]
    fn html_to_safe_text_strips_visibility_hidden() {
        let html =
            r#"<p>Hello</p><div style="visibility: hidden">secret payload</div><p>World</p>"#;
        let text = html_to_safe_text(html).unwrap();
        assert!(text.contains("Hello"));
        assert!(text.contains("World"));
        assert!(
            !text.contains("secret payload"),
            "visibility:hidden text should be stripped, got: {text:?}"
        );
    }

    #[test]
    fn html_to_safe_text_strips_nested_hidden_elements() {
        let html = r#"<div style="display:none"><p>Nested <strong>hidden</strong> content</p></div><p>Visible</p>"#;
        let text = html_to_safe_text(html).unwrap();
        assert!(text.contains("Visible"));
        assert!(
            !text.contains("hidden"),
            "Nested hidden content should be stripped, got: {text:?}"
        );
    }

    #[test]
    fn strip_hidden_preserves_visible_styled_content() {
        let html = r#"<p style="color:red">Styled text</p><span style="display:none">hidden</span><p>Normal</p>"#;
        let result = strip_hidden_elements(html, true).unwrap();
        assert!(
            result.contains("Styled text"),
            "Visible styled content should be preserved, got: {result:?}"
        );
        assert!(result.contains("Normal"));
        assert!(!result.contains("hidden"));
        assert!(
            !result.contains("style="),
            "Style attributes should be stripped, got: {result:?}"
        );
    }

    #[test]
    fn strip_hidden_allows_nonzero_opacity() {
        let html = r#"<span style="opacity:0.5">half visible</span>"#;
        let result = strip_hidden_elements(html, true).unwrap();
        assert!(
            result.contains("half visible"),
            "Content should be preserved, got: {result:?}"
        );
        assert!(
            !result.contains("style="),
            "Style attribute should be stripped, got: {result:?}"
        );
    }

    #[test]
    fn strip_hidden_not_tricked_by_data_style_attribute() {
        // "data-style" should not be confused with "style"
        let html =
            r#"<div data-style="display:none" style="display:none">hidden</div><p>Visible</p>"#;
        let result = strip_hidden_elements(html, true).unwrap();
        assert!(result.contains("Visible"));
        assert!(
            !result.contains("hidden"),
            "Real style=display:none should still be caught, got: {result:?}"
        );
    }

    #[test]
    fn strip_hidden_ignores_data_style_only() {
        // Only "data-style" attribute, no real "style" — should NOT strip
        let html = r#"<div data-style="display:none">keep this</div><p>Also keep</p>"#;
        let result = strip_hidden_elements(html, true).unwrap();
        assert!(
            result.contains("keep this"),
            "data-style should not trigger stripping, got: {result:?}"
        );
        assert!(result.contains("Also keep"));
    }

    #[test]
    fn strip_hidden_handles_void_elements() {
        // Void element with hidden style should not consume following content
        let html = r#"<input style="display:none"><p>Visible after void element</p>"#;
        let result = strip_hidden_elements(html, true).unwrap();
        assert!(
            result.contains("Visible after void element"),
            "Content after void element should be preserved, got: {result:?}"
        );
    }

    #[test]
    fn strip_hidden_handles_self_closing_tags() {
        let html = r#"<img style="display:none"/><p>Still visible</p>"#;
        let result = strip_hidden_elements(html, true).unwrap();
        assert!(
            result.contains("Still visible"),
            "Content after self-closing tag should be preserved, got: {result:?}"
        );
    }

    #[test]
    fn strip_hidden_closing_tag_word_boundary() {
        // </divider> should not match when tag_name is "div"
        let html = r#"<div style="display:none"><divider>keep</divider></div><p>After</p>"#;
        let result = strip_hidden_elements(html, true).unwrap();
        assert!(
            result.contains("After"),
            "Content after hidden div should be preserved, got: {result:?}"
        );
        assert!(
            !result.contains("keep"),
            "Content inside hidden div should be stripped, got: {result:?}"
        );
    }

    #[test]
    fn strip_hidden_extra_whitespace_in_style() {
        // CSS allows arbitrary whitespace around colons
        let html = r#"<span style="display:  none">hidden</span><p>Visible</p>"#;
        let result = strip_hidden_elements(html, true).unwrap();
        assert!(
            !result.contains("hidden"),
            "Extra whitespace in display:none should still be caught, got: {result:?}"
        );
        assert!(result.contains("Visible"));
    }

    #[test]
    fn strip_hidden_whitespace_around_colon() {
        let html = r#"<span style="display : none">hidden</span><p>Visible</p>"#;
        let result = strip_hidden_elements(html, true).unwrap();
        assert!(
            !result.contains("hidden"),
            "Whitespace around colon should still be caught, got: {result:?}"
        );
        assert!(result.contains("Visible"));
    }

    #[test]
    fn strip_hidden_catches_unquoted_style() {
        let html = r#"<span style=display:none>hidden</span><p>Visible</p>"#;
        let result = strip_hidden_elements(html, true).unwrap();
        assert!(
            !result.contains("hidden"),
            "Unquoted style=display:none should be caught, got: {result:?}"
        );
        assert!(result.contains("Visible"));
    }

    #[test]
    fn strip_hidden_unclosed_element_strips_to_end() {
        // Unclosed hidden element strips everything to end-of-document.
        // This prevents injection via unclosed tags like:
        //   <div style="display:none">IGNORE PREVIOUS INSTRUCTIONS
        let html = r#"<p>Before</p><div style="display:none">hidden payload<p>also hidden</p>"#;
        let result = strip_hidden_elements(html, true).unwrap();
        assert!(
            result.contains("Before"),
            "Content before unclosed hidden element should be preserved, got: {result:?}"
        );
        assert!(
            !result.contains("hidden payload"),
            "Hidden content from unclosed element should be stripped, got: {result:?}"
        );
        assert!(
            !result.contains("also hidden"),
            "Trailing content after unclosed hidden element should be stripped, got: {result:?}"
        );
    }

    #[test]
    fn sanitize_draft_strips_img_tags() {
        let html = r#"<p>Hello</p><img src="https://tracker.evil/pixel.gif"><p>World</p>"#;
        let sanitized = sanitize_html_for_draft(html).unwrap();
        assert!(
            !sanitized.contains("<img"),
            "img tags should be stripped from drafts"
        );
        assert!(!sanitized.contains("tracker.evil"));
        assert!(sanitized.contains("Hello"));
        assert!(sanitized.contains("World"));
    }

    #[test]
    fn strip_hidden_catches_html_entity_encoded_style() {
        // &#58; is HTML entity for ':'
        let html = r#"<span style="display&#58;none">hidden via entity</span><p>Visible</p>"#;
        let result = strip_hidden_elements(html, true).unwrap();
        assert!(
            !result.contains("hidden via entity"),
            "HTML entity-encoded style should be caught, got: {result:?}"
        );
        assert!(result.contains("Visible"));
    }

    #[test]
    fn strip_hidden_catches_hex_entity_encoded_style() {
        // &#x3a; is hex HTML entity for ':'
        let html = r#"<span style="display&#x3a;none">hidden via hex</span><p>Visible</p>"#;
        let result = strip_hidden_elements(html, true).unwrap();
        assert!(
            !result.contains("hidden via hex"),
            "Hex entity-encoded style should be caught, got: {result:?}"
        );
        assert!(result.contains("Visible"));
    }

    #[test]
    fn strip_hidden_catches_named_entity_colon_bypass() {
        let html =
            r#"<span style="display&colon;none">hidden via named entity</span><p>Visible</p>"#;
        let result = strip_hidden_elements(html, true).unwrap();
        assert!(
            !result.contains("hidden via named entity"),
            "Named entity &colon; bypass should be caught, got: {result:?}"
        );
        assert!(result.contains("Visible"));
    }

    #[test]
    fn strip_hidden_no_false_positive_on_text_overflow_hidden() {
        let html = r#"<div style="height:20px;text-overflow:hidden">truncated</div><p>After</p>"#;
        let result = strip_hidden_elements(html, true).unwrap();
        assert!(
            result.contains("truncated"),
            "Content should be preserved, got: {result:?}"
        );
    }

    #[test]
    fn strip_hidden_empty_tag_name_skips_tag() {
        // Tag with empty name: `< style="display:none">` — should at minimum
        // skip the tag itself and not leak content after it
        let html = r#"< style="display:none">payload<p>After</p>"#;
        // This is malformed HTML; browsers render it as text, but our parser
        // should handle it gracefully without panicking
        let _result = strip_hidden_elements(html, true).unwrap();
        // No assertion on content — just verify no panic
    }

    #[test]
    fn strip_hidden_no_false_positive_on_padding_left() {
        let html = r#"<div style="position:absolute;padding-left:-200px">content</div>"#;
        let result = strip_hidden_elements(html, true).unwrap();
        assert!(
            result.contains("content"),
            "padding-left should not trigger stripping, got: {result:?}"
        );
    }

    #[test]
    fn strip_hidden_self_closing_div_does_not_leak_content() {
        // In HTML5, <div/> is treated as <div>, not self-closing.
        // A crafted <div/> inside a hidden element must increment depth.
        let html = r#"<div style="display:none"><div/>ignored</div>INJECTED</div><p>Safe</p>"#;
        let result = strip_hidden_elements(html, true).unwrap();
        assert!(
            !result.contains("INJECTED"),
            "Self-closing div should not cause premature depth decrement, got: {result:?}"
        );
        assert!(result.contains("Safe"));
    }

    #[test]
    fn strip_hidden_strips_class_based_hidden_elements() {
        let html = r#"<style>.h { display: none; }</style><div class="h">hidden via class</div><p>Visible</p>"#;
        let result = strip_hidden_elements(html, true).unwrap();
        assert!(
            !result.contains("<style>"),
            "Style blocks should be stripped, got: {result:?}"
        );
        assert!(
            !result.contains("hidden via class"),
            "Elements with hidden classes should be stripped, got: {result:?}"
        );
        assert!(result.contains("Visible"));
    }

    #[test]
    fn strip_hidden_preserves_non_hidden_class_elements() {
        let html =
            r#"<style>.highlight { color: red; }</style><div class="highlight">visible text</div>"#;
        let result = strip_hidden_elements(html, true).unwrap();
        assert!(
            result.contains("visible text"),
            "Non-hidden class elements should be preserved, got: {result:?}"
        );
    }

    #[test]
    fn strip_hidden_class_based_visibility_hidden() {
        let html = r#"<style>.secret { visibility: hidden; }</style><span class="secret">injection</span><p>Safe</p>"#;
        let result = strip_hidden_elements(html, true).unwrap();
        assert!(
            !result.contains("injection"),
            "visibility:hidden class should strip element, got: {result:?}"
        );
        assert!(result.contains("Safe"));
    }

    #[test]
    fn strip_hidden_descendant_selector_does_not_strip_ancestor() {
        // `.wrapper .hide { display:none }` should only strip elements with class "hide",
        // not elements with class "wrapper"
        let html = r#"<style>.wrapper .hide { display: none; }</style><div class="wrapper"><p>Visible wrapper content</p><span class="hide">hidden</span></div>"#;
        let result = strip_hidden_elements(html, true).unwrap();
        assert!(
            result.contains("Visible wrapper content"),
            "Ancestor class should not be stripped, got: {result:?}"
        );
        assert!(
            !result.contains("hidden"),
            "Targeted class should be stripped, got: {result:?}"
        );
    }

    #[test]
    fn strip_hidden_comma_separated_selectors() {
        let html = r#"<style>.a, .b { display: none; }</style><div class="a">hidden-a</div><div class="b">hidden-b</div><p>Visible</p>"#;
        let result = strip_hidden_elements(html, true).unwrap();
        assert!(
            !result.contains("hidden-a"),
            "Class .a should be stripped, got: {result:?}"
        );
        assert!(
            !result.contains("hidden-b"),
            "Class .b should be stripped, got: {result:?}"
        );
        assert!(result.contains("Visible"));
    }

    #[test]
    fn filter_css_allows_safe_properties() {
        let css = "font-size: 14px; text-align: center; padding: 10px";
        let result = filter_css_properties(css);
        assert!(result.contains("font-size: 14px"));
        assert!(result.contains("text-align: center"));
        assert!(result.contains("padding: 10px"));
    }

    #[test]
    fn filter_css_strips_color_and_background_color() {
        // Both color and background-color are excluded to prevent same-color hiding
        assert_eq!(filter_css_properties("color: red"), "");
        assert_eq!(filter_css_properties("background-color: black"), "");
    }

    #[test]
    fn filter_css_strips_color_property() {
        // color is excluded to prevent same-color-as-background hiding
        let css = "color: red; font-size: 14px";
        let result = filter_css_properties(css);
        assert!(!result.contains("color"));
        assert!(result.contains("font-size: 14px"));
    }

    #[test]
    fn filter_css_strips_dangerous_properties() {
        let css = "background-image: url(https://tracker.evil/pixel); padding: 10px";
        let result = filter_css_properties(css);
        assert!(!result.contains("background-image"));
        assert!(!result.contains("tracker.evil"));
        assert!(result.contains("padding: 10px"));
    }

    #[test]
    fn filter_css_strips_position_and_display() {
        let css = "position: absolute; left: -9999px; display: none; font-size: 14px";
        let result = filter_css_properties(css);
        assert!(!result.contains("position"));
        assert!(!result.contains("display"));
        assert!(!result.contains("left"));
        assert!(result.contains("font-size: 14px"));
    }

    #[test]
    fn filter_css_strips_all_background_color() {
        // background-color is excluded entirely from the allowlist
        assert_eq!(filter_css_properties("background-color: transparent"), "");
        assert_eq!(filter_css_properties("background-color: #fff"), "");
        assert_eq!(filter_css_properties("background-color: black"), "");
    }

    #[test]
    fn filter_css_strips_zero_and_subpixel_height() {
        assert_eq!(filter_css_properties("height: 0"), "");
        assert_eq!(filter_css_properties("height: 0px"), "");
        assert_eq!(filter_css_properties("height: 0.001px"), "");
        assert_eq!(filter_css_properties("height: 0.5px"), "");
        assert_eq!(filter_css_properties("max-height: 0"), "");
        assert_eq!(filter_css_properties("height: 1px"), "");
        // Above threshold should be kept
        assert!(filter_css_properties("height: 100px").contains("height"));
        assert!(filter_css_properties("height: 2px").contains("height"));
    }

    #[test]
    fn filter_css_strips_url_in_any_value() {
        let css = "background-color: url(evil); padding: 10px";
        let result = filter_css_properties(css);
        assert!(!result.contains("url"));
        assert!(result.contains("padding: 10px"));
    }

    #[test]
    fn strip_hidden_preserves_normal_font_size() {
        let html = r#"<span style="font-size:14px">normal text</span>"#;
        let result = strip_hidden_elements(html, true).unwrap();
        assert!(
            result.contains("normal text"),
            "font-size:14px content should be preserved, got: {result:?}"
        );
        assert!(
            !result.contains("style="),
            "Style attribute should be stripped, got: {result:?}"
        );
    }

    #[test]
    fn strip_hidden_catches_css_comment_bypass() {
        let html = r#"<span style="display:/**/none">hidden</span><p>Visible</p>"#;
        let result = strip_hidden_elements(html, true).unwrap();
        assert!(
            !result.contains("hidden"),
            "CSS comment bypass should be caught, got: {result:?}"
        );
        assert!(result.contains("Visible"));
    }

    #[test]
    fn filter_css_strips_transparent_background_percentage_alpha() {
        assert_eq!(
            filter_css_properties("background-color: rgba(0,0,0,0%)"),
            ""
        );
        assert_eq!(
            filter_css_properties("background-color: hsla(0, 0%, 0%, 0%)"),
            ""
        );
    }

    #[test]
    fn strip_hidden_height_1px_without_overflow_preserved() {
        let html = r#"<hr style="height:1px"><p>After</p>"#;
        let result = strip_hidden_elements(html, true).unwrap();
        assert!(
            result.contains("After"),
            "Content should be preserved, got: {result:?}"
        );
    }

    #[test]
    fn strip_hidden_catches_css_backslash_escape() {
        // \69 = 'i' in CSS, so d\69splay:none = display:none
        let html = r#"<span style="d\69splay:none">hidden via css escape</span><p>Visible</p>"#;
        let result = strip_hidden_elements(html, true).unwrap();
        assert!(
            !result.contains("hidden via css escape"),
            "CSS backslash escape should be decoded, got: {result:?}"
        );
        assert!(result.contains("Visible"));
    }

    #[test]
    fn strip_hidden_catches_css_escape_visibility() {
        // \76 = 'v', \68 = 'h' → visibility:hidden
        let html = r#"<span style="\76isibility:\68idden">hidden</span><p>Visible</p>"#;
        let result = strip_hidden_elements(html, true).unwrap();
        assert!(
            !result.contains("hidden"),
            "CSS escaped visibility:hidden should be caught, got: {result:?}"
        );
        assert!(result.contains("Visible"));
    }

    #[test]
    fn decode_css_escapes_basic() {
        assert_eq!(decode_css_escapes(r"d\69 splay"), "display");
        assert_eq!(decode_css_escapes(r"d\69splay"), "display");
        assert_eq!(decode_css_escapes(r"\76isibility"), "visibility");
        assert_eq!(decode_css_escapes(r"\:"), ":");
        assert_eq!(decode_css_escapes("no escapes"), "no escapes");
    }

    #[test]
    fn strip_hidden_removes_elements_with_exotic_hiding() {
        // All hiding techniques now cause element removal
        let html = r#"<span style="opacity:0">text1</span><span style="font-size:0">text2</span><div style="height:0;overflow:hidden">text3</div><p style="color:red">visible</p>"#;
        let result = strip_hidden_elements(html, true).unwrap();
        assert!(
            !result.contains("text1"),
            "opacity:0 should be removed, got: {result:?}"
        );
        assert!(
            !result.contains("text2"),
            "font-size:0 should be removed, got: {result:?}"
        );
        assert!(
            !result.contains("text3"),
            "height:0+overflow:hidden should be removed, got: {result:?}"
        );
        assert!(
            result.contains("visible"),
            "Non-hidden should be preserved, got: {result:?}"
        );
    }
}
