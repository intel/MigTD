// Copyright (c) 2026 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

//! Strict parser for `config/servtd_attr.json`, shared by the MigTD build
//! (as a `const`) and `migtd-hash`, so both read the same value.
//!
//! The document must be a JSON object with exactly one top-level `servtdAttr`
//! key. The value is a number or a string holding a decimal or `0x`/`0X` hex
//! number; surrounding whitespace is trimmed. Empty, duplicate, nested-only,
//! unterminated or otherwise malformed input is an error.

use core::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServtdAttrConfigError {
    /// The document is not a JSON object.
    NotObject,
    /// No top-level `servtdAttr` key.
    Missing,
    /// More than one top-level `servtdAttr` key.
    Duplicate,
    /// Unbalanced or unterminated JSON, or a value that is not a string or an
    /// unsigned decimal number.
    Malformed,
    /// The value is empty.
    Empty,
    /// The value is not a decimal or `0x` hexadecimal number.
    NotANumber,
    /// The value does not fit in 64 bits.
    Overflow,
}

impl ServtdAttrConfigError {
    pub const fn message(&self) -> &'static str {
        match self {
            Self::NotObject => "not a JSON object",
            Self::Missing => "no top-level \"servtdAttr\" key",
            Self::Duplicate => "duplicate \"servtdAttr\" key",
            Self::Malformed => "malformed JSON or servtdAttr value",
            Self::Empty => "empty servtdAttr value",
            Self::NotANumber => "servtdAttr is not a decimal or 0x hex number",
            Self::Overflow => "servtdAttr does not fit in 64 bits",
        }
    }
}

impl fmt::Display for ServtdAttrConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.message())
    }
}

const KEY: &[u8] = b"servtdAttr";

const fn skip_ws(b: &[u8], mut i: usize) -> usize {
    while i < b.len() && b[i].is_ascii_whitespace() {
        i += 1;
    }
    i
}

/// Index of the closing quote of the string whose content starts at `start`.
const fn string_end(b: &[u8], start: usize) -> Result<usize, ServtdAttrConfigError> {
    let mut j = start;
    while j < b.len() {
        if b[j] == b'\\' {
            j += 2;
            continue;
        }
        if b[j] == b'"' {
            return Ok(j);
        }
        j += 1;
    }
    Err(ServtdAttrConfigError::Malformed)
}

const fn is_key(b: &[u8], start: usize, end: usize) -> bool {
    if end - start != KEY.len() {
        return false;
    }
    let mut k = 0;
    while k < KEY.len() {
        if b[start + k] != KEY[k] {
            return false;
        }
        k += 1;
    }
    true
}

/// Parse a decimal or `0x`/`0X` hex `SERVTD_ATTR` from `b[start..end]`.
/// Whitespace around the value is ignored; an empty value is an error.
const fn parse_range(b: &[u8], start: usize, end: usize) -> Result<u64, ServtdAttrConfigError> {
    let mut start = skip_ws(b, start);
    let mut end = end;
    while end > start && b[end - 1].is_ascii_whitespace() {
        end -= 1;
    }
    if start >= end {
        return Err(ServtdAttrConfigError::Empty);
    }
    let mut radix = 10u64;
    if end - start >= 2 && b[start] == b'0' && (b[start + 1] == b'x' || b[start + 1] == b'X') {
        radix = 16;
        start += 2;
        if start == end {
            return Err(ServtdAttrConfigError::NotANumber);
        }
    }
    let mut result = 0u64;
    while start < end {
        let digit = match b[start] {
            c @ b'0'..=b'9' => (c - b'0') as u64,
            c @ b'a'..=b'f' => (c - b'a') as u64 + 10,
            c @ b'A'..=b'F' => (c - b'A') as u64 + 10,
            _ => return Err(ServtdAttrConfigError::NotANumber),
        };
        if digit >= radix {
            return Err(ServtdAttrConfigError::NotANumber);
        }
        result = match result.checked_mul(radix) {
            Some(shifted) => match shifted.checked_add(digit) {
                Some(value) => value,
                None => return Err(ServtdAttrConfigError::Overflow),
            },
            None => return Err(ServtdAttrConfigError::Overflow),
        };
        start += 1;
    }
    Ok(result)
}

/// Parse a decimal or `0x`/`0X` hex `SERVTD_ATTR` text (for example a command
/// line value). Whitespace around the value is ignored; empty is an error.
pub const fn parse_servtd_attr_text(text: &str) -> Result<u64, ServtdAttrConfigError> {
    parse_range(text.as_bytes(), 0, text.len())
}

/// Read the top-level `servtdAttr` value of the config JSON.
pub const fn parse_servtd_attr_config(json: &str) -> Result<u64, ServtdAttrConfigError> {
    let b = json.as_bytes();
    let n = b.len();
    let mut i = skip_ws(b, 0);
    if i >= n || b[i] != b'{' {
        return Err(ServtdAttrConfigError::NotObject);
    }

    let mut depth = 0usize;
    let mut count = 0usize;
    let mut value_at = 0usize;
    while i < n {
        match b[i] {
            b'"' => {
                let end = match string_end(b, i + 1) {
                    Ok(end) => end,
                    Err(e) => return Err(e),
                };
                let after = skip_ws(b, end + 1);
                if depth == 1 && after < n && b[after] == b':' && is_key(b, i + 1, end) {
                    count += 1;
                    value_at = after + 1;
                }
                i = end + 1;
            }
            b'{' | b'[' => {
                depth += 1;
                i += 1;
            }
            b'}' | b']' => {
                if depth == 0 {
                    return Err(ServtdAttrConfigError::Malformed);
                }
                depth -= 1;
                i += 1;
            }
            _ => i += 1,
        }
    }
    if depth != 0 {
        return Err(ServtdAttrConfigError::Malformed);
    }
    if count == 0 {
        return Err(ServtdAttrConfigError::Missing);
    }
    if count > 1 {
        return Err(ServtdAttrConfigError::Duplicate);
    }

    // The value is a string, or a bare unsigned decimal number.
    let mut i = skip_ws(b, value_at);
    if i >= n {
        return Err(ServtdAttrConfigError::Malformed);
    }
    let (start, end, after_value) = if b[i] == b'"' {
        let mut j = i + 1;
        while j < n && b[j] != b'"' {
            if b[j] == b'\\' {
                return Err(ServtdAttrConfigError::Malformed);
            }
            j += 1;
        }
        if j >= n {
            return Err(ServtdAttrConfigError::Malformed);
        }
        (i + 1, j, j + 1)
    } else {
        let s = i;
        while i < n && b[i].is_ascii_digit() {
            i += 1;
        }
        if i == s {
            return Err(ServtdAttrConfigError::NotANumber);
        }
        (s, i, i)
    };
    let next = skip_ws(b, after_value);
    if next >= n || (b[next] != b',' && b[next] != b'}') {
        return Err(ServtdAttrConfigError::Malformed);
    }
    parse_range(b, start, end)
}

#[cfg(test)]
mod tests {
    use super::*;

    const OK: &[(&str, u64)] = &[
        (r#"{"servtdAttr": "0"}"#, 0),
        (r#"{"servtdAttr":"0x0"}"#, 0),
        (r#"{ "servtdAttr" : "137438953472" }"#, 1 << 37),
        ("{\n  \"servtdAttr\": \"0x2000000000\"\n}\n", 1 << 37),
        (r#"{"servtdAttr":"0X3FE00000000"}"#, 0x3FE_0000_0000),
        (r#"{"servtdAttr": 137438953472}"#, 1 << 37),
        (r#"{"servtdAttr": " 0x0 "}"#, 0),
        (r#"{"note":"x","servtdAttr":"0x2000000000","z":1}"#, 1 << 37),
        (r#"{"other":{"servtdAttr":"1"},"servtdAttr":"2"}"#, 2),
        (r#"{"servtdAttr":"0xffffffffffffffff"}"#, u64::MAX),
    ];

    const BAD: &[(&str, ServtdAttrConfigError)] = &[
        ("", ServtdAttrConfigError::NotObject),
        ("[]", ServtdAttrConfigError::NotObject),
        (r#"{}"#, ServtdAttrConfigError::Missing),
        (r#"{"servtd_attr":"0"}"#, ServtdAttrConfigError::Missing),
        // Nested only: not a top-level key.
        (
            r#"{"a":{"servtdAttr":"1"}}"#,
            ServtdAttrConfigError::Missing,
        ),
        (
            r#"{"servtdAttr":"1","servtdAttr":"2"}"#,
            ServtdAttrConfigError::Duplicate,
        ),
        (r#"{"servtdAttr":""}"#, ServtdAttrConfigError::Empty),
        (r#"{"servtdAttr":"  "}"#, ServtdAttrConfigError::Empty),
        (r#"{"servtdAttr":"0x"}"#, ServtdAttrConfigError::NotANumber),
        (
            r#"{"servtdAttr":"12ab"}"#,
            ServtdAttrConfigError::NotANumber,
        ),
        (r#"{"servtdAttr":-1}"#, ServtdAttrConfigError::NotANumber),
        // Unterminated string, bare hex or fraction, trailing garbage.
        (r#"{"servtdAttr":"0x1"#, ServtdAttrConfigError::Malformed),
        (r#"{"servtdAttr":0x10}"#, ServtdAttrConfigError::Malformed),
        (r#"{"servtdAttr":1.5}"#, ServtdAttrConfigError::Malformed),
        (
            r#"{"servtdAttr":"1" "x":2}"#,
            ServtdAttrConfigError::Malformed,
        ),
        (
            r#"{"servtdAttr":"0x10000000000000000"}"#,
            ServtdAttrConfigError::Overflow,
        ),
        (
            r#"{"servtdAttr":18446744073709551616}"#,
            ServtdAttrConfigError::Overflow,
        ),
    ];

    #[test]
    fn config_accepts_the_documented_forms() {
        for (json, expected) in OK {
            assert_eq!(parse_servtd_attr_config(json), Ok(*expected), "{json:?}");
        }
    }

    #[test]
    fn config_rejects_everything_else() {
        for (json, error) in BAD {
            assert_eq!(parse_servtd_attr_config(json), Err(*error), "{json:?}");
        }
    }

    #[test]
    fn text_accepts_decimal_and_hex() {
        assert_eq!(parse_servtd_attr_text("0"), Ok(0));
        assert_eq!(parse_servtd_attr_text(" 0x2000000000 "), Ok(1 << 37));
        assert_eq!(parse_servtd_attr_text("0X3fe00000000"), Ok(0x3FE_0000_0000));
        assert_eq!(parse_servtd_attr_text("137438953472"), Ok(1 << 37));
        assert_eq!(
            parse_servtd_attr_text(""),
            Err(ServtdAttrConfigError::Empty)
        );
        assert_eq!(
            parse_servtd_attr_text("0xg"),
            Err(ServtdAttrConfigError::NotANumber)
        );
    }

    #[test]
    fn parser_is_usable_in_const_context() {
        const VALUE: Result<u64, ServtdAttrConfigError> =
            parse_servtd_attr_config(r#"{"servtdAttr":"0x2000000000"}"#);
        assert_eq!(VALUE, Ok(1 << 37));
    }
}
