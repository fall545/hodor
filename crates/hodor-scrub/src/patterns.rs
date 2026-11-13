//! Needle generation: every detectable textual form of a secret.

use base64::Engine;
use percent_encoding::{utf8_percent_encode, NON_ALPHANUMERIC};
use std::collections::HashSet;

/// Values shorter than this are ignored: they cause false-positive storms
/// without meaningfully protecting anything (DESIGN §5.6).
pub const MIN_SECRET_LEN: usize = 8;

/// The pattern table handed to the Aho-Corasick automaton.
pub struct NeedleSet {
    patterns: Vec<Vec<u8>>,
    /// `aliases[i]` is the alias to substitute for `patterns[i]`.
    aliases: Vec<String>,
    max_len: usize,
}

impl NeedleSet {
    pub fn build<'a>(secrets: impl IntoIterator<Item = (&'a str, &'a [u8])>) -> Self {
        let mut set = Self {
            patterns: Vec::new(),
            aliases: Vec::new(),
            max_len: 0,
        };
        let mut seen: HashSet<Vec<u8>> = HashSet::new();
        for (alias, value) in secrets {
            if value.len() < MIN_SECRET_LEN {
                continue;
            }
            for variant in encodings(value) {
                if seen.insert(variant.clone()) {
                    set.push(alias.to_string(), variant);
                }
            }
        }
        set
    }

    pub fn is_empty(&self) -> bool {
        self.patterns.is_empty()
    }

    pub fn max_needle_len(&self) -> usize {
        self.max_len
    }

    pub fn patterns(&self) -> &[Vec<u8>] {
        &self.patterns
    }

    pub fn alias_at(&self, index: usize) -> &str {
        &self.aliases[index]
    }

    fn push(&mut self, alias: String, pattern: Vec<u8>) {
        self.max_len = self.max_len.max(pattern.len());
        self.patterns.push(pattern);
        self.aliases.push(alias);
    }
}

/// Textual forms a secret can leak in: raw, base64, hex (both cases),
/// percent-encoded. Anything more exotic falls to the withhold verdict.
fn encodings(value: &[u8]) -> Vec<Vec<u8>> {
    let mut out = vec![value.to_vec()];
    out.push(
        base64::engine::general_purpose::STANDARD
            .encode(value)
            .into_bytes(),
    );
    out.push(hex::encode(value).into_bytes());
    out.push(hex::encode_upper(value).into_bytes());
    if let Ok(text) = std::str::from_utf8(value) {
        out.push(
            utf8_percent_encode(text, NON_ALPHANUMERIC)
                .to_string()
                .into_bytes(),
        );
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_all_variants() {
        let set = NeedleSet::build([("openai", b"sk-live-abcd1234" as &[u8])]);
        assert!(set.patterns().len() >= 4);
        assert!(set.max_needle_len() > 0);
    }

    #[test]
    fn short_secrets_skipped() {
        let set = NeedleSet::build([("tiny", b"abc" as &[u8])]);
        assert!(set.is_empty());
    }

    #[test]
    fn duplicate_patterns_deduped() {
        let set = NeedleSet::build([
            ("a", b"sk-secret-1111" as &[u8]),
            ("a", b"sk-secret-1111" as &[u8]),
        ]);
        assert_eq!(set.patterns().len(), set.patterns().len());
        let set2 = NeedleSet::build([("a", b"sk-secret-1111" as &[u8])]);
        assert_eq!(set.patterns().len(), set2.patterns().len());
    }
}
