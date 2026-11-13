//! Stream and buffer scrubbing on top of the Aho-Corasick automaton.

use aho_corasick::{AhoCorasick, MatchKind};

use crate::patterns::NeedleSet;
use crate::verdict::looks_unanalyzable;

/// Scrubbed output. `output` is empty when `withheld` is set; the caller
/// replaces withheld output with a "see `hodor audit`" notice.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScrubResult {
    pub output: Vec<u8>,
    pub replacements: usize,
    pub withheld: bool,
}

/// Whole-buffer and streaming secret substitution.
pub struct Scrubber {
    needles: NeedleSet,
    automaton: Option<AhoCorasick>,
}

impl Scrubber {
    /// Build from `(alias, secret bytes)` pairs.
    pub fn build<'a>(secrets: impl IntoIterator<Item = (&'a str, &'a [u8])>) -> Self {
        let needles = NeedleSet::build(secrets);
        if needles.is_empty() {
            return Self {
                needles,
                automaton: None,
            };
        }
        let automaton = AhoCorasick::builder()
            .match_kind(MatchKind::LeftmostLongest)
            .build(needles.patterns())
            .expect("aho-corasick build cannot fail on non-empty input");
        Self {
            needles,
            automaton: Some(automaton),
        }
    }

    /// Scrub a complete buffer. `held_secret` marks the producing command as
    /// having had access to secret material: only then can unanalyzable output
    /// be withheld instead of passed through.
    pub fn scrub(&self, data: &[u8], held_secret: bool) -> ScrubResult {
        if held_secret && looks_unanalyzable(data) {
            return ScrubResult {
                output: Vec::new(),
                replacements: 0,
                withheld: true,
            };
        }
        let Some(automaton) = &self.automaton else {
            return ScrubResult {
                output: data.to_vec(),
                replacements: 0,
                withheld: false,
            };
        };
        let mut out = Vec::with_capacity(data.len());
        let mut replacements = 0usize;
        let mut pos = 0usize;
        for found in automaton.find_iter(data) {
            out.extend_from_slice(&data[pos..found.start()]);
            let alias = self.needles.alias_at(found.pattern().as_usize());
            out.extend_from_slice(format!("{{{{{alias}}}}}").as_bytes());
            replacements += 1;
            pos = found.end();
        }
        out.extend_from_slice(&data[pos..]);
        ScrubResult {
            output: out,
            replacements,
            withheld: false,
        }
    }

    /// Start a streaming scrub (for hodor-vfs reads and long pipes). Chunks
    /// are fed with [`StreamScrubber::feed`]; boundaries that could hide a
    /// needle are held back until the next chunk or [`StreamScrubber::finish`].
    pub fn stream(&self) -> StreamScrubber<'_> {
        StreamScrubber {
            scrubber: self,
            pending: Vec::new(),
        }
    }
}

pub struct StreamScrubber<'a> {
    scrubber: &'a Scrubber,
    pending: Vec<u8>,
}

impl StreamScrubber<'_> {
    /// Scrub one chunk; the tail that might continue a needle is retained.
    pub fn feed(&mut self, chunk: &[u8], held_secret: bool) -> ScrubResult {
        let hold = self.scrubber.needles.max_needle_len().saturating_sub(1);
        self.pending.extend_from_slice(chunk);
        if self.pending.len() <= hold {
            return ScrubResult {
                output: Vec::new(),
                replacements: 0,
                withheld: false,
            };
        }
        let keep = self.pending.len() - hold;
        let (ready, tail) = self.pending.split_at(keep);
        let result = self.scrubber.scrub(ready, held_secret);
        self.pending = tail.to_vec();
        result
    }

    /// Flush whatever is held back.
    pub fn finish(&mut self, held_secret: bool) -> ScrubResult {
        let pending = std::mem::take(&mut self.pending);
        self.scrubber.scrub(&pending, held_secret)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &[u8] = b"sk-live-abcd1234";

    fn scrubber() -> Scrubber {
        Scrubber::build([("openai", SECRET)])
    }

    #[test]
    fn replaces_plaintext_secret() {
        let out = scrubber().scrub(b"key is sk-live-abcd1234 ok", true);
        assert_eq!(out.output, b"key is {{openai}} ok" as &[u8]);
        assert_eq!(out.replacements, 1);
        assert!(!out.withheld);
    }

    #[test]
    fn replaces_base64_form() {
        let encoded = {
            use base64::Engine;
            base64::engine::general_purpose::STANDARD.encode(SECRET)
        };
        let out = scrubber().scrub(format!("token {encoded}!").as_bytes(), true);
        assert_eq!(out.output, b"token {{openai}}!" as &[u8]);
    }

    #[test]
    fn replaces_hex_forms() {
        let lower = hex::encode(SECRET);
        let upper = hex::encode_upper(SECRET);
        let out = scrubber().scrub(format!("{lower}/{upper}").as_bytes(), true);
        assert_eq!(out.output, b"{{openai}}/{{openai}}" as &[u8]);
    }

    #[test]
    fn replaces_url_encoded_form() {
        // Percent-encoding of a plain ASCII secret is identity, so use one
        // with characters that actually encode.
        let secret: &[u8] = b"p@ss word+9";
        let s = Scrubber::build([("db", secret)]);
        let encoded = percent_encoding::utf8_percent_encode(
            std::str::from_utf8(secret).unwrap(),
            percent_encoding::NON_ALPHANUMERIC,
        )
        .to_string();
        let out = s.scrub(format!("echo {encoded}").as_bytes(), true);
        assert_eq!(out.output, b"echo {{db}}" as &[u8]);
    }

    #[test]
    fn withholds_binary_when_secret_held() {
        let binary = [0x00, 0x01, 0x02, 0xff, 0xfe];
        let out = scrubber().scrub(&binary, true);
        assert!(out.withheld);
        assert!(out.output.is_empty());
    }

    #[test]
    fn passes_binary_when_no_secret_held() {
        let binary = [0x00, 0x01, 0x02, 0xff, 0xfe];
        let out = scrubber().scrub(&binary, false);
        assert!(!out.withheld);
        assert_eq!(out.output, binary.to_vec());
    }

    #[test]
    fn plain_text_without_secrets_passes_through() {
        let out = scrubber().scrub(b"all clear, 42 files", false);
        assert_eq!(out.output, b"all clear, 42 files");
        assert_eq!(out.replacements, 0);
    }

    #[test]
    fn stream_handles_secret_split_across_chunks() {
        let s = scrubber();
        let mut stream = s.stream();
        let secret_start = b"prefix sk-liv";
        let secret_end = b"e-abcd1234 suffix";
        let a = stream.feed(secret_start, true);
        let b = stream.feed(secret_end, true);
        let c = stream.finish(true);
        let joined = [a.output, b.output, c.output].concat();
        assert_eq!(joined, b"prefix {{openai}} suffix" as &[u8]);
        assert!(a.replacements + b.replacements + c.replacements >= 1);
    }

    #[test]
    fn empty_scrubber_is_passthrough() {
        let s = Scrubber::build(Vec::<(&str, &[u8])>::new());
        let out = s.scrub(b"anything at all", true);
        assert_eq!(out.output, b"anything at all");
    }

    #[test]
    fn multiple_aliases_both_replaced() {
        let s = Scrubber::build([("openai", SECRET), ("db", b"postgres-pw-777" as &[u8])]);
        let out = s.scrub(b"sk-live-abcd1234 and postgres-pw-777", true);
        assert_eq!(out.output, b"{{openai}} and {{db}}" as &[u8]);
    }
}
