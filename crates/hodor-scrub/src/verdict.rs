//! Heuristics for output we cannot reliably scan (DESIGN §5.6): such output is
//! withheld, never passed through, when the producing command held a secret.

/// Shannon entropy in bits per byte over the whole sample.
pub fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0usize; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let total = data.len() as f64;
    -counts
        .into_iter()
        .filter(|&c| c > 0)
        .map(|c| {
            let p = c as f64 / total;
            p * p.log2()
        })
        .sum::<f64>()
}

// Empirical anchors (bits/char, measured on this engine's samples):
// English ~4.2, source code ~5.0, random base64 ~5.5 (theoretical cap 6.0),
// random hex ~4.0 — hex is indistinguishable from prose by entropy, which is
// fine because the scanner matches hex forms of every secret directly.
// 5.4 therefore means "looks like a blob of encoded data, not human text";
// minified code occasionally trips this, which the DESIGN accepts as the
// safe-by-default direction.
const HIGH_ENTROPY_THRESHOLD: f64 = 5.4;
const HIGH_ENTROPY_MIN_LEN: usize = 64;

/// True when content is binary or high-entropy, i.e. we cannot prove it is
/// free of encoded secrets. Short inputs skip the entropy check: on tiny
/// samples entropy is noise, and NUL/invalid-UTF-8 already catch binaries.
pub fn looks_unanalyzable(data: &[u8]) -> bool {
    if data.is_empty() {
        return false;
    }
    if data.contains(&0u8) {
        return true;
    }
    if std::str::from_utf8(data).is_err() {
        return true;
    }
    data.len() >= HIGH_ENTROPY_MIN_LEN && shannon_entropy(data) > HIGH_ENTROPY_THRESHOLD
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn binary_content_with_nul() {
        assert!(looks_unanalyzable(b"ok\x00there"));
    }

    #[test]
    fn invalid_utf8_is_binary() {
        assert!(looks_unanalyzable(&[0xff, 0xfe, 0x80, 0x81]));
    }

    #[test]
    fn plain_text_passes() {
        assert!(!looks_unanalyzable(b"command succeeded: 42 files"));
    }

    #[test]
    fn english_text_passes_entropy() {
        let sample = b"the quick brown fox jumps over the lazy dog and then some more";
        assert!(!looks_unanalyzable(sample.as_slice()));
    }

    #[test]
    fn high_entropy_base64_blob_flagged() {
        let sample = b"q8Xz2Kp9RtVnB4mYc7LwE5sH3jD6fG1aU0iO2zN8xC4vM5bQ7wE9rT2yU3iO1pA6sD4fG7h";
        assert!(looks_unanalyzable(sample.as_slice()));
    }

    #[test]
    fn entropy_of_uniform_data_is_low() {
        assert!(shannon_entropy(b"aaaaaaaaaaaaaaaa") < 0.1);
    }
}
