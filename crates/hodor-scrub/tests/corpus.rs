//! Golden corpus (AGENTS.md: any change to detection logic must extend this
//! corpus with the case that motivated it).
//!
//! Scenario files live in `corpus/`. The `input` field may embed
//! `{{form:alias}}` where form is plain|b64|hex|hexupper|url; the loader
//! expands it with the encoding crates directly, so a regression in
//! `hodor_scrub::patterns` cannot hide behind a hand-computed expectation.

use base64::Engine;
use hodor_scrub::Scrubber;
use serde::Deserialize;

#[derive(Deserialize)]
struct Case {
    name: String,
    secrets: std::collections::BTreeMap<String, String>,
    #[serde(default)]
    held_secret: bool,
    #[serde(default)]
    input: String,
    #[serde(default)]
    input_b64: String,
    #[serde(default)]
    expect: String,
    #[serde(default)]
    expect_withheld: bool,
    #[serde(default)]
    expect_replacements: usize,
}

fn expand(template: &str, secrets: &std::collections::BTreeMap<String, String>) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::new();
    let mut rest = template;
    while let Some(start) = rest.find("{{") {
        out.extend_from_slice(&rest.as_bytes()[..start]);
        let after = &rest[start + 2..];
        let end = after.find("}}").expect("unbalanced corpus placeholder");
        let spec = &after[..end];
        let (form, alias) = spec.split_once(':').expect("placeholder form:alias");
        let value = secrets[alias].as_bytes();
        let encoded: Vec<u8> = match form {
            "plain" => value.to_vec(),
            "b64" => base64::engine::general_purpose::STANDARD
                .encode(value)
                .into_bytes(),
            "hex" => hex::encode(value).into_bytes(),
            "hexupper" => hex::encode_upper(value).into_bytes(),
            "url" => percent_encoding::utf8_percent_encode(
                std::str::from_utf8(value).unwrap(),
                percent_encoding::NON_ALPHANUMERIC,
            )
            .to_string()
            .into_bytes(),
            other => panic!("unknown corpus form {other}"),
        };
        out.extend_from_slice(&encoded);
        rest = &after[end + 2..];
    }
    out.extend_from_slice(rest.as_bytes());
    out
}

#[test]
fn golden_corpus() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/corpus");
    let mut files: Vec<_> = std::fs::read_dir(&dir)
        .expect("corpus dir")
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|e| e == "json"))
        .collect();
    files.sort();
    assert!(!files.is_empty(), "corpus must not be empty");

    for file in files {
        let raw = std::fs::read_to_string(&file).unwrap();
        let case: Case =
            serde_json::from_str(&raw).unwrap_or_else(|e| panic!("{}: {e}", file.display()));
        let scrubber = Scrubber::build(
            case.secrets
                .iter()
                .map(|(alias, value)| (alias.as_str(), value.as_bytes())),
        );
        let input = if !case.input_b64.is_empty() {
            base64::engine::general_purpose::STANDARD
                .decode(&case.input_b64)
                .unwrap()
        } else {
            expand(&case.input, &case.secrets)
        };
        let result = scrubber.scrub(&input, case.held_secret);
        assert_eq!(
            result.withheld, case.expect_withheld,
            "{}: withheld",
            case.name
        );
        assert_eq!(
            result.replacements, case.expect_replacements,
            "{}: replacements",
            case.name
        );
        if !case.expect.is_empty() {
            assert_eq!(
                result.output,
                case.expect.as_bytes(),
                "{}: output",
                case.name
            );
        }
    }
}
