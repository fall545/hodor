//! `{{alias}}` template resolution (R13).
//!
//! Inside a hodor-brokered command, `{{name}}` is *always* an object
//! reference: unknown or empty references fail closed, so a typo can never
//! turn into a literal string reaching the command line.

use crate::error::{CoreError, Result};

/// Resolve every `{{alias}}` in `arg` through `lookup`.
/// Returns `UnknownAlias` for any reference `lookup` cannot satisfy.
pub fn fill_template(arg: &str, lookup: &dyn Fn(&str) -> Option<String>) -> Result<String> {
    let mut out = String::with_capacity(arg.len());
    let mut rest = arg;
    while let Some(start) = rest.find("{{") {
        out.push_str(&rest[..start]);
        let inner_from = start + 2;
        let Some(inner) = rest[inner_from..].find("}}") else {
            // Unterminated "{{": treat the remainder as literal text.
            out.push_str(&rest[start..]);
            return Ok(out);
        };
        let alias = rest[inner_from..inner_from + inner].trim();
        let Some(value) = lookup(alias) else {
            return Err(CoreError::UnknownAlias(alias.to_string()));
        };
        out.push_str(&value);
        rest = &rest[inner_from + inner + 2..];
    }
    out.push_str(rest);
    Ok(out)
}

/// List alias references in `arg` without resolving them (for auditing).
pub fn extract_aliases(arg: &str) -> Vec<String> {
    let mut found = Vec::new();
    let mut rest = arg;
    while let Some(start) = rest.find("{{") {
        let inner_from = start + 2;
        let Some(inner) = rest[inner_from..].find("}}") else {
            break;
        };
        found.push(rest[inner_from..inner_from + inner].trim().to_string());
        rest = &rest[inner_from + inner + 2..];
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lookup(name: &str) -> Option<String> {
        (name == "openai").then(|| "sk-test-123456".to_string())
    }

    #[test]
    fn substitutes_known_alias() {
        let out = fill_template("Bearer {{openai}}!", &lookup).unwrap();
        assert_eq!(out, "Bearer sk-test-123456!");
    }

    #[test]
    fn substitutes_multiple_aliases_in_one_arg() {
        let out = fill_template("{{openai}}+{{openai}}", &lookup).unwrap();
        assert_eq!(out, "sk-test-123456+sk-test-123456");
    }

    #[test]
    fn passes_plain_args_through() {
        assert_eq!(
            fill_template("ls -la /tmp", &lookup).unwrap(),
            "ls -la /tmp"
        );
    }

    #[test]
    fn unknown_alias_fails_closed() {
        let err = fill_template("{{nope}}", &lookup).unwrap_err();
        assert!(matches!(err, CoreError::UnknownAlias(a) if a == "nope"));
    }

    #[test]
    fn unterminated_brace_stays_literal() {
        assert_eq!(fill_template("a {{b", &lookup).unwrap(), "a {{b");
    }

    #[test]
    fn extract_lists_references() {
        let refs = extract_aliases("x {{openai}} y {{ ghost }}");
        assert_eq!(refs, vec!["openai", "ghost"]);
    }
}
