//! Bilingual message catalogs (R21/R24) via Fluent.
//!
//! Catalogs live in `/i18n/*.flt` at the repo root — single source of truth
//! shared by every future consumer (daemon, dialogs, VSCode extension).

use fluent::{FluentArgs, FluentBundle, FluentResource, FluentValue};
use unic_langid::LanguageIdentifier;

use crate::config::Config;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Lang {
    En,
    Zh,
}

/// CLI help text stays English until M6 wires Fluent into clap; every other
/// user-facing string goes through [`Msgs`].
pub fn resolve(cli_override: Option<&str>, cfg: &Config) -> Lang {
    let from_cfg = |v: &str| match v {
        "zh" => Some(Lang::Zh),
        "en" => Some(Lang::En),
        _ => None,
    };
    if let Some(lang) = cli_override.and_then(from_cfg) {
        return lang;
    }
    if let Some(lang) = from_cfg(&cfg.lang) {
        return lang;
    }
    // "auto": follow the system locale.
    match std::env::var("LANG")
        .unwrap_or_default()
        .to_lowercase()
        .contains("zh")
    {
        true => Lang::Zh,
        false => Lang::En,
    }
}

pub struct Msgs {
    bundle: FluentBundle<FluentResource>,
}

impl Msgs {
    pub fn load(lang: Lang) -> Self {
        let (source, tag) = match lang {
            Lang::En => (include_str!("../../../i18n/en-US.flt"), "en-US"),
            Lang::Zh => (include_str!("../../../i18n/zh-CN.flt"), "zh-CN"),
        };
        let resource = FluentResource::try_new(source.to_owned())
            .unwrap_or_else(|e| panic!("bundled catalog {tag} must parse: {e:?}"));
        let langid: LanguageIdentifier = tag.parse().expect("static langid");
        let mut bundle = FluentBundle::new(vec![langid]);
        // Terminal output: skip Fluent's invisible bidi-isolation marks
        // around interpolations; they render as noise in terminals.
        bundle.set_use_isolating(false);
        bundle
            .add_resource(resource)
            .unwrap_or_else(|e| panic!("bundled catalog {tag} must load: {e:?}"));
        Self { bundle }
    }

    /// Localized message. Dynamic values ride alongside the sentence in the
    /// caller, not inside it, so catalogs stay interpolation-light.
    pub fn get<'a>(&self, key: &str, args: &[(&'a str, &'a str)]) -> String {
        let Some(message) = self.bundle.get_message(key) else {
            return format!("<{key}>");
        };
        let Some(pattern) = message.value() else {
            return format!("<{key}>");
        };
        let mut fluent_args = FluentArgs::new();
        for &(name, value) in args {
            fluent_args.set(name, FluentValue::from(value));
        }
        let mut errors = Vec::new();
        let formatted = self
            .bundle
            .format_pattern(pattern, Some(&fluent_args), &mut errors);
        formatted.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn both_catalogs_load_every_key() {
        for lang in [Lang::En, Lang::Zh] {
            let msgs = Msgs::load(lang);
            for key in ["vault-created", "unlock-ok", "run-denied", "canceled"] {
                let rendered = msgs.get(key, &[]);
                assert!(!rendered.starts_with('<'), "{lang:?} missing {key}");
            }
        }
    }

    #[test]
    fn placeholders_interpolate() {
        let msgs = Msgs::load(Lang::En);
        let rendered = msgs.get("object-added", &[("alias", "openai"), ("kind", "api-key")]);
        assert!(rendered.contains("openai"), "got: {rendered}");
        assert!(rendered.contains("api-key"), "got: {rendered}");
    }
}
