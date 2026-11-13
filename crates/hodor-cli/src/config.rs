//! Plain-text preferences (`config.toml`). Never holds secret material —
//! anything sensitive lives in the encrypted vault.

use serde::{Deserialize, Serialize};
use std::fs;

use hodor_core::paths;

#[derive(Clone, Debug)]
pub struct Config {
    pub lang: String,
    pub require_presence: bool,
    pub auto_lock_minutes: u32,
    pub pinentry: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            lang: "auto".into(),
            require_presence: false,
            auto_lock_minutes: 15,
            pinentry: String::new(),
        }
    }
}

#[derive(Serialize, Deserialize, Default)]
struct ConfigFile {
    #[serde(default)]
    lang: String,
    #[serde(default)]
    require_presence: bool,
    #[serde(default)]
    auto_lock_minutes: Option<u32>,
    #[serde(default)]
    pinentry: String,
}

pub fn load() -> anyhow::Result<Config> {
    let path = paths::config_path();
    if !path.exists() {
        return Ok(Config::default());
    }
    let raw = fs::read_to_string(&path)?;
    let file: ConfigFile = toml::from_str(&raw)?;
    let defaults = Config::default();
    Ok(Config {
        lang: if file.lang.is_empty() {
            defaults.lang
        } else {
            file.lang
        },
        require_presence: file.require_presence,
        auto_lock_minutes: file.auto_lock_minutes.unwrap_or(defaults.auto_lock_minutes),
        pinentry: file.pinentry,
    })
}

pub fn save(cfg: &Config) -> anyhow::Result<std::path::PathBuf> {
    let path = paths::config_path();
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir)?;
    }
    let file = ConfigFile {
        lang: cfg.lang.clone(),
        require_presence: cfg.require_presence,
        auto_lock_minutes: Some(cfg.auto_lock_minutes),
        pinentry: cfg.pinentry.clone(),
    };
    fs::write(&path, toml::to_string_pretty(&file)?)?;
    Ok(path)
}

/// Assign one recognized key; unknown keys and unparsable values are
/// reported distinctly so typos never silently no-op.
pub enum SetError {
    UnknownKey(String),
    BadValue { key: String, value: String },
}

pub fn set_key(cfg: &mut Config, key: &str, value: &str) -> Result<(), SetError> {
    match key {
        "lang" if matches!(value, "auto" | "en" | "zh") => cfg.lang = value.to_string(),
        "require-presence" if matches!(value, "on" | "off" | "true" | "false") => {
            cfg.require_presence = matches!(value, "on" | "true");
        }
        "auto-lock-minutes" => {
            cfg.auto_lock_minutes = value.parse().map_err(|_| SetError::BadValue {
                key: key.into(),
                value: value.into(),
            })?
        }
        "pinentry" => cfg.pinentry = value.to_string(),
        _ => return Err(SetError::UnknownKey(key.into())),
    }
    Ok(())
}

impl Config {
    pub fn pinentry_opt(&self) -> Option<String> {
        Some(self.pinentry.clone()).filter(|p| !p.is_empty())
    }
}
