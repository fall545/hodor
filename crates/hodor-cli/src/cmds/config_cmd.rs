//! `hodor config set|get`: plain-text preference management.

use anyhow::{bail, Result};

use crate::config::{self, SetError};
use crate::i18n::Msgs;

pub fn set(msgs: &Msgs, key: &str, value: &str) -> Result<()> {
    let mut cfg = config::load()?;
    if let Err(error) = config::set_key(&mut cfg, key, value) {
        bail!(localize_set_error(msgs, error));
    }
    let path = config::save(&cfg)?;
    println!(
        "{}",
        msgs.get("config-saved", &[("path", &path.display().to_string())])
    );
    Ok(())
}

pub fn get(key: &str) -> Result<()> {
    let cfg = config::load()?;
    let value = match key {
        "lang" => cfg.lang.clone(),
        "require-presence" => on_off(cfg.require_presence),
        "auto-lock-minutes" => cfg.auto_lock_minutes.to_string(),
        "pinentry" => cfg.pinentry.clone(),
        _ => bail!("unknown key: {key}"),
    };
    println!("{value}");
    Ok(())
}

fn localize_set_error(msgs: &Msgs, error: SetError) -> String {
    match error {
        SetError::UnknownKey(key) => msgs.get("config-unknown-key", &[("key", &key)]),
        SetError::BadValue { key, value } => {
            msgs.get("config-bad-value", &[("key", &key), ("value", &value)])
        }
    }
}

fn on_off(flag: bool) -> String {
    if flag { "on" } else { "off" }.to_string()
}
