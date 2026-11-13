//! `hodor status`: vault presence and config summary. Never requires the
//! passphrase, never prints object names or counts.

use anyhow::Result;
use hodor_core::paths;

use crate::config::Config;
use crate::i18n::Msgs;

pub fn run(msgs: &Msgs, cfg: &Config) -> Result<()> {
    println!("{}", msgs.get("status-header", &[]));
    let vault = paths::vault_path();
    println!(
        "{}",
        msgs.get("status-vault", &[("path", &vault.display().to_string())])
    );
    if vault.exists() {
        println!("{}", msgs.get("status-locked", &[]));
    }
    let presence = if cfg.require_presence { "on" } else { "off" };
    println!(
        "{}",
        msgs.get(
            "status-config",
            &[("lang", &cfg.lang), ("presence", presence)]
        )
    );
    Ok(())
}
