//! `hodor init`: create the vault, set passphrase and anti-phishing phrase.

use anyhow::{bail, Context, Result};
use hodor_askpass::AskPass;
use hodor_core::audit::AuditEvent;
use hodor_core::vault::{self, UnlockedVault};
use hodor_core::{paths, CoreError};
use std::io::{BufRead, Write};
use zeroize::Zeroizing;

use super::{ask_secret, commit};
use crate::config::Config;
use crate::i18n::Msgs;

const MIN_PASSPHRASE_LEN: usize = 8;

pub fn run(msgs: &Msgs, cfg: &Config, session: &str) -> Result<()> {
    let path = paths::vault_path();
    if path.exists() {
        bail!(msgs.get("vault-exists", &[("path", &path.display().to_string())]));
    }
    let ask = AskPass::new(None, cfg.pinentry_opt());
    let passphrase = read_new_passphrase(msgs, &ask)?;
    let phrase = read_visible_line(msgs)?;

    vault::create(&path, &passphrase, &phrase)?;
    let unlocked = reopen_and_audit(&path, &passphrase, session)?;
    println!("{}", msgs.get("anti-phish-shown", &[("phrase", &phrase)]));
    println!(
        "{}",
        msgs.get("vault-created", &[("path", &path.display().to_string())])
    );
    let _ = unlocked.lock(); // wipes the DEK explicitly for this short-lived process
    Ok(())
}

/// Two matching hidden inputs; cancel or mismatch aborts before anything is
/// written to disk.
fn read_new_passphrase(msgs: &Msgs, ask: &AskPass) -> Result<Zeroizing<String>> {
    let first = ask_secret(ask, msgs, &msgs.get("passphrase-new", &[]))?;
    if first.as_str().len() < MIN_PASSPHRASE_LEN {
        bail!(msgs.get("passphrase-too-short", &[]));
    }
    let second = ask_secret(ask, msgs, &msgs.get("passphrase-confirm", &[]))?;
    if first.as_str() != second.as_str() {
        bail!(msgs.get("passphrase-mismatch", &[]));
    }
    Ok(first)
}

/// The anti-phishing phrase is echoed to the terminal: the user must be able
/// to read and memorize it. `init` is an interactive, human-only command, so
/// plain stdin is acceptable here.
fn read_visible_line(msgs: &Msgs) -> Result<String> {
    print!("{}: ", msgs.get("anti-phish-prompt", &[]));
    std::io::stdout().flush()?;
    let mut line = String::new();
    std::io::stdin()
        .lock()
        .read_line(&mut line)
        .context("stdin")?;
    let phrase = line.trim().to_string();
    if phrase.is_empty() {
        bail!(msgs.get("canceled", &[]));
    }
    Ok(phrase)
}

fn reopen_and_audit(
    path: &std::path::Path,
    passphrase: &str,
    session: &str,
) -> Result<UnlockedVault> {
    let mut unlocked = match vault::open(path, passphrase) {
        Ok(u) => u,
        Err(CoreError::WrongPassphrase) | Err(CoreError::VaultCorrupt(_)) => {
            // We created this vault seconds ago with this very passphrase.
            bail!("vault just created failed to open: {path:?}");
        }
        Err(e) => return Err(e.into()),
    };
    commit(
        &mut unlocked,
        session,
        AuditEvent::VaultCreated,
        "vault created",
    )?;
    Ok(unlocked)
}
