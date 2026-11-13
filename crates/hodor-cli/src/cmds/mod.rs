//! Shared command plumbing: unlock flow, askpass wiring, audit-and-save.

pub mod add;
pub mod audit;
pub mod config_cmd;
pub mod init;
pub mod list;
pub mod lock;
pub mod policy;
pub mod revoke;
pub mod run;
pub mod status;
pub mod unlock;

use anyhow::{bail, Context, Result};
use hodor_askpass::{AskError, AskPass};
use hodor_core::audit::AuditEvent;
use hodor_core::biometric::PresenceResult;
use hodor_core::vault::{self, UnlockedVault, VaultContent};
use hodor_core::{paths, CoreError};
use zeroize::Zeroizing;

use crate::config::Config;
use crate::i18n::Msgs;

/// Ask for a secret out-of-band; cancel and terminal-less are distinct,
/// localized outcomes. All commands go through here — never stdin.
pub fn ask_secret(ask: &AskPass, msgs: &Msgs, prompt: &str) -> Result<Zeroizing<String>> {
    match ask.ask(prompt) {
        Ok(Some(value)) => Ok(value),
        Ok(None) => bail!(msgs.get("canceled", &[])),
        Err(AskError::NoTerminal) => bail!(msgs.get("no-input-tty", &[])),
        Err(e) => Err(e.into()),
    }
}

/// Unlock the vault: optional fingerprint presence factor, then the master
/// passphrase via pinentry/TTY — never agent-controlled stdin.
pub fn unlock_vault(msgs: &Msgs, cfg: &Config) -> Result<UnlockedVault> {
    let path = paths::vault_path();
    if !path.exists() {
        bail!(msgs.get("vault-missing", &[("path", &path.display().to_string())]));
    }
    if cfg.require_presence && !presence_gate(msgs)? {
        bail!(msgs.get("unlock-failed", &[]));
    }
    // No anti-phish phrase yet: it lives inside the vault being unlocked.
    let ask = AskPass::new(None, cfg.pinentry_opt());
    let passphrase = ask_secret(&ask, msgs, &msgs.get("passphrase-prompt", &[]))?;
    match vault::open(&path, &passphrase) {
        Ok(unlocked) => Ok(unlocked),
        Err(CoreError::WrongPassphrase) | Err(CoreError::VaultCorrupt(_)) => {
            bail!(msgs.get("unlock-failed", &[]));
        }
        Err(e) => Err(e.into()),
    }
}

/// Build an askpass bound to a vault whose content is already decrypted, so
/// every subsequent prompt shows the anti-phishing phrase.
pub fn askpass_for(content: &VaultContent, cfg: &Config) -> AskPass {
    AskPass::new(Some(content.anti_phish.clone()), cfg.pinentry_opt())
}

/// Append an audit entry and persist the new chain head in the vault.
pub fn commit(
    unlocked: &mut UnlockedVault,
    session: &str,
    event: AuditEvent,
    detail: &str,
) -> Result<()> {
    let vault_path = paths::vault_path();
    let audit_path = paths::audit_path();
    hodor_core::audit::append(
        &audit_path,
        &mut unlocked.content.audit_head,
        event,
        session,
        detail,
    )
    .context("audit append")?;
    unlocked.save(&vault_path).context("vault save")?;
    Ok(())
}

/// Returns true when presence is verified. A configured factor that cannot
/// run is a hard error: an unlock factor that silently degrades is a hole.
fn presence_gate(msgs: &Msgs) -> Result<bool> {
    println!("{}", msgs.get("presence-start", &[]));
    let verifier = hodor_core::biometric::default_verifier();
    match verifier.verify("hodor unlock")? {
        PresenceResult::Verified => {
            println!("{}", msgs.get("presence-ok", &[]));
            Ok(true)
        }
        PresenceResult::Denied => {
            println!("{}", msgs.get("presence-failed", &[]));
            Ok(false)
        }
        PresenceResult::Unavailable(reason) => {
            bail!(msgs.get("presence-unavailable", &[("reason", &reason)]));
        }
    }
}
