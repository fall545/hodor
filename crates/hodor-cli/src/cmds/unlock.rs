//! `hodor unlock`: verify the master passphrase and show vault summary.
//! One-shot by design — the CLI wipes the key at process exit; the
//! long-lived unlocked daemon arrives in M2.

use anyhow::Result;

use super::commit;
use crate::cmds::unlock_vault;
use crate::config::Config;
use crate::i18n::Msgs;
use hodor_core::audit::AuditEvent;

pub fn run(msgs: &Msgs, cfg: &Config, session: &str) -> Result<()> {
    let mut unlocked = unlock_vault(msgs, cfg)?;
    let count = unlocked.content.objects.len().to_string();
    let head = unlocked.content.audit_head[..16].to_string();
    println!(
        "{}",
        msgs.get("unlock-ok", &[("count", &count), ("head", &head)])
    );
    commit(&mut unlocked, session, AuditEvent::Unlocked, "cli unlock")?;
    let _ = unlocked.lock();
    Ok(())
}
