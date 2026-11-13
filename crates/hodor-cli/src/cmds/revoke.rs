//! `hodor revoke <alias>`: remove an object from the vault.

use anyhow::{bail, Result};

use super::{commit, unlock_vault};
use crate::config::Config;
use crate::i18n::Msgs;
use hodor_core::audit::AuditEvent;

pub fn run(msgs: &Msgs, cfg: &Config, session: &str, alias: &str) -> Result<()> {
    let mut unlocked = unlock_vault(msgs, cfg)?;
    let Some(position) = unlocked
        .content
        .objects
        .iter()
        .position(|o| o.alias == alias)
    else {
        bail!(msgs.get("alias-missing", &[("alias", alias)]));
    };
    unlocked.content.objects.remove(position);
    commit(
        &mut unlocked,
        session,
        AuditEvent::ObjectRevoked,
        &format!("alias={alias}"),
    )?;
    println!("{}", msgs.get("object-revoked", &[("alias", alias)]));
    let _ = unlocked.lock();
    Ok(())
}
