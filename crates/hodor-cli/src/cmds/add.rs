//! `hodor add sudo|ssh|api-key|token <alias>`: store a secret via pinentry/
//! TTY. The value never appears in argv, history, or process listings.

use anyhow::{bail, Result};
use zeroize::Zeroizing;

use super::{ask_secret, askpass_for, commit, unlock_vault};
use crate::config::Config;
use crate::i18n::Msgs;
use hodor_core::audit::AuditEvent;
use hodor_core::object::{ConfirmMode, HodorObject, ObjectKind, ObjectPolicy};

pub fn run(msgs: &Msgs, cfg: &Config, session: &str, alias: &str, kind: ObjectKind) -> Result<()> {
    let mut unlocked = unlock_vault(msgs, cfg)?;
    if unlocked.content.objects.iter().any(|o| o.alias == alias) {
        bail!(msgs.get("object-exists", &[("alias", alias)]));
    }
    let ask = askpass_for(&unlocked.content, cfg);
    let secret = read_value_twice(msgs, &ask, alias)?;

    let object = HodorObject {
        alias: alias.to_string(),
        kind,
        secret: hodor_core::object::SecretString::new(secret.as_str()),
        policy: ObjectPolicy {
            allowed_agents: Vec::new(),
            confirm: ConfirmMode::Always,
            uses: HodorObject::uses_default_for(kind),
            ttl_secs: None,
            max_uses: None,
            expires_at: None,
        },
    };
    unlocked.content.objects.push(object);
    let detail = format!("alias={alias} kind={}", kind.as_str());
    commit(&mut unlocked, session, AuditEvent::ObjectAdded, &detail)?;
    println!(
        "{}",
        msgs.get("object-added", &[("alias", alias), ("kind", kind.as_str())])
    );
    let _ = unlocked.lock();
    Ok(())
}

fn read_value_twice(
    msgs: &Msgs,
    ask: &hodor_askpass::AskPass,
    alias: &str,
) -> Result<Zeroizing<String>> {
    let first = ask_secret(
        ask,
        msgs,
        &msgs.get("add-value-prompt", &[("alias", alias)]),
    )?;
    let second = ask_secret(ask, msgs, &msgs.get("add-value-again", &[("alias", alias)]))?;
    if first.as_str() != second.as_str() {
        bail!(msgs.get("add-value-mismatch", &[]));
    }
    Ok(first)
}
