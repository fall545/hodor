//! `hodor run -- <command with {{alias}} refs>`: manual brokered execution.
//!
//! The human typing the command *is* the approval, but the policy engine
//! still runs: the hard blacklist refuses even the owner (nothing stops the
//! owner from running passwd in their own shell — outside Hodor's channel).

use anyhow::{bail, Result};
use std::process::Command;

use super::{commit, unlock_vault};
use crate::config::Config;
use crate::i18n::Msgs;
use hodor_core::audit::AuditEvent;
use hodor_core::object::HodorObject;
use hodor_core::templates::{extract_aliases, fill_template};
use hodor_core::CoreError;
use hodor_policy::normalize::normalize;
use hodor_policy::{evaluate, Decision, PolicyData};

pub fn run(msgs: &Msgs, cfg: &Config, session: &str, args: &[String]) -> Result<()> {
    if args.is_empty() {
        bail!(msgs.get("run-empty", &[]));
    }
    let mut unlocked = unlock_vault(msgs, cfg)?;

    let mut resolved = Vec::with_capacity(args.len());
    for arg in args {
        resolved.push(resolve_arg(msgs, &unlocked.content.objects, arg)?);
    }

    let policy = PolicyData {
        user_blacklist: unlocked.content.user_blacklist.clone(),
        whitelist: unlocked.content.whitelist.clone(),
    };
    let detail = format!("template: {}", args.join(" "));
    match evaluate(&normalize(&resolved), &policy) {
        Decision::HardDenied(category) => {
            commit(&mut unlocked, session, AuditEvent::CommandDenied, &detail)?;
            bail!(msgs.get("run-denied", &[("category", &category.to_string())]));
        }
        Decision::UserDenied(pattern) => {
            bail!(msgs.get("run-denied", &[("category", &pattern)]));
        }
        Decision::Whitelisted | Decision::Ask => {}
    }
    commit(
        &mut unlocked,
        session,
        AuditEvent::CommandRequested,
        &detail,
    )?;
    commit(&mut unlocked, session, AuditEvent::CommandApproved, &detail)?;

    let status = Command::new(&resolved[0]).args(&resolved[1..]).status()?;
    println!(
        "{}",
        msgs.get(
            "run-status",
            &[("code", &status.code().unwrap_or(-1).to_string())]
        )
    );
    let _ = unlocked.lock();
    Ok(())
}

/// Substitute `{{alias}}` in one argument, with use-permission and
/// unknown-alias errors localized at this boundary.
fn resolve_arg(msgs: &Msgs, objects: &[HodorObject], arg: &str) -> Result<String> {
    for alias in extract_aliases(arg) {
        if let Some(object) = objects.iter().find(|o| o.alias == alias) {
            if !object.policy.uses.exec {
                bail!(msgs.get(
                    "run-not-executable",
                    &[("alias", &alias), ("uses", &object.policy.uses.summary())]
                ));
            }
        }
    }
    let lookup = |alias: &str| -> Option<String> {
        objects
            .iter()
            .find(|o| o.alias == alias)
            .map(|o| o.secret.expose().to_string())
    };
    match fill_template(arg, &lookup) {
        Ok(value) => Ok(value),
        Err(CoreError::UnknownAlias(alias)) => {
            bail!(msgs.get("run-unknown-alias", &[("alias", &alias)]));
        }
        Err(e) => bail!("{e}"),
    }
}
