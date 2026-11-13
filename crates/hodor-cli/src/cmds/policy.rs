//! `hodor policy <alias> set ...`: adjust one object's policy in the vault.

use anyhow::{bail, Result};

use super::{commit, unlock_vault};
use crate::config::Config;
use crate::i18n::Msgs;
use hodor_core::audit::AuditEvent;
use hodor_core::object::{ConfirmMode, UseSet};

pub struct PolicyChange {
    pub confirm: Option<String>,
    pub ttl: Option<String>,
    pub max_uses: Option<u64>,
    pub agents: Option<String>,
    pub uses: Option<String>,
}

pub fn run(
    msgs: &Msgs,
    cfg: &Config,
    session: &str,
    alias: &str,
    change: PolicyChange,
) -> Result<()> {
    let mut unlocked = unlock_vault(msgs, cfg)?;
    let Some(object) = unlocked
        .content
        .objects
        .iter_mut()
        .find(|o| o.alias == alias)
    else {
        bail!(msgs.get("alias-missing", &[("alias", alias)]));
    };
    let policy = &mut object.policy;
    if let Some(confirm) = &change.confirm {
        policy.confirm = parse_confirm(msgs, confirm)?;
    }
    if let Some(ttl) = &change.ttl {
        policy.ttl_secs = Some(parse_duration(ttl)?);
    }
    if let Some(max_uses) = change.max_uses {
        policy.max_uses = Some(max_uses);
    }
    if let Some(agents) = &change.agents {
        policy.allowed_agents = split_list(agents);
    }
    if let Some(uses) = &change.uses {
        policy.uses = parse_uses(uses)?;
    }
    let detail = format!("alias={alias} policy updated");
    commit(&mut unlocked, session, AuditEvent::PolicyChanged, &detail)?;
    println!("{}", msgs.get("policy-updated", &[("alias", alias)]));
    let _ = unlocked.lock();
    Ok(())
}

fn parse_confirm(msgs: &Msgs, value: &str) -> Result<ConfirmMode> {
    match value {
        "always" => Ok(ConfirmMode::Always),
        "task" => Ok(ConfirmMode::Task),
        "whitelisted" => Ok(ConfirmMode::Whitelisted),
        _ => bail!(msgs.get("policy-unknown-kind", &[("value", value)])),
    }
}

/// `30m` → 1800, `2h` → 7200, plain digits are seconds.
fn parse_duration(value: &str) -> Result<u64> {
    // Plain digits mean seconds.
    if !value.is_empty() && value.chars().all(|c| c.is_ascii_digit()) {
        return value
            .parse()
            .map_err(|_| anyhow::anyhow!("bad duration: {value}"));
    }
    let (digits, unit) = value.split_at(value.len().saturating_sub(1));
    let amount: u64 = digits
        .parse()
        .map_err(|_| anyhow::anyhow!("bad duration: {value}"))?;
    let mul = match unit {
        "s" => 1,
        "m" => 60,
        "h" => 3600,
        "d" => 86400,
        _ => bail!("{value}: unknown unit (s|m|h|d)"),
    };
    amount
        .checked_mul(mul)
        .ok_or_else(|| anyhow::anyhow!("duration overflow: {value}"))
}

fn split_list(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect()
}

fn parse_uses(value: &str) -> Result<UseSet> {
    let mut uses = UseSet::default();
    for item in split_list(value) {
        match item.as_str() {
            "exec" => uses.exec = true,
            "http" => uses.http = true,
            "ssh" => uses.ssh = true,
            _ => bail!("{item}: unknown use (exec|http|ssh)"),
        }
    }
    Ok(uses)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn duration_units() {
        assert_eq!(parse_duration("30m").unwrap(), 1800);
        assert_eq!(parse_duration("2h").unwrap(), 7200);
        assert_eq!(parse_duration("90").unwrap(), 90);
        assert!(parse_duration("1x").is_err());
    }

    #[test]
    fn use_list_parsing() {
        let uses = parse_uses("exec, http").unwrap();
        assert!(uses.exec && uses.http && !uses.ssh);
    }
}
