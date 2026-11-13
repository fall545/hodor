//! The evaluation engine (DESIGN §5.4): fixed order, earlier layers veto
//! later ones — `hard deny → user deny → whitelist → ask`.

use crate::blacklist::{hard_deny, DenyCategory};
use crate::normalize::{basename, command_hash, NormalizedCommand};

/// Vault-sourced policy inputs (blacklist layer 2 and the whitelist layer 3).
#[derive(Clone, Debug, Default)]
pub struct PolicyData {
    /// User-extensible deny patterns, stored encrypted in the vault.
    pub user_blacklist: Vec<String>,
    /// Exact-command hashes approved to skip asking.
    pub whitelist: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Decision {
    /// Layer 1, non-overridable.
    HardDenied(DenyCategory),
    /// Layer 2, user-configured.
    UserDenied(String),
    /// Layer 3: exact hash match, runs without prompting.
    Whitelisted,
    /// No layer matched: ask the human.
    Ask,
}

pub fn evaluate(nc: &NormalizedCommand, policy: &PolicyData) -> Decision {
    if let Some(category) = hard_deny(nc) {
        return Decision::HardDenied(category);
    }
    if let Some(pattern) = user_deny(nc, policy) {
        return Decision::UserDenied(pattern);
    }
    let hash = command_hash(&nc.argv);
    if policy.whitelist.iter().any(|w| w == &hash) {
        return Decision::Whitelisted;
    }
    Decision::Ask
}

/// Pattern semantics (kept deliberately simple, documented for users):
/// a pattern matches when it equals the binary basename, or when it is an
/// absolute path prefix hit on any argument (same rules as the hard layer).
fn user_deny(nc: &NormalizedCommand, policy: &PolicyData) -> Option<String> {
    if nc.argv.is_empty() {
        return None;
    }
    let base = basename(&nc.binary);
    if let Some(hit) = policy.user_blacklist.iter().find(|p| p.as_str() == base) {
        return Some(hit.clone());
    }
    policy
        .user_blacklist
        .iter()
        .find(|p| p.starts_with('/') && nc.argv[1..].iter().any(|a| a.starts_with(p.as_str())))
        .cloned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::normalize::normalize;

    fn nc(items: &[&str]) -> NormalizedCommand {
        normalize(&items.iter().map(|s| s.to_string()).collect::<Vec<_>>())
    }

    fn sv(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn order_hard_deny_beats_everything() {
        let policy = PolicyData {
            user_blacklist: vec![],
            whitelist: vec![command_hash(&sv(&["passwd"]))],
        };
        assert_eq!(
            evaluate(&nc(&["passwd"]), &policy),
            Decision::HardDenied(DenyCategory::CredentialReset)
        );
    }

    #[test]
    fn user_deny_beats_whitelist() {
        let policy = PolicyData {
            user_blacklist: vec!["telemetry-agent".into()],
            whitelist: vec![command_hash(&sv(&["telemetry-agent", "--run"]))],
        };
        assert_eq!(
            evaluate(&nc(&["telemetry-agent", "--run"]), &policy),
            Decision::UserDenied("telemetry-agent".into())
        );
    }

    #[test]
    fn whitelist_matches_exact_argv_only() {
        let policy = PolicyData {
            user_blacklist: vec![],
            whitelist: vec![command_hash(&sv(&["apt", "install", "-y", "htop"]))],
        };
        assert_eq!(
            evaluate(&nc(&["apt", "install", "-y", "htop"]), &policy),
            Decision::Whitelisted
        );
        assert_eq!(
            evaluate(&nc(&["apt", "install", "-y", "nano"]), &policy),
            Decision::Ask
        );
    }

    #[test]
    fn unknown_commands_ask() {
        assert_eq!(
            evaluate(&nc(&["ls", "-la"]), &PolicyData::default()),
            Decision::Ask
        );
    }

    #[test]
    fn user_path_prefix_deny() {
        let policy = PolicyData {
            user_blacklist: vec!["/srv/prod-db".into()],
            whitelist: vec![],
        };
        assert_eq!(
            evaluate(&nc(&["cat", "/srv/prod-db/config"]), &policy),
            Decision::UserDenied("/srv/prod-db".into())
        );
    }
}
