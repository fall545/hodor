//! Hard deny layer (blacklist layer 1): compiled in, non-overridable.
//!
//! This is the last line of defense against the most catastrophic commands
//! (DESIGN §5.4) — it never replaces the per-command human gate, it bounds
//! the blast radius of a rubber-stamped approval.

use std::fmt;

use crate::normalize::{basename, NormalizedCommand};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DenyCategory {
    /// `passwd`, `chage`, `chpasswd`: makes the stored sudo password stale or
    /// locks the user out.
    CredentialReset,
    /// `visudo`, user/group surgery, writes into /etc/sudoers* or /etc/pam.d/.
    PrivilegeTamper,
    /// Reading /etc/shadow or biometric templates: enables offline cracking.
    SecretPillage,
    /// Killing, replacing, or rewriting hodor's own processes and files.
    HodorSelfAttack,
    /// `su`, nested `sudo`, `pkexec`, `nsenter`, `unshare --map-root-user`.
    PrivEscalation,
}

impl fmt::Display for DenyCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::CredentialReset => "credential-reset",
            Self::PrivilegeTamper => "privilege-tamper",
            Self::SecretPillage => "secret-pillage",
            Self::HodorSelfAttack => "hodor-self-attack",
            Self::PrivEscalation => "priv-escalation",
        };
        f.write_str(name)
    }
}

const RESET_BINARIES: [&str; 3] = ["passwd", "chage", "chpasswd"];
const TAMPER_BINARIES: [&str; 3] = ["visudo", "useradd", "userdel"];
const ESCAPE_BINARIES: [&str; 3] = ["su", "pkexec", "nsenter"];

/// Layer 1 of the evaluation order. Returns the category when the command
/// must be refused regardless of any user configuration.
pub fn hard_deny(nc: &NormalizedCommand) -> Option<DenyCategory> {
    if nc.argv.is_empty() {
        return None;
    }
    let base = basename(&nc.binary);
    if RESET_BINARIES.contains(&base.as_str()) {
        return Some(DenyCategory::CredentialReset);
    }
    if TAMPER_BINARIES.contains(&base.as_str()) {
        return Some(DenyCategory::PrivilegeTamper);
    }
    if ESCAPE_BINARIES.contains(&base.as_str()) {
        return Some(DenyCategory::PrivEscalation);
    }
    // The supervisor already runs as root; nested sudo gains nothing but
    // another password prompt surface.
    if base == "sudo" {
        return Some(DenyCategory::PrivEscalation);
    }
    let rest = &nc.argv[1..];
    if base == "usermod" && argv_mentions(rest, &["sudo", "wheel"]) {
        return Some(DenyCategory::PrivilegeTamper);
    }
    if base == "unshare"
        && rest
            .iter()
            .any(|a| a.contains("map-root-user") || a == "-r")
    {
        return Some(DenyCategory::PrivEscalation);
    }
    if (base == "kill" || base == "pkill") && rest.iter().any(|a| a.contains("hodor")) {
        return Some(DenyCategory::HodorSelfAttack);
    }
    rest.iter().find_map(|arg| protected_path_hit(arg))
}

fn argv_mentions(args: &[String], needles: &[&str]) -> bool {
    args.iter().any(|a| needles.contains(&a.as_str()))
}

/// Any argv element that names a protected location. Elements that are not
/// paths cost one `starts_with` each; that is the whole false-positive risk.
fn protected_path_hit(arg: &str) -> Option<DenyCategory> {
    let candidate = if arg.starts_with('~') {
        let home = dirs::home_dir()?.to_string_lossy().into_owned();
        arg.replacen('~', &home, 1)
    } else {
        arg.to_string()
    };
    let candidate = std::fs::canonicalize(&candidate)
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or(candidate);
    for (prefix, category) in protected_prefixes() {
        if candidate == prefix || candidate.starts_with(&format!("{prefix}/")) {
            return Some(category);
        }
    }
    None
}

fn protected_prefixes() -> Vec<(String, DenyCategory)> {
    let mut prefixes = vec![
        ("/etc/sudoers".to_string(), DenyCategory::PrivilegeTamper),
        ("/etc/sudoers.d".to_string(), DenyCategory::PrivilegeTamper),
        ("/etc/pam.d".to_string(), DenyCategory::PrivilegeTamper),
        ("/etc/shadow".to_string(), DenyCategory::SecretPillage),
        ("/etc/gshadow".to_string(), DenyCategory::SecretPillage),
        ("/var/lib/fprint".to_string(), DenyCategory::SecretPillage),
        ("/usr/lib/hodor".to_string(), DenyCategory::HodorSelfAttack),
    ];
    if let Some(home) = dirs::home_dir() {
        let home = home.to_string_lossy().into_owned();
        prefixes.push((format!("{home}/.hodor"), DenyCategory::HodorSelfAttack));
        prefixes.push((
            format!("{home}/.config/hodor"),
            DenyCategory::HodorSelfAttack,
        ));
    }
    prefixes
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::normalize::normalize;

    fn nc(items: &[&str]) -> NormalizedCommand {
        normalize(&items.iter().map(|s| s.to_string()).collect::<Vec<_>>())
    }

    #[test]
    fn password_reset_denied() {
        for cmd in [
            &["passwd"][..],
            &["passwd", "root"][..],
            &["chage"],
            &["chpasswd"],
        ] {
            assert_eq!(
                hard_deny(&nc(cmd)),
                Some(DenyCategory::CredentialReset),
                "{cmd:?}"
            );
        }
    }

    #[test]
    fn privilege_tampering_denied() {
        assert_eq!(
            hard_deny(&nc(&["visudo"])),
            Some(DenyCategory::PrivilegeTamper)
        );
        assert_eq!(
            hard_deny(&nc(&["useradd", "evil"])),
            Some(DenyCategory::PrivilegeTamper)
        );
        assert_eq!(
            hard_deny(&nc(&["usermod", "-aG", "sudo", "evil"])),
            Some(DenyCategory::PrivilegeTamper)
        );
        // usermod without sudo/wheel is not auto-denied; it goes to Ask.
        assert_eq!(hard_deny(&nc(&["usermod", "-aG", "docker", "ci"])), None);
    }

    #[test]
    fn sudoers_write_via_other_tools_denied() {
        assert_eq!(
            hard_deny(&nc(&["tee", "/etc/sudoers.d/agent"])),
            Some(DenyCategory::PrivilegeTamper)
        );
        assert_eq!(
            hard_deny(&nc(&["cat", "/etc/sudoers"])),
            Some(DenyCategory::PrivilegeTamper)
        );
    }

    #[test]
    fn shadow_and_fprint_reads_denied() {
        assert_eq!(
            hard_deny(&nc(&["cat", "/etc/shadow"])),
            Some(DenyCategory::SecretPillage)
        );
        assert_eq!(
            hard_deny(&nc(&["cp", "/var/lib/fprint/leolize", "/tmp"])),
            Some(DenyCategory::SecretPillage)
        );
    }

    #[test]
    fn privilege_escalation_denied() {
        assert_eq!(
            hard_deny(&nc(&["su", "-"])),
            Some(DenyCategory::PrivEscalation)
        );
        assert_eq!(
            hard_deny(&nc(&["sudo", "apt", "update"])),
            Some(DenyCategory::PrivEscalation)
        );
        assert_eq!(
            hard_deny(&nc(&["pkexec", "bash"])),
            Some(DenyCategory::PrivEscalation)
        );
        assert_eq!(
            hard_deny(&nc(&["unshare", "--map-root-user", "id"])),
            Some(DenyCategory::PrivEscalation)
        );
    }

    #[test]
    fn hodor_self_attack_denied() {
        assert_eq!(
            hard_deny(&nc(&["pkill", "-9", "hodor-daemon"])),
            Some(DenyCategory::HodorSelfAttack)
        );
        let home = dirs::home_dir().unwrap();
        let vault = format!("{}/.hodor/vault.bin", home.display());
        assert_eq!(
            hard_deny(&nc(&["cp", &vault, "/tmp/steal"])),
            Some(DenyCategory::HodorSelfAttack)
        );
    }

    #[test]
    fn benign_commands_pass_to_next_layer() {
        assert_eq!(hard_deny(&nc(&["apt", "install", "-y", "htop"])), None);
        assert_eq!(hard_deny(&nc(&["systemctl", "restart", "nginx"])), None);
        assert_eq!(hard_deny(&nc(&["cat", "/etc/hostname"])), None);
    }
}
