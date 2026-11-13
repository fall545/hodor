//! Command normalization: argv as received, plus the wrapper/interpreter
//! features a reviewer must see before deciding anything.

use sha2::{Digest, Sha256};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CommandFeature {
    /// Runs under sh/bash/zsh/... — argument text is shell code.
    ShellWrapped,
    /// Runs under python/node/ruby/... — argument text is program code.
    Interpreter,
    /// `-c` inline code on a shell or interpreter: the command body is hidden
    /// inside one string and MUST be shown to the user verbatim on approval.
    InlineCode,
    /// `env [VARS] cmd` — can smuggle arguments and environment.
    EnvWrapper,
    /// `xargs ... cmd` — target command arrives indirectly.
    XargsWrapper,
    /// Nested sudo: pointless under the root supervisor (already root).
    NestedSudo,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NormalizedCommand {
    /// argv exactly as received; the whitelist hashes this.
    pub argv: Vec<String>,
    /// argv[0] canonicalized when possible, raw otherwise.
    pub binary: String,
    pub features: Vec<CommandFeature>,
}

const SHELLS: [&str; 6] = ["sh", "bash", "zsh", "dash", "ksh", "fish"];
const INTERPRETERS: [&str; 6] = ["python", "python3", "node", "ruby", "perl", "php"];

/// Normalize an argv vector. Binary resolution uses `fs::canonicalize` on
/// the given token; PATH lookup belongs to the execution layer, not here.
pub fn normalize(argv: &[String]) -> NormalizedCommand {
    let Some(first) = argv.first() else {
        return NormalizedCommand {
            argv: argv.to_vec(),
            binary: String::new(),
            features: vec![],
        };
    };
    let base = basename(first);
    let binary = canonical_or_raw(first);
    let mut features = Vec::new();
    if SHELLS.contains(&base.as_str()) {
        features.push(CommandFeature::ShellWrapped);
    }
    if INTERPRETERS.contains(&base.as_str()) {
        features.push(CommandFeature::Interpreter);
    }
    if base == "env" {
        features.push(CommandFeature::EnvWrapper);
    }
    if base == "xargs" {
        features.push(CommandFeature::XargsWrapper);
    }
    if base == "sudo" {
        features.push(CommandFeature::NestedSudo);
    }
    let wraps_code = features.iter().any(|f| {
        matches!(
            f,
            CommandFeature::ShellWrapped | CommandFeature::Interpreter
        )
    });
    if wraps_code && argv.iter().skip(1).any(|a| a == "-c") {
        features.push(CommandFeature::InlineCode);
    }
    NormalizedCommand {
        argv: argv.to_vec(),
        binary,
        features,
    }
}

/// Exact-command hash for whitelist entries (R10): over the raw argv, so
/// only the identical command string matches.
pub fn command_hash(argv: &[String]) -> String {
    let mut hasher = Sha256::new();
    for arg in argv {
        hasher.update(arg.as_bytes());
        hasher.update([0x1f]);
    }
    hex::encode(hasher.finalize())
}

pub fn basename(path: &str) -> String {
    let cleaned = path.trim_end_matches('/');
    match cleaned.rsplit_once('/') {
        Some((_, base)) => base.to_string(),
        None => cleaned.to_string(),
    }
}

fn canonical_or_raw(path: &str) -> String {
    std::fs::canonicalize(path)
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|_| path.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn argv(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn detects_shell_wrapper_and_inline_code() {
        let nc = normalize(&argv(&["/usr/bin/bash", "-c", "rm -rf /"]));
        assert!(nc.features.contains(&CommandFeature::ShellWrapped));
        assert!(nc.features.contains(&CommandFeature::InlineCode));
    }

    #[test]
    fn detects_interpreter_without_inline_flag() {
        let nc = normalize(&argv(&["python3", "script.py"]));
        assert!(nc.features.contains(&CommandFeature::Interpreter));
        assert!(!nc.features.contains(&CommandFeature::InlineCode));
    }

    #[test]
    fn detects_env_and_xargs_and_nested_sudo() {
        for (cmd, feature) in [
            (vec!["env", "FOO=1", "ls"], CommandFeature::EnvWrapper),
            (vec!["xargs", "rm"], CommandFeature::XargsWrapper),
            (vec!["sudo", "ls"], CommandFeature::NestedSudo),
        ] {
            let nc = normalize(&argv(&cmd));
            assert!(nc.features.contains(&feature), "{cmd:?}");
        }
    }

    #[test]
    fn command_hash_is_exact_and_stable() {
        let a = command_hash(&argv(&["apt", "install", "-y", "htop"]));
        let b = command_hash(&argv(&["apt", "install", "-y", "htop"]));
        let c = command_hash(&argv(&["apt", "install", "-y", "nano"]));
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn empty_argv_yields_empty_binary() {
        let nc = normalize(&[]);
        assert_eq!(nc.binary, "");
        assert!(nc.features.is_empty());
    }
}
