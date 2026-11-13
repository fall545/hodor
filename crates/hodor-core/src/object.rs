//! Managed object model: everything an agent may *use* but never *see*.

use serde::{Deserialize, Serialize};
use std::fmt;
use zeroize::Zeroizing;

/// A string holding secret material. Zeroizes on drop; never printed by Debug.
///
/// The serde impls materialize a plain `String` for one statement before it is
/// wrapped; that window is confined to this file.
#[derive(Clone, Default)]
pub struct SecretString(Zeroizing<String>);

impl SecretString {
    pub fn new(value: impl Into<String>) -> Self {
        Self(Zeroizing::new(value.into()))
    }

    /// Expose the plaintext. Only daemon-side code may call this.
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for SecretString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[redacted]")
    }
}

impl Serialize for SecretString {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.expose())
    }
}

impl<'de> Deserialize<'de> for SecretString {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        Ok(Self::new(raw))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ObjectKind {
    Sudo,
    Ssh,
    ApiKey,
    Token,
}

impl ObjectKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Sudo => "sudo",
            Self::Ssh => "ssh",
            Self::ApiKey => "api-key",
            Self::Token => "token",
        }
    }
}

impl fmt::Display for ObjectKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Which ways an object may be consumed (R22).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct UseSet {
    pub exec: bool,
    pub http: bool,
    pub ssh: bool,
}

impl UseSet {
    pub fn is_empty(&self) -> bool {
        !self.exec && !self.http && !self.ssh
    }

    /// Human-readable list, e.g. `exec, http`.
    pub fn summary(&self) -> String {
        let mut parts = Vec::new();
        if self.exec {
            parts.push("exec");
        }
        if self.http {
            parts.push("http");
        }
        if self.ssh {
            parts.push("ssh");
        }
        parts.join(", ")
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ConfirmMode {
    /// Ask the user for every use (default).
    #[default]
    Always,
    /// Free of prompts within an approved task window (daemon-enforced, M2+).
    Task,
    /// Free of prompts only for whitelisted command hashes.
    Whitelisted,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObjectPolicy {
    /// Agents allowed to reference this object; empty means all.
    pub allowed_agents: Vec<String>,
    pub confirm: ConfirmMode,
    #[serde(default)]
    pub uses: UseSet,
    /// Grant window in seconds for `ConfirmMode::Task`.
    pub ttl_secs: Option<u64>,
    /// Lifetime use cap; enforced by the daemon (M2+).
    pub max_uses: Option<u64>,
    /// RFC3339 expiry timestamp.
    pub expires_at: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HodorObject {
    pub alias: String,
    pub kind: ObjectKind,
    pub secret: SecretString,
    pub policy: ObjectPolicy,
}

impl HodorObject {
    pub fn uses_default_for(kind: ObjectKind) -> UseSet {
        match kind {
            ObjectKind::Sudo => UseSet {
                exec: true,
                ..Default::default()
            },
            ObjectKind::Ssh => UseSet {
                ssh: true,
                ..Default::default()
            },
            ObjectKind::ApiKey | ObjectKind::Token => UseSet {
                http: true,
                exec: true,
                ..Default::default()
            },
        }
    }
}
