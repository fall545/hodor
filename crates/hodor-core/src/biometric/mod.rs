//! Biometric presence verification (R18).
//!
//! A fingerprint proves *presence*, it is never a decryption key on Linux:
//! fprintd only returns a boolean (DESIGN §5.2). It is therefore used as an
//! optional second factor at unlock. On macOS/Windows the hardware wraps the
//! DEK itself; those platform modules land at the end of M1.

pub enum PresenceResult {
    Verified,
    Denied,
    Unavailable(String),
}

pub trait PresenceVerifier {
    fn name(&self) -> &'static str;
    /// Prompt the physically present user to confirm via biometrics.
    fn verify(&self, prompt: &str) -> crate::Result<PresenceResult>;
}

/// Verifier for platforms where the module is not implemented yet.
pub struct UnavailableVerifier {
    pub platform: &'static str,
}

impl PresenceVerifier for UnavailableVerifier {
    fn name(&self) -> &'static str {
        self.platform
    }

    fn verify(&self, _prompt: &str) -> crate::Result<PresenceResult> {
        Ok(PresenceResult::Unavailable(format!(
            "biometric unlock not yet implemented on {}",
            self.platform
        )))
    }
}

#[cfg(target_os = "linux")]
pub fn default_verifier() -> Box<dyn PresenceVerifier> {
    Box::new(linux::FprintdVerifier)
}

#[cfg(not(target_os = "linux"))]
pub fn default_verifier() -> Box<dyn PresenceVerifier> {
    let platform = if cfg!(target_os = "macos") {
        "macOS"
    } else {
        "Windows"
    };
    Box::new(UnavailableVerifier { platform })
}

#[cfg(target_os = "linux")]
pub mod linux {
    use super::PresenceResult;
    use super::PresenceVerifier;
    use crate::error::CoreError;
    use std::process::{Command, Stdio};

    /// Presence factor via `fprintd-verify` (shelled out deliberately: a D-Bus
    /// dependency would not change the security property, which is the boolean).
    pub struct FprintdVerifier;

    impl PresenceVerifier for FprintdVerifier {
        fn name(&self) -> &'static str {
            "fprintd"
        }

        fn verify(&self, _prompt: &str) -> crate::Result<PresenceResult> {
            // The prompt is printed by the caller; fprintd-verify itself only
            // takes finger/user flags and drives its own UI when present.
            let status = Command::new("fprintd-verify")
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
            match status {
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(
                    PresenceResult::Unavailable("fprintd-verify not found in PATH".into()),
                ),
                Err(e) => Err(CoreError::Io(e)),
                Ok(status) if status.success() => Ok(PresenceResult::Verified),
                Ok(_) => Ok(PresenceResult::Denied),
            }
        }
    }
}
