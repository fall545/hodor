//! hodor-askpass: out-of-band secret input (R3).
//!
//! Rule of the crate: never read secrets from agent-controllable stdin.
//! Preferred path is pinentry (GPG's audited prompt); fallback is the user's
//! controlling terminal (/dev/tty), which is not the agent's pipe.

pub mod pinentry;
pub mod tty;

use zeroize::Zeroizing;

use pinentry::Pinentry;

#[derive(Debug, thiserror::Error)]
pub enum AskError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("pinentry protocol: {0}")]
    Protocol(String),
    #[error("no terminal available for secret input")]
    NoTerminal,
}

/// Ask the user for a secret. `None` means the user canceled.
pub type AskResult = Result<Option<Zeroizing<String>>, AskError>;

pub struct AskPass {
    /// Shown in every legitimate prompt; prompts without it are phishing.
    anti_phish: Option<String>,
    pinentry: Option<Pinentry>,
}

impl AskPass {
    pub fn new(anti_phish: Option<String>, pinentry_path: Option<String>) -> Self {
        let pinentry = pinentry::discover(pinentry_path.as_deref());
        Self {
            anti_phish,
            pinentry,
        }
    }

    /// Prompt for a secret. Falls back to the TTY when pinentry cannot run
    /// in this environment (headless, no DISPLAY); a TTY cancel is `None`.
    pub fn ask(&self, prompt: &str) -> AskResult {
        let desc = self.decorate(prompt);
        if let Some(entry) = &self.pinentry {
            match entry.ask(&desc) {
                Ok(Some(pin)) => return Ok(Some(pin)),
                Ok(None) => return Ok(None),
                Err(_) => {
                    // pinentry unusable here; try the controlling terminal.
                }
            }
        }
        tty::ask_on_tty(&desc)
    }

    fn decorate(&self, prompt: &str) -> String {
        match &self.anti_phish {
            Some(phrase) => format!("[{phrase}] {prompt}"),
            // Before the first unlock there is no phrase to show yet (it
            // lives inside the encrypted vault); this is documented in the
            // threat model (DESIGN §8).
            None => prompt.to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decorates_with_anti_phish_phrase() {
        let ask = AskPass {
            anti_phish: Some("blue whale".into()),
            pinentry: None,
        };
        assert_eq!(
            ask.decorate("enter passphrase"),
            "[blue whale] enter passphrase"
        );
    }

    #[test]
    fn no_phrase_decorates_to_plain_prompt() {
        let ask = AskPass {
            anti_phish: None,
            pinentry: None,
        };
        assert_eq!(ask.decorate("enter passphrase"), "enter passphrase");
    }
}
