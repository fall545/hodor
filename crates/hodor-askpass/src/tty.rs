//! Terminal fallback: read a secret from the user's controlling terminal.
//!
//! rpassword's default input/output path is /dev/tty — not stdin — so an
//! agent process on the other end of a pipe can never feed (or read back)
//! this input.

use zeroize::Zeroizing;

use crate::AskError;

pub fn ask_on_tty(prompt: &str) -> crate::AskResult {
    let config = rpassword::ConfigBuilder::new()
        .password_feedback_hide()
        .build();
    match rpassword::prompt_password_with_config(prompt, config) {
        Ok(pin) => Ok(Some(Zeroizing::new(pin))),
        // No controlling terminal: there is no out-of-band channel.
        Err(e) if e.kind() == std::io::ErrorKind::NotConnected => Err(AskError::NoTerminal),
        Err(e) => Err(AskError::Io(e)),
    }
}
