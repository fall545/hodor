//! Minimal pinentry client over the assuan protocol.
//!
//! Only what Hodor needs: SETTITLE / SETDESC / SETPROMPT / GETPIN / QUIT.
//! pinentry draws its own window or curses UI owned by the user's session —
//! exactly the out-of-band surface the threat model requires.

use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

use crate::AskError;

const CANDIDATE_NAMES: [&str; 3] = ["pinentry", "pinentry-curses", "pinentry-tty"];

pub struct Pinentry {
    binary: PathBuf,
}

/// Resolve the pinentry binary: explicit config > $PINENTRY > PATH scan.
pub fn discover(configured: Option<&str>) -> Option<Pinentry> {
    if let Some(path) = configured.filter(|p| !p.is_empty()) {
        return Some(Pinentry {
            binary: PathBuf::from(path),
        });
    }
    if let Ok(path) = std::env::var("PINENTRY") {
        if !path.is_empty() {
            return Some(Pinentry {
                binary: PathBuf::from(path),
            });
        }
    }
    CANDIDATE_NAMES
        .iter()
        .find_map(|name| which(name).map(|binary| Pinentry { binary }))
}

fn which(name: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|dir| dir.join(name))
        .find(|candidate| candidate.is_file())
}

impl Pinentry {
    /// Ask for a PIN. `Ok(None)` means the user canceled the dialog.
    pub fn ask(&self, desc: &str) -> crate::AskResult {
        let mut child = ChildHandle::spawn(&self.binary)?;
        child.set("SETTITLE", "Hodor")?;
        child.set("SETDESC", &single_line(desc))?;
        child.set("SETPROMPT", "Secret:")?;
        let answer = child.getpin()?;
        child.quit();
        Ok(answer)
    }
}

struct ChildHandle {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
}

impl ChildHandle {
    fn spawn(binary: &std::path::Path) -> Result<Self, AskError> {
        let mut child = Command::new(binary)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()?;
        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| AskError::Protocol("no stdin".into()))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| AskError::Protocol("no stdout".into()))?;
        let mut handle = Self {
            child,
            stdin,
            stdout: BufReader::new(stdout),
        };
        handle.read_ok()?;
        Ok(handle)
    }

    fn set(&mut self, command: &str, value: &str) -> Result<(), AskError> {
        let value = value.replace(['\r', '\n'], " ");
        writeln!(self.stdin, "{command} {value}")?;
        self.read_ok()
    }

    fn getpin(&mut self) -> crate::AskResult {
        writeln!(self.stdin, "GETPIN")?;
        let line = self.read_line()?;
        if let Some(pin) = line.strip_prefix("D ") {
            self.read_ok()?;
            return Ok(Some(zeroize(pin)));
        }
        // ERR lines mean "canceled" or "not confirmed" — the user declined.
        Ok(None)
    }

    fn quit(&mut self) {
        let _ = writeln!(self.stdin, "QUIT");
        let _ = self.child.wait();
    }

    fn read_ok(&mut self) -> Result<(), AskError> {
        let line = self.read_line()?;
        match line.starts_with("OK") {
            true => Ok(()),
            false => Err(AskError::Protocol(format!("expected OK, got: {line}"))),
        }
    }

    fn read_line(&mut self) -> Result<String, AskError> {
        let mut line = String::new();
        self.stdout.read_line(&mut line)?;
        Ok(line.trim_end().to_string())
    }
}

fn zeroize(value: &str) -> zeroize::Zeroizing<String> {
    zeroize::Zeroizing::new(value.to_string())
}

fn single_line(text: &str) -> String {
    text.replace(['\r', '\n'], " ")
}
