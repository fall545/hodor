//! Minimal pinentry client over the assuan protocol.
//!
//! Only what Hodor needs: SETTITLE / SETDESC / SETPROMPT / GETPIN / QUIT.
//! pinentry draws its own window or curses UI owned by the user's session —
//! exactly the out-of-band surface the threat model requires.

use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::time::Duration;

use crate::AskError;

/// GUI-capable candidates, in preference order.
const CANDIDATE_NAMES: [&str; 3] = ["pinentry", "pinentry-curses", "pinentry-tty"];
/// Headless candidates: only pinentry variants that prompt on the user's
/// terminal. GUI pinentry (gnome3/qt/...) cannot show a dialog without a
/// display and would just hang until the timeout; pinentry-curses needs a
/// tty on stdin, which we cannot give it (we speak assuan on pipes), so it
/// errors out — skip both and fall straight back to our own TTY input.
const HEADLESS_CANDIDATE_NAMES: [&str; 1] = ["pinentry-tty"];

/// Startup handshake should be near-instant; anything longer means the
/// pinentry cannot run here (dead display, missing socket, ...).
const GREETING_TIMEOUT: Duration = Duration::from_secs(5);
/// The user gets two minutes to find and answer the dialog; after that we
/// give up on pinentry and fall back to the terminal instead of hanging
/// forever on a window hidden behind others.
const DIALOG_TIMEOUT: Duration = Duration::from_secs(120);

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
    let candidates: &[&str] = match headless() {
        true => &HEADLESS_CANDIDATE_NAMES,
        false => &CANDIDATE_NAMES,
    };
    candidates
        .iter()
        .find_map(|name| which(name).map(|binary| Pinentry { binary }))
}

/// True when no graphical display is reachable: a bare SSH session, a
/// console login, or a server. Both Wayland and X11 set one of these.
fn headless() -> bool {
    std::env::var_os("DISPLAY").is_none() && std::env::var_os("WAYLAND_DISPLAY").is_none()
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
    /// Lines produced by the reader thread; reads must never block the
    /// caller indefinitely.
    lines: Receiver<std::io::Result<String>>,
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
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || read_lines(stdout, tx));
        let mut handle = Self {
            child,
            stdin,
            lines: rx,
        };
        handle.read_ok(GREETING_TIMEOUT)?;
        Ok(handle)
    }

    fn set(&mut self, command: &str, value: &str) -> Result<(), AskError> {
        let value = value.replace(['\r', '\n'], " ");
        writeln!(self.stdin, "{command} {value}")?;
        self.read_ok(DIALOG_TIMEOUT)
    }

    fn getpin(&mut self) -> crate::AskResult {
        writeln!(self.stdin, "GETPIN")?;
        let line = self.read_line(DIALOG_TIMEOUT)?;
        if let Some(pin) = line.strip_prefix("D ") {
            self.read_ok(DIALOG_TIMEOUT)?;
            return Ok(Some(zeroize(pin)));
        }
        // ERR lines mean "canceled" or "not confirmed" — the user declined.
        Ok(None)
    }

    fn quit(&mut self) {
        let _ = writeln!(self.stdin, "QUIT");
        let _ = self.child.wait();
    }

    fn read_ok(&mut self, timeout: Duration) -> Result<(), AskError> {
        let line = self.read_line(timeout)?;
        match line.starts_with("OK") {
            true => Ok(()),
            false => Err(AskError::Protocol(format!("expected OK, got: {line}"))),
        }
    }

    fn read_line(&mut self, timeout: Duration) -> Result<String, AskError> {
        match self.lines.recv_timeout(timeout) {
            Ok(Ok(line)) => Ok(line.trim_end().to_string()),
            Ok(Err(e)) => Err(AskError::Io(e)),
            // Timeout or a dead reader thread (pinentry exited, display
            // gone, dialog never answered): signal failure so the caller
            // falls back to the terminal instead of hanging forever.
            Err(_) => Err(AskError::Protocol(
                "pinentry did not answer in time".into(),
            )),
        }
    }
}

impl Drop for ChildHandle {
    fn drop(&mut self) {
        // A timed-out pinentry may still be alive (its dialog orphaned);
        // never leave the process behind.
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn read_lines(stdout: ChildStdout, tx: mpsc::Sender<std::io::Result<String>>) {
    let mut reader = BufReader::new(stdout);
    loop {
        let mut line = String::new();
        let result = reader.read_line(&mut line).map(|n| {
            // EOF: report once so the caller stops waiting, then exit.
            if n == 0 { None } else { Some(line) }
        });
        let (result, done) = match result {
            Ok(Some(line)) => (Ok(line), false),
            Ok(None) => (Ok(String::new()), true),
            Err(e) => (Err(e), true),
        };
        if tx.send(result).is_err() || done {
            return;
        }
    }
}

fn zeroize(value: &str) -> zeroize::Zeroizing<String> {
    zeroize::Zeroizing::new(value.to_string())
}

fn single_line(text: &str) -> String {
    text.replace(['\r', '\n'], " ")
}
