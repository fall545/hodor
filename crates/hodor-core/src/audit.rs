//! Append-only audit log with a SHA-256 hash chain (R7).
//!
//! `hash_n = SHA256(entry_n ‖ prev_hash)`; the chain head lives inside the
//! encrypted vault, so an agent with write access to the log cannot rewrite
//! history without the master passphrase. Deleting the whole log is detected
//! by comparing the last computed head against the vault head.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::Path;

use crate::error::{CoreError, Result};
use crate::vault::genesis_head;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AuditEvent {
    VaultCreated,
    Unlocked,
    Locked,
    ObjectAdded,
    ObjectRevoked,
    PolicyChanged,
    CommandRequested,
    CommandApproved,
    CommandDenied,
    OutputWithheld,
    GuardOn,
    GuardOff,
    GuardQuarantine,
    SecretWriteBlocked,
    SecretWriteAllowed,
    IntegrityAlert,
}

impl AuditEvent {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::VaultCreated => "vault-created",
            Self::Unlocked => "unlocked",
            Self::Locked => "locked",
            Self::ObjectAdded => "object-added",
            Self::ObjectRevoked => "object-revoked",
            Self::PolicyChanged => "policy-changed",
            Self::CommandRequested => "command-requested",
            Self::CommandApproved => "command-approved",
            Self::CommandDenied => "command-denied",
            Self::OutputWithheld => "output-withheld",
            Self::GuardOn => "guard-on",
            Self::GuardOff => "guard-off",
            Self::GuardQuarantine => "guard-quarantine",
            Self::SecretWriteBlocked => "secret-write-blocked",
            Self::SecretWriteAllowed => "secret-write-allowed",
            Self::IntegrityAlert => "integrity-alert",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditEntry {
    pub seq: u64,
    pub ts: String,
    pub event: String,
    pub session: String,
    pub detail: String,
    pub prev_hash: String,
    pub hash: String,
}

/// Outcome of a chain verification.
#[derive(Debug, PartialEq, Eq)]
pub struct ChainReport {
    pub entries: u64,
    /// First entry that breaks the chain, with a human-readable reason.
    pub broken_at: Option<(u64, String)>,
    /// Head recomputed from the log itself.
    pub computed_head: String,
    /// Whether `computed_head` matches the vault's head.
    pub head_ok: bool,
}

fn entry_hash(seq: u64, ts: &str, event: &str, session: &str, detail: &str, prev: &str) -> String {
    let mut hasher = Sha256::new();
    for part in [
        seq.to_string(),
        ts.to_string(),
        event.to_string(),
        session.to_string(),
        detail.to_string(),
        prev.to_string(),
    ] {
        hasher.update(part.as_bytes());
        hasher.update([0x1f]);
    }
    hex::encode(hasher.finalize())
}

fn last_seq(path: &Path) -> Result<u64> {
    if !path.exists() {
        return Ok(0);
    }
    let file = File::open(path)?;
    let mut last = 0u64;
    for line in BufReader::new(file).lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let entry: AuditEntry = serde_json::from_str(&line)
            .map_err(|e| CoreError::Audit(format!("unreadable entry: {e}")))?;
        last = entry.seq;
    }
    Ok(last)
}

/// Append one entry; `head` must be the current chain head and is advanced to
/// the new entry's hash on success. Callers persist the new head in the vault.
pub fn append(
    path: &Path,
    head: &mut String,
    event: AuditEvent,
    session: &str,
    detail: &str,
) -> Result<AuditEntry> {
    let seq = last_seq(path)? + 1;
    let ts = chrono::Utc::now().to_rfc3339();
    let prev = head.clone();
    let hash = entry_hash(seq, &ts, event.as_str(), session, detail, &prev);
    let entry = AuditEntry {
        seq,
        ts,
        event: event.as_str().to_string(),
        session: session.to_string(),
        detail: detail.to_string(),
        prev_hash: prev,
        hash,
    };
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let mut file = OpenOptions::new().create(true).append(true).open(path)?;
    let line =
        serde_json::to_string(&entry).map_err(|e| CoreError::Serialization(e.to_string()))?;
    writeln!(file, "{line}")?;
    *head = entry.hash.clone();
    Ok(entry)
}

/// Walk the whole log, recompute every hash, and compare with `expected_head`.
pub fn verify(path: &Path, expected_head: &str) -> Result<ChainReport> {
    if !path.exists() {
        return Err(CoreError::Audit("log file missing".into()));
    }
    let file = File::open(path)?;
    let mut prev = genesis_head();
    let mut seq_expected = 1u64;
    let mut entries = 0u64;
    let mut broken_at = None;
    let mut computed_head = prev.clone();
    for line in BufReader::new(file).lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let parsed: AuditEntry = match serde_json::from_str(&line) {
            Ok(p) => p,
            Err(e) => {
                broken_at = Some((seq_expected, format!("unparsable entry: {e}")));
                break;
            }
        };
        if let Some(reason) = check_entry(&parsed, &prev, seq_expected) {
            broken_at = Some((parsed.seq, reason));
            break;
        }
        entries += 1;
        seq_expected += 1;
        prev = parsed.hash.clone();
        computed_head = prev.clone();
    }
    let head_ok = broken_at.is_none() && computed_head == expected_head;
    Ok(ChainReport {
        entries,
        broken_at,
        computed_head,
        head_ok,
    })
}

fn check_entry(entry: &AuditEntry, prev: &str, expected_seq: u64) -> Option<String> {
    if entry.seq != expected_seq {
        return Some(format!("seq {} where {} expected", entry.seq, expected_seq));
    }
    if entry.prev_hash != prev {
        return Some("prev_hash does not chain".into());
    }
    let recomputed = entry_hash(
        entry.seq,
        &entry.ts,
        &entry.event,
        &entry.session,
        &entry.detail,
        &entry.prev_hash,
    );
    if recomputed != entry.hash {
        return Some("hash mismatch".into());
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chain_appends_and_verifies() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.log");
        let mut head = genesis_head();
        append(
            &path,
            &mut head,
            AuditEvent::VaultCreated,
            "cli:1",
            "vault created",
        )
        .unwrap();
        append(&path, &mut head, AuditEvent::Unlocked, "cli:1", "unlocked").unwrap();
        let report = verify(&path, &head).unwrap();
        assert_eq!(report.entries, 2);
        assert!(report.broken_at.is_none());
        assert!(report.head_ok);
    }

    #[test]
    fn tampered_entry_detected() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.log");
        let mut head = genesis_head();
        append(&path, &mut head, AuditEvent::Unlocked, "cli:1", "legit").unwrap();
        let head_after_tamper_target = head.clone();
        append(&path, &mut head, AuditEvent::ObjectAdded, "cli:1", "add me").unwrap();
        // Rewrite the second entry's detail behind the chain's back.
        let raw = std::fs::read_to_string(&path).unwrap();
        let mut lines: Vec<String> = raw.lines().map(str::to_string).collect();
        let mut entry: AuditEntry = serde_json::from_str(&lines[1]).unwrap();
        entry.detail = "rewritten".into();
        lines[1] = serde_json::to_string(&entry).unwrap();
        std::fs::write(&path, lines.join("\n") + "\n").unwrap();
        let report = verify(&path, &head_after_tamper_target).unwrap();
        // The tamper breaks at the second entry regardless of expected head.
        assert!(report.broken_at.is_some());
        assert!(!report.head_ok);
    }

    #[test]
    fn deleted_tail_detected_by_head_mismatch() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.log");
        let mut head = genesis_head();
        append(&path, &mut head, AuditEvent::Unlocked, "cli:1", "keep").unwrap();
        append(
            &path,
            &mut head,
            AuditEvent::ObjectAdded,
            "cli:1",
            "dropped",
        )
        .unwrap();
        // What the vault stored after both appends.
        let head_after_both = head.clone();
        // Truncate the log to drop the second entry, simulating deletion.
        let raw = std::fs::read_to_string(&path).unwrap();
        let first_line = raw.lines().next().unwrap().to_string();
        std::fs::write(&path, first_line + "\n").unwrap();
        let report = verify(&path, &head_after_both).unwrap();
        assert!(report.broken_at.is_none());
        assert!(
            !report.head_ok,
            "vault head no longer matches the truncated log"
        );
    }
}
