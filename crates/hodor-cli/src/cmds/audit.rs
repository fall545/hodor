//! `hodor audit [--verify]`: print the tail of the audit log, or recompute
//! the whole hash chain against the vault's stored head.

use anyhow::{bail, Result};
use std::fs::File;
use std::io::{BufRead, BufReader};

use super::unlock_vault;
use crate::config::Config;
use crate::i18n::Msgs;
use hodor_core::audit;
use hodor_core::paths;

const TAIL_LINES: usize = 20;

pub fn run(msgs: &Msgs, cfg: &Config, verify: bool) -> Result<()> {
    let log_path = paths::audit_path();
    if verify {
        return verify_chain(msgs, cfg, &log_path);
    }
    if !log_path.exists() {
        println!("{}", msgs.get("audit-title", &[]));
        return Ok(());
    }
    println!("{}", msgs.get("audit-title", &[]));
    let lines = read_tail(&log_path)?;
    for line in lines {
        print_entry(&line);
    }
    Ok(())
}

fn verify_chain(msgs: &Msgs, cfg: &Config, log_path: &std::path::Path) -> Result<()> {
    let unlocked = unlock_vault(msgs, cfg)?;
    let expected = unlocked.content.audit_head.clone();
    let _ = unlocked.lock();
    let report = audit::verify(log_path, &expected)?;
    if let Some((seq, reason)) = report.broken_at {
        bail!(msgs.get(
            "audit-tampered",
            &[("seq", &seq.to_string()), ("field", &reason)]
        ));
    }
    if !report.head_ok {
        let vault_head = &expected[..16.min(expected.len())];
        let log_head = &report.computed_head[..16.min(report.computed_head.len())];
        bail!(msgs.get(
            "audit-head-mismatch",
            &[("log_head", log_head), ("vault_head", vault_head)]
        ));
    }
    println!(
        "{}",
        msgs.get(
            "audit-ok",
            &[
                ("n", &report.entries.to_string()),
                ("head", &report.computed_head[..16])
            ]
        )
    );
    Ok(())
}

fn read_tail(path: &std::path::Path) -> Result<Vec<String>> {
    let reader = BufReader::new(File::open(path)?);
    let mut window = std::collections::VecDeque::new();
    for line in reader.lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        if window.len() == TAIL_LINES {
            window.pop_front();
        }
        window.push_back(line);
    }
    Ok(window.into_iter().collect())
}

fn print_entry(line: &str) {
    let Ok(entry) = serde_json_parse(line) else {
        println!("? {line}");
        return;
    };
    let detail = truncate(&entry.detail, 80);
    println!(
        "{:>4} {} {:<18} {:<12} {}",
        entry.seq, entry.ts, entry.event, entry.session, detail
    );
}

/// Keep the log-reading logic independent of core's serde types where a
/// broken entry must still print instead of aborting the listing.
fn serde_json_parse(line: &str) -> Result<AuditLine> {
    serde_json::from_str::<AuditLine>(line).map_err(|e| anyhow::anyhow!("{e}"))
}

#[derive(serde::Deserialize)]
struct AuditLine {
    seq: u64,
    ts: String,
    event: String,
    session: String,
    detail: String,
}

fn truncate(text: &str, max: usize) -> String {
    if text.len() <= max {
        return text.to_string();
    }
    format!("{}…", &text[..max])
}
