//! Canonical filesystem locations (XDG). Platform-neutral via `dirs`.

use std::path::PathBuf;

fn config_base() -> PathBuf {
    dirs::config_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("hodor")
}

pub fn vault_path() -> PathBuf {
    config_base().join("vault.bin")
}

pub fn config_path() -> PathBuf {
    config_base().join("config.toml")
}

pub fn audit_path() -> PathBuf {
    let base = dirs::state_dir()
        .or_else(dirs::config_dir)
        .unwrap_or_else(|| PathBuf::from("."));
    base.join("hodor").join("audit.log")
}
