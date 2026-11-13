use thiserror::Error;

pub type Result<T> = std::result::Result<T, CoreError>;

#[derive(Debug, Error)]
pub enum CoreError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("crypto: {0}")]
    Crypto(String),
    #[error("kdf: {0}")]
    Kdf(String),
    #[error("serialization: {0}")]
    Serialization(String),
    #[error("vault corrupt: {0}")]
    VaultCorrupt(String),
    #[error("vault not found at {0}")]
    VaultMissing(String),
    #[error("wrong passphrase or corrupted vault")]
    WrongPassphrase,
    #[error("unknown alias: {0}")]
    UnknownAlias(String),
    #[error("audit: {0}")]
    Audit(String),
    #[error("unsupported on this platform: {0}")]
    Unsupported(String),
}
