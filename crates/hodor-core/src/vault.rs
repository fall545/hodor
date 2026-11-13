//! The encrypted vault (R4). File layout, v1:
//!
//! ```text
//! magic "HODR" | version u16 LE | kdf m,t,p u32 LE | salt 16
//!   | nonce_kek 24 | sealed_dek 48 (32-byte DEK + 16-byte tag, wrapped by KEK)
//!   | nonce_dek 24  | ciphertext   (vault JSON sealed by the DEK)
//! ```
//!
//! The DEK is random per vault; the passphrase-derived KEK only wraps the DEK.
//! Adding a second unlock path later (Keychain / Hello / TPM, R18) means adding
//! another wrapped-DEK block — the format and passphrase path stay untouched.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};

use crate::crypto::{seal, unseal, KdfParams, RawKey, KEY_LEN, NONCE_LEN, SALT_LEN};
use crate::error::{CoreError, Result};
use crate::object::HodorObject;

pub const VAULT_MAGIC: [u8; 4] = *b"HODR";
pub const VAULT_VERSION: u16 = 1;

const FIXED_HEADER_LEN: usize = 4 + 2 + 12 + SALT_LEN + NONCE_LEN; // up to sealed_dek
const SEALED_DEK_LEN: usize = KEY_LEN + 16; // AEAD tag included

/// Hash-chain head before any audit entry exists.
pub fn genesis_head() -> String {
    hex::encode(Sha256::digest(b"hodor-audit-genesis"))
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct VaultContent {
    pub anti_phish: String,
    pub objects: Vec<HodorObject>,
    /// SHA-256 (hex) of the newest audit entry.
    pub audit_head: String,
    /// User-extensible deny patterns (blacklist layer 2, R12).
    pub user_blacklist: Vec<String>,
    /// Exact-command hashes exempt from asking (R10 whitelist).
    pub whitelist: Vec<String>,
}

/// Header parts needed to re-save a vault without re-deriving the KEK.
#[derive(Clone)]
struct SealedHeader {
    params: KdfParams,
    salt: Vec<u8>,
    nonce_kek: Vec<u8>,
    sealed_dek: Vec<u8>,
}

/// An opened vault: content plus the in-memory DEK. Dropping it wipes the key;
/// there is no long-lived unlock at the CLI level (daemon arrives in M2).
pub struct UnlockedVault {
    pub content: VaultContent,
    dek: RawKey,
    header: SealedHeader,
}

impl UnlockedVault {
    /// Re-encrypt and atomically replace the vault file.
    pub fn save(&self, path: &Path) -> Result<()> {
        let plaintext = content_json(&self.content)?;
        let (nonce_dek, ciphertext) = seal(&self.dek, &plaintext)?;
        let mut file = serialize_header(&self.header)?;
        file.extend_from_slice(&nonce_dek);
        file.extend_from_slice(&ciphertext);
        write_atomic(path, &file)
    }

    /// Consume the unlock: returns content and wipes the DEK.
    pub fn lock(self) -> VaultContent {
        self.content
    }
}

fn content_json(content: &VaultContent) -> Result<Vec<u8>> {
    // The plaintext JSON exists only inside this buffer, which the caller seals.
    let json = serde_json::to_vec(content).map_err(|e| CoreError::Serialization(e.to_string()))?;
    Ok(json)
}

fn serialize_header(header: &SealedHeader) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(FIXED_HEADER_LEN + SEALED_DEK_LEN);
    out.extend_from_slice(&VAULT_MAGIC);
    out.extend_from_slice(&VAULT_VERSION.to_le_bytes());
    out.extend_from_slice(&header.params.m_cost_kb.to_le_bytes());
    out.extend_from_slice(&header.params.t_cost.to_le_bytes());
    out.extend_from_slice(&header.params.p_cost.to_le_bytes());
    out.extend_from_slice(&header.salt);
    out.extend_from_slice(&header.nonce_kek);
    out.extend_from_slice(&header.sealed_dek);
    Ok(out)
}

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir)?;
    }
    let tmp: PathBuf = path.with_extension("tmp");
    fs::write(&tmp, bytes)?;
    // 600: vault is only ever readable by the owner.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&tmp, fs::Permissions::from_mode(0o600));
    }
    fs::rename(&tmp, path)?;
    Ok(())
}

pub fn create(path: &Path, passphrase: &str, anti_phish: &str) -> Result<()> {
    let salt = random_bytes(SALT_LEN)?;
    let kek = RawKey::from_passphrase(passphrase, &salt, &KdfParams::default())?;
    let dek = RawKey::from_entropy()?;
    let (nonce_kek, sealed_dek) = seal(&kek, dek.as_slice())?;
    let content = VaultContent {
        anti_phish: anti_phish.to_string(),
        audit_head: genesis_head(),
        ..Default::default()
    };
    let plaintext = content_json(&content)?;
    let (nonce_dek, ciphertext) = seal(&dek, &plaintext)?;
    let header = SealedHeader {
        params: KdfParams::default(),
        salt,
        nonce_kek,
        sealed_dek,
    };
    let mut file = serialize_header(&header)?;
    file.extend_from_slice(&nonce_dek);
    file.extend_from_slice(&ciphertext);
    write_atomic(path, &file)
}

pub fn open(path: &Path, passphrase: &str) -> Result<UnlockedVault> {
    let bytes = fs::read(path).map_err(|e| match e.kind() {
        std::io::ErrorKind::NotFound => CoreError::VaultMissing(path.display().to_string()),
        _ => CoreError::Io(e),
    })?;
    if bytes.len() < FIXED_HEADER_LEN + SEALED_DEK_LEN + NONCE_LEN + 16 {
        return Err(CoreError::VaultCorrupt("file too short".into()));
    }
    if bytes[0..4] != VAULT_MAGIC {
        return Err(CoreError::VaultCorrupt("bad magic".into()));
    }
    let version = u16::from_le_bytes([bytes[4], bytes[5]]);
    if version != VAULT_VERSION {
        return Err(CoreError::VaultCorrupt(format!(
            "unsupported version {version}"
        )));
    }
    let params = KdfParams {
        m_cost_kb: u32::from_le_bytes(bytes[6..10].try_into().unwrap()),
        t_cost: u32::from_le_bytes(bytes[10..14].try_into().unwrap()),
        p_cost: u32::from_le_bytes(bytes[14..18].try_into().unwrap()),
    };
    let salt = bytes[18..18 + SALT_LEN].to_vec();
    let nonce_kek = bytes[34..34 + NONCE_LEN].to_vec();
    let sealed_dek = bytes[58..58 + SEALED_DEK_LEN].to_vec();
    let nonce_dek = bytes[106..106 + NONCE_LEN].to_vec();
    let ciphertext = bytes[130..].to_vec();

    let kek = RawKey::from_passphrase(passphrase, &salt, &params)?;
    // Wrong passphrase and corruption are indistinguishable here by design.
    let dek_bytes =
        unseal(&kek, &nonce_kek, &sealed_dek).map_err(|_| CoreError::WrongPassphrase)?;
    let mut dek_fixed = [0u8; KEY_LEN];
    dek_fixed.copy_from_slice(&dek_bytes);
    let dek = RawKey::from_bytes(dek_fixed);
    let plaintext = unseal(&dek, &nonce_dek, &ciphertext)
        .map_err(|_| CoreError::VaultCorrupt("content block".into()))?;
    let content: VaultContent =
        serde_json::from_slice(&plaintext).map_err(|e| CoreError::Serialization(e.to_string()))?;

    let header = SealedHeader {
        params,
        salt,
        nonce_kek,
        sealed_dek,
    };
    Ok(UnlockedVault {
        content,
        dek,
        header,
    })
}

fn random_bytes(len: usize) -> Result<Vec<u8>> {
    let mut buf = vec![0u8; len];
    getrandom::getrandom(&mut buf).map_err(|e| CoreError::Crypto(e.to_string()))?;
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::object::{ConfirmMode, ObjectKind, ObjectPolicy, SecretString};

    fn vault_with_object(dir: &Path) -> PathBuf {
        let path = dir.join("vault.bin");
        create(&path, "master-pass-1", "blue whale").unwrap();
        let mut vault = open(&path, "master-pass-1").unwrap();
        vault.content.objects.push(HodorObject {
            alias: "openai".into(),
            kind: ObjectKind::ApiKey,
            secret: SecretString::new("sk-secret-value-123"),
            policy: ObjectPolicy {
                confirm: ConfirmMode::Always,
                ..Default::default()
            },
        });
        vault.save(&path).unwrap();
        path
    }

    #[test]
    fn create_open_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let path = vault_with_object(dir.path());
        let vault = open(&path, "master-pass-1").unwrap();
        assert_eq!(vault.content.objects.len(), 1);
        assert_eq!(
            vault.content.objects[0].secret.expose(),
            "sk-secret-value-123"
        );
        assert_eq!(vault.content.audit_head, genesis_head());
    }

    #[test]
    fn wrong_passphrase_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let path = vault_with_object(dir.path());
        assert!(matches!(
            open(&path, "nope"),
            Err(CoreError::WrongPassphrase)
        ));
    }

    #[test]
    fn save_reopen_preserves_objects() {
        let dir = tempfile::tempdir().unwrap();
        let path = vault_with_object(dir.path());
        let vault = open(&path, "master-pass-1").unwrap();
        let content = vault.lock();
        assert_eq!(content.objects[0].alias, "openai");
        let reopened = open(&path, "master-pass-1").unwrap();
        assert_eq!(reopened.content.objects.len(), 1);
    }

    #[test]
    fn tampered_header_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let path = vault_with_object(dir.path());
        let mut bytes = fs::read(&path).unwrap();
        bytes[20] ^= 0xff; // flip a salt byte
        fs::write(&path, &bytes).unwrap();
        assert!(matches!(
            open(&path, "master-pass-1"),
            Err(CoreError::WrongPassphrase)
        ));
    }
}
