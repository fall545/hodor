//! Symmetric crypto: Argon2id key derivation and XChaCha20-Poly1305 AEAD.
//! Keys live only in [`RawKey`], which zeroizes on drop.

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::Aead;
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::error::{CoreError, Result};

pub const KEY_LEN: usize = 32;
pub const NONCE_LEN: usize = 24;
pub const SALT_LEN: usize = 16;

/// Argon2id cost parameters; persisted in the vault header so they can evolve
/// without invalidating existing vaults.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KdfParams {
    pub m_cost_kb: u32,
    pub t_cost: u32,
    pub p_cost: u32,
}

impl Default for KdfParams {
    fn default() -> Self {
        // 64 MiB / 3 passes: ~0.3s on a desktop CPU, painful to brute-force offline.
        Self {
            m_cost_kb: 65536,
            t_cost: 3,
            p_cost: 1,
        }
    }
}

/// A 256-bit key that is wiped from memory when dropped.
pub struct RawKey(Zeroizing<[u8; KEY_LEN]>);

impl RawKey {
    pub fn from_entropy() -> Result<Self> {
        let mut buf = [0u8; KEY_LEN];
        fill_random(&mut buf)?;
        Ok(Self(Zeroizing::new(buf)))
    }

    pub fn from_passphrase(passphrase: &str, salt: &[u8], params: &KdfParams) -> Result<Self> {
        if salt.len() != SALT_LEN {
            return Err(CoreError::VaultCorrupt("bad salt length".into()));
        }
        let params = Params::new(
            params.m_cost_kb,
            params.t_cost,
            params.p_cost,
            Some(KEY_LEN),
        )
        .map_err(|e| CoreError::Kdf(e.to_string()))?;
        let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        let mut out = Zeroizing::new([0u8; KEY_LEN]);
        argon
            .hash_password_into(passphrase.as_bytes(), salt, out.as_mut())
            .map_err(|e| CoreError::Kdf(e.to_string()))?;
        Ok(Self(out))
    }

    pub fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    pub fn as_slice(&self) -> &[u8] {
        &*self.0
    }
}

/// Encrypt with XChaCha20-Poly1305; returns `(nonce, ciphertext_with_tag)`.
pub fn seal(key: &RawKey, plaintext: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    let cipher = XChaCha20Poly1305::new_from_slice(key.as_slice())
        .map_err(|e| CoreError::Crypto(e.to_string()))?;
    let mut nonce = [0u8; NONCE_LEN];
    fill_random(&mut nonce)?;
    let ct = cipher
        .encrypt(XNonce::from_slice(&nonce), plaintext)
        .map_err(|e| CoreError::Crypto(e.to_string()))?;
    Ok((nonce.to_vec(), ct))
}

/// Decrypt a `(nonce, ciphertext_with_tag)` pair. Fails if either is tampered.
pub fn unseal(key: &RawKey, nonce: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
    if nonce.len() != NONCE_LEN {
        return Err(CoreError::VaultCorrupt("bad nonce length".into()));
    }
    let cipher = XChaCha20Poly1305::new_from_slice(key.as_slice())
        .map_err(|e| CoreError::Crypto(e.to_string()))?;
    cipher
        .decrypt(XNonce::from_slice(nonce), ciphertext)
        .map_err(|_| CoreError::Crypto("authentication failed".into()))
}

fn fill_random(buf: &mut [u8]) -> Result<()> {
    getrandom::getrandom(buf).map_err(|e| CoreError::Crypto(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_open_roundtrip() {
        let key = RawKey::from_entropy().unwrap();
        let pt = b"attack at dawn, hold the door";
        let (nonce, ct) = seal(&key, pt).unwrap();
        assert_ne!(&ct[..], pt);
        let back = unseal(&key, &nonce, &ct).unwrap();
        assert_eq!(back, pt);
    }

    #[test]
    fn unseal_rejects_tampering() {
        let key = RawKey::from_entropy().unwrap();
        let (nonce, mut ct) = seal(&key, b"secret").unwrap();
        ct[0] ^= 0x01;
        assert!(unseal(&key, &nonce, &ct).is_err());
    }

    #[test]
    fn passphrase_derivation_is_deterministic_per_salt() {
        let salt = [7u8; SALT_LEN];
        let a = RawKey::from_passphrase("correct horse", &salt, &KdfParams::default()).unwrap();
        let b = RawKey::from_passphrase("correct horse", &salt, &KdfParams::default()).unwrap();
        let c = RawKey::from_passphrase("wrong battery", &salt, &KdfParams::default()).unwrap();
        assert_eq!(a.as_slice(), b.as_slice());
        assert_ne!(a.as_slice(), c.as_slice());
    }
}
