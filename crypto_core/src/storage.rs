//! Encrypted local storage and the multi-vault duress system.
//!
//! **Backend note:** the original spec called for SQLCipher. This build
//! environment has no C compiler at all (no `cl.exe`/`gcc`/`clang`), and
//! SQLCipher — like plain SQLite — is a C library, so nothing that links it
//! can be compiled or tested here regardless of which Cargo feature is
//! chosen (`bundled-sqlcipher` fails identically to a plain system-SQLite
//! build in this sandbox). Rather than ship a storage module that cannot be
//! built or tested, this uses [`redb`], a pure-Rust embedded store, with our
//! own Argon2id + ChaCha20Poly1305 envelope encryption applied to every
//! record. The security property SQLCipher would have given — data at rest
//! is unreadable without the PIN-derived key — is preserved; only the
//! implementation of "at rest" (page-level cipher vs. per-record AEAD) is
//! different. On a machine with a working C toolchain, swapping this module
//! for a `rusqlite`/`bundled-sqlcipher` backend behind the same [`Vault`]
//! API is a contained change.
//!
//! ## Duress system
//!
//! [`VaultManager`] holds two independently-keyed vaults on disk: the real
//! vault and a decoy. [`VaultManager::unlock`] tries the real vault's key
//! first; if the supplied PIN instead matches the decoy, it returns a
//! [`Session::Decoy`] and — in the same call, before returning — zeroizes
//! the real vault's in-memory key material and best-effort shreds the real
//! vault's file on disk. The caller (the UI layer) is responsible for
//! rendering the decoy session as an indistinguishable normal session.

use std::fs::OpenOptions;
use std::io::Write as _;
use std::path::{Path, PathBuf};

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    ChaCha20Poly1305, Key as AeadKey, KeyInit, Nonce,
    aead::{Aead, Payload},
};
use redb::{Database, ReadableDatabase, TableDefinition};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{VaultXError, Result};

const DATA_TABLE: TableDefinition<&[u8], &[u8]> = TableDefinition::new("vaultx_data");
const META_TABLE: TableDefinition<&[u8], &[u8]> = TableDefinition::new("vaultx_meta");
const SALT_KEY: &[u8] = b"salt";
const CANARY_KEY: &[u8] = b"__vaultx_canary__";
const CANARY_PLAINTEXT: &[u8] = b"VAULTX-VAULT-OK-v1";

// Argon2id parameters: 64 MiB memory, 3 passes, single lane. Chosen to be
// expensive enough to slow offline PIN guessing on a stolen device while
// staying well under a second on typical phone/desktop hardware.
const ARGON2_M_COST_KIB: u32 = 64 * 1024;
const ARGON2_T_COST: u32 = 3;
const ARGON2_P_COST: u32 = 1;
const SALT_LEN: usize = 16;

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
struct VaultKey([u8; 32]);

fn derive_vault_key(pin: &[u8], salt: &[u8; SALT_LEN]) -> Result<VaultKey> {
    let params = Params::new(ARGON2_M_COST_KIB, ARGON2_T_COST, ARGON2_P_COST, Some(32))
        .map_err(|e| VaultXError::Storage(format!("invalid argon2 params: {e}")))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = [0u8; 32];
    argon2
        .hash_password_into(pin, salt, &mut out)
        .map_err(|e| VaultXError::Storage(format!("argon2id derivation failed: {e}")))?;
    Ok(VaultKey(out))
}

/// A single encrypted vault backed by one `redb` file. Every value is
/// sealed with ChaCha20Poly1305 under a key derived from the vault's PIN via
/// Argon2id; the salt (not secret) lives in a plaintext metadata table so
/// re-opening the vault can re-derive the same key.
pub struct Vault {
    db: Database,
    key: VaultKey,
}

impl Vault {
    /// Create a brand-new vault file at `path`, sealed with `pin`.
    pub fn create(path: impl AsRef<Path>, pin: &[u8]) -> Result<Self> {
        let mut salt = [0u8; SALT_LEN];
        getrandom::fill(&mut salt)
            .map_err(|e| VaultXError::Storage(format!("rng failure: {e}")))?;
        let key = derive_vault_key(pin, &salt)?;

        let db = Database::create(path.as_ref())
            .map_err(|e| VaultXError::Storage(format!("redb create failed: {e}")))?;

        {
            let write_txn = db
                .begin_write()
                .map_err(|e| VaultXError::Storage(e.to_string()))?;
            {
                let mut meta = write_txn
                    .open_table(META_TABLE)
                    .map_err(|e| VaultXError::Storage(e.to_string()))?;
                meta.insert(SALT_KEY, salt.as_slice())
                    .map_err(|e| VaultXError::Storage(e.to_string()))?;
            }
            write_txn
                .commit()
                .map_err(|e| VaultXError::Storage(e.to_string()))?;
        }

        let vault = Self { db, key };
        vault.put(CANARY_KEY, CANARY_PLAINTEXT)?;
        Ok(vault)
    }

    /// Open an existing vault file at `path` with `pin`. Fails with
    /// [`VaultXError::Storage`] if the PIN is wrong (the canary record fails
    /// to decrypt) — callers use this to distinguish "wrong PIN for this
    /// vault" from "this is actually the decoy vault" in
    /// [`VaultManager::unlock`].
    pub fn open(path: impl AsRef<Path>, pin: &[u8]) -> Result<Self> {
        let db = Database::open(path.as_ref())
            .map_err(|e| VaultXError::Storage(format!("redb open failed: {e}")))?;

        let salt: [u8; SALT_LEN] = {
            let read_txn = db
                .begin_read()
                .map_err(|e| VaultXError::Storage(e.to_string()))?;
            let meta = read_txn
                .open_table(META_TABLE)
                .map_err(|e| VaultXError::Storage(e.to_string()))?;
            let raw = meta
                .get(SALT_KEY)
                .map_err(|e| VaultXError::Storage(e.to_string()))?
                .ok_or_else(|| VaultXError::Storage("vault missing salt metadata".into()))?;
            raw.value()
                .try_into()
                .map_err(|_| VaultXError::Storage("corrupt salt length".into()))?
        };

        let key = derive_vault_key(pin, &salt)?;
        let vault = Self { db, key };

        let canary = vault.get(CANARY_KEY)?;
        if canary.as_deref() != Some(CANARY_PLAINTEXT) {
            return Err(VaultXError::Storage("incorrect PIN for this vault".into()));
        }
        Ok(vault)
    }

    /// Encrypt and store `plaintext` under `key`.
    pub fn put(&self, key: &[u8], plaintext: &[u8]) -> Result<()> {
        let mut nonce_bytes = [0u8; 12];
        getrandom::fill(&mut nonce_bytes).map_err(|_| VaultXError::Aead)?;
        let cipher = ChaCha20Poly1305::new(&AeadKey::from(self.key.0));
        let nonce = Nonce::from(nonce_bytes);
        let ciphertext = cipher
            .encrypt(
                &nonce,
                Payload {
                    msg: plaintext,
                    aad: key,
                },
            )
            .map_err(|_| VaultXError::Aead)?;

        let mut record = Vec::with_capacity(12 + ciphertext.len());
        record.extend_from_slice(&nonce_bytes);
        record.extend_from_slice(&ciphertext);

        let write_txn = self
            .db
            .begin_write()
            .map_err(|e| VaultXError::Storage(e.to_string()))?;
        {
            let mut table = write_txn
                .open_table(DATA_TABLE)
                .map_err(|e| VaultXError::Storage(e.to_string()))?;
            table
                .insert(key, record.as_slice())
                .map_err(|e| VaultXError::Storage(e.to_string()))?;
        }
        write_txn
            .commit()
            .map_err(|e| VaultXError::Storage(e.to_string()))?;
        Ok(())
    }

    /// Fetch and decrypt the value stored under `key`, if present.
    pub fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        let read_txn = self
            .db
            .begin_read()
            .map_err(|e| VaultXError::Storage(e.to_string()))?;
        let table = read_txn
            .open_table(DATA_TABLE)
            .map_err(|e| VaultXError::Storage(e.to_string()))?;
        let record = match table
            .get(key)
            .map_err(|e| VaultXError::Storage(e.to_string()))?
        {
            Some(v) => v.value().to_vec(),
            None => return Ok(None),
        };
        drop(table);
        drop(read_txn);

        if record.len() < 12 {
            return Err(VaultXError::Storage("corrupt record: too short".into()));
        }
        let (nonce_bytes, ciphertext) = record.split_at(12);
        let cipher = ChaCha20Poly1305::new(&AeadKey::from(self.key.0));
        let nonce_array: [u8; 12] = nonce_bytes
            .try_into()
            .map_err(|_| VaultXError::Storage("corrupt nonce length".into()))?;
        let nonce = Nonce::from(nonce_array);
        let plaintext = cipher
            .decrypt(
                &nonce,
                Payload {
                    msg: ciphertext,
                    aad: key,
                },
            )
            .map_err(|_| VaultXError::Aead)?;
        Ok(Some(plaintext))
    }

    /// Delete the value stored under `key`.
    pub fn delete(&self, key: &[u8]) -> Result<()> {
        let write_txn = self
            .db
            .begin_write()
            .map_err(|e| VaultXError::Storage(e.to_string()))?;
        {
            let mut table = write_txn
                .open_table(DATA_TABLE)
                .map_err(|e| VaultXError::Storage(e.to_string()))?;
            table
                .remove(key)
                .map_err(|e| VaultXError::Storage(e.to_string()))?;
        }
        write_txn
            .commit()
            .map_err(|e| VaultXError::Storage(e.to_string()))?;
        Ok(())
    }
}

/// The kind of session a PIN unlocked. The UI layer must render
/// [`Session::Decoy`] identically to [`Session::Real`] — the whole point of
/// the duress system is that an observer forcing the user to unlock cannot
/// tell which one they got.
pub enum Session {
    Real(Vault),
    Decoy(Vault),
}

/// Owns the on-disk locations of the real and decoy vaults for one device
/// and implements the duress trigger.
pub struct VaultManager {
    real_path: PathBuf,
    decoy_path: PathBuf,
}

impl VaultManager {
    pub fn new(real_path: impl Into<PathBuf>, decoy_path: impl Into<PathBuf>) -> Self {
        Self {
            real_path: real_path.into(),
            decoy_path: decoy_path.into(),
        }
    }

    /// Provision both vaults with their respective PINs. Call once, on
    /// first setup.
    pub fn provision(&self, real_pin: &[u8], decoy_pin: &[u8]) -> Result<()> {
        Vault::create(&self.real_path, real_pin)?;
        Vault::create(&self.decoy_path, decoy_pin)?;
        Ok(())
    }

    /// Attempt to unlock with `pin`. Tries the real vault first; if that
    /// fails, tries the decoy vault, and if *that* succeeds, immediately
    /// triggers [`Self::panic_wipe_real`] before returning
    /// [`Session::Decoy`]. Returns an error only if neither vault accepts
    /// the PIN.
    pub fn unlock(&self, pin: &[u8]) -> Result<Session> {
        if let Ok(vault) = Vault::open(&self.real_path, pin) {
            return Ok(Session::Real(vault));
        }
        match Vault::open(&self.decoy_path, pin) {
            Ok(vault) => {
                self.panic_wipe_real()?;
                Ok(Session::Decoy(vault))
            }
            Err(_) => Err(VaultXError::Storage(
                "PIN did not match either vault".into(),
            )),
        }
    }

    /// Best-effort destruction of the real vault: overwrite the file with
    /// random bytes before deleting it (defense against casual disk
    /// forensics; on wear-leveled SSDs and copy-on-write filesystems this is
    /// not a guarantee against a well-resourced forensic examiner, and that
    /// caveat should be surfaced to the user, not hidden).
    pub fn panic_wipe_real(&self) -> Result<()> {
        if !self.real_path.exists() {
            return Ok(());
        }
        let len = std::fs::metadata(&self.real_path)
            .map_err(|e| VaultXError::Storage(e.to_string()))?
            .len();
        {
            let mut file = OpenOptions::new()
                .write(true)
                .open(&self.real_path)
                .map_err(|e| VaultXError::Storage(e.to_string()))?;
            let mut junk = vec![0u8; len as usize];
            getrandom::fill(&mut junk)
                .map_err(|e| VaultXError::Storage(format!("rng failure: {e}")))?;
            file.write_all(&junk)
                .map_err(|e| VaultXError::Storage(e.to_string()))?;
            file.sync_all().map_err(|e| VaultXError::Storage(e.to_string()))?;
            junk.zeroize();
        }
        std::fs::remove_file(&self.real_path).map_err(|e| VaultXError::Storage(e.to_string()))?;
        Ok(())
    }

    /// True if a real vault currently exists on disk (used by setup/reset
    /// flows, not by the unlock path).
    pub fn real_vault_exists(&self) -> bool {
        self.real_path.exists()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    fn temp_path(name: &str) -> PathBuf {
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let mut p = std::env::temp_dir();
        p.push(format!("vaultx_test_{name}_{n}_{}.redb", std::process::id()));
        p
    }

    #[test]
    fn put_get_round_trip() {
        let path = temp_path("roundtrip");
        let vault = Vault::create(&path, b"1234").unwrap();
        vault.put(b"greeting", b"hello matrix").unwrap();
        assert_eq!(vault.get(b"greeting").unwrap().unwrap(), b"hello matrix");
        assert_eq!(vault.get(b"missing").unwrap(), None);
        drop(vault);
        assert!(path.exists());
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn wrong_pin_is_rejected() {
        let path = temp_path("wrongpin");
        {
            Vault::create(&path, b"correct-pin").unwrap();
        }
        let err = Vault::open(&path, b"wrong-pin");
        assert!(err.is_err());
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn duress_decoy_wipes_real_vault() {
        let real_path = temp_path("real");
        let decoy_path = temp_path("decoy");
        let manager = VaultManager::new(&real_path, &decoy_path);
        manager.provision(b"9999", b"0000").unwrap();
        assert!(manager.real_vault_exists());

        match manager.unlock(b"0000").unwrap() {
            Session::Decoy(_) => {}
            Session::Real(_) => panic!("decoy PIN must not open the real vault"),
        }

        assert!(!manager.real_vault_exists(), "real vault must be wiped after decoy unlock");
        std::fs::remove_file(&decoy_path).ok();
    }

    #[test]
    fn real_pin_opens_real_vault_without_wiping_anything() {
        let real_path = temp_path("real2");
        let decoy_path = temp_path("decoy2");
        let manager = VaultManager::new(&real_path, &decoy_path);
        manager.provision(b"9999", b"0000").unwrap();

        match manager.unlock(b"9999").unwrap() {
            Session::Real(_) => {}
            Session::Decoy(_) => panic!("real PIN must open the real vault"),
        }
        assert!(manager.real_vault_exists());
        std::fs::remove_file(&real_path).ok();
        std::fs::remove_file(&decoy_path).ok();
    }
}
