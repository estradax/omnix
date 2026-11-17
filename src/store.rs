//! OAuth credential storage for rmcp's `CredentialStore`.
//!
//! Primary backend: the OS keychain (`keyring`). Fallback (headless/SSH/no keychain):
//! an encrypted file (ChaCha20-Poly1305) with 0600 permissions. The file key is derived
//! with Argon2id from `OMNIX_PASSPHRASE` when set; otherwise a random master key kept
//! in a separate 0600 file (this only protects against the credentials file being
//! copied or synced alone, not against a local attacker reading both files).
//! `OMNIX_CREDENTIAL_STORE=file` forces the file backend; `=keychain` forbids fallback.
//! Tokens are never logged; serialized buffers are zeroized.

use anyhow::{Context, Result, anyhow};
use async_trait::async_trait;
use chacha20poly1305::{
    ChaCha20Poly1305, Key, Nonce,
    aead::{Aead, KeyInit},
};
use rmcp::transport::auth::{
    AuthError, CredentialRefreshGuard, CredentialStore, StoredCredentials,
};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

const SERVICE: &str = "omnix";

pub struct OmnixStore {
    /// Stable id for this server's credentials (name + url hash).
    key: String,
    dir: PathBuf,
}

pub fn config_dir() -> PathBuf {
    if let Ok(d) = std::env::var("OMNIX_CONFIG_DIR") {
        return PathBuf::from(d);
    }
    dirs::config_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("omnix")
}

impl OmnixStore {
    pub fn new(server: &str, url: &str) -> Self {
        let h = hex::encode(&Sha256::digest(url.as_bytes())[..6]);
        let safe: String = server
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || c == '-' {
                    c
                } else {
                    '_'
                }
            })
            .collect();
        OmnixStore {
            key: format!("{safe}-{h}"),
            dir: config_dir(),
        }
    }

    fn file_path(&self) -> PathBuf {
        self.dir
            .join("credentials")
            .join(format!("{}.enc", self.key))
    }

    fn mode() -> String {
        std::env::var("OMNIX_CREDENTIAL_STORE").unwrap_or_default()
    }

    // ---- keychain ----
    async fn kc_get(&self) -> Result<Option<Zeroizing<String>>> {
        let key = self.key.clone();
        tokio::task::spawn_blocking(move || {
            let e = keyring::Entry::new(SERVICE, &key)?;
            match e.get_password() {
                Ok(p) => Ok(Some(Zeroizing::new(p))),
                Err(keyring::Error::NoEntry) => Ok(None),
                Err(e) => Err(anyhow!(e)),
            }
        })
        .await?
    }

    async fn kc_set(&self, v: Zeroizing<String>) -> Result<()> {
        let key = self.key.clone();
        tokio::task::spawn_blocking(move || {
            Ok(keyring::Entry::new(SERVICE, &key)?.set_password(&v)?)
        })
        .await?
    }

    async fn kc_delete(&self) -> Result<()> {
        let key = self.key.clone();
        tokio::task::spawn_blocking(move || {
            match keyring::Entry::new(SERVICE, &key)?.delete_credential() {
                Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
                Err(e) => Err(anyhow!(e)),
            }
        })
        .await?
    }

    // ---- encrypted file ----
    fn file_get(&self) -> Result<Option<Zeroizing<String>>> {
        let p = self.file_path();
        let Ok(blob) = std::fs::read(&p) else {
            return Ok(None);
        };
        let plain =
            decrypt(&self.dir, &blob).with_context(|| format!("decrypting {}", p.display()))?;
        Ok(Some(Zeroizing::new(String::from_utf8(plain.to_vec())?)))
    }

    fn file_set(&self, v: &str) -> Result<()> {
        let p = self.file_path();
        std::fs::create_dir_all(p.parent().unwrap())?;
        write_private(&p, &encrypt(&self.dir, v.as_bytes())?)
    }

    async fn get(&self) -> Result<Option<Zeroizing<String>>> {
        match Self::mode().as_str() {
            "file" => self.file_get(),
            "keychain" => self.kc_get().await,
            _ => match self.kc_get().await {
                Ok(Some(v)) => Ok(Some(v)),
                // Not in the keychain (or it's unavailable): check the file fallback.
                Ok(None) | Err(_) => self.file_get(),
            },
        }
    }

    async fn set(&self, v: Zeroizing<String>) -> Result<()> {
        match Self::mode().as_str() {
            "file" => self.file_set(&v),
            "keychain" => self.kc_set(v).await,
            _ => match self.kc_set(v.clone()).await {
                Ok(()) => {
                    let _ = std::fs::remove_file(self.file_path());
                    Ok(())
                }
                Err(_) => self.file_set(&v),
            },
        }
    }

    async fn delete(&self) -> Result<()> {
        let _ = self.kc_delete().await;
        let _ = std::fs::remove_file(self.file_path());
        Ok(())
    }
}

fn store_err(e: impl std::fmt::Display) -> AuthError {
    // Messages come from our own context strings / OS errors, never token data.
    AuthError::CredentialStoreError(e.to_string())
}

#[async_trait]
impl CredentialStore for OmnixStore {
    async fn load(&self) -> Result<Option<StoredCredentials>, AuthError> {
        let Some(s) = self.get().await.map_err(|e| store_err(format!("{e:#}")))? else {
            return Ok(None);
        };
        serde_json::from_str(&s)
            .map(Some)
            .map_err(|_| store_err("stored credentials are corrupt; run `omnix login` again"))
    }

    async fn save(&self, c: StoredCredentials) -> Result<(), AuthError> {
        let json = Zeroizing::new(serde_json::to_string(&c).map_err(store_err)?);
        self.set(json)
            .await
            .map_err(|e| store_err(format!("{e:#}")))
    }

    async fn clear(&self) -> Result<(), AuthError> {
        self.delete().await.map_err(|e| store_err(format!("{e:#}")))
    }

    /// Serialize refreshes across processes (several agents may run `omnix serve` at once):
    /// refresh tokens rotate, so two processes refreshing from the same one would break login.
    async fn acquire_refresh_guard(&self) -> Result<Option<CredentialRefreshGuard>, AuthError> {
        let path = self
            .dir
            .join("credentials")
            .join(format!("{}.lock", self.key));
        let file = tokio::task::spawn_blocking(move || -> std::io::Result<std::fs::File> {
            std::fs::create_dir_all(path.parent().unwrap())?;
            let f = std::fs::OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(false)
                .open(&path)?;
            f.lock()?; // blocks until other processes release; released when the File drops
            Ok(f)
        })
        .await
        .map_err(store_err)?
        .map_err(store_err)?;
        Ok(Some(CredentialRefreshGuard::new(file)))
    }
}

// ---- crypto ----

const MAGIC: &[u8; 4] = b"OMX1";

fn master_key(dir: &Path, salt: &[u8; 16], use_pass: bool) -> Result<Zeroizing<[u8; 32]>> {
    let mut key = Zeroizing::new([0u8; 32]);
    if use_pass {
        let pass = std::env::var("OMNIX_PASSPHRASE")
            .context("file was encrypted with OMNIX_PASSPHRASE, which is not set")?;
        argon2::Argon2::default()
            .hash_password_into(pass.as_bytes(), salt, &mut *key)
            .map_err(|e| anyhow!("kdf: {e}"))?;
    } else {
        let p = dir.join("master.key");
        match std::fs::read(&p) {
            Ok(b) if b.len() == 32 => key.copy_from_slice(&b),
            _ => {
                std::fs::create_dir_all(dir)?;
                rand::fill(&mut key[..]);
                write_private(&p, &*key)?;
            }
        }
    }
    Ok(key)
}

fn encrypt(dir: &Path, plain: &[u8]) -> Result<Vec<u8>> {
    let use_pass = std::env::var("OMNIX_PASSPHRASE").is_ok_and(|p| !p.is_empty());
    let mut salt = [0u8; 16];
    rand::fill(&mut salt[..]);
    let mut nonce = [0u8; 12];
    rand::fill(&mut nonce[..]);
    let key = master_key(dir, &salt, use_pass)?;
    let ct = ChaCha20Poly1305::new(&Key::from(*key))
        .encrypt(&Nonce::from(nonce), plain)
        .map_err(|_| anyhow!("encryption failed"))?;
    let mut out = MAGIC.to_vec();
    out.push(use_pass as u8);
    out.extend_from_slice(&salt);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

fn decrypt(dir: &Path, blob: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    if blob.len() < 4 + 1 + 16 + 12 + 16 || &blob[..4] != MAGIC {
        return Err(anyhow!("not an omnix credentials file"));
    }
    let use_pass = blob[4] == 1;
    let salt: [u8; 16] = blob[5..21].try_into()?;
    let nonce = &blob[21..33];
    let key = master_key(dir, &salt, use_pass)?;
    let plain = ChaCha20Poly1305::new(&Key::from(*key))
        .decrypt(
            &Nonce::try_from(nonce).map_err(|_| anyhow!("bad nonce"))?,
            &blob[33..],
        )
        .map_err(|_| anyhow!("decryption failed (wrong passphrase/key or corrupt file)"))?;
    Ok(Zeroizing::new(plain))
}

fn write_private(p: &Path, data: &[u8]) -> Result<()> {
    use std::io::Write;
    #[cfg(unix)]
    use std::os::unix::fs::OpenOptionsExt;
    let tmp = p.with_extension("tmp");
    let mut o = std::fs::OpenOptions::new();
    o.write(true).create(true).truncate(true);
    #[cfg(unix)]
    o.mode(0o600);
    let mut f = o.open(&tmp)?;
    f.write_all(data)?;
    f.sync_all()?;
    std::fs::rename(&tmp, p)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmpdir(n: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("omnix-store-{n}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn roundtrip_and_tamper_detection() {
        let d = tmpdir("rt");
        let blob = encrypt(&d, b"secret-token").unwrap();
        assert!(!blob.windows(12).any(|w| w == b"secret-token"));
        assert_eq!(&**decrypt(&d, &blob).unwrap(), b"secret-token");
        let mut bad = blob.clone();
        *bad.last_mut().unwrap() ^= 1;
        assert!(decrypt(&d, &bad).is_err());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let m = std::fs::metadata(d.join("master.key"))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(m & 0o777, 0o600);
        }
    }

    #[tokio::test]
    async fn file_backend_save_load_clear() {
        let d = tmpdir("fb");
        unsafe { std::env::set_var("OMNIX_CREDENTIAL_STORE", "file") };
        let s = OmnixStore {
            key: "srv-abc".into(),
            dir: d.clone(),
        };
        assert!(s.load().await.unwrap().is_none());
        s.save(StoredCredentials::new(
            "cid".into(),
            None,
            vec!["a".into()],
            None,
        ))
        .await
        .unwrap();
        let got = s.load().await.unwrap().unwrap();
        assert_eq!(got.client_id, "cid");
        assert_eq!(got.granted_scopes, ["a"]);
        let raw = std::fs::read(s.file_path()).unwrap();
        assert!(!raw.windows(3).any(|w| w == b"cid"));
        s.clear().await.unwrap();
        assert!(s.load().await.unwrap().is_none());
    }
}

#[cfg(test)]
mod lock_tests {
    use super::*;

    #[tokio::test]
    async fn refresh_guard_is_exclusive() {
        let d = std::env::temp_dir().join(format!("omnix-lock-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        let s = std::sync::Arc::new(OmnixStore {
            key: "k".into(),
            dir: d.clone(),
        });
        let g1 = s.acquire_refresh_guard().await.unwrap().unwrap();
        let s2 = s.clone();
        let waiter = tokio::spawn(async move { s2.acquire_refresh_guard().await.map(|_| ()) });
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        assert!(
            !waiter.is_finished(),
            "second guard acquired while the first was held"
        );
        drop(g1);
        tokio::time::timeout(std::time::Duration::from_secs(5), waiter)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        let _ = std::fs::remove_dir_all(&d);
    }
}
