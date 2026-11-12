//! Encrypted SSH key cache and decryption.
//!
//! Only SSH-key ciphers (type 5) that are neither deleted nor archived are retained from a sync.
//! Everything stored here is still encrypted with the user's Bitwarden keys (EncStrings exactly
//! as returned by the server), so the on-disk cache is encrypted by construction. Decryption
//! happens only with a user key that was just released by an authenticated Keychain read, using
//! a short-lived `bitwarden_crypto::KeyStore` that is dropped (and zeroized) immediately after.

use std::{collections::BTreeMap, path::PathBuf, str::FromStr};

use anyhow::{anyhow, Context, Result};
use bitwarden_api_api::models::{CipherType, SyncResponseModel};
use bitwarden_core::key_management::{KeySlotIds, PrivateKeySlotId, SymmetricKeySlotId};
use bitwarden_crypto::{
    Decryptable, EncString, KeyStore, KeyStoreContext, SymmetricCryptoKey, UnsignedSharedKey,
};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::config::write_private_file;

/// One SSH key cipher, still encrypted.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EncryptedSshCipher {
    pub id: String,
    pub organization_id: Option<String>,
    /// Per-cipher key, wrapped with the user or organization key.
    pub key: Option<String>,
    pub name: String,
    pub private_key: String,
    pub public_key: String,
    pub fingerprint: Option<String>,
    pub revision_date: String,
}

/// The subset of a sync response WardenFuse needs, all secrets still encrypted.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct EncryptedVault {
    pub user_id: String,
    pub email: String,
    /// User's asymmetric private key (wrapped with the user key), needed for org keys.
    pub private_key: Option<String>,
    /// Organization id -> organization key (encapsulated with the user's public key).
    pub org_keys: BTreeMap<String, String>,
    pub ciphers: Vec<EncryptedSshCipher>,
    /// Unix seconds of the sync that produced this data.
    pub synced_at: i64,
}

impl EncryptedVault {
    /// Extracts SSH key ciphers from a sync response.
    pub fn from_sync(resp: &SyncResponseModel, synced_at: i64) -> Result<Self> {
        let profile = resp
            .profile
            .as_ref()
            .ok_or_else(|| anyhow!("sync response has no profile"))?;
        let user_id = profile
            .id
            .map(|u| u.to_string())
            .ok_or_else(|| anyhow!("sync response profile has no id"))?;
        let email = profile.email.clone().unwrap_or_default();
        let private_key = profile
            .account_keys
            .as_ref()
            .and_then(|k| k.public_key_encryption_key_pair.wrapped_private_key.clone())
            .or_else(|| profile.private_key.clone());
        let mut org_keys = BTreeMap::new();
        for org in profile.organizations.iter().flatten() {
            if let (Some(id), Some(key)) = (org.id, org.key.as_ref()) {
                org_keys.insert(id.to_string(), key.clone());
            }
        }
        let mut ciphers = Vec::new();
        for c in resp.ciphers.iter().flatten() {
            if c.r#type != Some(CipherType::SSHKey) {
                continue;
            }
            // Deleted (trash) and archived items must never be offered by the agent.
            if c.deleted_date.is_some() || c.archived_date.is_some() {
                continue;
            }
            let (Some(id), Some(name), Some(ssh)) = (c.id, c.name.clone(), c.ssh_key.as_ref())
            else {
                continue;
            };
            let (Some(private_key), Some(public_key)) =
                (ssh.private_key.clone(), ssh.public_key.clone())
            else {
                continue;
            };
            ciphers.push(EncryptedSshCipher {
                id: id.to_string(),
                organization_id: c.organization_id.map(|o| o.to_string()),
                key: c.key.clone(),
                name,
                private_key,
                public_key,
                fingerprint: ssh.key_fingerprint.clone(),
                revision_date: c.revision_date.clone().unwrap_or_default(),
            });
        }
        ciphers.sort_by(|a, b| a.id.cmp(&b.id));
        Ok(Self {
            user_id,
            email,
            private_key,
            org_keys,
            ciphers,
            synced_at,
        })
    }

    #[must_use]
    pub fn cipher(&self, id: &str) -> Option<&EncryptedSshCipher> {
        self.ciphers.iter().find(|c| c.id == id)
    }
}

/// Decrypted, non-secret metadata of a key (safe to keep in memory while locked).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct KeyMeta {
    pub cipher_id: String,
    pub revision_date: String,
    pub name: String,
    /// OpenSSH public key line `alg base64` (no comment).
    pub public_key: String,
    pub fingerprint: String,
}

/// Decrypted private key PEM, zeroized on drop.
pub struct DecryptedKey {
    pub meta: KeyMeta,
    pub private_key_pem: Zeroizing<String>,
}

/// Decrypts vault data using a just-released user key.
pub struct VaultDecryptor<'a> {
    vault: &'a EncryptedVault,
    store: KeyStore<KeySlotIds>,
}

impl<'a> VaultDecryptor<'a> {
    pub fn new(vault: &'a EncryptedVault, user_key: &[u8]) -> Result<Self> {
        let key_str = Zeroizing::new(
            std::str::from_utf8(user_key)
                .map_err(|_| anyhow!("stored user key is not valid"))?
                .to_owned(),
        );
        let user_key = SymmetricCryptoKey::try_from(key_str.as_str().to_owned())
            .map_err(|_| anyhow!("stored user key is not valid"))?;
        let store = KeyStore::<KeySlotIds>::default();
        {
            let mut ctx = store.context_mut();
            #[allow(deprecated)]
            ctx.set_symmetric_key(SymmetricKeySlotId::User, user_key)
                .map_err(|e| anyhow!("unable to load user key: {e}"))?;
        }
        Ok(Self { vault, store })
    }

    fn cipher_key_slot(
        &self,
        ctx: &mut KeyStoreContext<'_, KeySlotIds>,
        c: &EncryptedSshCipher,
    ) -> Result<SymmetricKeySlotId> {
        let base = match &c.organization_id {
            None => SymmetricKeySlotId::User,
            Some(org) => self.org_key_slot(ctx, org)?,
        };
        match &c.key {
            None => Ok(base),
            Some(k) => {
                let enc = EncString::from_str(k).map_err(|_| anyhow!("invalid cipher key"))?;
                ctx.unwrap_symmetric_key(base, &enc)
                    .map_err(|_| anyhow!("unable to decrypt cipher key"))
            }
        }
    }

    fn org_key_slot(
        &self,
        ctx: &mut KeyStoreContext<'_, KeySlotIds>,
        org: &str,
    ) -> Result<SymmetricKeySlotId> {
        let enc_org_key = self
            .vault
            .org_keys
            .get(org)
            .ok_or_else(|| anyhow!("missing organization key"))?;
        if !ctx.has_private_key(PrivateKeySlotId::UserPrivateKey) {
            self.load_account_private_key(ctx)?;
        }
        let shared =
            UnsignedSharedKey::from_str(enc_org_key).map_err(|_| anyhow!("invalid org key"))?;
        shared
            .decapsulate(PrivateKeySlotId::UserPrivateKey, ctx)
            .map_err(|_| anyhow!("unable to decrypt organization key"))
    }

    /// Pair only with a user key that decrypts the current synced account key.
    pub(crate) fn verify_user_key(&self) -> Result<()> {
        self.load_account_private_key(&mut self.store.context_mut())
    }

    fn load_account_private_key(&self, ctx: &mut KeyStoreContext<'_, KeySlotIds>) -> Result<()> {
        let pk = self
            .vault
            .private_key
            .as_ref()
            .ok_or_else(|| anyhow!("missing account private key"))?;
        let enc = EncString::from_str(pk).map_err(|_| anyhow!("invalid private key"))?;
        let local = ctx
            .unwrap_private_key(SymmetricKeySlotId::User, &enc)
            .map_err(|_| anyhow!("unable to decrypt account private key"))?;
        ctx.persist_private_key(local, PrivateKeySlotId::UserPrivateKey)
            .map_err(|e| anyhow!("{e}"))
    }

    fn decrypt_str(
        ctx: &mut KeyStoreContext<'_, KeySlotIds>,
        slot: SymmetricKeySlotId,
        value: &str,
    ) -> Result<String> {
        let enc = EncString::from_str(value).map_err(|_| anyhow!("invalid encrypted field"))?;
        enc.decrypt(ctx, slot)
            .map_err(|_| anyhow!("unable to decrypt field"))
    }

    fn meta_with_ctx(
        &self,
        ctx: &mut KeyStoreContext<'_, KeySlotIds>,
        c: &EncryptedSshCipher,
    ) -> Result<(KeyMeta, SymmetricKeySlotId)> {
        let slot = self.cipher_key_slot(ctx, c)?;
        let name = Self::decrypt_str(ctx, slot, &c.name)?;
        let public_key = Self::decrypt_str(ctx, slot, &c.public_key)?;
        let public_key = normalize_public_key(&public_key)?;
        let fingerprint = match &c.fingerprint {
            Some(f) => Self::decrypt_str(ctx, slot, f).unwrap_or_default(),
            None => String::new(),
        };
        Ok((
            KeyMeta {
                cipher_id: c.id.clone(),
                revision_date: c.revision_date.clone(),
                name,
                public_key,
                fingerprint,
            },
            slot,
        ))
    }

    /// Decrypts metadata for every cipher. Ciphers that fail to decrypt are skipped and
    /// reported, never fatal.
    pub fn all_metadata(&self) -> (Vec<KeyMeta>, Vec<String>) {
        let mut ctx = self.store.context_mut();
        let mut out = Vec::new();
        let mut failed = Vec::new();
        for c in &self.vault.ciphers {
            match self.meta_with_ctx(&mut ctx, c) {
                Ok((m, _)) => out.push(m),
                Err(e) => {
                    tracing::warn!(cipher_id = %c.id, error = %e, "Skipping SSH key");
                    failed.push(c.id.clone());
                }
            }
        }
        (out, failed)
    }

    /// Decrypts one SSH private key.
    pub fn decrypt_key(&self, cipher_id: &str) -> Result<DecryptedKey> {
        let c = self
            .vault
            .cipher(cipher_id)
            .ok_or_else(|| anyhow!("SSH key no longer exists in the vault"))?;
        let mut ctx = self.store.context_mut();
        let (meta, slot) = self.meta_with_ctx(&mut ctx, c)?;
        let pem = Zeroizing::new(Self::decrypt_str(&mut ctx, slot, &c.private_key)?);
        Ok(DecryptedKey {
            meta,
            private_key_pem: pem,
        })
    }
}

/// `alg base64 [comment]` -> `alg base64`.
pub fn normalize_public_key(s: &str) -> Result<String> {
    let mut parts = s.split_whitespace();
    let alg = parts.next().ok_or_else(|| anyhow!("empty public key"))?;
    let b64 = parts
        .next()
        .ok_or_else(|| anyhow!("malformed public key"))?;
    Ok(format!("{alg} {b64}"))
}

/// On-disk cache of the encrypted vault (0600 in the app data dir).
pub struct VaultCache {
    path: PathBuf,
}

impl VaultCache {
    #[must_use]
    pub fn new(data_dir: &std::path::Path) -> Self {
        Self {
            path: data_dir.join("vault-cache.json"),
        }
    }

    #[must_use]
    pub fn load(&self, user_id: &str) -> Option<EncryptedVault> {
        let data = std::fs::read(&self.path).ok()?;
        let v: EncryptedVault = serde_json::from_slice(&data).ok()?;
        (v.user_id == user_id).then_some(v)
    }

    pub fn save(&self, v: &EncryptedVault) -> Result<()> {
        let data = serde_json::to_vec(v)?;
        write_private_file(&self.path, &data).context("writing vault cache")
    }

    pub fn delete(&self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use bitwarden_crypto::{KeyEncryptable, SymmetricKeyAlgorithm};

    use super::*;

    pub(crate) const TEST_ED25519_PEM: &str = "-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACAOYor3+kyAsXYs2sGikmUuhpxmVf2hAGd2TK7KwN4N9gAAAJj79ujB+/bo
wQAAAAtzc2gtZWQyNTUxOQAAACAOYor3+kyAsXYs2sGikmUuhpxmVf2hAGd2TK7KwN4N9g
AAAEAgAQkLDKjON00XO+Y09BoIBuQsAXAx6HUhQoTEodVzig5iivf6TICxdizawaKSZS6G
nGZV/aEAZ3ZMrsrA3g32AAAAEHRlc3RAZXhhbXBsZS5jb20BAgMEBQ==
-----END OPENSSH PRIVATE KEY-----";
    pub(crate) const TEST_ED25519_PUB: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIA5iivf6TICxdizawaKSZS6GnGZV/aEAZ3ZMrsrA3g32 test@example.com";

    pub(crate) fn make_user_key() -> (SymmetricCryptoKey, Zeroizing<Vec<u8>>) {
        let k = SymmetricCryptoKey::make(SymmetricKeyAlgorithm::Aes256CbcHmac);
        let b = Zeroizing::new(k.to_base64().to_string().into_bytes());
        (k, b)
    }

    fn enc(key: &SymmetricCryptoKey, s: &str) -> String {
        s.to_owned().encrypt_with_key(key).unwrap().to_string()
    }

    pub(crate) fn make_cipher(
        key: &SymmetricCryptoKey,
        id: &str,
        name: &str,
    ) -> EncryptedSshCipher {
        EncryptedSshCipher {
            id: id.into(),
            organization_id: None,
            key: None,
            name: enc(key, name),
            private_key: enc(key, TEST_ED25519_PEM),
            public_key: enc(key, TEST_ED25519_PUB),
            fingerprint: Some(enc(key, "SHA256:test")),
            revision_date: "2026-01-01T00:00:00Z".into(),
        }
    }

    #[test]
    fn decrypts_metadata_and_private_key() {
        let (k, kb) = make_user_key();
        let v = EncryptedVault {
            user_id: "u".into(),
            ciphers: vec![make_cipher(&k, "c1", "GitHub")],
            ..Default::default()
        };
        let d = VaultDecryptor::new(&v, &kb).unwrap();
        let (meta, failed) = d.all_metadata();
        assert!(failed.is_empty());
        assert_eq!(meta[0].name, "GitHub");
        assert_eq!(
            meta[0].public_key,
            normalize_public_key(TEST_ED25519_PUB).unwrap()
        );
        let key = d.decrypt_key("c1").unwrap();
        assert!(key.private_key_pem.contains("OPENSSH PRIVATE KEY"));
    }

    #[test]
    fn per_cipher_key_is_unwrapped() {
        let (user, kb) = make_user_key();
        let cipher_key = SymmetricCryptoKey::make(SymmetricKeyAlgorithm::Aes256CbcHmac);
        let wrapped = {
            let store = KeyStore::<KeySlotIds>::default();
            let mut ctx = store.context_mut();
            let u = ctx.add_local_symmetric_key(user.clone());
            let ck = ctx.add_local_symmetric_key(cipher_key.clone());
            ctx.wrap_symmetric_key(u, ck).unwrap().to_string()
        };
        let mut c = make_cipher(&cipher_key, "c1", "Wrapped");
        c.key = Some(wrapped);
        let v = EncryptedVault {
            user_id: "u".into(),
            ciphers: vec![c],
            ..Default::default()
        };
        let d = VaultDecryptor::new(&v, &kb).unwrap();
        assert_eq!(d.all_metadata().0[0].name, "Wrapped");
    }

    #[test]
    fn wrong_key_fails_closed() {
        let (k, _) = make_user_key();
        let (_, other) = make_user_key();
        let v = EncryptedVault {
            user_id: "u".into(),
            ciphers: vec![make_cipher(&k, "c1", "X")],
            ..Default::default()
        };
        let d = VaultDecryptor::new(&v, &other).unwrap();
        let (meta, failed) = d.all_metadata();
        assert!(meta.is_empty());
        assert_eq!(failed, vec!["c1".to_string()]);
        assert!(d.decrypt_key("c1").is_err());
    }

    #[test]
    fn from_sync_filters_deleted_archived_and_non_ssh() {
        use bitwarden_api_api::models::{
            CipherDetailsResponseModel, CipherSshKeyModel, ProfileResponseModel,
        };
        let mk = |t, deleted: bool, archived: bool| CipherDetailsResponseModel {
            id: Some(uuid::Uuid::new_v4()),
            r#type: Some(t),
            name: Some("2.x|y|z".into()),
            ssh_key: Some(Box::new(CipherSshKeyModel {
                private_key: Some("a".into()),
                public_key: Some("b".into()),
                key_fingerprint: None,
            })),
            deleted_date: deleted.then(|| "2026-01-01".into()),
            archived_date: archived.then(|| "2026-01-01".into()),
            ..CipherDetailsResponseModel::new()
        };
        let resp = SyncResponseModel {
            profile: Some(Box::new(ProfileResponseModel {
                id: Some(uuid::Uuid::new_v4()),
                ..ProfileResponseModel::new()
            })),
            ciphers: Some(vec![
                mk(CipherType::SSHKey, false, false),
                mk(CipherType::SSHKey, true, false),
                mk(CipherType::SSHKey, false, true),
                mk(CipherType::Login, false, false),
            ]),
            ..SyncResponseModel::new()
        };
        let v = EncryptedVault::from_sync(&resp, 0).unwrap();
        assert_eq!(v.ciphers.len(), 1);
    }

    #[test]
    fn cache_is_private_and_user_bound() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let cache = VaultCache::new(dir.path());
        let v = EncryptedVault {
            user_id: "u1".into(),
            ..Default::default()
        };
        cache.save(&v).unwrap();
        let mode = std::fs::metadata(dir.path().join("vault-cache.json"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
        assert_eq!(cache.load("u1"), Some(v));
        assert_eq!(cache.load("u2"), None);
    }
}
