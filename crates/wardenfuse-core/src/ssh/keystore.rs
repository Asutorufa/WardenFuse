//! A [`KeyStore`] for the upstream Bitwarden SSH agent that gates private key access on
//! authorization grants.
//!
//! * Public metadata (key name + public key) is kept separately and is what the agent lists.
//! * Decrypted private keys live in the upstream [`InMemoryEncryptedKeyStore`] (mlock'ed,
//!   encrypted with an ephemeral key) **only** while a grant or a one-shot authorization covers
//!   them, and are purged as soon as the last grant expires.
//! * `get_private_key` re-checks the grant against the monotonic clock, so even a late purge
//!   cannot be used to sign without a valid authorization (fail closed).

use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex, MutexGuard,
    },
    time::Duration,
};

use anyhow::{anyhow, Result};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use ssh_agent::{
    InMemoryEncryptedKeyStore, KeyStore, PrivateKey, PublicKey, QueryableKeyData, SSHKeyData,
};

use crate::{
    authz::{Authorizations, ProcessId},
    clock::MonoTime,
};

/// Key metadata as the agent sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetaKeyData {
    pub public_key: PublicKey,
    pub name: String,
    pub cipher_id: String,
}

impl QueryableKeyData for MetaKeyData {
    fn public_key(&self) -> &PublicKey {
        &self.public_key
    }
    fn name(&self) -> &String {
        &self.name
    }
    fn cipher_id(&self) -> &String {
        &self.cipher_id
    }
}

/// Parses an `alg base64` OpenSSH public key line.
pub fn parse_public_key(line: &str) -> Result<PublicKey> {
    let mut parts = line.split_whitespace();
    let alg = parts.next().ok_or_else(|| anyhow!("empty public key"))?;
    let blob = STANDARD
        .decode(
            parts
                .next()
                .ok_or_else(|| anyhow!("malformed public key"))?,
        )
        .map_err(|_| anyhow!("malformed public key"))?;
    Ok(PublicKey {
        alg: alg.to_owned(),
        blob,
    })
}

/// A single-use authorization (TTL = 0 / "every time"), valid for a short window only.
const ONE_SHOT_WINDOW: Duration = Duration::from_secs(30);

struct Inner {
    meta: Vec<MetaKeyData>,
    meta_known: bool,
    one_shot: HashMap<String, Vec<MonoTime>>,
}

/// Shared, cloneable handle.
#[derive(Clone)]
pub struct GatedKeyStore {
    inner: Arc<Mutex<Inner>>,
    private: Arc<InMemoryEncryptedKeyStore>,
    authz: Arc<Mutex<Authorizations>>,
    list_when_locked: Arc<AtomicBool>,
    /// False when the agent must refuse everything (logged out, stale vault, disabled).
    usable: Arc<AtomicBool>,
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

impl GatedKeyStore {
    pub fn new(authz: Arc<Mutex<Authorizations>>) -> Self {
        Self {
            inner: Arc::new(Mutex::new(Inner {
                meta: Vec::new(),
                meta_known: false,
                one_shot: HashMap::new(),
            })),
            private: Arc::new(InMemoryEncryptedKeyStore::new()),
            authz,
            list_when_locked: Arc::new(AtomicBool::new(true)),
            usable: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn authz(&self) -> &Arc<Mutex<Authorizations>> {
        &self.authz
    }

    pub fn set_list_when_locked(&self, v: bool) {
        self.list_when_locked.store(v, Ordering::SeqCst);
    }

    pub fn set_usable(&self, v: bool) {
        self.usable.store(v, Ordering::SeqCst);
        if !v {
            self.purge_all_private();
        }
    }

    #[must_use]
    pub fn is_usable(&self) -> bool {
        self.usable.load(Ordering::SeqCst)
    }

    /// Replaces the public metadata (atomically) and drops private material and grants of keys
    /// that changed or disappeared.
    pub fn set_metadata(&self, meta: Vec<MetaKeyData>) {
        let mut inner = lock(&self.inner);
        let removed: Vec<MetaKeyData> = inner
            .meta
            .iter()
            .filter(|old| !meta.contains(old))
            .cloned()
            .collect();
        inner.meta = meta;
        inner.meta_known = true;
        for m in &removed {
            inner.one_shot.remove(&m.public_key.to_string());
        }
        drop(inner);
        if !removed.is_empty() {
            let mut authz = lock(&self.authz);
            for m in &removed {
                authz.revoke_key(&m.public_key.to_string());
            }
            drop(authz);
            self.purge_unauthorized();
        }
    }

    /// Marks the metadata as incomplete (new or changed keys are pending decryption). Listing
    /// then requires an authentication, which decrypts the full list.
    pub fn mark_metadata_incomplete(&self) {
        lock(&self.inner).meta_known = false;
    }

    /// Forgets which keys are known (before first decrypt / after logout).
    pub fn forget_metadata(&self) {
        let mut inner = lock(&self.inner);
        inner.meta.clear();
        inner.meta_known = false;
        inner.one_shot.clear();
        drop(inner);
        self.purge_all_private();
    }

    #[must_use]
    pub fn metadata_known(&self) -> bool {
        lock(&self.inner).meta_known
    }

    #[must_use]
    pub fn metadata(&self) -> Vec<MetaKeyData> {
        lock(&self.inner).meta.clone()
    }

    #[must_use]
    pub fn meta_for(&self, public_key: &PublicKey) -> Option<MetaKeyData> {
        lock(&self.inner)
            .meta
            .iter()
            .find(|m| &m.public_key == public_key)
            .cloned()
    }

    /// Inserts decrypted private key material. The key's public key must match the vault
    /// metadata, otherwise it is rejected.
    pub fn insert_private(&self, key: SSHKeyData) -> Result<()> {
        let known = self.meta_for(key.public_key()).is_some();
        if !known {
            return Err(anyhow!(
                "decrypted private key does not match the vault public key"
            ));
        }
        self.private.insert(key)
    }

    #[must_use]
    pub fn has_private(&self, public_key: &PublicKey) -> bool {
        matches!(self.private.get(public_key), Ok(Some(_)))
    }

    pub fn add_one_shot(&self, public_key: &PublicKey) {
        let now = lock(&self.authz).now();
        if let Some(exp) = now.checked_add(ONE_SHOT_WINDOW) {
            lock(&self.inner)
                .one_shot
                .entry(public_key.to_string())
                .or_default()
                .push(exp);
        }
    }

    fn consume_one_shot(&self, key_id: &str, now: MonoTime) -> bool {
        let mut inner = lock(&self.inner);
        let Some(list) = inner.one_shot.get_mut(key_id) else {
            return false;
        };
        list.retain(|exp| now < *exp);
        let ok = !list.is_empty();
        if ok {
            list.remove(0);
        }
        if list.is_empty() {
            inner.one_shot.remove(key_id);
        }
        ok
    }

    fn has_pending_one_shot(&self, key_id: &str, now: MonoTime) -> bool {
        lock(&self.inner)
            .one_shot
            .get(key_id)
            .is_some_and(|l| l.iter().any(|exp| now < *exp))
    }

    pub fn purge_all_private(&self) {
        self.private.clear();
        lock(&self.inner).one_shot.clear();
    }

    /// Removes private key material that is no longer covered by any grant or pending
    /// one-shot authorization.
    pub fn purge_unauthorized(&self) {
        let meta = self.metadata();
        let mut keep = Vec::new();
        let mut changed = false;
        for m in meta {
            let Ok(Some(k)) = self.private.get(&m.public_key) else {
                continue;
            };
            let id = m.public_key.to_string();
            let now = lock(&self.authz).now();
            let authorized =
                lock(&self.authz).key_has_grant(&id) || self.has_pending_one_shot(&id, now);
            if authorized {
                keep.push(k);
            } else {
                changed = true;
            }
        }
        // Keys in the private store that are no longer in the metadata are dropped as well.
        let private_count = self
            .private
            .get_all_public_keys_and_names()
            .map(|v| v.len())
            .unwrap_or(0);
        if changed || private_count != keep.len() {
            if keep.is_empty() {
                self.private.clear();
            } else if let Err(e) = self.private.replace(keep) {
                tracing::error!(error = %e, "Failed to rebuild key store, clearing");
                self.private.clear();
            }
        }
    }

    #[must_use]
    pub fn private_count(&self) -> usize {
        self.private
            .get_all_public_keys_and_names()
            .map(|v| v.len())
            .unwrap_or(0)
    }

    /// Whether `process` is currently authorized for `public_key` (for the approver).
    pub fn is_authorized(&self, public_key: &PublicKey, process: &ProcessId) -> bool {
        lock(&self.authz).is_authorized(&public_key.to_string(), process)
    }
}

impl KeyStore for GatedKeyStore {
    type KeyData = MetaKeyData;

    fn insert(&self, key_data: Self::KeyData) -> Result<()> {
        let mut inner = lock(&self.inner);
        inner.meta.retain(|m| m.public_key != key_data.public_key);
        inner.meta.push(key_data);
        inner.meta_known = true;
        Ok(())
    }

    fn get(&self, public_key: &PublicKey) -> Result<Option<Self::KeyData>> {
        if !self.is_usable() {
            return Ok(None);
        }
        Ok(self.meta_for(public_key))
    }

    fn get_private_key(&self, public_key: &PublicKey) -> Result<Option<PrivateKey>> {
        if !self.is_usable() {
            return Ok(None);
        }
        let id = public_key.to_string();
        let now = lock(&self.authz).now();
        let authorized = lock(&self.authz).key_has_grant(&id) || self.consume_one_shot(&id, now);
        if !authorized {
            tracing::warn!("Private key requested without a valid authorization; refusing");
            return Ok(None);
        }
        let key = self.private.get_private_key(public_key)?;
        // Drop single-use material immediately after it was handed out for one signature.
        if !lock(&self.authz).key_has_grant(&id) && !self.has_pending_one_shot(&id, now) {
            self.purge_unauthorized();
        }
        Ok(key)
    }

    fn get_all_public_keys_and_names(&self) -> Result<Vec<(PublicKey, String)>> {
        if !self.is_usable() {
            return Ok(Vec::new());
        }
        Ok(lock(&self.inner)
            .meta
            .iter()
            .map(|m| (m.public_key.clone(), m.name.clone()))
            .collect())
    }

    fn replace(&self, keys: Vec<Self::KeyData>) -> Result<()> {
        self.set_metadata(keys);
        Ok(())
    }

    fn clear(&self) {
        self.forget_metadata();
    }

    /// Upstream semantics: "initialized" means listing is allowed without asking. We report it
    /// only when metadata is known and listing is allowed in the current lock state.
    fn is_initialized(&self) -> bool {
        if !self.is_usable() || !self.metadata_known() {
            return false;
        }
        self.list_when_locked.load(Ordering::SeqCst) || lock(&self.authz).active_count() > 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        authz::{ApprovalPolicy, ScopeMode},
        clock::MockClock,
        vault::tests::{TEST_ED25519_PEM, TEST_ED25519_PUB},
    };

    fn store(ttl: u64) -> (MockClock, GatedKeyStore, MetaKeyData) {
        let clock = MockClock::new();
        let authz = Authorizations::new(
            Arc::new(clock.clone()),
            Duration::from_secs(ttl),
            ApprovalPolicy::CacheForTtl,
            ScopeMode::KeyAndProcess,
        );
        let s = GatedKeyStore::new(Arc::new(Mutex::new(authz)));
        s.set_usable(true);
        let meta = MetaKeyData {
            public_key: parse_public_key(TEST_ED25519_PUB).unwrap(),
            name: "k".into(),
            cipher_id: "c1".into(),
        };
        s.set_metadata(vec![meta.clone()]);
        (clock, s, meta)
    }

    fn key() -> SSHKeyData {
        SSHKeyData::from_private_key_pem(TEST_ED25519_PEM, "k".into(), "c1".into()).unwrap()
    }

    #[test]
    fn private_key_requires_grant() {
        let (clock, s, meta) = store(600);
        s.insert_private(key()).unwrap();
        assert!(
            s.get_private_key(&meta.public_key).unwrap().is_none(),
            "no grant"
        );
        let scope = {
            let a = s.authz().lock().unwrap();
            a.scope_for(
                &meta.public_key.to_string(),
                &ProcessId::Executable("/usr/bin/ssh".into()),
            )
        };
        s.authz().lock().unwrap().grant(scope);
        assert!(s.get_private_key(&meta.public_key).unwrap().is_some());
        clock.advance(Duration::from_secs(600));
        assert!(
            s.get_private_key(&meta.public_key).unwrap().is_none(),
            "expired grant must fail closed even before the purge task runs"
        );
        s.purge_unauthorized();
        assert_eq!(s.private_count(), 0, "material purged after expiry");
    }

    #[test]
    fn one_shot_is_single_use() {
        let (_clock, s, meta) = store(0);
        s.insert_private(key()).unwrap();
        s.add_one_shot(&meta.public_key);
        assert!(s.get_private_key(&meta.public_key).unwrap().is_some());
        assert!(s.get_private_key(&meta.public_key).unwrap().is_none());
        assert_eq!(s.private_count(), 0);
    }

    #[test]
    fn one_shot_expires() {
        let (clock, s, meta) = store(0);
        s.insert_private(key()).unwrap();
        s.add_one_shot(&meta.public_key);
        clock.advance(ONE_SHOT_WINDOW);
        assert!(s.get_private_key(&meta.public_key).unwrap().is_none());
    }

    #[test]
    fn unusable_store_refuses_everything() {
        let (_clock, s, meta) = store(600);
        s.insert_private(key()).unwrap();
        s.add_one_shot(&meta.public_key);
        s.set_usable(false);
        assert!(s.get_private_key(&meta.public_key).unwrap().is_none());
        assert!(s.get_all_public_keys_and_names().unwrap().is_empty());
        assert_eq!(s.private_count(), 0);
    }

    #[test]
    fn removed_key_is_purged_and_revoked() {
        let (_clock, s, meta) = store(600);
        s.insert_private(key()).unwrap();
        let scope = s.authz().lock().unwrap().scope_for(
            &meta.public_key.to_string(),
            &ProcessId::Executable("/x".into()),
        );
        s.authz().lock().unwrap().grant(scope);
        s.set_metadata(vec![]);
        assert_eq!(s.private_count(), 0);
        assert!(!s
            .authz()
            .lock()
            .unwrap()
            .key_has_grant(&meta.public_key.to_string()));
    }

    #[test]
    fn mismatching_private_key_is_rejected() {
        let (_clock, s, _meta) = store(600);
        s.set_metadata(vec![MetaKeyData {
            public_key: PublicKey {
                alg: "ssh-ed25519".into(),
                blob: vec![1, 2, 3],
            },
            name: "other".into(),
            cipher_id: "c1".into(),
        }]);
        assert!(s.insert_private(key()).is_err());
    }

    #[test]
    fn listing_policy() {
        let (_clock, s, _meta) = store(600);
        assert!(s.is_initialized());
        s.set_list_when_locked(false);
        assert!(
            !s.is_initialized(),
            "locked + list disabled requires approval"
        );
        s.forget_metadata();
        s.set_list_when_locked(true);
        assert!(!s.is_initialized(), "unknown metadata requires approval");
    }
}
