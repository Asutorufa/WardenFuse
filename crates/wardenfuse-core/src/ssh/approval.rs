//! WardenFuse implementation of the upstream [`ApprovalRequester`].
//!
//! Called by the upstream `BitwardenAuthPolicy` for every sign request (and for list requests
//! when the key store reports it is not "initialized"). Decides, using the core's grants, whether
//! the native authentication UI must be shown. Same-scope concurrent requests are serialized so
//! that they share one authentication; different scopes never share results.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use async_trait::async_trait;
use ssh_agent::{ApprovalError, ApprovalRequester, PublicKey, SIGNamespace, SignApprovalRequest};

use super::keystore::GatedKeyStore;
use crate::{
    authz::{ProcessId, Scope},
    platform::{AuthFailure, AuthPurpose},
};

/// What needs to be decrypted after a successful authentication.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UnlockTarget {
    /// Refresh the key list only.
    Metadata,
    /// Decrypt the private key of one cipher (and refresh the key list).
    Key { cipher_id: String },
    /// Decrypt all private keys.
    AllKeys,
}

/// Implemented by the core service: authenticates through the platform (Keychain + LA) and
/// decrypts the requested material into the [`GatedKeyStore`].
#[async_trait]
pub trait Unlocker: Send + Sync + 'static {
    async fn unlock(&self, purpose: AuthPurpose, target: UnlockTarget) -> Result<(), AuthFailure>;
    /// Called after grants changed so that the purge timer can be rescheduled and the UI
    /// updated.
    fn grants_changed(&self);
    fn allow_forwarding(&self) -> bool;
    fn ttl_secs(&self) -> u64;
}

pub struct WardenFuseApprover<U: Unlocker> {
    store: GatedKeyStore,
    unlocker: Arc<U>,
    scope_locks: Mutex<HashMap<Scope, Arc<tokio::sync::Mutex<()>>>>,
}

impl<U: Unlocker> WardenFuseApprover<U> {
    pub fn new(store: GatedKeyStore, unlocker: Arc<U>) -> Self {
        Self {
            store,
            unlocker,
            scope_locks: Mutex::new(HashMap::new()),
        }
    }

    fn scope_lock(&self, scope: &Scope) -> Arc<tokio::sync::Mutex<()>> {
        let mut locks = self
            .scope_locks
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        // Drop locks nobody is waiting on, to keep the map small.
        locks.retain(|_, l| Arc::strong_count(l) > 1);
        locks.entry(scope.clone()).or_default().clone()
    }
}

fn process_id(path: Option<&str>) -> ProcessId {
    match path {
        Some(p) if p.starts_with('/') => ProcessId::Executable(p.to_owned()),
        _ => ProcessId::Unknown,
    }
}

fn fingerprint(pk: &PublicKey) -> String {
    use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine as _};
    use sha2::Digest as _;
    let digest = sha2::Sha256::digest(&pk.blob);
    format!("SHA256:{}", STANDARD_NO_PAD.encode(digest))
}

#[async_trait]
impl<U: Unlocker> ApprovalRequester for WardenFuseApprover<U> {
    async fn request_sign_approval(
        &self,
        request: SignApprovalRequest,
    ) -> Result<bool, ApprovalError> {
        let sign = &request.sign_request;
        if !self.store.is_usable() {
            return Ok(false);
        }
        let Some(meta) = self.store.meta_for(&sign.public_key) else {
            return Ok(false);
        };
        let forwarded = sign
            .connection
            .session_bind
            .as_ref()
            .is_some_and(|s| s.is_forwarding);
        if forwarded && !self.unlocker.allow_forwarding() {
            tracing::info!("Refusing forwarded sign request (agent forwarding is disabled)");
            return Ok(false);
        }

        let key_id = sign.public_key.to_string();
        let process = process_id(sign.connection.process_path.as_deref());
        let scope = self
            .store
            .authz()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .scope_for(&key_id, &process);

        let lock = self.scope_lock(&scope);
        let _guard = lock.lock().await;

        // Re-check after acquiring the scope lock: a concurrent request for the same scope may
        // have just authenticated.
        if self.store.is_authorized(&sign.public_key, &process)
            && self.store.has_private(&sign.public_key)
        {
            return Ok(true);
        }

        let usage = match &sign.namespace {
            Some(SIGNamespace::Git) => "git",
            Some(SIGNamespace::File) => "file",
            Some(SIGNamespace::Unsupported) => "sshsig",
            None => "ssh",
        };
        let purpose = AuthPurpose::SshSign {
            key_name: meta.name.clone(),
            key_fingerprint: fingerprint(&sign.public_key),
            process_name: sign.connection.process_name.clone(),
            process_path: sign.connection.process_path.clone(),
            process_id: sign.connection.process_id,
            usage: usage.to_owned(),
            host_key_fingerprint: sign
                .connection
                .session_bind
                .as_ref()
                .map(|s| s.host_fingerprint.clone()),
            forwarded,
            ttl_secs: if matches!(process, ProcessId::Unknown) {
                0
            } else {
                self.unlocker.ttl_secs()
            },
        };

        match self
            .unlocker
            .unlock(
                purpose,
                UnlockTarget::Key {
                    cipher_id: meta.cipher_id.clone(),
                },
            )
            .await
        {
            Ok(()) => {}
            Err(e) => {
                tracing::info!(reason = %e, "SSH sign request not authorized");
                return Ok(false);
            }
        }

        if !self.store.has_private(&sign.public_key) {
            // Decryption produced no usable key: fail closed.
            return Ok(false);
        }

        let granted = self
            .store
            .authz()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .grant(scope)
            .is_some();
        if !granted {
            self.store.add_one_shot(&sign.public_key);
        }
        self.unlocker.grants_changed();
        Ok(true)
    }

    async fn request_list_approval(&self) -> Result<bool, ApprovalError> {
        if !self.store.is_usable() {
            // Not logged in / disabled / stale: allow the request; the store lists nothing, so
            // clients see "no identities" instead of an error. Nothing secret is involved.
            return Ok(true);
        }
        match self
            .unlocker
            .unlock(AuthPurpose::SshList, UnlockTarget::Metadata)
            .await
        {
            Ok(()) => Ok(true),
            Err(_) => Ok(false),
        }
    }
}
