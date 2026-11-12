//! Account-scoped pairing and browser authentication. The phone unseals a random
//! envelope key. Only the Mac holds the envelope containing the Bitwarden user key.

#[cfg(test)]
pub(crate) mod tests;
mod transport;

use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::{Arc, Mutex, MutexGuard},
    time::Duration,
};

use anyhow::{anyhow, bail, ensure, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chacha20poly1305::{aead::AeadInOut, ChaCha20Poly1305, KeyInit};
use ring::rand::{SecureRandom, SystemRandom};
use rsa::{rand_core::OsRng, Oaep, RsaPublicKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use tokio::{
    sync::{oneshot, Notify},
    time::{self, Instant},
};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::{
    config::write_private_file,
    platform::{AuthFailure, Platform},
};

const PAIR_LIFETIME: Duration = Duration::from_secs(120);
const MAX_DEVICES: usize = 8;
type Secret = [u8; 32];

fn random<const N: usize>() -> Result<[u8; N]> {
    let mut bytes = [0; N];
    SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| anyhow!("Secure randomness unavailable"))?;
    Ok(bytes)
}

fn random_secret() -> Result<Zeroizing<Secret>> {
    let mut bytes = Zeroizing::new([0; 32]);
    SystemRandom::new()
        .fill(bytes.as_mut())
        .map_err(|_| anyhow!("Secure randomness unavailable"))?;
    Ok(bytes)
}

fn digest(bytes: &[u8]) -> Secret {
    Sha256::digest(bytes).into()
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub(crate) struct Account {
    pub session: Uuid,
    pub revision: Secret,
}

impl Account {
    pub fn new(session: Uuid, wrapped_private_key: &str) -> Self {
        Self {
            session,
            revision: digest(wrapped_private_key.as_bytes()),
        }
    }

    fn aad(&self, device: Uuid) -> Vec<u8> {
        let mut aad = b"WardenFuse Android envelope v1\0".to_vec();
        aad.extend(self.session.as_bytes());
        aad.extend(self.revision);
        aad.extend(device.as_bytes());
        aad
    }
}

#[derive(Deserialize, Serialize)]
struct Envelope {
    nonce: [u8; 12],
    ciphertext: Vec<u8>,
    wrapped_key: Vec<u8>,
}

impl Envelope {
    fn seal(
        account: &Account,
        device: Uuid,
        public_key: &RsaPublicKey,
        user_key: &[u8],
    ) -> Result<Self> {
        let secret = random_secret()?;
        let nonce = random()?;
        let cipher = envelope_cipher(secret.as_ref())?;
        let mut ciphertext = Zeroizing::new(user_key.to_vec());
        cipher
            .encrypt_in_place(&nonce.into(), &account.aad(device), &mut *ciphertext)
            .map_err(|_| anyhow!("Unable to encrypt the Bitwarden key"))?;
        // Android Keystore on Android 11–14 uses MGF1-SHA1 with OAEP-SHA256.
        let wrapped_key = public_key.encrypt(
            &mut OsRng,
            Oaep::new_with_mgf_hash::<Sha256, sha1::Sha1>(),
            secret.as_ref(),
        )?;
        Ok(Self {
            nonce,
            ciphertext: std::mem::take(&mut *ciphertext),
            wrapped_key,
        })
    }

    fn open(&self, account: &Account, device: Uuid, secret: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        let mut plaintext = Zeroizing::new(self.ciphertext.clone());
        envelope_cipher(secret)?
            .decrypt_in_place(&self.nonce.into(), &account.aad(device), &mut *plaintext)
            .map_err(|_| anyhow!("Invalid envelope key"))?;
        Ok(plaintext)
    }
}

fn envelope_cipher(secret: &[u8]) -> Result<ChaCha20Poly1305> {
    ChaCha20Poly1305::new_from_slice(secret).map_err(|_| anyhow!("Invalid envelope key"))
}

#[derive(Deserialize, Serialize)]
struct Device {
    id: Uuid,
    name: String,
    credential_hash: Secret,
    envelope: Envelope,
}

#[derive(Deserialize, Serialize)]
struct Enrollments {
    account: Account,
    devices: Vec<Device>,
}

struct Pairing {
    id: Uuid,
    token_hash: Option<Secret>,
    deadline: Instant,
    candidate: Option<Candidate>,
    cancel: CancellationToken,
}

struct Candidate {
    id: Uuid,
    name: String,
    credential_hash: Secret,
    public_key: RsaPublicKey,
    code: String,
    confirming: bool,
    result: oneshot::Sender<()>,
}

struct Pending {
    challenge: Secret,
    browser: String,
    verify: bool,
    deadline: Instant,
    claimed: Option<Uuid>,
    result: oneshot::Sender<Result<Unlocked, AuthFailure>>,
    cancel: CancellationToken,
}

pub(crate) struct Unlocked {
    device: Uuid,
    pub key: Zeroizing<Vec<u8>>,
}

struct State {
    account: Option<Account>,
    enrollments: Option<Enrollments>,
    listener: Option<transport::Listener>,
    error: Option<String>,
    pairing: Option<Pairing>,
    pending: Option<Pending>,
    online: HashMap<Uuid, (Uuid, CancellationToken)>,
}

impl State {
    fn devices(&self) -> &[Device] {
        match &self.enrollments {
            Some(saved) if self.account.as_ref() == Some(&saved.account) => &saved.devices,
            _ => &[],
        }
    }

    fn cancel_pairing(&mut self) {
        if let Some(pairing) = self.pairing.take() {
            pairing.cancel.cancel();
        }
    }

    fn cancel_pending(&mut self) {
        if let Some(pending) = self.pending.take() {
            pending.cancel.cancel();
        }
    }

    fn disconnect_all(&mut self) {
        self.cancel_pairing();
        self.cancel_pending();
        for token in self.online.drain().map(|(_, (_, token))| token) {
            token.cancel();
        }
    }
}

pub(crate) struct Android {
    path: PathBuf,
    state: Mutex<State>,
    changed: Notify,
    dirty: Arc<Notify>,
}

impl Android {
    pub fn new(dir: &Path, dirty: Arc<Notify>) -> Arc<Self> {
        let path = dir.join("android-devices.json");
        let enrollments = std::fs::read(&path)
            .ok()
            .and_then(|bytes| serde_json::from_slice(&bytes).ok());
        Arc::new(Self {
            path,
            state: Mutex::new(State {
                account: None,
                enrollments,
                listener: None,
                error: None,
                pairing: None,
                pending: None,
                online: HashMap::new(),
            }),
            changed: Notify::new(),
            dirty,
        })
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn changed(&self) {
        self.changed.notify_waiters();
        self.dirty.notify_one();
    }

    /// Account loss/replacement and a new wrapped private key invalidate all enrollments.
    /// Disabling the method only disconnects the listener and cancels requests.
    pub fn reconcile(
        self: &Arc<Self>,
        account: Option<Account>,
        enabled: bool,
        platform: &dyn Platform,
    ) {
        let mut s = self.lock();
        s.error = None;
        if s.account != account {
            s.disconnect_all();
            s.account = account;
        }
        if s.enrollments
            .as_ref()
            .is_some_and(|e| s.account.as_ref() != Some(&e.account))
        {
            s.enrollments = None;
            if let Err(e) = self.delete_enrollments() {
                s.error = Some(e.to_string());
            }
        }
        if !enabled || s.account.is_none() {
            s.listener = None;
            s.disconnect_all();
        } else if s.listener.is_none() {
            match transport::Listener::start(self, platform) {
                Ok(listener) => s.listener = Some(listener),
                Err(e) => s.error = Some(e.to_string()),
            }
        }
        self.changed();
    }

    fn delete_enrollments(&self) -> Result<()> {
        match std::fs::remove_file(&self.path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(anyhow!("Unable to delete Android enrollments: {e}")),
        }
    }

    pub fn snapshot(&self) -> serde_json::Value {
        let s = self.lock();
        serde_json::json!({
            "listening": s.listener.is_some(),
            "error": s.error,
            "pairing_id": s.pairing.as_ref().map(|p| p.id),
            "candidate": s.pairing.as_ref().and_then(|p| p.candidate.as_ref()).map(|c| c.name.as_str()),
            "waiting_for_browser_approval": s.pending.is_some(),
            "devices": s.devices().iter().map(|d| serde_json::json!({
                "id": d.id, "name": d.name, "connected": s.online.contains_key(&d.id),
            })).collect::<Vec<_>>(),
        })
    }

    pub fn available(&self) -> bool {
        let s = self.lock();
        s.listener.is_some() && !s.devices().is_empty()
    }

    pub fn addresses() -> Result<Vec<std::net::Ipv4Addr>> {
        transport::addresses()
    }

    pub fn begin_pairing(
        self: &Arc<Self>,
        address: std::net::Ipv4Addr,
        name: &str,
    ) -> Result<serde_json::Value> {
        ensure!(
            Self::addresses()?.contains(&address),
            "Choose a local network address on this Mac"
        );
        self.issue_pairing(address, name)
    }

    fn issue_pairing(
        self: &Arc<Self>,
        address: std::net::Ipv4Addr,
        name: &str,
    ) -> Result<serde_json::Value> {
        let mut s = self.lock();
        let listener = s.listener.as_ref().ok_or_else(|| {
            anyhow!("Android listener unavailable. Sign in and check the connection status.")
        })?;
        ensure!(
            s.devices().len() < MAX_DEVICES,
            "Remove an Android device before pairing another"
        );
        let token = random_secret()?;
        let qr = serde_json::json!({
            "version": 1, "host": address, "port": listener.port,
            "certificate": listener.certificate, "name": name,
            "token": URL_SAFE_NO_PAD.encode(token.as_ref()),
        })
        .to_string();
        let id = Uuid::new_v4();
        let deadline = Instant::now() + PAIR_LIFETIME;
        s.cancel_pairing();
        s.pairing = Some(Pairing {
            id,
            token_hash: Some(digest(token.as_ref())),
            deadline,
            candidate: None,
            cancel: CancellationToken::new(),
        });
        let android = Arc::downgrade(self);
        tokio::spawn(async move {
            time::sleep_until(deadline).await;
            if let Some(android) = android.upgrade() {
                android.cancel_pairing(id);
            }
        });
        self.changed();
        Ok(serde_json::json!({"ok": true, "pairing_id": id, "qr": qr}))
    }

    pub fn cancel_pairing(&self, id: Uuid) {
        let mut s = self.lock();
        if s.pairing.as_ref().is_some_and(|p| p.id == id) {
            s.cancel_pairing();
            self.changed();
        }
    }

    pub fn authorize_pairing(&self, id: Uuid, code: &str) -> Result<(Account, CancellationToken)> {
        let mut s = self.lock();
        let account = s
            .account
            .clone()
            .ok_or_else(|| anyhow!("No current account key"))?;
        let pair = s
            .pairing
            .as_mut()
            .filter(|p| p.id == id && Instant::now() < p.deadline)
            .ok_or_else(|| anyhow!("Pairing expired or the phone disconnected"))?;
        let candidate = pair
            .candidate
            .as_mut()
            .ok_or_else(|| anyhow!("Scan the pairing QR code first"))?;
        ensure!(
            !candidate.confirming,
            "Pairing is already awaiting Mac authentication"
        );
        ensure!(
            bool::from(candidate.code.as_bytes().ct_eq(code.as_bytes())),
            "The pairing code does not match"
        );
        candidate.confirming = true;
        Ok((account, pair.cancel.clone()))
    }

    pub fn finish_pairing(&self, id: Uuid, account: &Account, user_key: &[u8]) -> Result<()> {
        let mut s = self.lock();
        ensure!(
            s.account.as_ref() == Some(account),
            "The Bitwarden account key changed"
        );
        let pair = s
            .pairing
            .as_mut()
            .filter(|p| p.id == id && Instant::now() < p.deadline)
            .ok_or_else(|| anyhow!("Pairing expired or the phone disconnected"))?;
        let candidate = pair
            .candidate
            .take()
            .filter(|c| c.confirming && !c.result.is_closed())
            .ok_or_else(|| anyhow!("Pairing was cancelled"))?;
        let envelope = Envelope::seal(account, candidate.id, &candidate.public_key, user_key)?;
        let saved = s.enrollments.get_or_insert_with(|| Enrollments {
            account: account.clone(),
            devices: vec![],
        });
        saved.devices.push(Device {
            id: candidate.id,
            name: candidate.name,
            credential_hash: candidate.credential_hash,
            envelope,
        });
        if let Err(e) = self.save(saved) {
            saved.devices.pop();
            return Err(e);
        }
        // The record is committed before the phone is notified. If the reply is lost,
        // the phone can reconnect with the credential it saved before requesting pairing.
        s.pairing = None;
        let _ = candidate.result.send(());
        self.changed();
        Ok(())
    }

    fn save(&self, saved: &Enrollments) -> Result<()> {
        write_private_file(&self.path, &serde_json::to_vec(saved)?)
    }

    pub fn remove(&self, id: Uuid) -> Result<()> {
        let mut s = self.lock();
        let saved = s
            .enrollments
            .as_mut()
            .ok_or_else(|| anyhow!("Unknown Android device"))?;
        let index = saved
            .devices
            .iter()
            .position(|d| d.id == id)
            .ok_or_else(|| anyhow!("Unknown Android device"))?;
        let device = saved.devices.remove(index);
        if let Err(e) = self.save(saved) {
            saved.devices.insert(index, device);
            return Err(e);
        }
        if let Some((_, token)) = s.online.remove(&id) {
            token.cancel();
        }
        if s.pending.as_ref().is_some_and(|p| p.claimed == Some(id)) || s.devices().is_empty() {
            s.cancel_pending();
        }
        self.changed();
        Ok(())
    }

    pub fn cancel_request(&self) {
        self.lock().cancel_pending();
        self.changed();
    }

    pub async fn authenticate(
        &self,
        account: &Account,
        browser: String,
        verify: bool,
        timeout: Duration,
    ) -> Result<Unlocked, AuthFailure> {
        let challenge = random().map_err(|_| AuthFailure::Failed)?;
        let deadline = Instant::now() + timeout;
        let (result, rx) = oneshot::channel();
        {
            let mut s = self.lock();
            if s.listener.is_none() || s.account.as_ref() != Some(account) || s.devices().is_empty()
            {
                return Err(AuthFailure::Unavailable);
            }
            if s.pending.is_some() {
                return Err(AuthFailure::Failed);
            }
            s.pending = Some(Pending {
                challenge,
                browser,
                verify,
                deadline,
                claimed: None,
                result,
                cancel: CancellationToken::new(),
            });
        }
        let _ticket = RequestGuard {
            android: self,
            challenge,
        };
        self.changed();
        match time::timeout_at(deadline, rx).await {
            Ok(Ok(result)) if Instant::now() < deadline => result,
            Ok(Err(_)) if Instant::now() < deadline => Err(AuthFailure::Cancelled),
            _ => Err(AuthFailure::Timeout),
        }
    }

    pub fn still_valid(&self, account: &Account, result: &Unlocked) -> bool {
        let s = self.lock();
        s.listener.is_some()
            && s.account.as_ref() == Some(account)
            && s.devices().iter().any(|d| d.id == result.device)
    }

    fn respond(&self, device: Uuid, challenge: Secret, secret: &[u8]) -> Result<()> {
        let mut s = self.lock();
        let Some(p) = s
            .pending
            .as_ref()
            .filter(|p| p.challenge == challenge && p.claimed == Some(device))
        else {
            bail!("No such Android request");
        };
        let key = if Instant::now() >= p.deadline || p.result.is_closed() {
            Err(AuthFailure::Timeout)
        } else {
            s.account
                .as_ref()
                .and_then(|account| {
                    s.devices()
                        .iter()
                        .find(|d| d.id == device)
                        .and_then(|d| d.envelope.open(account, device, secret).ok())
                })
                .map(|key| Unlocked { device, key })
                .ok_or(AuthFailure::Failed)
        };
        let accepted = key.is_ok();
        if let Some(p) = s.pending.take() {
            let _ = p.result.send(key);
        }
        self.changed();
        ensure!(accepted, "Android proof rejected");
        Ok(())
    }
}

/// A dropped browser future, or a dropped phone connection after claiming a request, clears it.
struct RequestGuard<'a> {
    android: &'a Android,
    challenge: Secret,
}

impl Drop for RequestGuard<'_> {
    fn drop(&mut self) {
        let mut s = self.android.lock();
        if s.pending
            .as_ref()
            .is_some_and(|p| p.challenge == self.challenge)
        {
            s.cancel_pending();
            self.android.changed();
        }
    }
}
