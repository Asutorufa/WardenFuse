//! Legacy native-messaging biometrics protocol, as implemented by the official desktop app in
//! `apps/desktop/src/services/biometric-message-handler.service.ts` and consumed by
//! `apps/browser/src/background/nativeMessaging.background.ts`.
//!
//! 1. Browser → `{appId, message: {command: "setupEncryption", publicKey, userId, ...}}`
//!    (RSA-2048 SPKI public key, base64).
//! 2. Desktop verifies the user id, creates a fresh AES-256-CBC-HMAC session key and returns it
//!    RSA-OAEP(SHA-1) encrypted: `{appId, command: "setupEncryption", messageId: -1,
//!    sharedSecret}`.
//! 3. All further messages are EncStrings (type 2) under the session key containing
//!    `{command, messageId, userId, timestamp}`; replies carry a fresh `timestamp`.
//!
//! All cryptography uses `bitwarden_crypto`.

use std::{collections::HashMap, str::FromStr, time::Duration};

use base64::{engine::general_purpose::STANDARD, Engine as _};
use bitwarden_crypto::{
    EncString, KeyDecryptable, KeyEncryptable, PublicKey, SpkiPublicKeyBytes, SymmetricCryptoKey,
    SymmetricKeyAlgorithm, UnsignedSharedKey,
};
use serde_json::{json, Value};
use zeroize::Zeroizing;

use super::BrowserBackend;

const MESSAGE_VALID_FOR: Duration = Duration::from_secs(10);

/// Biometrics status values (`BiometricsStatus` enum of `@bitwarden/key-management`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum LegacyBiometricsStatus {
    Available = 0,
    UnlockNeeded = 1,
    HardwareUnavailable = 2,
    PlatformUnsupported = 5,
    NotEnabledInConnectedDesktopApp = 8,
}

/// Per-connection state: session keys by browser app id.
#[derive(Default)]
pub struct LegacySession {
    keys: HashMap<String, SymmetricCryptoKey>,
}

fn now_ms() -> i64 {
    chrono::Utc::now().timestamp_millis()
}

fn enc_to_object(e: &EncString) -> Value {
    let s = e.to_string();
    // "2.iv|data|mac"
    let (ty, rest) = s.split_once('.').unwrap_or(("2", ""));
    let mut parts = rest.split('|');
    json!({
        "encryptedString": s,
        "encryptionType": ty.parse::<u8>().unwrap_or(2),
        "iv": parts.next(),
        "data": parts.next(),
        "mac": parts.next(),
    })
}

fn object_to_enc(v: &Value) -> Option<EncString> {
    if let Some(s) = v.get("encryptedString").and_then(Value::as_str) {
        return EncString::from_str(s).ok();
    }
    let ty = v.get("encryptionType").and_then(Value::as_u64)?;
    let iv = v.get("iv").and_then(Value::as_str)?;
    let data = v.get("data").and_then(Value::as_str)?;
    let mac = v.get("mac").and_then(Value::as_str)?;
    EncString::from_str(&format!("{ty}.{iv}|{data}|{mac}")).ok()
}

impl LegacySession {
    /// Handles one decoded native message. Returns zero or more messages to send back.
    pub async fn handle<B: BrowserBackend + ?Sized>(
        &mut self,
        backend: &B,
        browser: &str,
        msg: &Value,
    ) -> Vec<Value> {
        let Some(app_id) = msg.get("appId").and_then(Value::as_str).map(str::to_owned) else {
            return vec![];
        };
        let Some(inner) = msg.get("message") else {
            return vec![];
        };

        if inner.get("command").and_then(Value::as_str) == Some("setupEncryption") {
            return self.setup_encryption(backend, &app_id, inner).await;
        }

        let Some(key) = self.keys.get(&app_id) else {
            return vec![json!({"command": "invalidateEncryption", "appId": app_id})];
        };
        let decrypted: Option<Zeroizing<String>> = object_to_enc(inner)
            .and_then(|e| KeyDecryptable::<_, String>::decrypt_with_key(&e, key).ok())
            .map(Zeroizing::new);
        let Some(plain) = decrypted else {
            self.keys.remove(&app_id);
            return vec![json!({"command": "invalidateEncryption", "appId": app_id})];
        };
        let Ok(req) = serde_json::from_str::<Value>(&plain) else {
            return vec![json!({"command": "invalidateEncryption", "appId": app_id})];
        };
        let ts = req.get("timestamp").and_then(Value::as_i64).unwrap_or(0);
        if (now_ms() - ts).unsigned_abs() > MESSAGE_VALID_FOR.as_millis() as u64 {
            tracing::info!("Ignoring stale native message");
            return vec![];
        }
        let message_id = req.get("messageId").cloned().unwrap_or(Value::Null);
        let command = req
            .get("command")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let user_id = req.get("userId").and_then(Value::as_str).map(str::to_owned);

        let mut reply = match command {
            "getBiometricsStatus" => json!({
                "command": command,
                "response": backend.biometrics_status(None).await as u8,
            }),
            "getBiometricsStatusForUser" => json!({
                "command": command,
                "response": backend.biometrics_status(user_id.as_deref()).await as u8,
            }),
            "unlockWithBiometricsForUser" => {
                let key = match user_id.as_deref() {
                    Some(uid) => backend.unlock_user_key(uid, browser).await,
                    None => None,
                };
                match key {
                    Some(k) => json!({
                        "command": command,
                        "response": true,
                        "userKeyB64": k.as_str(),
                    }),
                    None => json!({"command": command, "response": false}),
                }
            }
            "authenticateWithBiometrics" => json!({
                "command": command,
                "response": backend.verify_user(browser).await,
            }),
            other => {
                tracing::warn!(command = other, "Unknown native messaging command");
                return vec![];
            }
        };
        reply["messageId"] = message_id.clone();
        reply["timestamp"] = json!(now_ms());

        let plain = Zeroizing::new(reply.to_string());
        // Remove the user key from the JSON value as soon as it is serialized.
        if let Some(obj) = reply.as_object_mut() {
            obj.remove("userKeyB64");
        }
        let Some(key) = self.keys.get(&app_id) else {
            return vec![];
        };
        match plain.as_str().encrypt_with_key(key) {
            Ok(enc) => vec![json!({
                "appId": app_id,
                "messageId": message_id,
                "message": enc_to_object(&enc),
            })],
            Err(_) => vec![],
        }
    }

    async fn setup_encryption<B: BrowserBackend + ?Sized>(
        &mut self,
        backend: &B,
        app_id: &str,
        inner: &Value,
    ) -> Vec<Value> {
        let (Some(pk_b64), Some(user_id)) = (
            inner.get("publicKey").and_then(Value::as_str),
            inner.get("userId").and_then(Value::as_str),
        ) else {
            return vec![];
        };
        // The browser must be logged into the same account as WardenFuse.
        if backend.logged_in_user().await.as_deref() != Some(user_id) {
            tracing::info!("Browser requested a different account; refusing");
            self.keys.remove(app_id);
            return vec![json!({"command": "wrongUserId", "appId": app_id})];
        }
        let Ok(der) = STANDARD.decode(pk_b64) else {
            return vec![];
        };
        let Ok(public_key) = PublicKey::from_der(&SpkiPublicKeyBytes::from(der)) else {
            return vec![];
        };
        let session_key = SymmetricCryptoKey::make(SymmetricKeyAlgorithm::Aes256CbcHmac);
        // The browser protocol is exactly the unsigned RSA-OAEP-SHA1 encapsulation; the signed
        // `encapsulate()` replacement is not understood by the extension's legacy channel.
        #[allow(deprecated)]
        let Ok(shared) = UnsignedSharedKey::encapsulate_key_unsigned(&session_key, &public_key) else {
            return vec![];
        };
        // UnsignedSharedKey displays as "4.<base64>" (Rsa2048_OaepSha1_B64); the browser expects
        // the raw base64 RSA ciphertext.
        let s = shared.to_string();
        let Some(b64) = s.strip_prefix("4.") else {
            return vec![];
        };
        self.keys.insert(app_id.to_owned(), session_key);
        vec![json!({
            "appId": app_id,
            "command": "setupEncryption",
            "messageId": -1,
            "sharedSecret": b64,
        })]
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, Ordering};

    use async_trait::async_trait;
    use bitwarden_crypto::{PrivateKey, PublicKeyEncryptionAlgorithm};

    use super::*;
    use crate::browser::BrowserBackend;

    struct Backend {
        user: String,
        allow: AtomicBool,
    }

    #[async_trait]
    impl BrowserBackend for Backend {
        async fn logged_in_user(&self) -> Option<String> {
            Some(self.user.clone())
        }
        async fn biometrics_status(&self, user: Option<&str>) -> LegacyBiometricsStatus {
            match user {
                Some(u) if u != self.user => {
                    LegacyBiometricsStatus::NotEnabledInConnectedDesktopApp
                }
                _ => LegacyBiometricsStatus::Available,
            }
        }
        async fn unlock_user_key(&self, user: &str, _b: &str) -> Option<Zeroizing<String>> {
            (user == self.user && self.allow.load(Ordering::SeqCst))
                .then(|| Zeroizing::new("USERKEY".to_owned()))
        }
        async fn verify_user(&self, _b: &str) -> bool {
            self.allow.load(Ordering::SeqCst)
        }
    }

    /// Simulates the browser side using the same primitives.
    fn browser_setup(sess: &mut LegacySession) -> (PrivateKey, Value) {
        let private = PrivateKey::make(PublicKeyEncryptionAlgorithm::RsaOaepSha1);
        let spki = private.to_public_key().to_der().unwrap();
        let msg = json!({"appId": "app1", "message": {
            "command": "setupEncryption",
            "publicKey": STANDARD.encode(spki.as_ref()),
            "userId": "user-1",
            "messageId": 0,
            "timestamp": now_ms(),
        }});
        let _ = sess;
        (private, msg)
    }

    #[allow(deprecated)]
    fn shared_key(private: &PrivateKey, reply: &Value) -> SymmetricCryptoKey {
        let b64 = reply["sharedSecret"].as_str().unwrap();
        let shared = UnsignedSharedKey::from_str(&format!("4.{b64}")).unwrap();
        shared.decapsulate_key_unsigned(private).unwrap()
    }

    fn encrypted(key: &SymmetricCryptoKey, v: Value) -> Value {
        let enc = v.to_string().as_str().encrypt_with_key(key).unwrap();
        json!({"appId": "app1", "message": enc_to_object(&enc)})
    }

    fn decrypt(key: &SymmetricCryptoKey, reply: &Value) -> Value {
        let enc = object_to_enc(&reply["message"]).unwrap();
        let s: String = enc.decrypt_with_key(key).unwrap();
        serde_json::from_str(&s).unwrap()
    }

    #[tokio::test]
    async fn full_unlock_flow() {
        let backend = Backend {
            user: "user-1".into(),
            allow: AtomicBool::new(true),
        };
        let mut sess = LegacySession::default();
        let (private, setup) = browser_setup(&mut sess);
        let out = sess.handle(&backend, "Chrome", &setup).await;
        assert_eq!(out[0]["command"], "setupEncryption");
        let key = shared_key(&private, &out[0]);

        let req = encrypted(
            &key,
            json!({"command": "unlockWithBiometricsForUser", "messageId": 7, "userId": "user-1", "timestamp": now_ms()}),
        );
        let out = sess.handle(&backend, "Chrome", &req).await;
        let reply = decrypt(&key, &out[0]);
        assert_eq!(reply["response"], true);
        assert_eq!(reply["userKeyB64"], "USERKEY");
        assert_eq!(reply["messageId"], 7);
        assert_eq!(out[0]["messageId"], 7);

        backend.allow.store(false, Ordering::SeqCst);
        let req = encrypted(
            &key,
            json!({"command": "unlockWithBiometricsForUser", "messageId": 8, "userId": "user-1", "timestamp": now_ms()}),
        );
        let reply = decrypt(&key, &sess.handle(&backend, "Chrome", &req).await[0]);
        assert_eq!(
            reply["response"], false,
            "cancelled authentication returns no key"
        );
        assert!(reply.get("userKeyB64").is_none());
    }

    #[tokio::test]
    async fn wrong_user_is_rejected() {
        let backend = Backend {
            user: "someone-else".into(),
            allow: AtomicBool::new(true),
        };
        let mut sess = LegacySession::default();
        let (_p, setup) = browser_setup(&mut sess);
        let out = sess.handle(&backend, "Chrome", &setup).await;
        assert_eq!(out[0]["command"], "wrongUserId");
    }

    #[tokio::test]
    async fn unlock_for_other_user_after_setup_is_refused() {
        let backend = Backend {
            user: "user-1".into(),
            allow: AtomicBool::new(true),
        };
        let mut sess = LegacySession::default();
        let (private, setup) = browser_setup(&mut sess);
        let key = shared_key(&private, &sess.handle(&backend, "Chrome", &setup).await[0]);
        let req = encrypted(
            &key,
            json!({"command": "unlockWithBiometricsForUser", "messageId": 1, "userId": "user-2", "timestamp": now_ms()}),
        );
        let reply = decrypt(&key, &sess.handle(&backend, "Chrome", &req).await[0]);
        assert_eq!(reply["response"], false);
    }

    #[tokio::test]
    async fn stale_and_garbage_messages() {
        let backend = Backend {
            user: "user-1".into(),
            allow: AtomicBool::new(true),
        };
        let mut sess = LegacySession::default();
        // No session yet.
        let out = sess
            .handle(
                &backend,
                "Chrome",
                &json!({"appId": "app1", "message": {"encryptedString": "2.a|b|c"}}),
            )
            .await;
        assert_eq!(out[0]["command"], "invalidateEncryption");
        let (private, setup) = browser_setup(&mut sess);
        let key = shared_key(&private, &sess.handle(&backend, "Chrome", &setup).await[0]);
        let req = encrypted(
            &key,
            json!({"command": "getBiometricsStatus", "messageId": 1, "timestamp": now_ms() - 60_000}),
        );
        assert!(
            sess.handle(&backend, "Chrome", &req).await.is_empty(),
            "replay window"
        );
        let req = encrypted(
            &key,
            json!({"command": "getBiometricsStatusForUser", "messageId": 2, "userId": "user-1", "timestamp": now_ms()}),
        );
        let reply = decrypt(&key, &sess.handle(&backend, "Chrome", &req).await[0]);
        assert_eq!(reply["response"], 0);
    }
}
