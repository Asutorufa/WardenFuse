#![allow(clippy::unwrap_used)]

use std::{str::FromStr, sync::atomic::Ordering};

use base64::{engine::general_purpose::STANDARD, Engine};
use bitwarden_core::{
    client::{login_method::UserLoginMethod, persisted_state::AuthenticationTokens},
    UserId,
};
use bitwarden_crypto::{
    EncString, Kdf, KeyDecryptable, KeyEncryptable, PrivateKey, PublicKeyEncryptionAlgorithm,
    SymmetricCryptoKey, SymmetricKeyAlgorithm, UnsignedSharedKey,
};

use super::*;
use crate::{
    android::tests::{offer, read, MockPlatform, Phone},
    bitwarden::{LoggedIn, SessionBlob},
    browser::{legacy::LegacySession, sdk_ipc::test_unlock},
};

const USER: &str = "1fae1749-1a61-4eac-aa5d-aa8cd27bf68a";
const OTHER: &str = "99619c88-f76e-454b-ad82-13ebf48a88a0";
const SERVER: &str = "https://vault.example.invalid";

async fn login(user_id: &str, user_key: &SymmetricCryptoKey, private: &PrivateKey) -> LoggedIn {
    let blob = serde_json::to_vec(&SessionBlob {
        server_url: SERVER.into(),
        user_id: user_id.into(),
        email: "test@example.invalid".into(),
        login_method: UserLoginMethod::Username {
            client_id: "browser".into(),
            email: "test@example.invalid".into(),
            kdf: Kdf::default_pbkdf2(),
        },
        tokens: AuthenticationTokens {
            access_token: "test-token".into(),
            refresh_token: None,
            expires_on: 4_000_000_000,
        },
        android_session_id: uuid::Uuid::new_v4(),
    })
    .unwrap();
    let wrapped = private
        .to_der()
        .unwrap()
        .encrypt_with_key(user_key)
        .unwrap();
    LoggedIn {
        session: BitwardenSession::restore(&blob).await.unwrap(),
        user_key_b64: Zeroizing::new(user_key.to_base64().to_string()),
        vault: EncryptedVault {
            user_id: user_id.into(),
            private_key: Some(wrapped.to_string()),
            synced_at: chrono::Utc::now().timestamp(),
            ..EncryptedVault::default()
        },
    }
}

async fn legacy_unlock(core: &Core, private: &PrivateKey) -> Value {
    let mut legacy = LegacySession::default();
    let backend = core.handle();
    let public = private.to_public_key().to_der().unwrap();
    let setup = json!({
        "appId": "test", "message": {
            "command": "setupEncryption", "publicKey": STANDARD.encode(public.as_ref()),
            "userId": USER, "messageId": 0, "timestamp": chrono::Utc::now().timestamp_millis(),
        }
    });
    let reply = &legacy.handle(&backend, "Legacy browser", &setup).await[0];
    assert_eq!(reply["command"], "setupEncryption");
    let shared =
        UnsignedSharedKey::from_str(&format!("4.{}", reply["sharedSecret"].as_str().unwrap()))
            .unwrap();
    #[allow(deprecated)]
    let shared = shared.decapsulate_key_unsigned(private).unwrap();
    let message = json!({
        "command": "unlockWithBiometricsForUser", "messageId": 1, "userId": USER,
        "timestamp": chrono::Utc::now().timestamp_millis(),
    })
    .to_string();
    let enc = message.as_str().encrypt_with_key(&shared).unwrap();
    let request =
        json!({"appId":"test", "message":{"encryptedString":enc.to_string(), "encryptionType":2}});
    let reply = &legacy.handle(&backend, "Legacy browser", &request).await[0];
    let enc = EncString::from_str(reply["message"]["encryptedString"].as_str().unwrap()).unwrap();
    let plain: String = enc.decrypt_with_key(&shared).unwrap();
    serde_json::from_str(&plain).unwrap()
}

#[tokio::test]
async fn both_browser_protocols_use_android_envelope_and_account_changes_revoke_it() {
    let dir = tempfile::tempdir().unwrap();
    let settings = Settings {
        auto_sync: false,
        ssh_agent_enabled: false,
        browser_unlock_enabled: false, // Tests drive the same handlers without opening the user's socket.
        ..Default::default()
    };
    ConfigStore::new(dir.path()).save(&settings).unwrap();
    let platform = Arc::new(MockPlatform::default());
    let core = Core::start(
        CoreConfig {
            data_dir: dir.path().to_owned(),
            nmh_path: PathBuf::from("/unused/wardenfuse-nmh"),
            keychain_mode: "login_keychain_fallback".into(),
        },
        platform.clone(),
    )
    .await
    .unwrap();
    let key = SymmetricCryptoKey::make(SymmetricKeyAlgorithm::Aes256CbcHmac);
    let private = PrivateKey::make(PublicKeyEncryptionAlgorithm::RsaOaepSha1);
    core.finish_login(SERVER.into(), login(USER, &key, &private).await)
        .await
        .unwrap();
    lock(&core.0.settings).browser_unlock_enabled = true;

    // Default macOS authentication still runs and propagates both success and failure.
    let backend = core.handle();
    assert!(backend.unlock_user_key(USER, "Chrome").await.is_none());
    platform.allow.store(true, Ordering::SeqCst);
    assert_eq!(
        &*backend.unlock_user_key(USER, "Chrome").await.unwrap(),
        key.to_base64().to_string().as_str()
    );

    lock(&core.0.settings).browser_authentication = BrowserAuthentication::Android;
    core.0
        .reconcile_android(core.0.session.read().await.as_deref());
    assert!(
        backend.unlock_user_key(USER, "Chrome").await.is_none(),
        "no fallback without enrollment"
    );

    let phone = Phone::new(&core.0.android, &platform);
    let qr = offer(&core.0.android);
    let (mut socket, code) = phone.stage(&qr).await;
    platform.allow.store(false, Ordering::SeqCst);
    let command = |qr: &Value, code: &str| {
        json!({
            "cmd":"android_finish_pairing", "pairing_id":qr["pairing_id"], "code":code,
        })
    };
    assert_eq!(core.command(command(&qr, &code)).await["ok"], false);
    assert!(read(&mut socket).await.is_err());
    assert!(!core.0.android.available());

    let qr = offer(&core.0.android);
    let (mut socket, code) = phone.stage(&qr).await;
    platform.allow.store(true, Ordering::SeqCst);
    assert_eq!(core.command(command(&qr, &code)).await["ok"], true);
    assert_eq!(read(&mut socket).await.unwrap()["status"], "paired");
    assert!(matches!(
        lock(&platform.purposes).last().unwrap().purpose,
        AuthPurpose::AndroidEnrollment
    ));
    let prompts = lock(&platform.purposes).len();
    platform.allow.store(false, Ordering::SeqCst);

    let mut socket = phone.ready().await;
    let (legacy, _) = tokio::join!(
        legacy_unlock(&core, &private),
        phone.approve(&mut socket, "Legacy browser")
    );
    assert_eq!(legacy["response"], true);
    assert_eq!(legacy["userKeyB64"], key.to_base64().to_string().as_str());

    let mut socket = phone.ready().await;
    let uid = UserId::from_str(USER).unwrap();
    let (sdk, _) = tokio::join!(
        test_unlock(Arc::new(core.handle()), uid, CancellationToken::new()),
        phone.approve(&mut socket, "SDK browser"),
    );
    assert_eq!(
        sdk.user_key.unwrap().to_base64().to_string().as_str(),
        key.to_base64().to_string().as_str()
    );
    assert_eq!(
        lock(&platform.purposes).len(),
        prompts,
        "Android unlock used no Mac authentication"
    );
    assert!(backend.unlock_user_key(OTHER, "Chrome").await.is_none());

    let mut socket = phone.ready().await;
    let disconnect = CancellationToken::new();
    let (sdk, _) = tokio::join!(
        test_unlock(Arc::new(core.handle()), uid, disconnect.clone()),
        async {
            assert_eq!(read(&mut socket).await.unwrap()["status"], "request");
            disconnect.cancel();
            assert_eq!(read(&mut socket).await.unwrap()["status"], "cancelled");
        },
    );
    assert!(sdk.user_key.is_none());

    // Switching accounts drops the enrollment and makes the previous browser identity unusable.
    core.finish_login(SERVER.into(), login(OTHER, &key, &private).await)
        .await
        .unwrap();
    assert_eq!(backend.logged_in_user().await.as_deref(), Some(OTHER));
    assert!(!core.0.android.available());
    assert!(backend.unlock_user_key(USER, "Chrome").await.is_none());

    let phone = Phone::new(&core.0.android, &platform);
    let qr = offer(&core.0.android);
    let (mut socket, code) = phone.stage(&qr).await;
    platform.allow.store(true, Ordering::SeqCst);
    assert_eq!(core.command(command(&qr, &code)).await["ok"], true);
    assert_eq!(read(&mut socket).await.unwrap()["status"], "paired");
    let mut socket = phone.ready().await;
    let (key, _) = tokio::join!(backend.unlock_user_key(OTHER, "Chrome"), async {
        assert_eq!(read(&mut socket).await.unwrap()["status"], "request");
        core.logout("user").await;
        assert!(read(&mut socket).await.is_err());
    });
    assert!(key.is_none());
    assert!(platform.load_session().is_none());
    assert!(!dir.path().join("android-devices.json").exists());
    core.shutdown().await;
}
