//! Browser bridge end-to-end: simulated extension <-stdio-> wardenfuse-nmh <-UDS-> bridge.
//!
//! The SDK IPC test runs the official `bitwarden_ipc` client with the Noise crypto provider on
//! the "browser" side, exactly like the extension's WASM build does.

#![allow(clippy::unwrap_used, clippy::cast_possible_truncation)]

use std::{
    io::{Read, Write},
    path::PathBuf,
    process::{Child, ChildStdin, ChildStdout, Command, Stdio},
    str::FromStr,
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};

use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use bitwarden_crypto::{
    EncString, KeyDecryptable, KeyEncryptable, PrivateKey, PublicKeyEncryptionAlgorithm,
    SymmetricCryptoKey, UnsignedSharedKey,
};
use bitwarden_ipc::{
    CommunicationBackend, CommunicationBackendReceiver, Endpoint, ErrorKind,
    InMemorySessionRepository, IncomingMessage, IpcClient, IpcClientExt, IpcClientImpl,
    IpcErrorKind, NoiseCryptoProvider, NoiseCryptoProviderState, OutgoingMessage, Source,
};
use serde_json::{json, Value};
use wardenfuse_core::browser::{
    sdk_ipc::{
        AuthenticateBiometricsRequest, BiometricsStatus, GetBiometricsStatusRequest,
        UnlockBiometricsRequest,
    },
    BrowserBackend, BrowserBridge, LegacyBiometricsStatus, ALLOWED_ORIGINS,
};
use zeroize::Zeroizing;

const USER: &str = "8b1f6c2e-4d3a-4f5e-9a7b-1c2d3e4f5a6b";

struct Backend {
    allow: AtomicBool,
    prompts: AtomicUsize,
    key_b64: String,
}

#[async_trait]
impl BrowserBackend for Backend {
    async fn logged_in_user(&self) -> Option<String> {
        Some(USER.into())
    }
    async fn biometrics_status(&self, u: Option<&str>) -> LegacyBiometricsStatus {
        if u.is_some_and(|u| u != USER) {
            LegacyBiometricsStatus::NotEnabledInConnectedDesktopApp
        } else {
            LegacyBiometricsStatus::Available
        }
    }
    async fn unlock_user_key(&self, u: &str, _b: &str) -> Option<Zeroizing<String>> {
        self.prompts.fetch_add(1, Ordering::SeqCst);
        (u == USER && self.allow.load(Ordering::SeqCst))
            .then(|| Zeroizing::new(self.key_b64.clone()))
    }
    async fn verify_user(&self, _b: &str) -> bool {
        self.prompts.fetch_add(1, Ordering::SeqCst);
        self.allow.load(Ordering::SeqCst)
    }
}

fn nmh_binary() -> PathBuf {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let status = Command::new(env!("CARGO"))
        .args(["build", "-q", "-p", "wardenfuse-nmh"])
        .current_dir(&root)
        .status()
        .unwrap();
    assert!(status.success());
    let target =
        std::env::var_os("CARGO_TARGET_DIR").map_or_else(|| root.join("target"), PathBuf::from);
    target.join("debug/wardenfuse-nmh").canonicalize().unwrap()
}

struct Nmh {
    child: Child,
    stdin: Option<ChildStdin>,
    stdout: Option<ChildStdout>,
}

impl Nmh {
    fn spawn(bin: &PathBuf, home: &std::path::Path, origin: &str) -> Self {
        let mut child = Command::new(bin)
            .arg(origin)
            .env("HOME", home)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let stdin = child.stdin.take().unwrap();
        let stdout = child.stdout.take().unwrap();
        Self {
            child,
            stdin: Some(stdin),
            stdout: Some(stdout),
        }
    }
    fn send(&mut self, v: &Value) {
        let d = v.to_string();
        let w = self.stdin.as_mut().unwrap();
        w.write_all(&(d.len() as u32).to_ne_bytes()).unwrap();
        w.write_all(d.as_bytes()).unwrap();
        w.flush().unwrap();
    }
    fn recv(&mut self) -> Value {
        let mut len = [0u8; 4];
        let r = self.stdout.as_mut().unwrap();
        r.read_exact(&mut len).unwrap();
        let mut b = vec![0u8; u32::from_ne_bytes(len) as usize];
        r.read_exact(&mut b).unwrap();
        serde_json::from_slice(&b).unwrap()
    }
}

impl Drop for Nmh {
    fn drop(&mut self) {
        let _ = self.child.kill();
    }
}

struct Env {
    home: tempfile::TempDir,
    bin: PathBuf,
    backend: Arc<Backend>,
    _bridge: BrowserBridge,
    user_key: SymmetricCryptoKey,
}

async fn setup(check_path: bool) -> Env {
    let home = tempfile::Builder::new()
        .prefix("wfb")
        .tempdir_in("/tmp")
        .unwrap();
    let bin = nmh_binary();
    let user_key = SymmetricCryptoKey::make(bitwarden_crypto::SymmetricKeyAlgorithm::Aes256CbcHmac);
    let backend = Arc::new(Backend {
        allow: AtomicBool::new(true),
        prompts: AtomicUsize::new(0),
        key_b64: user_key.to_base64().to_string(),
    });
    let bridge = BrowserBridge::start(
        home.path().join(".wardenfuse/browser.sock"),
        if check_path {
            Some(bin.clone())
        } else {
            Some(PathBuf::from("/nonexistent/wardenfuse-nmh"))
        },
        backend.clone(),
    )
    .await
    .unwrap();
    Env {
        home,
        bin,
        backend,
        _bridge: bridge,
        user_key,
    }
}

fn now_ms() -> i64 {
    chrono::Utc::now().timestamp_millis()
}

fn enc_obj(key: &SymmetricCryptoKey, v: &Value) -> Value {
    let e = v.to_string().as_str().encrypt_with_key(key).unwrap();
    json!({"encryptedString": e.to_string(), "encryptionType": 2})
}

fn dec_obj(key: &SymmetricCryptoKey, v: &Value) -> Value {
    let e = EncString::from_str(v["encryptedString"].as_str().unwrap()).unwrap();
    let s: String = e.decrypt_with_key(key).unwrap();
    serde_json::from_str(&s).unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn legacy_native_messaging_unlock() {
    let env = setup(true).await;
    let (bin, home) = (env.bin.clone(), env.home.path().to_owned());
    let backend = env.backend.clone();
    let user_key_b64 = env.user_key.to_base64().to_string();
    tokio::task::spawn_blocking(move || {
        let mut nmh = Nmh::spawn(&bin, &home, ALLOWED_ORIGINS[0]);
        assert_eq!(nmh.recv()["command"], "connected");

        // Browser: generate RSA key pair, request secure channel.
        let private = PrivateKey::make(PublicKeyEncryptionAlgorithm::RsaOaepSha1);
        let spki = private.to_public_key().to_der().unwrap();
        nmh.send(&json!({"appId": "app", "message": {
            "command": "setupEncryption", "publicKey": STANDARD.encode(spki.as_ref()),
            "userId": USER, "messageId": 0, "timestamp": now_ms()}}));
        let r = nmh.recv();
        assert_eq!(r["command"], "setupEncryption");
        assert_eq!(r["messageId"], -1);
        #[allow(deprecated)]
        let session = UnsignedSharedKey::from_str(&format!("4.{}", r["sharedSecret"].as_str().unwrap()))
            .unwrap()
            .decapsulate_key_unsigned(&private)
            .unwrap();

        nmh.send(&json!({"appId": "app", "message": enc_obj(&session, &json!({
            "command": "getBiometricsStatusForUser", "messageId": 1, "userId": USER, "timestamp": now_ms()}))}));
        let r = dec_obj(&session, &nmh.recv()["message"]);
        assert_eq!(r["response"], 0);

        nmh.send(&json!({"appId": "app", "message": enc_obj(&session, &json!({
            "command": "unlockWithBiometricsForUser", "messageId": 2, "userId": USER, "timestamp": now_ms()}))}));
        let r = dec_obj(&session, &nmh.recv()["message"]);
        assert_eq!(r["response"], true);
        assert_eq!(r["userKeyB64"], user_key_b64);

        // Every unlock is a fresh authentication.
        nmh.send(&json!({"appId": "app", "message": enc_obj(&session, &json!({
            "command": "unlockWithBiometricsForUser", "messageId": 3, "userId": USER, "timestamp": now_ms()}))}));
        let _ = nmh.recv();
        assert_eq!(backend.prompts.load(Ordering::SeqCst), 2);

        // Account mismatch.
        nmh.send(&json!({"appId": "app2", "message": {
            "command": "setupEncryption", "publicKey": STANDARD.encode(spki.as_ref()),
            "userId": "00000000-0000-0000-0000-000000000000", "messageId": 0, "timestamp": now_ms()}}));
        assert_eq!(nmh.recv()["command"], "wrongUserId");
    })
    .await
    .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rejects_unknown_origin_and_foreign_binary() {
    let env = setup(true).await;
    let (bin, home) = (env.bin.clone(), env.home.path().to_owned());
    tokio::task::spawn_blocking(move || {
        let mut nmh = Nmh::spawn(
            &bin,
            &home,
            "chrome-extension://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/",
        );
        // The bridge closes the connection; the NMH reports "disconnected".
        assert_eq!(nmh.recv()["command"], "disconnected");
    })
    .await
    .unwrap();

    let env = setup(false).await; // expects a different executable path
    let (bin, home) = (env.bin.clone(), env.home.path().to_owned());
    tokio::task::spawn_blocking(move || {
        let mut nmh = Nmh::spawn(&bin, &home, ALLOWED_ORIGINS[0]);
        assert_eq!(nmh.recv()["command"], "disconnected");
    })
    .await
    .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn nmh_reports_disconnected_when_app_not_running() {
    let home = tempfile::Builder::new()
        .prefix("wfn")
        .tempdir_in("/tmp")
        .unwrap();
    let bin = nmh_binary();
    let mut nmh = Nmh::spawn(&bin, home.path(), ALLOWED_ORIGINS[0]);
    assert_eq!(nmh.recv()["command"], "disconnected");
}

// ---------- SDK IPC (official bitwarden-ipc client on the browser side) ----------

#[derive(Debug, thiserror::Error)]
#[error("io")]
struct IoErr;
impl IpcErrorKind for IoErr {
    fn kind(&self) -> ErrorKind {
        ErrorKind::Unreachable
    }
}

#[derive(Clone)]
struct BrowserSide {
    stdin: Arc<Mutex<ChildStdin>>,
    incoming: tokio::sync::broadcast::Sender<IncomingMessage>,
}
struct BrowserRx(tokio::sync::Mutex<tokio::sync::broadcast::Receiver<IncomingMessage>>);

impl CommunicationBackend for BrowserSide {
    type SendError = IoErr;
    type Receiver = BrowserRx;
    async fn send(&self, m: OutgoingMessage) -> Result<(), IoErr> {
        let v = json!({"type": "bitwarden-ipc-message", "message": {
            "destination": m.destination, "payload": m.payload, "topic": m.topic}});
        let d = v.to_string();
        let mut w = self.stdin.lock().unwrap();
        w.write_all(&(d.len() as u32).to_ne_bytes())
            .map_err(|_| IoErr)?;
        w.write_all(d.as_bytes()).map_err(|_| IoErr)?;
        w.flush().map_err(|_| IoErr)
    }
    async fn subscribe(&self) -> BrowserRx {
        BrowserRx(tokio::sync::Mutex::new(self.incoming.subscribe()))
    }
}
impl CommunicationBackendReceiver for BrowserRx {
    type ReceiveError = IoErr;
    async fn receive(&self) -> Result<IncomingMessage, IoErr> {
        self.0.lock().await.recv().await.map_err(|_| IoErr)
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sdk_ipc_biometrics_over_noise() {
    let env = setup(true).await;
    let mut nmh = Nmh::spawn(&env.bin, env.home.path(), ALLOWED_ORIGINS[0]);
    let first = tokio::task::block_in_place(|| nmh.recv());
    assert_eq!(first["command"], "connected");

    let (tx, _) = tokio::sync::broadcast::channel(64);
    let side = BrowserSide {
        stdin: Arc::new(Mutex::new(nmh.stdin.take().unwrap())),
        incoming: tx.clone(),
    };
    // Reader thread: NMH stdout -> IncomingMessage (as DesktopIpcTransport does).
    let mut stdout = nmh.stdout.take().unwrap();
    std::thread::spawn(move || loop {
        let mut len = [0u8; 4];
        if stdout.read_exact(&mut len).is_err() {
            return;
        }
        let mut b = vec![0u8; u32::from_ne_bytes(len) as usize];
        if stdout.read_exact(&mut b).is_err() {
            return;
        }
        let v: Value = serde_json::from_slice(&b).unwrap();
        if v["type"] != "forwarded-bitwarden-ipc-message" {
            continue;
        }
        let m = &v["message"];
        let payload: Vec<u8> = m["payload"]
            .as_array()
            .unwrap()
            .iter()
            .map(|x| x.as_u64().unwrap() as u8)
            .collect();
        let source: Source = serde_json::from_value(v["originalSource"].clone()).unwrap();
        let _ = tx.send(IncomingMessage {
            payload,
            destination: serde_json::from_value(m["destination"].clone()).unwrap(),
            source,
            topic: m["topic"].as_str().map(str::to_owned),
        });
    });

    let client = IpcClientImpl::new(
        NoiseCryptoProvider::new(),
        side,
        InMemorySessionRepository::<NoiseCryptoProviderState>::default(),
    );
    client.start(None).await.unwrap();

    let d = tokio::time::timeout(
        Duration::from_secs(10),
        client.request(
            bitwarden_ipc::discover::DiscoverRequest,
            Endpoint::DesktopRenderer,
            None,
        ),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(!d.version.is_empty());

    let uid = bitwarden_core::UserId::from_str(USER).unwrap();
    let status = client
        .request(
            GetBiometricsStatusRequest { user_id: uid },
            Endpoint::DesktopRenderer,
            None,
        )
        .await
        .unwrap();
    assert_eq!(status, BiometricsStatus::Available);

    let r = client
        .request(
            UnlockBiometricsRequest { user_id: uid },
            Endpoint::DesktopRenderer,
            None,
        )
        .await
        .unwrap();
    assert_eq!(
        r.user_key.unwrap().to_base64().to_string(),
        env.user_key.to_base64().to_string()
    );

    let other = bitwarden_core::UserId::from_str("00000000-0000-0000-0000-000000000001").unwrap();
    let r = client
        .request(
            UnlockBiometricsRequest { user_id: other },
            Endpoint::DesktopRenderer,
            None,
        )
        .await
        .unwrap();
    assert!(r.user_key.is_none(), "other account refused");

    env.backend.allow.store(false, Ordering::SeqCst);
    let ok = client
        .request(
            AuthenticateBiometricsRequest,
            Endpoint::DesktopRenderer,
            None,
        )
        .await
        .unwrap();
    assert!(!ok, "cancelled verification");
    drop(nmh);
}
