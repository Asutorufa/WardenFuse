#![allow(clippy::unwrap_used)]

use std::{
    net::Ipv4Addr,
    sync::{
        atomic::{AtomicBool, Ordering},
        OnceLock,
    },
};

use async_trait::async_trait;
use rsa::{traits::PublicKeyParts, RsaPrivateKey};
use rustls::{
    pki_types::{CertificateDer, ServerName},
    ClientConfig, RootCertStore,
};
use serde_json::{json, Value};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};
use tokio_rustls::{client::TlsStream, TlsConnector};

use super::*;
use crate::platform::{AuthRequest, BiometryState};

#[derive(Default)]
pub(crate) struct MockPlatform {
    pub purposes: Mutex<Vec<AuthRequest>>,
    pub allow: AtomicBool,
    key: Mutex<Option<Zeroizing<Vec<u8>>>>,
    session: Mutex<Option<Zeroizing<Vec<u8>>>>,
    identity: Mutex<Option<Zeroizing<Vec<u8>>>>,
}

#[async_trait]
impl Platform for MockPlatform {
    async fn authenticate(&self, request: AuthRequest) -> Result<Zeroizing<Vec<u8>>, AuthFailure> {
        self.purposes.lock().unwrap().push(request);
        if !self.allow.load(Ordering::SeqCst) {
            return Err(AuthFailure::Cancelled);
        }
        self.key
            .lock()
            .unwrap()
            .clone()
            .ok_or(AuthFailure::KeyMissing)
    }

    fn store_user_key(&self, _user_id: &str, key: &[u8]) -> Result<()> {
        *self.key.lock().unwrap() = Some(Zeroizing::new(key.to_vec()));
        Ok(())
    }

    fn delete_user_key(&self, _user_id: &str) {
        self.key.lock().unwrap().take();
    }

    fn store_session(&self, data: &[u8]) -> Result<()> {
        *self.session.lock().unwrap() = Some(Zeroizing::new(data.to_vec()));
        Ok(())
    }

    fn load_session(&self) -> Option<Zeroizing<Vec<u8>>> {
        self.session.lock().unwrap().clone()
    }

    fn delete_session(&self) {
        self.session.lock().unwrap().take();
    }

    fn load_android_identity(&self) -> Result<Option<Zeroizing<Vec<u8>>>> {
        Ok(self.identity.lock().unwrap().clone())
    }

    fn store_android_identity(&self, data: &[u8]) -> Result<()> {
        *self.identity.lock().unwrap() = Some(Zeroizing::new(data.to_vec()));
        Ok(())
    }

    fn biometry_state(&self) -> BiometryState {
        BiometryState::Available
    }

    fn state_changed(&self, _snapshot_json: String) {}
}

impl MockPlatform {
    fn certificate(&self) -> Vec<u8> {
        let identity = self.identity.lock().unwrap();
        let identity = identity.as_ref().unwrap();
        let len = u32::from_be_bytes(identity[..4].try_into().unwrap()) as usize;
        identity[4..4 + len].to_vec()
    }
}

fn phone_key() -> &'static RsaPrivateKey {
    static KEY: OnceLock<RsaPrivateKey> = OnceLock::new();
    KEY.get_or_init(|| RsaPrivateKey::new(&mut OsRng, 2048).unwrap())
}

pub(crate) struct Phone {
    id: Uuid,
    credential: Secret,
    port: u16,
    cert: Vec<u8>,
}

pub(crate) type PhoneSocket = TlsStream<TcpStream>;

impl Phone {
    pub fn new(android: &Arc<Android>, platform: &MockPlatform) -> Self {
        let cert = platform.certificate();
        let (port, certificate) = {
            let s = android.lock();
            let listener = s.listener.as_ref().unwrap();
            (listener.port, listener.certificate.clone())
        };
        assert_eq!(certificate, URL_SAFE_NO_PAD.encode(&cert));
        let _ = phone_key();
        Self {
            id: Uuid::new_v4(),
            credential: random().unwrap(),
            port,
            cert,
        }
    }

    pub async fn connect(&self) -> PhoneSocket {
        connect(self.port, Some(&self.cert)).await.unwrap()
    }

    pub async fn stage(&self, offer: &Value) -> (PhoneSocket, String) {
        let qr: Value = serde_json::from_str(offer["qr"].as_str().unwrap()).unwrap();
        assert_eq!(qr["certificate"], URL_SAFE_NO_PAD.encode(&self.cert));
        let mut socket = self.connect().await;
        self.send_pair(&mut socket, &qr).await;
        let reply = read(&mut socket).await.unwrap();
        assert_eq!(reply["status"], "confirm");
        (socket, reply["code"].as_str().unwrap().to_owned())
    }

    async fn send_pair(&self, socket: &mut PhoneSocket, qr: &Value) {
        let command = json!({
            "op":"pair", "version":1, "id":self.id, "name":"Test phone",
            "modulus": URL_SAFE_NO_PAD.encode(phone_key().n().to_bytes_be()),
        });
        write(socket, command.to_string().as_bytes()).await;
        let mut proof = URL_SAFE_NO_PAD
            .decode(qr["token"].as_str().unwrap())
            .unwrap();
        proof.extend(self.credential);
        write(socket, &proof).await;
    }

    pub async fn listen(&self) -> (PhoneSocket, Value) {
        let mut socket = self.connect().await;
        let command = json!({"op":"listen", "version":1, "id":self.id});
        write(&mut socket, command.to_string().as_bytes()).await;
        write(&mut socket, &self.credential).await;
        let status = read(&mut socket).await.unwrap();
        (socket, status)
    }

    pub async fn ready(&self) -> PhoneSocket {
        time::timeout(Duration::from_secs(3), async {
            loop {
                let (socket, status) = self.listen().await;
                if status["status"] == "busy" {
                    time::sleep(Duration::from_millis(10)).await;
                } else {
                    assert_eq!(status["status"], "ready");
                    return socket;
                }
            }
        })
        .await
        .unwrap()
    }

    pub async fn approve(&self, socket: &mut PhoneSocket, browser: &str) -> Vec<u8> {
        let request = read(socket).await.unwrap();
        assert_eq!(request["browser"], browser);
        let proof = Self::proof(&request);
        write(socket, &proof).await;
        assert_eq!(read(socket).await.unwrap()["status"], "approved");
        proof
    }

    fn proof(request: &Value) -> Vec<u8> {
        assert_eq!(request["status"], "request");
        assert!(request.get("user_key").is_none());
        let mut proof = URL_SAFE_NO_PAD
            .decode(request["challenge"].as_str().unwrap())
            .unwrap();
        let wrapped = URL_SAFE_NO_PAD
            .decode(request["wrapped_key"].as_str().unwrap())
            .unwrap();
        let key = phone_key()
            .decrypt(Oaep::new_with_mgf_hash::<Sha256, sha1::Sha1>(), &wrapped)
            .unwrap();
        proof.extend(key);
        proof
    }
}

async fn connect(port: u16, cert: Option<&[u8]>) -> Result<PhoneSocket> {
    let mut roots = RootCertStore::empty();
    if let Some(cert) = cert {
        roots.add(CertificateDer::from(cert.to_vec()))?;
    }
    let client =
        ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_protocol_versions(&[&rustls::version::TLS13])?
            .with_root_certificates(roots)
            .with_no_client_auth();
    let socket = TcpStream::connect((Ipv4Addr::LOCALHOST, port)).await?;
    Ok(TlsConnector::from(Arc::new(client))
        .connect(ServerName::try_from("wardenfuse.local")?, socket)
        .await?)
}

pub(crate) async fn read(socket: &mut PhoneSocket) -> Result<Value> {
    time::timeout(Duration::from_secs(4), async {
        let len = socket.read_u32().await?;
        let mut data = vec![0; len as usize];
        socket.read_exact(&mut data).await?;
        Ok(serde_json::from_slice(&data)?)
    })
    .await?
}

async fn write(socket: &mut PhoneSocket, bytes: &[u8]) {
    socket.write_u32(bytes.len() as u32).await.unwrap();
    socket.write_all(bytes).await.unwrap();
    socket.flush().await.unwrap();
}

pub(crate) fn offer(android: &Arc<Android>) -> Value {
    android
        .issue_pairing(Ipv4Addr::LOCALHOST, "Test Mac")
        .unwrap()
}

pub(crate) fn pairing_id(offer: &Value) -> Uuid {
    serde_json::from_value(offer["pairing_id"].clone()).unwrap()
}

struct Fixture {
    dir: tempfile::TempDir,
    platform: MockPlatform,
    android: Arc<Android>,
    account: Account,
    phone: Phone,
}

impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let platform = MockPlatform::default();
        let android = Android::new(dir.path(), Arc::new(Notify::new()));
        let account = Account::new(Uuid::new_v4(), "wrapped account private key");
        android.reconcile(Some(account.clone()), true, &platform);
        let phone = Phone::new(&android, &platform);
        Self {
            dir,
            platform,
            android,
            account,
            phone,
        }
    }

    async fn pair(&self) {
        let offer = offer(&self.android);
        let id = pairing_id(&offer);
        let (mut socket, code) = self.phone.stage(&offer).await;
        assert!(self.android.authorize_pairing(id, "wrong").is_err());
        assert_eq!(
            self.android.authorize_pairing(id, &code).unwrap().0,
            self.account
        );
        self.android
            .finish_pairing(id, &self.account, b"test Bitwarden user key")
            .unwrap();
        assert_eq!(read(&mut socket).await.unwrap()["status"], "paired");
    }

    fn request(&self, timeout: Duration) -> tokio::task::JoinHandle<Result<Unlocked, AuthFailure>> {
        let android = self.android.clone();
        let account = self.account.clone();
        tokio::spawn(async move {
            android
                .authenticate(&account, "Chrome".to_owned(), false, timeout)
                .await
        })
    }
}

#[tokio::test]
async fn pairing_requires_pin_token_confirmation_and_unexpired_session() {
    let f = Fixture::new();
    assert!(connect(f.phone.port, None).await.is_err(), "untrusted Mac");
    let qr = offer(&f.android);
    let (mut phone, code) = f.phone.stage(&qr).await;
    let id = pairing_id(&qr);
    assert!(!f.android.available());
    assert!(f.android.finish_pairing(id, &f.account, b"key").is_err());
    assert!(
        read(&mut phone).await.is_err(),
        "unconfirmed pairing closed"
    );
    assert_eq!(f.phone.listen().await.1["status"], "unpaired");

    let qr = offer(&f.android);
    let mut expired = f.phone.connect().await;
    f.android.lock().pairing.as_mut().unwrap().deadline = Instant::now();
    f.phone
        .send_pair(
            &mut expired,
            &serde_json::from_str(qr["qr"].as_str().unwrap()).unwrap(),
        )
        .await;
    assert!(read(&mut expired).await.is_err());
    assert!(f.android.authorize_pairing(id, &code).is_err());

    let qr = offer(&f.android);
    let id = pairing_id(&qr);
    let (mut primary, code) = f.phone.stage(&qr).await;
    let mut replay = f.phone.connect().await;
    f.phone
        .send_pair(
            &mut replay,
            &serde_json::from_str(qr["qr"].as_str().unwrap()).unwrap(),
        )
        .await;
    assert!(
        read(&mut replay).await.is_err(),
        "claimed QR token cannot be reused"
    );
    f.android.authorize_pairing(id, &code).unwrap();
    f.android.finish_pairing(id, &f.account, b"key").unwrap();
    assert_eq!(read(&mut primary).await.unwrap()["status"], "paired");
}

#[tokio::test]
async fn request_requires_matching_challenge_and_envelope_key() {
    let f = Fixture::new();
    f.pair().await;
    let mut phone = f.phone.ready().await;
    let result = f.request(Duration::from_secs(3));
    let proof = f.phone.approve(&mut phone, "Chrome").await;
    assert_eq!(
        result.await.unwrap().unwrap().key.as_slice(),
        b"test Bitwarden user key"
    );

    let mut phone = f.phone.ready().await;
    let result = f.request(Duration::from_secs(3));
    let new = read(&mut phone).await.unwrap();
    assert_ne!(new["challenge"], URL_SAFE_NO_PAD.encode(&proof[..32]));
    write(&mut phone, &proof).await;
    assert_eq!(read(&mut phone).await.unwrap()["status"], "rejected");
    assert!(result.await.unwrap().is_err());

    let mut phone = f.phone.ready().await;
    let result = f.request(Duration::from_secs(3));
    let mut bad = Phone::proof(&read(&mut phone).await.unwrap());
    bad[32] ^= 1;
    write(&mut phone, &bad).await;
    assert_eq!(read(&mut phone).await.unwrap()["status"], "rejected");
    assert!(matches!(result.await.unwrap(), Err(AuthFailure::Failed)));
}

#[tokio::test]
async fn concurrent_requests_disconnect_cancellation_and_revocation_fail_closed() {
    let f = Fixture::new();
    f.pair().await;
    let mut wrong = Phone::new(&f.android, &f.platform);
    wrong.id = f.phone.id;
    assert_eq!(
        wrong.listen().await.1["status"],
        "unpaired",
        "wrong credential"
    );

    let mut phone = f.phone.ready().await;
    let result = f.request(Duration::from_secs(3));
    let challenge = read(&mut phone).await.unwrap();
    assert!(matches!(
        f.request(Duration::from_secs(1)).await.unwrap(),
        Err(AuthFailure::Failed)
    ));
    drop(phone);
    assert!(matches!(result.await.unwrap(), Err(AuthFailure::Cancelled)));

    assert!(matches!(
        f.request(Duration::from_millis(40)).await.unwrap(),
        Err(AuthFailure::Timeout)
    ));
    let mut phone = f.phone.ready().await;
    let result = f.request(Duration::from_secs(3));
    let pending = read(&mut phone).await.unwrap();
    assert_ne!(challenge["challenge"], pending["challenge"]);
    write(
        &mut phone,
        &URL_SAFE_NO_PAD
            .decode(pending["challenge"].as_str().unwrap())
            .unwrap(),
    )
    .await;
    assert_eq!(read(&mut phone).await.unwrap()["status"], "cancelled");
    assert!(result.await.unwrap().is_err());

    let mut phone = f.phone.ready().await;
    let result = f.request(Duration::from_secs(3));
    let _ = read(&mut phone).await.unwrap();
    f.android.remove(f.phone.id).unwrap();
    assert!(result.await.unwrap().is_err());
    assert!(read(&mut phone).await.is_err());
    assert_eq!(f.phone.listen().await.1["status"], "unpaired");

    f.android
        .reconcile(Some(f.account.clone()), false, &f.platform);
    let restored = Android::new(f.dir.path(), Arc::new(Notify::new()));
    restored.reconcile(Some(f.account.clone()), true, &f.platform);
    assert!(!restored.available(), "revocation survives restart");
}

#[tokio::test]
async fn restart_recovers_only_current_enrollment_and_key_rotation_clears_it() {
    let f = Fixture::new();
    f.pair().await;
    let path = f.dir.path().join("android-devices.json");
    assert!(!std::fs::read_to_string(&path)
        .unwrap()
        .contains("test Bitwarden user key"));
    f.android
        .reconcile(Some(f.account.clone()), false, &f.platform);
    let restored = Android::new(f.dir.path(), Arc::new(Notify::new()));
    restored.reconcile(Some(f.account.clone()), true, &f.platform);
    assert!(restored.available());
    let mut phone = Phone::new(&restored, &f.platform);
    assert_eq!(phone.cert, f.phone.cert, "TLS pin survives restart");
    phone.id = f.phone.id;
    phone.credential = f.phone.credential;
    let mut socket = phone.ready().await;
    let approved = phone.approve(&mut socket, "Chrome");
    let request = restored.authenticate(
        &f.account,
        "Chrome".to_owned(),
        false,
        Duration::from_secs(3),
    );
    let (_, key) = tokio::join!(approved, request);
    assert_eq!(key.unwrap().key.as_slice(), b"test Bitwarden user key");

    let changed = Account::new(f.account.session, "rewrapped with a rotated user key");
    restored.reconcile(Some(changed), true, &f.platform);
    assert!(!path.exists());
    assert!(!restored.available());
    assert_eq!(phone.listen().await.1["status"], "unpaired");
}

#[test]
fn envelope_authenticates_ciphertext_device_and_account() {
    let device = Uuid::new_v4();
    let account = Account::new(Uuid::new_v4(), "wrapped");
    let mut env =
        Envelope::seal(&account, device, &phone_key().to_public_key(), b"vault key").unwrap();
    let key = phone_key()
        .decrypt(
            Oaep::new_with_mgf_hash::<Sha256, sha1::Sha1>(),
            &env.wrapped_key,
        )
        .unwrap();
    assert_eq!(
        env.open(&account, device, &key).unwrap().as_slice(),
        b"vault key"
    );
    assert!(env.open(&account, Uuid::new_v4(), &key).is_err());
    assert!(env
        .open(&Account::new(account.session, "rotated"), device, &key)
        .is_err());
    env.ciphertext[0] ^= 1;
    assert!(env.open(&account, device, &key).is_err());
}
