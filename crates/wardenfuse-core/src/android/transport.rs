//! TLS 1.3 with a QR-pinned server certificate and a per-device bearer credential.
//! Each bounded frame is a 32-bit big-endian length followed by JSON or binary bytes.
//! Binary frames keep tokens and envelope keys out of JSON strings.

use std::{
    collections::hash_map::Entry,
    net::Ipv4Addr,
    sync::{Arc, Weak},
    time::Duration,
};

use anyhow::{anyhow, bail, ensure, Context, Result};
use rustls::{
    pki_types::{CertificateDer, PrivatePkcs8KeyDer},
    ServerConfig,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::{oneshot, Semaphore},
    task::JoinHandle,
};
use tokio_rustls::{server::TlsStream, TlsAcceptor};

use super::{
    digest, random, Android, Candidate, RequestGuard, Secret, MAX_DEVICES, URL_SAFE_NO_PAD,
};
use crate::platform::Platform;
use base64::Engine;
use rsa::{BigUint, RsaPublicKey};
use serde::Deserialize;
use serde_json::{json, Value};
use subtle::ConstantTimeEq;
use tokio::time::{self, Instant};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;
use zeroize::Zeroizing;

pub(super) const PORT: u16 = 47635;
const FRAME_LIMIT: usize = 4096;
const IO_LIMIT: Duration = Duration::from_secs(5);
const IDLE_LIMIT: Duration = Duration::from_secs(25);
const MAX_CONNECTIONS: usize = 24;

pub(super) struct Listener {
    pub certificate: String,
    pub port: u16,
    task: JoinHandle<()>,
    cancel: CancellationToken,
}

impl Listener {
    pub fn start(android: &Arc<Android>, platform: &dyn Platform) -> Result<Self> {
        #[cfg(not(test))]
        let address = (Ipv4Addr::UNSPECIFIED, PORT);
        #[cfg(test)]
        let address = (Ipv4Addr::LOCALHOST, 0);
        let socket = std::net::TcpListener::bind(address)
            .with_context(|| format!("Unable to listen on Android pairing port {PORT}"))?;
        socket.set_nonblocking(true)?;
        let listener = TcpListener::from_std(socket)?;
        let (certificate, config) = server_config(platform)?;
        let port = listener.local_addr()?.port();
        let cancel = CancellationToken::new();
        let task = tokio::spawn(serve(
            listener,
            TlsAcceptor::from(Arc::new(config)),
            Arc::downgrade(android),
            cancel.clone(),
        ));
        Ok(Self {
            certificate,
            port,
            task,
            cancel,
        })
    }
}

impl Drop for Listener {
    fn drop(&mut self) {
        self.cancel.cancel();
        self.task.abort();
    }
}

fn server_config(platform: &dyn Platform) -> Result<(String, ServerConfig)> {
    let identity = match platform.load_android_identity()? {
        Some(identity) => identity,
        None => {
            let pair = rcgen::generate_simple_self_signed(vec!["wardenfuse.local".into()])?;
            let cert = pair.cert.der();
            let key = Zeroizing::new(pair.signing_key.serialize_der());
            let mut identity = Zeroizing::new((cert.len() as u32).to_be_bytes().to_vec());
            identity.extend(cert.as_ref());
            identity.extend(key.as_slice());
            platform.store_android_identity(&identity)?;
            identity
        }
    };
    let invalid = || anyhow!("Invalid Android TLS identity in the Mac Keychain");
    let len = u32::from_be_bytes(identity.get(..4).ok_or_else(invalid)?.try_into()?) as usize;
    let (cert, key) = identity[4..].split_at_checked(len).ok_or_else(invalid)?;
    let certificate = URL_SAFE_NO_PAD.encode(cert);
    let mut config =
        ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_protocol_versions(&[&rustls::version::TLS13])?
            .with_no_client_auth()
            .with_single_cert(
                vec![CertificateDer::from(cert.to_vec())],
                PrivatePkcs8KeyDer::from(key.to_vec()).into(),
            )?;
    // Each connection authenticates with a fresh handshake and the device credential.
    config.send_tls13_tickets = 0;
    Ok((certificate, config))
}

/// Offer numeric addresses on this Mac. No DNS or discovery is used by the phone.
pub(super) fn addresses() -> Result<Vec<Ipv4Addr>> {
    let mut list = std::ptr::null_mut();
    // SAFETY: getifaddrs allocates the list and fills the out pointer on success.
    if unsafe { libc::getifaddrs(&mut list) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let mut addresses = Vec::new();
    // SAFETY: traverse the live list up to the terminal null and check family before casting.
    unsafe {
        let mut next = list;
        while let Some(iface) = next.as_ref() {
            next = iface.ifa_next;
            if iface.ifa_flags & (libc::IFF_UP | libc::IFF_LOOPBACK) as u32 != libc::IFF_UP as u32
                || iface.ifa_addr.is_null()
                || (*iface.ifa_addr).sa_family as i32 != libc::AF_INET
            {
                continue;
            }
            let addr = &*iface.ifa_addr.cast::<libc::sockaddr_in>();
            addresses.push(Ipv4Addr::from(addr.sin_addr.s_addr.to_ne_bytes()));
        }
        libc::freeifaddrs(list);
    }
    addresses.sort_by_key(|address| (!address.is_private(), *address));
    addresses.dedup();
    Ok(addresses)
}

async fn serve(
    listener: TcpListener,
    tls: TlsAcceptor,
    android: Weak<Android>,
    cancel: CancellationToken,
) {
    let limit = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    loop {
        let (socket, _) = match listener.accept().await {
            Ok(conn) => conn,
            Err(_) => {
                time::sleep(Duration::from_secs(1)).await;
                continue;
            }
        };
        let Ok(permit) = limit.clone().try_acquire_owned() else {
            continue;
        };
        let Some(android) = android.upgrade() else {
            return;
        };
        let tls = tls.clone();
        let cancel = cancel.clone();
        tokio::spawn(async move {
            let _permit = permit;
            tokio::select! {
                biased;
                () = cancel.cancelled() => {}
                _ = connect(socket, tls, &android) => {}
            }
        });
    }
}

#[derive(Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
enum Command {
    Pair {
        version: u8,
        id: Uuid,
        name: String,
        modulus: String,
    },
    Listen {
        version: u8,
        id: Uuid,
    },
}

type Socket = TlsStream<TcpStream>;

async fn read_frame(socket: &mut Socket) -> Result<Zeroizing<Vec<u8>>> {
    let len = socket.read_u32().await? as usize;
    ensure!(
        (1..=FRAME_LIMIT).contains(&len),
        "Invalid Android frame length"
    );
    let mut frame = Zeroizing::new(vec![0; len]);
    socket.read_exact(&mut frame).await?;
    Ok(frame)
}

async fn write_json(socket: &mut Socket, value: Value) -> Result<()> {
    let data = serde_json::to_vec(&value)?;
    ensure!(data.len() <= FRAME_LIMIT, "Android response too large");
    time::timeout(IO_LIMIT, async {
        socket.write_u32(data.len() as u32).await?;
        socket.write_all(&data).await?;
        socket.flush().await
    })
    .await??;
    Ok(())
}

async fn connect(socket: TcpStream, tls: TlsAcceptor, android: &Android) -> Result<()> {
    let mut socket = time::timeout(IO_LIMIT, tls.accept(socket)).await??;
    let (command, credentials) = time::timeout(IO_LIMIT, async {
        let command = serde_json::from_slice::<Command>(&read_frame(&mut socket).await?)?;
        let credentials = read_frame(&mut socket).await?;
        Ok::<_, anyhow::Error>((command, credentials))
    })
    .await??;
    match command {
        Command::Pair {
            version: 1,
            id,
            name,
            modulus,
        } if credentials.len() == 64 => {
            pair(&mut socket, android, id, name, &modulus, credentials).await?;
        }
        Command::Listen { version: 1, id } if credentials.len() == 32 => {
            let hash = digest(&credentials);
            drop(credentials);
            listen(&mut socket, android, id, hash).await?;
        }
        _ => bail!("Unsupported Android command"),
    }
    let _ = time::timeout(IO_LIMIT, socket.shutdown()).await;
    Ok(())
}

struct PairGuard<'a> {
    android: &'a Android,
    id: Uuid,
}

impl Drop for PairGuard<'_> {
    fn drop(&mut self) {
        self.android.cancel_pairing(self.id);
    }
}

async fn pair(
    socket: &mut Socket,
    android: &Android,
    id: Uuid,
    name: String,
    modulus: &str,
    credentials: Zeroizing<Vec<u8>>,
) -> Result<()> {
    let token_hash = digest(&credentials[..32]);
    let credential_hash = digest(&credentials[32..]);
    drop(credentials);
    let (pair_id, deadline, cancel) = {
        let mut s = android.lock();
        ensure!(
            s.devices().len() < MAX_DEVICES && s.devices().iter().all(|d| d.id != id),
            "Invalid device"
        );
        let p = s
            .pairing
            .as_mut()
            .filter(|p| {
                p.candidate.is_none()
                    && Instant::now() < p.deadline
                    && p.token_hash
                        .is_some_and(|hash| bool::from(hash.ct_eq(&token_hash)))
            })
            .ok_or_else(|| anyhow!("Invalid or expired pairing token"))?;
        // Consume the token even if the remainder of the enrollment is invalid.
        p.token_hash = None;
        (p.id, p.deadline, p.cancel.clone())
    };
    let _guard = PairGuard {
        android,
        id: pair_id,
    };
    let name = name.trim();
    ensure!(
        !name.is_empty() && name.chars().count() <= 48 && !name.chars().any(char::is_control),
        "Invalid device name"
    );
    let modulus = URL_SAFE_NO_PAD.decode(modulus)?;
    ensure!(
        modulus.len() == 256 && modulus[0] >= 128,
        "Expected a 2048-bit RSA key"
    );
    let public_key = RsaPublicKey::new(BigUint::from_bytes_be(&modulus), BigUint::from(65_537u32))?;
    // 64-bit CSPRNG output reduced to eight digits (negligible modulo bias).
    let code = format!("{:08}", u64::from_be_bytes(random()?) % 100_000_000);
    let (result, rx) = oneshot::channel();
    {
        let mut s = android.lock();
        let p = s
            .pairing
            .as_mut()
            .filter(|p| p.id == pair_id)
            .ok_or_else(|| anyhow!("Pairing was cancelled"))?;
        p.candidate = Some(Candidate {
            id,
            name: name.to_owned(),
            credential_hash,
            public_key,
            code: code.clone(),
            confirming: false,
            result,
        });
    }
    android.changed();
    tokio::select! {
        biased;
        () = cancel.cancelled() => bail!("Pairing was cancelled"),
        () = time::sleep_until(deadline) => bail!("Pairing expired"),
        r = async {
            write_json(socket, json!({"status":"confirm", "code":code})).await?;
            tokio::select! {
                biased;
                _ = socket.read_u8() => bail!("Phone disconnected during pairing"),
                result = rx => result.map_err(|_| anyhow!("Pairing was cancelled")),
            }
        } => r?,
    }
    write_json(socket, json!({"status":"paired"})).await
}

struct OnlineGuard<'a> {
    android: &'a Android,
    device: Uuid,
    connection: Uuid,
}

impl Drop for OnlineGuard<'_> {
    fn drop(&mut self) {
        let mut s = self.android.lock();
        if s.online
            .get(&self.device)
            .is_some_and(|(id, _)| *id == self.connection)
        {
            s.online.remove(&self.device);
            self.android.changed();
        }
    }
}

struct Challenge {
    id: Secret,
    browser: String,
    verify: bool,
    deadline: Instant,
    wrapped_key: Vec<u8>,
    cancel: CancellationToken,
}

async fn listen(
    socket: &mut Socket,
    android: &Android,
    device: Uuid,
    credential_hash: Secret,
) -> Result<()> {
    let connection = Uuid::new_v4();
    let revocation = CancellationToken::new();
    let status = {
        let mut s = android.lock();
        if !s
            .devices()
            .iter()
            .any(|d| d.id == device && bool::from(d.credential_hash.ct_eq(&credential_hash)))
        {
            "unpaired"
        } else if let Entry::Vacant(entry) = s.online.entry(device) {
            entry.insert((connection, revocation.clone()));
            "ready"
        } else {
            "busy"
        }
    };
    if status != "ready" {
        return write_json(socket, json!({"status":status})).await;
    }
    let _online = OnlineGuard {
        android,
        device,
        connection,
    };
    android.changed();
    tokio::select! {
        biased;
        () = revocation.cancelled() => bail!("Phone was disconnected"),
        r = exchange(socket, android, device) => r,
    }
}

async fn wait_for_request(android: &Android, device: Uuid) -> Result<Challenge> {
    loop {
        let changed = std::pin::pin!(android.changed.notified());
        // Register before reading the state to avoid losing a notification.
        let mut changed = changed;
        changed.as_mut().enable();
        {
            let mut s = android.lock();
            let wrapped = s
                .devices()
                .iter()
                .find(|d| d.id == device)
                .ok_or_else(|| anyhow!("Unknown device"))?;
            if s.pending
                .as_ref()
                .is_some_and(|p| p.claimed.is_none() && Instant::now() < p.deadline)
            {
                let wrapped_key = wrapped.envelope.wrapped_key.clone();
                let pending = s.pending.as_mut().ok_or_else(|| anyhow!("No request"))?;
                pending.claimed = Some(device);
                return Ok(Challenge {
                    id: pending.challenge,
                    browser: pending.browser.clone(),
                    verify: pending.verify,
                    deadline: pending.deadline,
                    wrapped_key,
                    cancel: pending.cancel.clone(),
                });
            }
        }
        changed.await;
    }
}

async fn exchange(socket: &mut Socket, android: &Android, device: Uuid) -> Result<()> {
    write_json(socket, json!({"status":"ready"})).await?;
    let challenge = tokio::select! {
        biased;
        _ = socket.read_u8() => bail!("Phone disconnected"),
        r = time::timeout(IDLE_LIMIT, wait_for_request(android, device)) => match r {
            Ok(challenge) => challenge?,
            Err(_) => return write_json(socket, json!({"status":"idle"})).await,
        }
    };
    let _request = RequestGuard {
        android,
        challenge: challenge.id,
    };
    let approve = async {
        write_json(socket, json!({
            "status":"request", "challenge": URL_SAFE_NO_PAD.encode(challenge.id),
            "browser": challenge.browser, "verify": challenge.verify, "wrapped_key": URL_SAFE_NO_PAD.encode(challenge.wrapped_key),
            "remaining_ms": challenge.deadline.saturating_duration_since(Instant::now()).as_millis() as u64,
        })).await?;
        let reply = read_frame(socket).await?;
        ensure!(
            reply.len() >= 32 && bool::from(reply[..32].ct_eq(&challenge.id)),
            "Invalid Android challenge"
        );
        // 32 bytes = explicit cancellation; 64 = challenge followed by the envelope key.
        if reply.len() == 32 {
            return Ok("cancelled");
        }
        ensure!(reply.len() == 64, "Invalid Android proof");
        android.respond(device, challenge.id, &reply[32..])?;
        Ok("approved")
    };
    let status = tokio::select! {
        biased;
        () = challenge.cancel.cancelled() => "cancelled",
        r = time::timeout_at(challenge.deadline, approve) => match r {
            Ok(Ok(status)) => status,
            Ok(Err(_)) => "rejected",
            Err(_) => "expired",
        },
    };
    drop(_request);
    write_json(socket, json!({"status":status})).await
}
