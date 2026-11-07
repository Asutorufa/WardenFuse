//! Browser biometric unlock bridge.
//!
//! ```text
//! Bitwarden extension ──native messaging (stdio)──▶ wardenfuse-nmh ──UDS──▶ WardenFuse.app
//! ```
//!
//! `wardenfuse-nmh` is started on demand by the browser and is a dumb relay. All protocol
//! handling happens here, in the main process. A connection is accepted only when
//! * the peer has our UID (`LOCAL_PEERCRED`), and
//! * the peer executable (`proc_pidpath` of `LOCAL_PEERPID`) is the NMH bundled in this app, and
//! * the extension origin reported by the browser is an official Bitwarden extension.

pub mod legacy;
pub mod manifest;
pub mod sdk_ipc;

use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicI32, Ordering},
        Arc,
    },
};

use anyhow::{anyhow, bail, Result};
use async_trait::async_trait;
use serde_json::{json, Value};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{UnixListener, UnixStream},
    sync::{mpsc, Mutex, RwLock},
};
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;

pub use self::legacy::LegacyBiometricsStatus;
use self::{legacy::LegacySession, sdk_ipc::SdkIpc};
use crate::peer;

/// Max frame size, same limit browsers apply to host → browser messages.
pub const MAX_FRAME: usize = 1024 * 1024;

/// Official Bitwarden browser extension origins (from `native-messaging.main.ts`).
pub const ALLOWED_ORIGINS: &[&str] = &[
    // Chrome Web Store (Chrome, Brave, Vivaldi, Chromium, ...)
    "chrome-extension://nngceckbapebfimnlniiiahkandclblb/",
    // Chrome Web Store beta
    "chrome-extension://hccnnhgbibccigepcmlgppchkpfdophk/",
    // Microsoft Edge Add-ons
    "chrome-extension://jbkfoedolllekgbhcbcoahefnbanhhlh/",
    // Opera Add-ons
    "chrome-extension://ccnckbpmaceehanjmeomladnmlffdjgn/",
];

/// Operations the bridge needs from the core service.
#[async_trait]
pub trait BrowserBackend: Send + Sync + 'static {
    /// Bitwarden user id logged into WardenFuse, if any.
    async fn logged_in_user(&self) -> Option<String>;
    async fn biometrics_status(&self, user_id: Option<&str>) -> LegacyBiometricsStatus;
    /// Authenticates (Touch ID / password) and returns the user key (base64) for `user_id`.
    /// Must return `None` for any other account. Never served from the SSH TTL cache.
    async fn unlock_user_key(&self, user_id: &str, browser: &str) -> Option<Zeroizing<String>>;
    async fn verify_user(&self, browser: &str) -> bool;
}

pub async fn read_frame<R: AsyncReadExt + Unpin>(r: &mut R) -> std::io::Result<Option<Vec<u8>>> {
    let mut len = [0u8; 4];
    match r.read_exact(&mut len).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let n = u32::from_ne_bytes(len) as usize;
    if n > MAX_FRAME {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "frame too large",
        ));
    }
    let mut buf = vec![0u8; n];
    r.read_exact(&mut buf).await?;
    Ok(Some(buf))
}

pub async fn write_frame<W: AsyncWriteExt + Unpin>(w: &mut W, data: &[u8]) -> std::io::Result<()> {
    if data.len() > MAX_FRAME {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "frame too large",
        ));
    }
    let len = u32::try_from(data.len()).unwrap_or(u32::MAX).to_ne_bytes();
    w.write_all(&len).await?;
    w.write_all(data).await?;
    w.flush().await
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct ConnectionInfo {
    pub id: i32,
    pub browser: String,
    pub origin: String,
}

pub struct BrowserBridge {
    cancel: CancellationToken,
    socket: PathBuf,
    connections: sdk_ipc::ConnectionMap,
    sdk: Arc<SdkIpc>,
}

impl BrowserBridge {
    /// Starts listening. `expected_nmh` is the absolute path of the bundled NMH executable;
    /// `None` disables the executable check (tests only).
    pub async fn start<B: BrowserBackend>(
        socket: PathBuf,
        expected_nmh: Option<PathBuf>,
        backend: Arc<B>,
    ) -> Result<Self> {
        if let Some(dir) = socket.parent() {
            crate::config::ensure_private_dir(dir)?;
        }
        remove_stale_socket(&socket)?;
        let listener = UnixListener::bind(&socket)?;
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600))?;
        }
        let connections: sdk_ipc::ConnectionMap = Arc::new(RwLock::new(HashMap::new()));
        let sdk = Arc::new(SdkIpc::start(backend.clone(), connections.clone()).await?);
        let cancel = CancellationToken::new();
        let expected_nmh = expected_nmh.map(|p| p.canonicalize().unwrap_or(p));

        let next_id = Arc::new(AtomicI32::new(1));
        tokio::spawn({
            let cancel = cancel.clone();
            let connections = connections.clone();
            let sdk = sdk.clone();
            async move {
                loop {
                    let accepted = tokio::select! {
                        () = cancel.cancelled() => break,
                        r = listener.accept() => r,
                    };
                    let Ok((stream, _)) = accepted else { continue };
                    let id = next_id.fetch_add(1, Ordering::SeqCst);
                    let conns = connections.clone();
                    let sdk = sdk.clone();
                    let backend = backend.clone();
                    let expected = expected_nmh.clone();
                    let cancel = cancel.clone();
                    tokio::spawn(async move {
                        if let Err(e) = handle_connection(
                            id,
                            stream,
                            expected,
                            conns.clone(),
                            sdk,
                            backend,
                            cancel,
                        )
                        .await
                        {
                            tracing::info!(error = %e, "Browser connection closed");
                        }
                        conns.write().await.remove(&id);
                    });
                }
            }
        });
        Ok(Self {
            cancel,
            socket,
            connections,
            sdk,
        })
    }

    pub async fn connections(&self) -> Vec<ConnectionInfo> {
        self.connections
            .read()
            .await
            .iter()
            .map(|(id, (_, b))| ConnectionInfo {
                id: *id,
                browser: b.clone(),
                origin: String::new(),
            })
            .collect()
    }

    pub async fn connection_count(&self) -> usize {
        self.connections.read().await.len()
    }

    pub fn stop(&self) {
        self.cancel.cancel();
        self.sdk.stop();
        use std::os::unix::fs::FileTypeExt;
        if std::fs::symlink_metadata(&self.socket).is_ok_and(|m| m.file_type().is_socket()) {
            let _ = std::fs::remove_file(&self.socket);
        }
    }
}

impl Drop for BrowserBridge {
    fn drop(&mut self) {
        self.stop();
    }
}

fn remove_stale_socket(p: &Path) -> Result<()> {
    use std::os::unix::fs::FileTypeExt;
    match std::fs::symlink_metadata(p) {
        Ok(m) if m.file_type().is_socket() => Ok(std::fs::remove_file(p)?),
        Ok(_) => bail!("refusing to replace non-socket {}", p.display()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e.into()),
    }
}

fn verify_peer(stream: &UnixStream, expected: Option<&Path>) -> Result<()> {
    let cred = stream.peer_cred()?;
    if cred.uid() != peer::own_uid() {
        bail!("rejected browser bridge connection from foreign uid");
    }
    if let Some(expected) = expected {
        let pid = cred.pid().ok_or_else(|| anyhow!("peer pid unavailable"))?;
        let exe = peer::executable_path(pid).ok_or_else(|| anyhow!("peer path unavailable"))?;
        let exe = exe.canonicalize().unwrap_or(exe);
        if exe != expected {
            bail!("rejected browser bridge connection from {}", exe.display());
        }
    }
    Ok(())
}

async fn handle_connection<B: BrowserBackend>(
    id: i32,
    stream: UnixStream,
    expected: Option<PathBuf>,
    connections: sdk_ipc::ConnectionMap,
    sdk: Arc<SdkIpc>,
    backend: Arc<B>,
    cancel: CancellationToken,
) -> Result<()> {
    verify_peer(&stream, expected.as_deref())?;
    let (mut rd, mut wr) = stream.into_split();

    // Announcement from the NMH.
    let first = read_frame(&mut rd)
        .await?
        .ok_or_else(|| anyhow!("no announcement"))?;
    let ann: Value = serde_json::from_slice(&first)?;
    let origin = ann["origin"].as_str().unwrap_or_default().to_owned();
    if !ALLOWED_ORIGINS.contains(&origin.as_str()) {
        bail!("rejected unknown extension origin {origin}");
    }
    let browser = ann["browser"]
        .as_str()
        .filter(|s| !s.is_empty())
        .unwrap_or("your browser")
        .to_owned();
    tracing::info!(id, %browser, "Browser connected");

    let (tx, mut rx) = mpsc::channel::<String>(32);
    connections
        .write()
        .await
        .insert(id, (tx.clone(), browser.clone()));

    let writer = tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            if write_frame(&mut wr, msg.as_bytes()).await.is_err() {
                break;
            }
        }
    });

    // The extension waits for this before talking to us (same as the official proxy).
    tx.send(json!({"command": "connected"}).to_string()).await?;

    let legacy = Arc::new(Mutex::new(LegacySession::default()));
    loop {
        let frame = tokio::select! {
            () = cancel.cancelled() => break,
            f = read_frame(&mut rd) => f?,
        };
        let Some(frame) = frame else { break };
        let Ok(msg) = serde_json::from_slice::<Value>(&frame) else {
            continue;
        };
        if msg.get("type").and_then(Value::as_str) == Some("bitwarden-ipc-message") {
            sdk.receive(id, &msg);
            continue;
        }
        // Legacy commands may wait for Touch ID; handle them off the read loop.
        let legacy = legacy.clone();
        let backend = backend.clone();
        let tx = tx.clone();
        let browser = browser.clone();
        tokio::spawn(async move {
            let replies = legacy.lock().await.handle(&*backend, &browser, &msg).await;
            for r in replies {
                let _ = tx.send(r.to_string()).await;
            }
        });
    }
    drop(tx);
    writer.abort();
    Ok(())
}
