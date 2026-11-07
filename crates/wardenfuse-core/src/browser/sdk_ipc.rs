//! SDK IPC biometrics endpoint (browser feature flag `biometrics-sdk-ipc`).
//!
//! The browser extension's `DesktopIpcTransport` sends
//! `{type: "bitwarden-ipc-message", message: {destination: "DesktopRenderer", payload, topic}}`
//! over native messaging. We host the `DesktopRenderer` endpoint with the official
//! `bitwarden_ipc::IpcClientImpl` and `NoiseCryptoProvider` (Noise handshake, sessions,
//! fragmentation, RPC framing are all upstream code) and register the same RPC handlers the
//! desktop renderer registers (`DiscoverRequest`, `GetBiometricsStatus`, `UnlockBiometrics`,
//! `AuthenticateBiometrics`). Request/response types mirror
//! `bitwarden-shared-unlock/src/wasm/biometrics.rs` (that module is WASM-only upstream).

use std::{collections::HashMap, sync::Arc};

use bitwarden_core::UserId;
use bitwarden_crypto::SymmetricCryptoKey;
use bitwarden_ipc::{
    discover::{DiscoverHandler, DiscoverResponse},
    CommunicationBackend, CommunicationBackendReceiver, Endpoint, ErrorKind, HostId,
    InMemorySessionRepository, IncomingMessage, IpcClient, IpcClientExt, IpcClientImpl,
    IpcErrorKind, NoiseCryptoProvider, NoiseCryptoProviderState, OutgoingMessage, RpcHandler,
    RpcRequest, RpcRequestInfo, Source,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tokio::sync::{broadcast, mpsc, RwLock};
use zeroize::Zeroizing;

use super::{legacy::LegacyBiometricsStatus, BrowserBackend};

// ---- RPC types (wire compatible with bitwarden-shared-unlock) ----

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum BiometricsStatus {
    Available,
    UnlockNeeded,
    HardwareUnavailable,
    NotEnabled,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetBiometricsStatusRequest {
    pub user_id: UserId,
}
impl RpcRequest for GetBiometricsStatusRequest {
    type Response = BiometricsStatus;
    const NAME: &str = "GetBiometricsStatus";
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnlockBiometricsRequest {
    pub user_id: UserId,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnlockBiometricsResponse {
    pub user_key: Option<SymmetricCryptoKey>,
}
impl RpcRequest for UnlockBiometricsRequest {
    type Response = UnlockBiometricsResponse;
    const NAME: &str = "UnlockBiometrics";
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticateBiometricsRequest;
impl RpcRequest for AuthenticateBiometricsRequest {
    type Response = bool;
    const NAME: &str = "AuthenticateBiometrics";
}

// ---- Communication backend over our NMH connections ----

/// Outgoing frames per connection id.
pub type ConnectionMap = Arc<RwLock<HashMap<i32, (mpsc::Sender<String>, String)>>>;

#[derive(Debug, thiserror::Error)]
#[error("destination unreachable")]
pub struct Unreachable;

impl IpcErrorKind for Unreachable {
    fn kind(&self) -> ErrorKind {
        ErrorKind::Unreachable
    }
}

#[derive(Debug, thiserror::Error)]
#[error("receive channel closed")]
pub struct Closed;

impl IpcErrorKind for Closed {
    fn kind(&self) -> ErrorKind {
        ErrorKind::Fatal
    }
}

#[derive(Clone)]
pub struct NmhBackend {
    connections: ConnectionMap,
    incoming: broadcast::Sender<IncomingMessage>,
}

pub struct NmhReceiver(tokio::sync::Mutex<broadcast::Receiver<IncomingMessage>>);

impl CommunicationBackend for NmhBackend {
    type SendError = Unreachable;
    type Receiver = NmhReceiver;

    async fn send(&self, message: OutgoingMessage) -> Result<(), Self::SendError> {
        let Endpoint::BrowserBackground {
            id: HostId::Id(conn),
        } = message.destination
        else {
            return Err(Unreachable);
        };
        let frame = json!({
            "type": "forwarded-bitwarden-ipc-message",
            "message": {
                "destination": message.destination,
                "payload": message.payload,
                "topic": message.topic,
            },
            "originalSource": "DesktopRenderer",
        })
        .to_string();
        let tx = self
            .connections
            .read()
            .await
            .get(&conn)
            .map(|(tx, _)| tx.clone())
            .ok_or(Unreachable)?;
        tx.send(frame).await.map_err(|_| Unreachable)
    }

    async fn subscribe(&self) -> Self::Receiver {
        NmhReceiver(tokio::sync::Mutex::new(self.incoming.subscribe()))
    }
}

impl CommunicationBackendReceiver for NmhReceiver {
    type ReceiveError = Closed;

    async fn receive(&self) -> Result<IncomingMessage, Self::ReceiveError> {
        let mut rx = self.0.lock().await;
        loop {
            match rx.recv().await {
                Ok(m) => return Ok(m),
                Err(broadcast::error::RecvError::Lagged(_)) => continue,
                Err(broadcast::error::RecvError::Closed) => return Err(Closed),
            }
        }
    }
}

type Client = IpcClientImpl<
    NoiseCryptoProvider,
    NmhBackend,
    InMemorySessionRepository<NoiseCryptoProviderState>,
>;

fn browser_of(conns: &HashMap<i32, (mpsc::Sender<String>, String)>, src: &Source) -> String {
    match src {
        Source::BrowserBackground { id: HostId::Id(n) } => conns
            .get(n)
            .map(|(_, b)| b.clone())
            .unwrap_or_else(|| "your browser".into()),
        _ => "your browser".into(),
    }
}

fn is_browser(src: &Source) -> bool {
    matches!(src, Source::BrowserBackground { id: HostId::Id(_) })
}

struct StatusHandler<B: ?Sized>(Arc<B>);
impl<B: BrowserBackend + ?Sized> RpcHandler for StatusHandler<B> {
    type Request = GetBiometricsStatusRequest;
    async fn handle(&self, req: Self::Request, info: RpcRequestInfo) -> BiometricsStatus {
        if !is_browser(&info.source) {
            return BiometricsStatus::NotEnabled;
        }
        match self
            .0
            .biometrics_status(Some(&req.user_id.to_string()))
            .await
        {
            LegacyBiometricsStatus::Available => BiometricsStatus::Available,
            LegacyBiometricsStatus::UnlockNeeded => BiometricsStatus::UnlockNeeded,
            LegacyBiometricsStatus::HardwareUnavailable
            | LegacyBiometricsStatus::PlatformUnsupported => BiometricsStatus::HardwareUnavailable,
            LegacyBiometricsStatus::NotEnabledInConnectedDesktopApp => BiometricsStatus::NotEnabled,
        }
    }
}

struct UnlockHandler<B: ?Sized>(Arc<B>, ConnectionMap);
impl<B: BrowserBackend + ?Sized> RpcHandler for UnlockHandler<B> {
    type Request = UnlockBiometricsRequest;
    async fn handle(&self, req: Self::Request, info: RpcRequestInfo) -> UnlockBiometricsResponse {
        if !is_browser(&info.source) {
            return UnlockBiometricsResponse { user_key: None };
        }
        let browser = browser_of(&*self.1.read().await, &info.source);
        let key: Option<Zeroizing<String>> = self
            .0
            .unlock_user_key(&req.user_id.to_string(), &browser)
            .await;
        UnlockBiometricsResponse {
            user_key: key.and_then(|k| SymmetricCryptoKey::try_from(k.as_str().to_owned()).ok()),
        }
    }
}

struct VerifyHandler<B: ?Sized>(Arc<B>, ConnectionMap);
impl<B: BrowserBackend + ?Sized> RpcHandler for VerifyHandler<B> {
    type Request = AuthenticateBiometricsRequest;
    async fn handle(&self, _req: Self::Request, info: RpcRequestInfo) -> bool {
        if !is_browser(&info.source) {
            return false;
        }
        let browser = browser_of(&*self.1.read().await, &info.source);
        self.0.verify_user(&browser).await
    }
}

/// The running SDK IPC endpoint.
pub struct SdkIpc {
    _client: Arc<Client>,
    incoming: broadcast::Sender<IncomingMessage>,
    cancel: tokio_util::sync::CancellationToken,
}

impl SdkIpc {
    pub async fn start<B: BrowserBackend + ?Sized + 'static>(
        backend: Arc<B>,
        connections: ConnectionMap,
    ) -> anyhow::Result<Self> {
        let (incoming, _) = broadcast::channel(64);
        let com = NmhBackend {
            connections: connections.clone(),
            incoming: incoming.clone(),
        };
        let client: Arc<Client> = Arc::new(IpcClientImpl::new(
            NoiseCryptoProvider::new(),
            com,
            InMemorySessionRepository::default(),
        ));
        client
            .register_rpc_handler(DiscoverHandler::new(DiscoverResponse {
                version: env!("CARGO_PKG_VERSION").to_owned(),
            }))
            .await;
        client
            .register_rpc_handler(StatusHandler(backend.clone()))
            .await;
        client
            .register_rpc_handler(UnlockHandler(backend.clone(), connections.clone()))
            .await;
        client
            .register_rpc_handler(VerifyHandler(backend, connections))
            .await;
        let cancel = tokio_util::sync::CancellationToken::new();
        client
            .start(Some(cancel.clone()))
            .await
            .map_err(|_| anyhow::anyhow!("IPC client already running"))?;
        Ok(Self {
            _client: client,
            incoming,
            cancel,
        })
    }

    /// Feeds a `bitwarden-ipc-message` from connection `conn` into the IPC client.
    pub fn receive(&self, conn: i32, msg: &Value) {
        let m = &msg["message"];
        let Ok(destination) = serde_json::from_value::<Endpoint>(m["destination"].clone()) else {
            return;
        };
        if destination != Endpoint::DesktopRenderer {
            // DesktopMain-only services are not provided by WardenFuse.
            return;
        }
        let Some(payload) = m["payload"].as_array().map(|a| {
            a.iter()
                .filter_map(|b| b.as_u64().and_then(|b| u8::try_from(b).ok()))
                .collect::<Vec<u8>>()
        }) else {
            return;
        };
        let topic = m["topic"].as_str().map(str::to_owned);
        let _ = self.incoming.send(IncomingMessage {
            payload,
            destination,
            source: Source::BrowserBackground {
                id: HostId::Id(conn),
            },
            topic,
        });
    }

    pub fn stop(&self) {
        self.cancel.cancel();
    }
}
