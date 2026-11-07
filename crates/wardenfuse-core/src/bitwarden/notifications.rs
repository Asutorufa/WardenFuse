//! Bitwarden push notifications (SignalR hub, JSON protocol over WebSocket).
//!
//! The SDK does not contain a notifications client, so this is a deliberately minimal
//! implementation: it only turns server pushes into "sync now" / "logged out" events. No vault
//! data is received over this channel, it only carries change signals.

use std::time::Duration;

use futures::{SinkExt, StreamExt};
use serde_json::Value;
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::{client::IntoClientRequest, Message};

const RECORD_SEPARATOR: char = '\u{1e}';
const PING_INTERVAL: Duration = Duration::from_secs(15);
const SERVER_TIMEOUT: Duration = Duration::from_secs(45);

/// Push types from `Bitwarden.Core.Enums.PushType` that matter to WardenFuse.
mod push_type {
    pub const SYNC_CIPHER_UPDATE: i64 = 0;
    pub const SYNC_CIPHER_CREATE: i64 = 1;
    pub const SYNC_LOGIN_DELETE: i64 = 2;
    pub const SYNC_CIPHERS: i64 = 4;
    pub const SYNC_VAULT: i64 = 5;
    pub const SYNC_ORG_KEYS: i64 = 6;
    pub const SYNC_CIPHER_DELETE: i64 = 9;
    pub const LOG_OUT: i64 = 11;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PushEvent {
    Connected,
    SyncRequired,
    LoggedOut,
    Disconnected,
}

/// Parses one SignalR frame (without the record separator) into an event.
#[must_use]
pub fn parse_frame(frame: &str) -> Option<PushEvent> {
    let v: Value = serde_json::from_str(frame).ok()?;
    // type 1 = Invocation
    if v.get("type")?.as_i64()? != 1 {
        return None;
    }
    if v.get("target")?.as_str()? != "ReceiveMessage" {
        return None;
    }
    let arg = v.get("arguments")?.as_array()?.first()?;
    let t = arg
        .get("type")
        .or_else(|| arg.get("Type"))
        .and_then(Value::as_i64)?;
    match t {
        push_type::SYNC_CIPHER_UPDATE
        | push_type::SYNC_CIPHER_CREATE
        | push_type::SYNC_LOGIN_DELETE
        | push_type::SYNC_CIPHERS
        | push_type::SYNC_VAULT
        | push_type::SYNC_ORG_KEYS
        | push_type::SYNC_CIPHER_DELETE => Some(PushEvent::SyncRequired),
        push_type::LOG_OUT => Some(PushEvent::LoggedOut),
        _ => None,
    }
}

/// Connects once and forwards events until the connection ends.
pub async fn run_once(
    notifications_url: &str,
    access_token: &str,
    events: &mpsc::Sender<PushEvent>,
) -> anyhow::Result<()> {
    let base = notifications_url
        .replacen("https://", "wss://", 1)
        .replacen("http://", "ws://", 1);
    // The access token must be passed as a query parameter for WebSocket transports
    // (browsers cannot set headers on WebSocket requests and the hub expects it there).
    let url = format!("{base}/hub?access_token={access_token}");
    let mut request = url.into_client_request()?;
    request.headers_mut().insert(
        "User-Agent",
        format!("WardenFuse/{}", env!("CARGO_PKG_VERSION")).parse()?,
    );
    let (mut ws, _) = tokio::time::timeout(
        Duration::from_secs(20),
        tokio_tungstenite::connect_async(request),
    )
    .await??;

    ws.send(Message::text(format!(
        "{{\"protocol\":\"json\",\"version\":1}}{RECORD_SEPARATOR}"
    )))
    .await?;

    let mut handshake_done = false;
    let mut ping = tokio::time::interval(PING_INTERVAL);
    ping.tick().await;
    let mut last_rx = tokio::time::Instant::now();

    loop {
        tokio::select! {
            _ = ping.tick() => {
                if last_rx.elapsed() > SERVER_TIMEOUT {
                    anyhow::bail!("notification server timed out");
                }
                ws.send(Message::text(format!("{{\"type\":6}}{RECORD_SEPARATOR}"))).await?;
            }
            msg = ws.next() => {
                let Some(msg) = msg else { return Ok(()) };
                let msg = msg?;
                last_rx = tokio::time::Instant::now();
                let text = match msg {
                    Message::Text(t) => t.to_string(),
                    Message::Close(_) => return Ok(()),
                    Message::Ping(p) => { ws.send(Message::Pong(p)).await?; continue; }
                    _ => continue,
                };
                for frame in text.split(RECORD_SEPARATOR).filter(|f| !f.is_empty()) {
                    if !handshake_done {
                        // Handshake response: `{}` or `{"error": "..."}`.
                        let v: Value = serde_json::from_str(frame).unwrap_or(Value::Null);
                        if let Some(err) = v.get("error") {
                            anyhow::bail!("notification handshake failed: {err}");
                        }
                        handshake_done = true;
                        let _ = events.send(PushEvent::Connected).await;
                        continue;
                    }
                    let v: Value = serde_json::from_str(frame).unwrap_or(Value::Null);
                    if v.get("type").and_then(Value::as_i64) == Some(7) {
                        // Close message from the server.
                        return Ok(());
                    }
                    if let Some(ev) = parse_frame(frame) {
                        if events.send(ev).await.is_err() {
                            return Ok(());
                        }
                    }
                }
            }
        }
    }
}

/// Reconnect backoff: 5s, 10s, 20s, ... capped at 5 minutes.
#[must_use]
pub fn backoff(attempt: u32) -> Duration {
    let secs = 5u64.saturating_mul(1u64 << attempt.min(6));
    Duration::from_secs(secs.min(300))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_cipher_update() {
        let f = r#"{"type":1,"target":"ReceiveMessage","arguments":[{"contextId":"x","type":0,"payload":{"id":"1"}}]}"#;
        assert_eq!(parse_frame(f), Some(PushEvent::SyncRequired));
        let f = r#"{"type":1,"target":"ReceiveMessage","arguments":[{"ContextId":"x","Type":5,"Payload":{}}]}"#;
        assert_eq!(parse_frame(f), Some(PushEvent::SyncRequired));
    }

    #[test]
    fn parses_logout_and_ignores_others() {
        let f = r#"{"type":1,"target":"ReceiveMessage","arguments":[{"type":11}]}"#;
        assert_eq!(parse_frame(f), Some(PushEvent::LoggedOut));
        let f = r#"{"type":1,"target":"ReceiveMessage","arguments":[{"type":12}]}"#;
        assert_eq!(parse_frame(f), None, "send create is irrelevant");
        assert_eq!(parse_frame(r#"{"type":6}"#), None, "ping");
        assert_eq!(parse_frame("garbage"), None);
    }

    #[test]
    fn backoff_is_capped() {
        assert_eq!(backoff(0), Duration::from_secs(5));
        assert_eq!(backoff(1), Duration::from_secs(10));
        assert_eq!(backoff(20), Duration::from_secs(300));
    }
}
