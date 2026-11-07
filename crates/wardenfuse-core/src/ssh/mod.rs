//! SSH agent integration: the vendored upstream Bitwarden agent with WardenFuse's gated key
//! store and approver.

pub mod approval;
pub mod keystore;

use std::{path::PathBuf, sync::Arc};

use anyhow::Result;
use ssh_agent::BitwardenSSHAgent;

pub use self::{
    approval::{UnlockTarget, Unlocker, WardenFuseApprover},
    keystore::{parse_public_key, GatedKeyStore, MetaKeyData},
};

/// Owns the running upstream agent server.
pub struct SshAgentService<U: Unlocker> {
    agent: BitwardenSSHAgent<GatedKeyStore, WardenFuseApprover<U>>,
    socket: Option<PathBuf>,
}

impl<U: Unlocker> SshAgentService<U> {
    pub fn new(store: GatedKeyStore, unlocker: Arc<U>) -> Self {
        let approver = WardenFuseApprover::new(store.clone(), unlocker);
        Self {
            agent: BitwardenSSHAgent::new(store, approver),
            socket: None,
        }
    }

    /// Starts listening on `path`. Must be called from within the Tokio runtime.
    pub fn start(&mut self, path: PathBuf) -> Result<()> {
        if self.agent.is_running() {
            if self.socket.as_ref() == Some(&path) {
                return Ok(());
            }
            self.stop();
        }
        self.agent.start_at(&path)?;
        self.socket = Some(path);
        Ok(())
    }

    /// Stops the server and removes our socket file. Key material is managed by the store.
    pub fn stop(&mut self) {
        if self.agent.is_running() {
            self.agent.stop_server();
        }
        if let Some(p) = self.socket.take() {
            use std::os::unix::fs::FileTypeExt;
            if std::fs::symlink_metadata(&p).is_ok_and(|m| m.file_type().is_socket()) {
                let _ = std::fs::remove_file(&p);
            }
        }
    }

    #[must_use]
    pub fn is_running(&self) -> bool {
        self.agent.is_running()
    }

    #[must_use]
    pub fn socket(&self) -> Option<&PathBuf> {
        self.socket.as_ref()
    }
}
