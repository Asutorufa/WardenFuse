//! Interface to the native (Swift) layer: Keychain and LocalAuthentication.
//!
//! Swift evaluates an `LAContext` for native authentication, then passes it to the
//! user-presence Keychain read. The Android browser backend unseals a separate envelope in Rust.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

/// What the user is being asked to authorize. Rendered by the native authentication UI.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum AuthPurpose {
    /// An SSH signature.
    SshSign {
        key_name: String,
        key_fingerprint: String,
        /// Verified executable name from the kernel, if any.
        process_name: Option<String>,
        process_path: Option<String>,
        process_id: Option<u32>,
        /// "git" / "file" when the SSHSIG namespace was parsed, "ssh" for authentication.
        usage: String,
        /// Remote host key fingerprint from `session-bind@openssh.com`, if provided.
        host_key_fingerprint: Option<String>,
        forwarded: bool,
        /// Seconds the authorization will be cached for (0 = this request only).
        ttl_secs: u64,
    },
    /// Listing SSH public keys while the agent has no decrypted key list yet.
    SshList,
    /// Explicit "Unlock Agent" from the menu.
    AgentUnlock { ttl_secs: u64 },
    /// The official Bitwarden browser extension asks to unlock its vault.
    BrowserUnlock { browser: String },
    /// The browser extension asks for a plain user verification.
    BrowserVerify { browser: String },
    /// Enroll an Android key using the existing Mac authentication policy.
    AndroidEnrollment,
}

impl AuthPurpose {
    /// The localized reason string passed to `LAContext` (shown by the system dialog).
    #[must_use]
    pub fn reason(&self) -> String {
        match self {
            Self::SshSign {
                key_name,
                process_name,
                usage,
                ..
            } => {
                let what = match usage.as_str() {
                    "git" => "sign a Git object",
                    "file" => "sign a file",
                    _ => "authenticate over SSH",
                };
                match process_name {
                    Some(p) => format!("use SSH key \u{201c}{key_name}\u{201d} for {p} to {what}"),
                    None => format!("use SSH key \u{201c}{key_name}\u{201d} to {what}"),
                }
            }
            Self::SshList => "list the SSH keys in your Bitwarden vault".to_owned(),
            Self::AgentUnlock { .. } => "unlock the WardenFuse SSH agent".to_owned(),
            Self::BrowserUnlock { browser } => {
                format!("unlock Bitwarden in {browser}")
            }
            Self::BrowserVerify { browser } => format!("verify your identity for {browser}"),
            Self::AndroidEnrollment => {
                "pair an Android device for Bitwarden browser unlock".to_owned()
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthRequest {
    pub purpose: AuthPurpose,
    pub reason: String,
    /// Bitwarden user id whose Keychain item must be read.
    pub user_id: String,
    pub allow_biometrics: bool,
    pub allow_password: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthFailure {
    #[error("authentication was cancelled")]
    Cancelled,
    #[error("authentication failed")]
    Failed,
    #[error("authentication timed out")]
    Timeout,
    #[error("no authentication method is available")]
    Unavailable,
    #[error("the protected key is missing from the Keychain")]
    KeyMissing,
    #[error("the authentication UI could not be shown")]
    UiUnavailable,
}

/// Biometric hardware state as reported by LocalAuthentication.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BiometryState {
    Available,
    NotEnrolled,
    Unavailable,
}

#[async_trait]
pub trait Platform: Send + Sync + 'static {
    /// Authenticate the user and return the protected user key from the Keychain.
    async fn authenticate(&self, request: AuthRequest) -> Result<Zeroizing<Vec<u8>>, AuthFailure>;

    /// Store the user key in a user-presence protected Keychain item.
    fn store_user_key(&self, user_id: &str, key: &[u8]) -> anyhow::Result<()>;
    fn delete_user_key(&self, user_id: &str);

    /// Store the session blob (refresh token, login method) in a Keychain item that does not
    /// require user presence (needed for background sync), `WhenUnlockedThisDeviceOnly`.
    fn store_session(&self, data: &[u8]) -> anyhow::Result<()>;
    fn load_session(&self) -> Option<Zeroizing<Vec<u8>>>;
    fn delete_session(&self);

    /// TLS identity for the optional Android listener. This item contains no vault key.
    fn load_android_identity(&self) -> anyhow::Result<Option<Zeroizing<Vec<u8>>>> {
        anyhow::bail!("Android TLS identity storage unavailable")
    }

    fn store_android_identity(&self, _data: &[u8]) -> anyhow::Result<()> {
        anyhow::bail!("Android TLS identity storage unavailable")
    }

    fn delete_android_identity(&self) {}

    fn biometry_state(&self) -> BiometryState;

    /// Push a new state snapshot (JSON) to the UI. Must not block.
    fn state_changed(&self, snapshot_json: String);
}
