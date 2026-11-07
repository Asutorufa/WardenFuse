//! Bitwarden account session built on the official SDK.
//!
//! * Login: `bitwarden_core::Client::auth().login_password()` / `login_api_key()` /
//!   `send_two_factor_email()` (KDF, master password hash, 2FA protocol and user key
//!   decryption are all done by the SDK).
//! * Tokens: `bitwarden_auth::token_management::PasswordManagerTokenHandler` (refresh handled by
//!   the SDK middleware) over an in-memory `StateRegistry`.
//! * Sync: one long-lived `bitwarden_sync::SyncClient` with a single SSH-only `SyncHandler`.
//!
//! The long-lived client never has user crypto initialized: login happens on a short-lived
//! client whose key store is dropped right after the user key has been handed to the Keychain.

pub mod notifications;

use std::sync::{Arc, Mutex};

use anyhow::{anyhow, Result};
use bitwarden_api_api::models::SyncResponseModel;
use bitwarden_auth::token_management::PasswordManagerTokenHandler;
use bitwarden_core::{
    auth::login::{
        ApiKeyLoginRequest, LoginError, PasswordLoginRequest, TwoFactorEmailRequest,
        TwoFactorProvider, TwoFactorRequest,
    },
    client::{
        login_method::UserLoginMethod,
        persisted_state::{AuthenticationTokens, AUTHENTICATION_TOKENS, USER_LOGIN_METHOD},
    },
    Client, ClientSettings, DeviceType,
};
use bitwarden_state::registry::StateRegistry;
use bitwarden_sync::{SyncClient, SyncHandler, SyncHandlerError, SyncRequest};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::{config::ServerUrls, vault::EncryptedVault};

/// Client version reported to the server. The server only returns SSH key items to clients
/// that announce support for them, so this must track a recent official release.
pub const BITWARDEN_CLIENT_VERSION: &str = "2026.10.0";

/// What is persisted (Keychain, no user presence) to resume background sync after restart.
#[derive(Serialize, Deserialize)]
pub struct SessionBlob {
    pub server_url: String,
    pub user_id: String,
    pub email: String,
    pub login_method: UserLoginMethod,
    pub tokens: AuthenticationTokens,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TwoFactorMethod {
    Authenticator,
    Email,
    Yubikey,
}

impl TwoFactorMethod {
    fn provider(&self) -> TwoFactorProvider {
        match self {
            Self::Authenticator => TwoFactorProvider::Authenticator,
            Self::Email => TwoFactorProvider::Email,
            Self::Yubikey => TwoFactorProvider::Yubikey,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct TwoFactorInput {
    pub method: TwoFactorMethod,
    pub code: String,
    #[serde(default)]
    pub remember: bool,
}

pub enum LoginCredentials {
    Password {
        email: String,
        password: Zeroizing<String>,
        two_factor: Option<TwoFactorInput>,
    },
    ApiKey {
        client_id: String,
        client_secret: Zeroizing<String>,
        password: Zeroizing<String>,
    },
}

/// Successful login: a session plus the user key (base64) to be stored in the Keychain.
pub struct LoggedIn {
    pub session: BitwardenSession,
    pub user_key_b64: Zeroizing<String>,
    pub vault: EncryptedVault,
}

pub enum LoginOutcome {
    Success(Box<LoggedIn>),
    /// Second factor needed. Lists the methods WardenFuse can complete.
    TwoFactorRequired {
        methods: Vec<TwoFactorMethod>,
        unsupported: Vec<String>,
    },
}

#[derive(Debug, thiserror::Error)]
pub enum BwError {
    #[error("Invalid email, master password or two-step login code")]
    InvalidCredentials,
    #[error(
        "Bitwarden requires new device verification for this account. Enable two-step login, or \
         sign in with your personal API key (Settings → Bitwarden → Use API key)."
    )]
    NewDeviceVerification,
    #[error("Your session expired. Please log in again.")]
    SessionExpired,
    #[error("Network error: {0}")]
    Network(String),
    #[error("{0}")]
    Other(String),
}

fn classify_login_error(e: &LoginError) -> BwError {
    match e {
        LoginError::IdentityFail(f) => {
            let msg = format!(
                "{} {} {}",
                f.error, f.error_description, f.error_model.message
            )
            .to_lowercase();
            if msg.contains("new device") {
                BwError::NewDeviceVerification
            } else if msg.contains("invalid_grant") || msg.contains("username or password") {
                BwError::InvalidCredentials
            } else {
                BwError::Other(f.to_string())
            }
        }
        LoginError::Api(api) => BwError::Network(api.to_string()),
        other => BwError::Other(other.to_string()),
    }
}

fn client_settings(urls: &ServerUrls) -> ClientSettings {
    ClientSettings {
        identity_url: urls.identity.clone(),
        api_url: urls.api.clone(),
        user_agent: format!("WardenFuse/{} (macOS)", env!("CARGO_PKG_VERSION")),
        device_type: DeviceType::MacOsDesktop,
        device_identifier: None,
        bitwarden_client_version: Some(BITWARDEN_CLIENT_VERSION.to_owned()),
        bitwarden_package_type: None,
    }
}

fn build_client(urls: &ServerUrls, registry: StateRegistry) -> Client {
    Client::builder()
        .with_settings(client_settings(urls))
        .with_state(registry)
        .with_token_handler(Arc::new(PasswordManagerTokenHandler::default()))
        .build()
}

/// Collects SSH key ciphers from each sync.
struct SshSyncHandler {
    latest: Arc<Mutex<Option<EncryptedVault>>>,
}

#[async_trait::async_trait]
impl SyncHandler for SshSyncHandler {
    async fn on_sync(&self, response: &SyncResponseModel) -> Result<(), SyncHandlerError> {
        let v = EncryptedVault::from_sync(response, chrono::Utc::now().timestamp())
            .map_err(|e| -> SyncHandlerError { e.to_string().into() })?;
        *self
            .latest
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(v);
        Ok(())
    }
}

/// A logged-in account without decrypted key material.
pub struct BitwardenSession {
    pub server_url: String,
    pub urls: ServerUrls,
    pub user_id: String,
    pub email: String,
    client: Client,
    sync: SyncClient,
    latest: Arc<Mutex<Option<EncryptedVault>>>,
}

impl BitwardenSession {
    fn new(server_url: &str, registry: StateRegistry, user_id: String, email: String) -> Self {
        let urls = ServerUrls::from_server(server_url);
        let client = build_client(&urls, registry);
        let sync = SyncClient::new(client.clone());
        let latest = Arc::new(Mutex::new(None));
        sync.register_sync_handler(Arc::new(SshSyncHandler {
            latest: latest.clone(),
        }));
        Self {
            server_url: server_url.to_owned(),
            urls,
            user_id,
            email,
            client,
            sync,
            latest,
        }
    }

    fn state(&self) -> bitwarden_core::platform::StateClient {
        self.client.platform().state()
    }

    async fn seeded_registry(
        tokens: AuthenticationTokens,
        login_method: UserLoginMethod,
    ) -> Result<StateRegistry> {
        let registry = StateRegistry::new_with_memory_db();
        registry
            .setting(AUTHENTICATION_TOKENS)
            .map_err(|e| anyhow!("{e}"))?
            .update(tokens)
            .await
            .map_err(|e| anyhow!("{e}"))?;
        registry
            .setting(USER_LOGIN_METHOD)
            .map_err(|e| anyhow!("{e}"))?
            .update(login_method)
            .await
            .map_err(|e| anyhow!("{e}"))?;
        Ok(registry)
    }

    /// Logs in with the official SDK flow.
    pub async fn login(server_url: &str, creds: LoginCredentials) -> Result<LoginOutcome, BwError> {
        let urls = ServerUrls::from_server(server_url);
        let client = build_client(&urls, StateRegistry::new_with_memory_db());

        match &creds {
            LoginCredentials::Password {
                email,
                password,
                two_factor,
            } => {
                if let Some(tf) = two_factor {
                    if tf.code.trim().is_empty() && tf.method == TwoFactorMethod::Email {
                        // Empty code with the email method = "send me the code".
                        client
                            .auth()
                            .send_two_factor_email(&TwoFactorEmailRequest {
                                password: password.to_string(),
                                email: email.clone(),
                            })
                            .await
                            .map_err(|e| BwError::Other(e.to_string()))?;
                        return Ok(LoginOutcome::TwoFactorRequired {
                            methods: vec![TwoFactorMethod::Email],
                            unsupported: vec![],
                        });
                    }
                }
                let resp = client
                    .auth()
                    .login_password(&PasswordLoginRequest {
                        email: email.clone(),
                        password: password.to_string(),
                        two_factor: two_factor.as_ref().map(|t| TwoFactorRequest {
                            token: t.code.trim().to_owned(),
                            provider: t.method.provider(),
                            remember: t.remember,
                        }),
                    })
                    .await
                    .map_err(|e| classify_login_error(&e))?;
                if let Some(tf) = resp.two_factor {
                    let mut methods = Vec::new();
                    let mut unsupported = Vec::new();
                    if tf.authenticator.is_some() {
                        methods.push(TwoFactorMethod::Authenticator);
                    }
                    if tf.email.is_some() {
                        methods.push(TwoFactorMethod::Email);
                    }
                    if tf.yubi_key.is_some() {
                        methods.push(TwoFactorMethod::Yubikey);
                    }
                    if tf.web_authn.is_some() {
                        unsupported.push("passkey / security key (WebAuthn)".to_owned());
                    }
                    if tf.duo.is_some() || tf.organization_duo.is_some() {
                        unsupported.push("Duo".to_owned());
                    }
                    return Ok(LoginOutcome::TwoFactorRequired {
                        methods,
                        unsupported,
                    });
                }
                if !resp.authenticated {
                    return Err(BwError::InvalidCredentials);
                }
            }
            LoginCredentials::ApiKey {
                client_id,
                client_secret,
                password,
            } => {
                let resp = client
                    .auth()
                    .login_api_key(&ApiKeyLoginRequest {
                        client_id: client_id.clone(),
                        client_secret: client_secret.to_string(),
                        password: password.to_string(),
                    })
                    .await
                    .map_err(|e| classify_login_error(&e))?;
                if !resp.authenticated {
                    return Err(BwError::InvalidCredentials);
                }
            }
        }

        // The SDK has decrypted the user key with the master password. Take it out once, for
        // the Keychain, then drop this client (and with it the SDK key store).
        let user_key_b64 = Zeroizing::new(
            client
                .crypto()
                .get_user_encryption_key()
                .await
                .map_err(|e| BwError::Other(format!("unable to unlock vault: {e}")))?
                .to_string(),
        );
        let state = client.platform().state();
        let tokens = state
            .setting(AUTHENTICATION_TOKENS)
            .ok()
            .map(|s| async move { s.get().await.ok().flatten() });
        let tokens = match tokens {
            Some(f) => f.await,
            None => None,
        }
        .ok_or_else(|| BwError::Other("login did not return tokens".into()))?;
        let method = state
            .setting(USER_LOGIN_METHOD)
            .ok()
            .map(|s| async move { s.get().await.ok().flatten() });
        let method = match method {
            Some(f) => f.await,
            None => None,
        }
        .ok_or_else(|| BwError::Other("login did not return a login method".into()))?;
        drop(state);
        // Drop the login client: its SDK key store held the decrypted user key.
        drop(client);

        // Long-lived session client without crypto.
        let registry = Self::seeded_registry(tokens, method)
            .await
            .map_err(|e| BwError::Other(e.to_string()))?;
        let mut session = Self::new(server_url, registry, String::new(), String::new());
        let vault = session
            .sync_now(true)
            .await?
            .ok_or_else(|| BwError::Other("initial sync returned no data".into()))?;
        session.user_id = vault.user_id.clone();
        session.email = vault.email.clone();
        Ok(LoginOutcome::Success(Box::new(LoggedIn {
            session,
            user_key_b64,
            vault,
        })))
    }

    /// Restores a session from the Keychain session blob.
    pub async fn restore(blob: &[u8]) -> Result<Self> {
        let blob: SessionBlob = serde_json::from_slice(blob)?;
        let registry = Self::seeded_registry(blob.tokens, blob.login_method).await?;
        Ok(Self::new(
            &blob.server_url,
            registry,
            blob.user_id,
            blob.email,
        ))
    }

    /// Serializes the current tokens + login method for the Keychain.
    pub async fn session_blob(&self) -> Result<Zeroizing<Vec<u8>>> {
        let tokens = self
            .state()
            .setting(AUTHENTICATION_TOKENS)
            .map_err(|e| anyhow!("{e}"))?
            .get()
            .await
            .map_err(|e| anyhow!("{e}"))?
            .ok_or_else(|| anyhow!("not authenticated"))?;
        let login_method = self
            .state()
            .setting(USER_LOGIN_METHOD)
            .map_err(|e| anyhow!("{e}"))?
            .get()
            .await
            .map_err(|e| anyhow!("{e}"))?
            .ok_or_else(|| anyhow!("not authenticated"))?;
        Ok(Zeroizing::new(serde_json::to_vec(&SessionBlob {
            server_url: self.server_url.clone(),
            user_id: self.user_id.clone(),
            email: self.email.clone(),
            login_method,
            tokens,
        })?))
    }

    /// Current access token (refreshed by the SDK middleware during API calls).
    pub async fn access_token(&self) -> Option<Zeroizing<String>> {
        self.state()
            .setting(AUTHENTICATION_TOKENS)
            .ok()?
            .get()
            .await
            .ok()
            .flatten()
            .map(|t| Zeroizing::new(t.access_token))
    }

    /// Runs the SDK sync. With `force = false` the SDK first compares the account revision date
    /// and skips the full sync if nothing changed. Returns new vault data if a sync happened.
    pub async fn sync_now(&self, force: bool) -> Result<Option<EncryptedVault>, BwError> {
        let synced = self
            .sync
            .sync(SyncRequest {
                force,
                exclude_subdomains: Some(true),
            })
            .await
            .map_err(|e| {
                let s = e.to_string();
                let l = s.to_lowercase();
                if l.contains("401")
                    || l.contains("invalid_grant")
                    || l.contains("not authenticated")
                    || l.contains("account has been deleted")
                {
                    BwError::SessionExpired
                } else {
                    BwError::Network(s)
                }
            })?;
        if !synced {
            return Ok(None);
        }
        Ok(self
            .latest
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take())
    }
}
