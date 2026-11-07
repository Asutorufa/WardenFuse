//! The WardenFuse core service: owns the account session, vault cache, SSH agent, browser
//! bridge and authorization state. Everything security relevant is decided here.

use std::{
    path::PathBuf,
    sync::{Arc, Mutex, MutexGuard, Weak},
    time::Duration,
};

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use serde::Deserialize;
use serde_json::{json, Value};
use ssh_agent::SSHKeyData;
use tokio::sync::{Notify, RwLock};
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;

use crate::{
    authz::{Authorizations, Scope},
    bitwarden::{
        notifications::{self, PushEvent},
        BitwardenSession, BwError, LoginCredentials, LoginOutcome, TwoFactorInput,
    },
    browser::{manifest::Manifests, BrowserBackend, BrowserBridge, LegacyBiometricsStatus},
    clock::{Clock, SystemClock},
    config::{self, ConfigStore, Settings},
    platform::{AuthFailure, AuthPurpose, AuthRequest, BiometryState, Platform},
    ssh::{parse_public_key, GatedKeyStore, MetaKeyData, SshAgentService, UnlockTarget, Unlocker},
    ssh_config,
    vault::{EncryptedVault, VaultCache, VaultDecryptor},
};

const AUTH_TIMEOUT: Duration = Duration::from_secs(90);

/// Startup configuration from the app.
#[derive(Debug, Clone, Deserialize)]
pub struct CoreConfig {
    /// `~/Library/Application Support/WardenFuse`
    pub data_dir: PathBuf,
    /// Bundled NMH executable, `Contents/MacOS/wardenfuse-nmh`.
    pub nmh_path: PathBuf,
    /// Whether Keychain items are protected by `SecAccessControl` (Team-ID signed build) or
    /// stored in the legacy keychain (ad-hoc signed build). Display/diagnostics only.
    #[serde(default)]
    pub keychain_mode: String,
}

#[derive(Debug, Clone, Default, serde::Serialize)]
struct LoginState {
    stage: &'static str,
    methods: Vec<crate::bitwarden::TwoFactorMethod>,
    unsupported: Vec<String>,
    error: Option<String>,
}

#[derive(Debug, Clone, Default)]
struct Status {
    login: LoginState,
    syncing: bool,
    sync_error: Option<String>,
    last_sync_ok: Option<i64>,
    session_expired: bool,
    notifications_connected: bool,
    ssh_error: Option<String>,
    browser_error: Option<String>,
    pending_keys: usize,
    undecryptable_keys: usize,
    last_lock_reason: Option<String>,
}

pub struct CoreInner {
    cfg: CoreConfig,
    platform: Arc<dyn Platform>,
    clock: Arc<dyn Clock>,
    config_store: ConfigStore,
    settings: Mutex<Settings>,
    status: Mutex<Status>,
    session: RwLock<Option<Arc<BitwardenSession>>>,
    vault: Mutex<Option<Arc<EncryptedVault>>>,
    cache: VaultCache,
    store: GatedKeyStore,
    agent: Mutex<Option<SshAgentService<UnlockerHandle>>>,
    bridge: tokio::sync::Mutex<Option<BrowserBridge>>,
    auth_lock: tokio::sync::Mutex<()>,
    sync_lock: tokio::sync::Mutex<()>,
    state_dirty: Notify,
    grants_dirty: Notify,
    sync_wake: Notify,
    account_tasks: Mutex<Option<CancellationToken>>,
    shutdown: CancellationToken,
    manifests: Manifests,
    self_ref: Mutex<Weak<CoreInner>>,
    /// Exclusive instance lock (held for the lifetime of the process).
    _instance_lock: std::fs::File,
}

/// Prevents two cores from running at once (they would fight over the sockets).
fn acquire_instance_lock(data_dir: &std::path::Path) -> Result<std::fs::File> {
    use std::os::unix::{fs::OpenOptionsExt, io::AsRawFd};
    let f = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .mode(0o600)
        .open(data_dir.join("instance.lock"))?;
    // SAFETY: valid fd; LOCK_NB makes this non-blocking.
    let rc = unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    if rc != 0 {
        return Err(anyhow!("WardenFuse is already running"));
    }
    Ok(f)
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Weak handle given to the SSH approver and the browser bridge, avoiding reference cycles.
#[derive(Clone)]
pub struct UnlockerHandle(Weak<CoreInner>);

impl UnlockerHandle {
    fn core(&self) -> Option<Arc<CoreInner>> {
        self.0.upgrade()
    }
}

#[async_trait]
impl Unlocker for UnlockerHandle {
    async fn unlock(&self, purpose: AuthPurpose, target: UnlockTarget) -> Result<(), AuthFailure> {
        let core = self.core().ok_or(AuthFailure::Unavailable)?;
        core.authenticate_and_decrypt(purpose, target).await
    }

    fn grants_changed(&self) {
        if let Some(c) = self.core() {
            c.grants_dirty.notify_one();
            c.state_dirty.notify_one();
        }
    }

    fn allow_forwarding(&self) -> bool {
        self.core()
            .is_some_and(|c| lock(&c.settings).allow_agent_forwarding)
    }

    fn ttl_secs(&self) -> u64 {
        self.core().map_or(0, |c| {
            let s = lock(&c.settings);
            if s.ssh_approval_policy == crate::authz::ApprovalPolicy::EveryTime {
                0
            } else {
                s.ssh_ttl_secs
            }
        })
    }
}

#[async_trait]
impl BrowserBackend for UnlockerHandle {
    async fn logged_in_user(&self) -> Option<String> {
        let core = self.core()?;
        if !lock(&core.settings).browser_unlock_enabled {
            return None;
        }
        let id = core
            .session
            .read()
            .await
            .as_ref()
            .map(|s| s.user_id.clone());
        id
    }

    async fn biometrics_status(&self, user_id: Option<&str>) -> LegacyBiometricsStatus {
        let Some(core) = self.core() else {
            return LegacyBiometricsStatus::NotEnabledInConnectedDesktopApp;
        };
        let current = self.logged_in_user().await;
        let Some(current) = current else {
            return LegacyBiometricsStatus::NotEnabledInConnectedDesktopApp;
        };
        if user_id.is_some_and(|u| u != current) {
            return LegacyBiometricsStatus::NotEnabledInConnectedDesktopApp;
        }
        let allow_password = lock(&core.settings).allow_password_fallback;
        match core.platform.biometry_state() {
            BiometryState::Available => LegacyBiometricsStatus::Available,
            _ if allow_password => LegacyBiometricsStatus::Available,
            _ => LegacyBiometricsStatus::HardwareUnavailable,
        }
    }

    async fn unlock_user_key(&self, user_id: &str, browser: &str) -> Option<Zeroizing<String>> {
        let core = self.core()?;
        if self.logged_in_user().await.as_deref() != Some(user_id) {
            return None;
        }
        // Always a fresh authentication: never derived from the SSH TTL.
        let key = core
            .authenticate(AuthPurpose::BrowserUnlock {
                browser: browser.to_owned(),
            })
            .await
            .ok()?;
        let s = Zeroizing::new(std::str::from_utf8(&key).ok()?.to_owned());
        Some(s)
    }

    async fn verify_user(&self, browser: &str) -> bool {
        let Some(core) = self.core() else {
            return false;
        };
        if self.logged_in_user().await.is_none() {
            return false;
        }
        core.authenticate(AuthPurpose::BrowserVerify {
            browser: browser.to_owned(),
        })
        .await
        .is_ok()
    }
}

#[derive(Clone)]
pub struct Core(Arc<CoreInner>);

impl Core {
    /// Creates the core and starts background tasks. Must be called inside the runtime.
    pub async fn start(cfg: CoreConfig, platform: Arc<dyn Platform>) -> Result<Self> {
        Self::start_with_clock(cfg, platform, Arc::new(SystemClock)).await
    }

    pub async fn start_with_clock(
        cfg: CoreConfig,
        platform: Arc<dyn Platform>,
        clock: Arc<dyn Clock>,
    ) -> Result<Self> {
        config::ensure_private_dir(&cfg.data_dir)?;
        let instance_lock = acquire_instance_lock(&cfg.data_dir)?;
        let config_store = ConfigStore::new(&cfg.data_dir);
        let settings = config_store.load();
        let authz = Authorizations::new(
            clock.clone(),
            settings.ssh_ttl(),
            settings.ssh_approval_policy,
            settings.ssh_scope_mode,
        );
        let store = GatedKeyStore::new(Arc::new(Mutex::new(authz)));
        store.set_list_when_locked(settings.list_keys_when_locked);
        let inner = Arc::new(CoreInner {
            cache: VaultCache::new(&cfg.data_dir),
            manifests: Manifests::new(cfg.nmh_path.clone()),
            cfg,
            platform,
            clock,
            config_store,
            settings: Mutex::new(settings),
            status: Mutex::new(Status::default()),
            session: RwLock::new(None),
            vault: Mutex::new(None),
            store,
            agent: Mutex::new(None),
            bridge: tokio::sync::Mutex::new(None),
            auth_lock: tokio::sync::Mutex::new(()),
            sync_lock: tokio::sync::Mutex::new(()),
            state_dirty: Notify::new(),
            grants_dirty: Notify::new(),
            sync_wake: Notify::new(),
            account_tasks: Mutex::new(None),
            shutdown: CancellationToken::new(),
            self_ref: Mutex::new(Weak::new()),
            _instance_lock: instance_lock,
        });
        *lock(&inner.self_ref) = Arc::downgrade(&inner);
        let core = Self(inner);
        core.spawn_state_pusher();
        core.spawn_purger();
        core.apply_services().await;
        core.restore_session().await;
        core.0.state_dirty.notify_one();
        Ok(core)
    }

    #[must_use]
    pub fn inner(&self) -> &Arc<CoreInner> {
        &self.0
    }

    fn handle(&self) -> UnlockerHandle {
        UnlockerHandle(Arc::downgrade(&self.0))
    }

    // ---------- background tasks ----------

    fn spawn_state_pusher(&self) {
        let core = self.0.clone();
        let shutdown = self.0.shutdown.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    () = shutdown.cancelled() => return,
                    () = core.state_dirty.notified() => {}
                }
                // Coalesce bursts of changes.
                tokio::time::sleep(Duration::from_millis(30)).await;
                let snap = Core(core.clone()).snapshot().await;
                core.platform.state_changed(snap.to_string());
            }
        });
    }

    /// Purges decrypted private keys when their grants expire and refreshes the UI.
    fn spawn_purger(&self) {
        let core = self.0.clone();
        let shutdown = self.0.shutdown.clone();
        tokio::spawn(async move {
            loop {
                let next = lock(core.store.authz()).next_expiry();
                let now = core.clock.now();
                let wait = next.map(|n| now.until(n) + Duration::from_millis(5));
                tokio::select! {
                    () = shutdown.cancelled() => return,
                    () = core.grants_dirty.notified() => {}
                    () = async {
                        match wait {
                            Some(w) => tokio::time::sleep(w).await,
                            None => std::future::pending().await,
                        }
                    } => {}
                }
                core.store.purge_unauthorized();
                core.state_dirty.notify_one();
            }
        });
    }

    fn start_account_tasks(&self) {
        let token = self.0.shutdown.child_token();
        if let Some(old) = lock(&self.0.account_tasks).replace(token.clone()) {
            old.cancel();
        }
        // Fallback periodic sync (only acts while notifications are not connected).
        {
            let core = self.0.clone();
            let token = token.clone();
            tokio::spawn(async move {
                loop {
                    let interval =
                        Duration::from_secs(lock(&core.settings).fallback_sync_interval_secs);
                    tokio::select! {
                        () = token.cancelled() => return,
                        () = tokio::time::sleep(interval) => {}
                        () = core.sync_wake.notified() => continue,
                    }
                    let (auto, connected) = (
                        lock(&core.settings).auto_sync,
                        lock(&core.status).notifications_connected,
                    );
                    if auto && !connected {
                        let _ = Core(core.clone()).sync(false).await;
                    } else {
                        // Even with live notifications, re-evaluate staleness.
                        Core(core.clone()).update_usability();
                    }
                }
            });
        }
        // Push notifications.
        {
            let weak = Arc::downgrade(&self.0);
            tokio::spawn(async move {
                let mut attempt = 0u32;
                loop {
                    let Some(core) = weak.upgrade() else { return };
                    if !lock(&core.settings).auto_sync {
                        drop(core);
                        tokio::select! {
                            () = token.cancelled() => return,
                            () = tokio::time::sleep(Duration::from_secs(60)) => continue,
                        }
                    }
                    let session = core.session.read().await.clone();
                    let Some(session) = session else { return };
                    // Refreshes the access token through the SDK middleware if needed.
                    let _ = Core(core.clone()).sync(false).await;
                    let token_str = session.access_token().await;
                    let (tx, mut rx) = tokio::sync::mpsc::channel(8);
                    let url = session.urls.notifications.clone();
                    drop(core);
                    let conn = async {
                        match token_str {
                            Some(t) => notifications::run_once(&url, &t, &tx).await,
                            None => Err(anyhow!("no access token")),
                        }
                    };
                    tokio::pin!(conn);
                    let result = loop {
                        tokio::select! {
                            () = token.cancelled() => return,
                            r = &mut conn => break r,
                            ev = rx.recv() => {
                                let Some(core) = weak.upgrade() else { return };
                                match ev {
                                    Some(PushEvent::Connected) => {
                                        attempt = 0;
                                        lock(&core.status).notifications_connected = true;
                                        core.state_dirty.notify_one();
                                    }
                                    Some(PushEvent::SyncRequired) => {
                                        let c = Core(core.clone());
                                        tokio::spawn(async move {
                                            tokio::time::sleep(Duration::from_secs(1)).await;
                                            let _ = c.sync(true).await;
                                        });
                                    }
                                    Some(PushEvent::LoggedOut) => {
                                        let c = Core(core.clone());
                                        tokio::spawn(async move { c.logout("server").await });
                                        return;
                                    }
                                    Some(PushEvent::Disconnected) | None => {}
                                }
                            }
                        }
                    };
                    if let Some(core) = weak.upgrade() {
                        lock(&core.status).notifications_connected = false;
                        core.state_dirty.notify_one();
                    }
                    if let Err(e) = result {
                        tracing::info!(error = %e, "Notification connection ended");
                    }
                    let delay = notifications::backoff(attempt);
                    attempt = attempt.saturating_add(1);
                    tokio::select! {
                        () = token.cancelled() => return,
                        () = tokio::time::sleep(delay) => {}
                    }
                }
            });
        }
    }

    fn stop_account_tasks(&self) {
        if let Some(t) = lock(&self.0.account_tasks).take() {
            t.cancel();
        }
        lock(&self.0.status).notifications_connected = false;
    }

    // ---------- account ----------

    async fn restore_session(&self) {
        let Some(blob) = self.0.platform.load_session() else {
            return;
        };
        match BitwardenSession::restore(&blob).await {
            Ok(session) => {
                let user_id = session.user_id.clone();
                if let Some(v) = self.0.cache.load(&user_id) {
                    lock(&self.0.status).last_sync_ok = Some(v.synced_at);
                    *lock(&self.0.vault) = Some(Arc::new(v));
                }
                *self.0.session.write().await = Some(Arc::new(session));
                self.update_usability();
                self.start_account_tasks();
            }
            Err(e) => {
                tracing::warn!(error = %e, "Stored session is unreadable; login required");
                self.0.platform.delete_session();
            }
        }
    }

    pub async fn login(&self, server_url: &str, creds: LoginCredentials) -> Value {
        let server_url = match config::normalize_server_url(server_url) {
            Ok(s) => s,
            Err(e) => return json!({"ok": false, "error": e.to_string()}),
        };
        lock(&self.0.status).login = LoginState {
            stage: "in_progress",
            ..Default::default()
        };
        self.0.state_dirty.notify_one();
        let result = BitwardenSession::login(&server_url, creds).await;
        let reply = match result {
            Ok(LoginOutcome::TwoFactorRequired {
                methods,
                unsupported,
            }) => {
                lock(&self.0.status).login = LoginState {
                    stage: "two_factor",
                    methods: methods.clone(),
                    unsupported: unsupported.clone(),
                    error: None,
                };
                json!({"ok": false, "two_factor": methods, "unsupported": unsupported})
            }
            Ok(LoginOutcome::Success(done)) => match self.finish_login(server_url, *done).await {
                Ok(()) => {
                    lock(&self.0.status).login = LoginState {
                        stage: "idle",
                        ..Default::default()
                    };
                    json!({"ok": true})
                }
                Err(e) => {
                    lock(&self.0.status).login = LoginState {
                        stage: "idle",
                        error: Some(e.to_string()),
                        ..Default::default()
                    };
                    json!({"ok": false, "error": e.to_string()})
                }
            },
            Err(e) => {
                lock(&self.0.status).login = LoginState {
                    stage: "idle",
                    error: Some(e.to_string()),
                    ..Default::default()
                };
                json!({"ok": false, "error": e.to_string(), "code": match e {
                    BwError::NewDeviceVerification => "new_device_verification",
                    BwError::InvalidCredentials => "invalid_credentials",
                    BwError::Network(_) => "network",
                    _ => "other",
                }})
            }
        };
        self.0.state_dirty.notify_one();
        reply
    }

    async fn finish_login(
        &self,
        server_url: String,
        done: crate::bitwarden::LoggedIn,
    ) -> Result<()> {
        let crate::bitwarden::LoggedIn {
            session,
            user_key_b64,
            vault,
        } = done;
        // Account switch: everything from the previous account is discarded.
        let previous = self
            .0
            .session
            .read()
            .await
            .as_ref()
            .map(|s| s.user_id.clone());
        if previous.is_some() {
            self.logout("account_switch").await;
        }
        self.0
            .platform
            .store_user_key(&session.user_id, user_key_b64.as_bytes())
            .map_err(|e| anyhow!("Unable to store the key in the Keychain: {e}"))?;
        let blob = session.session_blob().await?;
        self.0.platform.store_session(&blob)?;
        // Initial key list from the user key we already hold (no extra prompt after login).
        {
            let d = VaultDecryptor::new(&vault, user_key_b64.as_bytes())?;
            let (meta, failed) = d.all_metadata();
            self.0.store.set_metadata(to_meta(meta));
            let mut st = lock(&self.0.status);
            st.undecryptable_keys = failed.len();
            st.pending_keys = 0;
        }
        drop(user_key_b64);
        let _ = self.0.cache.save(&vault);
        {
            let mut st = lock(&self.0.status);
            st.last_sync_ok = Some(vault.synced_at);
            st.sync_error = None;
            st.session_expired = false;
        }
        *lock(&self.0.vault) = Some(Arc::new(vault));
        {
            let mut settings = lock(&self.0.settings);
            if settings.server_url != server_url {
                settings.server_url = server_url;
                let _ = self.0.config_store.save(&settings);
            }
        }
        *self.0.session.write().await = Some(Arc::new(session));
        self.update_usability();
        self.start_account_tasks();
        Ok(())
    }

    pub async fn logout(&self, reason: &str) {
        tracing::info!(reason, "Logging out");
        self.stop_account_tasks();
        let session = self.0.session.write().await.take();
        lock(self.0.store.authz()).revoke_all();
        self.0.store.set_usable(false);
        self.0.store.forget_metadata();
        *lock(&self.0.vault) = None;
        self.0.cache.delete();
        if let Some(s) = session {
            self.0.platform.delete_user_key(&s.user_id);
        }
        self.0.platform.delete_session();
        {
            let mut st = lock(&self.0.status);
            *st = Status {
                last_lock_reason: Some(reason.to_owned()),
                ..Status::default()
            };
        }
        self.0.grants_dirty.notify_one();
        self.0.state_dirty.notify_one();
    }

    // ---------- sync ----------

    pub async fn sync(&self, force: bool) -> Result<()> {
        let session = self.0.session.read().await.clone();
        let Some(session) = session else {
            return Err(anyhow!("not logged in"));
        };
        let _g = self.0.sync_lock.lock().await;
        lock(&self.0.status).syncing = true;
        self.0.state_dirty.notify_one();
        let result = session.sync_now(force).await;
        let mut st_err = None;
        match result {
            Ok(Some(vault)) => {
                if vault.user_id != session.user_id {
                    st_err = Some("Sync returned a different account".to_owned());
                } else {
                    self.apply_vault(vault);
                }
            }
            Ok(None) => {
                lock(&self.0.status).last_sync_ok = Some(chrono::Utc::now().timestamp());
                if let Some(v) = lock(&self.0.vault).as_ref() {
                    // Keep the cache timestamp current so offline restarts honour max offline.
                    let mut v2 = (**v).clone();
                    v2.synced_at = chrono::Utc::now().timestamp();
                    let _ = self.0.cache.save(&v2);
                }
            }
            Err(BwError::SessionExpired) => {
                lock(&self.0.status).session_expired = true;
                st_err = Some(BwError::SessionExpired.to_string());
            }
            Err(e) => st_err = Some(e.to_string()),
        }
        // Persist rotated tokens.
        if let Ok(blob) = session.session_blob().await {
            let _ = self.0.platform.store_session(&blob);
        }
        {
            let mut st = lock(&self.0.status);
            st.syncing = false;
            st.sync_error.clone_from(&st_err);
        }
        self.update_usability();
        self.0.state_dirty.notify_one();
        st_err.map_or(Ok(()), |e| Err(anyhow!(e)))
    }

    /// Atomically applies a new encrypted vault.
    fn apply_vault(&self, new: EncryptedVault) {
        let old = lock(&self.0.vault).clone();
        let current_meta = self.0.store.metadata();
        // Keep metadata for unchanged ciphers; changed/new ones are pending until the next
        // authentication decrypts them. Removed ones disappear (and lose their grants).
        let mut kept = Vec::new();
        let mut pending = 0;
        for c in &new.ciphers {
            let unchanged = old
                .as_ref()
                .and_then(|o| o.cipher(&c.id))
                .is_some_and(|oc| oc == c);
            match current_meta.iter().find(|m| m.cipher_id == c.id) {
                Some(m) if unchanged => kept.push(m.clone()),
                _ => pending += 1,
            }
        }
        let had_metadata = self.0.store.metadata_known();
        self.0.store.set_metadata(kept);
        if pending > 0 || !had_metadata {
            self.0.store.mark_metadata_incomplete();
        }
        let _ = self.0.cache.save(&new);
        {
            let mut st = lock(&self.0.status);
            st.pending_keys = pending;
            st.last_sync_ok = Some(new.synced_at);
            st.session_expired = false;
        }
        *lock(&self.0.vault) = Some(Arc::new(new));
        self.0.grants_dirty.notify_one();
    }

    /// Enables/disables the key store according to login state, staleness and settings.
    fn update_usability(&self) {
        let s = lock(&self.0.settings).clone();
        let last = lock(&self.0.status).last_sync_ok;
        let has_vault = lock(&self.0.vault).is_some();
        let fresh = last.is_some_and(|t| {
            let age = chrono::Utc::now().timestamp().saturating_sub(t);
            age >= -300
                && u64::try_from(age.max(0)).unwrap_or(u64::MAX) <= s.max_offline().as_secs()
        });
        let usable = s.ssh_agent_enabled && has_vault && fresh;
        self.0.store.set_usable(usable);
        let mut st = lock(&self.0.status);
        st.ssh_error = if has_vault && !fresh {
            Some(format!(
                "Vault has not synced for more than {} hours; SSH keys are disabled until the next \
                 successful sync",
                s.max_offline_hours
            ))
        } else {
            None
        };
    }

    // ---------- authentication ----------

    pub async fn unlock_agent(&self) -> Result<(), AuthFailure> {
        let ttl = lock(&self.0.settings).ssh_ttl_secs;
        self.0
            .authenticate_and_decrypt(
                AuthPurpose::AgentUnlock { ttl_secs: ttl },
                UnlockTarget::AllKeys,
            )
            .await?;
        let granted = lock(self.0.store.authz())
            .grant(Scope {
                key: None,
                process: None,
            })
            .is_some();
        if !granted {
            // TTL 0 / every time: nothing to keep unlocked, drop the material again.
            self.0.store.purge_unauthorized();
        }
        self.0.grants_dirty.notify_one();
        self.0.state_dirty.notify_one();
        Ok(())
    }

    /// Lock: revoke all SSH grants and purge decrypted private keys.
    pub fn lock_agent(&self, reason: &str) {
        lock(self.0.store.authz()).revoke_all();
        self.0.store.purge_all_private();
        lock(&self.0.status).last_lock_reason = Some(reason.to_owned());
        self.0.grants_dirty.notify_one();
        self.0.state_dirty.notify_one();
    }

    pub async fn system_event(&self, event: &str) {
        let s = lock(&self.0.settings).clone();
        let logged_in = self.0.session.read().await.is_some();
        match event {
            "screen_locked" if s.lock_on_screen_lock => self.lock_agent("screen_lock"),
            "will_sleep" if s.lock_on_sleep => self.lock_agent("sleep"),
            "session_resigned" if s.lock_on_user_switch => self.lock_agent("user_switch"),
            // Restart notifications and catch up.
            "did_wake" | "network_up" | "session_active" if logged_in => {
                self.start_account_tasks();
            }
            _ => {}
        }
    }

    // ---------- settings / services ----------

    pub async fn update_settings(&self, candidate: Settings) -> Result<Settings> {
        let validated = candidate.validate()?;
        self.0.config_store.save(&validated)?;
        *lock(&self.0.settings) = validated.clone();
        self.apply_services().await;
        self.update_usability();
        self.0.sync_wake.notify_one();
        self.0.state_dirty.notify_one();
        Ok(validated)
    }

    /// Reconciles running services with the settings.
    async fn apply_services(&self) {
        let s = lock(&self.0.settings).clone();
        lock(self.0.store.authz()).configure(s.ssh_ttl(), s.ssh_approval_policy, s.ssh_scope_mode);
        self.0.store.set_list_when_locked(s.list_keys_when_locked);
        self.0.grants_dirty.notify_one();

        // SSH agent
        {
            let mut agent = lock(&self.0.agent);
            if s.ssh_agent_enabled {
                let svc = agent.get_or_insert_with(|| {
                    SshAgentService::new(self.0.store.clone(), Arc::new(self.handle()))
                });
                let path = PathBuf::from(&s.ssh_socket_path);
                let res = if let Some(dir) = path.parent() {
                    config::ensure_private_dir(dir).and_then(|()| svc.start(path))
                } else {
                    Err(anyhow!("invalid socket path"))
                };
                lock(&self.0.status).ssh_error = res.err().map(|e| e.to_string());
            } else if let Some(mut svc) = agent.take() {
                svc.stop();
                lock(self.0.store.authz()).revoke_all();
                self.0.store.purge_all_private();
            }
        }

        // Browser bridge
        {
            let mut bridge = self.0.bridge.lock().await;
            if s.browser_unlock_enabled {
                if bridge.is_none() {
                    match BrowserBridge::start(
                        config::browser_socket_path(),
                        Some(self.0.cfg.nmh_path.clone()),
                        Arc::new(self.handle()),
                    )
                    .await
                    {
                        Ok(b) => {
                            *bridge = Some(b);
                            lock(&self.0.status).browser_error = None;
                        }
                        Err(e) => lock(&self.0.status).browser_error = Some(e.to_string()),
                    }
                }
            } else if let Some(b) = bridge.take() {
                b.stop();
            }
        }
    }

    pub async fn shutdown(&self) {
        self.stop_account_tasks();
        if let Some(mut a) = lock(&self.0.agent).take() {
            a.stop();
        }
        if let Some(b) = self.0.bridge.lock().await.take() {
            b.stop();
        }
        lock(self.0.store.authz()).revoke_all();
        self.0.store.set_usable(false);
        self.0.store.forget_metadata();
        self.0.shutdown.cancel();
    }

    /// "Reset Local Authentication State".
    pub async fn reset_local_auth(&self) {
        self.lock_agent("reset");
        self.0.store.mark_metadata_incomplete();
        // Re-create the browser bridge so that all browser channel keys are dropped.
        if let Some(b) = self.0.bridge.lock().await.take() {
            b.stop();
        }
        self.apply_services().await;
    }

    /// Removes everything WardenFuse created (for uninstall). Does not touch other apps.
    pub async fn uninstall(&self) -> Value {
        self.logout("uninstall").await;
        let mut errors = Vec::new();
        if let Err(e) = self.0.manifests.uninstall_all() {
            errors.push(e.to_string());
        }
        if let Err(e) = ssh_config::uninstall(&ssh_config::default_path()) {
            errors.push(e.to_string());
        }
        self.shutdown().await;
        let _ = std::fs::remove_file(self.0.cfg.data_dir.join("settings.json"));
        let _ = std::fs::remove_dir(&self.0.cfg.data_dir);
        let _ = std::fs::remove_dir(config::runtime_dir());
        json!({"ok": errors.is_empty(), "errors": errors})
    }

    // ---------- state ----------

    pub async fn snapshot(&self) -> Value {
        let settings = lock(&self.0.settings).clone();
        let st = lock(&self.0.status).clone();
        let session = self.0.session.read().await.clone();
        let (remaining, active) = {
            let mut a = lock(self.0.store.authz());
            (a.longest_remaining(), a.active_count())
        };
        let keys: Vec<Value> = self
            .0
            .store
            .metadata()
            .iter()
            .map(|m| {
                json!({
                    "name": m.name,
                    "public_key": m.public_key.to_string(),
                    "unlocked": self.0.store.has_private(&m.public_key),
                })
            })
            .collect();
        let (agent_running, socket) = {
            let a = lock(&self.0.agent);
            (
                a.as_ref().is_some_and(SshAgentService::is_running),
                a.as_ref().and_then(|s| s.socket().cloned()),
            )
        };
        let (bridge_running, connections) = {
            let b = self.0.bridge.lock().await;
            match b.as_ref() {
                Some(b) => (true, b.connection_count().await),
                None => (false, 0),
            }
        };
        let vault_count = lock(&self.0.vault).as_ref().map_or(0, |v| v.ciphers.len());
        let now_unix = chrono::Utc::now().timestamp();
        json!({
            "account": {
                "logged_in": session.is_some(),
                "email": session.as_ref().map(|s| s.email.clone()),
                "user_id": session.as_ref().map(|s| s.user_id.clone()),
                "server_url": session.as_ref().map_or(settings.server_url.clone(), |s| s.server_url.clone()),
                "session_expired": st.session_expired,
            },
            "login": st.login,
            "sync": {
                "syncing": st.syncing,
                "last_success_unix": st.last_sync_ok,
                "error": st.sync_error,
                "notifications_connected": st.notifications_connected,
            },
            "ssh": {
                "enabled": settings.ssh_agent_enabled,
                "running": agent_running,
                "usable": self.0.store.is_usable(),
                "socket": socket.map(|p| p.to_string_lossy().into_owned()).unwrap_or(settings.ssh_socket_path.clone()),
                "vault_key_count": vault_count,
                "keys": keys,
                "list_complete": self.0.store.metadata_known(),
                "pending_keys": st.pending_keys,
                "undecryptable_keys": st.undecryptable_keys,
                "locked": active == 0,
                "active_grants": active,
                "unlocked_until_unix": remaining.map(|r| now_unix + i64::try_from(r.as_secs()).unwrap_or(0)),
                "last_lock_reason": st.last_lock_reason,
                "error": st.ssh_error,
                "ssh_config_installed": ssh_config::is_installed(&ssh_config::default_path()),
            },
            "browser": {
                "enabled": settings.browser_unlock_enabled,
                "bridge_running": bridge_running,
                "connections": connections,
                "error": st.browser_error,
                "manifests": self.0.manifests.status(),
                "nmh_path": self.0.cfg.nmh_path,
            },
            "security": {
                "biometry": self.0.platform.biometry_state(),
                "keychain_mode": self.0.cfg.keychain_mode,
            },
            "settings": settings,
        })
    }

    // ---------- command dispatch (JSON, used by the FFI) ----------

    pub async fn command(&self, cmd: Value) -> Value {
        let name = cmd["cmd"].as_str().unwrap_or_default();
        let r: Result<Value> = async {
            Ok(match name {
                "get_state" => self.snapshot().await,
                "login" => {
                    let two_factor: Option<TwoFactorInput> =
                        serde_json::from_value(cmd["two_factor"].clone()).ok();
                    self.login(
                        cmd["server_url"].as_str().unwrap_or(config::DEFAULT_SERVER),
                        LoginCredentials::Password {
                            email: cmd["email"].as_str().unwrap_or_default().trim().to_owned(),
                            password: Zeroizing::new(
                                cmd["password"].as_str().unwrap_or_default().to_owned(),
                            ),
                            two_factor,
                        },
                    )
                    .await
                }
                "login_api_key" => {
                    self.login(
                        cmd["server_url"].as_str().unwrap_or(config::DEFAULT_SERVER),
                        LoginCredentials::ApiKey {
                            client_id: cmd["client_id"].as_str().unwrap_or_default().trim().to_owned(),
                            client_secret: Zeroizing::new(
                                cmd["client_secret"].as_str().unwrap_or_default().trim().to_owned(),
                            ),
                            password: Zeroizing::new(
                                cmd["password"].as_str().unwrap_or_default().to_owned(),
                            ),
                        },
                    )
                    .await
                }
                "cancel_login" => {
                    lock(&self.0.status).login = LoginState {
                        stage: "idle",
                        ..Default::default()
                    };
                    self.0.state_dirty.notify_one();
                    json!({"ok": true})
                }
                "logout" => {
                    self.logout("user").await;
                    json!({"ok": true})
                }
                "sync_now" => match self.sync(true).await {
                    Ok(()) => json!({"ok": true}),
                    Err(e) => json!({"ok": false, "error": e.to_string()}),
                },
                "lock_agent" => {
                    self.lock_agent("user");
                    json!({"ok": true})
                }
                "unlock_agent" => match self.unlock_agent().await {
                    Ok(()) => json!({"ok": true}),
                    Err(e) => json!({"ok": false, "error": e.to_string()}),
                },
                "update_settings" => {
                    let s: Settings = serde_json::from_value(cmd["settings"].clone())?;
                    match self.update_settings(s).await {
                        Ok(s) => json!({"ok": true, "settings": s}),
                        Err(e) => json!({"ok": false, "error": e.to_string()}),
                    }
                }
                "install_browser" => {
                    let r = self.0.manifests.install(
                        cmd["browser"].as_str().unwrap_or_default(),
                        cmd["replace"].as_bool().unwrap_or(false),
                    );
                    self.0.state_dirty.notify_one();
                    match r {
                        Ok(state) => json!({"ok": true, "state": state}),
                        Err(e) => json!({"ok": false, "error": e.to_string()}),
                    }
                }
                "uninstall_browser" => {
                    let r = self.0.manifests.uninstall(cmd["browser"].as_str().unwrap_or_default());
                    self.0.state_dirty.notify_one();
                    match r {
                        Ok(()) => json!({"ok": true}),
                        Err(e) => json!({"ok": false, "error": e.to_string()}),
                    }
                }
                "ssh_config_snippet" => {
                    let sock = lock(&self.0.settings).ssh_socket_path.clone();
                    json!({
                        "ok": true,
                        "ssh_config": ssh_config::snippet(&sock),
                        "env": ssh_config::env_snippet(&sock),
                        "git_signing": format!(
                            "git config --global gpg.format ssh\ngit config --global user.signingkey \"<public key>\"\ngit config --global commit.gpgsign true\n# ssh-keygen uses SSH_AUTH_SOCK:\n{}",
                            ssh_config::env_snippet(&sock)
                        ),
                    })
                }
                "install_ssh_config" => {
                    let sock = lock(&self.0.settings).ssh_socket_path.clone();
                    let r = ssh_config::install(&ssh_config::default_path(), &sock);
                    self.0.state_dirty.notify_one();
                    match r {
                        Ok(b) => json!({"ok": true, "backup": b}),
                        Err(e) => json!({"ok": false, "error": e.to_string()}),
                    }
                }
                "uninstall_ssh_config" => {
                    let r = ssh_config::uninstall(&ssh_config::default_path());
                    self.0.state_dirty.notify_one();
                    match r {
                        Ok(_) => json!({"ok": true}),
                        Err(e) => json!({"ok": false, "error": e.to_string()}),
                    }
                }
                "reset_local_auth" => {
                    self.reset_local_auth().await;
                    json!({"ok": true})
                }
                "uninstall" => self.uninstall().await,
                "system_event" => {
                    self.system_event(cmd["event"].as_str().unwrap_or_default()).await;
                    json!({"ok": true})
                }
                "diagnostics" => self.diagnostics().await,
                other => json!({"ok": false, "error": format!("unknown command {other}")}),
            })
        }
        .await;
        r.unwrap_or_else(|e| json!({"ok": false, "error": e.to_string()}))
    }

    async fn diagnostics(&self) -> Value {
        let s = lock(&self.0.settings).clone();
        let sock = PathBuf::from(&s.ssh_socket_path);
        let sock_mode = std::fs::metadata(&sock).ok().map(|m| {
            use std::os::unix::fs::PermissionsExt;
            format!("{:o}", m.permissions().mode() & 0o777)
        });
        let bsock = config::browser_socket_path();
        json!({
            "ok": true,
            "ssh_socket_exists": sock.exists(),
            "ssh_socket_mode": sock_mode,
            "browser_socket_exists": bsock.exists(),
            "nmh_exists": self.0.cfg.nmh_path.exists(),
            "nmh_path": self.0.cfg.nmh_path,
            "manifests": self.0.manifests.status(),
            "ssh_auth_sock_env": std::env::var("SSH_AUTH_SOCK").ok(),
            "version": env!("CARGO_PKG_VERSION"),
        })
    }
}

fn to_meta(meta: Vec<crate::vault::KeyMeta>) -> Vec<MetaKeyData> {
    meta.into_iter()
        .filter_map(|m| {
            Some(MetaKeyData {
                public_key: parse_public_key(&m.public_key).ok()?,
                name: m.name,
                cipher_id: m.cipher_id,
            })
        })
        .collect()
}

impl CoreInner {
    async fn authenticate(&self, purpose: AuthPurpose) -> Result<Zeroizing<Vec<u8>>, AuthFailure> {
        let user_id = self
            .session
            .read()
            .await
            .as_ref()
            .map(|s| s.user_id.clone())
            .ok_or(AuthFailure::Unavailable)?;
        let (allow_biometrics, allow_password) = {
            let s = lock(&self.settings);
            (s.prefer_touch_id, s.allow_password_fallback)
        };
        // One native authentication dialog at a time.
        let _g = self.auth_lock.lock().await;
        let req = AuthRequest {
            reason: purpose.reason(),
            purpose,
            user_id,
            allow_biometrics,
            allow_password,
        };
        match tokio::time::timeout(AUTH_TIMEOUT, self.platform.authenticate(req)).await {
            Ok(r) => r,
            Err(_) => Err(AuthFailure::Timeout),
        }
    }

    /// Authenticates and decrypts the requested material into the gated key store.
    async fn authenticate_and_decrypt(
        &self,
        purpose: AuthPurpose,
        target: UnlockTarget,
    ) -> Result<(), AuthFailure> {
        let vault = lock(&self.vault).clone().ok_or(AuthFailure::Unavailable)?;
        if !self.store.is_usable() {
            return Err(AuthFailure::Unavailable);
        }
        let key = self.authenticate(purpose).await?;
        let decryptor = VaultDecryptor::new(&vault, &key).map_err(|_| AuthFailure::KeyMissing)?;
        let (meta, failed) = decryptor.all_metadata();
        self.store.set_metadata(to_meta(meta));
        {
            let mut st = lock(&self.status);
            st.pending_keys = 0;
            st.undecryptable_keys = failed.len();
        }
        let ids: Vec<String> = match &target {
            UnlockTarget::Metadata => vec![],
            UnlockTarget::Key { cipher_id } => vec![cipher_id.clone()],
            UnlockTarget::AllKeys => vault.ciphers.iter().map(|c| c.id.clone()).collect(),
        };
        let mut ok = ids.is_empty();
        for id in ids {
            match decryptor.decrypt_key(&id) {
                Ok(k) => match SSHKeyData::from_private_key_pem(
                    &k.private_key_pem,
                    k.meta.name.clone(),
                    k.meta.cipher_id.clone(),
                ) {
                    Ok(data) => match self.store.insert_private(data) {
                        Ok(()) => ok = true,
                        Err(e) => tracing::warn!(error = %e, "Rejected decrypted key"),
                    },
                    Err(e) => tracing::warn!(error = %e, "Unable to parse SSH private key"),
                },
                Err(e) => tracing::warn!(error = %e, "Unable to decrypt SSH key"),
            }
        }
        drop(decryptor);
        drop(key);
        self.state_dirty.notify_one();
        if ok {
            Ok(())
        } else {
            Err(AuthFailure::Failed)
        }
    }
}
