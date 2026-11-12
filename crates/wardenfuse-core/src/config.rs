//! Persistent, non-secret settings. Validated by the core; the UI only submits candidates.

use std::{
    fs,
    io::Write as _,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    time::Duration,
};

use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};

use crate::authz::{ApprovalPolicy, ScopeMode};

pub const DEFAULT_SERVER: &str = "https://vault.bitwarden.com";
pub const DEFAULT_SSH_TTL_SECS: u64 = 600;
pub const DEFAULT_SYNC_INTERVAL_SECS: u64 = 300;
pub const DEFAULT_MAX_OFFLINE_HOURS: u64 = 72;
pub const MAX_SSH_TTL_SECS: u64 = 24 * 3600;

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum BrowserAuthentication {
    #[default]
    Mac,
    Android,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct Settings {
    // General
    pub launch_at_login: bool,
    pub show_menu_bar_icon: bool,

    // Bitwarden
    pub server_url: String,
    pub auto_sync: bool,
    pub fallback_sync_interval_secs: u64,
    /// Cached SSH keys stop being usable when the last successful sync is older than this.
    pub max_offline_hours: u64,

    // Browser integration
    pub browser_unlock_enabled: bool,
    pub browser_authentication: BrowserAuthentication,
    pub android_timeout_secs: u64,

    // SSH agent
    pub ssh_agent_enabled: bool,
    pub ssh_socket_path: String,
    pub ssh_ttl_secs: u64,
    pub ssh_approval_policy: ApprovalPolicy,
    pub ssh_scope_mode: ScopeMode,
    pub allow_agent_forwarding: bool,
    pub list_keys_when_locked: bool,

    // Security
    pub prefer_touch_id: bool,
    pub allow_password_fallback: bool,
    pub lock_on_screen_lock: bool,
    pub lock_on_sleep: bool,
    pub lock_on_user_switch: bool,
    pub clear_on_account_switch: bool,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            launch_at_login: false,
            show_menu_bar_icon: true,
            server_url: DEFAULT_SERVER.to_owned(),
            auto_sync: true,
            fallback_sync_interval_secs: DEFAULT_SYNC_INTERVAL_SECS,
            max_offline_hours: DEFAULT_MAX_OFFLINE_HOURS,
            browser_unlock_enabled: true,
            browser_authentication: BrowserAuthentication::Mac,
            android_timeout_secs: 30,
            ssh_agent_enabled: true,
            ssh_socket_path: default_socket_path().to_string_lossy().into_owned(),
            ssh_ttl_secs: DEFAULT_SSH_TTL_SECS,
            ssh_approval_policy: ApprovalPolicy::CacheForTtl,
            ssh_scope_mode: ScopeMode::KeyAndProcess,
            allow_agent_forwarding: false,
            list_keys_when_locked: true,
            prefer_touch_id: true,
            allow_password_fallback: true,
            lock_on_screen_lock: true,
            lock_on_sleep: true,
            lock_on_user_switch: true,
            clear_on_account_switch: true,
        }
    }
}

impl Settings {
    #[must_use]
    pub fn ssh_ttl(&self) -> Duration {
        Duration::from_secs(self.ssh_ttl_secs)
    }

    #[must_use]
    pub fn max_offline(&self) -> Duration {
        Duration::from_secs(self.max_offline_hours.saturating_mul(3600))
    }

    /// Validates and normalizes. Returns an error describing the first invalid field.
    pub fn validate(mut self) -> Result<Self> {
        self.server_url = normalize_server_url(&self.server_url)?;
        if !(10..=60).contains(&self.android_timeout_secs) {
            bail!("Android authentication timeout must be between 10 and 60 seconds");
        }
        if self.ssh_ttl_secs > MAX_SSH_TTL_SECS {
            bail!("SSH authentication TTL must be at most 24 hours");
        }
        if !(60..=86_400).contains(&self.fallback_sync_interval_secs) {
            bail!("Fallback sync interval must be between 1 minute and 24 hours");
        }
        if !(1..=24 * 30).contains(&self.max_offline_hours) {
            bail!("Maximum offline period must be between 1 hour and 30 days");
        }
        let sock = expand_tilde(self.ssh_socket_path.trim());
        if !sock.is_absolute() {
            bail!("SSH socket path must be absolute");
        }
        // sun_path is 104 bytes on Darwin including the NUL terminator.
        if sock.as_os_str().len() >= 104 {
            bail!("SSH socket path is too long (max 103 bytes)");
        }
        if sock.file_name().is_none() {
            bail!("SSH socket path must name a file");
        }
        self.ssh_socket_path = sock.to_string_lossy().into_owned();
        // LocalAuthentication has no public "password only" policy:
        // `.deviceOwnerAuthentication` always offers Touch ID when available. Supported:
        // Touch ID only, or Touch ID with macOS password fallback.
        if !self.prefer_touch_id {
            bail!(
                "macOS cannot require the system password without offering Touch ID; choose \
                 \"Touch ID only\" or \"Touch ID or macOS password\""
            );
        }
        Ok(self)
    }
}

/// Server URLs derived from the user-facing server URL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerUrls {
    pub api: String,
    pub identity: String,
    pub notifications: String,
}

impl ServerUrls {
    #[must_use]
    pub fn from_server(server: &str) -> Self {
        let s = server.trim_end_matches('/');
        match s {
            "https://vault.bitwarden.com" | "https://bitwarden.com" => Self {
                api: "https://api.bitwarden.com".into(),
                identity: "https://identity.bitwarden.com".into(),
                notifications: "https://notifications.bitwarden.com".into(),
            },
            "https://vault.bitwarden.eu" | "https://bitwarden.eu" => Self {
                api: "https://api.bitwarden.eu".into(),
                identity: "https://identity.bitwarden.eu".into(),
                notifications: "https://notifications.bitwarden.eu".into(),
            },
            // Self-hosted (official server and Vaultwarden use the same layout).
            other => Self {
                api: format!("{other}/api"),
                identity: format!("{other}/identity"),
                notifications: format!("{other}/notifications"),
            },
        }
    }
}

pub fn normalize_server_url(url: &str) -> Result<String> {
    let url = url.trim().trim_end_matches('/');
    let rest = if let Some(r) = url.strip_prefix("https://") {
        r
    } else if let Some(r) = url.strip_prefix("http://") {
        // Plain HTTP only for loopback development servers.
        let host = r.split(['/', ':']).next().unwrap_or_default();
        if host != "localhost" && host != "127.0.0.1" {
            bail!("Server URL must use https://");
        }
        r
    } else {
        bail!("Server URL must start with https://");
    };
    if rest.is_empty() || rest.contains(char::is_whitespace) || rest.contains(['?', '#', '@']) {
        bail!("Server URL is invalid");
    }
    Ok(url.to_owned())
}

#[must_use]
pub fn home_dir() -> PathBuf {
    std::env::var_os("HOME").map_or_else(|| PathBuf::from("/"), PathBuf::from)
}

fn expand_tilde(p: &str) -> PathBuf {
    if let Some(rest) = p.strip_prefix("~/") {
        home_dir().join(rest)
    } else if p == "~" {
        home_dir()
    } else {
        PathBuf::from(p)
    }
}

/// `~/.wardenfuse` — short, space free, private (0700) runtime directory for the sockets.
#[must_use]
pub fn runtime_dir() -> PathBuf {
    home_dir().join(".wardenfuse")
}

#[must_use]
pub fn default_socket_path() -> PathBuf {
    runtime_dir().join("ssh-agent.sock")
}

#[must_use]
pub fn browser_socket_path() -> PathBuf {
    runtime_dir().join("browser.sock")
}

/// Ensures the private runtime dir exists with mode 0700 and is owned by us.
pub fn ensure_private_dir(dir: &Path) -> Result<()> {
    use std::os::unix::fs::{DirBuilderExt, MetadataExt};
    if !dir.exists() {
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)
            .with_context(|| format!("creating {}", dir.display()))?;
    }
    let meta = fs::symlink_metadata(dir)?;
    if !meta.is_dir() {
        bail!("{} is not a directory", dir.display());
    }
    // SAFETY: geteuid has no preconditions.
    if meta.uid() != unsafe { libc::geteuid() } {
        bail!("{} is not owned by the current user", dir.display());
    }
    if meta.mode() & 0o077 != 0 {
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

/// Atomically writes `data` to `path` with mode 0600.
pub fn write_private_file(path: &Path, data: &[u8]) -> Result<()> {
    let dir = path.parent().ok_or_else(|| anyhow!("no parent dir"))?;
    let tmp = dir.join(format!(
        ".{}.tmp-{}",
        path.file_name().and_then(|n| n.to_str()).unwrap_or("f"),
        std::process::id()
    ));
    {
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp)?;
        f.write_all(data)?;
        f.sync_all()?;
    }
    fs::rename(&tmp, path)?;
    Ok(())
}

pub struct ConfigStore {
    path: PathBuf,
}

impl ConfigStore {
    #[must_use]
    pub fn new(data_dir: &Path) -> Self {
        Self {
            path: data_dir.join("settings.json"),
        }
    }

    /// Loads settings; a corrupt or invalid file falls back to defaults (never to something
    /// less secure than the defaults).
    #[must_use]
    pub fn load(&self) -> Settings {
        let Ok(data) = fs::read(&self.path) else {
            return Settings::default();
        };
        match serde_json::from_slice::<Settings>(&data).map_err(anyhow::Error::from) {
            Ok(mut s) => {
                // Migrate the unsupported "password only" combination of earlier builds to
                // Touch ID with password fallback, keeping all other settings.
                if !s.prefer_touch_id {
                    s.prefer_touch_id = true;
                    s.allow_password_fallback = true;
                }
                s
            }
            .validate()
            .unwrap_or_else(|e| {
                tracing::warn!(error = %e, "Invalid settings file, using defaults");
                Settings::default()
            }),
            Err(e) => {
                tracing::warn!(error = %e, "Unreadable settings file, using defaults");
                Settings::default()
            }
        }
    }

    pub fn save(&self, s: &Settings) -> Result<()> {
        let data = serde_json::to_vec_pretty(s)?;
        write_private_file(&self.path, &data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_valid_and_secure() {
        let s = Settings::default().validate().unwrap();
        assert_eq!(s.ssh_ttl_secs, 600);
        assert_eq!(s.fallback_sync_interval_secs, 300);
        assert!(!s.allow_agent_forwarding);
        assert!(s.lock_on_sleep && s.lock_on_screen_lock);
    }

    #[test]
    fn rejects_bad_values() {
        let mut s = Settings {
            ssh_ttl_secs: MAX_SSH_TTL_SECS + 1,
            ..Default::default()
        };
        assert!(s.clone().validate().is_err());
        s.ssh_ttl_secs = 0;
        assert!(s.clone().validate().is_ok(), "TTL 0 = always authenticate");
        s.server_url = "http://evil.example.com".into();
        assert!(s.clone().validate().is_err());
        s.server_url = "https://vault.example.com/".into();
        assert_eq!(
            s.clone().validate().unwrap().server_url,
            "https://vault.example.com"
        );
        s.ssh_socket_path = "relative.sock".into();
        assert!(s.clone().validate().is_err());
        s.ssh_socket_path = format!("/{}", "a".repeat(120));
        assert!(s.clone().validate().is_err());
        s.ssh_socket_path = "/tmp/x.sock".into();
        s.allow_password_fallback = false;
        assert!(s.clone().validate().is_ok(), "Touch ID only");
        s.prefer_touch_id = false;
        s.allow_password_fallback = true;
        assert!(
            s.clone().validate().is_err(),
            "password only is not enforceable"
        );
        s.allow_password_fallback = false;
        assert!(s.validate().is_err());
    }

    #[test]
    fn password_only_is_migrated_on_load() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("settings.json"),
            br#"{"prefer_touch_id": false, "allow_password_fallback": true, "ssh_ttl_secs": 60}"#,
        )
        .unwrap();
        let s = ConfigStore::new(dir.path()).load();
        assert!(s.prefer_touch_id && s.allow_password_fallback);
        assert_eq!(s.ssh_ttl_secs, 60, "other settings are kept");
    }

    #[test]
    fn server_urls() {
        let u = ServerUrls::from_server("https://vault.bitwarden.com");
        assert_eq!(u.api, "https://api.bitwarden.com");
        let u = ServerUrls::from_server("https://vw.example.com");
        assert_eq!(u.identity, "https://vw.example.com/identity");
        assert_eq!(u.notifications, "https://vw.example.com/notifications");
    }

    #[test]
    fn save_and_load_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let store = ConfigStore::new(dir.path());
        let s = Settings {
            ssh_ttl_secs: 60,
            ..Default::default()
        };
        store.save(&s).unwrap();
        let mode = fs::metadata(dir.path().join("settings.json"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
        assert_eq!(store.load(), s.validate().unwrap());
    }

    #[test]
    fn corrupt_file_falls_back_to_defaults() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("settings.json"), b"{not json").unwrap();
        assert_eq!(ConfigStore::new(dir.path()).load(), Settings::default());
    }
}
