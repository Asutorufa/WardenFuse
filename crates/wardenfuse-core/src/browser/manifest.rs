//! Chromium native messaging host manifests (`com.8bit.bitwarden.json`).
//!
//! WardenFuse never silently overwrites a manifest it did not create (typically the one
//! installed by Bitwarden Desktop). Replacing it requires an explicit user action, and the
//! original is kept as a backup that uninstall restores.

use std::{
    fs,
    path::{Path, PathBuf},
};

use anyhow::{bail, Context, Result};
use serde::Serialize;
use serde_json::{json, Value};

use super::ALLOWED_ORIGINS;
use crate::config::home_dir;

pub const HOST_NAME: &str = "com.8bit.bitwarden";
const MANIFEST_FILE: &str = "com.8bit.bitwarden.json";
const BACKUP_SUFFIX: &str = ".wardenfuse-backup";
const NMH_BINARY_NAME: &str = "wardenfuse-nmh";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Browser {
    pub id: &'static str,
    pub name: &'static str,
    /// Relative to `~/Library/Application Support`.
    pub support_dir: &'static str,
}

/// Chrome and Brave first; others when their profile directory exists.
pub const BROWSERS: &[Browser] = &[
    Browser {
        id: "chrome",
        name: "Google Chrome",
        support_dir: "Google/Chrome",
    },
    Browser {
        id: "brave",
        name: "Brave",
        support_dir: "BraveSoftware/Brave-Browser",
    },
    Browser {
        id: "edge",
        name: "Microsoft Edge",
        support_dir: "Microsoft Edge",
    },
    Browser {
        id: "chromium",
        name: "Chromium",
        support_dir: "Chromium",
    },
    Browser {
        id: "vivaldi",
        name: "Vivaldi",
        support_dir: "Vivaldi",
    },
    Browser {
        id: "chrome-beta",
        name: "Google Chrome Beta",
        support_dir: "Google/Chrome Beta",
    },
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case", tag = "state")]
pub enum ManifestState {
    /// Browser profile directory not found.
    BrowserNotFound,
    /// No `com.8bit.bitwarden` host registered.
    NotInstalled,
    /// Ours and pointing at this app's NMH.
    Installed,
    /// Ours but pointing at another (moved/old) copy of WardenFuse.
    Stale { path: String },
    /// Another application's host (usually Bitwarden Desktop).
    Foreign { path: String },
    /// Unreadable / not JSON.
    Invalid,
}

#[derive(Debug, Clone, Serialize)]
pub struct BrowserStatus {
    pub browser: Browser,
    pub manifest_path: String,
    #[serde(flatten)]
    pub state: ManifestState,
    pub has_backup: bool,
}

pub struct Manifests {
    app_support: PathBuf,
    nmh_path: PathBuf,
}

fn is_ours(path: &str) -> bool {
    Path::new(path)
        .file_name()
        .is_some_and(|n| n == NMH_BINARY_NAME)
}

impl Manifests {
    #[must_use]
    pub fn new(nmh_path: PathBuf) -> Self {
        Self {
            app_support: home_dir().join("Library/Application Support"),
            nmh_path,
        }
    }

    #[must_use]
    pub fn with_root(app_support: PathBuf, nmh_path: PathBuf) -> Self {
        Self {
            app_support,
            nmh_path,
        }
    }

    fn dir(&self, b: &Browser) -> PathBuf {
        self.app_support
            .join(b.support_dir)
            .join("NativeMessagingHosts")
    }

    fn manifest(&self, b: &Browser) -> PathBuf {
        self.dir(b).join(MANIFEST_FILE)
    }

    fn backup(&self, b: &Browser) -> PathBuf {
        self.dir(b).join(format!("{MANIFEST_FILE}{BACKUP_SUFFIX}"))
    }

    #[must_use]
    pub fn manifest_json(&self) -> Value {
        json!({
            "name": HOST_NAME,
            "description": "WardenFuse – Bitwarden biometric unlock bridge (not an official Bitwarden product)",
            "path": self.nmh_path.to_string_lossy(),
            "type": "stdio",
            "allowed_origins": ALLOWED_ORIGINS,
        })
    }

    #[must_use]
    pub fn state(&self, b: &Browser) -> ManifestState {
        if !self.app_support.join(b.support_dir).is_dir() {
            return ManifestState::BrowserNotFound;
        }
        let path = self.manifest(b);
        let Ok(data) = fs::read(&path) else {
            return ManifestState::NotInstalled;
        };
        let Ok(v) = serde_json::from_slice::<Value>(&data) else {
            return ManifestState::Invalid;
        };
        let host_path = v["path"].as_str().unwrap_or_default().to_owned();
        if !is_ours(&host_path) {
            return ManifestState::Foreign { path: host_path };
        }
        let current = self.manifest_json();
        let same_path = Path::new(&host_path) == self.nmh_path;
        let same_origins = v["allowed_origins"] == current["allowed_origins"];
        if same_path && same_origins {
            ManifestState::Installed
        } else {
            ManifestState::Stale { path: host_path }
        }
    }

    #[must_use]
    pub fn status(&self) -> Vec<BrowserStatus> {
        BROWSERS
            .iter()
            .map(|b| BrowserStatus {
                browser: *b,
                manifest_path: self.manifest(b).to_string_lossy().into_owned(),
                state: self.state(b),
                has_backup: self.backup(b).exists(),
            })
            .collect()
    }

    /// Installs or repairs the manifest for one browser.
    ///
    /// A foreign manifest is only replaced with `replace_foreign = true`; it is moved to a
    /// backup first.
    pub fn install(&self, browser_id: &str, replace_foreign: bool) -> Result<ManifestState> {
        let b = BROWSERS
            .iter()
            .find(|b| b.id == browser_id)
            .context("unknown browser")?;
        match self.state(b) {
            ManifestState::BrowserNotFound => bail!("{} is not installed", b.name),
            ManifestState::Foreign { path } if !replace_foreign => bail!(
                "{} already has a Bitwarden native messaging host ({path}). Confirm replacing it \
                 to switch browser unlock to WardenFuse.",
                b.name
            ),
            ManifestState::Foreign { .. } | ManifestState::Invalid => {
                let backup = self.backup(b);
                if !backup.exists() {
                    fs::rename(self.manifest(b), &backup)
                        .context("backing up existing manifest")?;
                }
            }
            _ => {}
        }
        fs::create_dir_all(self.dir(b))?;
        let data = serde_json::to_vec_pretty(&self.manifest_json())?;
        crate::config::write_private_file(&self.manifest(b), &data)?;
        // Browsers read the manifest as the user; 0644 is the conventional mode.
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(self.manifest(b), fs::Permissions::from_mode(0o644))?;
        }
        Ok(self.state(b))
    }

    /// Removes our manifest and restores a backed-up foreign manifest, if any. Never touches
    /// a manifest that is not ours.
    pub fn uninstall(&self, browser_id: &str) -> Result<()> {
        let b = BROWSERS
            .iter()
            .find(|b| b.id == browser_id)
            .context("unknown browser")?;
        match self.state(b) {
            ManifestState::Installed | ManifestState::Stale { .. } => {
                fs::remove_file(self.manifest(b))?;
            }
            _ => {}
        }
        let backup = self.backup(b);
        if backup.exists() && !self.manifest(b).exists() {
            fs::rename(&backup, self.manifest(b))?;
        }
        Ok(())
    }

    pub fn uninstall_all(&self) -> Result<()> {
        for b in BROWSERS {
            if self.app_support.join(b.support_dir).is_dir() {
                self.uninstall(b.id)?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn setup() -> (tempfile::TempDir, Manifests) {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir_all(dir.path().join("Google/Chrome")).unwrap();
        fs::create_dir_all(dir.path().join("BraveSoftware/Brave-Browser")).unwrap();
        let m = Manifests::with_root(
            dir.path().to_path_buf(),
            PathBuf::from("/Applications/WardenFuse.app/Contents/MacOS/wardenfuse-nmh"),
        );
        (dir, m)
    }

    #[test]
    fn install_and_uninstall() {
        let (_d, m) = setup();
        assert_eq!(m.state(&BROWSERS[0]), ManifestState::NotInstalled);
        assert_eq!(m.state(&BROWSERS[2]), ManifestState::BrowserNotFound);
        assert_eq!(
            m.install("chrome", false).unwrap(),
            ManifestState::Installed
        );
        let v: Value =
            serde_json::from_slice(&fs::read(m.manifest(&BROWSERS[0])).unwrap()).unwrap();
        assert_eq!(v["name"], HOST_NAME);
        assert_eq!(
            v["allowed_origins"].as_array().unwrap().len(),
            ALLOWED_ORIGINS.len()
        );
        m.uninstall("chrome").unwrap();
        assert_eq!(m.state(&BROWSERS[0]), ManifestState::NotInstalled);
        assert!(m.install("edge", false).is_err());
    }

    #[test]
    fn foreign_manifest_needs_confirmation_and_is_restored() {
        let (_d, m) = setup();
        let b = &BROWSERS[0];
        fs::create_dir_all(m.dir(b)).unwrap();
        let foreign = br#"{"name":"com.8bit.bitwarden","path":"/Applications/Bitwarden.app/Contents/MacOS/desktop_proxy"}"#;
        fs::write(m.manifest(b), foreign).unwrap();
        assert!(matches!(m.state(b), ManifestState::Foreign { .. }));
        assert!(m.install("chrome", false).is_err(), "no silent overwrite");
        assert_eq!(fs::read(m.manifest(b)).unwrap(), foreign);
        assert_eq!(m.install("chrome", true).unwrap(), ManifestState::Installed);
        assert_eq!(fs::read(m.backup(b)).unwrap(), foreign);
        m.uninstall("chrome").unwrap();
        assert_eq!(
            fs::read(m.manifest(b)).unwrap(),
            foreign,
            "original restored"
        );
        assert!(!m.backup(b).exists());
    }

    #[test]
    fn uninstall_never_removes_foreign() {
        let (_d, m) = setup();
        let b = &BROWSERS[1];
        fs::create_dir_all(m.dir(b)).unwrap();
        fs::write(m.manifest(b), br#"{"path":"/x/desktop_proxy"}"#).unwrap();
        m.uninstall("brave").unwrap();
        assert!(m.manifest(b).exists());
    }

    #[test]
    fn moved_app_is_stale_and_repairable() {
        let (d, m) = setup();
        m.install("chrome", false).unwrap();
        let moved = Manifests::with_root(
            d.path().to_path_buf(),
            PathBuf::from("/Users/x/Applications/WardenFuse.app/Contents/MacOS/wardenfuse-nmh"),
        );
        assert!(matches!(
            moved.state(&BROWSERS[0]),
            ManifestState::Stale { .. }
        ));
        assert_eq!(
            moved.install("chrome", false).unwrap(),
            ManifestState::Installed
        );
    }
}
