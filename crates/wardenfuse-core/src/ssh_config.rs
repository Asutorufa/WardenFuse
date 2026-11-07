//! Safe, opt-in integration with `~/.ssh/config`.
//!
//! WardenFuse only ever touches a clearly marked block. The original file is backed up once
//! before the first modification, edits are atomic, and removal deletes only our block.

use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};

use anyhow::{bail, Result};

use crate::config::home_dir;

const BEGIN: &str = "# >>> WardenFuse SSH agent >>>";
const END: &str = "# <<< WardenFuse SSH agent <<<";

/// `IdentityAgent` value, quoted when it contains spaces.
fn agent_value(socket: &str) -> String {
    if socket.contains(' ') {
        format!("\"{socket}\"")
    } else {
        socket.to_owned()
    }
}

/// Snippet shown in Settings for manual configuration.
#[must_use]
pub fn snippet(socket: &str) -> String {
    format!("Host *\n  IdentityAgent {}\n", agent_value(socket))
}

/// Shell export for terminals that use `SSH_AUTH_SOCK`.
#[must_use]
pub fn env_snippet(socket: &str) -> String {
    format!("export SSH_AUTH_SOCK={}", agent_value(socket))
}

fn block(socket: &str) -> String {
    format!(
        "{BEGIN}\n# Managed by WardenFuse. Remove it from WardenFuse Settings → SSH Agent.\n{}{END}\n",
        snippet(socket)
    )
}

fn strip_block(content: &str) -> (String, bool) {
    let Some(start) = content.find(BEGIN) else {
        return (content.to_owned(), false);
    };
    let Some(end_rel) = content[start..].find(END) else {
        return (content.to_owned(), false);
    };
    let mut end = start + end_rel + END.len();
    if content[end..].starts_with('\n') {
        end += 1;
    }
    let mut out = String::with_capacity(content.len());
    out.push_str(&content[..start]);
    out.push_str(&content[end..]);
    (out, true)
}

#[must_use]
pub fn default_path() -> PathBuf {
    home_dir().join(".ssh/config")
}

#[must_use]
pub fn is_installed(path: &Path) -> bool {
    fs::read_to_string(path).is_ok_and(|c| c.contains(BEGIN) && c.contains(END))
}

fn check_regular(path: &Path) -> Result<()> {
    if let Ok(m) = fs::symlink_metadata(path) {
        if m.file_type().is_symlink() {
            bail!(
                "{} is a symlink; please add the configuration manually",
                path.display()
            );
        }
        if !m.is_file() {
            bail!("{} is not a regular file", path.display());
        }
    }
    Ok(())
}

/// Adds (or updates) our block at the top of the file, so it applies before any `Host`
/// sections that might set another `IdentityAgent`. Returns the backup path, if one was made.
pub fn install(path: &Path, socket: &str) -> Result<Option<PathBuf>> {
    check_regular(path)?;
    let existing = fs::read_to_string(path).unwrap_or_default();
    let (rest, had_block) = strip_block(&existing);
    let mut backup = None;
    if !existing.is_empty() && !had_block {
        let b = path.with_extension("wardenfuse-backup");
        if !b.exists() {
            fs::copy(path, &b)?;
            fs::set_permissions(&b, fs::Permissions::from_mode(0o600))?;
        }
        backup = Some(b);
    }
    let mut new = block(socket);
    if !rest.is_empty() {
        new.push('\n');
        new.push_str(rest.trim_start_matches('\n'));
    }
    write(path, &new)?;
    Ok(backup)
}

/// Removes only our block.
pub fn uninstall(path: &Path) -> Result<bool> {
    check_regular(path)?;
    let Ok(existing) = fs::read_to_string(path) else {
        return Ok(false);
    };
    let (rest, had) = strip_block(&existing);
    if had {
        write(path, rest.trim_start_matches('\n'))?;
    }
    Ok(had)
}

fn write(path: &Path, content: &str) -> Result<()> {
    if let Some(dir) = path.parent() {
        if !dir.exists() {
            fs::create_dir_all(dir)?;
            fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
        }
    }
    let mode = fs::metadata(path).map_or(0o600, |m| m.permissions().mode() & 0o777);
    crate::config::write_private_file(path, content.as_bytes())?;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn install_is_idempotent_and_preserves_content() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("config");
        let original = "Host github.com\n  User git\n";
        fs::write(&p, original).unwrap();
        fs::set_permissions(&p, fs::Permissions::from_mode(0o644)).unwrap();
        let backup = install(&p, "/Users/a/.wardenfuse/ssh-agent.sock").unwrap();
        assert_eq!(fs::read_to_string(backup.unwrap()).unwrap(), original);
        install(&p, "/Users/a/.wardenfuse/ssh-agent.sock").unwrap();
        let c = fs::read_to_string(&p).unwrap();
        assert_eq!(c.matches(BEGIN).count(), 1);
        assert!(c.starts_with(BEGIN));
        assert!(c.ends_with(original));
        assert_eq!(
            fs::metadata(&p).unwrap().permissions().mode() & 0o777,
            0o644
        );
        assert!(uninstall(&p).unwrap());
        assert_eq!(fs::read_to_string(&p).unwrap(), original);
    }

    #[test]
    fn creates_missing_file_and_refuses_symlink() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join(".ssh/config");
        assert!(install(&p, "/tmp/a b.sock").unwrap().is_none());
        assert!(fs::read_to_string(&p)
            .unwrap()
            .contains("IdentityAgent \"/tmp/a b.sock\""));
        let link = d.path().join("link");
        std::os::unix::fs::symlink(&p, &link).unwrap();
        assert!(install(&link, "/tmp/x.sock").is_err());
    }
}
