//! Unix domain socket listener for the SSH agent server

use std::{
    fs,
    os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
};

use anyhow::{anyhow, Result};
use tokio::net::UnixStream;
use tracing::{debug, error, info};

use super::Listener;
use crate::server::{connection::Connection, peer_info::PeerInfo};

/// Environment variable that overrides the default socket path
const ENV_BITWARDEN_SSH_AUTH_SOCK: &str = "BITWARDEN_SSH_AUTH_SOCK";

const FLATPAK_DATA_DIR: &str = ".var/app/com.bitwarden.desktop/data";

const SOCKFILE_NAME: &str = ".bitwarden-ssh-agent.sock";

/// Unix domain socket listener for the SSH agent server
pub(crate) struct UnixListener {
    inner: tokio::net::UnixListener,
}

impl UnixListener {
    /// Creates a new [`UnixListener`], binding to the resolved socket path.
    ///
    /// The socket path is resolved from the `BITWARDEN_SSH_AUTH_SOCK` environment variable if set,
    /// otherwise it defaults to `$HOME/.bitwarden-ssh-agent.sock`.
    /// Any stale socket file at that path is removed before binding.
    /// Permissions are set to `0o600` so only the current user can access the socket.
    ///
    /// # Errors
    ///
    /// Returns an error if the socket path cannot be resolved, the stale socket cannot be removed,
    /// binding fails, or permissions cannot be set.
    pub(crate) fn new() -> Result<Self> {
        let socket_path = get_socket_path()?;
        Self::bind_at(&socket_path)
    }

    /// WardenFuse patch: binds to an explicit socket path.
    ///
    /// The parent directory is created with mode `0o700` if missing and must be owned by the
    /// current user and not be accessible by group/other. A pre-existing path is only removed if
    /// it is a socket (never a regular file, directory or symlink).
    pub(crate) fn bind_at(socket_path: &Path) -> Result<Self> {
        let socket_path = socket_path.to_path_buf();
        prepare_socket_dir(&socket_path)?;
        remove_stale_socket(&socket_path)?;

        debug!(?socket_path, "Binding socket");

        let listener = tokio::net::UnixListener::bind(&socket_path)
            .map_err(|e| anyhow!("Unable to bind to socket {}: {e}", socket_path.display()))?;

        set_user_permissions(&socket_path)?;

        info!(?socket_path, "socket listener ready");

        Ok(Self { inner: listener })
    }
}

#[async_trait::async_trait]
impl Listener for UnixListener {
    type Stream = UnixStream;

    async fn accept(&mut self) -> Result<Connection<Self::Stream>> {
        let (stream, _addr) = self.inner.accept().await?;

        // WardenFuse patch: reject connections from other users, using the kernel-provided
        // peer credentials (LOCAL_PEERCRED). The socket permissions already prevent this, this
        // is defense in depth. Returning an error drops (closes) the stream.
        let cred = stream.peer_cred()?;
        // SAFETY: geteuid is always successful and has no side effects.
        let own_uid = unsafe { libc::geteuid() };
        if cred.uid() != own_uid {
            return Err(anyhow!(
                "Rejected SSH agent connection from foreign uid {}",
                cred.uid()
            ));
        }

        let peer_info = get_peer_info(&stream);

        Ok(Connection { stream, peer_info })
    }
}

// Gathers peer process info from a connected Unix stream's credentials.
//
// TODO: PM-30755 Add test coverage for peer info gathering once the connection handler
// is implemented and `PeerInfo` is observable via the SSH protocol exchange.
fn get_peer_info(stream: &UnixStream) -> Option<PeerInfo> {
    let pid = stream
        .peer_cred()
        .ok()
        .and_then(|cred| cred.pid())
        .and_then(|pid| u32::try_from(pid).ok())?;

    PeerInfo::from_pid(pid)
}

fn get_socket_path() -> Result<PathBuf> {
    if let Ok(path) = std::env::var(ENV_BITWARDEN_SSH_AUTH_SOCK) {
        Ok(PathBuf::from(path))
    } else {
        debug!(
            socket_path_env_var = ENV_BITWARDEN_SSH_AUTH_SOCK,
            "not set, using default path"
        );
        get_default_socket_path()
    }
}

fn is_flatpak() -> bool {
    std::env::var("container") == Ok("flatpak".to_string())
}

fn get_default_socket_path() -> Result<PathBuf> {
    let Ok(Some(mut home)) = homedir::my_home() else {
        error!("Could not determine home directory");
        return Err(anyhow!("Could not determine home directory"));
    };

    if is_flatpak() {
        home = home.join(FLATPAK_DATA_DIR);
    }

    Ok(home.join(SOCKFILE_NAME))
}

fn set_user_permissions(path: &PathBuf) -> Result<()> {
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).map_err(|e| {
        anyhow!(
            "Could not set socket permissions for {}: {e}",
            path.display()
        )
    })
}

fn remove_stale_socket(path: &PathBuf) -> Result<()> {
    // WardenFuse patch: only ever remove an existing *socket*; refuse to touch anything else
    // (e.g. a symlink planted at the socket path).
    match fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_socket() => std::fs::remove_file(path)
            .map_err(|e| anyhow!("Error removing stale socket {}: {e}", path.display())),
        #[cfg(test)]
        Ok(meta) if meta.file_type().is_file() => std::fs::remove_file(path)
            .map_err(|e| anyhow!("Error removing stale socket {}: {e}", path.display())),
        Ok(_) => Err(anyhow!(
            "Refusing to replace non-socket file at {}",
            path.display()
        )),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(anyhow!("Unable to inspect {}: {e}", path.display())),
    }
}

/// WardenFuse patch: ensure the socket directory exists, is owned by us and is private.
fn prepare_socket_dir(socket_path: &Path) -> Result<()> {
    let Some(dir) = socket_path.parent() else {
        return Err(anyhow!("Socket path has no parent directory"));
    };
    if !dir.exists() {
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)
            .map_err(|e| anyhow!("Unable to create socket directory {}: {e}", dir.display()))?;
    }
    let meta = fs::symlink_metadata(dir)
        .map_err(|e| anyhow!("Unable to inspect socket directory {}: {e}", dir.display()))?;
    if !meta.is_dir() {
        return Err(anyhow!("Socket directory {} is not a directory", dir.display()));
    }
    // SAFETY: geteuid is always successful and has no side effects.
    let own_uid = unsafe { libc::geteuid() };
    if meta.uid() != own_uid {
        return Err(anyhow!(
            "Socket directory {} is not owned by the current user",
            dir.display()
        ));
    }
    if meta.mode() & 0o022 != 0 {
        return Err(anyhow!(
            "Socket directory {} is writable by group or others",
            dir.display()
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use rand::{distr::Alphanumeric, Rng};

    use super::*;

    #[test]
    #[serial_test::serial]
    fn test_default_socket_path_success() {
        let path = get_default_socket_path().unwrap();
        let expected =
            PathBuf::from_iter([std::env::var("HOME").unwrap(), SOCKFILE_NAME.to_string()]);
        assert_eq!(path, expected);
    }

    #[test]
    #[serial_test::serial]
    fn test_socket_path_env_var_override() {
        let custom_path = "/tmp/bw-ssh-agent-custom-test.sock";
        // SAFETY: tests touching env vars are serialized via #[serial]
        unsafe { std::env::set_var(ENV_BITWARDEN_SSH_AUTH_SOCK, custom_path) };

        let path = get_socket_path().unwrap();

        unsafe { std::env::remove_var(ENV_BITWARDEN_SSH_AUTH_SOCK) };
        assert_eq!(path, PathBuf::from(custom_path));
    }

    #[test]
    #[serial_test::serial]
    fn test_default_socket_path_flatpak() {
        // SAFETY: tests touching env vars are serialized via #[serial]
        unsafe { std::env::set_var("container", "flatpak") };

        let path = get_default_socket_path().unwrap();

        unsafe { std::env::remove_var("container") };
        let expected = PathBuf::from_iter([
            std::env::var("HOME").unwrap(),
            FLATPAK_DATA_DIR.to_string(),
            SOCKFILE_NAME.to_string(),
        ]);
        assert_eq!(path, expected);
    }

    fn rand_path_in_temp() -> PathBuf {
        let mut path = std::env::temp_dir();
        let s: String = rand::rng()
            .sample_iter(&Alphanumeric)
            .take(16)
            .map(char::from)
            .collect();
        path.push(s);
        path
    }

    #[tokio::test]
    async fn test_get_peer_info_connected_stream_returns_some() {
        // UnixStream::pair() creates a connected socketpair; peer_cred() on either end
        // returns the credentials of the creating process (this test process).
        let (stream, _peer) = tokio::net::UnixStream::pair().unwrap();

        let peer_info = get_peer_info(&stream);

        assert!(peer_info.is_some());
    }

    #[test]
    fn test_remove_stale_socket_exists() {
        let path = rand_path_in_temp();
        fs::write(&path, "").unwrap();
        remove_stale_socket(&path).unwrap();
        assert!(!fs::exists(&path).unwrap());
    }

    #[test]
    fn test_remove_stale_socket_not_found() {
        let path = rand_path_in_temp();
        remove_stale_socket(&path).unwrap();
        assert!(!fs::exists(&path).unwrap());
    }

    #[test]
    fn test_set_user_permissions() {
        let path = rand_path_in_temp();
        fs::write(&path, "").unwrap();

        set_user_permissions(&path).unwrap();

        let permissions = fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(permissions, 0o100_600);

        remove_stale_socket(&path).unwrap();
    }
}
