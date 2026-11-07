//! End-to-end tests of the SSH agent with the system OpenSSH client tools.
//!
//! Uses the vendored upstream agent server, WardenFuse's gated key store and approver, a mock
//! authenticator (stands in for Touch ID + Keychain) and a mock monotonic clock.

#![allow(clippy::unwrap_used, clippy::cast_possible_truncation)]

use std::{
    path::{Path, PathBuf},
    process::Command,
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};

use async_trait::async_trait;
use ssh_agent::SSHKeyData;
use wardenfuse_core::{
    authz::{ApprovalPolicy, Authorizations, ScopeMode},
    clock::MockClock,
    platform::{AuthFailure, AuthPurpose},
    ssh::{parse_public_key, GatedKeyStore, MetaKeyData, SshAgentService, UnlockTarget, Unlocker},
};

const PEM: &str = "-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACAOYor3+kyAsXYs2sGikmUuhpxmVf2hAGd2TK7KwN4N9gAAAJj79ujB+/bo
wQAAAAtzc2gtZWQyNTUxOQAAACAOYor3+kyAsXYs2sGikmUuhpxmVf2hAGd2TK7KwN4N9g
AAAEAgAQkLDKjON00XO+Y09BoIBuQsAXAx6HUhQoTEodVzig5iivf6TICxdizawaKSZS6G
nGZV/aEAZ3ZMrsrA3g32AAAAEHRlc3RAZXhhbXBsZS5jb20BAgMEBQ==
-----END OPENSSH PRIVATE KEY-----";
const PUB: &str =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIA5iivf6TICxdizawaKSZS6GnGZV/aEAZ3ZMrsrA3g32";

struct MockUnlocker {
    store: GatedKeyStore,
    prompts: AtomicUsize,
    allow: AtomicBool,
    delay: Duration,
    ttl: u64,
    purposes: Mutex<Vec<AuthPurpose>>,
}

#[async_trait]
impl Unlocker for MockUnlocker {
    async fn unlock(&self, purpose: AuthPurpose, target: UnlockTarget) -> Result<(), AuthFailure> {
        self.prompts.fetch_add(1, Ordering::SeqCst);
        self.purposes.lock().unwrap().push(purpose);
        tokio::time::sleep(self.delay).await;
        if !self.allow.load(Ordering::SeqCst) {
            return Err(AuthFailure::Cancelled);
        }
        if matches!(target, UnlockTarget::Key { .. } | UnlockTarget::AllKeys) {
            let k = SSHKeyData::from_private_key_pem(PEM, "Test key".into(), "c1".into()).unwrap();
            self.store.insert_private(k).unwrap();
        }
        Ok(())
    }
    fn grants_changed(&self) {}
    fn allow_forwarding(&self) -> bool {
        false
    }
    fn ttl_secs(&self) -> u64 {
        self.ttl
    }
}

struct Env {
    _dir: tempfile::TempDir,
    sock: PathBuf,
    clock: MockClock,
    store: GatedKeyStore,
    unlocker: Arc<MockUnlocker>,
    _agent: SshAgentService<MockUnlocker>,
    pubfile: PathBuf,
}

fn setup(ttl: u64, delay: Duration) -> Env {
    let dir = tempfile::Builder::new()
        .prefix("wf")
        .tempdir_in("/tmp")
        .unwrap();
    let sock = dir.path().join("agent/s.sock");
    let clock = MockClock::new();
    let authz = Authorizations::new(
        Arc::new(clock.clone()),
        Duration::from_secs(ttl),
        ApprovalPolicy::CacheForTtl,
        ScopeMode::KeyAndProcess,
    );
    let store = GatedKeyStore::new(Arc::new(Mutex::new(authz)));
    store.set_usable(true);
    store.set_metadata(vec![MetaKeyData {
        public_key: parse_public_key(PUB).unwrap(),
        name: "Test key".into(),
        cipher_id: "c1".into(),
    }]);
    let unlocker = Arc::new(MockUnlocker {
        store: store.clone(),
        prompts: AtomicUsize::new(0),
        allow: AtomicBool::new(true),
        delay,
        ttl,
        purposes: Mutex::new(vec![]),
    });
    let mut agent = SshAgentService::new(store.clone(), unlocker.clone());
    agent.start(sock.clone()).unwrap();
    let pubfile = dir.path().join("key.pub");
    std::fs::write(&pubfile, format!("{PUB} test\n")).unwrap();
    Env {
        _dir: dir,
        sock,
        clock,
        store,
        unlocker,
        _agent: agent,
        pubfile,
    }
}

async fn run(
    cmd: &str,
    args: Vec<String>,
    sock: &Path,
    stdin: Option<&[u8]>,
) -> std::process::Output {
    let cmd = cmd.to_owned();
    let sock = sock.to_owned();
    let stdin = stdin.map(<[u8]>::to_vec);
    tokio::task::spawn_blocking(move || {
        use std::io::Write;
        let mut c = Command::new(cmd)
            .args(args)
            .env("SSH_AUTH_SOCK", sock)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        if let Some(i) = stdin {
            c.stdin.take().unwrap().write_all(&i).unwrap();
        }
        drop(c.stdin.take());
        c.wait_with_output().unwrap()
    })
    .await
    .unwrap()
}

/// `ssh-keygen -Y sign` = Git commit signing path (SSHSIG, namespace "git").
async fn git_sign(env: &Env) -> bool {
    let out = run(
        "ssh-keygen",
        vec![
            "-Y".into(),
            "sign".into(),
            "-n".into(),
            "git".into(),
            "-f".into(),
            env.pubfile.to_string_lossy().into(),
        ],
        &env.sock,
        Some(b"commit payload"),
    )
    .await;
    out.status.success() && String::from_utf8_lossy(&out.stdout).contains("BEGIN SSH SIGNATURE")
}

fn prompts(env: &Env) -> usize {
    env.unlocker.prompts.load(Ordering::SeqCst)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ssh_add_lists_keys_and_socket_is_private() {
    let env = setup(600, Duration::ZERO);
    let out = run("ssh-add", vec!["-L".into()], &env.sock, None).await;
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(s.contains(PUB), "{s}");
    assert!(s.contains("Test key"));
    use std::os::unix::fs::PermissionsExt;
    let mode = std::fs::metadata(&env.sock).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);
    let dmode = std::fs::metadata(env.sock.parent().unwrap())
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(dmode, 0o700);
    assert_eq!(
        prompts(&env),
        0,
        "listing does not prompt when allowed while locked"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ttl_caches_then_expires_and_is_not_extended() {
    let env = setup(600, Duration::ZERO);
    assert!(git_sign(&env).await);
    assert_eq!(prompts(&env), 1, "first signature requires authentication");
    match &env.unlocker.purposes.lock().unwrap()[0] {
        AuthPurpose::SshSign {
            usage,
            process_name,
            ttl_secs,
            ..
        } => {
            assert_eq!(usage, "git");
            assert_eq!(process_name.as_deref(), Some("ssh-keygen"));
            assert_eq!(*ttl_secs, 600);
        }
        p => panic!("unexpected purpose {p:?}"),
    }
    for _ in 0..3 {
        env.clock.advance(Duration::from_secs(150));
        assert!(git_sign(&env).await);
    }
    assert_eq!(prompts(&env), 1, "within 10 minutes no re-authentication");
    env.clock.advance(Duration::from_secs(150)); // 600s after authentication
    assert!(git_sign(&env).await);
    assert_eq!(prompts(&env), 2, "signing did not extend the TTL");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ttl_zero_prompts_every_time() {
    let env = setup(0, Duration::ZERO);
    assert!(git_sign(&env).await);
    assert!(git_sign(&env).await);
    assert_eq!(prompts(&env), 2);
    assert_eq!(env.store.private_count(), 0, "no key material retained");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancel_denies_signature() {
    let env = setup(600, Duration::ZERO);
    env.unlocker.allow.store(false, Ordering::SeqCst);
    assert!(!git_sign(&env).await);
    assert_eq!(env.store.private_count(), 0);
    env.unlocker.allow.store(true, Ordering::SeqCst);
    assert!(git_sign(&env).await);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn lock_revokes_authorization() {
    let env = setup(600, Duration::ZERO);
    assert!(git_sign(&env).await);
    env.store.authz().lock().unwrap().revoke_all();
    env.store.purge_all_private();
    assert!(git_sign(&env).await);
    assert_eq!(prompts(&env), 2);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_requests_share_one_authentication_per_scope() {
    let env = Arc::new(setup(600, Duration::from_millis(300)));
    let mut tasks = vec![];
    for _ in 0..4 {
        let e = env.clone();
        tasks.push(tokio::spawn(async move { git_sign(&e).await }));
    }
    for t in tasks {
        assert!(t.await.unwrap());
    }
    assert_eq!(prompts(&env), 1, "same key + same executable = one prompt");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_requests_with_ttl_zero_cannot_bypass() {
    let env = Arc::new(setup(0, Duration::from_millis(100)));
    let mut tasks = vec![];
    for _ in 0..3 {
        let e = env.clone();
        tasks.push(tokio::spawn(async move { git_sign(&e).await }));
    }
    for t in tasks {
        assert!(t.await.unwrap());
    }
    assert_eq!(
        prompts(&env),
        3,
        "every signature authenticated individually"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn removed_key_cannot_sign() {
    let env = setup(600, Duration::ZERO);
    assert!(git_sign(&env).await);
    env.store.set_metadata(vec![]);
    assert!(!git_sign(&env).await);
    let out = run("ssh-add", vec!["-L".into()], &env.sock, None).await;
    assert!(!String::from_utf8_lossy(&out.stdout).contains(PUB));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unusable_store_denies_everything() {
    let env = setup(600, Duration::ZERO);
    env.store.set_usable(false);
    assert!(!git_sign(&env).await);
    assert_eq!(prompts(&env), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn signature_verifies() {
    let env = setup(600, Duration::ZERO);
    let out = run(
        "ssh-keygen",
        vec![
            "-Y".into(),
            "sign".into(),
            "-n".into(),
            "file".into(),
            "-f".into(),
            env.pubfile.to_string_lossy().into(),
        ],
        &env.sock,
        Some(b"hello"),
    )
    .await;
    assert!(out.status.success());
    let dir = env.pubfile.parent().unwrap();
    std::fs::write(dir.join("sig"), &out.stdout).unwrap();
    std::fs::write(dir.join("allowed"), format!("test@example.com {PUB}\n")).unwrap();
    let v = run(
        "ssh-keygen",
        vec![
            "-Y".into(),
            "verify".into(),
            "-f".into(),
            dir.join("allowed").to_string_lossy().into(),
            "-I".into(),
            "test@example.com".into(),
            "-n".into(),
            "file".into(),
            "-s".into(),
            dir.join("sig").to_string_lossy().into(),
        ],
        &env.sock,
        Some(b"hello"),
    )
    .await;
    assert!(v.status.success(), "{}", String::from_utf8_lossy(&v.stderr));
}

mod core_service {
    use std::sync::Arc;

    use async_trait::async_trait;
    use wardenfuse_core::{
        platform::{AuthFailure, AuthRequest, BiometryState, Platform},
        service::{Core, CoreConfig},
    };
    use zeroize::Zeroizing;

    struct NullPlatform;
    #[async_trait]
    impl Platform for NullPlatform {
        async fn authenticate(&self, _r: AuthRequest) -> Result<Zeroizing<Vec<u8>>, AuthFailure> {
            Err(AuthFailure::Cancelled)
        }
        fn store_user_key(&self, _u: &str, _k: &[u8]) -> anyhow::Result<()> {
            Ok(())
        }
        fn delete_user_key(&self, _u: &str) {}
        fn store_session(&self, _d: &[u8]) -> anyhow::Result<()> {
            Ok(())
        }
        fn load_session(&self) -> Option<Zeroizing<Vec<u8>>> {
            None
        }
        fn delete_session(&self) {}
        fn biometry_state(&self) -> BiometryState {
            BiometryState::Unavailable
        }
        fn state_changed(&self, _s: String) {}
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn second_instance_is_refused_and_settings_are_validated() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = CoreConfig {
            data_dir: dir.path().join("data"),
            nmh_path: "/nonexistent/wardenfuse-nmh".into(),
            keychain_mode: String::new(),
        };
        // Services disabled up front so the test never touches the real ~/.wardenfuse sockets.
        std::fs::create_dir_all(&cfg.data_dir).unwrap();
        std::fs::write(
            cfg.data_dir.join("settings.json"),
            r#"{"ssh_agent_enabled": false, "browser_unlock_enabled": false}"#,
        )
        .unwrap();
        let first = Core::start(cfg.clone(), Arc::new(NullPlatform))
            .await
            .unwrap();
        assert!(Core::start(cfg, Arc::new(NullPlatform)).await.is_err());

        // Logged out: state is reported and invalid settings are rejected by the core.
        let state = first.command(serde_json::json!({"cmd": "get_state"})).await;
        assert_eq!(state["account"]["logged_in"], false);
        let mut s = state["settings"].clone();
        s["ssh_ttl_secs"] = serde_json::json!(999_999);
        let r = first
            .command(serde_json::json!({"cmd": "update_settings", "settings": s}))
            .await;
        assert_eq!(r["ok"], false);
        let mut s = state["settings"].clone();
        s["ssh_ttl_secs"] = serde_json::json!(60);
        let r = first
            .command(serde_json::json!({"cmd": "update_settings", "settings": s}))
            .await;
        assert_eq!(r["ok"], true, "{r}");
        assert_eq!(r["settings"]["ssh_ttl_secs"], 60);
        first.shutdown().await;
    }
}
