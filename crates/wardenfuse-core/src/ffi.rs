//! Thin C ABI between the SwiftUI app and the core (same process).
//!
//! * Commands: `wf_command(id, json)`, answered asynchronously via `command_result`.
//! * State: pushed via `state_changed` whenever it changes (no polling).
//! * Authentication: `auth_request(id, json)` asks Swift to authenticate and read the protected
//!   Keychain item; Swift answers with `wf_auth_complete(id, status, bytes, len)`.
//!
//! All strings are UTF-8, NUL terminated, and only valid during the call.

use std::{
    collections::HashMap,
    ffi::{c_char, c_void, CStr, CString},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex, OnceLock,
    },
};

use async_trait::async_trait;
use tokio::sync::oneshot;
use zeroize::Zeroizing;

use crate::{
    platform::{AuthFailure, AuthRequest, BiometryState, Platform},
    service::{Core, CoreConfig},
};

#[repr(C)]
#[derive(Clone, Copy)]
pub struct WFCallbacks {
    pub ctx: *mut c_void,
    pub state_changed: extern "C" fn(ctx: *mut c_void, json: *const c_char),
    pub command_result: extern "C" fn(ctx: *mut c_void, id: u64, json: *const c_char),
    pub auth_request: extern "C" fn(ctx: *mut c_void, id: u64, json: *const c_char),
    /// Stores `data` under `account`. `protected_item` = user presence required. Returns 0 on
    /// success, an OSStatus otherwise.
    pub keychain_store: extern "C" fn(
        ctx: *mut c_void,
        account: *const c_char,
        data: *const u8,
        len: usize,
        protected_item: bool,
    ) -> i32,
    /// Loads an unprotected item. On success writes a `malloc`ed buffer to `out`, which the
    /// core zeroizes and `free`s.
    pub keychain_load: extern "C" fn(
        ctx: *mut c_void,
        account: *const c_char,
        out: *mut *mut u8,
        out_len: *mut usize,
    ) -> i32,
    pub keychain_delete: extern "C" fn(ctx: *mut c_void, account: *const c_char),
    /// 0 = available, 1 = not enrolled, 2 = unavailable.
    pub biometry_state: extern "C" fn(ctx: *mut c_void) -> i32,
}

impl WFCallbacks {
    fn send_result(&self, id: u64, json: &str) {
        let c = cstring(json);
        (self.command_result)(self.ctx, id, c.as_ptr());
    }
}

// SAFETY: the Swift side guarantees that the callbacks and `ctx` are thread safe (they hop to
// the main actor where needed) and live for the whole process lifetime.
unsafe impl Send for WFCallbacks {}
unsafe impl Sync for WFCallbacks {}

type AuthReply = oneshot::Sender<Result<Zeroizing<Vec<u8>>, AuthFailure>>;

struct FfiPlatform {
    cb: WFCallbacks,
    next_auth: AtomicU64,
    pending: Mutex<HashMap<u64, AuthReply>>,
}

fn cstring(s: &str) -> CString {
    CString::new(s.replace('\0', "")).unwrap_or_default()
}

#[async_trait]
impl Platform for FfiPlatform {
    async fn authenticate(&self, request: AuthRequest) -> Result<Zeroizing<Vec<u8>>, AuthFailure> {
        let id = self.next_auth.fetch_add(1, Ordering::SeqCst);
        let (tx, rx) = oneshot::channel();
        self.pending
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(id, tx);
        let json = serde_json::to_string(&request).map_err(|_| AuthFailure::Failed)?;
        let c = cstring(&json);
        (self.cb.auth_request)(self.cb.ctx, id, c.as_ptr());
        let res = rx.await.unwrap_or(Err(AuthFailure::UiUnavailable));
        if res.is_err() {
            self.pending
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .remove(&id);
        }
        res
    }

    fn store_user_key(&self, user_id: &str, key: &[u8]) -> anyhow::Result<()> {
        let acct = cstring(&format!("userkey.{user_id}"));
        let rc =
            (self.cb.keychain_store)(self.cb.ctx, acct.as_ptr(), key.as_ptr(), key.len(), true);
        if rc == 0 {
            Ok(())
        } else {
            Err(anyhow::anyhow!("Keychain error {rc}"))
        }
    }

    fn delete_user_key(&self, user_id: &str) {
        let acct = cstring(&format!("userkey.{user_id}"));
        (self.cb.keychain_delete)(self.cb.ctx, acct.as_ptr());
    }

    fn store_session(&self, data: &[u8]) -> anyhow::Result<()> {
        let acct = cstring("session");
        let rc =
            (self.cb.keychain_store)(self.cb.ctx, acct.as_ptr(), data.as_ptr(), data.len(), false);
        if rc == 0 {
            Ok(())
        } else {
            Err(anyhow::anyhow!("Keychain error {rc}"))
        }
    }

    fn load_session(&self) -> Option<Zeroizing<Vec<u8>>> {
        let acct = cstring("session");
        let mut out: *mut u8 = std::ptr::null_mut();
        let mut len = 0usize;
        let rc = (self.cb.keychain_load)(self.cb.ctx, acct.as_ptr(), &mut out, &mut len);
        if rc != 0 || out.is_null() {
            return None;
        }
        // SAFETY: Swift returns a malloc'ed buffer of `len` bytes that we now own.
        let v = unsafe {
            let slice = std::slice::from_raw_parts_mut(out, len);
            let v = Zeroizing::new(slice.to_vec());
            zeroize::Zeroize::zeroize(slice);
            libc::free(out.cast());
            v
        };
        Some(v)
    }

    fn delete_session(&self) {
        let acct = cstring("session");
        (self.cb.keychain_delete)(self.cb.ctx, acct.as_ptr());
    }

    fn biometry_state(&self) -> BiometryState {
        match (self.cb.biometry_state)(self.cb.ctx) {
            0 => BiometryState::Available,
            1 => BiometryState::NotEnrolled,
            _ => BiometryState::Unavailable,
        }
    }

    fn state_changed(&self, snapshot_json: String) {
        let c = cstring(&snapshot_json);
        (self.cb.state_changed)(self.cb.ctx, c.as_ptr());
    }
}

struct Global {
    runtime: tokio::runtime::Runtime,
    core: Core,
    platform: Arc<FfiPlatform>,
    cb: WFCallbacks,
}

static GLOBAL: OnceLock<Global> = OnceLock::new();

fn init_logging() {
    use tracing_subscriber::{fmt, EnvFilter};
    let filter =
        EnvFilter::try_from_env("WARDENFUSE_LOG").unwrap_or_else(|_| EnvFilter::new("info"));
    // Logs go to stderr (unified log via the app). Secrets are never logged.
    let _ = fmt()
        .with_env_filter(filter)
        .with_target(false)
        .with_ansi(false)
        .try_init();
}

/// Starts the core. Returns false if already started or on error.
///
/// # Safety
/// `config_json` must be a valid NUL-terminated string. `callbacks` must stay valid for the
/// lifetime of the process.
#[no_mangle]
pub unsafe extern "C" fn wf_start(config_json: *const c_char, callbacks: WFCallbacks) -> bool {
    if GLOBAL.get().is_some() || config_json.is_null() {
        return false;
    }
    init_logging();
    // SAFETY: caller guarantees a valid C string.
    let Ok(cfg_str) = (unsafe { CStr::from_ptr(config_json) }).to_str() else {
        return false;
    };
    let Ok(cfg) = serde_json::from_str::<CoreConfig>(cfg_str) else {
        return false;
    };
    // Two workers are plenty for an agent + sync; blocking pool kept small as well.
    let Ok(runtime) = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .max_blocking_threads(2)
        .thread_name("wardenfuse-core")
        .enable_all()
        .build()
    else {
        return false;
    };
    let platform = Arc::new(FfiPlatform {
        cb: callbacks,
        next_auth: AtomicU64::new(1),
        pending: Mutex::new(HashMap::new()),
    });
    let p: Arc<dyn Platform> = platform.clone();
    let core = match runtime.block_on(Core::start(cfg, p)) {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(error = %e, "Core failed to start");
            return false;
        }
    };
    GLOBAL
        .set(Global {
            runtime,
            core,
            platform,
            cb: callbacks,
        })
        .is_ok()
}

/// Runs a JSON command asynchronously; the result is delivered through `command_result`.
///
/// # Safety
/// `json` must be a valid NUL-terminated string.
#[no_mangle]
pub unsafe extern "C" fn wf_command(id: u64, json: *const c_char) {
    let Some(g) = GLOBAL.get() else { return };
    if json.is_null() {
        return;
    }
    // SAFETY: caller guarantees a valid C string. Copy before returning.
    let s = Zeroizing::new(
        unsafe { CStr::from_ptr(json) }
            .to_string_lossy()
            .into_owned(),
    );
    let core = g.core.clone();
    let cb = g.cb;
    g.runtime.spawn(async move {
        let v: serde_json::Value = serde_json::from_str(&s).unwrap_or_default();
        drop(s);
        let out = core.command(v).await;
        cb.send_result(id, &out.to_string());
    });
}

/// Completes an authentication request. `status`: 0 = success (key provided), 1 = cancelled,
/// 2 = failed, 3 = unavailable, 4 = key missing, 5 = UI unavailable, 6 = timed out.
///
/// # Safety
/// `key` must point to `len` readable bytes (or be null with `len == 0`).
#[no_mangle]
pub unsafe extern "C" fn wf_auth_complete(id: u64, status: i32, key: *const u8, len: usize) {
    let Some(g) = GLOBAL.get() else { return };
    let tx = g
        .platform
        .pending
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .remove(&id);
    let Some(tx) = tx else { return };
    let res = match status {
        0 if !key.is_null() && len > 0 => {
            // SAFETY: caller guarantees `len` readable bytes.
            Ok(Zeroizing::new(
                unsafe { std::slice::from_raw_parts(key, len) }.to_vec(),
            ))
        }
        1 => Err(AuthFailure::Cancelled),
        3 => Err(AuthFailure::Unavailable),
        4 => Err(AuthFailure::KeyMissing),
        5 => Err(AuthFailure::UiUnavailable),
        6 => Err(AuthFailure::Timeout),
        _ => Err(AuthFailure::Failed),
    };
    let _ = tx.send(res);
}

/// Synchronous shutdown: stops the SSH agent, the browser bridge and sync, removes sockets
/// and drops key material.
#[no_mangle]
pub extern "C" fn wf_shutdown() {
    let Some(g) = GLOBAL.get() else { return };
    let core = g.core.clone();
    g.runtime.block_on(async move { core.shutdown().await });
}
