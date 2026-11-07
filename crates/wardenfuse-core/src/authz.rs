//! SSH signing authorization grants with a fixed TTL.
//!
//! A [`Grant`] is created only after a successful Touch ID / macOS password authentication that
//! also released the protected Bitwarden user key from the Keychain. It allows signing requests
//! that fall inside its [`Scope`] until `expires_at`, which is fixed at creation time
//! (`authenticated_at + ttl`) and is **never** extended by signing.
//!
//! All decisions use the monotonic [`Clock`]; the UI only ever displays what this module says.

use std::{sync::Arc, time::Duration};

use crate::clock::{Clock, MonoTime};

/// Identity of an SSH key, the OpenSSH public key string (`alg base64`).
pub type KeyId = String;

/// Identity of a local requesting process.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ProcessId {
    /// Absolute executable path obtained from the kernel (`proc_pidpath` of the peer PID
    /// returned by `LOCAL_PEERCRED`).
    Executable(String),
    /// The peer process could not be identified. Requests from unidentified peers are never
    /// served from a cached grant.
    Unknown,
}

/// What a grant covers.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Scope {
    /// `None` = every key (only created by an explicit "Unlock Agent").
    pub key: Option<KeyId>,
    /// `None` = every local process (explicit "Unlock Agent", or `ScopeMode::Key`).
    pub process: Option<ProcessId>,
}

impl Scope {
    fn covers(&self, key: &str, process: &ProcessId) -> bool {
        let key_ok = self.key.as_deref().is_none_or(|k| k == key);
        let process_ok = match &self.process {
            None => true,
            Some(ProcessId::Unknown) => false,
            Some(p) => p == process && *process != ProcessId::Unknown,
        };
        key_ok && process_ok
    }

    fn covers_key(&self, key: &str) -> bool {
        self.key.as_deref().is_none_or(|k| k == key)
    }
}

/// Signing approval policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalPolicy {
    /// Always authenticate, never cache.
    EveryTime,
    /// Cache a successful authentication for the configured TTL.
    CacheForTtl,
}

/// How narrowly cached grants are scoped.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScopeMode {
    /// Key + requesting executable (default).
    KeyAndProcess,
    /// Key only; any local process of the same user may use the grant.
    Key,
}

#[derive(Debug, Clone)]
pub struct Grant {
    pub scope: Scope,
    pub expires_at: MonoTime,
}

/// The current set of grants.
pub struct Authorizations {
    clock: Arc<dyn Clock>,
    grants: Vec<Grant>,
    ttl: Duration,
    policy: ApprovalPolicy,
    scope_mode: ScopeMode,
}

impl Authorizations {
    pub fn new(
        clock: Arc<dyn Clock>,
        ttl: Duration,
        policy: ApprovalPolicy,
        mode: ScopeMode,
    ) -> Self {
        Self {
            clock,
            grants: Vec::new(),
            ttl,
            policy,
            scope_mode: mode,
        }
    }

    #[must_use]
    pub fn now(&self) -> MonoTime {
        self.clock.now()
    }

    /// Whether grants are cached at all with the current configuration.
    #[must_use]
    pub fn caching_enabled(&self) -> bool {
        self.policy == ApprovalPolicy::CacheForTtl && !self.ttl.is_zero()
    }

    /// Applies a new configuration. Any change to TTL, policy or scope mode revokes all
    /// existing grants, so that a shortened TTL or stricter policy is effective immediately.
    pub fn configure(&mut self, ttl: Duration, policy: ApprovalPolicy, mode: ScopeMode) {
        if ttl != self.ttl || policy != self.policy || mode != self.scope_mode {
            self.grants.clear();
        }
        self.ttl = ttl;
        self.policy = policy;
        self.scope_mode = mode;
    }

    fn prune(&mut self) {
        let now = self.clock.now();
        self.grants.retain(|g| now < g.expires_at);
    }

    /// Builds the scope for a request according to the configured scope mode.
    #[must_use]
    pub fn scope_for(&self, key: &str, process: &ProcessId) -> Scope {
        Scope {
            key: Some(key.to_owned()),
            process: match self.scope_mode {
                ScopeMode::KeyAndProcess => Some(process.clone()),
                ScopeMode::Key => None,
            },
        }
    }

    /// Is a signing request for `key` from `process` covered by a still-valid grant?
    pub fn is_authorized(&mut self, key: &str, process: &ProcessId) -> bool {
        self.prune();
        self.grants.iter().any(|g| g.scope.covers(key, process))
    }

    /// Is there any valid grant that covers `key` for some process?
    pub fn key_has_grant(&mut self, key: &str) -> bool {
        self.prune();
        self.grants.iter().any(|g| g.scope.covers_key(key))
    }

    /// Records a grant right after a successful authentication.
    ///
    /// Returns the expiry, or `None` when caching is disabled (TTL = 0 or "every time"). The
    /// expiry is computed from *now*, i.e. the authentication time, and is never extended.
    pub fn grant(&mut self, scope: Scope) -> Option<MonoTime> {
        if !self.caching_enabled() {
            return None;
        }
        if matches!(scope.process, Some(ProcessId::Unknown)) {
            // Never cache for an unidentified peer.
            return None;
        }
        let expires_at = self.clock.now().checked_add(self.ttl)?;
        self.prune();
        // Replacing an identical scope keeps exactly one grant per scope. Re-authentication is
        // the only way to get a new expiry.
        self.grants.retain(|g| g.scope != scope);
        self.grants.push(Grant { scope, expires_at });
        Some(expires_at)
    }

    pub fn revoke_all(&mut self) {
        self.grants.clear();
    }

    /// Revokes every grant that could cover `key` (including agent-wide grants, because the
    /// set of keys they were created for has changed).
    pub fn revoke_key(&mut self, key: &str) {
        self.grants
            .retain(|g| g.scope.key.as_deref().is_some_and(|k| k != key));
    }

    /// Earliest expiry among valid grants, used to schedule key material purging.
    pub fn next_expiry(&mut self) -> Option<MonoTime> {
        self.prune();
        self.grants.iter().map(|g| g.expires_at).min()
    }

    /// Remaining time of the longest-living grant (for display only).
    pub fn longest_remaining(&mut self) -> Option<Duration> {
        self.prune();
        let now = self.clock.now();
        self.grants.iter().map(|g| now.until(g.expires_at)).max()
    }

    pub fn active_count(&mut self) -> usize {
        self.prune();
        self.grants.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clock::MockClock;

    const K1: &str = "ssh-ed25519 AAAA1";
    const K2: &str = "ssh-ed25519 AAAA2";

    fn exe(p: &str) -> ProcessId {
        ProcessId::Executable(p.to_owned())
    }

    fn setup(ttl_secs: u64) -> (MockClock, Authorizations) {
        let clock = MockClock::new();
        let a = Authorizations::new(
            Arc::new(clock.clone()),
            Duration::from_secs(ttl_secs),
            ApprovalPolicy::CacheForTtl,
            ScopeMode::KeyAndProcess,
        );
        (clock, a)
    }

    #[test]
    fn grant_valid_for_ttl_then_expires() {
        let (clock, mut a) = setup(600);
        let ssh = exe("/usr/bin/ssh");
        assert!(!a.is_authorized(K1, &ssh));
        let scope = a.scope_for(K1, &ssh);
        assert!(a.grant(scope).is_some());
        assert!(a.is_authorized(K1, &ssh));
        clock.advance(Duration::from_secs(599));
        assert!(a.is_authorized(K1, &ssh));
        clock.advance(Duration::from_secs(1));
        assert!(
            !a.is_authorized(K1, &ssh),
            "exactly at expiry the grant is invalid"
        );
    }

    #[test]
    fn signing_does_not_extend_ttl() {
        let (clock, mut a) = setup(600);
        let ssh = exe("/usr/bin/ssh");
        let scope = a.scope_for(K1, &ssh);
        a.grant(scope);
        // Many successful checks (= signatures) must not move the expiry.
        for _ in 0..9 {
            clock.advance(Duration::from_secs(60));
            assert!(a.is_authorized(K1, &ssh));
        }
        clock.advance(Duration::from_secs(60));
        assert!(!a.is_authorized(K1, &ssh));
    }

    #[test]
    fn ttl_zero_never_caches() {
        let (_clock, mut a) = setup(0);
        let ssh = exe("/usr/bin/ssh");
        let scope = a.scope_for(K1, &ssh);
        assert!(a.grant(scope).is_none());
        assert!(!a.is_authorized(K1, &ssh));
    }

    #[test]
    fn every_time_policy_never_caches() {
        let (_clock, mut a) = setup(600);
        a.configure(
            Duration::from_secs(600),
            ApprovalPolicy::EveryTime,
            ScopeMode::KeyAndProcess,
        );
        let ssh = exe("/usr/bin/ssh");
        assert!(a.grant(a.scope_for(K1, &ssh)).is_none());
        assert!(!a.is_authorized(K1, &ssh));
    }

    #[test]
    fn scope_isolates_keys_and_processes() {
        let (_clock, mut a) = setup(600);
        let ssh = exe("/usr/bin/ssh");
        let git = exe("/usr/bin/ssh-keygen");
        a.grant(a.scope_for(K1, &ssh));
        assert!(a.is_authorized(K1, &ssh));
        assert!(!a.is_authorized(K2, &ssh), "other key");
        assert!(!a.is_authorized(K1, &git), "other process");
        assert!(!a.is_authorized(K1, &ProcessId::Unknown), "unknown process");
    }

    #[test]
    fn unknown_process_is_never_cached() {
        let (_clock, mut a) = setup(600);
        let scope = a.scope_for(K1, &ProcessId::Unknown);
        assert!(a.grant(scope).is_none());
        assert!(!a.is_authorized(K1, &ProcessId::Unknown));
    }

    #[test]
    fn key_scope_mode_shares_across_processes() {
        let (_clock, mut a) = setup(600);
        a.configure(
            Duration::from_secs(600),
            ApprovalPolicy::CacheForTtl,
            ScopeMode::Key,
        );
        a.grant(a.scope_for(K1, &exe("/usr/bin/ssh")));
        assert!(a.is_authorized(K1, &exe("/opt/homebrew/bin/git")));
        assert!(!a.is_authorized(K2, &exe("/usr/bin/ssh")));
    }

    #[test]
    fn config_change_revokes() {
        let (_clock, mut a) = setup(600);
        let ssh = exe("/usr/bin/ssh");
        a.grant(a.scope_for(K1, &ssh));
        a.configure(
            Duration::from_secs(60),
            ApprovalPolicy::CacheForTtl,
            ScopeMode::KeyAndProcess,
        );
        assert!(!a.is_authorized(K1, &ssh));
    }

    #[test]
    fn same_config_keeps_grants() {
        let (_clock, mut a) = setup(600);
        let ssh = exe("/usr/bin/ssh");
        a.grant(a.scope_for(K1, &ssh));
        a.configure(
            Duration::from_secs(600),
            ApprovalPolicy::CacheForTtl,
            ScopeMode::KeyAndProcess,
        );
        assert!(a.is_authorized(K1, &ssh));
    }

    #[test]
    fn revoke_key_and_all() {
        let (_clock, mut a) = setup(600);
        let ssh = exe("/usr/bin/ssh");
        a.grant(a.scope_for(K1, &ssh));
        a.grant(a.scope_for(K2, &ssh));
        a.grant(Scope {
            key: None,
            process: None,
        });
        a.revoke_key(K1);
        assert!(!a.is_authorized(K1, &ssh));
        assert!(a.is_authorized(K2, &ssh));
        a.revoke_all();
        assert!(!a.is_authorized(K2, &ssh));
    }

    #[test]
    fn regrant_does_not_extend_existing_but_replaces() {
        let (clock, mut a) = setup(600);
        let ssh = exe("/usr/bin/ssh");
        a.grant(a.scope_for(K1, &ssh));
        clock.advance(Duration::from_secs(300));
        // A new authentication (new Touch ID) creates a fresh expiry from *its* time.
        let exp = a.grant(a.scope_for(K1, &ssh)).unwrap();
        assert_eq!(a.now().until(exp), Duration::from_secs(600));
        assert_eq!(a.active_count(), 1);
    }

    #[test]
    fn next_expiry_and_remaining() {
        let (clock, mut a) = setup(600);
        a.grant(a.scope_for(K1, &exe("/a")));
        clock.advance(Duration::from_secs(100));
        a.grant(a.scope_for(K2, &exe("/a")));
        assert_eq!(a.longest_remaining(), Some(Duration::from_secs(600)));
        let next = a.next_expiry().unwrap();
        assert_eq!(a.now().until(next), Duration::from_secs(500));
    }
}
