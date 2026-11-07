//! Monotonic time source used for every authentication expiry decision.
//!
//! `std::time::Instant` on macOS is based on `CLOCK_UPTIME_RAW`, which does **not** advance
//! while the machine is asleep. Using it for authentication TTLs would silently extend an
//! authorization across a sleep period. We therefore use `CLOCK_MONOTONIC`, which on Darwin
//! is derived from `mach_continuous_time` and keeps counting during sleep, and is never
//! affected by wall-clock changes.

use std::{
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::Duration,
};

/// A monotonic point in time, expressed as the duration since an arbitrary fixed origin.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MonoTime(Duration);

impl MonoTime {
    #[must_use]
    pub fn from_duration(d: Duration) -> Self {
        Self(d)
    }

    #[must_use]
    pub fn checked_add(self, d: Duration) -> Option<Self> {
        self.0.checked_add(d).map(Self)
    }

    /// Time remaining until `later`, zero if `later` is in the past.
    #[must_use]
    pub fn until(self, later: MonoTime) -> Duration {
        later.0.saturating_sub(self.0)
    }
}

/// Abstract clock so that TTL logic can be tested deterministically.
pub trait Clock: Send + Sync + 'static {
    fn now(&self) -> MonoTime;
}

/// Production clock based on `CLOCK_MONOTONIC` (includes time spent asleep on macOS).
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> MonoTime {
        let mut ts = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        // SAFETY: `ts` is a valid, writable timespec. CLOCK_MONOTONIC is always available on the
        // supported platforms.
        let rc = unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
        if rc != 0 {
            // Fail closed: an unreadable clock maps to "far future", which makes every grant
            // appear expired (grants are only valid while `now < expires_at`).
            return MonoTime(Duration::MAX);
        }
        let secs = u64::try_from(ts.tv_sec).unwrap_or(0);
        let nanos = u32::try_from(ts.tv_nsec).unwrap_or(0);
        MonoTime(Duration::new(secs, nanos))
    }
}

/// Manually advanced clock for tests.
#[derive(Debug, Default, Clone)]
pub struct MockClock {
    nanos: Arc<AtomicU64>,
}

impl MockClock {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn advance(&self, d: Duration) {
        let n = u64::try_from(d.as_nanos()).unwrap_or(u64::MAX);
        self.nanos.fetch_add(n, Ordering::SeqCst);
    }
}

impl Clock for MockClock {
    fn now(&self) -> MonoTime {
        MonoTime(Duration::from_nanos(self.nanos.load(Ordering::SeqCst)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn system_clock_is_monotonic() {
        let c = SystemClock;
        let a = c.now();
        let b = c.now();
        assert!(b >= a);
        assert_ne!(a, MonoTime(Duration::MAX));
    }

    #[test]
    fn mock_clock_advances() {
        let c = MockClock::new();
        let a = c.now();
        c.advance(Duration::from_secs(5));
        assert_eq!(a.until(c.now()), Duration::from_secs(5));
        assert_eq!(c.now().until(a), Duration::ZERO);
    }
}
