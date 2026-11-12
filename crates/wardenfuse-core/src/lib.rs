//! WardenFuse core library.
//!
//! Linked as a static library into `WardenFuse.app` (single process). Contains all business
//! logic; the SwiftUI layer only renders state and provides Keychain / LocalAuthentication.

mod android;
pub mod authz;
pub mod bitwarden;
pub mod browser;
pub mod clock;
pub mod config;
pub mod ffi;
pub mod peer;
pub mod platform;
pub mod service;
pub mod ssh;
pub mod ssh_config;
pub mod vault;
