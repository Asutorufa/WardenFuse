# WardenFuse architecture

## Processes

```
WardenFuse.app  (one resident process, LSUIElement menu bar app)
├── SwiftUI / AppKit (main thread)
│   ├── MenuBarExtra (.window), Settings scene, Login window — created on demand
│   ├── AuthCoordinator: system LAContext dialog only, Keychain reads (SecAccessControl)
│   ├── KeychainStore, SystemEvents (sleep / screen lock / user switch / network)
│   └── SMAppService.mainApp (Launch at Login — no LaunchAgent plist)
└── Rust core, static library (libwardenfuse_core.a), Tokio: 2 workers, ≤2 blocking
    ├── Bitwarden session: bitwarden-core (login), bitwarden-auth (token renewal),
    │   bitwarden-sync (SyncClient + SSH-only SyncHandler), in-memory StateRegistry
    ├── Notifications: SignalR (JSON) over WebSocket → "sync now" / "logged out"
    ├── Vault: encrypted SSH cipher cache, decryption with bitwarden-crypto KeyStore
    ├── SSH agent: vendored upstream BitwardenSSHAgent + GatedKeyStore + approver
    ├── Authorizations: fixed-TTL grants on a CLOCK_MONOTONIC clock
    └── Browser bridge: UDS ~/.wardenfuse/browser.sock
        ├── legacy native-messaging biometrics protocol (bitwarden-crypto)
        └── SDK IPC endpoint "DesktopRenderer" (bitwarden-ipc, Noise)

wardenfuse-nmh  (Contents/MacOS, started on demand by Chrome/Brave/Edge…, 400 KB, std only)
    stdin/stdout  ⇄  ~/.wardenfuse/browser.sock   (no secrets, no protocol logic)
```

There is no daemon, no LaunchAgent, no helper and no CLI. When the app is not running, the SSH
agent socket does not exist and the NMH replies `{"command":"disconnected"}`.

| State | SSH agent | Browser unlock |
|---|---|---|
| Menu bar popover closed / no windows | running | running |
| App quit (`wf_shutdown`) | stopped, socket removed, keys dropped | NMH reports disconnected |
| Agent locked | lists keys (configurable), every signature requires authentication | unaffected (always authenticates) |
| Logged out | lists nothing | `NotEnabledInConnectedDesktopApp` |

Automatic and sudden termination are disabled so macOS never reaps the resident agent.

## Swift ⇄ Rust

`crates/wardenfuse-core/include/wardenfuse.h`:

* `wf_command(id, json)` → async → `command_result(id, json)`
* `state_changed(json)`: the core pushes a complete snapshot when something changes
  (coalesced 30 ms). The UI never polls; the only timer is the TTL countdown, and only while
  the popover is open.
* `auth_request(id, json)` → Swift → `wf_auth_complete(id, status, key)`
* Keychain callbacks (`keychain_store/load/delete`), `biometry_state`.

The UI submits settings candidates; the core validates, persists (`settings.json`, 0600) and
reconciles running services, then pushes the resulting state.

## Bitwarden SDK reuse — decision record

Requirement: reuse the official SDK as much as possible while keeping idle memory low.

Options evaluated (measured with a probe binary: release, thin LTO, `opt-level=s`, stripped,
arm64, after one prelogin request against `identity.bitwarden.com`):

| | A. `bitwarden-core` + `bitwarden-sync` directly (full PM client) | **B. SDK via thin adapter (chosen)** | C. custom HTTP + `bitwarden-crypto` |
|---|---|---|---|
| Crates used | `bitwarden-pm` (vault, send, fido, exporters, …) | `bitwarden-core[internal]`, `bitwarden-auth`, `bitwarden-sync`, `bitwarden-state`, `bitwarden-api-api`, `bitwarden-crypto` | `bitwarden-crypto` + reqwest |
| Binary size (probe) | not built (superset of B) | **5.8 MB** | 3.8 MB |
| RSS / phys_footprint (probe) | not measured (estimate: B + vault state) | **9.8 MB / 2.8 MB** | 10.1 MB / 3.1 MB |
| Dependency crates | > B | 367 | 307 |
| Login / KDF / hash / 2FA / tokens | SDK | **SDK** | re-implemented |
| Follows server changes | best | **good** (same code paths as SDK) | manual |
| Maintenance | high (many unused subsystems to keep initialized) | low | high (protocol drift) |
| Security | SDK | **SDK** | own implementation of auth protocol |

Idle memory is the same within noise; B costs ~2 MB of binary. A would initialize vault,
folder, send, policy state and handlers WardenFuse never uses. **B** keeps all authentication,
KDF, master-password hashing, user-key decryption, token renewal and sync on official code and
registers exactly one `SyncHandler`.

What is still WardenFuse code, and why:

* **Notifications (SignalR client)** — the SDK has none. It only produces "sync now"/"logged out"
  signals; vault data always comes from the SDK sync.
* **SSH cipher extraction** — `bitwarden-vault` would pull the whole vault model. Decryption still
  uses `bitwarden_crypto::KeyStore` (`unwrap_symmetric_key`, `unwrap_private_key`,
  `UnsignedSharedKey::decapsulate`, `Decryptable`), i.e. official crypto, including V2 (COSE) keys.
* **SDK IPC biometrics RPC types** — upstream defines them only in the WASM module of
  `bitwarden-shared-unlock`; WardenFuse mirrors the four types with identical `NAME`s and serde
  shapes. Transport, Noise handshake, sessions, fragmentation and RPC are `bitwarden-ipc`.
* `bitwarden-ipc` is used with its `test-support` feature, which only re-exports
  `NoiseCryptoProvider` and the `CommunicationBackend` traits needed to host an endpoint outside
  WASM. No behaviour changes.

SDK limitations accepted:

* `login_password` has no "new device verification" OTP field. Accounts without two-step login
  that hit this check can use the personal API key login (`login_api_key`, also SDK).
* WebAuthn/Duo second factors are not supported (no UI for them in the SDK login flow).
* SSO / Trusted Device Encryption / Key Connector accounts are not supported.

The long-lived session client never has user crypto initialized: login runs on a short-lived
client, the user key is moved to the Keychain and that client (and its key store) is dropped.

## Key lifecycle

```
login (master password) ──SDK──▶ user key ──▶ Keychain item (SecAccessControl .userPresence)
                                           └─▶ decrypt key list once, then dropped

sign request ─▶ grant valid? ──yes──▶ sign (private key still in secure_memory store)
                    │no
                    ▼
        LAContext.evaluatePolicy (system dialog only)
                    ▼ context.interactionNotAllowed = true
        SecItemCopyMatching(kSecUseAuthenticationContext = evaluated context)
                    ▼ user key (only now in Rust memory, Zeroizing)
        decrypt this cipher's private key (bitwarden-crypto) → upstream InMemoryEncryptedKeyStore
        user key dropped; grant(key, executable) expires_at = now + TTL (monotonic)
                    ▼
        purge task removes private key when the last covering grant expires
```

`get_private_key` re-checks the grant with the clock (fail closed even if the purge task is
late). TTL 0 uses single-use authorizations valid for 30 s and purges immediately after use.

## Sync strategy

1. Restore session from Keychain + encrypted cache, then sync.
2. Notifications (cipher create/update/delete, vault sync, org keys) → forced sync.
3. Disconnect → exponential backoff (5 s … 5 min) and catch-up sync on reconnect.
4. Without notifications → fallback timer (default 5 min) using the SDK's revision-date check,
   so an idle check is one small request.
5. Manual "Sync Now"; wake / network-up restart notifications.

A new key set is applied atomically. Unchanged ciphers keep their metadata; changed/new ones
become visible after the next authentication; removed ones lose their grants and key material
immediately. A failed sync never discards data. If the last successful sync is older than the
configured maximum (default 72 h), the agent refuses to list or sign until a sync succeeds.

## Files

| Path | Content | Protection |
|---|---|---|
| Keychain `userkey.<user id>` | Bitwarden user key | user presence ACL (strong mode) |
| Keychain `session` | refresh/access token, login method, server, email | `WhenUnlockedThisDeviceOnly` |
| `~/Library/Application Support/WardenFuse/settings.json` | settings | 0600 |
| `…/vault-cache.json` | SSH ciphers **as EncStrings** + wrapped org/private keys | 0600, encrypted by Bitwarden keys |
| `~/.wardenfuse/ssh-agent.sock`, `browser.sock` | sockets | dir 0700, sockets 0600, peer uid check |
| `~/Library/Application Support/<Browser>/NativeMessagingHosts/com.8bit.bitwarden.json` | NMH manifest | official extension origins only |

## User interface

Standard SwiftUI components carry the design; WardenFuse adds no blur, vibrancy or custom
backgrounds of its own.

| Surface | Implementation | Liquid Glass |
|---|---|---|
| Menu bar | Real `NSMenu` on an `NSStatusItem` (system material, radius, highlight, key equivalents): native section headers and action items (Lock/Unlock, Sync Now, Settings… ⌘,, Quit ⌘Q); only the info rows (header, values, TTL countdown bar, sync pill) are embedded SwiftUI views, created when the menu opens and released when it closes | Drawn by the system; the header pill button uses `.glass` (capsule) |
| Settings | AppKit window like System Settings: `NSSplitViewController` with a sidebar item (no divider), content item without titlebar separator, `NSSearchField`, account row, colored icon tiles, back/forward toolbar group with pane title; SwiftUI header card + grouped `Form` per pane on the window background. Released on close | Sidebar, toolbar, search field and controls are rendered by the system |
| Login | AppKit-managed window with grouped `Form`, `@FocusState` field order, Return to submit, Esc to cancel | Footer buttons `.glass`/`.glassProminent` |
| Authentication | system LocalAuthentication dialog only | — |

Glass styles are applied through `glassButtonStyle()` / `GlassGroup`, which fall back to the
standard bordered styles below macOS 26. Reduce Transparency, Increase Contrast and Reduce Motion
are handled by the system materials; the app has no custom animations. The only periodically
updating views are `Text(timerInterval:)` (TTL countdown) and relative dates, rendered by the
system text engine while the menu is open — no app timers.
