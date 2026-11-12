# WardenFuse

A lightweight native Bitwarden biometric bridge and SSH agent for macOS.

> **WardenFuse is not an official Bitwarden product** and is not affiliated with or endorsed by
> Bitwarden, Inc. It reuses Bitwarden's open-source code under the GPL-3.0 (see
> [NOTICE.md](NOTICE.md)).

## Overview

WardenFuse gives you two Bitwarden Desktop features without running the Electron desktop app:

1. **Browser biometric unlock** — the *official, unmodified* Bitwarden browser extension
   (Chrome, Brave, Edge, Chromium, Vivaldi) unlocks with Touch ID, your macOS password,
   or a [paired Android device](docs/ANDROID.md).
2. **SSH agent** — the SSH keys stored in your Bitwarden vault are served by an
   OpenSSH-compatible agent, and every signature is authorized with Touch ID / macOS password,
   cached for a configurable time.

It is a single SwiftUI menu bar app with the logic in a Rust core linked into the same process.
SSH keys are managed in the official Bitwarden web vault; WardenFuse only reads them.

## Features

* Menu bar status: account, agent state, key count, authorization countdown, sync status;
  Lock / Unlock / Sync Now / Settings / Quit.
* Native Settings window (General, Bitwarden, Browser, SSH Agent, Security).
* Bitwarden login with master password + two-step login (authenticator app, email, YubiKey OTP)
  or personal API key; bitwarden.com, bitwarden.eu, self-hosted and Vaultwarden URLs.
* Automatic sync: live push notifications, reconnect with backoff, 5-minute fallback,
  sync on wake/network change, manual sync.
* SSH agent: `ssh-add -L`, public key authentication, Git over SSH, Git commit signing
  (`gpg.format ssh`), Ed25519, RSA (SHA-256/512), ECDSA P-256/384/521.
* Touch ID / macOS password for each signature with a fixed TTL (default 10 minutes).
* Browser unlock via both the legacy native-messaging channel and the new SDK IPC channel
  (feature flag `biometrics-sdk-ipc`).
* Launch at login with `SMAppService.mainApp`.
* Safe install / repair / removal of native messaging manifests and `~/.ssh/config`
  integration, never overwriting other apps' configuration without asking.

Not included by design: CLI, password management UI, SSH key editing, WebView/Electron UI,
custom browser extension, HTTP management server, background daemon.

## Architecture

```
WardenFuse.app (one process)                         wardenfuse-nmh (on demand, by the browser)
 ├─ SwiftUI menu bar / Settings / Login               stdin/stdout ⇄ ~/.wardenfuse/browser.sock
 ├─ LocalAuthentication + Keychain (Swift)
 └─ Rust core (static library)
     ├─ Bitwarden SDK: login, tokens, sync
     ├─ SSH agent (upstream Bitwarden agent, vendored)
     ├─ authorization TTL engine (monotonic clock)
     └─ browser bridge (legacy NM + SDK IPC)
```

Details, the SDK reuse decision (with measurements) and data flows:
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Installation

1. Build `WardenFuse.app` (see [Building from Source](#building-from-source)) or download a
   release DMG, and move it to `/Applications`.
2. Open WardenFuse. A shield icon appears in the menu bar.
3. **Log In…** with your Bitwarden account.
4. Settings → **Browser** → *Install* for your browser(s).
5. Settings → **SSH Agent** → *Add to ~/.ssh/config…* (or copy the snippet).
6. Settings → General → *Launch at login* (optional).

Release DMGs are **ad-hoc signed**, not Developer ID signed or Apple-notarized. This
requires no paid Apple Developer account, but Gatekeeper may block the downloaded app.
If that happens, try opening WardenFuse once, then go to **System Settings → Privacy &
Security → Open Anyway** and confirm. Only do this for a build you trust; the GitHub
Release also includes a SHA-256 checksum.

No terminal commands are required. If Bitwarden Desktop is installed, WardenFuse detects its
native messaging manifest and only replaces it after you confirm (a backup is kept and restored
when you remove WardenFuse's connection).

## Browser Integration

In the official Bitwarden extension: *Settings → Account security → Unlock with biometrics*.

* Host name `com.8bit.bitwarden`; the manifest allows only the official Bitwarden extension IDs
  (Chrome Web Store, Chrome Web Store beta, Edge Add-ons, Opera Add-ons).
* The bridge accepts a connection only if the peer has your UID **and** its executable is the
  `wardenfuse-nmh` inside this app (`LOCAL_PEERPID` + `proc_pidpath`) **and** the extension
  origin is allowed.
* The browser must be logged into the same Bitwarden account as WardenFuse; other accounts get
  `wrongUserId` / no key.
* Every browser unlock requires fresh authentication, independent of the SSH authorization
  TTL. **Settings → Browser → Browser authentication** selects macOS or [Android](docs/ANDROID.md).
* Both channels are implemented: legacy (`setupEncryption` RSA-OAEP handshake + AES-CBC-HMAC
  messages) and SDK IPC (`DesktopRenderer` endpoint on `bitwarden-ipc` with the Noise
  provider: `DiscoverRequest`, `GetBiometricsStatus`, `UnlockBiometrics`,
  `AuthenticateBiometrics`). Which one the extension uses depends on Bitwarden's server-side
  feature flag; WardenFuse does not need to know.

## SSH Agent

Socket: `~/.wardenfuse/ssh-agent.sock` (directory `0700`, socket `0600`, connections from other
UIDs are rejected). Configure OpenSSH:

```sshconfig
Host *
  IdentityAgent ~/.wardenfuse/ssh-agent.sock
```

or `export SSH_AUTH_SOCK=~/.wardenfuse/ssh-agent.sock` (needed by `ssh-keygen -Y sign`, i.e.
Git commit signing). Git commit signing:

```bash
git config --global gpg.format ssh
git config --global user.signingkey "ssh-ed25519 AAAA…"
git config --global commit.gpgsign true
```

Only SSH-key items that are not deleted or archived are served. Private keys are never returned
to clients and cannot be imported or exported through the agent. Agent forwarding is refused by
default (requests marked as forwarded by OpenSSH's `session-bind@openssh.com`).

## Touch ID Authentication

* Only the macOS system dialog is shown (`LAContext.evaluatePolicy`); WardenFuse opens no window
  of its own and never asks for a password itself. The macOS password is not your Bitwarden
  master password.
* The dialog's reason is built only from verified facts, e.g. *“WardenFuse” is trying to sign a
  Git commit with SSH key “Personal”*, *authenticate with SSH key “GitHub” for ssh*, *unlock
  Bitwarden in Brave Browser*, *unlock the WardenFuse SSH agent*. The requesting program is named
  only when the kernel resolved its executable (`LOCAL_PEERCRED` PID → `proc_pidpath`); the Git /
  file usage comes from the SSHSIG namespace parsed by the agent.
* Authentication methods (Settings → Security):
  * **Touch ID or macOS password** (default) — `.deviceOwnerAuthentication`: Touch ID first, the
    system password dialog as fallback.
  * **Touch ID only** — `.deviceOwnerAuthenticationWithBiometrics`: when Touch ID is unavailable
    (e.g. lid closed), requests are denied.
  * *Password only* is **not offered**: macOS has no public policy that excludes Touch ID, so it
    cannot be enforced honestly. Settings files from earlier builds with that combination are
    migrated to the default.
* After a successful evaluation the context is switched to `interactionNotAllowed`, and the
  Bitwarden user key is read from a Keychain item protected by `SecAccessControl(.userPresence)`
  **with that evaluated `LAContext`** (`kSecUseAuthenticationContext`). The read therefore cannot
  show a second dialog — if macOS wanted one, it fails instead (fail closed). The key bytes are
  what the Rust core needs to decrypt an SSH key; there is no "authenticated" boolean.
* One dialog at a time; cancel, failure and the 85 s timeout (the context is invalidated) return no
  secret; quitting WardenFuse cancels a pending request.

## Authentication TTL

* Default 10 minutes; options: every time (0), 1 min, 5 min, 10 min, 30 min, 1 h, custom (≤ 24 h).
* The expiry is fixed at authentication time and is **not** extended by signing.
* Measured with `CLOCK_MONOTONIC` (keeps counting while asleep, unaffected by clock changes).
* Scope (default): *SSH key + requesting executable*. Optional: *SSH key*. "Unlock Agent" in the
  menu creates an explicit all-keys authorization. Requests from unidentifiable processes are
  never served from a cache.
* Concurrent requests for the same scope share one prompt; different scopes never share.
* Authorizations are discarded on: expiry, Lock Agent, screen lock, sleep, user switch, app quit,
  account switch / logout, key changed or deleted in the vault, settings change, session
  expiry, failed sync beyond the offline limit.
* While authorized, the decrypted private key stays in the upstream `secure_memory` store
  (mlock'ed, encrypted with an ephemeral key) and is purged when the last covering
  authorization expires. Cancel / failure / timeout deny the signature.

## Bitwarden Synchronization

Push notifications trigger syncs; a 5-minute fallback runs only while notifications are
unavailable. The new key set is applied atomically; failures keep the last good data. If no sync
has succeeded for longer than *Disable cached keys after offline for* (default 72 h), the agent
stops serving keys until the next successful sync.

## Security Model

* Threat model includes other local processes of the same user: they can reach the agent socket
  (like any SSH agent) but cannot obtain a signature without your Touch ID / password, and the
  dialog shows which executable is asking.
* User key and SSH private keys are never written to disk in plaintext. The on-disk cache only
  contains Bitwarden EncStrings. Tokens live in the Keychain.
* Secrets are held in `Zeroizing` buffers and dropped right after use; they are never logged.
* Fail closed everywhere: missing key, mismatched public key, stale vault, cancelled prompt,
  unreachable UI ⇒ deny.

**Keychain protection modes** (Settings → Security shows the active one):

| Build | Mode |
|---|---|
| Signed with an Apple Team ID (`SIGN_IDENTITY`, `TEAM_ID`) | Data protection keychain, `SecAccessControl(.userPresence)`: the OS enforces authentication for the user key |
| Ad-hoc signed (default local build) | Login keychain fallback: macOS does not allow access-control items without a Team ID (`errSecMissingEntitlement`). The key is read only after `LAContext` succeeds, but the binding is enforced by WardenFuse, not by `securityd`. |

For daily use, sign with at least a free Apple Development certificate.

## Privacy

WardenFuse connects to your Bitwarden server for identity, API and notifications. If you enable
Android browser unlock, the Mac also listens for authenticated connections from paired phones.
WardenFuse has no telemetry or analytics.

## Supported Platforms

* `WardenFuse.app` is a universal binary (arm64 + x86_64) with a minimum of macOS 15.
* Apple Silicon: macOS 15, 26 and 27. Built with the macOS 27 SDK; Liquid Glass styling is used
  on macOS 26 and later, standard controls on macOS 15.
* Intel: macOS 15 and 26 (macOS 27 no longer supports Intel Macs). CI builds and tests the Rust
  core natively on an Intel runner; the app itself has not been run on Intel hardware.
* Touch ID is optional (system password fallback).

## Building from Source

Requirements: Xcode 27 (macOS 27 SDK), Rust 1.98.0 (pinned by `rust-toolchain.toml`; the
`x86_64-apple-darwin` target is installed automatically by rustup).

```bash
scripts/build-app.sh
```

Output: universal `dist/WardenFuse.app`. Options:

```bash
ARCHS=arm64 scripts/build-app.sh
```

### GitHub Releases (no signing certificate required)

Push a version tag to trigger the CI tests, universal macOS build, ad-hoc signing,
DMG packaging, and automatic GitHub Release upload:

```bash
git tag v0.1.0
git push origin v0.1.0
```

The version in the app bundle is taken from the tag. GitHub Releases contain
`WardenFuse.dmg` and `WardenFuse.dmg.sha256`. No Apple signing/notarization
secrets are needed. Regular CI runs also upload the ad-hoc DMG as an Actions artifact.



```bash
SIGN_IDENTITY="Developer ID Application: Name (TEAMID)" TEAM_ID=TEAMID DMG=1 scripts/build-app.sh
scripts/notarize.sh dist/WardenFuse.dmg
```

Development:

```bash
cargo test --workspace
```

```bash
cargo clippy --workspace --all-targets -- -D warnings
```

Swift tests (authentication coordinator with mocked LocalAuthentication / Keychain; run after
`scripts/build-app.sh`, which produces the static library the package links):

```bash
swift test --package-path macos
```

The Swift package (`macos/Package.swift`) can be opened in Xcode. The app icon is generated from
code (no SF Symbols, which may not be used in app icons):

```bash
swift scripts/make-icon.swift
```

## Troubleshooting

* **`ssh-add -L` says "no identities"** — not logged in, the agent is disabled, or the vault is
  stale (see the menu). Check `SSH_AUTH_SOCK` / `IdentityAgent`.
* **"Key list appears after the first authentication"** — after a restart the key names are still
  encrypted; the first `ssh` asks once to list keys. Or use *Unlock Agent*.
* **Browser says the desktop app is not running** — WardenFuse must be running; check
  Settings → Browser (manifest *Connected to WardenFuse*), restart the browser after installing.
* **Login fails with new device verification** — enable two-step login, or log in with your
  personal API key.
* Logs: Console.app, process `WardenFuse` (`WARDENFUSE_LOG=debug` for more).

## Known Limitations

* SSO, Trusted Device Encryption and Key Connector accounts are not supported; WebAuthn and Duo
  second factors are not supported.
* Only Chromium-based browsers (Firefox and Safari are not supported).
* Forwarded-request detection relies on OpenSSH's `session-bind@openssh.com` extension.
* The requesting executable is reliable, but "which remote host" is only shown when OpenSSH
  provides `session-bind`.
* Ad-hoc signed builds use the Keychain fallback mode (see Security Model).
* Not tested in CI against a real Bitwarden account (credentials are never embedded in CI).

## Upstream Dependencies

| Component | Source | Pinned at |
|---|---|---|
| SSH agent (`ssh_agent`), secure memory (`secure_memory`) — vendored, patched | `bitwarden/clients` `apps/desktop/desktop_native` | `4fe208f` |
| `bitwarden-core`, `bitwarden-auth`, `bitwarden-sync`, `bitwarden-state`, `bitwarden-api-api`, `bitwarden-crypto`, `bitwarden-ipc` | `bitwarden/sdk-internal` | `a13b4c4` |

Patches and update procedure: [vendor/UPSTREAM.md](vendor/UPSTREAM.md).

## License

GPL-3.0-only. See [LICENSE](LICENSE) and [NOTICE.md](NOTICE.md). Bitwarden SDK crates are used
under the GPL-3.0 option of their dual license; no `bitwarden_license` code is used.
