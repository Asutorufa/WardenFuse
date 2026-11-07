# Vendored upstream code

| Directory | Upstream | Commit | License |
|---|---|---|---|
| `vendor/ssh_agent` | `bitwarden/clients` `apps/desktop/desktop_native/ssh_agent` | `4fe208f3eceb3eba5d9f67cf9201ae7b623ec71a` (2026-11-06) | GPL-3.0 |
| `vendor/secure_memory` | `bitwarden/clients` `apps/desktop/desktop_native/secure_memory` | same | GPL-3.0 |

The crates keep their upstream names (`ssh_agent`, `secure_memory`) and directory layout so they
can be diffed directly against upstream. The `examples/` directory of `secure_memory` was not
copied. Workspace dependency versions in the root `Cargo.toml` mirror
`apps/desktop/desktop_native/Cargo.toml` at the same commit.

These crates have no Electron/N-API dependency upstream; the napi bridge (`desktop_native/napi`)
is **not** vendored. WardenFuse provides its own `KeyStore` and `ApprovalRequester`
implementations instead (`crates/wardenfuse-core/src/ssh`).

## Patches (search for `WardenFuse patch`)

| File | Change | Why |
|---|---|---|
| `ssh_agent/src/server/listener/unix.rs` | `UnixListener::bind_at(path)`; parent dir created `0700` and must be owned by the user and not group/other writable; stale path removed **only if it is a socket**; peers whose `LOCAL_PEERCRED` uid differs from ours are rejected | Configurable socket path from Settings instead of an env var; defense in depth |
| `ssh_agent/src/server/listener/mod.rs` | `create_listeners_at(path)` | same |
| `ssh_agent/src/server/mod.rs` | `SSHAgentServer::start_with_socket_path` | same |
| `ssh_agent/src/agent.rs` | `BitwardenSSHAgent::start_at`, `stop_server` (stop without clearing the key store) | Key lifetime is managed by WardenFuse's gated store |
| `ssh_agent/src/server/auth_policy.rs` | `ConnectionContext.process_id`, `process_path` | Authorization scope and UI need the kernel-verified executable path, not only the basename |
| `ssh_agent/src/server/peer_info.rs`, `connection.rs` | carry `process_path` / pid into the context | same |
| `ssh_agent/src/authorization.rs` (tests) | initialize the new fields | compile |
| `ssh_agent/src/lib.rs` | also export `PrivateKey`, `QueryableKeyData` | external `KeyStore` implementations |
| `ssh_agent/src/server/protocol.rs` | **Bug fix:** `detect_namespace` skipped 4 bytes of a non-existent version field. The data an agent signs for SSHSIG is `"SSHSIG" ‖ string namespace ‖ …` (the version only exists in the armored signature), so upstream never recognized real `git`/`file` requests from `ssh-keygen -Y sign`. Test fixture adjusted accordingly. | Found by WardenFuse's end-to-end test with OpenSSH `ssh-keygen`; worth reporting upstream |

## Updating

1. `git -C <clients> diff 4fe208f..<new> -- apps/desktop/desktop_native/{ssh_agent,secure_memory}`
2. Apply the diff here, re-apply/verify the patches above, update the commit in this file,
   `NOTICE.md`, and the dependency pins in the root `Cargo.toml`.
3. `cargo test --workspace`.

The `sdk-internal` crates are **not** vendored; they are Git dependencies pinned to
`a13b4c4e1fa3685280241f417920fd19d7ef24a6` in the root `Cargo.toml` (update all together).
