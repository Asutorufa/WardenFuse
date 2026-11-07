# Notices

WardenFuse is **not** an official Bitwarden product and is not affiliated with or endorsed by
Bitwarden, Inc. "Bitwarden" is a trademark of Bitwarden, Inc.; it is used here only to describe
compatibility.

WardenFuse is licensed under the GNU General Public License v3.0 only (see `LICENSE`).

## Third-party code included in this repository

### bitwarden/clients — `apps/desktop/desktop_native/{ssh_agent,secure_memory}`

* Source: https://github.com/bitwarden/clients (commit `4fe208f3eceb3eba5d9f67cf9201ae7b623ec71a`)
* Copyright © Bitwarden Inc.
* License: GPL-3.0 (as declared in `apps/desktop/desktop_native/Cargo.toml`)
* Location: `vendor/ssh_agent`, `vendor/secure_memory`; modifications are marked
  `WardenFuse patch` and listed in `vendor/UPSTREAM.md`.

### bitwarden/sdk-internal (used as Cargo dependencies, not vendored)

* Source: https://github.com/bitwarden/sdk-internal (commit `a13b4c4e1fa3685280241f417920fd19d7ef24a6`)
* Crates: `bitwarden-core`, `bitwarden-auth`, `bitwarden-sync`, `bitwarden-state`,
  `bitwarden-api-api`, `bitwarden-crypto`, `bitwarden-ipc` and their workspace dependencies.
* Copyright © Bitwarden Inc.
* License: dual `GPL-3.0-only OR LicenseRef-Bitwarden-SDK`. WardenFuse uses them under the
  **GPL-3.0** option. No code from directories named `bitwarden_license` (Bitwarden SDK License
  only) is used.

Other Rust and Swift dependencies retain their own licenses (MIT / Apache-2.0 / BSD etc.); run
`cargo about` or `cargo tree` for the full list.
