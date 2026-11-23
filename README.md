# aptkeyman

Prepare third-party APT OpenPGP keys **before** `apt-get update`.

```bash
aptkeyman seed --apt-update          # or: --apt-log /path/to/apt-update.log
sudo aptkeyman download
sudo apt-get update
```

Zephyr-style Python + Meson CLI (AGPL-3.0-or-later).

## Why

HTTPS only authenticates the host. APT still needs repository signing keys on
disk (`Signed-By=` / keyrings). Distros do not auto-trust every vendor.
`aptkeyman` keeps a local fact DB, seeds it from local keyrings and
`apt-get update` “Missing key …” errors, and installs keys under
`/etc/apt/keyrings`. It treats `/usr/share/keyrings` as read-only: if a
source’s `Signed-By` there is missing or outdated, the key is written to
`/etc/apt/keyrings` and the sources file is rewritten to match.

## Commands

| Command | Purpose |
|---------|---------|
| `download` | Install missing keys used by sources lists |
| `update` | Refresh those keys; purge unused managed key files |
| `verify` | Check installed keyrings vs DB fingerprints |
| `seed` | Seed from wellknown + `/usr/share/keyrings` + apt misses |
| `scan` / `list` / `show` | Inspect sources and facts |
| `accept` / `deny` / `add` / `fetch` | Manage trust state |
| `export` / `import` | JSON dump / merge |
| `gui` | wxPython UI |
| `version` | Version |

## Build

```bash
sudo apt install meson ninja-build python3 gettext asciidoctor gnupg
meson setup /build
ninja -C /build
meson test -C /build
sudo ninja -C /build install
# or: ninja -C /build install-symlinks
```

Build downloads well-known key blobs into `aptkeyman.db` (and can seed from
local keyrings via `--seed-keyrings` in `scripts/build_db.py`).

Optional GUI: `sudo apt install python3-wxgtk4.0`

## Database fields

`name`, `server` (URL pattern), `fingerprint`, `keyurl`, `keyfile`, `keydata`,
`state` (`new`/`accepted`/`denied`), `origin` (`wellknown`/`keyring`/`apt-miss`/…),
`installed_path`, `managed`, `proxy_mode`
(`auto` / empty, `always`, `never`, or an explicit `scheme://host:port`).

Downloads honor `http_proxy` / `https_proxy` / `no_proxy` (and
`--proxy` / `--http-proxy` / `--https-proxy` / `--no-proxy`). Use
`-j` / `--jobs` for concurrent fetches (default 8).

## License

Copyright (C) 2026 Lenik \<aptkeyman@bodz.net\>

Licensed under **AGPL-3.0-or-later**.
This project opposes AI exploitation and AI hegemony, and rejects mindless
MIT-style licensing and politically naive BSD-style licensing.
