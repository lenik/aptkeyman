#!/usr/bin/env python3
# Copyright (C) 2026 Lenik <aptkeyman@bodz.net>
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Seed DB from local keyrings and apt-get update missing-key diagnostics."""

from __future__ import annotations

import json
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path

from aptkeyman_db import KeyDatabase, KeyFact, auto_keyfile, norm_fp
from aptkeyman_fetch import ensure_gpg_keyring, fingerprints_of
from aptkeyman_sources import scan_sources

DEFAULT_KEYRING_DIRS = (
    Path("/usr/share/keyrings"),
    Path("/etc/apt/keyrings"),
    Path("/etc/apt/trusted.gpg.d"),
)

_MISSING_KEY = re.compile(
    r"Missing key\s+([0-9A-Fa-f]{8,40})",
    re.IGNORECASE,
)
_MISSING_KEYRING = re.compile(
    r'Failed to parse keyring\s+"([^"]+)"',
    re.IGNORECASE,
)
_NO_PUBKEY = re.compile(r"NO_PUBKEY\s+([0-9A-Fa-f]+)", re.IGNORECASE)
@dataclass
class SeedHit:
    name: str
    origin: str
    detail: str = ""


def _name_from_path(path: Path) -> str:
    stem = path.name
    for suf in (".gpg", ".asc", ".pgp"):
        if stem.endswith(suf):
            stem = stem[: -len(suf)]
            break
    return stem.replace(" ", "-").lower() or "key"


def seed_from_keyrings(
    db: KeyDatabase,
    dirs: list[Path] | None = None,
    *,
    state: str = "accepted",
) -> list[SeedHit]:
    hits: list[SeedHit] = []
    for d in dirs or list(DEFAULT_KEYRING_DIRS):
        if not d.is_dir():
            continue
        for path in sorted(d.iterdir()):
            if not path.is_file():
                continue
            if path.suffix.lower() not in (".gpg", ".asc", ".pgp"):
                continue
            try:
                raw = path.read_bytes()
            except OSError as e:
                hits.append(SeedHit(path.name, "keyring", f"read error: {e}"))
                continue
            if not raw or len(raw) < 32:
                continue
            blob = ensure_gpg_keyring(raw)
            fps = fingerprints_of(blob)
            name = _name_from_path(path)
            # attach server pattern from sources that reference this path
            server = ""
            for src in scan_sources():
                if src.signed_by and Path(src.signed_by) == path:
                    from urllib.parse import urlparse

                    host = urlparse(src.uri).netloc
                    if host:
                        server = f"{host}/*"
                        break
            existing = db.get_by_name(name)
            if existing and existing.has_blob and not fps:
                continue
            # Do not clobber a managed install under keyrings_dir with a
            # /usr/share path (upsert used to sticky-keep managed=1 while
            # overwriting installed_path — that made purge try to unlink
            # vendor keyrings).
            if existing and existing.managed:
                installed_path = existing.installed_path
                managed = True
            else:
                installed_path = str(path)
                managed = False
            fact = KeyFact(
                id=None,
                name=name,
                server=server or (existing.server if existing else ""),
                fingerprint=fps[0] if fps else (existing.fingerprint if existing else ""),
                keyurl=existing.keyurl if existing else "",
                keyfile=path.name,
                keydata=blob,
                state=state if not existing else existing.state,
                origin="keyring",
                installed_path=installed_path,
                managed=managed,
                notes=f"seeded from {path}",
            )
            db.upsert(fact, keep_state=bool(existing))
            hits.append(SeedHit(name, "keyring", str(path)))
    return hits


_VERIFY_FAILED_URI = re.compile(
    r"OpenPGP signature verification failed:\s+(\S+)",
    re.IGNORECASE,
)


def parse_apt_update_log(text: str) -> list[dict]:
    """Extract missing-key / missing-keyring facts from apt-get update output."""
    lines = text.splitlines()
    current_uri = ""
    enriched: list[dict] = []
    for line in lines:
        em = re.match(r"^Err:\d+\s+(\S+)", line)
        if em:
            current_uri = em.group(1)
        vm = _VERIFY_FAILED_URI.search(line)
        if vm:
            current_uri = vm.group(1)
        for m in _MISSING_KEY.finditer(line):
            enriched.append(
                {
                    "type": "missing_key",
                    "fingerprint": norm_fp(m.group(1)),
                    "uri": current_uri,
                }
            )
        for m in _NO_PUBKEY.finditer(line):
            enriched.append(
                {
                    "type": "missing_key",
                    "fingerprint": norm_fp(m.group(1)),
                    "uri": current_uri,
                }
            )
        for m in _MISSING_KEYRING.finditer(line):
            enriched.append(
                {
                    "type": "missing_keyring",
                    "path": m.group(1),
                    "name": _name_from_path(Path(m.group(1))),
                    "uri": current_uri,
                }
            )
    return enriched


def seed_from_apt_misses(
    db: KeyDatabase,
    findings: list[dict],
    *,
    state: str = "new",
) -> list[SeedHit]:
    hits: list[SeedHit] = []
    for item in findings:
        if item.get("type") == "missing_key":
            fp = norm_fp(item.get("fingerprint", ""))
            if not fp:
                continue
            existing = db.get_by_fingerprint(fp)
            if existing:
                # mark notes
                if item.get("uri") and not existing.server:
                    from urllib.parse import urlparse

                    host = urlparse(item["uri"]).netloc
                    if host:
                        existing.server = f"{host}/*"
                        db.upsert(existing, keep_state=True)
                hits.append(SeedHit(existing.name, "apt-miss", f"known fp {fp}"))
                continue
            name = f"missing-{fp[-8:].lower()}"
            uri = item.get("uri") or ""
            server = ""
            if uri:
                from urllib.parse import urlparse

                host = urlparse(uri).netloc
                if host:
                    server = f"{host}/*"
                    name = host.replace(":", "_").replace("/", "-")
                    # avoid clobber
                    if db.get_by_name(name) and not db.get_by_fingerprint(fp):
                        name = f"{name}-{fp[-8:].lower()}"
            fact = KeyFact(
                id=None,
                name=name,
                server=server,
                fingerprint=fp,
                keyurl="",
                keyfile=auto_keyfile(name),
                keydata=None,
                state=state,
                origin="apt-miss",
                notes=f"apt-get update missing key {fp}" + (f" for {uri}" if uri else ""),
            )
            db.upsert(fact, keep_state=True)
            hits.append(SeedHit(name, "apt-miss", fp))
        elif item.get("type") == "missing_keyring":
            name = item.get("name") or _name_from_path(Path(item["path"]))
            path = item["path"]
            uri = item.get("uri") or ""
            server = ""
            if uri:
                from urllib.parse import urlparse

                host = urlparse(uri).netloc
                if host:
                    server = f"{host}/*"
            existing = db.get_by_name(name)
            fact = KeyFact(
                id=None,
                name=name,
                server=(existing.server if existing and existing.server else server),
                fingerprint=existing.fingerprint if existing else "",
                keyurl=existing.keyurl if existing else "",
                keyfile=(existing.keyfile if existing and existing.keyfile else Path(path).name),
                keydata=existing.keydata if existing else None,
                state=existing.state if existing else state,
                origin=existing.origin if existing else "apt-miss",
                installed_path=path,
                managed=False,
                notes=(
                    existing.notes
                    if existing and existing.notes
                    else f"apt reports missing keyring {path}"
                ),
            )
            db.upsert(fact, keep_state=True)
            hits.append(SeedHit(name, "apt-miss", path))
    return hits


def run_apt_update_capture(*, sudo: bool = True) -> tuple[int, str]:
    cmd = ["apt-get", "update"]
    if sudo:
        cmd = ["sudo", "-n"] + cmd
    proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    text = (proc.stdout or "") + "\n" + (proc.stderr or "")
    return proc.returncode, text


def seed_from_wellknown(db: KeyDatabase, json_path: Path) -> list[SeedHit]:
    data = json.loads(json_path.read_text(encoding="utf-8"))
    for item in data.get("keys", []):
        item.setdefault("origin", "wellknown")
    n = db.import_json(data, keep_state=True)
    return [SeedHit(k["name"], "wellknown", "json") for k in data.get("keys", [])][:n]


def seed_all(
    db: KeyDatabase,
    *,
    datadir: Path,
    apt_log: Path | None = None,
    run_apt: bool = False,
    keyring_dirs: list[Path] | None = None,
) -> list[SeedHit]:
    hits: list[SeedHit] = []
    wk = datadir / "wellknown.json"
    if wk.is_file():
        hits.extend(seed_from_wellknown(db, wk))
    hits.extend(seed_from_keyrings(db, keyring_dirs))

    text = ""
    if apt_log and apt_log.is_file():
        text = apt_log.read_text(encoding="utf-8", errors="replace")
    elif run_apt:
        _rc, text = run_apt_update_capture(sudo=True)
    if text:
        findings = parse_apt_update_log(text)
        hits.extend(seed_from_apt_misses(db, findings))
    return hits
