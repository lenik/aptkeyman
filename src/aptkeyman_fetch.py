#!/usr/bin/env python3
# Copyright (C) 2026 Lenik <aptkeyman@bodz.net>
# SPDX-License-Identifier: AGPL-3.0-or-later

"""HTTP fetch + OpenPGP keyring helpers."""

from __future__ import annotations

import shutil
import subprocess
import tempfile
import urllib.request
from collections.abc import Callable
from pathlib import Path

from aptkeyman_db import KeyFact
from aptkeyman_proxy import ProxyConfig, opener_for_url

USER_AGENT = "aptkeyman/0.0.2 (+https://github.com/lenik/aptkeyman)"
ProgressCb = Callable[[int, int], None]


def fetch_url(
    url: str,
    timeout: float = 60.0,
    *,
    proxy_mode: str | None = None,
    proxy_cfg: ProxyConfig | None = None,
    on_progress: ProgressCb | None = None,
    chunk_size: int = 64 * 1024,
) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    opener = opener_for_url(url, proxy_mode=proxy_mode, cfg=proxy_cfg)
    with opener.open(req, timeout=timeout) as resp:
        total = 0
        try:
            total = int(resp.headers.get("Content-Length") or 0)
        except (TypeError, ValueError):
            total = 0
        if on_progress:
            on_progress(0, total)
        chunks: list[bytes] = []
        got = 0
        while True:
            chunk = resp.read(chunk_size)
            if not chunk:
                break
            chunks.append(chunk)
            got += len(chunk)
            if on_progress:
                on_progress(got, total)
        data = b"".join(chunks)
        if on_progress:
            on_progress(len(data), total or len(data))
        return data


def is_binary_keyring(data: bytes) -> bool:
    if not data:
        return False
    head = data.lstrip()[:32]
    return not head.startswith(b"-----BEGIN")


def ensure_gpg_keyring(data: bytes) -> bytes:
    if is_binary_keyring(data):
        return data
    gpg = shutil.which("gpg")
    if not gpg:
        return data
    with tempfile.TemporaryDirectory() as td:
        inp = Path(td) / "in.asc"
        out = Path(td) / "out.gpg"
        inp.write_bytes(data)
        proc = subprocess.run(
            [gpg, "--dearmor", "-o", str(out), str(inp)],
            capture_output=True,
            check=False,
        )
        if proc.returncode != 0 or not out.is_file():
            return data
        return out.read_bytes()


def fingerprints_of(data: bytes) -> list[str]:
    gpg = shutil.which("gpg")
    if not gpg:
        return []
    proc = subprocess.run(
        ["gpg", "--batch", "--with-colons", "--show-keys"],
        input=data,
        capture_output=True,
        check=False,
    )
    if proc.returncode != 0:
        return []
    out: list[str] = []
    for line in proc.stdout.decode(errors="replace").splitlines():
        if line.startswith("fpr:"):
            parts = line.split(":")
            if len(parts) > 9 and parts[9]:
                out.append(parts[9].upper())
    return out


def fingerprint_matches(data: bytes, expected: str) -> bool:
    exp = "".join(c for c in expected.upper() if c.isalnum())
    if not exp:
        return True
    for got in fingerprints_of(data):
        if got == exp or got.endswith(exp) or exp.endswith(got):
            return True
    return False


def validate_blob(fact: KeyFact, blob: bytes) -> bytes:
    if fact.fingerprint and fingerprints_of(blob):
        if not fingerprint_matches(blob, fact.fingerprint):
            raise ValueError(
                f"{fact.name}: fingerprint mismatch: expected {fact.fingerprint}, "
                f"got {', '.join(fingerprints_of(blob))}"
            )
    return blob


def download_key_blob(
    fact: KeyFact,
    *,
    refresh: bool = False,
    proxy_cfg: ProxyConfig | None = None,
    on_progress: ProgressCb | None = None,
) -> bytes:
    """Fetch and dearmor key material (no DB writes; safe for worker threads)."""
    if fact.keydata and not refresh:
        return fact.keydata
    if not fact.keyurl:
        if fact.keydata:
            return fact.keydata
        raise ValueError(f"{fact.name}: no keyurl")
    raw = fetch_url(
        fact.keyurl,
        proxy_mode=fact.proxy_mode,
        proxy_cfg=proxy_cfg,
        on_progress=on_progress,
    )
    return validate_blob(fact, ensure_gpg_keyring(raw))
