#!/usr/bin/env python3
# Copyright (C) 2026 Lenik <aptkeyman@bodz.net>
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Verify installed keyring files against the DB."""

from __future__ import annotations

from pathlib import Path

from aptkeyman_db import KeyDatabase
from aptkeyman_fetch import fingerprints_of
from aptkeyman_keys import (
    DEFAULT_KEYRINGS,
    SYSTEM_KEYRINGS,
    ActionResult,
    find_current_keyfile,
    install_keyfile_path,
    keyfile_is_current,
)
from aptkeyman_patterns import find_matching
from aptkeyman_sources import scan_sources


def verify_keys(
    db: KeyDatabase,
    *,
    keyrings_dir: Path = DEFAULT_KEYRINGS,
    system_keyrings: Path = SYSTEM_KEYRINGS,
    source_paths: list[Path] | None = None,
) -> list[ActionResult]:
    sources = scan_sources(source_paths)
    facts = db.list()
    results: list[ActionResult] = []
    seen: set[str] = set()

    for src in sources:
        matches = find_matching(facts, src.uri)
        if not matches:
            results.append(
                ActionResult("?", "unmatched", src.uri, f"no DB fact for {src.uri}")
            )
            continue
        fact = matches[0]
        if fact.name in seen:
            continue
        seen.add(fact.name)

        active = Path(src.signed_by) if src.signed_by else install_keyfile_path(
            fact, keyrings_dir, src
        )
        current = find_current_keyfile(
            fact, src, keyrings_dir, system_keyrings=system_keyrings
        )

        if keyfile_is_current(active, fact):
            data = active.read_bytes()
            results.append(
                ActionResult(
                    fact.name,
                    "ok",
                    str(active),
                    f"{len(data)} bytes; fps={','.join(fingerprints_of(data)[:2]) or '-'}",
                )
            )
            continue

        if current is not None:
            results.append(
                ActionResult(
                    fact.name,
                    "stale_signed_by",
                    str(active),
                    f"Signed-By outdated/missing; current key at {current}",
                )
            )
            continue

        if not active.is_file():
            results.append(
                ActionResult(
                    fact.name,
                    "missing_file",
                    str(active),
                    f"absent (also checked {system_keyrings})",
                )
            )
            continue

        data = active.read_bytes()
        detail = "fingerprint mismatch" if fact.fingerprint else "not current"
        if fact.fingerprint and fingerprints_of(data):
            detail = (
                f"expected {fact.fingerprint}, got {', '.join(fingerprints_of(data))}"
            )
        results.append(ActionResult(fact.name, "fp_mismatch", str(active), detail))
    return results
