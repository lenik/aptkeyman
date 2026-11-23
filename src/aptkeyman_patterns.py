#!/usr/bin/env python3
# Copyright (C) 2026 Lenik <aptkeyman@bodz.net>
# SPDX-License-Identifier: AGPL-3.0-or-later

from __future__ import annotations

from fnmatch import fnmatch
from urllib.parse import urlparse


def uri_match_target(uri: str) -> str:
    p = urlparse(uri)
    if not p.scheme or not p.netloc:
        return uri.lstrip("/").rstrip("/")
    path = (p.path or "").rstrip("/")
    return f"{p.netloc}{path}"


def pattern_matches(pattern: str, uri: str) -> bool:
    pattern = (pattern or "").strip()
    if not pattern:
        return False
    target = uri_match_target(uri)
    candidates = {target}
    p = urlparse(uri if "://" in uri else f"https://{uri}")
    if p.netloc:
        candidates.add(p.netloc)
        if p.path and p.path != "/":
            parts = [x for x in p.path.split("/") if x]
            for i in range(1, len(parts) + 1):
                candidates.add(f"{p.netloc}/{'/'.join(parts[:i])}")

    pat = pattern.rstrip("/")
    for cand in candidates:
        if fnmatch(cand, pat):
            return True
        if pat.endswith("/*") and fnmatch(cand, pat[:-2]):
            return True
        if "*" not in pat and (cand == pat or cand.startswith(pat + "/")):
            return True
    return False


def find_matching(facts, uri: str):
    matched = [f for f in facts if pattern_matches(f.server, uri)]
    matched.sort(key=lambda f: len(f.server or ""), reverse=True)
    return matched
