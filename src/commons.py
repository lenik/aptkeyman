#!/usr/bin/env python3
# Copyright (C) 2026 Lenik <aptkeyman@bodz.net>
# SPDX-License-Identifier: AGPL-3.0-or-later

from __future__ import annotations

import gettext
import locale
import os
from pathlib import Path

TEXT_DOMAIN = "aptkeyman"
PROJECT_YEAR = 2026
PROJECT_AUTHOR = "Lenik"
PROJECT_EMAIL = "aptkeyman@bodz.net"


def init_i18n(argv0: str) -> gettext.NullTranslations:
    locale.setlocale(locale.LC_ALL, "")

    localedir = os.environ.get("APTKEYMAN_LOCALEDIR") or os.environ.get("ZEPHYR_LOCALEDIR")
    if not localedir and "/" in argv0:
        build_po = Path(argv0).resolve().parent / "po"
        if build_po.is_dir():
            localedir = str(build_po)

    trans = gettext.translation(TEXT_DOMAIN, localedir=localedir, fallback=True)
    trans.install()
    return trans


def package_data_dir(argv0: str | None = None) -> Path:
    """Locate installed/shared data (wellknown.json, builtin db)."""
    env = os.environ.get("APTKEYMAN_DATADIR")
    if env:
        return Path(env)
    here = Path(__file__).resolve().parent
    # source tree: ../data next to src/
    cand = here.parent / "data"
    if cand.is_dir():
        return cand
    if argv0:
        p = Path(argv0).resolve().parent
        for c in (p / "data", p.parent / "share" / "aptkeyman", Path("/usr/share/aptkeyman")):
            if c.is_dir():
                return c
    return Path("/usr/share/aptkeyman")


def read_version(argv0: str | None = None) -> str:
    env = os.environ.get("APTKEYMAN_VERSION")
    if env:
        return env
    candidates: list[Path] = []
    if argv0:
        p = Path(argv0).resolve().parent
        candidates += [p / "VERSION", p.parent / "VERSION"]
    here = Path(__file__).resolve().parent
    candidates += [here.parent / "VERSION", Path("/usr/share/doc/aptkeyman/VERSION")]
    for c in candidates:
        try:
            if c.is_file():
                return c.read_text(encoding="utf-8").strip().lstrip("v")
        except OSError:
            pass
    return "0.0.0"
