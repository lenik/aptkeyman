#!/usr/bin/env python3
# Copyright (C) 2026 Lenik <aptkeyman@bodz.net>
# SPDX-License-Identifier: AGPL-3.0-or-later

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

DEFAULT_SOURCES = (
    Path("/etc/apt/sources.list"),
    Path("/etc/apt/sources.list.d"),
)

_ONE_LINE = re.compile(
    r"^(?P<type>deb(?:-src)?)\s+"
    r"(?:\[(?P<options>[^\]]*)\]\s+)?"
    r"(?P<uri>\S+)\s+"
    r"(?P<suite>\S+)"
    r"(?P<components>.*)?$"
)


@dataclass
class AptSource:
    uri: str
    suite: str = ""
    components: str = ""
    source_type: str = "deb"
    options: dict[str, str] = field(default_factory=dict)
    file: Path | None = None
    line: int | None = None
    enabled: bool = True

    @property
    def signed_by(self) -> str | None:
        for k, v in self.options.items():
            if k.lower() == "signed-by":
                return v
        return None


def _parse_options(raw: str | None) -> dict[str, str]:
    if not raw:
        return {}
    opts: dict[str, str] = {}
    for part in raw.strip().split():
        if "=" in part:
            k, v = part.split("=", 1)
            opts[k.strip().lower()] = v.strip()
        else:
            opts[part.strip().lower()] = "true"
    return opts


def parse_one_line(line: str, *, file: Path | None = None, lineno: int = 0) -> AptSource | None:
    s = line.strip()
    if not s or s.startswith("#"):
        return None
    m = _ONE_LINE.match(s)
    if not m:
        return None
    return AptSource(
        uri=m.group("uri"),
        suite=m.group("suite") or "",
        components=(m.group("components") or "").strip(),
        source_type=m.group("type"),
        options=_parse_options(m.group("options")),
        file=file,
        line=lineno,
        enabled=True,
    )


def parse_list_file(path: Path) -> list[AptSource]:
    out: list[AptSource] = []
    text = path.read_text(encoding="utf-8", errors="replace")
    for i, line in enumerate(text.splitlines(), 1):
        src = parse_one_line(line, file=path, lineno=i)
        if src:
            out.append(src)
    return out


def parse_deb822(path: Path) -> list[AptSource]:
    text = path.read_text(encoding="utf-8", errors="replace")
    stanzas = [s for s in re.split(r"\n\s*\n", text) if s.strip()]
    out: list[AptSource] = []
    for stanza in stanzas:
        fields: dict[str, str] = {}
        current = None
        for line in stanza.splitlines():
            if not line.strip() or line.strip().startswith("#"):
                continue
            if line[:1] in (" ", "\t"):
                if current:
                    fields[current] += "\n" + line.strip()
                continue
            if ":" in line:
                k, v = line.split(":", 1)
                current = k.strip()
                fields[current] = v.strip()
        enabled = fields.get("Enabled", "yes").lower() not in ("no", "false", "0")
        uris = fields.get("URIs") or fields.get("URI") or ""
        types = (fields.get("Types") or fields.get("Type") or "deb").split()
        suites = (fields.get("Suites") or fields.get("Suite") or "").split()
        comps = fields.get("Components") or fields.get("Component") or ""
        signed = fields.get("Signed-By") or ""
        opts: dict[str, str] = {}
        if signed:
            opts["signed-by"] = signed.split("\n")[0].strip()
        suite = suites[0] if suites else ""
        for uri in uris.split():
            for t in types:
                out.append(
                    AptSource(
                        uri=uri,
                        suite=suite,
                        components=comps,
                        source_type=t,
                        options=dict(opts),
                        file=path,
                        enabled=enabled,
                    )
                )
    return out


def iter_source_files(paths: list[Path] | None = None) -> list[Path]:
    roots = paths or list(DEFAULT_SOURCES)
    files: list[Path] = []
    for p in roots:
        p = Path(p)
        if p.is_file():
            files.append(p)
        elif p.is_dir():
            for child in sorted(p.iterdir()):
                if child.suffix in (".list", ".sources") or child.name == "sources.list":
                    if child.is_file():
                        files.append(child)
    return files


def scan_sources(paths: list[Path] | None = None) -> list[AptSource]:
    sources: list[AptSource] = []
    for f in iter_source_files(paths):
        try:
            if f.suffix == ".sources":
                sources.extend(parse_deb822(f))
            else:
                sources.extend(parse_list_file(f))
        except OSError:
            continue
    return [s for s in sources if s.enabled]


def rewrite_signed_by(
    path: Path,
    old: str | Path,
    new: str | Path,
    *,
    dry_run: bool = False,
) -> bool:
    """Replace Signed-By / signed-by path *old* with *new* in a sources file.

    Returns True if the file would change (or did change when not dry_run).
    """
    old_s = str(old)
    new_s = str(new)
    if not old_s or old_s == new_s:
        return False
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False
    if old_s not in text:
        return False
    updated = text.replace(old_s, new_s)
    if updated == text:
        return False
    if not dry_run:
        path.write_text(updated, encoding="utf-8")
    return True


def rewrite_signed_by_in_sources(
    old: str | Path,
    new: str | Path,
    *,
    source_paths: list[Path] | None = None,
    dry_run: bool = False,
) -> list[Path]:
    """Rewrite *old* → *new* across apt sources files. Returns changed paths."""
    changed: list[Path] = []
    for f in iter_source_files(source_paths):
        if rewrite_signed_by(f, old, new, dry_run=dry_run):
            changed.append(f)
    return changed
