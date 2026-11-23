#!/usr/bin/env python3
# Copyright (C) 2026 Lenik <aptkeyman@bodz.net>
# SPDX-License-Identifier: AGPL-3.0-or-later

from __future__ import annotations

import errno
import os
import shutil
import tempfile
import urllib.error
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

from aptkeyman_db import KeyDatabase, KeyFact, auto_keyfile
from aptkeyman_fetch import (
    download_key_blob,
    ensure_gpg_keyring,
    fetch_url,
    fingerprint_matches,
    fingerprints_of,
)
from aptkeyman_patterns import find_matching
from aptkeyman_progress import ProgressBoard, callback_for
from aptkeyman_proxy import ProxyConfig, ProxyRequiredError
from aptkeyman_sources import AptSource, rewrite_signed_by_in_sources, scan_sources

# Managed installs go here (writable with sudo).
DEFAULT_KEYRINGS = Path("/etc/apt/keyrings")
# Read-only vendor/distro keyrings used for availability / freshness checks.
SYSTEM_KEYRINGS = Path("/usr/share/keyrings")
DEFAULT_FETCH_JOBS = 8

# Re-exports for callers that historically imported these from aptkeyman_keys.
__all__ = [
    "ActionResult",
    "DEFAULT_FETCH_JOBS",
    "DEFAULT_KEYRINGS",
    "SYSTEM_KEYRINGS",
    "download_for_sources",
    "download_key_blob",
    "ensure_gpg_keyring",
    "ensure_keydata",
    "fetch_url",
    "fingerprint_matches",
    "fingerprints_of",
    "update_keys",
    "verify_keys",
    "write_keyfile",
]


@dataclass
class ActionResult:
    name: str
    status: str
    path: str = ""
    detail: str = ""


def path_is_under(path: Path, root: Path) -> bool:
    """True if *path* is *root* or a file/dir beneath it."""
    try:
        Path(path).resolve().relative_to(Path(root).resolve())
        return True
    except (ValueError, OSError):
        return False


def keyfile_name(fact: KeyFact, source: AptSource | None = None) -> str:
    if fact.keyfile:
        return fact.keyfile
    if source and source.signed_by:
        return Path(source.signed_by).name
    return auto_keyfile(fact.name)


def install_keyfile_path(
    fact: KeyFact,
    keyrings_dir: Path,
    source: AptSource | None = None,
) -> Path:
    """Destination for managed key installs (always under keyrings_dir)."""
    return Path(keyrings_dir) / keyfile_name(fact, source)


def resolve_keyfile_path(
    fact: KeyFact,
    source: AptSource | None,
    keyrings_dir: Path,
) -> Path:
    """Backward-compatible alias: prefer install path under keyrings_dir."""
    return install_keyfile_path(fact, keyrings_dir, source)


def lookup_key_paths(
    fact: KeyFact,
    source: AptSource | None,
    keyrings_dir: Path,
    *,
    system_keyrings: Path = SYSTEM_KEYRINGS,
) -> list[Path]:
    """Candidate keyring paths to check (install dir, signed-by, /usr/share)."""
    name = keyfile_name(fact, source)
    seen: set[str] = set()
    out: list[Path] = []

    def add(p: Path) -> None:
        key = str(p)
        if key in seen:
            return
        seen.add(key)
        out.append(p)

    add(Path(keyrings_dir) / name)
    if source and source.signed_by:
        sb = Path(source.signed_by)
        add(sb)
        add(Path(keyrings_dir) / sb.name)
        add(Path(system_keyrings) / sb.name)
    add(Path(system_keyrings) / name)
    return out


def keyfile_is_current(path: Path, fact: KeyFact) -> bool:
    """True if *path* exists and matches the fact fingerprint / keydata."""
    try:
        if not path.is_file() or path.stat().st_size == 0:
            return False
        data = path.read_bytes()
    except OSError:
        return False
    if fact.fingerprint:
        fps = fingerprints_of(data)
        if fps:
            return fingerprint_matches(data, fact.fingerprint)
        if not fact.keydata:
            return False
    if fact.keydata:
        return data == fact.keydata or ensure_gpg_keyring(data) == fact.keydata
    return True


def find_current_keyfile(
    fact: KeyFact,
    source: AptSource | None,
    keyrings_dir: Path,
    *,
    system_keyrings: Path = SYSTEM_KEYRINGS,
) -> Path | None:
    for path in lookup_key_paths(
        fact, source, keyrings_dir, system_keyrings=system_keyrings
    ):
        if keyfile_is_current(path, fact):
            return path
    return None


def ensure_keydata(
    db: KeyDatabase,
    fact: KeyFact,
    *,
    refresh: bool = False,
    proxy_cfg: ProxyConfig | None = None,
) -> KeyFact:
    if fact.keydata and not refresh:
        return fact
    if not fact.keyurl:
        if fact.keydata:
            return fact
        raise ValueError(f"{fact.name}: no keyurl")
    blob = download_key_blob(fact, refresh=True, proxy_cfg=proxy_cfg)
    return db.set_keydata(fact.name, blob, keyurl=fact.keyurl)


def write_keyfile(path: Path, data: bytes, *, dry_run: bool = False) -> None:
    """Write *data* to *path*, staging under the system temp dir first.

    Avoids creating ``*.tmp`` siblings next to privileged destinations such as
    ``/usr/share/keyrings/`` (which would fail with EACCES for non-root).
    Same-filesystem installs use ``os.replace``; cross-device falls back to copy.
    """
    if dry_run:
        return
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(
        prefix="aptkeyman-",
        suffix=path.suffix or ".gpg",
        dir=tempfile.gettempdir(),
    )
    tmp: Path | None = Path(tmp_name)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        assert tmp is not None
        os.chmod(tmp, 0o644)
        try:
            os.replace(tmp, path)
            tmp = None  # renamed into place
        except OSError as e:
            if e.errno != errno.EXDEV:
                raise
            shutil.copyfile(tmp, path)
            os.chmod(path, 0o644)
    finally:
        if tmp is not None:
            tmp.unlink(missing_ok=True)


def discover_unknown(db: KeyDatabase, sources: list[AptSource]) -> list[KeyFact]:
    facts = db.list()
    created: list[KeyFact] = []
    for src in sources:
        if find_matching(facts, src.uri):
            continue
        p = urlparse(src.uri)
        host = p.netloc or src.uri
        name = host.replace(":", "_").replace("/", "-")
        if db.get_by_name(name):
            continue
        fact = KeyFact(
            id=None,
            name=name,
            server=f"{host}/*",
            fingerprint="",
            keyurl="",
            keyfile=auto_keyfile(name),
            keydata=None,
            state="new",
            origin="manual",
            notes=f"auto-discovered from {src.file}:{src.line or '?'}",
        )
        created.append(db.upsert(fact))
        facts.append(created[-1])
    return created


@dataclass
class _PendingInstall:
    fact: KeyFact
    src: AptSource
    dest: Path
    active: Path
    old_signed: str
    need_fetch: bool


def _install_fetched(
    db: KeyDatabase,
    pending: _PendingInstall,
    *,
    keyrings_dir: Path,
    system_keyrings: Path,
    source_paths: list[Path] | None,
    refresh: bool,
    dry_run: bool,
) -> ActionResult:
    fact = pending.fact
    dest = pending.dest
    active = pending.active
    old_signed = pending.old_signed
    src = pending.src

    if not fact.keydata:
        return ActionResult(fact.name, "missing_url", str(dest), "no keydata")

    # Outside keyrings_dir (e.g. /usr/share/keyrings): on refresh/update always
    # copy into keyrings_dir and rewrite Signed-By. Plain download may skip when
    # the system copy is already current.
    outside = bool(old_signed) and not path_is_under(Path(old_signed), keyrings_dir)
    migrate = refresh or outside

    if not migrate and keyfile_is_current(active, fact):
        managed = path_is_under(active, keyrings_dir)
        if not dry_run:
            db.set_installed(
                fact.name,
                str(active if managed else dest),
                managed=managed,
            )
        return ActionResult(fact.name, "skipped", str(active), "already present")

    wrote = False
    if refresh or outside or not keyfile_is_current(dest, fact):
        try:
            write_keyfile(dest, fact.keydata, dry_run=dry_run)
            wrote = True
        except OSError as e:
            return ActionResult(fact.name, "error", str(dest), str(e))

    detail_parts: list[str] = []
    if dry_run:
        detail_parts.append("dry-run")
    elif wrote:
        detail_parts.append(f"{len(fact.keydata)} bytes")
    else:
        detail_parts.append("dest already current")

    if old_signed and Path(old_signed) != dest:
        try:
            changed = rewrite_signed_by_in_sources(
                old_signed,
                dest,
                source_paths=source_paths,
                dry_run=dry_run,
            )
        except OSError as e:
            return ActionResult(
                fact.name,
                "error",
                str(dest),
                f"rewrite Signed-By failed: {e}",
            )
        if changed:
            detail_parts.append(f"signed-by → {dest} ({len(changed)} file(s))")
        elif outside:
            return ActionResult(
                fact.name,
                "error",
                str(dest),
                f"key installed but Signed-By still {old_signed} (no sources rewritten)",
            )
        else:
            detail_parts.append(f"signed-by was {old_signed}")
    elif not old_signed:
        detail_parts.append("no Signed-By in source (key installed only)")

    sys_copy = Path(system_keyrings) / keyfile_name(fact, src)
    if (
        old_signed
        and Path(old_signed) == sys_copy
        and sys_copy.is_file()
        and not keyfile_is_current(sys_copy, fact)
    ):
        detail_parts.append(f"outdated {sys_copy}")

    if not dry_run:
        # Managed installs always live under keyrings_dir — never /usr/share.
        db.set_installed(fact.name, str(dest), managed=True)
    if outside and not wrote:
        status = "migrated"
    elif wrote:
        status = "written"
    else:
        status = "migrated"
    return ActionResult(
        fact.name,
        status,
        str(dest),
        "; ".join(detail_parts),
    )


def download_for_sources(
    db: KeyDatabase,
    *,
    keyrings_dir: Path = DEFAULT_KEYRINGS,
    system_keyrings: Path = SYSTEM_KEYRINGS,
    source_paths: list[Path] | None = None,
    refresh: bool = False,
    dry_run: bool = False,
    only_accepted: bool = True,
    discover: bool = True,
    proxy_cfg: ProxyConfig | None = None,
    jobs: int = DEFAULT_FETCH_JOBS,
    progress: bool = True,
) -> list[ActionResult]:
    """Install keys under *keyrings_dir*; check *system_keyrings* for freshness.

    Apt's Signed-By path is the source of truth for "already present". If that
    path (often under ``/usr/share/keyrings``) is missing or outdated, the key
    is written to *keyrings_dir* and sources files are rewritten to point there.

    Network fetches run concurrently (*jobs* workers) with a docker-pull style
    progress board when *progress* is true and stderr is a TTY.
    """
    sources = scan_sources(source_paths)
    if discover:
        discover_unknown(db, sources)

    facts = db.list()
    results: list[ActionResult] = []
    seen: set[str] = set()
    pending: list[_PendingInstall] = []

    for src in sources:
        matches = find_matching(facts, src.uri)
        if not matches:
            continue
        fact = matches[0]
        if fact.name in seen:
            continue
        seen.add(fact.name)

        if fact.state == "denied":
            results.append(ActionResult(fact.name, "denied", detail="state=denied"))
            continue
        if only_accepted and fact.state != "accepted":
            results.append(
                ActionResult(
                    fact.name,
                    "new",
                    detail=f"state={fact.state}; run: aptkeyman accept {fact.name}",
                )
            )
            continue

        dest = install_keyfile_path(fact, keyrings_dir, src)
        old_signed = src.signed_by or ""
        active = Path(old_signed) if old_signed else dest

        outside = bool(old_signed) and not path_is_under(Path(old_signed), keyrings_dir)
        # update/refresh always relocates Signed-By into keyrings_dir; download may
        # skip when a system/vendor keyring is already current.
        if not refresh and not outside and keyfile_is_current(active, fact):
            if not dry_run:
                db.set_installed(fact.name, str(active), managed=True)
            results.append(
                ActionResult(fact.name, "skipped", str(active), "already present")
            )
            continue
        if not refresh and outside and keyfile_is_current(active, fact):
            if not dry_run:
                db.set_installed(fact.name, str(active), managed=False)
            results.append(
                ActionResult(fact.name, "skipped", str(active), "already present")
            )
            continue

        need_fetch = bool(refresh or not fact.keydata)
        # refresh with no keyurl but local blob: keep blob, no network
        if refresh and not fact.keyurl and fact.keydata:
            need_fetch = False
        pending.append(
            _PendingInstall(
                fact=fact,
                src=src,
                dest=dest,
                active=active,
                old_signed=old_signed,
                need_fetch=need_fetch,
            )
        )

    to_fetch = [p for p in pending if p.need_fetch]
    fetched: dict[str, bytes | Exception] = {}
    board: ProgressBoard | None = None
    if to_fetch and progress:
        board = ProgressBoard([p.fact.name for p in to_fetch])
        for p in to_fetch:
            board.waiting(p.fact.name)

    def _worker(p: _PendingInstall) -> tuple[str, bytes | Exception]:
        try:
            blob = download_key_blob(
                p.fact,
                refresh=refresh,
                proxy_cfg=proxy_cfg,
                on_progress=callback_for(board, p.fact.name),
            )
            if board is not None:
                board.done(p.fact.name, len(blob))
            return p.fact.name, blob
        except (
            urllib.error.URLError,
            ValueError,
            OSError,
            ProxyRequiredError,
        ) as e:
            if board is not None:
                board.error(p.fact.name, str(e))
            return p.fact.name, e

    workers = max(1, min(jobs, len(to_fetch))) if to_fetch else 1
    if to_fetch:
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futs = [pool.submit(_worker, p) for p in to_fetch]
            for fut in as_completed(futs):
                name, outcome = fut.result()
                fetched[name] = outcome
    if board is not None:
        board.close()

    for p in pending:
        if p.need_fetch:
            outcome = fetched.get(p.fact.name)
            if isinstance(outcome, Exception):
                results.append(
                    ActionResult(p.fact.name, "error", str(p.dest), str(outcome))
                )
                continue
            if outcome is None:
                results.append(
                    ActionResult(p.fact.name, "error", str(p.dest), "fetch failed")
                )
                continue
            if not dry_run:
                p.fact = db.set_keydata(p.fact.name, outcome, keyurl=p.fact.keyurl)
            else:
                p.fact.keydata = outcome
        results.append(
            _install_fetched(
                db,
                p,
                keyrings_dir=keyrings_dir,
                system_keyrings=system_keyrings,
                source_paths=source_paths,
                refresh=refresh,
                dry_run=dry_run,
            )
        )

    return results


def update_keys(
    db: KeyDatabase,
    *,
    keyrings_dir: Path = DEFAULT_KEYRINGS,
    system_keyrings: Path = SYSTEM_KEYRINGS,
    source_paths: list[Path] | None = None,
    dry_run: bool = False,
    purge: bool = True,
    proxy_cfg: ProxyConfig | None = None,
    jobs: int = DEFAULT_FETCH_JOBS,
    progress: bool = True,
) -> list[ActionResult]:
    """Refresh all keys used by sources; purge managed keys no longer referenced."""
    sources = scan_sources(source_paths)
    facts = db.list()
    needed: set[str] = set()
    for src in sources:
        matches = find_matching(facts, src.uri)
        if matches:
            needed.add(matches[0].name)

    results = download_for_sources(
        db,
        keyrings_dir=keyrings_dir,
        system_keyrings=system_keyrings,
        source_paths=source_paths,
        refresh=True,
        dry_run=dry_run,
        only_accepted=True,
        discover=True,
        proxy_cfg=proxy_cfg,
        jobs=jobs,
        progress=progress,
    )

    if purge:
        for fact in db.list_managed():
            if fact.name in needed:
                continue
            path = Path(fact.installed_path) if fact.installed_path else None
            # Only delete files we installed under keyrings_dir — never
            # /usr/share/keyrings or other vendor paths.
            if path and path.is_file() and path_is_under(path, keyrings_dir):
                if not dry_run:
                    try:
                        path.unlink()
                    except OSError as e:
                        results.append(
                            ActionResult(fact.name, "purge_error", str(path), str(e))
                        )
                        continue
                results.append(
                    ActionResult(
                        fact.name,
                        "purged",
                        str(path),
                        "dry-run" if dry_run else "unused managed key removed",
                    )
                )
            elif path and path.is_file():
                results.append(
                    ActionResult(
                        fact.name,
                        "purge_skip",
                        str(path),
                        "not under keyrings dir; left on disk, cleared managed flag",
                    )
                )
            if not dry_run:
                db.clear_installed(fact.name)

    return results


def verify_keys(*args, **kwargs):
    """Lazy re-export — implementation lives in aptkeyman_verify."""
    from aptkeyman_verify import verify_keys as _verify_keys

    return _verify_keys(*args, **kwargs)