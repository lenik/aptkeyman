#!/usr/bin/env python3
# Copyright (C) 2026 Lenik <aptkeyman@bodz.net>
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Build prebuilt data/aptkeyman.db from wellknown.json (+ optional local seed)."""

from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.error
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from aptkeyman_db import KeyDatabase, KeyFact  # noqa: E402
from aptkeyman_fetch import (  # noqa: E402
    ensure_gpg_keyring,
    fetch_url,
    fingerprint_matches,
    fingerprints_of,
)
from aptkeyman_progress import ProgressBoard, callback_for  # noqa: E402
from aptkeyman_proxy import ProxyConfig, ProxyRequiredError  # noqa: E402
from aptkeyman_seed import seed_from_apt_misses, seed_from_keyrings, parse_apt_update_log  # noqa: E402


def _proxy_mode_of(item: dict) -> str:
    pm = item.get("proxy_mode") or ""
    return "" if pm == "auto" else pm


def _download_one(
    item: dict,
    proxy_cfg: ProxyConfig,
    board: ProgressBoard | None = None,
) -> tuple[str, bytes | None, str]:
    """Return (name, blob|None, status_line)."""
    name = item["name"]
    keyurl = item.get("keyurl") or ""
    if not keyurl:
        return name, None, f"skip {name}: no keyurl"
    proxy_mode = _proxy_mode_of(item)
    last_err: Exception | None = None
    for attempt in range(1, 4):
        try:
            raw = fetch_url(
                keyurl,
                proxy_mode=proxy_mode,
                proxy_cfg=proxy_cfg,
                on_progress=callback_for(board, name),
            )
            blob = ensure_gpg_keyring(raw)
            fp_expected = (item.get("fingerprint") or "").replace(" ", "").upper()
            got_list = fingerprints_of(blob)
            if fp_expected and got_list and not fingerprint_matches(blob, fp_expected):
                print(
                    f"  WARN {name} fingerprint: expected {fp_expected}, got {got_list}",
                    file=sys.stderr,
                )
            if board is not None:
                board.done(name, len(blob))
            fp = f" fp={got_list[0]}" if got_list else ""
            return name, blob, f"download {name}: {keyurl}\n  ok {len(blob)} bytes{fp}"
        except (urllib.error.URLError, OSError, ValueError, ProxyRequiredError) as e:
            last_err = e
            print(f"  retry {name} {attempt}/3: {e}", file=sys.stderr)
            time.sleep(attempt)
    if board is not None:
        board.error(name, str(last_err))
    return name, None, f"download {name}: {keyurl}\n  FAIL {last_err}"


def build(
    json_path: Path,
    out_path: Path,
    *,
    skip_download: bool = False,
    seed_keyrings: bool = False,
    apt_log: Path | None = None,
    proxy_cfg: ProxyConfig | None = None,
    jobs: int = 8,
) -> None:
    data = json.loads(json_path.read_text(encoding="utf-8"))
    out_path.parent.mkdir(parents=True, exist_ok=True)
    if out_path.exists():
        out_path.unlink()

    proxy_cfg = proxy_cfg or ProxyConfig()
    items = list(data.get("keys", []))

    blobs: dict[str, bytes | None] = {item["name"]: None for item in items}
    ok = fail = 0

    if not skip_download:
        to_fetch = [item for item in items if item.get("keyurl")]
        for item in items:
            if not item.get("keyurl"):
                print(f"skip {item['name']}: no keyurl")
        workers = max(1, min(jobs, len(to_fetch))) if to_fetch else 1
        board = ProgressBoard([item["name"] for item in to_fetch]) if to_fetch else None
        if board is not None:
            for item in to_fetch:
                board.waiting(item["name"])
        if to_fetch:
            with ThreadPoolExecutor(max_workers=workers) as pool:
                futs = {
                    pool.submit(_download_one, item, proxy_cfg, board): item["name"]
                    for item in to_fetch
                }
                for fut in as_completed(futs):
                    name, blob, msg = fut.result()
                    # ProgressBoard already streamed status; avoid duplicate lines.
                    if board is None:
                        print(msg)
                    blobs[name] = blob
                    if blob is not None:
                        ok += 1
                    else:
                        fail += 1
        if board is not None:
            board.close()
            print(f"downloads ok={ok} fail={fail}")

    with KeyDatabase(out_path) as db:
        db.set_meta("built_from", str(json_path))
        db.set_meta("wellknown_version", str(data.get("version", 1)))
        for item in items:
            name = item["name"]
            db.upsert(
                KeyFact(
                    id=None,
                    name=name,
                    server=item.get("server", ""),
                    fingerprint=(item.get("fingerprint") or "").replace(" ", "").upper(),
                    keyurl=item.get("keyurl") or "",
                    keyfile=item.get("keyfile") or "",
                    keydata=blobs.get(name),
                    state=item.get("state") or "accepted",
                    origin="wellknown",
                    notes=item.get("notes", ""),
                    proxy_mode=_proxy_mode_of(item),
                )
            )

        if seed_keyrings:
            for h in seed_from_keyrings(db):
                print(f"keyring {h.name}: {h.detail}")
        if apt_log and apt_log.is_file():
            findings = parse_apt_update_log(apt_log.read_text(encoding="utf-8", errors="replace"))
            for h in seed_from_apt_misses(db, findings):
                print(f"apt-miss {h.name}: {h.detail}")

        snap = {"version": data.get("version", 1), "keys": [f.to_dict() for f in db.list()]}
        snap_path = out_path.with_suffix(".manifest.json")
        snap_path.write_text(json.dumps(snap, indent=2) + "\n", encoding="utf-8")
        print(f"wrote {out_path} (downloads ok={ok} fail={fail})")
        print(f"wrote {snap_path}")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--json", type=Path, default=ROOT / "data/wellknown.json")
    ap.add_argument("--out", type=Path, default=ROOT / "data/aptkeyman.db")
    ap.add_argument("--skip-download", action="store_true")
    ap.add_argument("--seed-keyrings", action="store_true")
    ap.add_argument("--apt-log", type=Path)
    ap.add_argument("--proxy", default=None)
    ap.add_argument("--http-proxy", default=None)
    ap.add_argument("--https-proxy", default=None)
    ap.add_argument("--no-proxy", default=None)
    ap.add_argument("-j", "--jobs", type=int, default=8)
    args = ap.parse_args()
    build(
        args.json,
        args.out,
        skip_download=args.skip_download,
        seed_keyrings=args.seed_keyrings,
        apt_log=args.apt_log,
        proxy_cfg=ProxyConfig(
            proxy=args.proxy,
            http_proxy=args.http_proxy,
            https_proxy=args.https_proxy,
            no_proxy=args.no_proxy,
        ),
        jobs=args.jobs,
    )


if __name__ == "__main__":
    main()
