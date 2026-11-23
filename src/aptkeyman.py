#!/usr/bin/env python3
# Copyright (C) 2026 Lenik <aptkeyman@bodz.net>
# SPDX-License-Identifier: AGPL-3.0-or-later

"""aptkeyman — prepare APT GPG keys before apt-get update."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import TextIO

from commons import PROJECT_AUTHOR, PROJECT_EMAIL, PROJECT_YEAR, init_i18n, package_data_dir, read_version


def _usage(out: TextIO) -> None:
    out.write(
        _(
            "Usage: aptkeyman COMMAND [OPTION]...\n"
            "Manage third-party APT OpenPGP keys for sources.list entries.\n"
        )
    )
    out.write("\n")
    out.write(_("Commands:\n"))
    cmds = [
        ("download", _("download missing keys used by sources lists")),
        ("update", _("refresh keys for sources; purge unused managed keys")),
        ("verify", _("verify installed keyring files against the DB")),
        ("seed", _("seed DB from keyrings / wellknown / apt-get update misses")),
        ("scan", _("scan apt sources and show key matches")),
        ("list", _("list key facts in the database")),
        ("show", _("show one key fact as JSON")),
        ("accept", _("mark key fact(s) as accepted")),
        ("deny", _("mark key fact(s) as denied")),
        ("add", _("add or update a key fact")),
        ("fetch", _("fetch key blob into the DB")),
        ("export", _("dump DB as JSON")),
        ("import", _("merge external JSON data into the DB")),
        ("gui", _("open wxPython GUI")),
        ("path", _("print DB path")),
        ("version", _("print version information")),
        ("help", _("show this help")),
    ]
    for name, desc in cmds:
        out.write(f"  {name:<10} {desc}\n")
    out.write("\n")
    out.write(
        _("Typical flow: aptkeyman seed && sudo aptkeyman download && sudo apt-get update\n")
    )
    out.write("\n")
    out.write(_("Report bugs to: <{email}>\n").format(email=PROJECT_EMAIL))


def _version(out: TextIO, argv0: str) -> None:
    ver = read_version(argv0)
    out.write(f"aptkeyman {ver}\n")
    out.write(_("Copyright (C) {year} {author}\n").format(year=PROJECT_YEAR, author=PROJECT_AUTHOR))
    out.write(_("License AGPL-3.0-or-later: <https://www.gnu.org/licenses/agpl-3.0.html>\n"))
    out.write(_("This is free software: you are free to change and redistribute it.\n"))
    out.write(_("This project opposes AI exploitation and AI hegemony.\n"))
    out.write(
        _(
            "This project rejects mindless MIT-style licensing and politically naive "
            "BSD-style licensing.\n"
        )
    )
    out.write(_("There is NO WARRANTY, to the extent permitted by law.\n"))


def _add_db_opts(p: argparse.ArgumentParser) -> None:
    from aptkeyman_db import default_user_db_path

    p.add_argument("--db", type=Path, default=None, help=f"SQLite DB (default: {default_user_db_path()})")
    p.add_argument("--datadir", type=Path, default=None, help="wellknown.json / builtin DB dir")
    p.add_argument("--no-builtin", action="store_true", help="do not merge packaged DB")


def _add_proxy_opts(p: argparse.ArgumentParser) -> None:
    p.add_argument(
        "--proxy",
        default=None,
        help="proxy URL for http and https (overrides http_proxy/https_proxy)",
    )
    p.add_argument("--http-proxy", default=None, help="HTTP proxy URL")
    p.add_argument("--https-proxy", default=None, help="HTTPS proxy URL")
    p.add_argument(
        "--no-proxy",
        default=None,
        help="comma-separated hosts that bypass the proxy (overrides no_proxy)",
    )


def _proxy_cfg_from_args(args):
    from aptkeyman_proxy import ProxyConfig

    return ProxyConfig(
        proxy=getattr(args, "proxy", None),
        http_proxy=getattr(args, "http_proxy", None),
        https_proxy=getattr(args, "https_proxy", None),
        no_proxy=getattr(args, "no_proxy", None),
    )


def _want_progress(args) -> bool:
    return not bool(getattr(args, "quiet", False))


def _open(args):
    from aptkeyman_db import open_db

    datadir = args.datadir or package_data_dir()
    return open_db(args.db, datadir=datadir, init_from_builtin=not args.no_builtin)


def cmd_list(args) -> int:
    db = _open(args)
    try:
        facts = db.list(state=args.state)
        if args.json:
            print(json.dumps([f.to_dict() for f in facts], indent=2))
            return 0
        if not facts:
            print("(no keys)")
            return 0
        w = max(len(f.name) for f in facts)
        for f in facts:
            blob = "blob" if f.has_blob else "----"
            fp = (f.fingerprint[:16] + "…") if len(f.fingerprint) > 16 else (f.fingerprint or "-")
            print(f"{f.name:<{w}}  {f.state:<8}  {f.origin:<10}  {blob}  {f.server or '-'}  {fp}")
        return 0
    finally:
        db.close()


def cmd_scan(args) -> int:
    from aptkeyman_patterns import find_matching
    from aptkeyman_sources import scan_sources

    db = _open(args)
    try:
        paths = [Path(p) for p in args.sources] if args.sources else None
        sources = scan_sources(paths)
        facts = db.list()
        for s in sources:
            matches = find_matching(facts, s.uri)
            tag = matches[0].name if matches else "?"
            st = matches[0].state if matches else "-"
            sb = s.signed_by or "-"
            loc = f"{s.file}:{s.line}" if s.file else "-"
            print(f"{tag:24} {st:8} {s.uri}  signed-by={sb}  ({loc})")
        return 0
    finally:
        db.close()


def cmd_download(args) -> int:
    from aptkeyman_keys import DEFAULT_KEYRINGS, download_for_sources

    db = _open(args)
    try:
        paths = [Path(p) for p in args.sources] if args.sources else None
        results = download_for_sources(
            db,
            keyrings_dir=args.keyrings_dir or DEFAULT_KEYRINGS,
            source_paths=paths,
            refresh=args.refresh,
            dry_run=args.dry_run,
            only_accepted=not args.all_states,
            discover=not args.no_discover,
            proxy_cfg=_proxy_cfg_from_args(args),
            jobs=args.jobs,
            progress=_want_progress(args),
        )
        rc = 0
        for r in results:
            print(f"{r.status:10} {r.name:24} {r.path or '-'}  {r.detail}")
            if r.status in ("error", "missing_url"):
                rc = 1
        if not results:
            print("no matching sources / nothing to do")
        return rc
    finally:
        db.close()


def cmd_update(args) -> int:
    from aptkeyman_keys import DEFAULT_KEYRINGS, update_keys

    db = _open(args)
    try:
        paths = [Path(p) for p in args.sources] if args.sources else None
        results = update_keys(
            db,
            keyrings_dir=args.keyrings_dir or DEFAULT_KEYRINGS,
            source_paths=paths,
            dry_run=args.dry_run,
            purge=not args.no_purge,
            proxy_cfg=_proxy_cfg_from_args(args),
            jobs=args.jobs,
            progress=_want_progress(args),
        )
        rc = 0
        for r in results:
            print(f"{r.status:10} {r.name:24} {r.path or '-'}  {r.detail}")
            if r.status in ("error", "purge_error", "missing_url"):
                rc = 1
        return rc
    finally:
        db.close()


def cmd_verify(args) -> int:
    from aptkeyman_keys import DEFAULT_KEYRINGS, verify_keys

    db = _open(args)
    try:
        paths = [Path(p) for p in args.sources] if args.sources else None
        results = verify_keys(
            db,
            keyrings_dir=args.keyrings_dir or DEFAULT_KEYRINGS,
            source_paths=paths,
        )
        rc = 0
        for r in results:
            print(f"{r.status:12} {r.name:24} {r.path or '-'}  {r.detail}")
            if r.status != "ok":
                rc = 1
        return rc
    finally:
        db.close()


def cmd_seed(args) -> int:
    from aptkeyman_seed import seed_all

    db = _open(args)
    try:
        datadir = args.datadir or package_data_dir()
        hits = seed_all(
            db,
            datadir=datadir,
            apt_log=args.apt_log,
            run_apt=args.apt_update,
            keyring_dirs=[Path(p) for p in args.keyrings] if args.keyrings else None,
        )
        for h in hits:
            print(f"{h.origin:10} {h.name:28} {h.detail}")
        print(f"total {len(hits)}")
        return 0
    finally:
        db.close()


def cmd_export(args) -> int:
    db = _open(args)
    try:
        data = db.export_json(include_blobs=args.blobs)
        text = json.dumps(data, indent=2) + "\n"
        if args.output:
            Path(args.output).write_text(text, encoding="utf-8")
        else:
            sys.stdout.write(text)
        return 0
    finally:
        db.close()


def cmd_import(args) -> int:
    db = _open(args)
    try:
        raw = Path(args.file).read_text(encoding="utf-8") if args.file != "-" else sys.stdin.read()
        data = json.loads(raw)
        n = db.import_json(data, keep_state=not args.force_state)
        print(f"imported {n} keys")
        return 0
    finally:
        db.close()


def cmd_accept(args) -> int:
    db = _open(args)
    try:
        for name in args.names:
            db.set_state(name, "accepted")
            print(f"accepted {name}")
        return 0
    except KeyError as e:
        print(f"unknown key: {e}", file=sys.stderr)
        return 1
    finally:
        db.close()


def cmd_deny(args) -> int:
    db = _open(args)
    try:
        for name in args.names:
            db.set_state(name, "denied")
            print(f"denied {name}")
        return 0
    except KeyError as e:
        print(f"unknown key: {e}", file=sys.stderr)
        return 1
    finally:
        db.close()


def cmd_show(args) -> int:
    db = _open(args)
    try:
        f = db.get_by_name(args.name)
        if not f:
            print(f"unknown key: {args.name}", file=sys.stderr)
            return 1
        print(json.dumps(f.to_dict(), indent=2))
        return 0
    finally:
        db.close()


def cmd_fetch(args) -> int:
    from aptkeyman_keys import ensure_gpg_keyring, ensure_keydata, fetch_url

    db = _open(args)
    try:
        f = db.get_by_name(args.name)
        if not f:
            print(f"unknown key: {args.name}", file=sys.stderr)
            return 1
        proxy_cfg = _proxy_cfg_from_args(args)
        if args.url:
            blob = ensure_gpg_keyring(
                fetch_url(args.url, proxy_mode=f.proxy_mode, proxy_cfg=proxy_cfg)
            )
            f = db.set_keydata(f.name, blob, keyurl=args.url)
        else:
            f = ensure_keydata(db, f, refresh=True, proxy_cfg=proxy_cfg)
        print(f"fetched {f.name}: {len(f.keydata or b'')} bytes")
        return 0
    except Exception as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    finally:
        db.close()


def cmd_add(args) -> int:
    from aptkeyman_db import KeyFact
    from aptkeyman_keys import ensure_keydata

    db = _open(args)
    try:
        pm = args.proxy_mode or ""
        if pm == "auto":
            pm = ""
        fact = KeyFact(
            id=None,
            name=args.name,
            server=args.server,
            fingerprint=(args.fingerprint or "").replace(" ", "").upper(),
            keyurl=args.keyurl or "",
            keyfile=args.keyfile or "",
            keydata=None,
            state=args.state,
            origin="manual",
            notes=args.notes or "",
            proxy_mode=pm,
        )
        f = db.upsert(fact)
        if args.keyurl and args.fetch:
            f = ensure_keydata(db, f, refresh=True, proxy_cfg=_proxy_cfg_from_args(args))
        print(json.dumps(f.to_dict(), indent=2))
        return 0
    except Exception as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    finally:
        db.close()


def cmd_gui(args) -> int:
    from aptkeyman_gui import run_gui
    from aptkeyman_keys import DEFAULT_KEYRINGS

    return run_gui(
        db_path=args.db,
        datadir=args.datadir or package_data_dir(),
        keyrings_dir=args.keyrings_dir or DEFAULT_KEYRINGS,
    )


def cmd_path(args) -> int:
    from aptkeyman_db import default_user_db_path

    print(args.db or default_user_db_path())
    return 0


def _make_subparsers() -> dict[str, argparse.ArgumentParser]:
    from aptkeyman_db import STATES
    from aptkeyman_keys import DEFAULT_KEYRINGS

    holders: dict[str, argparse.ArgumentParser] = {}

    def sub(name: str) -> argparse.ArgumentParser:
        sp = argparse.ArgumentParser(prog=f"aptkeyman {name}")
        _add_db_opts(sp)
        holders[name] = sp
        return sp

    sp = sub("download")
    _add_proxy_opts(sp)
    sp.add_argument("--keyrings-dir", type=Path, default=DEFAULT_KEYRINGS)
    sp.add_argument("--sources", nargs="*")
    sp.add_argument("--refresh", action="store_true")
    sp.add_argument("--dry-run", action="store_true")
    sp.add_argument("--all-states", action="store_true")
    sp.add_argument("--no-discover", action="store_true")
    sp.add_argument(
        "-j",
        "--jobs",
        type=int,
        default=8,
        help="concurrent key downloads (default: 8)",
    )

    sp = sub("update")
    _add_proxy_opts(sp)
    sp.add_argument("--keyrings-dir", type=Path, default=DEFAULT_KEYRINGS)
    sp.add_argument("--sources", nargs="*")
    sp.add_argument("--dry-run", action="store_true")
    sp.add_argument("--no-purge", action="store_true")
    sp.add_argument(
        "-j",
        "--jobs",
        type=int,
        default=8,
        help="concurrent key downloads (default: 8)",
    )

    sp = sub("verify")
    sp.add_argument("--keyrings-dir", type=Path, default=DEFAULT_KEYRINGS)
    sp.add_argument("--sources", nargs="*")

    sp = sub("seed")
    sp.add_argument("--apt-update", action="store_true")
    sp.add_argument("--apt-log", type=Path)
    sp.add_argument("--keyrings", nargs="*")

    sp = sub("scan")
    sp.add_argument("--sources", nargs="*")

    sp = sub("list")
    sp.add_argument("--state", choices=STATES)
    sp.add_argument("--json", action="store_true")

    sp = sub("show")
    sp.add_argument("name")

    sp = sub("accept")
    sp.add_argument("names", nargs="+")

    sp = sub("deny")
    sp.add_argument("names", nargs="+")

    sp = sub("add")
    _add_proxy_opts(sp)
    sp.add_argument("name")
    sp.add_argument("--server", required=True)
    sp.add_argument("--keyurl", default="")
    sp.add_argument("--fingerprint", default="")
    sp.add_argument("--keyfile", default="")
    sp.add_argument("--state", choices=STATES, default="new")
    sp.add_argument("--notes", default="")
    sp.add_argument(
        "--proxy-mode",
        default="",
        help="auto|always|never|scheme://host:port (stored on the fact)",
    )
    sp.add_argument("--fetch", action="store_true")

    sp = sub("fetch")
    _add_proxy_opts(sp)
    sp.add_argument("name")
    sp.add_argument("--url")

    sp = sub("export")
    sp.add_argument("-o", "--output", type=Path)
    sp.add_argument("--blobs", action="store_true")

    sp = sub("import")
    sp.add_argument("file")
    sp.add_argument("--force-state", action="store_true")

    sp = sub("gui")
    sp.add_argument("--keyrings-dir", type=Path, default=DEFAULT_KEYRINGS)

    sub("path")
    return holders


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv if argv is None else argv)
    init_i18n(argv[0])
    args = argv[1:]

    quiet = False
    filtered: list[str] = []
    i = 0
    while i < len(args):
        if args[i] in ("-q", "--quiet"):
            quiet = True
            i += 1
            continue
        if args[i] in ("-v", "--verbose"):
            i += 1
            continue
        filtered.append(args[i])
        i += 1
    args = filtered

    if not args or args[0] in ("-h", "--help", "help"):
        _usage(sys.stdout)
        return 0
    if args[0] in ("--version", "version"):
        _version(sys.stdout, argv[0])
        return 0

    cmd = args[0]
    rest = args[1:]
    holders = _make_subparsers()
    if cmd not in holders:
        print(f"aptkeyman: unknown command: {cmd}", file=sys.stderr)
        _usage(sys.stderr)
        return 2

    subargs = holders[cmd].parse_args(rest)
    subargs.quiet = quiet
    if getattr(subargs, "datadir", None) is None:
        subargs.datadir = package_data_dir(argv[0])

    handlers = {
        "download": cmd_download,
        "update": cmd_update,
        "verify": cmd_verify,
        "seed": cmd_seed,
        "scan": cmd_scan,
        "list": cmd_list,
        "show": cmd_show,
        "accept": cmd_accept,
        "deny": cmd_deny,
        "add": cmd_add,
        "fetch": cmd_fetch,
        "export": cmd_export,
        "import": cmd_import,
        "gui": cmd_gui,
        "path": cmd_path,
    }
    return handlers[cmd](subargs)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
