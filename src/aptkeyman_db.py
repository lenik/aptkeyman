#!/usr/bin/env python3
# Copyright (C) 2026 Lenik <aptkeyman@bodz.net>
# SPDX-License-Identifier: AGPL-3.0-or-later

"""SQLite store for apt key facts."""

from __future__ import annotations

import json
import shutil
import sqlite3
from dataclasses import dataclass
from pathlib import Path
STATES = ("new", "accepted", "denied")
ORIGINS = ("wellknown", "keyring", "apt-miss", "manual", "import")
# proxy_mode: ''/'auto' | 'always' | 'never' | explicit 'scheme://host:port'
PROXY_MODES_DOC = "auto|always|never|<proxy-url>"

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS keys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    server TEXT NOT NULL DEFAULT '',
    fingerprint TEXT NOT NULL DEFAULT '',
    keyurl TEXT NOT NULL DEFAULT '',
    keyfile TEXT NOT NULL DEFAULT '',
    keydata BLOB,
    state TEXT NOT NULL DEFAULT 'new'
        CHECK (state IN ('new', 'accepted', 'denied')),
    origin TEXT NOT NULL DEFAULT 'manual',
    installed_path TEXT NOT NULL DEFAULT '',
    managed INTEGER NOT NULL DEFAULT 0,
    notes TEXT NOT NULL DEFAULT '',
    proxy_mode TEXT NOT NULL DEFAULT '',
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_keys_state ON keys(state);
CREATE INDEX IF NOT EXISTS idx_keys_fingerprint ON keys(fingerprint);
CREATE INDEX IF NOT EXISTS idx_keys_managed ON keys(managed);
"""


@dataclass
class KeyFact:
    id: int | None
    name: str
    server: str
    fingerprint: str
    keyurl: str
    keyfile: str
    keydata: bytes | None
    state: str
    origin: str = "manual"
    installed_path: str = ""
    managed: bool = False
    notes: str = ""
    proxy_mode: str = ""

    @property
    def has_blob(self) -> bool:
        return bool(self.keydata)

    def to_dict(self, include_blob: bool = False) -> dict:
        import base64

        d = {
            "name": self.name,
            "server": self.server,
            "fingerprint": self.fingerprint,
            "keyurl": self.keyurl,
            "keyfile": self.keyfile,
            "state": self.state,
            "origin": self.origin,
            "installed_path": self.installed_path,
            "managed": self.managed,
            "notes": self.notes,
            "proxy_mode": self.proxy_mode or "auto",
            "has_keydata": self.has_blob,
            "keydata_size": len(self.keydata) if self.keydata else 0,
        }
        if include_blob and self.keydata is not None:
            d["keydata_b64"] = base64.b64encode(self.keydata).decode("ascii")
        return d


def default_user_db_path() -> Path:
    return Path.home() / ".local" / "share" / "aptkeyman" / "aptkeyman.db"


def auto_keyfile(name: str) -> str:
    safe = "".join(c if c.isalnum() or c in "-_." else "-" for c in name.strip().lower())
    safe = safe.strip("-._") or "unknown"
    if not safe.endswith((".gpg", ".asc", ".pgp")):
        safe += ".gpg"
    return safe


def norm_fp(fp: str) -> str:
    return "".join(c for c in (fp or "").upper() if c.isalnum())


class KeyDatabase:
    def __init__(self, path: Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(self.path)
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(SCHEMA)
        self._migrate()
        self._conn.commit()

    def _migrate(self) -> None:
        cols = {r[1] for r in self._conn.execute("PRAGMA table_info(keys)")}
        for col, decl in (
            ("origin", "TEXT NOT NULL DEFAULT 'manual'"),
            ("installed_path", "TEXT NOT NULL DEFAULT ''"),
            ("managed", "INTEGER NOT NULL DEFAULT 0"),
            ("proxy_mode", "TEXT NOT NULL DEFAULT ''"),
        ):
            if col not in cols:
                self._conn.execute(f"ALTER TABLE keys ADD COLUMN {col} {decl}")

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> "KeyDatabase":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def set_meta(self, key: str, value: str) -> None:
        self._conn.execute(
            "INSERT INTO meta(key, value) VALUES(?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (key, value),
        )
        self._conn.commit()

    def get_meta(self, key: str, default: str | None = None) -> str | None:
        row = self._conn.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
        return row["value"] if row else default

    def upsert(self, fact: KeyFact, *, keep_state: bool = False) -> KeyFact:
        existing = self.get_by_name(fact.name)
        if existing is None:
            self._conn.execute(
                """
                INSERT INTO keys(name, server, fingerprint, keyurl, keyfile, keydata,
                                 state, origin, installed_path, managed, notes, proxy_mode)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    fact.name,
                    fact.server,
                    norm_fp(fact.fingerprint),
                    fact.keyurl,
                    fact.keyfile or auto_keyfile(fact.name),
                    fact.keydata,
                    fact.state if fact.state in STATES else "new",
                    fact.origin or "manual",
                    fact.installed_path or "",
                    1 if fact.managed else 0,
                    fact.notes or "",
                    fact.proxy_mode or "",
                ),
            )
            self._conn.commit()
            return self.get_by_name(fact.name)  # type: ignore[return-value]

        state = existing.state if keep_state else (
            fact.state if fact.state in STATES else existing.state
        )
        keydata = fact.keydata if fact.keydata is not None else existing.keydata
        self._conn.execute(
            """
            UPDATE keys SET
                server = COALESCE(NULLIF(?, ''), server),
                fingerprint = COALESCE(NULLIF(?, ''), fingerprint),
                keyurl = COALESCE(NULLIF(?, ''), keyurl),
                keyfile = COALESCE(NULLIF(?, ''), keyfile),
                keydata = ?,
                state = ?,
                origin = COALESCE(NULLIF(?, ''), origin),
                installed_path = CASE WHEN ? != '' THEN ? ELSE installed_path END,
                managed = CASE WHEN ? THEN 1 ELSE managed END,
                notes = COALESCE(NULLIF(?, ''), notes),
                proxy_mode = COALESCE(NULLIF(?, ''), proxy_mode),
                updated_at = datetime('now')
            WHERE name = ?
            """,
            (
                fact.server,
                norm_fp(fact.fingerprint),
                fact.keyurl,
                fact.keyfile,
                keydata,
                state,
                fact.origin,
                fact.installed_path,
                fact.installed_path,
                1 if fact.managed else 0,
                fact.notes,
                fact.proxy_mode or "",
                fact.name,
            ),
        )
        self._conn.commit()
        return self.get_by_name(fact.name)  # type: ignore[return-value]

    def set_state(self, name: str, state: str) -> KeyFact:
        if state not in STATES:
            raise ValueError(state)
        cur = self._conn.execute(
            "UPDATE keys SET state=?, updated_at=datetime('now') WHERE name=?",
            (state, name),
        )
        if cur.rowcount == 0:
            raise KeyError(name)
        self._conn.commit()
        return self.get_by_name(name)  # type: ignore[return-value]

    def set_keydata(self, name: str, keydata: bytes, keyurl: str | None = None) -> KeyFact:
        if keyurl:
            self._conn.execute(
                "UPDATE keys SET keydata=?, keyurl=?, updated_at=datetime('now') WHERE name=?",
                (keydata, keyurl, name),
            )
        else:
            self._conn.execute(
                "UPDATE keys SET keydata=?, updated_at=datetime('now') WHERE name=?",
                (keydata, name),
            )
        self._conn.commit()
        f = self.get_by_name(name)
        if not f:
            raise KeyError(name)
        return f

    def set_installed(self, name: str, path: str, managed: bool = True) -> KeyFact:
        self._conn.execute(
            "UPDATE keys SET installed_path=?, managed=?, updated_at=datetime('now') WHERE name=?",
            (path, 1 if managed else 0, name),
        )
        self._conn.commit()
        return self.get_by_name(name)  # type: ignore[return-value]

    def clear_installed(self, name: str) -> None:
        self._conn.execute(
            "UPDATE keys SET installed_path='', managed=0, updated_at=datetime('now') WHERE name=?",
            (name,),
        )
        self._conn.commit()

    def get_by_name(self, name: str) -> KeyFact | None:
        row = self._conn.execute("SELECT * FROM keys WHERE name=?", (name,)).fetchone()
        return _row(row) if row else None

    def get_by_fingerprint(self, fp: str) -> KeyFact | None:
        fp = norm_fp(fp)
        if not fp:
            return None
        rows = self._conn.execute("SELECT * FROM keys").fetchall()
        for row in rows:
            stored = norm_fp(row["fingerprint"] or "")
            if stored and (stored == fp or stored.endswith(fp) or fp.endswith(stored)):
                return _row(row)
        return None

    def list(self, state: str | None = None) -> list[KeyFact]:
        if state:
            rows = self._conn.execute(
                "SELECT * FROM keys WHERE state=? ORDER BY name", (state,)
            ).fetchall()
        else:
            rows = self._conn.execute("SELECT * FROM keys ORDER BY name").fetchall()
        return [_row(r) for r in rows]

    def list_managed(self) -> list[KeyFact]:
        rows = self._conn.execute(
            "SELECT * FROM keys WHERE managed=1 ORDER BY name"
        ).fetchall()
        return [_row(r) for r in rows]

    def delete(self, name: str) -> None:
        self._conn.execute("DELETE FROM keys WHERE name=?", (name,))
        self._conn.commit()

    def export_json(self, *, include_blobs: bool = False) -> dict:
        return {
            "version": int(self.get_meta("wellknown_version", "1") or "1"),
            "keys": [f.to_dict(include_blob=include_blobs) for f in self.list()],
        }

    def import_json(self, data: dict, *, keep_state: bool = True) -> int:
        import base64

        n = 0
        for item in data.get("keys", []):
            blob = None
            if item.get("keydata_b64"):
                blob = base64.b64decode(item["keydata_b64"])
            pm = item.get("proxy_mode") or ""
            if pm == "auto":
                pm = ""
            fact = KeyFact(
                id=None,
                name=item["name"],
                server=item.get("server", ""),
                fingerprint=norm_fp(item.get("fingerprint", "")),
                keyurl=item.get("keyurl", ""),
                keyfile=item.get("keyfile") or auto_keyfile(item["name"]),
                keydata=blob,
                state=item.get("state") or "new",
                origin=item.get("origin") or "import",
                installed_path=item.get("installed_path", ""),
                managed=bool(item.get("managed", False)),
                notes=item.get("notes", ""),
                proxy_mode=pm,
            )
            self.upsert(fact, keep_state=keep_state)
            n += 1
        if "version" in data:
            self.set_meta("wellknown_version", str(data["version"]))
        return n

    def merge_from(self, other: "KeyDatabase", *, prefer_local_state: bool = True) -> int:
        n = 0
        for fact in other.list():
            local = self.get_by_name(fact.name)
            if local is None:
                self.upsert(fact)
            else:
                merged = KeyFact(
                    id=local.id,
                    name=fact.name,
                    server=fact.server or local.server,
                    fingerprint=fact.fingerprint or local.fingerprint,
                    keyurl=fact.keyurl or local.keyurl,
                    keyfile=fact.keyfile or local.keyfile,
                    keydata=fact.keydata if fact.keydata is not None else local.keydata,
                    state=local.state if prefer_local_state else fact.state,
                    origin=local.origin or fact.origin,
                    installed_path=local.installed_path,
                    managed=local.managed,
                    notes=fact.notes or local.notes,
                    proxy_mode=fact.proxy_mode or local.proxy_mode,
                )
                self.upsert(merged, keep_state=False)
            n += 1
        return n


def _row(row: sqlite3.Row) -> KeyFact:
    keys = row.keys()
    return KeyFact(
        id=row["id"],
        name=row["name"],
        server=row["server"] or "",
        fingerprint=row["fingerprint"] or "",
        keyurl=row["keyurl"] or "",
        keyfile=row["keyfile"] or "",
        keydata=bytes(row["keydata"]) if row["keydata"] is not None else None,
        state=row["state"],
        origin=row["origin"] if "origin" in keys else "manual",
        installed_path=row["installed_path"] if "installed_path" in keys else "",
        managed=bool(row["managed"]) if "managed" in keys else False,
        notes=row["notes"] or "",
        proxy_mode=row["proxy_mode"] if "proxy_mode" in keys else "",
    )


def open_db(
    path: Path | None = None,
    *,
    datadir: Path | None = None,
    init_from_builtin: bool = True,
) -> KeyDatabase:
    db_path = Path(path) if path else default_user_db_path()
    created = not db_path.is_file()
    db = KeyDatabase(db_path)

    if not init_from_builtin:
        return db

    data_root = datadir or (Path(__file__).resolve().parent.parent / "data")
    builtin_db = data_root / "aptkeyman.db"
    builtin_json = data_root / "wellknown.json"

    if builtin_db.is_file():
        if created:
            db.close()
            shutil.copy2(builtin_db, db_path)
            db = KeyDatabase(db_path)
            db.set_meta("seeded_from", str(builtin_db))
        else:
            with KeyDatabase(builtin_db) as bdb:
                db.merge_from(bdb, prefer_local_state=True)
    elif created and builtin_json.is_file():
        data = json.loads(builtin_json.read_text(encoding="utf-8"))
        for item in data.get("keys", []):
            item.setdefault("origin", "wellknown")
        db.import_json(data, keep_state=False)
        db.set_meta("seeded_from", str(builtin_json))
    return db
