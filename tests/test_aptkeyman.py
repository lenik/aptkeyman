#!/usr/bin/env python3
# Copyright (C) 2026 Lenik <aptkeyman@bodz.net>
# SPDX-License-Identifier: AGPL-3.0-or-later

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from aptkeyman_db import KeyDatabase, KeyFact
from aptkeyman_keys import download_for_sources, ensure_keydata, update_keys, write_keyfile
from aptkeyman_patterns import pattern_matches
from aptkeyman_proxy import ProxyConfig, ProxyRequiredError, normalize_proxy_mode, opener_for_url
from aptkeyman_seed import parse_apt_update_log, seed_from_apt_misses
from aptkeyman_sources import parse_one_line, rewrite_signed_by


class PatternTests(unittest.TestCase):
    def test_microsoft(self):
        self.assertTrue(
            pattern_matches(
                "*.microsoft.com/*",
                "https://packages.microsoft.com/ubuntu/22.04/prod",
            )
        )

    def test_github(self):
        self.assertTrue(pattern_matches("cli.github.com/*", "https://cli.github.com/packages"))


class SourcesTests(unittest.TestCase):
    def test_signed_by(self):
        line = (
            "deb [arch=amd64 signed-by=/etc/apt/keyrings/githubcli-archive-keyring.gpg] "
            "https://cli.github.com/packages stable main"
        )
        s = parse_one_line(line)
        self.assertIsNotNone(s)
        assert s is not None
        self.assertEqual(s.signed_by, "/etc/apt/keyrings/githubcli-archive-keyring.gpg")


class DownloadTests(unittest.TestCase):
    def test_write_blob(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            db_path = root / "t.db"
            keyrings = root / "keyrings"
            sources = root / "sources.list.d"
            sources.mkdir()
            (sources / "gh.list").write_text(
                f"deb [signed-by={keyrings}/githubcli-archive-keyring.gpg] "
                "https://cli.github.com/packages stable main\n"
            )
            blob = b"\x99 fake-gpg-blob"
            with KeyDatabase(db_path) as db:
                db.upsert(
                    KeyFact(
                        id=None,
                        name="github-cli",
                        server="cli.github.com/*",
                        fingerprint="",
                        keyurl="https://example.invalid/key.gpg",
                        keyfile="githubcli-archive-keyring.gpg",
                        keydata=blob,
                        state="accepted",
                        origin="wellknown",
                    )
                )
                results = download_for_sources(
                    db,
                    keyrings_dir=keyrings,
                    source_paths=[sources],
                    discover=False,
                )
            self.assertTrue(any(r.status == "written" for r in results))
            self.assertEqual((keyrings / "githubcli-archive-keyring.gpg").read_bytes(), blob)

    def test_migrate_outdated_system_key(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            keyrings = root / "etc-apt-keyrings"
            system = root / "usr-share-keyrings"
            sources = root / "sources.list.d"
            keyrings.mkdir()
            system.mkdir()
            sources.mkdir()
            old = b"\x01old-system-key"
            new = b"\x02new-managed-key"
            sys_path = system / "nodesource.gpg"
            sys_path.write_bytes(old)
            src_file = sources / "nodesource.sources"
            src_file.write_text(
                "Types: deb\n"
                "URIs: https://deb.nodesource.com/node_24.x\n"
                "Suites: nodistro\n"
                "Components: main\n"
                f"Signed-By: {sys_path}\n"
            )
            with KeyDatabase(root / "t.db") as db:
                db.upsert(
                    KeyFact(
                        id=None,
                        name="nodesource",
                        server="deb.nodesource.com/*",
                        fingerprint="",
                        keyurl="https://example.invalid/nodesource.gpg",
                        keyfile="nodesource.gpg",
                        keydata=new,
                        state="accepted",
                        origin="wellknown",
                    )
                )
                results = download_for_sources(
                    db,
                    keyrings_dir=keyrings,
                    system_keyrings=system,
                    source_paths=[sources],
                    discover=False,
                )
            dest = keyrings / "nodesource.gpg"
            self.assertTrue(any(r.status == "written" for r in results))
            self.assertEqual(dest.read_bytes(), new)
            self.assertEqual(sys_path.read_bytes(), old)  # never overwrite /usr
            text = src_file.read_text()
            self.assertIn(f"Signed-By: {dest}", text)
            self.assertNotIn(str(sys_path), text)

    def test_skip_current_system_key(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            keyrings = root / "etc-apt-keyrings"
            system = root / "usr-share-keyrings"
            sources = root / "sources.list.d"
            keyrings.mkdir()
            system.mkdir()
            sources.mkdir()
            blob = b"\x03current-key"
            sys_path = system / "intel-graphics.gpg"
            sys_path.write_bytes(blob)
            (sources / "intel.sources").write_text(
                "Types: deb\n"
                "URIs: https://repositories.intel.com/gpu/ubuntu\n"
                "Suites: jammy\n"
                "Components: unified\n"
                f"Signed-By: {sys_path}\n"
            )
            with KeyDatabase(root / "t.db") as db:
                db.upsert(
                    KeyFact(
                        id=None,
                        name="intel-graphics",
                        server="repositories.intel.com/*",
                        fingerprint="",
                        keyurl="",
                        keyfile="intel-graphics.gpg",
                        keydata=blob,
                        state="accepted",
                        origin="wellknown",
                    )
                )
                results = download_for_sources(
                    db,
                    keyrings_dir=keyrings,
                    system_keyrings=system,
                    source_paths=[sources],
                    discover=False,
                )
            self.assertTrue(any(r.status == "skipped" for r in results))
            self.assertFalse((keyrings / "intel-graphics.gpg").exists())

    def test_update_migrates_current_system_key(self):
        """update/refresh must copy into keyrings_dir and rewrite Signed-By."""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            keyrings = root / "etc-apt-keyrings"
            system = root / "usr-share-keyrings"
            sources = root / "sources.list.d"
            keyrings.mkdir()
            system.mkdir()
            sources.mkdir()
            blob = b"\x04proxmox-key"
            sys_path = system / "proxmox-archive-keyring.gpg"
            sys_path.write_bytes(blob)
            src_file = sources / "proxmox.list"
            src_file.write_text(
                f"deb [signed-by={sys_path}] https://enterprise.proxmox.com/debian/pve "
                "bookworm pve-enterprise\n"
            )
            with KeyDatabase(root / "t.db") as db:
                db.upsert(
                    KeyFact(
                        id=None,
                        name="proxmox-archive-keyring",
                        server="enterprise.proxmox.com/*",
                        fingerprint="",
                        keyurl="",
                        keyfile="proxmox-archive-keyring.gpg",
                        keydata=blob,
                        state="accepted",
                        origin="keyring",
                    )
                )
                results = update_keys(
                    db,
                    keyrings_dir=keyrings,
                    system_keyrings=system,
                    source_paths=[sources],
                    purge=False,
                )
            dest = keyrings / "proxmox-archive-keyring.gpg"
            self.assertTrue(dest.is_file())
            self.assertEqual(dest.read_bytes(), blob)
            self.assertEqual(sys_path.read_bytes(), blob)  # never delete/overwrite /usr
            text = src_file.read_text()
            self.assertIn(str(dest), text)
            self.assertNotIn(str(sys_path), text)
            self.assertTrue(any(r.status in ("written", "migrated") for r in results))
            with KeyDatabase(root / "t.db") as db:
                f = db.get_by_name("proxmox-archive-keyring")
                assert f is not None
                self.assertTrue(f.managed)
                self.assertEqual(f.installed_path, str(dest))

    def test_purge_skips_system_keyring_path(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            keyrings = root / "etc-apt-keyrings"
            system = root / "usr-share-keyrings"
            sources = root / "sources.list.d"
            keyrings.mkdir()
            system.mkdir()
            sources.mkdir()
            sys_path = system / "proxmox-archive-keyring.gpg"
            sys_path.write_bytes(b"\x05vendor")
            with KeyDatabase(root / "t.db") as db:
                db.upsert(
                    KeyFact(
                        id=None,
                        name="proxmox-archive-keyring",
                        server="enterprise.proxmox.com/*",
                        fingerprint="",
                        keyurl="",
                        keyfile="proxmox-archive-keyring.gpg",
                        keydata=b"\x05vendor",
                        state="accepted",
                        origin="keyring",
                        installed_path=str(sys_path),
                        managed=True,
                    )
                )
                results = update_keys(
                    db,
                    keyrings_dir=keyrings,
                    system_keyrings=system,
                    source_paths=[sources],
                    purge=True,
                )
            self.assertTrue(sys_path.is_file())  # must not unlink vendor path
            self.assertTrue(any(r.status == "purge_skip" for r in results))
            with KeyDatabase(root / "t.db") as db:
                f = db.get_by_name("proxmox-archive-keyring")
                assert f is not None
                self.assertFalse(f.managed)


class SourcesRewriteTests(unittest.TestCase):
    def test_rewrite_list_and_sources(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            old = "/usr/share/keyrings/foo.gpg"
            new = "/etc/apt/keyrings/foo.gpg"
            list_f = root / "a.list"
            list_f.write_text(f"deb [signed-by={old}] https://example.com stable main\n")
            src_f = root / "b.sources"
            src_f.write_text(f"Types: deb\nURIs: https://example.com\nSigned-By: {old}\n")
            self.assertTrue(rewrite_signed_by(list_f, old, new))
            self.assertTrue(rewrite_signed_by(src_f, old, new))
            self.assertIn(new, list_f.read_text())
            self.assertIn(new, src_f.read_text())
            self.assertNotIn(old, list_f.read_text())


class WriteKeyfileTests(unittest.TestCase):
    def test_stages_in_tmpdir_not_sibling(self):
        with tempfile.TemporaryDirectory() as td:
            dest = Path(td) / "keyrings" / "demo.gpg"
            dest.parent.mkdir()
            write_keyfile(dest, b"\x99keydata")
            self.assertEqual(dest.read_bytes(), b"\x99keydata")
            self.assertFalse(dest.with_suffix(".gpg.tmp").exists())
            self.assertFalse((dest.parent / "demo.gpg.tmp").exists())


class SeedTests(unittest.TestCase):
    def test_parse_missing_key(self):
        log = (
            "Err:30 https://cli.github.com/packages stable InRelease\n"
            "  Sub-process /usr/bin/sqv returned an error code (1), error message is: "
            "Missing key 7F38BBB59D064DBCB3D84D725612B36462313325, which is needed to verify signature.\n"
        )
        findings = parse_apt_update_log(log)
        self.assertTrue(any(f.get("fingerprint", "").endswith("62313325") for f in findings))
        with tempfile.TemporaryDirectory() as td:
            with KeyDatabase(Path(td) / "x.db") as db:
                hits = seed_from_apt_misses(db, findings)
                self.assertTrue(hits)
                self.assertIsNotNone(
                    db.get_by_fingerprint("7F38BBB59D064DBCB3D84D725612B36462313325")
                )


class ProgressTests(unittest.TestCase):
    def test_format_and_board_plain(self):
        from io import StringIO

        from aptkeyman_progress import ProgressBoard, format_bytes

        self.assertEqual(format_bytes(4528), "4.5kB")
        buf = StringIO()
        board = ProgressBoard(["docker", "github-cli"], stream=buf, enabled=True)
        # force non-TTY path
        board._tty = False
        board.waiting("docker")
        board.progress("docker", 1000, 2760)
        board.done("docker", 2760)
        board.error("github-cli", "reset by peer")
        board.close()
        text = buf.getvalue()
        self.assertIn("docker: Downloading", text)
        self.assertIn("docker: Complete", text)
        self.assertIn("github-cli: Error", text)


class ProxyTests(unittest.TestCase):
    def test_normalize(self):
        self.assertEqual(normalize_proxy_mode(None), "auto")
        self.assertEqual(normalize_proxy_mode(""), "auto")
        self.assertEqual(normalize_proxy_mode("ALWAYS"), "always")
        self.assertEqual(
            normalize_proxy_mode("http://localhost:8118"),
            "http://localhost:8118",
        )

    def test_always_requires_proxy(self):
        env = {k: v for k, v in os.environ.items() if k.lower() not in (
            "http_proxy", "https_proxy", "all_proxy", "no_proxy"
        )}
        with mock.patch.dict(os.environ, env, clear=True):
            with self.assertRaises(ProxyRequiredError):
                opener_for_url(
                    "https://cli.github.com/key.gpg",
                    proxy_mode="always",
                    cfg=ProxyConfig(),
                )

    def test_never_ignores_env_proxy(self):
        from urllib.request import ProxyHandler

        cfg = ProxyConfig(proxy="http://127.0.0.1:8118")
        opener = opener_for_url(
            "https://example.com/k.gpg",
            proxy_mode="never",
            cfg=cfg,
        )
        # Empty ProxyHandler suppresses defaults; Py3.13 may omit it entirely
        # when proxies={}. Either way: no active proxy mapping.
        proxied = [
            h.proxies
            for h in opener.handlers
            if isinstance(h, ProxyHandler) and h.proxies
        ]
        self.assertEqual(proxied, [])

    def test_explicit_mode_url(self):
        opener = opener_for_url(
            "https://example.com/k.gpg",
            proxy_mode="http://127.0.0.1:9999",
            cfg=ProxyConfig(),
        )
        ph = next(h for h in opener.handlers if h.__class__.__name__ == "ProxyHandler")
        self.assertEqual(ph.proxies.get("https"), "http://127.0.0.1:9999")

    def test_proxy_mode_persisted(self):
        with tempfile.TemporaryDirectory() as td:
            with KeyDatabase(Path(td) / "p.db") as db:
                db.upsert(
                    KeyFact(
                        id=None,
                        name="docker",
                        server="download.docker.com/*",
                        fingerprint="",
                        keyurl="https://example.invalid/docker.gpg",
                        keyfile="docker.gpg",
                        keydata=None,
                        state="accepted",
                        proxy_mode="always",
                    )
                )
                f = db.get_by_name("docker")
                assert f is not None
                self.assertEqual(f.proxy_mode, "always")


class RefreshNoKeyurlTests(unittest.TestCase):
    def test_refresh_keeps_local_blob(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            keyrings = root / "keyrings"
            sources = root / "sources.list.d"
            keyrings.mkdir()
            sources.mkdir()
            blob = b"\x11local-distro-key"
            (sources / "debian.list").write_text(
                f"deb [signed-by={keyrings}/debian-archive-keyring.pgp] "
                "http://deb.debian.org/debian stable main\n"
            )
            with KeyDatabase(root / "t.db") as db:
                db.upsert(
                    KeyFact(
                        id=None,
                        name="debian-archive-keyring",
                        server="deb.debian.org/*",
                        fingerprint="",
                        keyurl="",
                        keyfile="debian-archive-keyring.pgp",
                        keydata=blob,
                        state="accepted",
                        origin="keyring",
                    )
                )
                results = download_for_sources(
                    db,
                    keyrings_dir=keyrings,
                    source_paths=[sources],
                    refresh=True,
                    discover=False,
                )
            self.assertTrue(any(r.status == "written" for r in results))
            self.assertFalse(any(r.status == "error" for r in results))
            self.assertEqual(
                (keyrings / "debian-archive-keyring.pgp").read_bytes(),
                blob,
            )

    def test_ensure_keydata_no_url_with_blob(self):
        with tempfile.TemporaryDirectory() as td:
            with KeyDatabase(Path(td) / "t.db") as db:
                f = db.upsert(
                    KeyFact(
                        id=None,
                        name="local-only",
                        server="example.com/*",
                        fingerprint="",
                        keyurl="",
                        keyfile="local.gpg",
                        keydata=b"\x22blob",
                        state="accepted",
                    )
                )
                out = ensure_keydata(db, f, refresh=True)
                self.assertEqual(out.keydata, b"\x22blob")


if __name__ == "__main__":
    unittest.main()
