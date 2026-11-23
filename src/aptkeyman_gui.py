#!/usr/bin/env python3
# Copyright (C) 2026 Lenik <aptkeyman@bodz.net>
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Optional wxPython GUI for aptkeyman."""

from __future__ import annotations

import os
import sys
from pathlib import Path


def _system_dist_packages() -> list[Path]:
    maj, min_ = sys.version_info[:2]
    return [
        Path("/usr/lib/python3/dist-packages"),
        Path(f"/usr/lib/python{maj}.{min_}/dist-packages"),
        Path(f"/usr/local/lib/python{maj}.{min_}/dist-packages"),
    ]


def import_wx():
    """
    Import wx, even when running inside a venv that hides Debian dist-packages.

    python3-wxgtk4.0 installs into /usr/lib/python3/dist-packages; virtualenvs
    created without --system-site-packages will not see it unless we add that
    path (or re-exec /usr/bin/python3).
    """
    try:
        import wx

        return wx
    except ImportError:
        pass

    for path in _system_dist_packages():
        s = str(path)
        if path.is_dir() and s not in sys.path:
            sys.path.append(s)
    try:
        import wx

        return wx
    except ImportError:
        pass

    system_py = Path("/usr/bin/python3")
    if system_py.is_file() and Path(sys.executable).resolve() != system_py.resolve():
        os.execv(str(system_py), [str(system_py), *sys.argv])

    raise ImportError(
        "wxPython is not available to this Python interpreter.\n"
        f"  executable: {sys.executable}\n"
        "Install the Debian package and/or use system Python:\n"
        "  sudo apt install python3-wxgtk4.0\n"
        "  /usr/bin/python3 $(command -v aptkeyman) gui"
    )


def run_gui(
    *,
    db_path: Path | None = None,
    datadir: Path | None = None,
    keyrings_dir: Path | None = None,
) -> int:
    try:
        wx = import_wx()
    except ImportError as e:
        print(str(e), file=sys.stderr)
        return 1

    from aptkeyman_db import open_db
    from aptkeyman_keys import DEFAULT_KEYRINGS, download_for_sources, update_keys, verify_keys
    from aptkeyman_seed import seed_all
    from commons import package_data_dir

    keyrings_dir = keyrings_dir or DEFAULT_KEYRINGS
    datadir = datadir or package_data_dir()

    class MainFrame(wx.Frame):
        def __init__(self):
            super().__init__(None, title="aptkeyman", size=(900, 560))
            self.db = open_db(db_path, datadir=datadir)
            panel = wx.Panel(self)
            vbox = wx.BoxSizer(wx.VERTICAL)

            self.list = wx.ListCtrl(panel, style=wx.LC_REPORT | wx.BORDER_SUNKEN)
            for i, title in enumerate(
                ("Name", "State", "Origin", "Server", "Fingerprint", "Keyfile")
            ):
                self.list.InsertColumn(i, title, width=120 if i < 5 else 160)
            vbox.Add(self.list, 1, wx.EXPAND | wx.ALL, 8)

            btn_row = wx.BoxSizer(wx.HORIZONTAL)
            for label, handler in (
                ("Refresh", self.on_refresh),
                ("Seed", self.on_seed),
                ("Download", self.on_download),
                ("Update", self.on_update),
                ("Verify", self.on_verify),
                ("Accept", self.on_accept),
                ("Deny", self.on_deny),
            ):
                b = wx.Button(panel, label=label)
                b.Bind(wx.EVT_BUTTON, handler)
                btn_row.Add(b, 0, wx.RIGHT, 6)
            vbox.Add(btn_row, 0, wx.LEFT | wx.RIGHT | wx.BOTTOM, 8)

            self.log = wx.TextCtrl(panel, style=wx.TE_MULTILINE | wx.TE_READONLY | wx.HSCROLL)
            vbox.Add(self.log, 0, wx.EXPAND | wx.LEFT | wx.RIGHT | wx.BOTTOM, 8)
            self.log.SetMinSize((-1, 120))

            panel.SetSizer(vbox)
            self.Bind(wx.EVT_CLOSE, self.on_close)
            self.reload_list()

        def append_log(self, msg: str) -> None:
            self.log.AppendText(msg.rstrip() + "\n")

        def reload_list(self) -> None:
            self.list.DeleteAllItems()
            for f in self.db.list():
                i = self.list.InsertItem(self.list.GetItemCount(), f.name)
                self.list.SetItem(i, 1, f.state)
                self.list.SetItem(i, 2, f.origin)
                self.list.SetItem(i, 3, f.server)
                self.list.SetItem(i, 4, (f.fingerprint[:16] + "…") if len(f.fingerprint) > 16 else f.fingerprint)
                self.list.SetItem(i, 5, f.keyfile)

        def selected_names(self) -> list[str]:
            names = []
            idx = self.list.GetFirstSelected()
            while idx != -1:
                names.append(self.list.GetItemText(idx))
                idx = self.list.GetNextSelected(idx)
            return names

        def on_refresh(self, _evt):
            self.reload_list()

        def on_seed(self, _evt):
            hits = seed_all(self.db, datadir=datadir, run_apt=False)
            self.append_log(f"seeded {len(hits)} entries")
            self.reload_list()

        def on_download(self, _evt):
            results = download_for_sources(self.db, keyrings_dir=keyrings_dir)
            for r in results:
                self.append_log(f"{r.status:10} {r.name:20} {r.path} {r.detail}")
            self.reload_list()

        def on_update(self, _evt):
            results = update_keys(self.db, keyrings_dir=keyrings_dir)
            for r in results:
                self.append_log(f"{r.status:10} {r.name:20} {r.path} {r.detail}")
            self.reload_list()

        def on_verify(self, _evt):
            results = verify_keys(self.db, keyrings_dir=keyrings_dir)
            for r in results:
                self.append_log(f"{r.status:10} {r.name:20} {r.path} {r.detail}")

        def on_accept(self, _evt):
            for name in self.selected_names():
                try:
                    self.db.set_state(name, "accepted")
                    self.append_log(f"accepted {name}")
                except KeyError:
                    self.append_log(f"unknown {name}")
            self.reload_list()

        def on_deny(self, _evt):
            for name in self.selected_names():
                try:
                    self.db.set_state(name, "denied")
                    self.append_log(f"denied {name}")
                except KeyError:
                    self.append_log(f"unknown {name}")
            self.reload_list()

        def on_close(self, evt):
            self.db.close()
            evt.Skip()

    app = wx.App(False)
    frame = MainFrame()
    frame.Show()
    app.MainLoop()
    return 0
