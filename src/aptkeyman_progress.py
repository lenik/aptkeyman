#!/usr/bin/env python3
# Copyright (C) 2026 Lenik <aptkeyman@bodz.net>
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Multi-line download progress (docker-pull style) for concurrent fetches."""

from __future__ import annotations

import sys
import threading
from dataclasses import dataclass, field
from typing import TextIO


def format_bytes(n: int) -> str:
    n = max(0, int(n))
    if n < 1000:
        return f"{n}B"
    if n < 1000_000:
        return f"{n / 1000:.1f}kB".replace(".0kB", "kB")
    if n < 1000_000_000:
        return f"{n / 1000_000:.1f}MB".replace(".0MB", "MB")
    return f"{n / 1000_000_000:.2f}GB"


def _bar(got: int, total: int, width: int = 22) -> str:
    if total > 0:
        frac = min(1.0, got / total)
    elif got > 0:
        frac = 0.5
    else:
        frac = 0.0
    filled = int(round(frac * width))
    if filled >= width and width > 0:
        return "=" * width
    if filled <= 0:
        return ">" + " " * (width - 1) if width else ""
    return "=" * (filled - 1) + ">" + " " * (width - filled)


@dataclass
class _Row:
    state: str = "waiting"  # waiting|downloading|done|error
    got: int = 0
    total: int = 0
    detail: str = ""


@dataclass
class ProgressBoard:
    """In-place multi-row progress when stderr is a TTY; otherwise line events."""

    names: list[str]
    stream: TextIO = field(default_factory=lambda: sys.stderr)
    enabled: bool = True
    name_width: int = 0

    def __post_init__(self) -> None:
        self._lock = threading.Lock()
        self._rows = {n: _Row() for n in self.names}
        self._order = list(self.names)
        self._drawn = 0
        self._closed = False
        self._tty = bool(self.enabled and hasattr(self.stream, "isatty") and self.stream.isatty())
        if not self.name_width and self._order:
            self.name_width = max(len(n) for n in self._order)
        self.name_width = max(self.name_width, 8)

    def _line(self, name: str) -> str:
        row = self._rows[name]
        label = f"{name:<{self.name_width}}"
        if row.state == "waiting":
            return f"{label}  Waiting"
        if row.state == "downloading":
            total = row.total
            got = row.got
            bar = _bar(got, total)
            if total > 0:
                sizes = f"{format_bytes(got)}/{format_bytes(total)}"
            else:
                sizes = format_bytes(got)
            return f"{label}  Downloading [{bar}] {sizes}"
        if row.state == "done":
            return f"{label}  Complete {format_bytes(row.got)}"
        # error
        detail = row.detail.replace("\n", " ").strip()
        if len(detail) > 60:
            detail = detail[:57] + "..."
        return f"{label}  Error {detail}"

    def _redraw(self) -> None:
        if not self._tty or self._closed:
            return
        n = len(self._order)
        if self._drawn:
            self.stream.write(f"\033[{self._drawn}A")
        for name in self._order:
            self.stream.write(f"\033[2K\r{self._line(name)}\n")
        self.stream.flush()
        self._drawn = n

    def _emit_plain(self, name: str, msg: str) -> None:
        if self._tty or not self.enabled:
            return
        self.stream.write(f"{name}: {msg}\n")
        self.stream.flush()

    def waiting(self, name: str) -> None:
        if not self.enabled or name not in self._rows:
            return
        with self._lock:
            self._rows[name] = _Row(state="waiting")
            self._redraw()

    def progress(self, name: str, got: int, total: int = 0) -> None:
        if not self.enabled or name not in self._rows:
            return
        with self._lock:
            prev = self._rows[name].state
            self._rows[name] = _Row(state="downloading", got=got, total=total)
            self._redraw()
            if not self._tty and prev != "downloading":
                self._emit_plain(name, "Downloading")

    def done(self, name: str, size: int) -> None:
        if not self.enabled or name not in self._rows:
            return
        with self._lock:
            self._rows[name] = _Row(state="done", got=size, total=size)
            self._redraw()
            self._emit_plain(name, f"Complete {format_bytes(size)}")

    def error(self, name: str, detail: str) -> None:
        if not self.enabled or name not in self._rows:
            return
        with self._lock:
            self._rows[name] = _Row(state="error", detail=detail)
            self._redraw()
            self._emit_plain(name, f"Error {detail}")

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            if self._tty and self._drawn:
                # leave the final board visible; just stop rewriting
                self._closed = True
            else:
                self._closed = True


def callback_for(board: ProgressBoard | None, name: str):
    """Return a ``(got, total)`` callback bound to *name*, or None."""
    if board is None:
        return None

    def _cb(got: int, total: int = 0) -> None:
        board.progress(name, got, total)

    return _cb
