#!/usr/bin/env python3
# Copyright (C) 2026 Lenik <aptkeyman@bodz.net>
# SPDX-License-Identifier: AGPL-3.0-or-later

"""HTTP(S) proxy selection for key downloads."""

from __future__ import annotations

import os
from dataclasses import dataclass
from urllib.parse import urlparse
from urllib.request import OpenerDirector, ProxyHandler, build_opener, getproxies_environment

PROXY_MODES_SPECIAL = frozenset({"auto", "always", "never"})


class ProxyRequiredError(RuntimeError):
    """Raised when proxy_mode=always but no proxy is configured."""


@dataclass
class ProxyConfig:
    """CLI / process-level proxy overrides (env still used when unset)."""

    proxy: str | None = None  # shorthand for both http + https
    http_proxy: str | None = None
    https_proxy: str | None = None
    no_proxy: str | None = None  # None = read env; "" = empty list

    def resolved_proxies(self) -> dict[str, str]:
        http = (
            self.http_proxy
            or self.proxy
            or os.environ.get("http_proxy")
            or os.environ.get("HTTP_PROXY")
            or ""
        )
        https = (
            self.https_proxy
            or self.proxy
            or os.environ.get("https_proxy")
            or os.environ.get("HTTPS_PROXY")
            or http
        )
        out: dict[str, str] = {}
        if http:
            out["http"] = http
        if https:
            out["https"] = https
        return out

    def resolved_no_proxy(self) -> str:
        if self.no_proxy is not None:
            return self.no_proxy
        return os.environ.get("no_proxy") or os.environ.get("NO_PROXY") or ""


def normalize_proxy_mode(mode: str | None) -> str:
    raw = (mode or "").strip()
    if not raw:
        return "auto"
    low = raw.lower()
    if low in PROXY_MODES_SPECIAL:
        return low
    if "://" in raw:
        return raw
    raise ValueError(f"invalid proxy_mode: {mode!r}")


def _host_matches_no_proxy(host: str, no_proxy: str) -> bool:
    """Subset of curl/wget no_proxy matching (hosts, .suffix, *)."""
    host = (host or "").lower().rstrip(".")
    if not host or not no_proxy.strip():
        return False
    for item in no_proxy.split(","):
        pat = item.strip().lower()
        if not pat:
            continue
        if pat == "*":
            return True
        # strip optional leading dot for suffix match
        if pat.startswith("."):
            if host.endswith(pat) or host == pat[1:]:
                return True
            continue
        if host == pat or host.endswith("." + pat):
            return True
    return False


def opener_for_url(
    url: str,
    proxy_mode: str | None = None,
    cfg: ProxyConfig | None = None,
) -> OpenerDirector:
    """Build a urllib opener honoring per-key *proxy_mode* and *cfg*."""
    cfg = cfg or ProxyConfig()
    mode = normalize_proxy_mode(proxy_mode)

    if mode == "never":
        return build_opener(ProxyHandler({}))

    if mode not in PROXY_MODES_SPECIAL:
        # Explicit proxy URL stored in the column
        return build_opener(ProxyHandler({"http": mode, "https": mode}))

    proxies = cfg.resolved_proxies()

    if mode == "always":
        if not proxies:
            raise ProxyRequiredError(
                "proxy_mode=always but no proxy set "
                "(use --proxy / http_proxy / https_proxy)"
            )
        # Force proxy; ignore no_proxy
        return build_opener(ProxyHandler(proxies))

    # auto: env/CLI proxies with no_proxy bypass
    host = urlparse(url).hostname or ""
    if _host_matches_no_proxy(host, cfg.resolved_no_proxy()):
        return build_opener(ProxyHandler({}))
    if proxies:
        return build_opener(ProxyHandler(proxies))
    # Fall back to urllib's environment discovery (covers odd cases)
    env = getproxies_environment()
    if env:
        return build_opener(ProxyHandler(env))
    return build_opener(ProxyHandler({}))
