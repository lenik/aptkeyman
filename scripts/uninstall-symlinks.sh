#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Invoked as: bash scripts/uninstall-symlinks.sh <SOURCE_ROOT> <BUILD_ROOT>
set -euo pipefail
prefix="${MESON_INSTALL_PREFIX:-/usr}"
bindir="${prefix}/bin"
datadir="${prefix}/share"
mandir="${datadir}/man"
for p in \
    "$bindir/aptkeyman" \
    "$bindir/commons.py" \
    "$bindir/aptkeyman_db.py" \
    "$bindir/aptkeyman_patterns.py" \
    "$bindir/aptkeyman_sources.py" \
    "$bindir/aptkeyman_fetch.py" \
    "$bindir/aptkeyman_progress.py" \
    "$bindir/aptkeyman_keys.py" \
    "$bindir/aptkeyman_proxy.py" \
    "$bindir/aptkeyman_seed.py" \
    "$bindir/aptkeyman_verify.py" \
    "$bindir/aptkeyman_gui.py" \
    "$mandir/man1/aptkeyman.1" \
    "$datadir/bash-completion/completions/aptkeyman" \
    "$datadir/aptkeyman/wellknown.json" \
    "$datadir/aptkeyman/aptkeyman.db"
do
    if [ -L "$p" ]; then
        sudo rm -f "$p"
        printf "Removed %s\n" "$p"
    else
        printf "Skipped (not a symlink): %s\n" "$p"
    fi
done
