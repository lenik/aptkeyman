#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Invoked as: bash scripts/install-symlinks.sh <SOURCE_ROOT> <BUILD_ROOT>
set -euo pipefail
SOURCE_ROOT="${1:-${MESON_SOURCE_ROOT:-.}}"
BUILD_ROOT="${2:-${MESON_BUILD_ROOT:-.}}"
prefix="${MESON_INSTALL_PREFIX:-/usr}"
bindir="${prefix}/bin"
datadir="${prefix}/share"
mandir="${datadir}/man"
mkdir -p "$bindir" "$datadir/bash-completion/completions" "$mandir/man1" "$datadir/aptkeyman"
sudo ln -sfn "${BUILD_ROOT}/aptkeyman" "$bindir/aptkeyman"
for m in commons.py aptkeyman_db.py aptkeyman_patterns.py aptkeyman_sources.py \
         aptkeyman_fetch.py aptkeyman_progress.py aptkeyman_keys.py aptkeyman_proxy.py \
         aptkeyman_seed.py aptkeyman_verify.py aptkeyman_gui.py; do
    sudo ln -sfn "${BUILD_ROOT}/$m" "$bindir/$m"
done
sudo ln -sfn "${BUILD_ROOT}/aptkeyman.1" "$mandir/man1/aptkeyman.1"
sudo ln -sfn "${SOURCE_ROOT}/aptkeyman.bash" "$datadir/bash-completion/completions/aptkeyman"
sudo ln -sfn "${SOURCE_ROOT}/data/wellknown.json" "$datadir/aptkeyman/wellknown.json"
if [ -f "${BUILD_ROOT}/aptkeyman.db" ]; then
    sudo ln -sfn "${BUILD_ROOT}/aptkeyman.db" "$datadir/aptkeyman/aptkeyman.db"
fi
printf "Symlinks installed under %s\n" "$prefix"
