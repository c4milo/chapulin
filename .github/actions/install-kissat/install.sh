#!/bin/bash
# Build kissat from the pinned release tag unless the cache restored the
# binary, then put it on PATH. Reads VERSION from the environment that
# action.yml sets from its input.
set -euo pipefail

if [ ! -x ~/kissat-inst/kissat ]; then
  curl -fsSL "https://github.com/arminbiere/kissat/archive/refs/tags/$VERSION.tar.gz" | tar xz
  cd "kissat-$VERSION"
  ./configure
  make -j"$(nproc)"
  mkdir -p ~/kissat-inst
  cp build/kissat ~/kissat-inst/
fi
echo "$HOME/kissat-inst" >> "$GITHUB_PATH"
~/kissat-inst/kissat --version
