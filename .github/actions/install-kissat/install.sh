#!/bin/bash
# Build kissat from the pinned release tag unless the cache restored the
# binary, then put it on PATH. The tarball is checked against the pinned
# hash before it is unpacked. Reads VERSION and SHA256 from the
# environment that action.yml sets from its inputs.
set -euo pipefail

if [ ! -x ~/kissat-inst/kissat ]; then
  curl -fsSL -o "$RUNNER_TEMP/kissat.tar.gz" "https://github.com/arminbiere/kissat/archive/refs/tags/$VERSION.tar.gz"
  echo "$SHA256  $RUNNER_TEMP/kissat.tar.gz" | sha256sum -c -
  tar xzf "$RUNNER_TEMP/kissat.tar.gz"
  cd "kissat-$VERSION"
  ./configure
  make -j"$(nproc)"
  mkdir -p ~/kissat-inst
  cp build/kissat ~/kissat-inst/
fi
echo "$HOME/kissat-inst" >> "$GITHUB_PATH"
~/kissat-inst/kissat --version
