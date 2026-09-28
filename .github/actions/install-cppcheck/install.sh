#!/bin/bash
# Download the cppcheck source tarball, check it against the pinned hash,
# and build it into ~/cppcheck-inst. Reads VERSION and SHA256 from the
# environment that action.yml sets from its inputs. FILESDIR names the
# install prefix, so cppcheck finds std.cfg and its other cfg files there
# at run time.
set -euo pipefail

prefix="$HOME/cppcheck-inst"
tarball="cppcheck-$VERSION.tar.gz"
curl -fsSL -o "$RUNNER_TEMP/$tarball" "https://github.com/danmar/cppcheck/archive/refs/tags/$VERSION.tar.gz"
echo "$SHA256  $RUNNER_TEMP/$tarball" | sha256sum -c -
tar xzf "$RUNNER_TEMP/$tarball" -C "$RUNNER_TEMP"
cmake -S "$RUNNER_TEMP/cppcheck-$VERSION" -B "$RUNNER_TEMP/cppcheck-build" \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_INSTALL_PREFIX="$prefix" \
    -DFILESDIR="$prefix/share/Cppcheck" >/dev/null
cmake --build "$RUNNER_TEMP/cppcheck-build" -j"$(nproc)" >/dev/null
cmake --install "$RUNNER_TEMP/cppcheck-build" >/dev/null
