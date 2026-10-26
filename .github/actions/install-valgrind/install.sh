#!/bin/bash
# Download the Valgrind source tarball, check it against the pinned hash,
# and build it into ~/valgrind-inst. Reads VERSION and SHA256 from the
# environment that action.yml sets from its inputs. The build needs a C
# compiler and make, which a runner and the docker-check image hold.
set -euo pipefail

prefix="$HOME/valgrind-inst"
tarball="valgrind-$VERSION.tar.bz2"
curl -fsSL -o "$RUNNER_TEMP/$tarball" "https://sourceware.org/pub/valgrind/valgrind-$VERSION.tar.bz2"
echo "$SHA256  $RUNNER_TEMP/$tarball" | sha256sum -c -
tar xjf "$RUNNER_TEMP/$tarball" -C "$RUNNER_TEMP"
cd "$RUNNER_TEMP/valgrind-$VERSION"
./configure --prefix="$prefix" >/dev/null
make -j"$(nproc)" >/dev/null
make install >/dev/null
"$prefix/bin/valgrind" --version
