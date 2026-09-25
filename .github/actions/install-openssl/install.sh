#!/bin/bash
# Download the OpenSSL source tarball, check it against the pinned hash,
# and build it into ~/openssl-inst. Reads VERSION and SHA256 from the
# environment that action.yml sets from its inputs. no-shared so each
# binary carries its own libcrypto: no LD_LIBRARY_PATH, and no chance of
# binding the system 3.0. no-docs skips the pod2man pass, which is most
# of the build.
set -euo pipefail

prefix="$HOME/openssl-inst"
tarball="openssl-$VERSION.tar.gz"
curl -fsSL -o "$RUNNER_TEMP/$tarball" "https://github.com/openssl/openssl/releases/download/openssl-$VERSION/$tarball"
echo "$SHA256  $RUNNER_TEMP/$tarball" | sha256sum -c -
tar xzf "$RUNNER_TEMP/$tarball" -C "$RUNNER_TEMP"
cd "$RUNNER_TEMP/openssl-$VERSION"
./Configure --prefix="$prefix" --openssldir="$prefix/ssl" no-shared no-docs
make -j"$(nproc)"
# install_ssldirs too: install_sw alone leaves OPENSSLDIR without
# openssl.cnf, and `openssl req` needs it.
make install_sw install_ssldirs
