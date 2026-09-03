#!/bin/bash
# Download the Bootlin riscv32 tarball, check it against the pinned hash,
# and unpack it into ~/rv32tc. Reads VERSION and SHA256 from the
# environment that action.yml sets from its inputs.
set -euo pipefail

url="https://toolchains.bootlin.com/downloads/releases/toolchains/riscv32-ilp32d/tarballs/riscv32-ilp32d--musl--${VERSION}.tar.xz"
curl -sSL -o /tmp/rv32tc.tar.xz "$url"
echo "$SHA256  /tmp/rv32tc.tar.xz" | sha256sum -c -
mkdir -p ~/rv32tc && tar -xJf /tmp/rv32tc.tar.xz -C ~/rv32tc --strip-components=1
