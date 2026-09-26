#!/bin/bash
# Download the Zig tarball, check it against the pinned hash, and unpack
# it into ~/zig. Reads VERSION and SHA256 from the environment that
# action.yml sets from its inputs.
set -euo pipefail

url="https://ziglang.org/download/${VERSION}/zig-x86_64-linux-${VERSION}.tar.xz"
curl -sSfL -o /tmp/zig.tar.xz "$url"
echo "$SHA256  /tmp/zig.tar.xz" | sha256sum -c -
mkdir -p ~/zig && tar -xJf /tmp/zig.tar.xz -C ~/zig --strip-components=1
