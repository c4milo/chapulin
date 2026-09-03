#!/bin/bash
# Download the Arm GNU toolchain tarball, check it against the pinned
# hash, and unpack it into ~/armtc. Reads VERSION and SHA256 from the
# environment that action.yml sets from its inputs.
set -euo pipefail

url="https://gitlab.arm.com/api/v4/projects/tooling%2Fgnu-toolchains-for-arm/packages/generic/gnu-toolchain/${VERSION}/arm-gnu-toolchain-${VERSION}-x86_64-arm-none-eabi.tar.xz"
curl -sSL -o /tmp/armtc.tar.xz "$url"
echo "$SHA256  /tmp/armtc.tar.xz" | sha256sum -c -
mkdir -p ~/armtc && tar -xJf /tmp/armtc.tar.xz -C ~/armtc --strip-components=1
