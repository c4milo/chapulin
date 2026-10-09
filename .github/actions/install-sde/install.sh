#!/bin/bash
# Download the Intel SDE tarball, check it against the pinned hash, and
# unpack it into ~/sde. Reads VERSION, DOWNLOAD_ID and SHA256 from the
# environment that action.yml sets from its inputs.
set -euo pipefail

url="https://downloadmirror.intel.com/${DOWNLOAD_ID}/sde-external-${VERSION}-lin.tar.xz"
curl -sSfL -o /tmp/sde.tar.xz "$url"
echo "$SHA256  /tmp/sde.tar.xz" | sha256sum -c -
mkdir -p ~/sde && tar -xJf /tmp/sde.tar.xz -C ~/sde --strip-components=1
