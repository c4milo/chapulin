#!/bin/bash
# Download the CBMC .deb for the pinned release, check it against the
# pinned hash, and install it. Reads VERSION and SHA256 from the
# environment that action.yml sets from its inputs.
set -euo pipefail

deb="ubuntu-24.04-cbmc-$VERSION-Linux.deb"
curl -fsSL -o "$RUNNER_TEMP/$deb" "https://github.com/diffblue/cbmc/releases/download/cbmc-$VERSION/$deb"
echo "$SHA256  $RUNNER_TEMP/$deb" | sha256sum -c -
sudo dpkg -i "$RUNNER_TEMP/$deb"
cbmc --version
