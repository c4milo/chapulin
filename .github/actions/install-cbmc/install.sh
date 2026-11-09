#!/bin/bash
# Download the CBMC .deb for the pinned release, or take it from the
# Actions cache that action.yml restores, check it against the pinned
# hash, and install it. Reads VERSION and SHA256 from the environment
# that action.yml sets from its inputs.
set -euo pipefail

deb="ubuntu-24.04-cbmc-$VERSION-Linux.deb"
dir="$HOME/.cache/chapulin-cbmc"
mkdir -p "$dir"
if [ ! -f "$dir/$deb" ]; then
    # GitHub's release download answered 504 for hours at a time, so the
    # download retries every error, five times, 20 seconds apart.
    curl -fsSL --retry 5 --retry-all-errors --retry-delay 20 \
        -o "$dir/$deb" "https://github.com/diffblue/cbmc/releases/download/cbmc-$VERSION/$deb"
fi
echo "$SHA256  $dir/$deb" | sha256sum -c -
sudo dpkg -i "$dir/$deb"
cbmc --version
