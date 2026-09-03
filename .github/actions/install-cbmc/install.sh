#!/bin/bash
# Download the CBMC .deb for the pinned release and install it. Reads
# VERSION from the environment that action.yml sets from its input.
set -euo pipefail

curl -fsSLO "https://github.com/diffblue/cbmc/releases/download/cbmc-$VERSION/ubuntu-24.04-cbmc-$VERSION-Linux.deb"
sudo dpkg -i "ubuntu-24.04-cbmc-$VERSION-Linux.deb"
cbmc --version
