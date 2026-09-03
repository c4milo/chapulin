#!/bin/bash
# Download elan-init.sh, check it against the pinned hash, run it, and
# put elan on PATH. Reads SHA256 from the environment that action.yml
# sets from its input.
set -euo pipefail

if [ ! -x "$HOME/.elan/bin/elan" ]; then
  curl -sSf -o "$RUNNER_TEMP/elan-init.sh" https://elan.lean-lang.org/elan-init.sh
  echo "$SHA256  $RUNNER_TEMP/elan-init.sh" | sha256sum -c -
  sh "$RUNNER_TEMP/elan-init.sh" -y --default-toolchain none
fi
echo "$HOME/.elan/bin" >> "$GITHUB_PATH"
