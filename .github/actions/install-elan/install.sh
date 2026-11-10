#!/bin/bash
# Download elan-init.sh, check it against the pinned hash, run it, and
# put elan on PATH. Reads SHA256 from the environment that action.yml
# sets from its input.
#
# elan-init.sh downloads the elan release from GitHub with a curl of its
# own, which does not retry. On 2026-11-08 that download answered 504 and
# eight nightly jobs failed at this step. So each download gets five
# attempts, 20 seconds apart. The attempts cover a short failure alone:
# a restored ~/.elan covers a long one, because it needs no download.
set -euo pipefail

if [ ! -x "$HOME/.elan/bin/elan" ]; then
  curl -sSf --retry 5 --retry-all-errors --retry-delay 20 \
    -o "$RUNNER_TEMP/elan-init.sh" https://elan.lean-lang.org/elan-init.sh
  echo "$SHA256  $RUNNER_TEMP/elan-init.sh" | sha256sum -c -
  for attempt in 1 2 3 4 5; do
    if sh "$RUNNER_TEMP/elan-init.sh" -y --default-toolchain none; then
      break
    fi
    if [ "$attempt" = 5 ]; then
      echo "install-elan: elan-init.sh failed in five attempts" >&2
      exit 1
    fi
    echo "install-elan: attempt $attempt of elan-init.sh failed, trying again" >&2
    sleep 20
  done
fi
echo "$HOME/.elan/bin" >> "$GITHUB_PATH"
