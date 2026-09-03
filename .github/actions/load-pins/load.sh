#!/bin/bash
# Append every NAME=value line of tools/toolchain.env to GITHUB_ENV.
#
# GITHUB_ENV takes NAME=value lines, which is the file's own format, so
# the lines copy across unchanged. The shape check runs first: a line
# with spaces or quotes would still copy, and the job would then hold a
# value neither `make include` nor `sh .` reads the same way. The header
# of tools/toolchain.env states the format.
set -euo pipefail

pins="$GITHUB_WORKSPACE/tools/toolchain.env"
shape='^(#|$|[A-Z][A-Z0-9_]*=[^[:space:]"'"'"']*$)'
if grep -nvE "$shape" "$pins"; then
  echo "load-pins: the lines above are not NAME=value; see the format note in tools/toolchain.env"
  exit 1
fi
grep -E '^[A-Z]' "$pins" >> "$GITHUB_ENV"
echo "load-pins: $(grep -cE '^[A-Z]' "$pins") pins from tools/toolchain.env"
