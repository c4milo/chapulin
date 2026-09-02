#!/usr/bin/env bash
# Runs the mips CI lane locally: the codegen gate under Ubuntu's
# gcc-mips-linux-gnu, then the cross-check roster built with it and run
# under qemu-mips user mode, inside an x86_64 ubuntu container. Mirrors
# the mips job in .github/workflows/check.yml; tools/toolchain.env pins
# the container, and the container's apt supplies the gcc, as the job's
# does (Ubuntu 24.04 ships 12.4.0). Needs docker (OrbStack works); skips
# without it.
set -euo pipefail

if [ "${1:-}" != "--inside" ]; then
    cd "$(dirname "$0")/.."
    # shellcheck source=tools/toolchain.env
    . tools/toolchain.env
    command -v docker >/dev/null 2>&1 || {
        echo "SKIP mips local lane: docker not available" >&2
        exit 0
    }
    exec docker run --rm --platform linux/amd64 \
        -v "$PWD":/src -w /src "ubuntu@$UBUNTU_DIGEST" \
        bash /src/test/docker-mips.sh --inside
fi

# ---- inside the container from here on ----
export DEBIAN_FRONTEND=noninteractive
apt-get update -q >/dev/null
apt-get install -y -q make python3 git gcc-mips-linux-gnu qemu-user >/dev/null

# The same two steps the CI job runs, in its order: the codegen gate under
# this gcc -- both mips32r2 specs match its -dumpmachine, and the -O2 one
# holds poly1305.c at the two madd it records
# (https://github.com/c4milo/chapulin/issues/122) -- then the suites.
# test/violations/inv16-widemul-compare-carries.violation names this
# script as its catch target for the same reason.
make lint-wide-multiply-gcc WIDEMUL_GCC=mips-linux-gnu-gcc
make cross-check CROSS=mips-linux-gnu- RUNNER=qemu-mips
