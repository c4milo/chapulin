#!/usr/bin/env bash
# Runs test/aes-runtime-qemu.sh inside an ubuntu container: a host
# object's rows without the CH_CPU_CONSTANT_TIME_AES bit, run under
# qemu-x86_64 on a CPU model without AES-NI or PCLMULQDQ (docs/decisions.md
# 81 and 89). The mips job
# in .github/workflows/check.yml runs the same script on its runner.
# tools/toolchain.env pins the container, and the container's apt supplies
# gcc and qemu-user, as the runner's does (Ubuntu 24.04 ships gcc 13.3 and
# qemu 8.2.2).
#
# The container runs on the host's architecture. On an arm64 host the
# script compiles with x86_64-linux-gnu-gcc, because an x86-64 container
# there runs gcc under emulation, about ten times slower. qemu-x86_64
# emulates the same CPU model on either host.
#
# test/violations/inv26-runtime-initial-seal-ignores-answer.violation
# names this script as its catch target. Needs docker (OrbStack works);
# skips without it.
set -euo pipefail

if [ "${1:-}" != "--inside" ]; then
    cd "$(dirname "$0")/.."
    # shellcheck source=tools/toolchain.env
    . tools/toolchain.env
    command -v docker >/dev/null 2>&1 || {
        echo "SKIP the host object's qemu lane: docker not available" >&2
        exit 0
    }
    exec docker run --rm -v "$PWD":/src -w /src "ubuntu@$UBUNTU_DIGEST" \
        bash /src/test/docker-aes-runtime-qemu.sh --inside
fi

# ---- inside the container from here on ----
export DEBIAN_FRONTEND=noninteractive
apt-get update -q >/dev/null
if [ "$(uname -m)" = x86_64 ]; then
    apt-get install -y -q make gcc libc6-dev qemu-user >/dev/null
else
    apt-get install -y -q make gcc gcc-x86-64-linux-gnu libc6-dev-amd64-cross qemu-user >/dev/null
    export X86_CC=x86_64-linux-gnu-gcc
fi
exec ./test/aes-runtime-qemu.sh
