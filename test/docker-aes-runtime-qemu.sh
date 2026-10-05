#!/usr/bin/env bash
# Runs test/aes-runtime-qemu.sh inside an ubuntu container: a host
# object's rows under each ch_cfg.cpu value, run under qemu-x86_64 on CPU
# models without the instructions the value does not name
# (docs/decisions.md 81, 89, 90 and 93). It hands that script its own
# argument: "x86-kernels" builds and runs bin/x86_kernels_test alone,
# which counts the calls into the x86-64 kernels, and "sha2-equiv"
# bin/sha2_equiv_test alone, which holds sha256_hw.c to sha256.c on the SHA
# extensions qemu's max model has. The mips job
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
# names this script as its catch target, as does the violation that
# hashes a client's transcript under bits its caller never set. The
# violations of chacha20.c's use_avx2 and gcm_vaes.h's gcm_use_vaes name
# it with "x86-kernels", and the violations of sha256_hw.c's constants and
# wipes with "sha2-equiv".
# Needs docker (OrbStack works); skips without it.
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
        bash /src/test/docker-aes-runtime-qemu.sh --inside "$@"
fi
shift

# ---- inside the container from here on ----
export DEBIAN_FRONTEND=noninteractive
apt-get update -q >/dev/null
if [ "$(uname -m)" = x86_64 ]; then
    apt-get install -y -q make gcc libc6-dev qemu-user >/dev/null
else
    apt-get install -y -q make gcc gcc-x86-64-linux-gnu libc6-dev-amd64-cross qemu-user >/dev/null
    export X86_CC=x86_64-linux-gnu-gcc
fi
exec ./test/aes-runtime-qemu.sh "$@"
