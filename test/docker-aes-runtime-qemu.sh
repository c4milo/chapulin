#!/usr/bin/env bash
# Runs test/aes-runtime-qemu.sh inside an ubuntu container: a host
# object's rows under each ch_cfg.cpu value, run under qemu-x86_64 and
# qemu-aarch64 on CPU models without the instructions the value does not
# name (docs/decisions.md 81, 89, 90, 93 and 94). It hands that script its
# own argument, which runs one part of it: "x86-kernels" builds and runs
# bin/x86_kernels_test alone, which counts the calls into the x86-64
# kernels; "sha2-equiv" bin/sha2_equiv_test alone, for x86-64 and for
# arm64, which holds sha256_hw.c and sha512_hw.c to the portable code on
# the instructions qemu's max models have; "arm64-hash-count" the two
# counting binaries for arm64, which alone compiles the SHA-512 entries;
# "p256-equiv" bin/p256_equiv_test alone, for x86-64 and for arm64,
# which holds the wide P-256 files to the files under their own names on
# the two forms of their carry steps that gcc reads; "keccak"
# bin/sha3_hw_equiv_test and bin/mlkem_hw_equiv_test alone, which clang
# builds for arm64, the one object that holds Keccak on the SHA-3
# instructions; "aes-equiv" bin/aes_equiv_test alone, for x86-64 and for
# arm64, which holds aes_hw.c's two key expansions to the table and
# searches the stack each leaves; "rsa-ifma-callers"
# bin/tcp_blocking_loop_host and bin/webpki_auth_host alone, for x86-64,
# which count the RSA public operations each caller of the verifiers
# sends to AVX-512 IFMA; and
# "rsa-ifma" bin/webpki_loop_aes alone for x86-64, whose server runs
# ch_srv_check with and without CH_CPU_AVX512_IFMA on a model without
# AVX-512 IFMA; and "rsa-addcarry" bin/rsa_addcarry_equiv_test and
# bin/rsa_sign_equiv_test alone, which gcc builds for x86-64 on
# rsa_mont64_addcarry.c's rows.
# The mips job in .github/workflows/check.yml runs the same script on its
# runner. tools/toolchain.env pins the container, and the container's apt
# supplies gcc, clang and qemu-user, as the runner's does (Ubuntu 24.04
# ships gcc 13.3, clang 18.1 and qemu 8.2.2).
#
# The container runs on the host's architecture, and the script compiles
# for the other one with the cross gcc: x86_64-linux-gnu-gcc on an arm64
# host and aarch64-linux-gnu-gcc on an x86-64 one. A container of the other
# architecture would run gcc under emulation, about ten times slower. Each
# qemu emulates the same CPU model on either host.
#
# test/violations/inv26-runtime-initial-seal-ignores-answer.violation
# names this script as its catch target, as does the violation that
# hashes a client's transcript under bits its caller never set. The
# violations of chacha20.c's use_avx2 and gcm_vaes.h's gcm_use_vaes name
# it with "x86-kernels", the violations of sha256_hw.c's and sha512_hw.c's
# constants and wipes with "sha2-equiv", the violations of the
# SHA-512 entries with "arm64-hash-count", the two violations of the
# intrinsics in p256_wide_word.h's carry steps with "p256-equiv", the
# violations of what sha3_hw.c leaves on the stack with "keccak", the
# violations of aes_hw.c's two key expansions with "aes-equiv", and the
# violations that hand an RSA verifier 0 in place of a session's
# ch_cfg.cpu with "rsa-ifma-callers", and the violations of the rows'
# intrinsic, their wipes and the define that picks them with
# "rsa-addcarry".
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
    apt-get install -y -q make gcc libc6-dev gcc-aarch64-linux-gnu libc6-dev-arm64-cross qemu-user clang >/dev/null
else
    apt-get install -y -q make gcc libc6-dev gcc-x86-64-linux-gnu libc6-dev-amd64-cross qemu-user clang >/dev/null
fi
exec ./test/aes-runtime-qemu.sh "$@"
