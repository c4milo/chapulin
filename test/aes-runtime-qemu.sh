#!/usr/bin/env bash
# Shows that a host object's session runs an instruction set only where its
# caller's ch_cfg.cpu names it (docs/decisions.md 81, 89, 90 and 93). It
# builds host binaries for x86-64 and for arm64, statically, and runs them
# under qemu-x86_64 and qemu-aarch64 on CPU models that lack instructions,
# where each such instruction raises SIGILL.
#
# The x86-64 half, on a model without AES-NI, PCLMULQDQ and AVX2:
#
#   - bin/aes_runtime_test "absent" must pass: the published vectors of
#     RFC 9001 and RFC 9369 Appendix A, byte for byte, on the table and the
#     portable GHASH.
#   - bin/quic_loop_aes and bin/webpki_loop_aes "absent" must pass: whole
#     QUIC and TCP handshakes, resumptions and pin rows between this
#     tree's client and server, both ends stating the probe's bit alone,
#     in the objects that hold the instructions. Their ChaCha20 runs on
#     SSE2.
#   - bin/aes_runtime_test "present" must die of SIGILL, which is what shows
#     the CPU model traps the AES instructions, and so that the runs above
#     executed none.
#   - bin/quic_test_hw's vectors, whose first pass states the AES bit, must
#     die of SIGILL too.
#   - each loop with "cpu 0x9 0x9", both ends stating CH_CPU_AVX2 beside
#     the probe's bit, must die of SIGILL: its records or packets run
#     chacha20_avx2.c's kernel, which shows the model traps AVX2, and so
#     that the runs above executed none of it.
#
# On a model without AVX2 alone, which gcm_vaes.c's kernels need beside
# VAES and VPCLMULQDQ:
#
#   - bin/aes_runtime_test "present" and each loop with "cpu 0x7 0x7" must
#     pass: under the AES bit without CH_CPU_VAES, AES-GCM runs gcm_hw.c's
#     128-bit loops and no kernel.
#   - each loop with "cpu 0x17 0x17", both ends adding CH_CPU_VAES, must
#     die of SIGILL: its AES-GCM runs the kernels.
#
# On the model with every instruction qemu has, where it has the kernels':
#
#   - each loop with one end stating a kernel's bit and the other not, in
#     both orders, must pass: 0xd against 0x5, the AVX2 ChaCha20 against
#     SSE2, and 0x1f against 0x7, the VAES AES-GCM against the 128-bit
#     loops. A qemu that lacks a kernel's instructions skips its rows.
#
# On a model without the SHA extensions:
#
#   - each loop with "cpu 0x5 0x5" and with "cpu 0x7 0x7", both ends
#     leaving CH_CPU_CONSTANT_TIME_SHA256 clear, must pass: the first runs
#     ChaCha20 and its key schedule on SHA-256, the second AES-256-GCM
#     and its key schedule on SHA-384, and every SHA-256 call of both runs
#     sha256.c.
#   - each loop with "cpu 0x25 0x25" and with "cpu 0x27 0x27", the same
#     values with the bit, must die of SIGILL: a session with the bit
#     hashes its transcript on sha256_hw.c's instructions, which shows the
#     model traps them, and so that the runs above executed none.
#   - bin/aes_runtime_test "present" must pass: its rows state the AES bit
#     and no hash bit, so HKDF derives their Initial keys on sha256.c.
#
# On the model with every instruction qemu has, with
# CH_REQUIRE_HASH_INSTRUCTIONS=1 in the environment, so a qemu without
# the SHA extensions fails these rows and does not skip them:
#
#   - bin/sha2_equiv_test must pass: sha256_hw.c against sha256.c over
#     every length and split it tries, and no value of a call in the stack
#     the call leaves (test/sha2_equiv_test.c).
#   - each loop with one end stating the SHA-256 bit and the other not, in
#     both orders, must pass: 0x25 against 0x5 and 0x27 against 0x7, so
#     the instructions and sha256.c compute the same transcript hashes
#     and the same keys.
#
# On any model:
#
#   - bin/x86_kernels_test must pass. It counts the calls the library
#     sends to each kernel under each ch_cfg.cpu value and runs none of a
#     kernel's instructions (test/x86_kernels_test.c).
#   - bin/p256_equiv_test must pass for x86-64 and for arm64: the wide
#     P-256 files against the files under their own names
#     (test/p256_equiv_test.c), on the two forms of p256_wide_word.h's
#     carry steps that gcc reads, the intrinsics for x86-64 and the
#     128-bit sums for arm64 (docs/decisions.md 94). clang reads a third
#     form, so a machine whose compiler is clang compiles no line of the
#     intrinsics.
#   - bin/mlkem_vector_equiv_test must pass for x86-64 and for arm64: the
#     vector NTT on SSE2 and on NEON against mlkem_poly.c's loops
#     (test/mlkem_vector_equiv_test.c, docs/decisions.md 101). A machine's
#     own compiler reads one of the file's two arms, so this is the run
#     that holds the other.
#
# On the model with every instruction qemu has, which has the AES
# instructions on both architectures:
#
#   - bin/aes_equiv_test must pass for x86-64 and for arm64: aes_hw.c's
#     AES-NI arm and its Arm arm against quic_aes_soft.c's table, and the
#     search of the stack each key expansion leaves
#     (test/aes_equiv_test.c, docs/decisions.md 123). The two arms expand
#     a key in different code, and a machine's own compiler reads one, so
#     this is the run that holds the other.
#
# On the model with every instruction qemu has, with
# CH_REQUIRE_X86_KERNELS=1 in the environment, so a qemu without AVX2
# fails the row and does not skip it:
#
#   - bin/mlkem_avx2_equiv_test must pass for x86-64: the four-way Keccak
#     in AVX2 against sha3.c's SHAKE128, and ML-KEM's copy over it against
#     mlkem.c (test/mlkem_avx2_equiv_test.c, docs/decisions.md 107). Both
#     files have a body on x86-64 alone, so on an arm64 machine this is
#     the run that holds them.
#   - bin/poly1305_equiv_test must pass for x86-64: the AVX2 Poly1305 and
#     the SSE2 path against poly1305.c's loop, and the search of the stack
#     each leaves for the powers of r (test/poly1305_equiv_test.c,
#     docs/decisions.md 110). The kernel has a body on x86-64 alone.
#
# On any model, for x86-64:
#
#   - bin/tcp_blocking_loop_host and bin/webpki_auth_host must pass. On
#     the stand-ins test/rsa_ifma_count.c, test/rsa_ifma_sign_count.c and
#     test/aead_avx512_count.c, which run no AVX-512 instruction, they
#     count the RSA public operations each caller of the two verifiers
#     sends to AVX-512 IFMA: a pinned CertificateVerify, ch_srv_check's
#     check of the RSA identity, and a webpki chain with RSA links and its
#     CertificateVerify (test/tcp_blocking_loop_ifma.h,
#     test/webpki_auth_ifma.h). The first also counts the handshake's
#     ChaCha20 calls into the AVX-512 kernel. Only an x86-64 object sends
#     any, so on an arm64 machine this is the run that holds the callers.
#   - bin/rsa_addcarry_equiv_test and bin/rsa_sign_equiv_test must pass,
#     built by gcc for x86-64 with rsa_mont64_addcarry.c's rows on: the
#     rows on the _addcarry_u64 form of their add with carry against
#     rsa_mont64.c's loops, and the signer on the rows against the ladder,
#     with the search of the stack below it (docs/decisions.md 122). The
#     host object's rsa_mont64.c must call both row entries under that gcc.
#     A gcc build for x86-64 alone runs the rows, so on a machine whose
#     compiler is clang this is the run that holds them.
#
# On the model with every instruction qemu has, with
# CH_REQUIRE_X86_KERNELS=1 in the environment, so a qemu without AVX2
# fails the row and does not skip it:
#
#   - bin/rsa_avx2_equiv_test must pass for x86-64: rsa_avx2.c's RSA public
#     operation on AVX2 against the same file over its lane model, and
#     rsa_vp1_cpu under CH_CPU_AVX2 against rsa_vp1
#     (test/rsa_avx2_equiv_test.c, docs/decisions.md 122). The kernel has
#     a body on x86-64 alone.
#
# On a model without AES-NI, PCLMULQDQ, AVX2 and the SHA extensions:
#
#   - bin/hash_runtime_test and bin/hash_runtime_exporter_test must pass.
#     They count the calls into each hash's two paths under every
#     ch_cfg.cpu value and run no instruction a bit names
#     (test/hash_runtime_test.c).
#
# On a model without AVX-512 IFMA, which rsa_ifma.c's kernel runs:
#
#   - bin/webpki_loop_aes with "cpu 0x1 0x1" must pass: its server's
#     ch_srv_check verifies an RSA-PSS signature, and with the probe's bit
#     alone the public operation runs on rsa_mont64.c
#     (test/webpki_loop_runtime.h).
#   - the same loop with "cpu 0x101 0x101", both ends adding
#     CH_CPU_AVX512_IFMA, must die of SIGILL: that check runs the
#     operation on the kernel, which shows the model traps the kernel's
#     instructions, and so that the row above ran none of them.
#
# QEMU's TCG implements no AVX-512 instruction (QEMU 11.1.2 warns that it
# cannot give a model avx512f or avx512ifma), so no model here runs the
# kernel. The nightly's rsa-ifma-sde job runs it under Intel's Software
# Development Emulator (test/platforms.mk, rsa-ifma-sde-check).
#
# The arm64 half holds the SHA-512 bit, which an arm64 object alone
# defines. QEMU's cortex-a72 model has FEAT_AES, FEAT_PMULL and FEAT_SHA256
# and no FEAT_SHA512, and its max model has all four. On cortex-a72:
#
#   - each loop with "cpu 0x25 0x25" and with "cpu 0x27 0x27", both ends
#     leaving CH_CPU_CONSTANT_TIME_SHA512 clear, must pass: the second runs
#     AES-256-GCM, whose key schedule and transcript run SHA-384, on
#     sha512.c.
#   - each loop with "cpu 0x65 0x65" and with "cpu 0x67 0x67", the same
#     values with the bit, must die of SIGILL: a session with the bit
#     hashes its transcript on sha512_hw.c's instructions.
#   - bin/hash_runtime_test and bin/hash_runtime_exporter_test must pass
#     as an arm64 object, which alone compiles the SHA-512 entries they
#     count.
#
# On max, with CH_REQUIRE_HASH_INSTRUCTIONS=1:
#
#   - bin/sha2_equiv_test must pass: sha256_hw.c's arm64 arm against
#     sha256.c and sha512_hw.c against sha512.c.
#   - each loop with one end stating the SHA-512 bit and the other not, in
#     both orders, must pass: 0x65 against 0x25 and 0x67 against 0x27.
#
# The arm64 half once more as clang compiles it, for the SHA-3 bit: an
# arm64 object holds Keccak on the SHA-3 instructions where clang compiled
# it and nowhere else (docs/decisions.md 99). cortex-a72 has no FEAT_SHA3
# either, and every handshake of the two loops runs ML-KEM. On cortex-a72:
#
#   - each loop with "cpu 0x25 0x25" and with "cpu 0x27 0x27" must pass.
#   - each loop with "cpu 0xa5 0xa5" and with "cpu 0xa7 0xa7", the same
#     values with the SHA-3 bit, must die of SIGILL: a session with the bit
#     runs ML-KEM's hashes on the instructions.
#
# On max, with CH_REQUIRE_HASH_INSTRUCTIONS=1:
#
#   - bin/sha3_hw_equiv_test must pass: sha3_hw.c against sha3.c, and the
#     search of the stack each kind of call leaves.
#   - bin/mlkem_hw_equiv_test must pass: ML-KEM's two copies against
#     mlkem.c and mlkem_poly.c.
#   - each loop with one end stating the SHA-3 bit and the other not, in
#     both orders, must pass: 0xa5 against 0x25 and 0xa7 against 0x27.
#
# No QEMU arm64 model turns FEAT_AES or FEAT_SHA256 off (QEMU 8.2 and
# 10.2), so for those two the arm64 half of the claim rests on the call
# counts bin/aes_runtime_test and bin/hash_runtime_test read and on
# test/aes-runtime-disasm.sh, which finds the instructions in aes_hw.c's,
# ghash_hw.c's, gcm_hw.c's and sha256_hw.c's functions alone.
#
# One argument runs part of this, which is what a violation names as its
# catch when its edit shows on one architecture alone, so that its verdict
# is the same on every machine:
#
#   x86-kernels       bin/x86_kernels_test for x86-64, for the violations
#                     of chacha20.c's use_avx2 and gcm_vaes.h's
#                     gcm_use_vaes
#   sha2-equiv        bin/sha2_equiv_test for x86-64 and for arm64, for the
#                     violations of what sha256_hw.c and sha512_hw.c
#                     compute and wipe
#   arm64-hash-count  the two counting binaries for arm64, for the
#                     violations of the entries an arm64 object alone
#                     compiles
#   p256-equiv        bin/p256_equiv_test for x86-64 and for arm64, for the
#                     violations of the intrinsics in p256_wide_word.h's
#                     carry steps
#   keccak            bin/sha3_hw_equiv_test and bin/mlkem_hw_equiv_test
#                     for arm64, built with clang, for the violations of
#                     what sha3_hw.c computes and leaves on the stack
#   mlkem-vector      bin/mlkem_vector_equiv_test for x86-64 and for arm64,
#                     for the violations of mlkem_vector.c's SSE2 and NEON
#                     arms
#   poly1305-avx2     bin/poly1305_equiv_test for x86-64, for the
#                     violations of poly1305_avx2.c
#   aes-equiv         bin/aes_equiv_test for x86-64 and for arm64, for the
#                     violations of aes_hw.c's two key expansions
#   mlkem-avx2        bin/mlkem_avx2_equiv_test for x86-64, for the
#                     violations of keccak_avx2.c and mlkem_avx2.c
#   rsa-ifma-callers  bin/tcp_blocking_loop_host and bin/webpki_auth_host
#                     for x86-64, for the violations of the callers that
#                     hand the RSA verifiers a session's ch_cfg.cpu
#   rsa-ifma          bin/webpki_loop_aes for x86-64, its rows on the
#                     model without AVX-512 IFMA alone
#   rsa-addcarry      bin/rsa_addcarry_equiv_test and bin/rsa_sign_equiv_test
#                     for x86-64 under gcc, for the violations of the rows'
#                     intrinsic, their wipes and the define that picks them
#   rsa-avx2          bin/rsa_avx2_equiv_test for x86-64, for the
#                     violations of rsa_avx2_lanes.h's instructions
#
# Linux only: qemu-user runs a Linux binary. X86_CC and ARM64_CC name the
# two compilers. Each is cc by default where cc targets its architecture,
# and x86_64-linux-gnu-gcc or aarch64-linux-gnu-gcc where it does not.
# KECCAK_ARM64_CC names the clang that builds the SHA-3 rows for arm64,
# clang by default; it links with the libraries ARM64_CC's toolchain
# carries. The
# mips job in .github/workflows/check.yml runs this script on every push,
# because the qemu-user package it installs carries both emulators, and
# test/docker-aes-runtime-qemu.sh runs it in a container elsewhere.
cd "$(dirname "$0")/.." || exit 1
# Several runs below must die of SIGILL. Under a core limit above 0,
# qemu-user writes the guest's core file into this directory, and the
# kernel may write qemu's own: 9 MB and 153 MB in an ubuntu:24.04
# container.
ulimit -c 0
only=${1:-}
case "$only" in
"" | x86-kernels | sha2-equiv | arm64-hash-count | p256-equiv | keccak | mlkem-vector | mlkem-avx2 | poly1305-avx2 | \
    aes-equiv | rsa-ifma-callers | rsa-ifma | rsa-addcarry | rsa-avx2) ;;
*)
    echo "usage: $0 [x86-kernels | sha2-equiv | arm64-hash-count | p256-equiv | keccak | mlkem-vector | mlkem-avx2 | poly1305-avx2 | aes-equiv | rsa-ifma-callers | rsa-ifma | rsa-addcarry | rsa-avx2]" >&2
    exit 2
    ;;
esac

# The compiler for one architecture: the one the environment names, or cc
# where cc targets the architecture, or the cross gcc.
compiler_for() { # $1 = the environment's value, $2 = the target's macro, $3 = the cross gcc
    local cc=$1
    if [ -z "$cc" ]; then
        cc=$3
        cc -dM -E -x c /dev/null 2> /dev/null | grep -qw "$2" && cc=cc
    fi
    "$cc" -dM -E -x c /dev/null 2> /dev/null | grep -qw "$2" ||
        { echo "aes-runtime-qemu: $cc does not compile for $2; set X86_CC or ARM64_CC" >&2; exit 1; }
    printf '%s\n' "$cc"
}
# A part that runs one architecture's binaries needs that architecture's
# compiler and emulator alone.
x86_cc=""
arm64_cc=""
x86_qemu=${QEMU_X86_64:-qemu-x86_64}
arm64_qemu=${QEMU_AARCH64:-qemu-aarch64}
if [ "$only" != arm64-hash-count ] && [ "$only" != keccak ]; then
    x86_cc=$(compiler_for "${X86_CC:-}" __x86_64__ x86_64-linux-gnu-gcc) || exit 1
    command -v "$x86_qemu" > /dev/null || { echo "aes-runtime-qemu: $x86_qemu is missing" >&2; exit 1; }
fi
if [ "$only" != x86-kernels ] && [ "$only" != mlkem-avx2 ] && [ "$only" != poly1305-avx2 ] &&
    [ "$only" != rsa-ifma-callers ] && [ "$only" != rsa-ifma ] && [ "$only" != rsa-addcarry ] &&
    [ "$only" != rsa-avx2 ]; then
    arm64_cc=$(compiler_for "${ARM64_CC:-}" __aarch64__ aarch64-linux-gnu-gcc) || exit 1
    command -v "$arm64_qemu" > /dev/null || { echo "aes-runtime-qemu: $arm64_qemu is missing" >&2; exit 1; }
fi
# clang for arm64, the one compiler under which sha3_hw.c has a body.
keccak_cc=""
if [ -z "$only" ] || [ "$only" = keccak ]; then
    keccak_cc=${KECCAK_ARM64_CC:-clang}
    "$keccak_cc" --target=aarch64-linux-gnu -dM -E -x c /dev/null 2> /dev/null | grep -qw __clang__ ||
        { echo "aes-runtime-qemu: $keccak_cc is not a clang that compiles for aarch64; set KECCAK_ARM64_CC" >&2; exit 1; }
fi
x86_out=bin/qemu
arm64_out=bin/qemu-arm64
mkdir -p "$x86_out" "$arm64_out"
# No -DCH_NATIVE_WIDEMUL: every binary here is a host object, which holds
# both multiplies and whose ct.h refuses the define.
flags=(-Wall -Wextra -Wpedantic -Werror -std=c11 -O2 -D_DEFAULT_SOURCE -static -I. -Itest
       -DCH_RAND_EXTERN)
runtime=(-DCH_SUITE_AES_GCM -DCH_CPU_RUNTIME)
both=(-DCH_ROLE_SERVER -DCH_ROLE_BOTH -DCH_TRUST_WEBPKI)
exporter=(-DCH_EXPORTER -DHKDF_LABEL_MAX=32)
# Each binary links the sources its rule in the Makefile links, one list
# a line, so each list here is the one check links. X86_64_TARGET=yes
# makes each list name avx512_wipe.c where an x86-64 host object holds it,
# whatever this machine's compiler targets.
lists=$(make -s --no-print-directory print-aes-runtime-qemu-srcs X86_64_TARGET=yes) ||
    { echo "aes-runtime-qemu: make print-aes-runtime-qemu-srcs failed" >&2; exit 1; }
read -r -a quic_srcs <<< "$(sed -n 1p <<< "$lists")"
read -r -a tcp_srcs <<< "$(sed -n 2p <<< "$lists")"
read -r -a runtime_test_srcs <<< "$(sed -n 3p <<< "$lists")"
read -r -a quic_test_hw_srcs <<< "$(sed -n 4p <<< "$lists")"
read -r -a kernels_test_srcs <<< "$(sed -n 5p <<< "$lists")"
read -r -a sha2_equiv_srcs <<< "$(sed -n 6p <<< "$lists")"
read -r -a hash_count_srcs <<< "$(sed -n 7p <<< "$lists")"
read -r -a hash_count_quic_srcs <<< "$(sed -n 8p <<< "$lists")"
read -r -a p256_equiv_srcs <<< "$(sed -n 9p <<< "$lists")"
read -r -a sha3_hw_equiv_srcs <<< "$(sed -n 10p <<< "$lists")"
read -r -a mlkem_hw_equiv_srcs <<< "$(sed -n 11p <<< "$lists")"
read -r -a mlkem_vector_equiv_srcs <<< "$(sed -n 12p <<< "$lists")"
read -r -a mlkem_avx2_equiv_srcs <<< "$(sed -n 13p <<< "$lists")"
read -r -a poly1305_equiv_srcs <<< "$(sed -n 14p <<< "$lists")"
read -r -a blocking_counted_srcs <<< "$(sed -n 15p <<< "$lists")"
read -r -a webpki_auth_counted_srcs <<< "$(sed -n 16p <<< "$lists")"
read -r -a aes_equiv_srcs <<< "$(sed -n 17p <<< "$lists")"
read -r -a rsa_addcarry_equiv_srcs <<< "$(sed -n 18p <<< "$lists")"
read -r -a rsa_sign_equiv_srcs <<< "$(sed -n 19p <<< "$lists")"
read -r -a rsa_avx2_equiv_srcs <<< "$(sed -n 20p <<< "$lists")"
[ "${#rsa_avx2_equiv_srcs[@]}" -gt 0 ] ||
    { echo "aes-runtime-qemu: make print-aes-runtime-qemu-srcs printed fewer than twenty lists" >&2; exit 1; }
# avx512_wipe.c has a body for x86-64 alone. For arm64 it is a translation
# unit with no declaration, which -Wpedantic refuses, so the arm64 builds
# link these copies of the three lists they take, without it.
arm64_quic_srcs=()
arm64_tcp_srcs=()
arm64_hash_count_srcs=()
for src in "${quic_srcs[@]}"; do [ "$src" = avx512_wipe.c ] || arm64_quic_srcs+=("$src"); done
for src in "${tcp_srcs[@]}"; do [ "$src" = avx512_wipe.c ] || arm64_tcp_srcs+=("$src"); done
for src in "${hash_count_srcs[@]}"; do [ "$src" = avx512_wipe.c ] || arm64_hash_count_srcs+=("$src"); done

# Runs one binary on a CPU model and requires its exit status. A run that
# must pass prints what it wrote when it does not.
expect_on() { # $1 = qemu, $2 = its binaries' directory, $3 = model, $4 = the status, $5 = what a wrong status means, $6... = binary and arguments
    local emulator=$1 out=$2 model=$3 want=$4 meaning=$5 rc=0
    shift 5
    "$emulator" -cpu "$model" "$out/$1" "${@:2}" > "$out/row.log" 2>&1 || rc=$?
    [ "$rc" -eq "$want" ] && return 0
    [ "$want" -ne 0 ] || cat "$out/row.log" >&2
    echo "aes-runtime-qemu: $emulator on $model, $* exited $rc and not $want: $meaning" >&2
    exit 1
}
expect() { expect_on "$x86_qemu" "$x86_out" "$@"; }
expect_arm64() { expect_on "$arm64_qemu" "$arm64_out" "$@"; }
sigill=132
# QEMU's arm64 model without FEAT_SHA512 and FEAT_SHA3, which has FEAT_AES,
# FEAT_PMULL and FEAT_SHA256.
no_sha512=cortex-a72
no_sha3=cortex-a72
# QEMU's x86-64 model without AVX-512 IFMA. Its max model has no AVX-512
# instruction today, and the minus sign keeps the rows' meaning on a QEMU
# that adds them.
no_ifma='max,-avx512ifma'

# bin/webpki_loop_aes for x86-64: this tree's TCP client and server in the
# ROLE=both TRUST=webpki suite object.
build_webpki_loop() {
    "$x86_cc" "${flags[@]}" -DCH_TRANSPORT_TCP_NONBLOCKING "${both[@]}" "${runtime[@]}" \
        -o "$x86_out/webpki_loop_aes" test/webpki_loop_test.c "${tcp_srcs[@]}"
}

# The rows of CH_CPU_AVX512_IFMA. Each row's server runs ch_srv_check under
# its value before the handshake, and that check verifies an RSA-PSS
# signature, on rsa_ifma.c's kernel where the value holds the bit.
rsa_ifma_rows() {
    expect "$no_ifma" 0 "a server without CH_CPU_AVX512_IFMA ran an AVX-512 instruction" \
        webpki_loop_aes cpu 0x1 0x1
    expect "$no_ifma" "$sigill" "a server with CH_CPU_AVX512_IFMA ran no AVX-512 IFMA instruction" \
        webpki_loop_aes cpu 0x101 0x101
}

if [ -z "$only" ] || [ "$only" = x86-kernels ]; then
    "$x86_cc" "${flags[@]}" -DCH_TRANSPORT_QUIC_NONBLOCKING "${runtime[@]}" -o "$x86_out/x86_kernels_test" \
        test/x86_kernels_test.c test/x86_kernels_count.c "${kernels_test_srcs[@]}" || exit 1
    expect max 0 "a call ran a kernel its ch_cfg.cpu value does not name, or ran none where it does" \
        x86_kernels_test
fi
if [ "$only" = x86-kernels ]; then
    echo "aes-runtime-qemu: bin/x86_kernels_test counted each kernel's calls under every ch_cfg.cpu value"
    exit 0
fi

if [ -z "$only" ] || [ "$only" = p256-equiv ]; then
    # The wide P-256 files against the files under their own names, on the
    # two forms of the carry steps that gcc reads: the intrinsics for
    # x86-64 and the 128-bit sums for arm64. Each define names its form, so
    # a row runs it under any compiler, and not the form that compiler
    # would pick.
    "$x86_cc" "${flags[@]}" -DCH_CPU_RUNTIME -DP256_WIDE_CARRY=P256_WIDE_CARRY_INTRINSIC \
        -o "$x86_out/p256_equiv_test" test/p256_equiv_test.c "${p256_equiv_srcs[@]}" || exit 1
    expect max 0 \
        "the wide P-256 files on the x86-64 intrinsics and the files under their own names disagree, or a wide call left a word on the stack" \
        p256_equiv_test
    "$arm64_cc" "${flags[@]}" -DCH_CPU_RUNTIME -DP256_WIDE_CARRY=P256_WIDE_CARRY_SUM \
        -o "$arm64_out/p256_equiv_test" test/p256_equiv_test.c "${p256_equiv_srcs[@]}" || exit 1
    expect_arm64 max 0 \
        "the wide P-256 files on the 128-bit sums and the files under their own names disagree, or a wide call left a word on the stack" \
        p256_equiv_test
fi
if [ "$only" = p256-equiv ]; then
    echo "aes-runtime-qemu: bin/p256_equiv_test held the wide P-256 files to the files under their own names, on the intrinsics for x86-64 and on the 128-bit sums for arm64"
    exit 0
fi

if [ -z "$only" ] || [ "$only" = mlkem-vector ]; then
    # The vector NTT against mlkem_poly.c's loops, on SSE2 for x86-64 and
    # on NEON for arm64.
    "$x86_cc" "${flags[@]}" -DCH_CPU_RUNTIME -o "$x86_out/mlkem_vector_equiv_test" \
        test/mlkem_vector_equiv_test.c "${mlkem_vector_equiv_srcs[@]}" || exit 1
    expect max 0 "the vector NTT on SSE2 and mlkem_poly.c's loops disagree" mlkem_vector_equiv_test
    "$arm64_cc" "${flags[@]}" -DCH_CPU_RUNTIME -o "$arm64_out/mlkem_vector_equiv_test" \
        test/mlkem_vector_equiv_test.c "${mlkem_vector_equiv_srcs[@]}" || exit 1
    expect_arm64 max 0 "the vector NTT on NEON and mlkem_poly.c's loops disagree" mlkem_vector_equiv_test
fi
if [ "$only" = mlkem-vector ]; then
    echo "aes-runtime-qemu: bin/mlkem_vector_equiv_test held the vector NTT to mlkem_poly.c's loops, on SSE2 for x86-64 and on NEON for arm64"
    exit 0
fi

if [ -z "$only" ] || [ "$only" = mlkem-avx2 ]; then
    # The four-way Keccak against sha3.c and ML-KEM's copy over it against
    # mlkem.c, which have a body on x86-64 alone.
    "$x86_cc" "${flags[@]}" -DCH_CPU_RUNTIME -o "$x86_out/mlkem_avx2_equiv_test" \
        test/mlkem_avx2_equiv_test.c "${mlkem_avx2_equiv_srcs[@]}" || exit 1
    CH_REQUIRE_X86_KERNELS=1 expect max 0 \
        "the four-way Keccak and sha3.c disagree, or ML-KEM's copy over it and mlkem.c do" \
        mlkem_avx2_equiv_test
fi
if [ "$only" = mlkem-avx2 ]; then
    echo "aes-runtime-qemu: bin/mlkem_avx2_equiv_test held the four-way Keccak to sha3.c and ML-KEM's copy over it to mlkem.c, on AVX2 for x86-64"
    exit 0
fi

if [ -z "$only" ] || [ "$only" = poly1305-avx2 ]; then
    # The AVX2 Poly1305 and the SSE2 path against poly1305.c's loop. The
    # kernel has a body on x86-64 alone.
    "$x86_cc" "${flags[@]}" -o "$x86_out/poly1305_equiv_test" test/poly1305_equiv_test.c \
        "${poly1305_equiv_srcs[@]}" || exit 1
    CH_REQUIRE_X86_KERNELS=1 expect max 0 \
        "the AVX2 Poly1305 or the SSE2 path and poly1305.c's loop disagree, or a call left a power of r on the stack" \
        poly1305_equiv_test
fi
if [ "$only" = poly1305-avx2 ]; then
    echo "aes-runtime-qemu: bin/poly1305_equiv_test held the AVX2 Poly1305 and the SSE2 path to poly1305.c's loop, on AVX2 for x86-64"
    exit 0
fi

if [ -z "$only" ] || [ "$only" = aes-equiv ]; then
    # aes_hw.c against quic_aes_soft.c's table, on AES-NI for x86-64 and
    # on the Arm AES instructions for arm64, with the search of the stack
    # each key expansion leaves. test/aes_equiv_hw.c defines
    # CH_CPU_RUNTIME itself, as the Makefile's rule says, so no line here
    # passes it.
    "$x86_cc" "${flags[@]}" -DCH_TRANSPORT_QUIC_NONBLOCKING -o "$x86_out/aes_equiv_test" \
        test/aes_equiv_test.c "${aes_equiv_srcs[@]}" || exit 1
    expect max 0 \
        "aes_hw.c's AES-NI arm and the table disagree, or a key expansion left a word it computed on the stack" \
        aes_equiv_test
    "$arm64_cc" "${flags[@]}" -DCH_TRANSPORT_QUIC_NONBLOCKING -o "$arm64_out/aes_equiv_test" \
        test/aes_equiv_test.c "${aes_equiv_srcs[@]}" || exit 1
    expect_arm64 max 0 \
        "aes_hw.c's Arm arm and the table disagree, or a key expansion left a word it computed on the stack" \
        aes_equiv_test
fi
if [ "$only" = aes-equiv ]; then
    echo "aes-runtime-qemu: bin/aes_equiv_test held aes_hw.c to the table and found no word of a schedule on the stack, on AES-NI for x86-64 and on the Arm AES instructions for arm64"
    exit 0
fi

if [ -z "$only" ] || [ "$only" = rsa-ifma-callers ]; then
    # The binaries that count the RSA public operations each caller of the
    # two verifiers sends to AVX-512 IFMA, as their rules in the Makefile
    # build them. They link test/rsa_ifma_count.c in place of rsa_ifma.c,
    # and the Makefile's other stand-ins in place of the AVX-512 signer,
    # ChaCha20 and Poly1305, so no row runs an AVX-512 instruction and any
    # model runs them.
    "$x86_cc" "${flags[@]}" -DCH_CPU_RUNTIME -DTEST_WIDEMUL_COUNTED -DCH_ROLE_SERVER -DCH_ROLE_BOTH \
        -o "$x86_out/tcp_blocking_loop_host" test/tcp_blocking_loop_test.c "${blocking_counted_srcs[@]}" ||
        exit 1
    expect max 0 \
        "a pinned CertificateVerify or ch_srv_check's check sent RSA's public operation to AVX-512 IFMA under a value without CH_CPU_AVX512_IFMA, or none under a value with it" \
        tcp_blocking_loop_host
    "$x86_cc" "${flags[@]}" -DCH_CPU_RUNTIME -DTEST_WIDEMUL_COUNTED -DCH_TRUST_WEBPKI \
        -o "$x86_out/webpki_auth_host" test/webpki_auth_test.c "${webpki_auth_counted_srcs[@]}" || exit 1
    expect max 0 \
        "a webpki chain's link or its CertificateVerify sent RSA's public operation to AVX-512 IFMA under a value without CH_CPU_AVX512_IFMA, or none under a value with it" \
        webpki_auth_host
fi
if [ "$only" = rsa-ifma-callers ]; then
    echo "aes-runtime-qemu: as an x86-64 object, each caller of the RSA verifiers sent the public operation to AVX-512 IFMA exactly where its session's ch_cfg.cpu held CH_CPU_AVX512_IFMA"
    exit 0
fi

if [ -z "$only" ] || [ "$only" = rsa-addcarry ]; then
    # rsa_mont64_addcarry.c's rows, which a gcc build for x86-64 alone runs
    # (docs/decisions.md 122): the host object's rsa_mont64.c calls both row
    # entries under a gcc, and neither under a clang X86_CC names. The two
    # binaries name the rows, so they run them under either, as their rules
    # in the Makefile do for bin/rsa_addcarry_equiv_test.
    rows_called=1
    "$x86_cc" -dM -E -x c /dev/null | grep -qw __clang__ && rows_called=0
    "$x86_cc" -std=c11 -O2 -DCH_RAND_EXTERN -DCH_CPU_RUNTIME -I. -c rsa_mont64.c -o "$x86_out/rsa_mont64.o" ||
        exit 1
    for symbol in rsa_mont64_addcarry_mul rsa_mont64_addcarry_square; do
        called=0
        nm -u "$x86_out/rsa_mont64.o" | grep -qw "$symbol" && called=1
        [ "$called" = "$rows_called" ] ||
            { echo "aes-runtime-qemu: rsa_mont64.c under $x86_cc calls $symbol: $called, where a gcc build alone does" >&2
              exit 1; }
    done
    rows=(-DCH_CPU_RUNTIME -DRSA_MONT64_ADDCARRY=1 -DRSA_MONT64_BLOCKS=0 -DCH_RSA_MODULUS_MAX=512)
    "$x86_cc" "${flags[@]}" "${rows[@]}" -o "$x86_out/rsa_addcarry_equiv_test" "${rsa_addcarry_equiv_srcs[@]}" ||
        exit 1
    expect max 0 "the rows on _addcarry_u64 and rsa_mont64.c's loops disagree" rsa_addcarry_equiv_test
    "$x86_cc" "${flags[@]}" "${rows[@]}" -o "$x86_out/rsa_sign_equiv_test" test/rsa_sign_equiv_test.c \
        "${rsa_sign_equiv_srcs[@]}" || exit 1
    expect max 0 \
        "the signer on the rows and the ladder disagree, or a call left a value it computed from the key on the stack" \
        rsa_sign_equiv_test
fi
if [ -z "$only" ] || [ "$only" = rsa-avx2 ]; then
    # RSA's public operation on AVX2 against its lane model, which has a
    # body on x86-64 alone. The binary builds at the 512-byte bound, where
    # the kernel holds both digit widths.
    "$x86_cc" "${flags[@]}" -DCH_CPU_RUNTIME -DCH_RSA_MODULUS_MAX=512 -o "$x86_out/rsa_avx2_equiv_test" \
        "${rsa_avx2_equiv_srcs[@]}" || exit 1
    CH_REQUIRE_X86_KERNELS=1 expect max 0 \
        "rsa_avx2.c on AVX2 and its lane model disagree, or rsa_vp1_cpu under CH_CPU_AVX2 and rsa_vp1 do" \
        rsa_avx2_equiv_test
fi
if [ "$only" = rsa-avx2 ]; then
    echo "aes-runtime-qemu: bin/rsa_avx2_equiv_test held rsa_avx2.c on AVX2 to its lane model, and rsa_vp1_cpu under CH_CPU_AVX2 to rsa_vp1, for x86-64"
    exit 0
fi

if [ "$only" = rsa-addcarry ]; then
    echo "aes-runtime-qemu: under gcc for x86-64 rsa_mont64.c called the rows, bin/rsa_addcarry_equiv_test held them to the loops on _addcarry_u64, and bin/rsa_sign_equiv_test held the signer on them to the ladder and found nothing on the stack"
    exit 0
fi

if [ "$only" = rsa-ifma ]; then
    build_webpki_loop || exit 1
    rsa_ifma_rows
    echo "aes-runtime-qemu: on $no_ifma bin/webpki_loop_aes passed with both ends stating the probe's bit alone, and died of SIGILL with both stating CH_CPU_AVX512_IFMA"
    exit 0
fi

if [ -z "$only" ] || [ "$only" = keccak ]; then
    # sha3_hw.c against sha3.c, with the search of the stack each kind of
    # call leaves, and ML-KEM's two copies against mlkem.c and
    # mlkem_poly.c, as clang compiles them for arm64, on the model with
    # every instruction. The binaries fail where the model lacks FEAT_SHA3
    # or the object holds no Keccak on the instructions, so these rows
    # cannot pass by skipping.
    "$keccak_cc" --target=aarch64-linux-gnu "${flags[@]}" -DCH_CPU_RUNTIME \
        -o "$arm64_out/sha3_hw_equiv_test" test/sha3_hw_equiv_test.c "${sha3_hw_equiv_srcs[@]}" || exit 1
    CH_REQUIRE_HASH_INSTRUCTIONS=1 expect_arm64 max 0 \
        "sha3_hw.c and sha3.c disagree, a call left a lane it computed on the stack, the object holds no Keccak on the instructions, or this qemu's max model lacks FEAT_SHA3" \
        sha3_hw_equiv_test
    "$keccak_cc" --target=aarch64-linux-gnu "${flags[@]}" -DCH_CPU_RUNTIME \
        -o "$arm64_out/mlkem_hw_equiv_test" test/mlkem_hw_equiv_test.c "${mlkem_hw_equiv_srcs[@]}" || exit 1
    CH_REQUIRE_HASH_INSTRUCTIONS=1 expect_arm64 max 0 \
        "ML-KEM's copies and mlkem.c disagree, the object holds no Keccak on the instructions, or this qemu's max model lacks FEAT_SHA3" \
        mlkem_hw_equiv_test
fi
if [ "$only" = keccak ]; then
    echo "aes-runtime-qemu: as clang compiles them for arm64, bin/sha3_hw_equiv_test held sha3_hw.c to sha3.c and found no lane on the stack, and bin/mlkem_hw_equiv_test held ML-KEM's copies to mlkem.c"
    exit 0
fi

if [ -z "$only" ] || [ "$only" = sha2-equiv ]; then
    # sha256_hw.c against sha256.c, and on arm64 sha512_hw.c against
    # sha512.c, each on the model with every instruction. The binary fails
    # where the model lacks a hash's instructions, so these rows cannot pass
    # by skipping.
    "$x86_cc" "${flags[@]}" -DCH_CPU_RUNTIME -DCH_HASH_SHA384 "${exporter[@]}" \
        -o "$x86_out/sha2_equiv_test" test/sha2_equiv_test.c "${sha2_equiv_srcs[@]}" || exit 1
    CH_REQUIRE_HASH_INSTRUCTIONS=1 expect max 0 \
        "sha256_hw.c and sha256.c disagree, a call left a value it computed on the stack, or this qemu's max model lacks the SHA extensions" \
        sha2_equiv_test
    "$arm64_cc" "${flags[@]}" -DCH_CPU_RUNTIME -DCH_HASH_SHA384 "${exporter[@]}" \
        -o "$arm64_out/sha2_equiv_test" test/sha2_equiv_test.c "${sha2_equiv_srcs[@]}" || exit 1
    CH_REQUIRE_HASH_INSTRUCTIONS=1 expect_arm64 max 0 \
        "sha256_hw.c or sha512_hw.c disagrees with the portable code, a call left a value it computed on the stack, or this qemu's max model lacks FEAT_SHA256 or FEAT_SHA512" \
        sha2_equiv_test
fi
if [ "$only" = sha2-equiv ]; then
    echo "aes-runtime-qemu: bin/sha2_equiv_test held sha256_hw.c to sha256.c on x86-64 and arm64, and sha512_hw.c to sha512.c on arm64"
    exit 0
fi

# The two counting binaries for arm64, which alone compiles the SHA-512
# entries. They run no hash instruction, so the model without FEAT_SHA512
# runs them.
"$arm64_cc" "${flags[@]}" -DCH_TRANSPORT_QUIC_NONBLOCKING "${runtime[@]}" -o "$arm64_out/hash_runtime_test" \
    test/hash_runtime_test.c "${arm64_hash_count_srcs[@]}" "${hash_count_quic_srcs[@]}" || exit 1
"$arm64_cc" "${flags[@]}" "${runtime[@]}" "${exporter[@]}" -o "$arm64_out/hash_runtime_exporter_test" \
    test/hash_runtime_test.c "${arm64_hash_count_srcs[@]}" || exit 1
for b in hash_runtime_test hash_runtime_exporter_test; do
    expect_arm64 "$no_sha512" 0 \
        "a hash call ran on a path its ch_cfg.cpu value does not name" "$b"
done
if [ "$only" = arm64-hash-count ]; then
    echo "aes-runtime-qemu: the two counting binaries counted each hash's calls under every ch_cfg.cpu value in an arm64 object"
    exit 0
fi

"$x86_cc" "${flags[@]}" -DCH_TRANSPORT_QUIC_NONBLOCKING "${runtime[@]}" -o "$x86_out/aes_runtime_test" \
    test/aes_runtime_test.c test/aes_runtime_soft.c test/aes_runtime_hw.c "${runtime_test_srcs[@]}" || exit 1
"$x86_cc" "${flags[@]}" -DCH_TRANSPORT_QUIC_NONBLOCKING "${both[@]}" "${runtime[@]}" \
    -o "$x86_out/quic_loop_aes" test/quic_loop_test.c "${quic_srcs[@]}" || exit 1
build_webpki_loop || exit 1
"$x86_cc" "${flags[@]}" -DCH_TRANSPORT_QUIC_NONBLOCKING -DCH_CPU_RUNTIME -DCH_AES_256_TEST \
    -o "$x86_out/quic_test_hw" test/quic_vectors.c "${quic_test_hw_srcs[@]}" || exit 1
"$x86_cc" "${flags[@]}" -DCH_TRANSPORT_QUIC_NONBLOCKING "${runtime[@]}" -o "$x86_out/hash_runtime_test" \
    test/hash_runtime_test.c "${hash_count_srcs[@]}" "${hash_count_quic_srcs[@]}" || exit 1
"$x86_cc" "${flags[@]}" "${runtime[@]}" "${exporter[@]}" -o "$x86_out/hash_runtime_exporter_test" \
    test/hash_runtime_test.c "${hash_count_srcs[@]}" || exit 1
loops=(quic_loop_aes webpki_loop_aes)

# No AES-NI, PCLMULQDQ or AVX2.
bare='max,-aes,-pclmulqdq,-avx2'
for b in aes_runtime_test "${loops[@]}"; do
    expect "$bare" 0 "a row without the AES bit and without CH_CPU_AVX2 ran one of their instructions" \
        "$b" absent
done
expect "$bare" "$sigill" "the model does not trap the AES instructions" aes_runtime_test present
expect "$bare" "$sigill" "the vectors that state the AES bit ran no AES instruction" quic_test_hw
for b in "${loops[@]}"; do
    expect "$bare" "$sigill" "a session with CH_CPU_AVX2 ran no AVX2 instruction" "$b" cpu 0x9 0x9
done

# AES-NI and PCLMULQDQ, and no AVX2, so no VAES kernel either.
no_avx2='max,-avx2'
expect "$no_avx2" 0 "the AES bit alone ran a 256-bit instruction" aes_runtime_test present
for b in "${loops[@]}"; do
    expect "$no_avx2" 0 "a session with the AES bit and without CH_CPU_VAES ran a 256-bit instruction" \
        "$b" cpu 0x7 0x7
    expect "$no_avx2" "$sigill" "a session with CH_CPU_VAES beside the AES bit ran no kernel" \
        "$b" cpu 0x17 0x17
done

# No SHA extensions. A session hashes on them exactly where its
# ch_cfg.cpu holds the SHA-256 bit.
no_sha='max,-sha-ni'
for b in "${loops[@]}"; do
    for bits in 0x5 0x7; do
        expect "$no_sha" 0 "a session without the SHA-256 bit ran a SHA instruction" \
            "$b" cpu "$bits" "$bits"
    done
    for bits in 0x25 0x27; do
        expect "$no_sha" "$sigill" "a session with the SHA-256 bit ran no SHA instruction" \
            "$b" cpu "$bits" "$bits"
    done
done
expect "$no_sha" 0 "a row without the SHA-256 bit derived its Initial keys on a SHA instruction" \
    aes_runtime_test present

# None of the instructions a ch_cfg.cpu bit names. The two binaries that
# count each hash's calls run every path on the portable code and seal
# their Initial packet on the table, so they must pass here.
no_named="$bare,-sha-ni"
for b in hash_runtime_test hash_runtime_exporter_test; do
    expect "$no_named" 0 "a binary that counts hash calls ran an instruction a ch_cfg.cpu bit names" "$b"
done

# No AVX-512 IFMA.
rsa_ifma_rows

# Every instruction this qemu has. One end on the SHA extensions and the
# other on sha256.c must compute the same transcript hashes and keys: with
# ChaCha20, whose key schedule runs SHA-256, and with AES-256-GCM, whose
# transcript takes SHA-256 beside SHA-384.
for b in "${loops[@]}"; do
    CH_REQUIRE_HASH_INSTRUCTIONS=1 expect max 0 "the SHA extensions and sha256.c disagree" "$b" cpu 0x25 0x5
    CH_REQUIRE_HASH_INSTRUCTIONS=1 expect max 0 "the SHA extensions and sha256.c disagree" "$b" cpu 0x5 0x25
    CH_REQUIRE_HASH_INSTRUCTIONS=1 expect max 0 "the SHA extensions and sha256.c disagree" "$b" cpu 0x27 0x7
    CH_REQUIRE_HASH_INSTRUCTIONS=1 expect max 0 "the SHA extensions and sha256.c disagree" "$b" cpu 0x7 0x27
done

# Every instruction this qemu has. One end on a kernel and the other on
# the 128-bit path must compute the same records and packets. The probe is
# the one the test binaries ask their CPU with (test/x86_kernels_cpu.h).
cat > "$x86_out/probe.c" << 'PROBE'
#include <stdio.h>

#include "x86_kernels_cpu.h"

int main(void) {
    printf("%s %s\n", x86_cpu_has_avx2() ? "avx2" : "-",
           x86_cpu_has_vaes() ? "vaes vpclmulqdq" : "-");
    return 0;
}
PROBE
"$x86_cc" "${flags[@]}" -o "$x86_out/probe" "$x86_out/probe.c" || exit 1
cpuid=$("$x86_qemu" -cpu max "$x86_out/probe") ||
    { echo "aes-runtime-qemu: the CPU probe failed on max" >&2; exit 1; }
mixed="no handshake between a kernel and a 128-bit path: this qemu's max model lacks AVX2"
if grep -qw avx2 <<< "$cpuid"; then
    mixed="one end on the AVX2 ChaCha20 and the other on SSE2 agreed"
    for b in "${loops[@]}"; do
        expect max 0 "the AVX2 ChaCha20 and the SSE2 one disagree" "$b" cpu 0xd 0x5
        expect max 0 "the AVX2 ChaCha20 and the SSE2 one disagree" "$b" cpu 0x5 0xd
    done
    if grep -qw vaes <<< "$cpuid" && grep -qw vpclmulqdq <<< "$cpuid"; then
        mixed="$mixed, and so did one on the VAES AES-GCM and the other on the 128-bit loops"
        for b in "${loops[@]}"; do
            expect max 0 "the VAES AES-GCM and the 128-bit one disagree" "$b" cpu 0x1f 0x7
            expect max 0 "the VAES AES-GCM and the 128-bit one disagree" "$b" cpu 0x7 0x1f
        done
    fi
fi

# The arm64 half: the two loops as an arm64 host object, whose sessions
# hash SHA-384 on the SHA-512 instructions exactly where their ch_cfg.cpu
# holds the SHA-512 bit.
"$arm64_cc" "${flags[@]}" -DCH_TRANSPORT_QUIC_NONBLOCKING "${both[@]}" "${runtime[@]}" \
    -o "$arm64_out/quic_loop_aes" test/quic_loop_test.c "${arm64_quic_srcs[@]}" || exit 1
"$arm64_cc" "${flags[@]}" -DCH_TRANSPORT_TCP_NONBLOCKING "${both[@]}" "${runtime[@]}" \
    -o "$arm64_out/webpki_loop_aes" test/webpki_loop_test.c "${arm64_tcp_srcs[@]}" || exit 1
for b in "${loops[@]}"; do
    for bits in 0x25 0x27; do
        expect_arm64 "$no_sha512" 0 "a session without the SHA-512 bit ran a SHA-512 instruction" \
            "$b" cpu "$bits" "$bits"
    done
    for bits in 0x65 0x67; do
        expect_arm64 "$no_sha512" "$sigill" "a session with the SHA-512 bit ran no SHA-512 instruction" \
            "$b" cpu "$bits" "$bits"
    done
    CH_REQUIRE_HASH_INSTRUCTIONS=1 expect_arm64 max 0 "the SHA-512 instructions and sha512.c disagree" "$b" cpu 0x65 0x25
    CH_REQUIRE_HASH_INSTRUCTIONS=1 expect_arm64 max 0 "the SHA-512 instructions and sha512.c disagree" "$b" cpu 0x25 0x65
    CH_REQUIRE_HASH_INSTRUCTIONS=1 expect_arm64 max 0 "the SHA-512 instructions and sha512.c disagree" "$b" cpu 0x67 0x27
    CH_REQUIRE_HASH_INSTRUCTIONS=1 expect_arm64 max 0 "the SHA-512 instructions and sha512.c disagree" "$b" cpu 0x27 0x67
done

# The two loops once more as clang compiles them for arm64, the one object
# that holds Keccak on the SHA-3 instructions. Every handshake runs ML-KEM,
# whose hashes run on the instructions exactly where an end's ch_cfg.cpu
# holds the SHA-3 bit.
"$keccak_cc" --target=aarch64-linux-gnu "${flags[@]}" -DCH_TRANSPORT_QUIC_NONBLOCKING "${both[@]}" \
    "${runtime[@]}" -o "$arm64_out/quic_loop_keccak" test/quic_loop_test.c "${arm64_quic_srcs[@]}" || exit 1
"$keccak_cc" --target=aarch64-linux-gnu "${flags[@]}" -DCH_TRANSPORT_TCP_NONBLOCKING "${both[@]}" \
    "${runtime[@]}" -o "$arm64_out/webpki_loop_keccak" test/webpki_loop_test.c "${arm64_tcp_srcs[@]}" || exit 1
for b in quic_loop_keccak webpki_loop_keccak; do
    for bits in 0x25 0x27; do
        expect_arm64 "$no_sha3" 0 "a session without the SHA-3 bit ran a SHA-3 instruction" \
            "$b" cpu "$bits" "$bits"
    done
    for bits in 0xa5 0xa7; do
        expect_arm64 "$no_sha3" "$sigill" "a session with the SHA-3 bit ran no SHA-3 instruction" \
            "$b" cpu "$bits" "$bits"
    done
    CH_REQUIRE_HASH_INSTRUCTIONS=1 expect_arm64 max 0 "the SHA-3 instructions and sha3.c disagree" "$b" cpu 0xa5 0x25
    CH_REQUIRE_HASH_INSTRUCTIONS=1 expect_arm64 max 0 "the SHA-3 instructions and sha3.c disagree" "$b" cpu 0x25 0xa5
    CH_REQUIRE_HASH_INSTRUCTIONS=1 expect_arm64 max 0 "the SHA-3 instructions and sha3.c disagree" "$b" cpu 0xa7 0x27
    CH_REQUIRE_HASH_INSTRUCTIONS=1 expect_arm64 max 0 "the SHA-3 instructions and sha3.c disagree" "$b" cpu 0x27 0xa7
done

echo "aes-runtime-qemu: on $bare the rows without the AES bit and without CH_CPU_AVX2 passed in the" \
    "vectors and both loops, and the rows with either died of SIGILL; on $no_avx2 the rows with" \
    "the AES bit passed and the rows that add CH_CPU_VAES died of SIGILL; on $no_sha the rows" \
    "without the SHA-256 bit passed and the rows with it died of SIGILL; on $no_named the two" \
    "binaries that count each hash's calls passed; on $no_ifma the webpki loop passed without" \
    "CH_CPU_AVX512_IFMA and died of SIGILL with it; on max, sha256_hw.c" \
    "agreed with sha256.c, one end on the SHA extensions and the other on sha256.c agreed, and" \
    "$mixed; on arm64's $no_sha512 the rows without the SHA-512 bit passed and the rows with it" \
    "died of SIGILL, and on its max sha512_hw.c agreed with sha512.c and one end on the SHA-512" \
    "instructions and the other on sha512.c agreed; as clang compiles arm64, on $no_sha3 the rows" \
    "without the SHA-3 bit passed and the rows with it died of SIGILL, and on max sha3_hw.c agreed" \
    "with sha3.c and left no lane on the stack, ML-KEM's copies agreed with mlkem.c, and one end on" \
    "the SHA-3 instructions and the other on sha3.c agreed; the vector NTT agreed with" \
    "mlkem_poly.c's loops on SSE2 and on NEON; aes_hw.c agreed with the table and left no word of a" \
    "schedule on the stack on AES-NI and on the Arm AES instructions; and each caller of the RSA" \
    "verifiers sent the public operation to AVX-512 IFMA exactly where its session's ch_cfg.cpu" \
    "held the bit"
