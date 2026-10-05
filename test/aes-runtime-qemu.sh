#!/usr/bin/env bash
# Shows that a host object's session runs an x86-64 instruction set only
# where its caller's ch_cfg.cpu names it (docs/decisions.md 81, 89, 90
# and 93). It builds eight binaries for x86-64, as host objects, statically,
# and runs them under qemu-x86_64 on CPU models with instructions turned
# off, where each such instruction raises SIGILL.
#
# On a model without AES-NI, PCLMULQDQ and AVX2:
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
#     every length and split it tries, and no schedule or state word of a
#     call in the stack the call leaves (test/sha2_equiv_test.c). With
#     "sha2-equiv" as this script's argument it builds and runs that
#     binary alone, which is what the violations of sha256_hw.c's
#     constants and of its wipe name as their catch: the run gives one
#     verdict on every machine, where the machine's own CPU may lack the
#     instructions.
#   - each loop with one end stating the SHA-256 bit and the other not, in
#     both orders, must pass: 0x25 against 0x5 and 0x27 against 0x7, so
#     the instructions and sha256.c compute the same transcript hashes
#     and the same keys.
#
# On any model:
#
#   - bin/x86_kernels_test must pass. It counts the calls the library
#     sends to each kernel under each ch_cfg.cpu value and runs none of a
#     kernel's instructions (test/x86_kernels_test.c). With "x86-kernels"
#     as this script's argument it builds and runs that binary alone,
#     which is what the violations of chacha20.c's use_avx2 and
#     gcm_vaes.h's gcm_use_vaes name as their catch.
#
# On a model without AES-NI, PCLMULQDQ, AVX2 and the SHA extensions:
#
#   - bin/hash_runtime_test and bin/hash_runtime_exporter_test must pass.
#     They count the calls into each hash's two paths under every
#     ch_cfg.cpu value and run no instruction a bit names
#     (test/hash_runtime_test.c).
#
# QEMU's arm64 models all implement the AES and SHA-256 extensions, and
# none of their properties turns either off (QEMU 8.2 and 10.2), so the
# arm64 half of the claim rests on the call counts bin/aes_runtime_test
# and bin/hash_runtime_test read and on test/aes-runtime-disasm.sh, which
# finds the instructions in aes_hw.c's, ghash_hw.c's, gcm_hw.c's and
# sha256_hw.c's functions alone.
#
# Linux only: qemu-user runs a Linux binary. X86_CC names an x86-64
# compiler, cc by default, which must be one on an x86-64 host;
# x86_64-linux-gnu-gcc cross-compiles from an arm64 one. The mips job in
# .github/workflows/check.yml runs this script on every push, because the
# qemu-user package it installs carries qemu-x86_64, and
# test/docker-aes-runtime-qemu.sh runs it in a container elsewhere.
cd "$(dirname "$0")/.." || exit 1
# Several runs below must die of SIGILL. Under a core limit above 0,
# qemu-user writes the guest's core file into this directory, and the
# kernel may write qemu's own: 9 MB and 153 MB in an ubuntu:24.04
# container.
ulimit -c 0
only=${1:-}
case "$only" in
"" | x86-kernels | sha2-equiv) ;;
*)
    echo "usage: $0 [x86-kernels | sha2-equiv]" >&2
    exit 2
    ;;
esac
x86_cc=${X86_CC:-cc}
qemu=${QEMU_X86_64:-qemu-x86_64}
command -v "$qemu" > /dev/null || { echo "aes-runtime-qemu: $qemu is missing" >&2; exit 1; }
"$x86_cc" -dM -E -x c /dev/null | grep -qw __x86_64__ ||
    { echo "aes-runtime-qemu: $x86_cc does not compile for x86-64; set X86_CC" >&2; exit 1; }
out=bin/qemu
mkdir -p "$out"
# No -DCH_NATIVE_WIDEMUL: every binary here is a host object, which holds
# both multiplies and whose ct.h refuses the define.
flags=(-Wall -Wextra -Wpedantic -Werror -std=c11 -O2 -D_DEFAULT_SOURCE -static -I. -Itest
       -DCH_RAND_EXTERN)
runtime=(-DCH_SUITE_AES_GCM -DCH_CPU_RUNTIME)
both=(-DCH_ROLE_SERVER -DCH_ROLE_BOTH -DCH_TRUST_WEBPKI)
# Each binary links the sources its rule in the Makefile links, one list
# a line, so each list here is the one check links.
lists=$(make -s --no-print-directory print-aes-runtime-qemu-srcs) ||
    { echo "aes-runtime-qemu: make print-aes-runtime-qemu-srcs failed" >&2; exit 1; }
read -r -a quic_srcs <<< "$(sed -n 1p <<< "$lists")"
read -r -a tcp_srcs <<< "$(sed -n 2p <<< "$lists")"
read -r -a runtime_test_srcs <<< "$(sed -n 3p <<< "$lists")"
read -r -a quic_test_hw_srcs <<< "$(sed -n 4p <<< "$lists")"
read -r -a kernels_test_srcs <<< "$(sed -n 5p <<< "$lists")"
read -r -a sha2_equiv_srcs <<< "$(sed -n 6p <<< "$lists")"
read -r -a hash_count_srcs <<< "$(sed -n 7p <<< "$lists")"
read -r -a hash_count_quic_srcs <<< "$(sed -n 8p <<< "$lists")"
[ "${#hash_count_quic_srcs[@]}" -gt 0 ] ||
    { echo "aes-runtime-qemu: make print-aes-runtime-qemu-srcs printed fewer than eight lists" >&2; exit 1; }

# Runs one binary of $out on a CPU model and requires its exit status. A
# run that must pass prints what it wrote when it does not.
expect() { # $1 = model, $2 = the status, $3 = what a wrong status means, $4... = binary and arguments
    local model=$1 want=$2 meaning=$3 rc=0
    shift 3
    "$qemu" -cpu "$model" "$out/$1" "${@:2}" > "$out/row.log" 2>&1 || rc=$?
    [ "$rc" -eq "$want" ] && return 0
    [ "$want" -ne 0 ] || cat "$out/row.log" >&2
    echo "aes-runtime-qemu: on $model, $* exited $rc and not $want: $meaning" >&2
    exit 1
}
sigill=132

if [ "$only" != sha2-equiv ]; then
    "$x86_cc" "${flags[@]}" -DCH_TRANSPORT_QUIC_NONBLOCKING "${runtime[@]}" -o "$out/x86_kernels_test" \
        test/x86_kernels_test.c test/x86_kernels_count.c "${kernels_test_srcs[@]}" || exit 1
    expect max 0 "a call ran a kernel its ch_cfg.cpu value does not name, or ran none where it does" \
        x86_kernels_test
fi
if [ "$only" = x86-kernels ]; then
    echo "aes-runtime-qemu: bin/x86_kernels_test counted each kernel's calls under every ch_cfg.cpu value"
    exit 0
fi

# sha256_hw.c against sha256.c, on the model with every instruction. The
# binary fails where the model lacks the SHA extensions, so this row
# cannot pass by skipping.
"$x86_cc" "${flags[@]}" -DCH_CPU_RUNTIME -DCH_HASH_SHA384 -DCH_EXPORTER -DHKDF_LABEL_MAX=32 \
    -o "$out/sha2_equiv_test" test/sha2_equiv_test.c "${sha2_equiv_srcs[@]}" || exit 1
CH_REQUIRE_HASH_INSTRUCTIONS=1 expect max 0 \
    "sha256_hw.c and sha256.c disagree, a call left its schedule or its state on the stack, or this qemu's max model lacks the SHA extensions" \
    sha2_equiv_test
if [ "$only" = sha2-equiv ]; then
    echo "aes-runtime-qemu: bin/sha2_equiv_test held sha256_hw.c to sha256.c on the SHA extensions"
    exit 0
fi

"$x86_cc" "${flags[@]}" -DCH_TRANSPORT_QUIC_NONBLOCKING "${runtime[@]}" -o "$out/aes_runtime_test" \
    test/aes_runtime_test.c test/aes_runtime_soft.c test/aes_runtime_hw.c "${runtime_test_srcs[@]}" || exit 1
"$x86_cc" "${flags[@]}" -DCH_TRANSPORT_QUIC_NONBLOCKING "${both[@]}" "${runtime[@]}" \
    -o "$out/quic_loop_aes" test/quic_loop_test.c "${quic_srcs[@]}" || exit 1
"$x86_cc" "${flags[@]}" -DCH_TRANSPORT_TCP_NONBLOCKING "${both[@]}" "${runtime[@]}" \
    -o "$out/webpki_loop_aes" test/webpki_loop_test.c "${tcp_srcs[@]}" || exit 1
"$x86_cc" "${flags[@]}" -DCH_TRANSPORT_QUIC_NONBLOCKING -DCH_CPU_RUNTIME -DCH_AES_256_TEST \
    -o "$out/quic_test_hw" test/quic_vectors.c "${quic_test_hw_srcs[@]}" || exit 1
"$x86_cc" "${flags[@]}" -DCH_TRANSPORT_QUIC_NONBLOCKING "${runtime[@]}" -o "$out/hash_runtime_test" \
    test/hash_runtime_test.c "${hash_count_srcs[@]}" "${hash_count_quic_srcs[@]}" || exit 1
"$x86_cc" "${flags[@]}" "${runtime[@]}" -DCH_EXPORTER -DHKDF_LABEL_MAX=32 \
    -o "$out/hash_runtime_exporter_test" test/hash_runtime_test.c "${hash_count_srcs[@]}" || exit 1
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
# count each hash's calls run both paths on sha256.c's code and seal
# their Initial packet on the table, so they must pass here.
no_named="$bare,-sha-ni"
for b in hash_runtime_test hash_runtime_exporter_test; do
    expect "$no_named" 0 "a binary that counts hash calls ran an instruction a ch_cfg.cpu bit names" "$b"
done

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
cat > "$out/probe.c" << 'PROBE'
#include <stdio.h>

#include "x86_kernels_cpu.h"

int main(void) {
    printf("%s %s\n", x86_cpu_has_avx2() ? "avx2" : "-",
           x86_cpu_has_vaes() ? "vaes vpclmulqdq" : "-");
    return 0;
}
PROBE
"$x86_cc" "${flags[@]}" -o "$out/probe" "$out/probe.c" || exit 1
cpuid=$("$qemu" -cpu max "$out/probe") ||
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
echo "aes-runtime-qemu: on $bare the rows without the AES bit and without CH_CPU_AVX2 passed in the" \
    "vectors and both loops, and the rows with either died of SIGILL; on $no_avx2 the rows with" \
    "the AES bit passed and the rows that add CH_CPU_VAES died of SIGILL; on $no_sha the rows" \
    "without the SHA-256 bit passed and the rows with it died of SIGILL; on $no_named the two" \
    "binaries that count each hash's calls passed; on max, sha256_hw.c" \
    "agreed with sha256.c, one end on the SHA extensions and the other on sha256.c agreed, and" \
    "$mixed"
