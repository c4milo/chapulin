#!/usr/bin/env bash
# Shows that a host object's session whose caller did not set
# CH_CPU_CONSTANT_TIME_AES runs no AES instruction (docs/decisions.md 81
# and 89). It builds four binaries for x86-64, as host objects,
# statically, and runs them under qemu-x86_64 on a CPU model with AES-NI
# and PCLMULQDQ turned off, where either instruction raises SIGILL:
#
#   - bin/aes_runtime_test "absent" must pass: the published vectors of
#     RFC 9001 and RFC 9369 Appendix A, byte for byte, on the table and the
#     portable GHASH.
#   - bin/quic_loop_aes and bin/webpki_loop_aes "absent" must pass: whole
#     QUIC and TCP handshakes, resumptions and pin rows between this
#     tree's client and server, both ends stating the probe's bit alone,
#     in the objects that hold the instructions.
#   - bin/aes_runtime_test "present" must die of SIGILL, which is what shows
#     the CPU model traps the instructions, and so that the runs above
#     executed none.
#   - bin/quic_test_hw's vectors, whose first pass states the bit, must die
#     of SIGILL too.
#
# QEMU's arm64 models all implement the AES extension, and none of their
# properties turns it off (QEMU 8.2 and 10.2), so the arm64 half of the
# claim rests on the call counts bin/aes_runtime_test reads and on
# test/aes-runtime-disasm.sh, which finds the instructions in aes_hw.c's,
# ghash_hw.c's and gcm_hw.c's functions alone.
#
# Linux only: qemu-user runs a Linux binary. X86_CC names an x86-64
# compiler, cc by default, which must be one on an x86-64 host;
# x86_64-linux-gnu-gcc cross-compiles from an arm64 one. The mips job in
# .github/workflows/check.yml runs this script on every push, because the
# qemu-user package it installs carries qemu-x86_64, and
# test/docker-aes-runtime-qemu.sh runs it in a container elsewhere.
cd "$(dirname "$0")/.." || exit 1
# Two runs below must die of SIGILL. Under a core limit above 0, qemu-user
# writes the guest's core file into this directory, and the kernel may
# write qemu's own: 9 MB and 153 MB in an ubuntu:24.04 container.
ulimit -c 0
x86_cc=${X86_CC:-cc}
qemu=${QEMU_X86_64:-qemu-x86_64}
cpu='max,-aes,-pclmulqdq'
command -v "$qemu" > /dev/null || { echo "aes-runtime-qemu: $qemu is missing" >&2; exit 1; }
"$x86_cc" -dM -E -x c /dev/null | grep -qw __x86_64__ ||
    { echo "aes-runtime-qemu: $x86_cc does not compile for x86-64; set X86_CC" >&2; exit 1; }
out=bin/qemu
mkdir -p "$out"
flags=(-Wall -Wextra -Wpedantic -Werror -std=c11 -O2 -D_DEFAULT_SOURCE -static -I. -Itest
       -DCH_RAND_EXTERN -DCH_NATIVE_WIDEMUL)
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
[ "${#quic_test_hw_srcs[@]}" -gt 0 ] ||
    { echo "aes-runtime-qemu: make print-aes-runtime-qemu-srcs printed fewer than four lists" >&2; exit 1; }
"$x86_cc" "${flags[@]}" -DCH_TRANSPORT_QUIC_NONBLOCKING "${runtime[@]}" -o "$out/aes_runtime_test" \
    test/aes_runtime_test.c test/aes_runtime_soft.c test/aes_runtime_hw.c "${runtime_test_srcs[@]}" || exit 1
"$x86_cc" "${flags[@]}" -DCH_TRANSPORT_QUIC_NONBLOCKING "${both[@]}" "${runtime[@]}" \
    -o "$out/quic_loop_aes" test/quic_loop_test.c "${quic_srcs[@]}" || exit 1
"$x86_cc" "${flags[@]}" -DCH_TRANSPORT_TCP_NONBLOCKING "${both[@]}" "${runtime[@]}" \
    -o "$out/webpki_loop_aes" test/webpki_loop_test.c "${tcp_srcs[@]}" || exit 1
"$x86_cc" "${flags[@]}" -DCH_TRANSPORT_QUIC_NONBLOCKING -DCH_CPU_RUNTIME -DCH_AES_256_TEST \
    -o "$out/quic_test_hw" test/quic_vectors.c "${quic_test_hw_srcs[@]}" || exit 1

for b in aes_runtime_test quic_loop_aes webpki_loop_aes; do
    "$qemu" -cpu "$cpu" "$out/$b" absent ||
        { echo "aes-runtime-qemu: $b failed its rows without the AES bit on a CPU without AES-NI or PCLMULQDQ" >&2; exit 1; }
done
rc=0
"$qemu" -cpu "$cpu" "$out/aes_runtime_test" present > /dev/null 2>&1 || rc=$?
[ "$rc" -eq 132 ] ||
    { echo "aes-runtime-qemu: the rows with the AES bit exited $rc there; SIGILL is 132" >&2; exit 1; }
rc=0
"$qemu" -cpu "$cpu" "$out/quic_test_hw" > /dev/null 2>&1 || rc=$?
[ "$rc" -eq 132 ] ||
    { echo "aes-runtime-qemu: the vectors on the instructions exited $rc there; SIGILL is 132" >&2; exit 1; }
echo "aes-runtime-qemu: on $cpu the rows without the AES bit passed in the vectors and both" \
    "loops, and the rows with it died of SIGILL"
