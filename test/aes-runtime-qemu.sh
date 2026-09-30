#!/usr/bin/env bash
# Shows that an AES=runtime session whose caller found no AES instructions
# runs none (docs/decisions.md 81). It builds three binaries for x86-64,
# statically, and runs them under qemu-x86_64 on a CPU model with AES-NI
# and PCLMULQDQ turned off, where either instruction raises SIGILL:
#
#   - bin/aes_runtime_test "absent" must pass: the published vectors of
#     RFC 9001 and RFC 9369 Appendix A, byte for byte, on the table and the
#     portable GHASH.
#   - bin/quic_loop_aes_runtime and bin/webpki_loop_aes_runtime "absent"
#     must pass: whole QUIC and TCP handshakes, resumptions and pin rows
#     between this tree's client and server, both ends answering that the
#     instructions are absent, in the objects that hold them.
#   - bin/aes_runtime_test "present" must die of SIGILL, which is what shows
#     the CPU model traps the instructions, and so that the runs above
#     executed none.
#   - bin/quic_test_hw's vectors, built AES=hw, must die of SIGILL too.
#
# QEMU's arm64 models all implement the AES extension, and none of their
# properties turns it off (QEMU 8.2 and 10.2), so the arm64 half of the
# claim rests on the call counts bin/aes_runtime_test reads and on
# test/aes-runtime-disasm.sh, which finds the instructions in aes_hw.c's
# and ghash_hw.c's functions alone.
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
runtime=(-DCH_SUITE_AES_GCM -DCH_AES_RUNTIME -DCH_NATIVE_AES)
both=(-DCH_ROLE_SERVER -DCH_ROLE_BOTH -DCH_TRUST_WEBPKI)
common=(gcm.c quic_initial.c quic_retry.c quic_packet.c quic_keys.c hkdf.c sha256.c sha512.c
        sha512_compress.c chacha20.c poly1305.c aead.c buf.c ct.c)
lists=$(make -s --no-print-directory print-aes-runtime-loop-srcs) ||
    { echo "aes-runtime-qemu: make print-aes-runtime-loop-srcs failed" >&2; exit 1; }
read -r -a quic_srcs <<< "$(sed -n 1p <<< "$lists")"
read -r -a tcp_srcs <<< "$(sed -n 2p <<< "$lists")"
"$x86_cc" "${flags[@]}" -DCH_TRANSPORT_QUIC_NONBLOCKING "${runtime[@]}" -o "$out/aes_runtime_test" \
    test/aes_runtime_test.c test/aes_runtime_soft.c test/aes_runtime_hw.c aes.c "${common[@]}" || exit 1
"$x86_cc" "${flags[@]}" -DCH_TRANSPORT_QUIC_NONBLOCKING "${both[@]}" "${runtime[@]}" \
    -o "$out/quic_loop_aes_runtime" test/quic_loop_test.c "${quic_srcs[@]}" || exit 1
"$x86_cc" "${flags[@]}" -DCH_TRANSPORT_TCP_NONBLOCKING "${both[@]}" "${runtime[@]}" \
    -o "$out/webpki_loop_aes_runtime" test/webpki_loop_test.c "${tcp_srcs[@]}" || exit 1
"$x86_cc" "${flags[@]}" -DCH_TRANSPORT_QUIC_NONBLOCKING -maes -mpclmul -DCH_AES_HW -DCH_AES_256_TEST \
    -o "$out/quic_test_hw" test/quic_vectors.c aes.c aes_hw.c ghash_hw.c "${common[@]}" || exit 1

for b in aes_runtime_test quic_loop_aes_runtime webpki_loop_aes_runtime; do
    "$qemu" -cpu "$cpu" "$out/$b" absent ||
        { echo "aes-runtime-qemu: $b failed the absent answer on a CPU without AES-NI or PCLMULQDQ" >&2; exit 1; }
done
rc=0
"$qemu" -cpu "$cpu" "$out/aes_runtime_test" present > /dev/null 2>&1 || rc=$?
[ "$rc" -eq 132 ] ||
    { echo "aes-runtime-qemu: the present answer exited $rc there; SIGILL is 132" >&2; exit 1; }
rc=0
"$qemu" -cpu "$cpu" "$out/quic_test_hw" > /dev/null 2>&1 || rc=$?
[ "$rc" -eq 132 ] ||
    { echo "aes-runtime-qemu: the AES=hw vectors exited $rc there; SIGILL is 132" >&2; exit 1; }
echo "aes-runtime-qemu: on $cpu the absent answer passed in the vectors and both loops," \
    "and the present answer and AES=hw died of SIGILL"
