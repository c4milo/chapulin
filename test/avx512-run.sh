#!/usr/bin/env bash
# Runs one test binary on a CPU with what CH_CPU_AVX512 names: AVX-512F,
# AVX-512BW, AVX-512VL, VAES and VPCLMULQDQ (cpu_cfg.h, docs/decisions.md
# 130). The catch target of the violations whose test needs the 512-bit
# AES-GCM kernel to run, such as one that reads past a buffer through a byte
# mask: no static check sees such a read, and only a run of the kernel does.
# test/violations.py runs a script by path and reads its exit status, and a
# binary under SDE needs a command, so this is the path.
#
#   test/avx512-run.sh BINARY [ARGUMENT...]
#
# BINARY is a path under bin/. Where /proc/cpuinfo lists every one of the
# five, the binary runs on this CPU. Where it does not and SDE64 names an
# executable sde64, the binary runs under Intel SDE on the model SDE_CPU
# names, -icx by default, which has them all; the nightly's test-invariants
# job installs SDE for this. Either way CH_REQUIRE_AVX512 is 1, so a binary
# that finds no such CPU fails rather than skips. Where neither holds, the
# script prints SKIP and exits 0, and a violation that names it then reports
# unguarded rather than caught. SDE is an emulator: it shows what the
# instructions compute and nothing about how long they take.
cd "$(dirname "$0")/.." || exit 1
binary=$1
shift

has_avx512() {
    [ -r /proc/cpuinfo ] || return 1
    local flag
    for flag in avx512f avx512bw avx512vl vaes vpclmulqdq; do
        grep -qw "$flag" /proc/cpuinfo || return 1
    done
}

if has_avx512; then
    exec env CH_REQUIRE_AVX512=1 "./$binary" "$@"
fi
sde=${SDE64:-}
if [ -n "$sde" ] && [ -x "$sde" ]; then
    exec env CH_REQUIRE_AVX512=1 "$sde" "${SDE_CPU:--icx}" -- "./$binary" "$@"
fi
echo "SKIP $binary: this CPU lacks what CH_CPU_AVX512 names, and SDE64 names no sde64"
exit 0
