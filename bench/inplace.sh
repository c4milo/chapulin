#!/usr/bin/env bash
# Times the connected read and write of a TLS session through the calls
# that copy and through the calls that work in place, and writes
# bench/results-inplace-<os>-<arch>-<compiler>.csv, the compiler being
# clang or gcc. docs/performance.md, "Reads and writes in place", draws it
# as a chart (tools/inplace_chart.py). `make bench-inplace` runs it.
# BENCH_MACHINE names a class of CPU in the file name, as
# bench/record.sh's does.
#
# It builds bench/inplace.c twice from this tree, over the objects make
# compiles for two configurations that differ in TRANSPORT alone:
#
#   - TRANSPORT=tcp-blocking, with -DBENCH_COPY: ch_write over a send that
#     copies each record out, and ch_read over a recv that copies each
#     record in and the plaintext out (docs/decisions.md 247 and 248);
#   - TRANSPORT=tcp-nonblocking: ch_seal_in_place and ch_read_in_place.
#
# Both are TRUST=webpki SUITE=aesgcm TX_RECORD=16384 RAND=extern: colibri's
# record options, with RAND=extern because no timed call draws randomness.
# make print-lib-objs names each configuration's objects, which make builds
# from its own source list with each source's flags, and make
# print-lib-def its defines. So the bench holds no list of its own.
#
# Each row runs under the ch_cfg.cpu value a caller on this CPU would state
# (bench/cpu_value.sh, as bench/primitives.sh states it). BENCH_CPU from
# the environment wins.
#
# A row's time moves with the address of the process's stack
# (docs/performance.md, the pitfalls table): under gcc 14 on an Intel Xeon
# with AVX-512, an AES-256-GCM write of 1 KiB in place took 310 to 330 ns at
# some 16-byte positions of the stack and 390 to 404 ns at others. So where
# setarch exists, each program runs once at each of the POSITIONS positions
# of one 4 KiB page, with address randomization off: setarch -R puts the
# stack at the same address in every run, below the environment, and a
# variable of 16 k bytes moves it by 16 k bytes. Each run takes
# POSITION_SAMPLES samples a row, and every run of the bench reads the same
# positions. Where setarch does not exist, as on macOS, each program runs
# TURNS times at the addresses the system picks, with bench/inplace.c's
# default samples. The two programs run in turns, pinned to one core with
# taskset where it exists: BENCH_CORE names the core, the last one by
# default. A row's figure is the median of its runs' figures, each the
# median of the run's samples, and its iqr_pct is the 75th percentile of
# those figures less the 25th, as a share of the median.
#
# `bench/inplace.sh --quick` builds both programs, runs each once with
# three samples a row and writes nothing. `bench/inplace.sh --build`
# builds both and runs neither, and `make check` runs it through
# test/script-builds.sh.
set -euo pipefail
cd "$(dirname "$0")/.."
QUICK=""
BUILD_ONLY=""
case "${1:-}" in
--quick) QUICK=--quick ;;
--build) BUILD_ONLY=yes ;;
"") ;;
*)
    echo "usage: bench/inplace.sh [--quick | --build]" >&2
    exit 2
    ;;
esac
TURNS=21
POSITIONS=256
POSITION_SAMPLES=51
CC=${CC:-cc}
read -r -a CC_WORDS <<<"$CC"
CONFIG=(TRUST=webpki SUITE=aesgcm TX_RECORD=16384 RAND=extern)
LIB_CFLAGS=$(make -s --no-print-directory print-lib-cflags CC="$CC")
HOST_TARGET=$(make -s --no-print-directory print-host-target CC="$CC")
if [ -z "$LIB_CFLAGS" ] || [ -z "$HOST_TARGET" ]; then
    echo "FAIL inplace bench: $CC builds no host object, which SUITE=aesgcm needs" >&2
    exit 1
fi
case "$(uname -m)" in
arm64 | aarch64) ARCH=arm64 ;;
x86_64 | amd64) ARCH=x86_64 ;;
*)
    echo "SKIP inplace bench: $(uname -m) builds no host object" >&2
    exit 0
    ;;
esac
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
if "${CC_WORDS[@]}" --version 2>/dev/null | head -1 | grep -qi clang; then
    FAMILY=clang
else
    FAMILY=gcc
fi
OUT=bench/results-inplace-$OS-$ARCH${BENCH_MACHINE:+-$BENCH_MACHINE}-$FAMILY.csv
BENCH_NAME=inplace
# shellcheck source=bench/cpu_value.sh
. bench/cpu_value.sh
VALUE=$(cpu_value)
# BENCH_BUILD_DIR names a directory that keeps the two programs, as
# bench/record.sh's does.
if [ -n "${BENCH_BUILD_DIR:-}" ]; then
    W=$BENCH_BUILD_DIR
    mkdir -p "$W"
    rm -f "$W/rows"
else
    W=$(mktemp -d)
    trap 'rm -rf "$W"' EXIT
fi

# Builds one program: $1 = its name, $2 = the transport, the rest = flags.
build() {
    local name=$1 transport=$2 objs defs
    shift 2
    objs=$(make -s --no-print-directory print-lib-objs CC="$CC" TRANSPORT="$transport" "${CONFIG[@]}")
    defs=$(make -s --no-print-directory print-lib-def CC="$CC" TRANSPORT="$transport" "${CONFIG[@]}")
    # objs and defs each hold a list as one string, which the shell must
    # split.
    # shellcheck disable=SC2086
    make -s --no-print-directory CC="$CC" TRANSPORT="$transport" "${CONFIG[@]}" $objs
    # shellcheck disable=SC2086
    "${CC_WORDS[@]}" $LIB_CFLAGS $defs "$@" -DBENCH_CPU="$VALUE" -Isrc -Iinclude/chapulin \
        -Iinclude -I. -o "$W/$name" bench/inplace.c $objs
}
build copy tcp-blocking -DBENCH_COPY
build in_place tcp-nonblocking
if [ -n "$BUILD_ONLY" ]; then
    echo "inplace bench: --build built both programs and ran neither" >&2
    exit 0
fi

PIN=()
if command -v taskset >/dev/null 2>&1; then
    PIN=(taskset -c "${BENCH_CORE:-$(($(getconf _NPROCESSORS_ONLN) - 1))}")
fi
if [ -n "$QUICK" ]; then
    "${PIN[@]}" "$W/copy" --quick
    "${PIN[@]}" "$W/in_place" --quick
    echo "inplace bench: --quick ran every row once and wrote nothing" >&2
    exit 0
fi
load() { # the three load averages, space separated
    uptime | sed -e 's/.*load average[s]*: //' -e 's/,//g'
}
cpu() {
    if [ "$(uname -s)" = Darwin ]; then
        sysctl -n machdep.cpu.brand_string
    elif grep -q '^model name' /proc/cpuinfo; then
        sed -n 's/^model name[[:space:]]*: //p' /proc/cpuinfo | head -1
    else
        local info
        info=$(lscpu 2>/dev/null || true)
        sed -n '/^Model name:/{s/^Model name:[[:space:]]*//p;q;}' <<<"$info"
    fi
}
# Each program at one stack position: $1 = the program, $2 = the position.
run_at() {
    env -i BENCH_STACK_PAD="$(printf '%*s' $((16 * $2)) '')" "$SETARCH" -R "${PIN[@]}" \
        "$W/$1" --samples "$POSITION_SAMPLES"
}
SETARCH=$(command -v setarch || true)
LOAD_BEFORE=$(load)
if [ -n "$SETARCH" ]; then
    RUNS_NOTE="$POSITIONS runs of each program, one at each 16-byte stack position of a page under setarch -R, of $POSITION_SAMPLES samples each"
    for position in $(seq 0 $((POSITIONS - 1))); do
        run_at copy "$position" >>"$W/rows"
        run_at in_place "$position" >>"$W/rows"
    done
else
    RUNS_NOTE="$TURNS runs of each program at the stack addresses the system picked"
    for _ in $(seq "$TURNS"); do
        "${PIN[@]}" "$W/copy" >>"$W/rows"
        "${PIN[@]}" "$W/in_place" >>"$W/rows"
    done
fi
LOAD_AFTER=$(load)
# The tree is named before the CSV is opened, as bench/record.sh does.
TREE=$(git describe --always --dirty 2>/dev/null || echo "${BENCH_TREE:-unknown}")
{
    echo "# bench/inplace.sh on $(cpu) ($ARCH)${BENCH_HOST:+, $BENCH_HOST}, $(uname -s)" \
        "$(uname -r), $(date -u +%Y-%m-%d), tree $TREE"
    echo "# $("${CC_WORDS[@]}" --version | head -1); $CC $LIB_CFLAGS; objects:" \
        "${CONFIG[*]}, TRANSPORT=tcp-blocking for copy and TRANSPORT=tcp-nonblocking for" \
        "in_place; ch_cfg.cpu $VALUE: $(cpu_names "$VALUE")"
    echo "# load average (1, 5, 15 min) before: $LOAD_BEFORE; after: $LOAD_AFTER;" \
        "pinned: ${PIN[*]:-no taskset}"
    echo "# copy_ns and in_place_ns: per call for a write and per record for a read, the" \
        "median over $RUNS_NOTE, the programs in turns, each run's figure the median of its" \
        "samples; iqr_pct: the runs' 75th percentile less their 25th, percent of the median"
    echo "direction,aead,bytes,copy_ns,in_place_ns,copy_iqr_pct,in_place_iqr_pct"
    awk -F, '
        # The median of a list of n figures, and in low and high its 25th
        # and 75th percentiles, by nearest rank.
        function median(list, n,   i, j, t, v) {
            split(list, v, " ")
            for (i = 1; i <= n; i++)
                for (j = i + 1; j <= n; j++)
                    if (v[j] + 0 < v[i] + 0) { t = v[i]; v[i] = v[j]; v[j] = t }
            low = v[int((n + 3) / 4)]; high = v[int((3 * n + 3) / 4)]
            return n % 2 ? v[(n + 1) / 2] : (v[n / 2] + v[n / 2 + 1]) / 2
        }
        {
            key = $2 "," $3 "," $4
            if (!(key in seen)) { seen[key] = 1; order[++count] = key }
            figures[$1, key] = figures[$1, key] " " $6
            runs[$1, key]++
        }
        END {
            for (k = 1; k <= count; k++) {
                key = order[k]
                copy = median(figures["copy", key], runs["copy", key])
                copy_iqr = 100 * (high - low) / copy
                in_place = median(figures["in_place", key], runs["in_place", key])
                in_place_iqr = 100 * (high - low) / in_place
                printf "%s,%.1f,%.1f,%.1f,%.1f\n", key, copy, in_place, copy_iqr, in_place_iqr
            }
        }' "$W/rows"
} >"$OUT"
cat "$OUT"
echo "inplace bench: wrote $OUT" >&2
