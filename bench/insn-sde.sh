#!/usr/bin/env bash
# Counts the instructions of each row a host object's benchmarks run, under
# Intel SDE, for the ch_cfg.cpu values that pick the kernels valgrind does
# not run: VAES, AVX-512 IFMA, AVX-512 and the x86-64 SHA extensions.
# Writes two files, which make insn-gate-sde holds to the recorded ones
# with tools/insn-gate.py (docs/decisions.md 235):
#
#   bench/results-insn-sde-x86_64.csv, or the file INSN_OUT names: each
#   primitive row of bench/primitives.c under 0x13f, which adds the SHA-256
#   and IFMA bits to the AES, multiply, AVX2 and VAES ones, and under 0xd3f,
#   which adds BMI1 and BMI2_ADX.
#
#   bench/results-insn-sde-record-x86_64.csv, or the file INSN_RECORD_OUT
#   names: each row of bench/record.c under the three values bench/record.sh
#   builds for these kernels, 0x1f, 0x11f and 0x31f.
#
# The programs are bench/primitives.sh's and bench/record.sh's, which
# --build compiles into BENCH_BUILD_DIR with -DBENCH_SDE added. SDE adds
# the counts of every marked region of a process, so each row runs in a
# process of its own: --count --only LABEL marks the one operation, and
# sde64 -icount -start_ssc_mark 111 -stop_ssc_mark 222 prints its count
# (bench_count.h). SDE emulates one CPU, SDE_CPU, -icx by default, and
# gives the program that CPU's CPUID, so glibc picks one memcpy on every
# runner and the count holds every image's instructions. --list names the
# rows; it runs no kernel, so the runner's own CPU runs it.
#
# SDE shows what the instructions are, not how long they take, so the
# counts hold the work of a kernel and nothing of its timing. Skips
# without SDE64, the path of sde64.
set -euo pipefail
cd "$(dirname "$0")/.."

SDE64=$(command -v "${SDE64:-sde64}" || true)
if [ -z "$SDE64" ]; then
    echo "SKIP SDE insn count: SDE64 names no sde64" >&2
    exit 0
fi
[ "$(uname -m)" = x86_64 ] || {
    echo "SKIP SDE insn count: SDE emulates x86-64, and this machine is $(uname -m)" >&2
    exit 0
}
SDE_CPU=${SDE_CPU:--icx}
export CC=${CC:-gcc}
OUT=${INSN_OUT:-bench/results-insn-sde-x86_64.csv}
RECORD_OUT=${INSN_RECORD_OUT:-bench/results-insn-sde-record-x86_64.csv}
VALUES=(0x13f 0xd3f)
RECORDS=(record_kernels:0x1f record_ifma:0x11f record_avx512:0x31f)
PRIMITIVE_GROUPS=(hash cipher aead verify secret_key)
RECORD_GROUPS=(aes128gcm aes256gcm chacha20poly1305)
JOBS=$(nproc)

W=$(mktemp -d)
trap 'rm -rf "$W"' EXIT

BENCH_BUILD_DIR="$W/primitives" PRIMITIVES_EXTRA_FLAGS="-DBENCH_SDE" bench/primitives.sh --build
BENCH_BUILD_DIR="$W/record" RECORD_EXTRA_FLAGS="-DBENCH_SDE" bench/record.sh --build

# The count of one row: SDE's ICOUNT line, after a check that the program
# printed the row, so a label that named no row cannot read as a count.
count_row() { # $1 = label; the rest = the program and its arguments before the groups
    local label=$1 out
    shift
    out=$("$SDE64" "$SDE_CPU" -icount -start_ssc_mark 111 -stop_ssc_mark 222 -- "$@" 2>&1) || {
        echo "FAIL SDE insn count: $* failed at $label" >&2
        printf '%s\n' "$out" | tail -20 >&2
        return 1
    }
    printf '%s\n' "$out" | grep -q "^$label," || {
        echo "FAIL SDE insn count: $* counted no row named $label" >&2
        return 1
    }
    printf '%s/%s,%s\n' "${label%,*}" "${label##*,}" \
        "$(printf '%s\n' "$out" | sed -n 's/^\$\$ TID: 0 ICOUNT: \([0-9]*\)$/\1/p')"
}

# One column of counts, in the program's order, into $1: each row counted
# in its own process, JOBS at a time, each into a file of its own.
count_column() { # $1 = output; $2 = program; $3 = groups; the rest = arguments before the groups
    local out=$1 program=$2 groups=$3 dir
    shift 3
    dir=$(mktemp -d "$W/column.XXXXXX")
    # The groups are words without spaces, so the list splits on spaces.
    # shellcheck disable=SC2086
    "$program" --count --list "$@" $groups >"$dir/labels"
    local i=0 failed=0
    while IFS= read -r label; do
        i=$((i + 1))
        # shellcheck disable=SC2086
        count_row "$label" "$program" --count --only "$label" "$@" $groups >"$dir/$i" &
        if [ $((i % JOBS)) -eq 0 ]; then
            wait || failed=1
        fi
    done <"$dir/labels"
    wait || failed=1
    [ "$failed" -eq 0 ] || exit 1
    : >"$out"
    for n in $(seq 1 "$i"); do
        cat "$dir/$n" >>"$out"
    done
    if [ "$(wc -l <"$out")" -ne "$i" ] || grep -q ',$' "$out"; then
        echo "FAIL SDE insn count: $program wrote $(wc -l <"$out") counts for $i rows" >&2
        exit 1
    fi
}

# Joins columns of counts into a CSV, as bench/insn-host.sh does.
write_csv() { # $1 = output; $2 = header after op; the rest = count files
    local out=$1 header=$2 tmp
    shift 2
    tmp=$(mktemp)
    {
        printf '# %s; %s; sde64 %s; instructions between the SSC marks, every image\n' \
            "$("$CC" --version | head -1)" "$("$SDE64" -version 2>&1 | grep -m1 -i version)" "$SDE_CPU"
        printf 'op%s\n' "$header"
        paste -d, "$@" | awk -F, '{
            line = $1 "," $2
            for (i = 3; i <= NF; i += 2) {
                if ($i != $1) { print "op order differs: " $1 " " $i > "/dev/stderr"; exit 1 }
                line = line "," $(i + 1)
            }
            print line
        }'
    } >"$tmp"
    mv "$tmp" "$out"
    echo "wrote $out" >&2
}

COLUMNS=()
HEADER=""
for value in "${VALUES[@]}"; do
    count_column "$W/primitives-$value" "$W/primitives/primitives" "${PRIMITIVE_GROUPS[*]}" \
        --cpu "$value"
    COLUMNS+=("$W/primitives-$value")
    HEADER="$HEADER,cpu_$value"
    echo "SDE insn count: primitives under $value counted" >&2
done
write_csv "$OUT" "$HEADER" "${COLUMNS[@]}"

COLUMNS=()
HEADER=""
for entry in "${RECORDS[@]}"; do
    count_column "$W/${entry%%:*}" "$W/record/${entry%%:*}" "${RECORD_GROUPS[*]}"
    COLUMNS+=("$W/${entry%%:*}")
    HEADER="$HEADER,cpu_${entry#*:}"
    echo "SDE insn count: ${entry%%:*} counted" >&2
done
write_csv "$RECORD_OUT" "$HEADER" "${COLUMNS[@]}"
