#!/usr/bin/env bash
# Counts the instructions of each row a host object's benchmarks run, under
# valgrind's callgrind, for each ch_cfg.cpu value valgrind executes on this
# architecture. Writes two files, which make insn-gate-host holds to the
# recorded ones with tools/insn-gate.py (docs/decisions.md 235):
#
#   bench/results-insn-host-<arch>.csv, or the file INSN_OUT names: each
#   primitive row of bench/primitives.c and each whole handshake of
#   bench/primitives_handshake.c, one column for each value.
#
#   bench/results-insn-record-<arch>.csv, or the file INSN_RECORD_OUT
#   names: each row of bench/record.c, a TLS record's protection and its
#   stages, under the two values bench/record.sh builds for every CPU.
#
# The programs are bench/primitives.sh's and bench/record.sh's, which
# --build compiles into BENCH_BUILD_DIR with -DBENCH_CALLGRIND added. Their
# --count option runs each row's operation once, then once more between a
# CALLGRIND_ZERO_STATS and a CALLGRIND_DUMP_STATS_AT, so each dump holds
# one operation. tools/callgrind-own.py sums the instructions the dump
# counted in the program's own code: glibc picks its memcpy and memset
# from the CPU it starts on, so a count that held them would differ from
# one runner to the next.
#
# A count is a property of the compiler and of the inputs. The inputs are
# fixed: bench_fill and the DRBG take fixed seeds, so ML-DSA's rejection
# loop runs the same rounds each time, and a secret-key operation runs in
# constant time, so its count does not depend on the random bytes it
# draws. The compiler is CC, gcc by default, and its first line of
# --version heads each CSV, so a moved compiler shows.
#
# Valgrind runs no AVX-512, no VAES and no x86-64 SHA extensions, so no
# value here sets those bits, and the rows those bits pick stay on the
# timed rows. Skips without valgrind.
set -euo pipefail
cd "$(dirname "$0")/.."

VALGRIND=${VALGRIND:-$(command -v valgrind || true)}
[ -n "$VALGRIND" ] || {
    echo "SKIP host insn count: no valgrind" >&2
    exit 0
}
VALGRIND_INCLUDE=${VALGRIND_INCLUDE:-$(dirname "$VALGRIND")/../include}
[ -f "$VALGRIND_INCLUDE/valgrind/callgrind.h" ] || {
    echo "FAIL host insn count: no valgrind/callgrind.h under $VALGRIND_INCLUDE" >&2
    exit 1
}
export CC=${CC:-gcc}

# The values each architecture counts. Each is a value a caller on a CPU
# with those instructions states, and valgrind executes every instruction
# the paths it picks run. 0x1 is the portable code, 0x7 adds the AES and
# multiply bits, and on x86-64 0xf adds AVX2, 0xc0f BMI1 and BMI2_ADX
# beside it. On arm64 0x27 adds the SHA-256 instructions and 0x67 the
# SHA-512 ones. The SHA-3 bit picks nothing in an object gcc compiled
# (docs/decisions.md 99), so no value here sets it. No value sets
# CH_CPU_SVE2 either: valgrind 3.27.1 dies of SIGILL at the first XAR of
# chacha20_sve2.c's copy (docs/decisions.md 242). The record binaries
# take their value on the compile line: 0x3 and 0x7.
case "$(uname -m)" in
x86_64)
    ARCH=x86_64
    VALUES=(0x1 0x7 0xf 0xc0f)
    ;;
aarch64 | arm64)
    ARCH=arm64
    VALUES=(0x1 0x7 0x27 0x67)
    ;;
*)
    echo "FAIL host insn count: no values for $(uname -m)" >&2
    exit 1
    ;;
esac
OUT=${INSN_OUT:-bench/results-insn-host-$ARCH.csv}
RECORD_OUT=${INSN_RECORD_OUT:-bench/results-insn-record-$ARCH.csv}
HANDSHAKES=(handshake_rsa handshake_ecdsa handshake_rsa_hybrid handshake_ecdsa_hybrid)
RECORDS=(record:0x3 record_multiply:0x7)

W=$(mktemp -d)
trap 'rm -rf "$W"' EXIT

BENCH_BUILD_DIR="$W/primitives" PRIMITIVES_EXTRA_FLAGS="-DBENCH_CALLGRIND -I$VALGRIND_INCLUDE" \
    bench/primitives.sh --build
BENCH_BUILD_DIR="$W/record" RECORD_EXTRA_FLAGS="-DBENCH_CALLGRIND -I$VALGRIND_INCLUDE" \
    bench/record.sh --build

# The rows one program counts, as op,count in the program's order, into
# $1/counts.
count_program() { # $1 = a directory of its own; the rest = the program and its arguments
    local dir=$1
    shift
    mkdir -p "$dir"
    if ! "$VALGRIND" --tool=callgrind --compress-strings=no --compress-pos=no --dump-instr=no \
        --callgrind-out-file="$dir/cg.out" "$@" >"$dir/rows" 2>"$dir/log"; then
        echo "FAIL host insn count: $* failed under valgrind" >&2
        tail -20 "$dir/log" >&2
        exit 1
    fi
    # Each dump request writes cg.out.N, and the end of the program
    # writes cg.out, which holds what ran after the last request.
    local dumps
    dumps=$(find "$dir" -name 'cg.out.*' | awk -F. '{ print $NF "\t" $0 }' | sort -n | cut -f2)
    # The dump paths hold no space, so the list splits on newlines alone.
    # shellcheck disable=SC2086
    python3 tools/callgrind-own.py "$1" $dumps |
        awk -F, '{ printf "%s/%s,%s\n", $1, $2, $3 }' >"$dir/counts"
    if [ "$(wc -l <"$dir/counts")" -ne "$(wc -l <"$dir/rows")" ]; then
        echo "FAIL host insn count: $(wc -l <"$dir/rows") rows ran in $* and" \
            "$(wc -l <"$dir/counts") dumps were read" >&2
        exit 1
    fi
}

# Joins columns of counts into a CSV: the compiler line, the header line,
# then each op with the count of each column beside it. Every column runs
# the same rows in one order, and a row whose op differs stops the script.
write_csv() { # $1 = output; $2 = header after op; the rest = count files
    local out=$1 header=$2
    shift 2
    local tmp
    tmp=$(mktemp)
    {
        printf '# %s; %s; -O2 host object; instructions in the program alone (tools/callgrind-own.py)\n' \
            "$("$CC" --version | head -1)" "$("$VALGRIND" --version)"
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
    count_program "$W/count-$value" "$W/primitives/primitives" --count --cpu "$value" \
        hash cipher aead verify secret_key
    for program in "${HANDSHAKES[@]}"; do
        count_program "$W/count-$value-$program" "$W/primitives/$program" --count --cpu "$value" \
            handshake
        cat "$W/count-$value-$program/counts" >>"$W/count-$value/counts"
    done
    COLUMNS+=("$W/count-$value/counts")
    HEADER="$HEADER,cpu_$value"
    echo "host insn count: --cpu $value counted" >&2
done
write_csv "$OUT" "$HEADER" "${COLUMNS[@]}"

COLUMNS=()
HEADER=""
for entry in "${RECORDS[@]}"; do
    count_program "$W/count-${entry%%:*}" "$W/record/${entry%%:*}" --count \
        aes128gcm aes256gcm chacha20poly1305
    COLUMNS+=("$W/count-${entry%%:*}/counts")
    HEADER="$HEADER,cpu_${entry#*:}"
    echo "host insn count: ${entry%%:*} counted" >&2
done
write_csv "$RECORD_OUT" "$HEADER" "${COLUMNS[@]}"
