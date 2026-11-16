#!/usr/bin/env bash
# Counts the instructions of each primitive row a host object runs, under
# valgrind's callgrind, for each ch_cfg.cpu value valgrind executes on this
# architecture. Writes bench/results-insn-host-<arch>.csv, or the file
# INSN_OUT names, which make insn-gate-host holds to the recorded one with
# tools/insn-gate.py (docs/decisions.md 235).
#
# The program is bench/primitives.c's, over the Makefile's
# BENCH_PRIMITIVE_SRCS as a host object holds them, built with
# -DBENCH_CALLGRIND. Its --count option runs each row's operation once,
# then once more between a CALLGRIND_ZERO_STATS and a
# CALLGRIND_DUMP_STATS_AT, so each dump holds one operation.
# tools/callgrind-own.py sums the instructions the dump counted in the
# program's own code: glibc picks its memcpy and memset from the CPU it
# starts on, so a count that held them would differ from one runner to
# the next.
#
# A count is a property of the compiler and of the inputs. The inputs are
# fixed: bench_fill and the DRBG take fixed seeds, so ML-DSA's rejection
# loop runs the same rounds each time, and a secret-key operation runs in
# constant time, so its count does not depend on the random bytes it
# draws. The compiler is CC, gcc by default, and its first line of
# --version heads the CSV, so a moved compiler shows.
#
# Valgrind runs no AVX-512 and no VAES, so no value here sets those bits,
# and the rows those bits pick stay on bench/primitives.sh's timed rows.
# Skips without valgrind.
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
CC=${CC:-gcc}

# The values each architecture counts. Each is a value a caller on a CPU
# with those instructions states, and valgrind executes every instruction
# the paths it picks run. 0x1 is the portable code, 0x7 adds the AES and
# multiply bits, and on x86-64 0xf adds AVX2, 0xc0f BMI1 and BMI2_ADX
# beside it. On arm64 0x27 adds the SHA-256 instructions and 0x67 the
# SHA-512 ones. The SHA-3 bit picks nothing in an object gcc compiled
# (docs/decisions.md 99), so no value here sets it.
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

W=$(mktemp -d)
trap 'rm -rf "$W"' EXIT

LIB_CFLAGS=$(make -s --no-print-directory print-lib-cflags CC="$CC")
read -r -a SRCS <<<"$(make -s --no-print-directory print-bench-primitive-srcs)"
read -r -a HOST_SRCS <<<"$(make -s --no-print-directory print-host-srcs HOST_SRCS_OF="${SRCS[*]}")"
if [ -z "$LIB_CFLAGS" ] || [ "${#HOST_SRCS[@]}" -le "${#SRCS[@]}" ]; then
    echo "FAIL host insn count: make returned no flags or no host sources" >&2
    exit 1
fi
# sha512_avx2.c compiles apart, as bench/primitives.sh says.
SHA512_AVX2_UNIT=$(make -s --no-print-directory sha512-avx2-unit CC="$CC" SHA512_AVX2_UNIT_DIR="$W")
HOST_SRCS=("${HOST_SRCS[@]/#src\/sha512_avx2.c/$SHA512_AVX2_UNIT}")
# LIB_CFLAGS is a list of flags, so it splits on spaces.
# shellcheck disable=SC2086
"$CC" $LIB_CFLAGS -DCH_RAND_DRBG -DBENCH_CALLGRIND -DCH_RSA_MODULUS_MAX=512 -DCH_CPU_RUNTIME \
    -I"$VALGRIND_INCLUDE" -Isrc -Iinclude/chapulin -Iinclude -I. -Ibench -Itest \
    -o "$W/primitives" "${HOST_SRCS[@]}"

# One column of counts: the rows in the program's order, as op,count.
count_value() { # $1 = a ch_cfg.cpu value
    local dir="$W/$1"
    mkdir -p "$dir"
    if ! "$VALGRIND" --tool=callgrind --compress-strings=no --compress-pos=no --dump-instr=no \
        --callgrind-out-file="$dir/cg.out" "$W/primitives" --count --cpu "$1" \
        hash cipher aead verify secret_key >"$dir/rows" 2>"$dir/log"; then
        echo "FAIL host insn count: the program failed under valgrind at --cpu $1" >&2
        tail -20 "$dir/log" >&2
        exit 1
    fi
    # Each dump request writes cg.out.N, and the end of the program
    # writes cg.out, which holds what ran after the last request.
    local dumps
    dumps=$(find "$dir" -name 'cg.out.*' | awk -F. '{ print $NF "\t" $0 }' | sort -n | cut -f2)
    # The dump paths hold no space, so the list splits on newlines alone.
    # shellcheck disable=SC2086
    python3 tools/callgrind-own.py "$W/primitives" $dumps |
        awk -F, '{ printf "%s/%s,%s\n", $1, $2, $3 }' >"$dir/counts"
    if [ "$(wc -l <"$dir/counts")" -ne "$(wc -l <"$dir/rows")" ]; then
        echo "FAIL host insn count: $(wc -l <"$dir/rows") rows ran at --cpu $1 and" \
            "$(wc -l <"$dir/counts") dumps were read" >&2
        exit 1
    fi
}

for value in "${VALUES[@]}"; do
    count_value "$value"
    echo "host insn count: --cpu $value counted" >&2
done

TMPOUT=$(mktemp)
{
    printf '# %s; %s; -O2 host object; instructions in the program alone (tools/callgrind-own.py)\n' \
        "$("$CC" --version | head -1)" "$("$VALGRIND" --version)"
    printf 'op'
    for value in "${VALUES[@]}"; do
        printf ',cpu_%s' "$value"
    done
    printf '\n'
    # The first column's ops, then each column's counts beside them, in
    # one order: every value runs the same rows.
    COLUMNS=()
    for value in "${VALUES[@]}"; do
        COLUMNS+=("$W/$value/counts")
    done
    paste -d, "${COLUMNS[@]}" |
        awk -F, '{
            line = $1 "," $2
            for (i = 3; i <= NF; i += 2) {
                if ($i != $1) { print "op order differs: " $1 " " $i > "/dev/stderr"; exit 1 }
                line = line "," $(i + 1)
            }
            print line
        }'
} >"$TMPOUT"
mv "$TMPOUT" "$OUT"
echo "wrote $OUT" >&2
