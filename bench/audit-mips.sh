#!/usr/bin/env bash
# Reads what the compiler actually emitted for the three mips32r2 hot
# spots: the multiply mix in poly1305's blocks() and p256's mont_mul(),
# and the shape of chacha20's block() (loop kept or unrolled, memory
# traffic). Compiles the objects with the same container clang and flags
# as insn-mips.sh, so the disassembly matches the counted binaries, then
# counts mnemonics per function and per loop body (the span each backward
# branch closes; calls do not count as loops). Fails loudly if the loop
# structure stops matching the prose. Writes the findings to
# bench/notes-mips.md and stdout. Skips without docker.
#
# The eval calls below assign the P_, M_ and C_ variables from stats()
# output. shellcheck does not follow eval, so it reports every one of them
# as unassigned. One file-level disable replaces a directive on nearly
# every line from the checks to the report text. Dropping the check costs
# little here because set -u still stops the run on a misspelled name.
# shellcheck disable=SC2154
set -euo pipefail

if [ "${1:-}" != "--inside" ]; then
    cd "$(dirname "$0")/.."
    command -v docker >/dev/null 2>&1 || {
        echo "SKIP mips audit: docker not available" >&2
        exit 0
    }
    TMPOUT=$(mktemp)
    trap 'rm -f "$TMPOUT"' EXIT
    docker run --rm -v "$PWD":/src:ro -w /src alpine \
        sh -c 'apk add -q bash clang llvm >/dev/null 2>&1 \
               && exec bash /src/bench/audit-mips.sh --inside' \
        > "$TMPOUT"
    # tee would have truncated the committed file before the run produced a
    # line, so a failing audit destroyed last run's results.
    mv "$TMPOUT" bench/notes-mips.md
    cat bench/notes-mips.md
    echo "wrote bench/notes-mips.md" >&2
    exit 0
fi

# ---- inside the container from here on; markdown goes to stdout ----
W=/tmp/audit
mkdir -p "$W/shim"

cat > "$W/shim/string.h" <<'EOF'
#pragma once
#include <stddef.h>
void *memcpy(void *, const void *, size_t);
void *memmove(void *, const void *, size_t);
void *memset(void *, int, size_t);
int memcmp(const void *, const void *, size_t);
size_t strlen(const char *);
EOF

# The compile half of insn-mips.sh's flags; these objects never link.
CC="clang -target mips-linux-musl -march=mips32r2 -mno-abicalls -fno-pic -G0 \
    -Os -fno-stack-protector -ffreestanding -nostdlibinc -I/src -I$W/shim -c"
for src in poly1305 p256 chacha20; do
    $CC "/src/$src.c" -o "$W/$src.o"
done

# The llvm package does not always put llvm-objdump on PATH, so fall back to
# the versioned install directory and take the first match. Check the result
# because an unmatched glob would otherwise pass its own pattern along as a
# filename.
OBJDUMP=$(command -v llvm-objdump || printf '%s\n' /usr/lib/llvm*/bin/llvm-objdump | head -1)
[ -x "$OBJDUMP" ] || { echo "FAIL: the container has no llvm-objdump" >&2; exit 1; }

# Per-function statistics from the disassembly. Every backward branch or
# jump (calls and returns excluded) closes a loop; loops are reported in
# branch-address order, so disjoint loops appear in source order and an
# outer loop follows its inner loops.
cat > "$W/fnstats.awk" <<'EOF'
function h2d(h,   i, c, v) {
    v = 0
    h = tolower(h)
    for (i = 1; i <= length(h); i++) {
        c = index("0123456789abcdef", substr(h, i, 1)) - 1
        v = v * 16 + c
    }
    return v
}
$0 ~ ("^[0-9a-f]+ <" FN ">:$") { grab = 1; next }
/^[0-9a-f]+ <.+>:$/ { grab = 0 }
grab && /^ *[0-9a-f]+: / {
    a = $1
    sub(/:$/, "", a)
    n++
    addr[n] = h2d(a)
    mnem[n] = $2
    line[n] = $0
}
END {
    if (n == 0) { print "found=0"; exit }
    nl = 0
    for (i = 1; i <= n; i++) {
        m = mnem[i]
        if (m !~ /^[bj]/) { continue }
        br++
        if (m == "jal" || m == "jalr" || m == "bal") { calls++; continue }
        if (m == "jr") { ret++; continue }
        if (!match(line[i], /[ \t]0x[0-9a-f]+/)) { continue }
        t = h2d(substr(line[i], RSTART + 3, RLENGTH - 3))
        if (t >= addr[1] && t <= addr[i]) {
            nl++
            llo[nl] = t
            lhi[nl] = addr[i]
        }
    }
    for (i = 1; i <= n; i++) {
        m = mnem[i]
        ismul = (m == "maddu" || m == "madd" || m == "multu" || m == "mult" || \
                 m == "mul" || m == "msub" || m == "msubu")
        ismem = (m ~ /^[ls][bhw]/)
        if (ismul) { mall[m]++ }
        if (m == "mtlo" || m == "mthi") { mt++ }
        for (k = 1; k <= nl; k++) {
            if (addr[i] < llo[k] || addr[i] > lhi[k]) { continue }
            lin[k]++
            if (m == "maddu") { lmaddu[k]++ }
            if (m == "multu") { lmultu[k]++ }
            if (m == "mul") { lmul[k]++ }
            if (ismem) { lmem[k]++ }
        }
    }
    printf "found=1 insns=%d branches=%d ret=%d calls=%d loops=%d mtlohi=%d ", \
        n, br + 0, ret + 0, calls + 0, nl, mt + 0
    printf "maddu=%d multu=%d mult=%d mul=%d", \
        mall["maddu"] + 0, mall["multu"] + 0, mall["mult"] + 0, mall["mul"] + 0
    for (k = 1; k <= nl; k++) {
        printf " loop%d_insns=%d loop%d_maddu=%d loop%d_multu=%d loop%d_mul=%d loop%d_mem=%d", \
            k, lin[k] + 0, k, lmaddu[k] + 0, k, lmultu[k] + 0, k, lmul[k] + 0, k, lmem[k] + 0
    }
    printf "\n"
}
EOF

stats() { # $1 = object  $2 = function  $3 = shell-variable prefix
    "$OBJDUMP" -d --no-show-raw-insn "$W/$1" | awk -v FN="$2" -f "$W/fnstats.awk" \
        | tr ' ' '\n' | sed "s/^/${3}_/"
}

eval "$(stats poly1305.o blocks P)"
eval "$(stats p256.o mont_mul M)"
eval "$(stats chacha20.o block C)"

# The prose below describes this structure; a compiler that changes it
# must fail the run, not ship stale sentences.
[ "$P_found" -eq 1 ] && [ "$M_found" -eq 1 ] && [ "$C_found" -eq 1 ] || {
    echo "FAIL: a target function is missing from its object (inlined?)" >&2
    exit 1
}
[ "$P_loops" -eq 1 ] || { echo "FAIL: blocks() has $P_loops loops, prose assumes 1" >&2; exit 1; }
[ "$C_loops" -eq 3 ] || { echo "FAIL: block() has $C_loops loops, prose assumes 3" >&2; exit 1; }
[ "$M_loops" -eq 5 ] || { echo "FAIL: mont_mul() has $M_loops loops, prose assumes 5" >&2; exit 1; }
[ "$C_loop2_insns" -gt "$C_loop1_insns" ] && [ "$C_loop2_insns" -gt "$C_loop3_insns" ] || {
    echo "FAIL: block() loop 2 is not the largest; round-loop numbers would be wrong" >&2
    exit 1
}
[ "$M_mtlohi" -gt 0 ] && [ "$M_multu" -eq 0 ] || {
    echo "FAIL: mont_mul multiply lowering changed (mtlo/mthi=$M_mtlohi, multu=$M_multu)" >&2
    exit 1
}
# ct_widemul builds each limb product from four 16x16 pieces, so blocks()
# must reach the hi/lo multiplier zero times. A non-zero count here is the
# leak returning, and lint-wide-multiply guards the same property from the
# source side (https://github.com/c4milo/chapulin/issues/53).
[ "$P_multu" -eq 0 ] && [ "$P_maddu" -eq 0 ] && [ "$P_mult" -eq 0 ] || {
    echo "FAIL: blocks() reaches the hi/lo multiplier: $P_multu multu, $P_maddu maddu, $P_mult mult" >&2
    exit 1
}
[ "$P_mul" -eq 100 ] && [ "$P_loop1_mul" -eq 100 ] || {
    echo "FAIL: blocks() has $P_mul mul ($P_loop1_mul in the block loop), prose assumes 100 in the loop" >&2
    exit 1
}
[ "$M_mul" -eq 1 ] && [ "$M_loop1_maddu" -eq 1 ] && [ "$M_loop2_maddu" -eq 1 ] || {
    echo "FAIL: mont_mul mix is $M_mul mul, $M_loop1_maddu+$M_loop2_maddu inner maddu; prose assumes 1,1,1" >&2
    exit 1
}
[ "$C_loop2_mem" -eq 0 ] || {
    echo "FAIL: block() round loop touches memory $C_loop2_mem times, prose assumes registers only" >&2
    exit 1
}

CLANG_VER=$(clang --version | head -1)

cat <<EOF
# mips32r2 codegen notes

Counts read from llvm-objdump disassembly of the objects behind
bench/insn-mips.sh ($CLANG_VER,
-target mips-linux-musl -march=mips32r2 -Os). Static instruction counts;
bench/audit-mips.sh regenerates this file and fails if the shapes below
change.

## poly1305.c blocks(): mul only, 100 multiplies per block

blocks() keeps its single 16-byte block loop. The loop body is
$P_loop1_insns instructions with $P_loop1_mul mul per block and nothing
in the hi/lo multiplier: multu $P_multu, maddu $P_maddu, mult $P_mult.
ct_widemul builds each of the 25 limb products from four 16x16 pieces,
so the 25 products cost 100 mul. mips32r2 documents no timing for mul
either, but the operands are 16 bits wide by construction, which is what
the decomposition buys here.

## p256.c mont_mul(): maddu for every product

mont_mul multiplies through the hi/lo accumulator: $M_maddu maddu,
$M_multu multu, $M_mul mul. Each v = a[i]*b[j] + t[j] + c step preloads
hi/lo with mtlo/mthi (the t[j] + c partial) and issues one maddu; the
one mul computes u = t[0]*m0inv, where only the low word matters. Both
eight-iteration CIOS inner loops carry one maddu each
($M_loop1_maddu and $M_loop2_maddu), the outer limb loop spans them, and
the trailing compare and subtract loops close the function; nothing
unrolls at -Os. The $M_calls jal calls are memset (the t[] zeroing) and
memcpy (the no-subtract exit).

## chacha20.c block(): rounds looped, state in registers

clang does not unroll the rounds. block() carries $C_branches branch or
jump instructions: $C_loops loop back-edges (state copy-in, the
ten-iteration double-round loop, add-and-serialize) plus $C_ret return.
The round loop body is $C_loop2_insns instructions for two rounds (eight
quarter-rounds) per iteration and contains $C_loop2_mem loads or stores:
the sixteen state words and their temporaries stay in registers for all
20 rounds, spilling nothing.
EOF
