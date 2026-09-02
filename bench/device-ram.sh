#!/usr/bin/env bash
# Models chapulin's flash and stack cost on a mips32r2 device instead of
# deriving them from a hosted build: cross-compiles the default build's
# library sources (no tests) at -Os, reads flash from each object's
# .text+.rodata sections, and takes worst-case frames from -fstack-usage.
# The same sources build for the host arch at -Os alongside, so the two
# columns compare like for like. Objects are sized, never linked, so a
# declaration-only libc shim stands in for string.h. Writes
# bench/results-device.csv. Fails without the pinned clang.
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT=$PWD

# Every row is a property of what one compiler emits: a re-run under a
# different clang major moved every row, untouched modules included
# (https://github.com/c4milo/chapulin/issues/111). So the compiler is the
# Makefile's CLANG_RV, resolved in its order (the versioned name, the
# versioned Homebrew keg, then the unversioned candidates), and it must be
# the LLVM_MAJOR that tools/toolchain.env pins or the script stops. The
# unversioned candidates can be any major, which is why the check below
# is not optional.
# shellcheck source=tools/toolchain.env
. tools/toolchain.env
CLANG=$(make -s --no-print-directory -C "$ROOT" print-clang-rv)
[ -n "$CLANG" ] || {
    echo "FAIL device model: no clang found; the pin is LLVM $LLVM_MAJOR (tools/toolchain.env)" >&2
    exit 1
}
CLANG_VERSION=$("$CLANG" --version | head -1)
case "$CLANG_VERSION" in
*"clang version $LLVM_MAJOR."*) ;;
*)
    echo "FAIL device model: $CLANG is $CLANG_VERSION" >&2
    echo "FAIL device model: the pin is LLVM $LLVM_MAJOR (tools/toolchain.env). Every row of" >&2
    echo "FAIL device model: bench/results-device.csv is a property of that compiler, so install" >&2
    echo "FAIL device model: it, or bump the pin and re-measure; never measure with another." >&2
    exit 1
    ;;
esac

TRIPLE="-target mips-none-elf -mcpu=mips32r2"
# TRIPLE holds three arguments, so it must word-split here. Quoted, clang
# reads the whole string as one unknown argument and rejects it.
# shellcheck disable=SC2086
echo 'int probe;' | "$CLANG" $TRIPLE -c -x c - -o /dev/null 2>/dev/null || {
    echo "FAIL device model: $CLANG has no MIPS backend" >&2
    exit 1
}
SIZE=$(dirname "$CLANG")/llvm-size
[ -x "$SIZE" ] || SIZE=$(command -v "llvm-size-$LLVM_MAJOR" || command -v llvm-size || true)
[ -n "$SIZE" ] || {
    echo "FAIL device model: no llvm-size beside $CLANG or on PATH" >&2
    exit 1
}
HOST_TRIPLE=$("$CLANG" -dumpmachine)

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
mkdir "$TMP/shim" "$TMP/dev" "$TMP/host"

cat > "$TMP/shim/string.h" <<'EOF'
#pragma once
#include <stddef.h>
void *memcpy(void *, const void *, size_t);
void *memmove(void *, const void *, size_t);
void *memset(void *, int, size_t);
int memcmp(const void *, const void *, size_t);
size_t strlen(const char *);
EOF

# The sources the Makefile links into the default (PIN=rsa) bin/chapulin.o;
# p256 is measured too so the PIN=ecdsa column stays known, but the totals
# below count the default build only.
# The module list comes from the Makefile, so it cannot drift from what
# the build packages. LIB_SRCS for the default profile (PIN=rsa,
# TRUST=pinned, KEX=x25519); RAND=extern keeps the generator out, since
# the caller supplies entropy.
SRCS=$(make -s --no-print-directory -C "$ROOT" print-lib-srcs RAND=extern \
      | tr ' ' '\n' | sed 's/\.c$//' | tr '\n' ' ')
EXTRA_SRCS="p256"

# An empty list would size nothing and still print a totals row, which
# reads as a real measurement. Fail instead.
[ -n "$SRCS" ] || {
    echo "device model: make print-lib-srcs returned no sources" >&2
    exit 1
}

DEV="$CLANG $TRIPLE -Os -ffreestanding -nostdlibinc -fstack-usage -DCH_RAND_EXTERN -I$ROOT -I$TMP/shim -c"
HOSTCC="$CLANG -Os -fstack-usage -DCH_RAND_EXTERN -I$ROOT -c"

sections() { # $1 = section pattern  $2 = object: summed bytes
    "$SIZE" -A "$2" | awk -v pat="$1" '$1 ~ pat { sum += $2 } END { print sum + 0 }'
}

su_top() { # $1 = su file: "bytes fn" of the deepest frame
    awk -F'\t' '{ n = split($1, a, ":"); if ($2 + 0 >= m) { m = $2 + 0; fn = a[n] } }
        END { printf "%d %s\n", m, fn }' "$1"
}

for src in $SRCS $EXTRA_SRCS; do
    (cd "$TMP/dev" && $DEV "$ROOT/$src.c" -o "$src.o")
    (cd "$TMP/host" && $HOSTCC "$ROOT/$src.c" -o "$src.o")
done

OUT=bench/results-device.csv
# The comment line names the compiler that produced every row, so a
# reader can tell a source change from a compiler change.
# tools/bench-numbers.py skips lines that start with #.
{
    echo "# $CLANG_VERSION (LLVM_MAJOR=$LLVM_MAJOR, tools/toolchain.env); device $TRIPLE -Os; host $HOST_TRIPLE -Os"
    echo "module,mips_text_B,mips_rodata_B,mips_flash_B,mips_max_frame_B,mips_max_frame_fn,host_flash_B,host_max_frame_B"
} > "$OUT"

T_TEXT=0
T_RO=0
T_HOST=0
T_FRAME=0
T_FRAME_FN=""
T_HFRAME=0
for src in $SRCS; do
    TEXT=$(sections '^\.text' "$TMP/dev/$src.o")
    RO=$(sections '^\.rodata' "$TMP/dev/$src.o")
    # Mach-O flash lives in __text, __const, __cstring, and __literalN.
    HOSTF=$(sections '^__(text|const|cstring|literal)' "$TMP/host/$src.o")
    read -r FRAME FN <<< "$(su_top "$TMP/dev/$src.su")"
    read -r HFRAME _ <<< "$(su_top "$TMP/host/$src.su")"
    echo "$src,$TEXT,$RO,$((TEXT + RO)),$FRAME,$FN,$HOSTF,$HFRAME" >> "$OUT"
    T_TEXT=$((T_TEXT + TEXT))
    T_RO=$((T_RO + RO))
    T_HOST=$((T_HOST + HOSTF))
    if [ "$FRAME" -gt "$T_FRAME" ]; then T_FRAME=$FRAME; T_FRAME_FN=$FN; fi
    if [ "$HFRAME" -gt "$T_HFRAME" ]; then T_HFRAME=$HFRAME; fi
done
echo "total,$T_TEXT,$T_RO,$((T_TEXT + T_RO)),$T_FRAME,$T_FRAME_FN,$T_HOST,$T_HFRAME" >> "$OUT"

# Out-of-build modules, sized but outside the totals: what a PIN=ecdsa
# build swaps in for rsa + rsa_mont.
for src in $EXTRA_SRCS; do
    TEXT=$(sections '^\.text' "$TMP/dev/$src.o")
    RO=$(sections '^\.rodata' "$TMP/dev/$src.o")
    HOSTF=$(sections '^__(text|const|cstring|literal)' "$TMP/host/$src.o")
    read -r FRAME FN <<< "$(su_top "$TMP/dev/$src.su")"
    read -r HFRAME _ <<< "$(su_top "$TMP/host/$src.su")"
    echo "$src (PIN=ecdsa),$TEXT,$RO,$((TEXT + RO)),$FRAME,$FN,$HOSTF,$HFRAME" >> "$OUT"
done

echo "device flash and stack model ($CLANG_VERSION; $TRIPLE -Os; host = $HOST_TRIPLE -Os)"
grep -v '^#' "$OUT" | column -s, -t
echo
echo "deepest -fstack-usage frames, mips32r2 -Os (frames, not call-graph"
echo "peaks; bench/sram.sh walks the host call graph):"
cat "$TMP"/dev/*.su | sort -t "$(printf '\t')" -k2,2nr | head -10 \
    | awk -F'\t' '{ printf "  %5d B  %s\n", $2, $1 }'
echo "wrote $OUT"
