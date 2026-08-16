#!/usr/bin/env bash
# Models chapulin's flash and stack cost on a mips32r2 device instead of
# deriving them from a hosted build: cross-compiles the default build's
# seventeen library sources (no tests) at -Os, reads flash from each
# object's .text+.rodata sections, and takes worst-case frames from
# -fstack-usage. The same
# sources build for the host arch at -Os alongside, so the two columns
# compare like for like. Objects are sized, never linked, so a
# declaration-only libc shim stands in for string.h. Writes
# bench/results-device.csv. Skips without a MIPS-capable clang.
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT=$PWD

TRIPLE="-target mips-none-elf -mcpu=mips32r2"
CLANG=clang
echo 'int probe;' | $CLANG $TRIPLE -c -x c - -o /dev/null 2>/dev/null \
    || CLANG=/opt/homebrew/opt/llvm/bin/clang
echo 'int probe;' | $CLANG $TRIPLE -c -x c - -o /dev/null 2>/dev/null || {
    echo "SKIP device model: no clang with a MIPS backend (brew install llvm)" >&2
    exit 0
}
SIZE=$(dirname "$CLANG")/llvm-size
[ -x "$SIZE" ] || SIZE=$(command -v llvm-size \
    || echo /Library/Developer/CommandLineTools/usr/bin/llvm-size)

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
SRCS="ct sha256 hkdf chacha20 poly1305 aead x25519 rsa rsa_mont buf record keysched \
      io hsmsg session handshake tls"
EXTRA_SRCS="p256"

DEV="$CLANG $TRIPLE -Os -ffreestanding -nostdlibinc -fstack-usage -I$ROOT -I$TMP/shim -c"
HOSTCC="$CLANG -Os -fstack-usage -I$ROOT -c"

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
echo "module,mips_text_B,mips_rodata_B,mips_flash_B,mips_max_frame_B,mips_max_frame_fn,host_flash_B,host_max_frame_B" > "$OUT"

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

HOST_TRIPLE=$($CLANG -dumpmachine)
echo "device flash and stack model ($CLANG $TRIPLE -Os; host = $HOST_TRIPLE -Os)"
column -s, -t < "$OUT"
echo
echo "deepest -fstack-usage frames, mips32r2 -Os (frames, not call-graph"
echo "peaks; bench/sram.sh walks the host call graph):"
cat "$TMP"/dev/*.su | sort -t "$(printf '\t')" -k2,2nr | head -10 \
    | awk -F'\t' '{ printf "  %5d B  %s\n", $2, $1 }'
echo "wrote $OUT"
