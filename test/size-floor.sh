#!/bin/bash
# ct.h refuses a size_t narrower than 32 bits. This compiles ct.h for a
# 16-bit target, msp430, where it must stop on that assertion, and for a
# 32-bit one, armv7m, where it must compile. `make lint-size-floor` runs it
# with CLANG_RV, a clang that targets both. test/violations.py runs it with
# no argument, and then it asks make for CLANG_RV itself.
set -euo pipefail
cd "$(dirname "$0")/.."

cc=${1:-$(make -s --no-print-directory print-clang-rv)}
fail() {
    echo "lint-size-floor: $*" >&2
    exit 1
}
[ -n "$cc" ] || fail "no clang that targets msp430 and armv7m (CLANG_RV)"
compile() {
    "$cc" --target="$1" -ffreestanding -fsyntax-only -std=c11 -I. -x c ct.h 2>&1
}

if out=$(compile msp430); then
    fail "ct.h compiled for msp430, whose size_t is 16 bits"
fi
case "$out" in
*"a size_t of at least 32 bits"*) ;;
*) fail "ct.h stopped for msp430, but not on the size_t floor: $out" ;;
esac
out=$(compile armv7m-none-eabi) || fail "ct.h does not compile for armv7m, whose size_t is 32 bits: $out"
echo "lint-size-floor: ct.h refuses msp430's 16-bit size_t and compiles for armv7m's 32-bit one"
