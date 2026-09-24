#!/usr/bin/env bash
# ct.h's two refusals of an X25519=wide build, checked the way rand-check
# checks cfg.h's: a build that states what the field needs compiles, and a
# build that leaves out either half does not. `make check` runs it, and it
# is the catch target of the INV-34 violation that drops one refusal:
# test/violations.py runs a script by path and reads its exit status, and a
# make target is not a path.
#
# The two halves are checked one at a time, so a build that dropped one of
# them cannot hide behind the other:
#
#   - -DCH_X25519_WIDE without -DCH_NATIVE_MUL128, on this compiler: nobody
#     asserted the timing of the 64x64->128 multiply, so it must not build.
#   - -DCH_X25519_WIDE with -DCH_NATIVE_MUL128, for a 32-bit target: the
#     compiler has no unsigned __int128, so it must not build. The pinned
#     clang cross-compiles for the Cortex-M3 with no toolchain beside it,
#     the way lint-wide-multiply compiles for it.
cd "$(dirname "$0")/.." || exit 1

# One translation unit that reads ct.h and nothing else, so what passes or
# fails is the preprocessor rule and not some later compile error.
tu=$(mktemp -t chapulin_x25519_XXXXXX).c
trap 'rm -f "$tu" "${tu%.c}"' EXIT
echo '#include "ct.h"' > "$tu"
cc=${CC:-cc}

# The build that states both, on a compiler with the type: it compiles.
if ! "$cc" -std=c11 -I. -fsyntax-only -DCH_X25519_WIDE -DCH_NATIVE_MUL128 "$tu"; then
    echo "x25519-builds: -DCH_X25519_WIDE with CH_NATIVE_MUL128 must compile on $cc" >&2
    exit 1
fi

# The field with nobody asserting the multiply's timing: it does not.
if "$cc" -std=c11 -I. -fsyntax-only -DCH_X25519_WIDE "$tu" 2>/dev/null; then
    echo "x25519-builds: -DCH_X25519_WIDE without CH_NATIVE_MUL128 compiled; ct.h must refuse it" >&2
    exit 1
fi

# The field on a target without unsigned __int128, with the assertion made,
# so only the type is missing. The pinned clang is the one make resolves.
clang_rv=$(make -s --no-print-directory print-clang-rv)
if [ -z "$clang_rv" ]; then
    echo "x25519-builds: no clang to cross-compile with; see the LLVM_MAJOR pin in tools/toolchain.env" >&2
    exit 1
fi
m3=(-target thumbv7m-none-eabi -mcpu=cortex-m3 -ffreestanding -nostdlibinc -Itools/freestanding)
if ! "$clang_rv" "${m3[@]}" -std=c11 -I. -fsyntax-only "$tu"; then
    echo "x25519-builds: ct.h must compile for the Cortex-M3 without the wide field" >&2
    exit 1
fi
if "$clang_rv" "${m3[@]}" -std=c11 -I. -fsyntax-only \
    -DCH_X25519_WIDE -DCH_NATIVE_MUL128 "$tu" 2>/dev/null; then
    echo "x25519-builds: -DCH_X25519_WIDE compiled for the Cortex-M3; ct.h must refuse a target without unsigned __int128" >&2
    exit 1
fi

echo "x25519-builds: ct.h admits X25519=wide only with CH_NATIVE_MUL128 and unsigned __int128"
