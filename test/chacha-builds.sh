#!/usr/bin/env bash
# chacha20_vector.h's two refusals of a CHACHA=vector build, and the call
# that makes the build run the vector path, checked the way
# test/x25519-builds.sh checks ct.h's rules for X25519=wide. `make check`
# runs it, and it is the catch target of the violations that drop a
# refusal or the call (https://github.com/c4milo/chapulin/issues/181).
#
# Each rule is checked on its own, beside a build the same compiler must
# accept, so a failure here is the rule and not a missing header:
#
#   - for the Cortex-M3, which has neither NEON nor SSE2, the header must
#     not compile;
#   - for big-endian AArch64, which has NEON, the header must not compile,
#     and for little-endian AArch64 it must;
#   - chacha20.c compiled with -DCH_CHACHA_VECTOR must call
#     chacha20_vector_xor, and compiled without it must not, so a vector
#     object cannot run the portable loop under the vector name.
#
# The cross targets use the pinned clang, which make resolves, with no
# toolchain beside it, the way lint-wide-multiply compiles for them.
cd "$(dirname "$0")/.." || exit 1

work=$(mktemp -d -t chapulin_chacha_XXXXXX)
trap 'rm -rf "$work"' EXIT
tu=$work/header.c
printf '#define CH_CHACHA_VECTOR\n#include "chacha20_vector.h"\n' > "$tu"
cc=${CC:-cc}

clang_rv=$(make -s --no-print-directory print-clang-rv)
if [ -z "$clang_rv" ]; then
    echo "chacha-builds: no clang to cross-compile with; see the LLVM_MAJOR pin in tools/toolchain.env" >&2
    exit 1
fi

# One compile of the header for a target, syntax only.
header_builds() { # $1... = target flags
    "$clang_rv" "$@" -ffreestanding -nostdlibinc -Itools/freestanding -std=c11 -I. \
        -fsyntax-only "$tu" 2>/dev/null
}

if header_builds -target thumbv7m-none-eabi -mcpu=cortex-m3; then
    echo "chacha-builds: chacha20_vector.h compiled for the Cortex-M3; it must refuse a target with neither NEON nor SSE2" >&2
    exit 1
fi
if ! header_builds -target aarch64-none-elf -march=armv8-a; then
    echo "chacha-builds: chacha20_vector.h must compile for little-endian AArch64" >&2
    exit 1
fi
if header_builds -target aarch64_be-none-elf -march=armv8-a; then
    echo "chacha-builds: chacha20_vector.h compiled for big-endian AArch64; it must refuse a big-endian target" >&2
    exit 1
fi

# Whether chacha20.c's object calls the vector path, read from the
# undefined symbols nm lists. Mach-O names carry a leading underscore.
calls_vector() { # $1... = extra flags
    "$cc" -std=c11 -O2 -I. "$@" -c chacha20.c -o "$work/chacha20.o" || exit 1
    nm -u "$work/chacha20.o" | grep -qE '(^|[[:space:]_])chacha20_vector_xor$'
}

if ! "$cc" -std=c11 -I. -fsyntax-only "$tu" 2>/dev/null; then
    echo "chacha-builds: SKIP the call check: $cc targets neither NEON nor SSE2 on a little-endian core"
else
    if ! calls_vector -DCH_CHACHA_VECTOR; then
        echo "chacha-builds: chacha20.c with -DCH_CHACHA_VECTOR does not call chacha20_vector_xor" >&2
        exit 1
    fi
fi
if calls_vector; then
    echo "chacha-builds: chacha20.c without -DCH_CHACHA_VECTOR calls chacha20_vector_xor" >&2
    exit 1
fi

echo "chacha-builds: chacha20_vector.h admits NEON or SSE2 on a little-endian target alone, and chacha20.c calls the vector path only under CH_CHACHA_VECTOR"
