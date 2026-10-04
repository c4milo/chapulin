#!/usr/bin/env bash
# chacha20_vector.h's two refusals of a CHACHA=vector build, and the calls
# that make the build run the vector paths, checked the way
# test/widemul-builds.sh checks ct.h's rules for a host object. `make check`
# runs it, and it is the catch target of the violations that drop a
# refusal or a call (https://github.com/c4milo/chapulin/issues/181).
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
#     object cannot run the portable loop under the vector name;
#   - poly1305.c compiled with -DCH_CHACHA_VECTOR and -DCH_NATIVE_WIDEMUL
#     must call poly1305_vector_blocks, and compiled with either define
#     alone, or with both and -DCH_CT_WIDEMUL, must not, so the vector
#     Poly1305 runs exactly where the build states the multiply's timing
#     (docs/decisions.md 83);
#   - for x86-64, with no instruction flag, chacha20_avx2.c must define
#     chacha20_avx2_xor and hold 256-bit instructions, which its target
#     attribute turns on, while chacha20.c and chacha20_vector.c hold
#     none, so the rest of the object runs on any x86-64 CPU; chacha20.c
#     must call chacha20_vector_xor, and not the kernel while use_avx2
#     answers 0, so no object runs AVX2 before the caller's CH_CPU_AVX2
#     bit can say the CPU has it; and for arm64, chacha20_avx2.c must
#     define
#     nothing (docs/decisions.md 90).
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

# The same question for poly1305.c and the vector Poly1305.
calls_poly1305_vector() { # $1... = extra flags
    "$cc" -std=c11 -O2 -DCH_RAND_EXTERN -I. "$@" -c poly1305.c -o "$work/poly1305.o" || exit 1
    nm -u "$work/poly1305.o" | grep -qE '(^|[[:space:]_])poly1305_vector_blocks$'
}

if ! "$cc" -std=c11 -I. -fsyntax-only "$tu" 2>/dev/null; then
    echo "chacha-builds: SKIP the call check: $cc targets neither NEON nor SSE2 on a little-endian core"
else
    if ! calls_vector -DCH_CHACHA_VECTOR; then
        echo "chacha-builds: chacha20.c with -DCH_CHACHA_VECTOR does not call chacha20_vector_xor" >&2
        exit 1
    fi
    if ! calls_poly1305_vector -DCH_CHACHA_VECTOR -DCH_NATIVE_WIDEMUL; then
        echo "chacha-builds: poly1305.c with -DCH_CHACHA_VECTOR and -DCH_NATIVE_WIDEMUL does not call poly1305_vector_blocks" >&2
        exit 1
    fi
    if calls_poly1305_vector -DCH_CHACHA_VECTOR; then
        echo "chacha-builds: poly1305.c with -DCH_CHACHA_VECTOR and no CH_NATIVE_WIDEMUL calls poly1305_vector_blocks" >&2
        exit 1
    fi
    if calls_poly1305_vector -DCH_CHACHA_VECTOR -DCH_NATIVE_WIDEMUL -DCH_CT_WIDEMUL; then
        echo "chacha-builds: poly1305.c under -DCH_CT_WIDEMUL calls poly1305_vector_blocks" >&2
        exit 1
    fi
fi
if calls_vector; then
    echo "chacha-builds: chacha20.c without -DCH_CHACHA_VECTOR calls chacha20_vector_xor" >&2
    exit 1
fi
if calls_poly1305_vector -DCH_NATIVE_WIDEMUL; then
    echo "chacha-builds: poly1305.c without -DCH_CHACHA_VECTOR calls poly1305_vector_blocks" >&2
    exit 1
fi

# The AVX2 kernel, asked of the pinned clang for x86-64 and arm64 targets
# whatever the host, as the header checks above are.
cross_object() { # $1 = target, $2 = source; writes $work/cross.o and $work/cross.s
    "$clang_rv" -target "$1" -ffreestanding -nostdlibinc -Itools/freestanding -std=c11 -O2 -I. \
        -DCH_CHACHA_VECTOR -c "$2" -o "$work/cross.o" || exit 1
    "$clang_rv" -target "$1" -ffreestanding -nostdlibinc -Itools/freestanding -std=c11 -O2 -I. \
        -DCH_CHACHA_VECTOR -S "$2" -o "$work/cross.s" || exit 1
}
x86=x86_64-unknown-linux-gnu
cross_object "$x86" chacha20_avx2.c
if ! nm "$work/cross.o" | grep -qE '[[:space:]]T[[:space:]]_?chacha20_avx2_xor$' ||
    ! grep -q '%ymm' "$work/cross.s"; then
    echo "chacha-builds: chacha20_avx2.c for x86-64 must define chacha20_avx2_xor on 256-bit registers" >&2
    exit 1
fi
for src in chacha20.c chacha20_vector.c; do
    cross_object "$x86" "$src"
    if grep -q '%ymm' "$work/cross.s"; then
        echo "chacha-builds: $src for x86-64 holds a 256-bit instruction; only chacha20_avx2.c may" >&2
        exit 1
    fi
done
cross_object "$x86" chacha20.c
if ! nm -u "$work/cross.o" | grep -qE '(^|[[:space:]_])chacha20_vector_xor$' ||
    nm -u "$work/cross.o" | grep -qE '(^|[[:space:]_])chacha20_avx2_xor$'; then
    echo "chacha-builds: chacha20.c for x86-64 must call chacha20_vector_xor, and not the AVX2 kernel while use_avx2 answers 0" >&2
    exit 1
fi
cross_object aarch64-none-elf chacha20_avx2.c
if nm "$work/cross.o" | grep -q chacha20_avx2_xor; then
    echo "chacha-builds: chacha20_avx2.c for arm64 defines chacha20_avx2_xor; it has a body on x86-64 alone" >&2
    exit 1
fi

echo "chacha-builds: chacha20_vector.h admits NEON or SSE2 on a little-endian target alone, chacha20.c calls the vector path only under CH_CHACHA_VECTOR and not the AVX2 kernel while use_avx2 answers 0, the kernel's 256-bit instructions stay in chacha20_avx2.c, and poly1305.c calls its vector path only under that define and CH_NATIVE_WIDEMUL"
