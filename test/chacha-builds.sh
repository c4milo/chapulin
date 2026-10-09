#!/usr/bin/env bash
# chacha20_vector.h's two refusals, the calls that make a host object run
# the vector ChaCha20, and the x86-64 kernel's instructions in its own
# file, checked the way test/widemul-builds.sh checks ct.h's rules for a
# host object. `make check` runs it, and it is the catch target of the
# violations that drop a refusal or a call
# (https://github.com/c4milo/chapulin/issues/181, docs/decisions.md 89).
#
# Each rule is checked on its own, beside a build the same compiler must
# accept, so a failure here is the rule and not a missing header:
#
#   - for the Cortex-M3, which has neither NEON nor SSE2, the header must
#     not compile;
#   - for big-endian AArch64, which has NEON, the header must not compile,
#     and for little-endian AArch64 it must;
#   - a device object's chacha20.c, compiled without -DCH_CPU_RUNTIME,
#     must call no vector path, and its poly1305.c must call no vector
#     Poly1305, with -DCH_NATIVE_WIDEMUL and without it: a device object
#     holds the portable loops alone (docs/decisions.md 83 and 89).
#     test/widemul-builds.sh holds a host object's Poly1305;
#   - in a host object, chacha20_xor must call chacha20_vector_xor, so no
#     session runs the portable loop under the vector name, and on x86-64
#     it must call neither kernel: it takes no description of the CPU, so
#     it runs the path every CPU has. chacha20_xor_cpu, which takes a
#     session's ch_cfg.cpu, must call chacha20_vector_xor, on x86-64 both
#     kernels too, and on arm64 no kernel. A use_avx2 or use_avx512 that
#     answers one value for every session leaves one of the calls out, so
#     this holds both answers; bin/x86_kernels_test holds which bit gives
#     which;
#   - for x86-64, with no instruction flag, chacha20_avx2.c must define
#     chacha20_avx2_xor and hold 256-bit instructions, which its target
#     attribute turns on, and chacha20_avx512.c must define
#     chacha20_avx512_xor on 512-bit registers and call
#     avx512_wipe_registers, while chacha20.c and chacha20_vector.c hold
#     neither, so the rest of the object runs on any x86-64 CPU; and for
#     arm64, the two kernels' files must define nothing (docs/decisions.md
#     90);
#   - the same for the AVX2 Poly1305, the AEAD's other half
#     (docs/decisions.md 110): for x86-64, poly1305_avx2_native.c must
#     define poly1305_avx2_blocks_native on 256-bit registers, and
#     poly1305_native.c must call it and hold no 256-bit instruction
#     itself, as poly1305_vector_native.c must hold none; for arm64,
#     poly1305_avx2_native.c must define nothing and poly1305_native.c call
#     nothing of it; and poly1305.c under its own names, and its native copy
#     under -DCH_CT_WIDEMUL, which turns the vector paths off, must call
#     no AVX2 entry on either target;
#   - for x86-64, avx512_wipe.c must define avx512_wipe_registers, whose
#     body zeros each of the 32 vector registers with a VPXORD of the
#     register with itself and each of k1 to k7 with a KXORW, and for
#     arm64 it must define nothing.
#
# The cross targets use the pinned clang, which make resolves, with no
# toolchain beside it, the way lint-wide-multiply compiles for them.
cd "$(dirname "$0")/.." || exit 1

work=$(mktemp -d -t chapulin_chacha_XXXXXX)
trap 'rm -rf "$work"' EXIT
tu=$work/header.c
printf '#define CH_CPU_RUNTIME\n#include "chacha20_vector.h"\n' > "$tu"
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

# Whether a device object's source calls a symbol, read from the undefined
# symbols nm lists. Mach-O names carry a leading underscore.
device_calls() { # $1 = source, $2 = symbol, $3... = extra flags
    local src=$1 symbol=$2
    shift 2
    "$cc" -std=c11 -O2 -DCH_RAND_EXTERN -I. "$@" -c "$src" -o "$work/device.o" || exit 1
    nm -u "$work/device.o" | grep -qE "(^|[[:space:]_])$symbol\$"
}

for symbol in chacha20_vector_xor chacha20_avx2_xor; do
    if device_calls chacha20.c "$symbol"; then
        echo "chacha-builds: chacha20.c without -DCH_CPU_RUNTIME calls $symbol; a device object runs the portable loop alone" >&2
        exit 1
    fi
done
for symbol in poly1305_vector_blocks poly1305_vector_blocks_native; do
    if device_calls poly1305.c "$symbol" || device_calls poly1305.c "$symbol" -DCH_NATIVE_WIDEMUL; then
        echo "chacha-builds: poly1305.c without -DCH_CPU_RUNTIME calls $symbol; a device object runs the portable loop alone" >&2
        exit 1
    fi
done

# A host object's source, asked of the pinned clang for x86-64 and arm64
# targets whatever the host, as the header checks above are.
cross_object() { # $1 = target, $2 = source; writes $work/cross.o and $work/cross.s
    "$clang_rv" -target "$1" -ffreestanding -nostdlibinc -Itools/freestanding -std=c11 -O2 -I. \
        -DCH_CPU_RUNTIME -c "$2" -o "$work/cross.o" || exit 1
    "$clang_rv" -target "$1" -ffreestanding -nostdlibinc -Itools/freestanding -std=c11 -O2 -I. \
        -DCH_CPU_RUNTIME -S "$2" -o "$work/cross.s" || exit 1
}

# Whether the body of one function in $work/cross.s names a symbol: the
# lines from the function's label to its .size directive, which clang
# writes for these ELF targets. It fails the script when the function has
# no body there, so a renamed function cannot pass by being absent.
body_names() { # $1 = function, $2 = symbol
    awk -v f="$1" -v s="$2" '
        $0 ~ "^" f ":" { inside = 1; seen = 1; next }
        inside && $0 ~ "^[[:space:]]*\\.size[[:space:]]+" f "," { inside = 0 }
        inside && index($0, s) { found = 1 }
        END { if (!seen) exit 2; exit !found }' "$work/cross.s"
    case $? in
    0) return 0 ;;
    1) return 1 ;;
    *)
        echo "chacha-builds: chacha20.c for a host object defines no $1" >&2
        exit 1
        ;;
    esac
}

x86=x86_64-unknown-linux-gnu
arm64=aarch64-none-elf
for target in "$x86" "$arm64"; do
    cross_object "$target" chacha20.c
    if ! body_names chacha20_xor chacha20_vector_xor; then
        echo "chacha-builds: chacha20_xor for a host object on $target does not call chacha20_vector_xor" >&2
        exit 1
    fi
    for kernel in chacha20_avx2_xor chacha20_avx512_xor; do
        if body_names chacha20_xor "$kernel"; then
            echo "chacha-builds: chacha20_xor for a host object on $target calls $kernel; it takes no description of the CPU" >&2
            exit 1
        fi
    done
    if ! body_names chacha20_xor_cpu chacha20_vector_xor; then
        echo "chacha-builds: chacha20_xor_cpu on $target does not call chacha20_vector_xor; a session without CH_CPU_AVX2 runs it" >&2
        exit 1
    fi
done
cross_object "$x86" chacha20.c
if ! body_names chacha20_xor_cpu chacha20_avx2_xor; then
    echo "chacha-builds: chacha20_xor_cpu for x86-64 does not call the AVX2 kernel; a session with CH_CPU_AVX2 runs it" >&2
    exit 1
fi
if ! body_names chacha20_xor_cpu chacha20_avx512_xor; then
    echo "chacha-builds: chacha20_xor_cpu for x86-64 does not call the AVX-512 kernel; a session with CH_CPU_AVX512_IFMA runs it" >&2
    exit 1
fi
cross_object "$arm64" chacha20.c
for kernel in chacha20_avx2_xor chacha20_avx512_xor; do
    if body_names chacha20_xor_cpu "$kernel"; then
        echo "chacha-builds: chacha20_xor_cpu for arm64 calls $kernel, which has a body on x86-64 alone" >&2
        exit 1
    fi
done

# The AVX2 kernel's instructions.
cross_object "$x86" chacha20_avx2.c
if ! nm "$work/cross.o" | grep -qE '[[:space:]]T[[:space:]]_?chacha20_avx2_xor$' ||
    ! grep -q '%ymm' "$work/cross.s"; then
    echo "chacha-builds: chacha20_avx2.c for x86-64 must define chacha20_avx2_xor on 256-bit registers" >&2
    exit 1
fi
for src in chacha20.c chacha20_vector.c; do
    cross_object "$x86" "$src"
    if grep -qE '%[yz]mm' "$work/cross.s"; then
        echo "chacha-builds: $src for x86-64 holds a 256-bit or 512-bit instruction; only the kernels' files may" >&2
        exit 1
    fi
done
cross_object "$arm64" chacha20_avx2.c
if nm "$work/cross.o" | grep -q chacha20_avx2_xor; then
    echo "chacha-builds: chacha20_avx2.c for arm64 defines chacha20_avx2_xor; it has a body on x86-64 alone" >&2
    exit 1
fi

# The AVX-512 kernel's instructions, and the wipe of the registers it ran
# the key through, which it calls before it returns.
cross_object "$x86" chacha20_avx512.c
if ! nm "$work/cross.o" | grep -qE '[[:space:]]T[[:space:]]_?chacha20_avx512_xor$' ||
    ! grep -q '%zmm' "$work/cross.s"; then
    echo "chacha-builds: chacha20_avx512.c for x86-64 must define chacha20_avx512_xor on 512-bit registers" >&2
    exit 1
fi
if ! body_names chacha20_avx512_xor avx512_wipe_registers; then
    echo "chacha-builds: chacha20_avx512_xor for x86-64 does not call avx512_wipe_registers, so the key stays in the vector registers" >&2
    exit 1
fi
cross_object "$arm64" chacha20_avx512.c
if nm "$work/cross.o" | grep -q chacha20_avx512_xor; then
    echo "chacha-builds: chacha20_avx512.c for arm64 defines chacha20_avx512_xor; it has a body on x86-64 alone" >&2
    exit 1
fi

# The AVX2 Poly1305's instructions, and the one copy that calls it.
cross_object "$x86" poly1305_avx2_native.c
if ! nm "$work/cross.o" | grep -qE '[[:space:]]T[[:space:]]_?poly1305_avx2_blocks_native$' ||
    ! grep -q '%ymm' "$work/cross.s"; then
    echo "chacha-builds: poly1305_avx2_native.c for x86-64 must define poly1305_avx2_blocks_native on 256-bit registers" >&2
    exit 1
fi
cross_object "$x86" poly1305_native.c
if ! nm -u "$work/cross.o" | grep -qE '(^|[[:space:]_])poly1305_avx2_blocks_native$'; then
    echo "chacha-builds: poly1305_native.c for x86-64 does not call poly1305_avx2_blocks_native; a session with CH_CPU_AVX2 and the multiply bit runs it" >&2
    exit 1
fi
for src in poly1305_native.c poly1305_vector_native.c; do
    cross_object "$x86" "$src"
    if grep -q '%ymm' "$work/cross.s"; then
        echo "chacha-builds: $src for x86-64 holds a 256-bit instruction; only poly1305_avx2_native.c may" >&2
        exit 1
    fi
done
cross_object "$arm64" poly1305_avx2_native.c
if nm "$work/cross.o" | grep -q poly1305_avx2; then
    echo "chacha-builds: poly1305_avx2_native.c for arm64 defines the AVX2 Poly1305; it has a body on x86-64 alone" >&2
    exit 1
fi
for target in "$x86" "$arm64"; do
    for build in "poly1305.c" "poly1305_native.c -DCH_CT_WIDEMUL"; do
        # shellcheck disable=SC2086
        "$clang_rv" -target "$target" -ffreestanding -nostdlibinc -Itools/freestanding -std=c11 -O2 \
            -I. -DCH_CPU_RUNTIME -c $build -o "$work/cross.o" || exit 1
        if nm "$work/cross.o" | grep -q poly1305_avx2; then
            echo "chacha-builds: $build for $target defines or calls an AVX2 Poly1305 entry; only the native copy on x86-64 may" >&2
            exit 1
        fi
    done
done
cross_object "$arm64" poly1305_native.c
if nm "$work/cross.o" | grep -q poly1305_avx2; then
    echo "chacha-builds: poly1305_native.c for arm64 defines or calls an AVX2 Poly1305 entry; the kernel has a body on x86-64 alone" >&2
    exit 1
fi

# The wipe of the AVX-512 registers: one VPXORD for each of xmm0 to xmm31,
# which zeros the whole 512-bit register, and one KXORW for each of k1 to
# k7, in the one function the file defines for x86-64.
cross_object "$x86" avx512_wipe.c
if ! nm "$work/cross.o" | grep -qE '[[:space:]]T[[:space:]]_?avx512_wipe_registers$'; then
    echo "chacha-builds: avx512_wipe.c for x86-64 must define avx512_wipe_registers" >&2
    exit 1
fi
for n in $(seq 0 31); do
    if ! grep -qE "^[[:space:]]*vpxord[[:space:]]+%xmm$n, %xmm$n, %xmm$n$" "$work/cross.s"; then
        echo "chacha-builds: avx512_wipe_registers for x86-64 does not zero zmm$n" >&2
        exit 1
    fi
done
for n in $(seq 1 7); do
    if ! grep -qE "^[[:space:]]*kxorw[[:space:]]+%k$n, %k$n, %k$n$" "$work/cross.s"; then
        echo "chacha-builds: avx512_wipe_registers for x86-64 does not zero k$n" >&2
        exit 1
    fi
done
cross_object "$arm64" avx512_wipe.c
if nm "$work/cross.o" | grep -q avx512_wipe_registers; then
    echo "chacha-builds: avx512_wipe.c for arm64 defines avx512_wipe_registers; it has a body on x86-64 alone" >&2
    exit 1
fi

echo "chacha-builds: chacha20_vector.h admits NEON or SSE2 on a little-endian target alone, a device object calls no vector path, a host object's chacha20_xor calls the 128-bit path and no kernel, chacha20_xor_cpu calls the 128-bit path and on x86-64 both kernels, the kernels' 256-bit and 512-bit instructions stay in chacha20_avx2.c and chacha20_avx512.c, which calls avx512_wipe_registers, the AVX2 Poly1305's stay in poly1305_avx2_native.c, which only poly1305.c's native copy on x86-64 calls, and avx512_wipe_registers zeros zmm0 to zmm31 and k1 to k7 on x86-64 alone"
