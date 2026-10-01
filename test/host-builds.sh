#!/usr/bin/env bash
# The host test, checked in each of its three places against real
# compilers (docs/decisions.md 89). A target is a host target when its
# compiler targets arm64 or x86-64, NEON or SSE2 on a little-endian core,
# and has unsigned __int128.
#
#   - cpu_cfg.h compiles -DCH_CPU_RUNTIME on this host's cc, and stops it
#     for each target in refused below. Each of the first five fails one
#     probe and passes the others, so each of the header's refusals is
#     checked alone; two of them borrow a macro with -D or -U to get
#     there. The pinned clang cross-compiles for each with no toolchain
#     beside it, the way test/x25519-builds.sh compiles for the Cortex-M3.
#   - the Makefile's HOST_TARGET gives a TRUST=webpki object
#     -DCH_CPU_RUNTIME under this host's cc, and none under a compiler for
#     each of those targets, so each of its probes is checked alone too.
#   - build.zig gives the define to the same targets: this host, and
#     arm64 and x86-64 Linux, and to none of a Cortex-M3 and a big-endian
#     arm64 core.
#
# `make check` runs it (check-host-builds). It is the catch target of the
# violations that break one of the three: test/violations.py runs a script
# by path and reads its exit status, and a make target is not a path.
cd "$(dirname "$0")/.." || exit 1
unset MAKEFLAGS MFLAGS MAKELEVEL
cc=${CC:-cc}
zig=${ZIG:-zig}
out=bin/host-builds
mkdir -p "$out"

fail() {
    echo "host-builds: $*" >&2
    exit 1
}

clang_rv=$(make -s --no-print-directory print-clang-rv)
[ -n "$clang_rv" ] || fail "no clang to cross-compile with; see the LLVM_MAJOR pin in tools/toolchain.env"

# One translation unit that reads cpu_cfg.h and nothing else, so what passes
# or fails is the header's rule and not a later compile error.
tu=$out/cpu_cfg.c
echo '#include "cpu_cfg.h"' > "$tu"

# The targets that fail the host test, as clang's arguments: a 64-bit
# little-endian core with SSE2's macro and unsigned __int128 that is
# neither architecture; an arm64 core without NEON; an x86-64 core without
# SSE2; a big-endian arm64 core; an x86-64 core without unsigned __int128;
# and the Cortex-M3, a device, which fails three probes.
refused=(
    "riscv64-none-elf -D__SSE2__"
    "aarch64-none-elf -march=armv8-a+nosimd"
    "x86_64-none-elf -mno-sse2"
    "aarch64_be-none-elf"
    "x86_64-none-elf -U__SIZEOF_INT128__"
    "thumbv7m-none-eabi -mcpu=cortex-m3"
)

if ! "$cc" -std=c11 -I. -fsyntax-only -DCH_CPU_RUNTIME "$tu"; then
    fail "-DCH_CPU_RUNTIME must compile on $cc, a host target"
fi
for target in "${refused[@]}"; do
    read -r -a words <<< "$target"
    if ! "$clang_rv" -target "${words[@]}" -std=c11 -I. -fsyntax-only "$tu"; then
        fail "cpu_cfg.h must compile without -DCH_CPU_RUNTIME for $target"
    fi
    if "$clang_rv" -target "${words[@]}" -std=c11 -I. -fsyntax-only -DCH_CPU_RUNTIME "$tu" 2>/dev/null; then
        fail "-DCH_CPU_RUNTIME compiled for $target; cpu_cfg.h must refuse a target that fails the host test"
    fi
done

# The Makefile's defines for a TRUST=webpki object under a compiler.
make_defs() {
    make -s --no-print-directory print-lib-def RAND=extern TRUST=webpki ROLE=client "CC=$1"
}
case " $(make_defs "$cc") " in
*" -DCH_CPU_RUNTIME "*) ;;
*) fail "the Makefile gives a TRUST=webpki object no -DCH_CPU_RUNTIME under $cc, a host target" ;;
esac
for target in "${refused[@]}"; do
    case " $(make_defs "$clang_rv -target $target") " in
    *" -DCH_CPU_RUNTIME "*) fail "the Makefile gives a TRUST=webpki object -DCH_CPU_RUNTIME under a compiler for $target" ;;
    esac
done

# build.zig's defines for a TRUST=webpki object for a Zig target, or for
# this host with none.
zig_defs() {
    local name=$1
    shift
    "$zig" build lib-lists --summary none --prefix "$out/$name" --cache-dir bin/zig/cache \
        -DRAND=extern -DTRUST=webpki "$@" > "$out/$name.log" 2>&1 || {
        cat "$out/$name.log" >&2
        fail "zig build lib-lists $* failed"
    }
    tr '\n' ' ' < "$out/$name/lib-def.txt"
}
for target in native aarch64-linux-gnu x86_64-linux-gnu; do
    options=()
    [ "$target" = native ] || options=("-Dtarget=$target")
    case " $(zig_defs "$target" "${options[@]}") " in
    *" -DCH_CPU_RUNTIME "*) ;;
    *) fail "build.zig gives a TRUST=webpki object no -DCH_CPU_RUNTIME for $target, a host target" ;;
    esac
done
for target in thumb-freestanding-eabi aarch64_be-linux-gnu; do
    case " $(zig_defs "$target" "-Dtarget=$target") " in
    *" -DCH_CPU_RUNTIME "*) fail "build.zig gives a TRUST=webpki object -DCH_CPU_RUNTIME for $target" ;;
    esac
done

echo "host-builds: cpu_cfg.h, the Makefile and build.zig each give -DCH_CPU_RUNTIME to a host target alone"
