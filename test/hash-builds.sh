#!/usr/bin/env bash
# Which object holds a hash on the CPU's instructions, and which of its
# files holds the instructions (docs/decisions.md 93). `make check` runs
# it, and it is the catch target of the violations that break one of the
# rules below.
#
#   - a device object's sources call no entry on the instructions:
#     sha256.c, hkdf.c and keysched.c, compiled without -DCH_CPU_RUNTIME,
#     name no symbol that ends in _hw, and sha256_hw.c compiled that way
#     defines nothing;
#   - hash_hw.h refuses a build without -DCH_CPU_RUNTIME, so no device
#     object compiles a copy on the instructions;
#   - for x86-64 and for arm64, with no instruction flag, sha256_hw.c must
#     compile, define sha256_update_hw, sha256_final_hw and sha256_of_hw,
#     and hold SHA-256 instructions, which its target attribute turns on
#     for its own functions alone. A file without the attribute does not
#     compile here;
#   - for both targets, a host object's sha256.c, hkdf.c, keysched.c,
#     hkdf_hw.c and keysched_hw.c hold no SHA-256 instruction;
#   - for both targets, the copies call the hash on the instructions and
#     the files under their own names the portable one: hkdf_hw.c names
#     sha256_update_hw, sha256_final_hw and sha256_of_hw and none of
#     sha256.c's three, hkdf.c the reverse, and keysched_hw.c names
#     hkdf_hw.c's calls where keysched.c names hkdf.c's.
#
# test/aes-runtime-disasm.sh reads the same about the instructions from a
# whole packaged object on the host's own compiler. This script asks the
# pinned clang for both architectures, so it gives one verdict on every
# machine, which is what a violation's catch needs.
cd "$(dirname "$0")/.." || exit 1

work=$(mktemp -d -t chapulin_hash_XXXXXX)
trap 'rm -rf "$work"' EXIT
cc=${CC:-cc}

fail() {
    echo "hash-builds: $*" >&2
    exit 1
}

clang_rv=$(make -s --no-print-directory print-clang-rv)
[ -n "$clang_rv" ] || fail "no clang to cross-compile with; see the LLVM_MAJOR pin in tools/toolchain.env"

# The symbols a device object's source names, defined or not. Mach-O names
# carry a leading underscore.
device_symbols() { # $1 = source
    "$cc" -std=c11 -O2 -DCH_RAND_EXTERN -I. -c "$1" -o "$work/device.o" || exit 1
    nm "$work/device.o"
}
for src in sha256.c hkdf.c keysched.c sha256_hw.c; do
    symbols=$(device_symbols "$src") || fail "$src does not compile without -DCH_CPU_RUNTIME"
    if grep -qE '_hw$' <<< "$symbols"; then
        fail "$src without -DCH_CPU_RUNTIME names an entry on the instructions; a device object holds the portable hash alone"
    fi
done
# A global definition is an uppercase type letter other than U. A Mach-O
# object holds one local symbol for its empty section, which is none of
# the file's.
if device_symbols sha256_hw.c | grep -qE '[[:space:]][A-TV-Z][[:space:]]'; then
    fail "sha256_hw.c without -DCH_CPU_RUNTIME defines a symbol; it has a body in a host object alone"
fi
for src in hkdf_hw.c keysched_hw.c; do
    if "$cc" -std=c11 -DCH_RAND_EXTERN -I. -fsyntax-only "$src" 2> /dev/null; then
        fail "$src compiled without -DCH_CPU_RUNTIME; hash_hw.h must refuse a copy outside a host object"
    fi
done

# A host object's source, asked of the pinned clang for x86-64 and arm64
# targets whatever the host. It writes $work/cross.o and $work/cross.s.
cross_object() { # $1 = target, $2 = source
    "$clang_rv" -target "$1" -ffreestanding -nostdlibinc -Itools/freestanding -std=c11 -O2 -I. \
        -DCH_CPU_RUNTIME -DCH_HASH_SHA384 -c "$2" -o "$work/cross.o" ||
        fail "$2 does not compile for a host object on $1 with no instruction flag"
    "$clang_rv" -target "$1" -ffreestanding -nostdlibinc -Itools/freestanding -std=c11 -O2 -I. \
        -DCH_CPU_RUNTIME -DCH_HASH_SHA384 -S "$2" -o "$work/cross.s" || exit 1
}

# Whether $work/cross.s holds a SHA-256 instruction: sha256h, sha256h2,
# sha256su0 and sha256su1 on arm64, and sha256rnds2, sha256msg1 and
# sha256msg2 on x86-64.
holds_sha256() {
    grep -qE '^[[:space:]]+sha256(h|h2|su0|su1|rnds2|msg1|msg2)[[:space:]]' "$work/cross.s"
}

# Whether $work/cross.o names a symbol, defined or not.
names() { # $1 = symbol
    nm "$work/cross.o" | grep -qE "[[:space:]]$1\$"
}

# Whether $work/cross.o defines a function.
defines() { # $1 = symbol
    nm "$work/cross.o" | grep -qE "[[:space:]]T[[:space:]]$1\$"
}

x86=x86_64-unknown-linux-gnu
arm64=aarch64-none-elf
for target in "$x86" "$arm64"; do
    cross_object "$target" sha256_hw.c
    for symbol in sha256_update_hw sha256_final_hw sha256_of_hw; do
        defines "$symbol" || fail "sha256_hw.c for $target does not define $symbol"
    done
    holds_sha256 || fail "sha256_hw.c for $target holds no SHA-256 instruction"

    for src in sha256.c hkdf.c keysched.c hkdf_hw.c keysched_hw.c; do
        cross_object "$target" "$src"
        if holds_sha256; then
            fail "$src for $target holds a SHA-256 instruction; only sha256_hw.c may"
        fi
    done

    cross_object "$target" hkdf.c
    for symbol in sha256_update sha256_final sha256_of; do
        names "$symbol" || fail "hkdf.c for $target does not call $symbol"
        names "${symbol}_hw" && fail "hkdf.c for $target calls ${symbol}_hw; under its own names it hashes on sha256.c"
    done
    cross_object "$target" hkdf_hw.c
    for symbol in sha256_update sha256_final sha256_of; do
        names "${symbol}_hw" || fail "hkdf_hw.c for $target does not call ${symbol}_hw"
        names "$symbol" && fail "hkdf_hw.c for $target calls $symbol; the copy hashes on the instructions"
    done
    defines hkdf_extract_hw || fail "hkdf_hw.c for $target does not define hkdf_extract_hw"
    defines hkdf_extract && fail "hkdf_hw.c for $target defines hkdf_extract, which hkdf.c defines"

    cross_object "$target" keysched.c
    names hkdf_extract || fail "keysched.c for $target does not call hkdf_extract"
    names hkdf_extract_hw && fail "keysched.c for $target calls hkdf_extract_hw; under its own names it runs hkdf.c"
    cross_object "$target" keysched_hw.c
    names hkdf_extract_hw || fail "keysched_hw.c for $target does not call hkdf_extract_hw"
    names hkdf_extract && fail "keysched_hw.c for $target calls hkdf_extract; the copy runs hkdf_hw.c"
    defines ks_handshake_hw || fail "keysched_hw.c for $target does not define ks_handshake_hw"
done

echo "hash-builds: a device object holds the portable hash alone, hash_hw.h refuses a copy outside a host object, sha256_hw.c compiles for x86-64 and arm64 with no instruction flag and holds the SHA-256 instructions, no other hash source holds one, and each copy calls the hash on the instructions"
