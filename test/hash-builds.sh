#!/usr/bin/env bash
# Which object holds a hash on the CPU's instructions, and which of its
# files holds the instructions (docs/decisions.md 93). `make check` runs
# it, and it is the catch target of the violations that break one of the
# rules below.
#
#   - a device object's sources call no entry on the instructions:
#     sha256.c, sha512.c, hkdf.c and keysched.c, compiled without
#     -DCH_CPU_RUNTIME, name no symbol that ends in _hw, and sha256_hw.c,
#     sha512_hw.c and sha512_avx2.c compiled that way define nothing;
#   - hash_hw.h refuses a build without -DCH_CPU_RUNTIME, so no device
#     object compiles a copy on the instructions;
#   - for x86-64 and for arm64, with no instruction flag, sha256_hw.c must
#     compile, define sha256_update_hw, sha256_final_hw and sha256_of_hw,
#     and hold SHA-256 instructions, which its target attribute turns on
#     for its own functions alone. A file without the attribute does not
#     compile here;
#   - for arm64, with no instruction flag, sha512_hw.c must compile, define
#     its five entries and hold SHA-512 instructions. For x86-64, which
#     has none, it must define the same five, call
#     sha512_avx2_compress_blocks and not sha512_compress_blocks, and hold
#     no instruction on a 256-bit register: it is sha512.c's first arm
#     compiled once more over the kernel (docs/decisions.md 128), and the
#     copy must not compress on the plain C the other arm runs;
#   - for x86-64, with no instruction flag, sha512_avx2.c must compile,
#     define sha512_avx2_compress_blocks, hold instructions on 256-bit
#     registers, which its target attribute turns on for its own
#     functions alone, and hold no BMI1 or BMI2 instruction, which
#     CH_CPU_AVX2 does not state. For arm64 it must define nothing;
#   - for arm64, sha512_hw.c must hold none of FEAT_SHA3's instructions.
#     The compilers turn them on with FEAT_SHA512's under one target
#     attribute and write them for plain C, and the SHA-512 bit states
#     nothing about them;
#   - for both targets, a host object's sha256.c, sha512.c,
#     sha512_compress_blocks.c, sha512_avx2.c, hkdf.c, keysched.c,
#     hkdf_hw.c and keysched_hw.c, and sha512_compress.c under the same
#     define, hold no SHA-256 and no SHA-512 instruction, sha256_hw.c no
#     SHA-512 one and sha512_hw.c no SHA-256 one;
#   - for both targets, the copies call the hash on the instructions and
#     the files under their own names the portable one: hkdf_hw.c names
#     sha256_update_hw, sha256_final_hw and sha256_of_hw and none of
#     sha256.c's three, hkdf.c the reverse, and keysched_hw.c names
#     hkdf_hw.c's calls where keysched.c names hkdf.c's. The same holds
#     for the three SHA-384 calls the two files make: the copies name
#     sha512_hw.c's, which run the SHA-512 instructions on arm64 and the
#     AVX2 kernel on x86-64.
#
# The same for Keccak (docs/decisions.md 99), which has a body on the
# instructions where clang compiles an arm64 host object:
#
#   - a device object's sha3.c, mlkem.c and mlkem_poly.c name no symbol
#     that ends in _hw, sha3_hw.c, mlkem_hw.c and mlkem_poly_hw.c compiled
#     that way define nothing, and keccak_hw.h refuses such a build;
#   - for arm64, sha3_hw.c must define its six entries and hold FEAT_SHA3's
#     instructions and no SHA-256 or SHA-512 one, and for x86-64 ML-KEM's
#     two copies must define nothing;
#   - for x86-64, sha3_hw.c must define its six entries and hold ANDN and
#     RORX and no NOT, which sha3_andn.h's chi on BMI1 writes, and sha3.c
#     must hold no BMI1 or BMI2 instruction, because a session without
#     CH_CPU_BMI1 and CH_CPU_BMI2_ADX runs it (docs/decisions.md 217);
#   - for both targets, sha3.c, mlkem.c, mlkem_poly.c, mlkem_poly_native.c
#     and ML-KEM's two copies hold none of FEAT_SHA3's instructions, so
#     sha3_hw.c holds every one an object runs;
#   - for arm64, ML-KEM's copies call Keccak on the instructions and the
#     files under their own names the portable one: mlkem_hw.c and
#     mlkem_poly_hw.c name the _hw entries of every SHA-3 and SHAKE call
#     they make and none of sha3.c's, mlkem.c and mlkem_poly.c the
#     reverse, and every mlk_ call mlkem_hw.c makes goes to the copy's
#     own, to a native copy (widemul.h), to the vector NTT, which hashes
#     nothing (mlkem_vector.h), or to mlk_sample_pair_neon, the matrix's
#     sampler on the two-way Keccak, which both copies call and which takes
#     the form of the permutation as an argument (mlkem_neon.h).
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

# The symbols a device object's source names, defined or not, with both
# hashes' arms of hkdf.c and keysched.c compiled. Mach-O names carry a
# leading underscore.
device_symbols() { # $1 = source
    "$cc" -std=c11 -O2 -DCH_RAND_EXTERN -DCH_HASH_SHA384 -Isrc -Iinclude/chapulin -Iinclude -I. -c "$1" -o "$work/device.o" || exit 1
    nm "$work/device.o"
}
for src in src/sha256.c src/sha512.c src/hkdf.c src/keysched.c src/sha256_hw.c src/sha512_hw.c src/sha512_avx2.c; do
    symbols=$(device_symbols "$src") || fail "$src does not compile without -DCH_CPU_RUNTIME"
    if grep -qE '_hw$' <<< "$symbols"; then
        fail "$src without -DCH_CPU_RUNTIME names an entry on the instructions; a device object holds the portable hash alone"
    fi
done
# A global definition is an uppercase type letter other than U. A Mach-O
# object holds one local symbol for its empty section, which is none of
# the file's.
for src in src/sha256_hw.c src/sha512_hw.c src/sha512_avx2.c; do
    if device_symbols "$src" | grep -qE '[[:space:]][A-TV-Z][[:space:]]'; then
        fail "$src without -DCH_CPU_RUNTIME defines a symbol; it has a body in a host object alone"
    fi
done
for src in src/hkdf_hw.c src/keysched_hw.c; do
    if "$cc" -std=c11 -DCH_RAND_EXTERN -Isrc -Iinclude/chapulin -Iinclude -I. -fsyntax-only "$src" 2> /dev/null; then
        fail "$src compiled without -DCH_CPU_RUNTIME; src/hash_hw.h must refuse a copy outside a host object"
    fi
done
for src in src/sha3.c src/mlkem.c src/mlkem_poly.c src/sha3_hw.c src/mlkem_hw.c src/mlkem_poly_hw.c; do
    symbols=$(device_symbols "$src") || fail "$src does not compile without -DCH_CPU_RUNTIME"
    if grep -qE '_hw$' <<< "$symbols"; then
        fail "$src without -DCH_CPU_RUNTIME names an entry on the instructions; a device object holds the portable Keccak alone"
    fi
done
for src in src/sha3_hw.c src/mlkem_hw.c src/mlkem_poly_hw.c; do
    if device_symbols "$src" | grep -qE '[[:space:]][A-TV-Z][[:space:]]'; then
        fail "$src without -DCH_CPU_RUNTIME defines a symbol; it has a body in a host object alone"
    fi
done
if printf '#include "src/keccak_hw.h"\n' | "$cc" -std=c11 -Isrc -Iinclude/chapulin -Iinclude -I. -x c -fsyntax-only - 2> /dev/null; then
    fail "src/keccak_hw.h compiled without -DCH_CPU_RUNTIME; it must refuse a copy outside a host object"
fi

# A host object's source, asked of the pinned clang for x86-64 and arm64
# targets whatever the host. It writes $work/cross.o and $work/cross.s.
# ML-KEM's files read cfg.h, which asks for an entropy pattern.
cross_object() { # $1 = target, $2 = source
    "$clang_rv" -target "$1" -ffreestanding -nostdlibinc -Itools/freestanding -std=c11 -O2 -Isrc -Iinclude/chapulin -Iinclude -I. \
        -DCH_CPU_RUNTIME -DCH_HASH_SHA384 -DCH_RAND_EXTERN -c "$2" -o "$work/cross.o" ||
        fail "$2 does not compile for a host object on $1 with no instruction flag"
    "$clang_rv" -target "$1" -ffreestanding -nostdlibinc -Itools/freestanding -std=c11 -O2 -Isrc -Iinclude/chapulin -Iinclude -I. \
        -DCH_CPU_RUNTIME -DCH_HASH_SHA384 -DCH_RAND_EXTERN -S "$2" -o "$work/cross.s" || exit 1
}

# Whether $work/cross.s holds a SHA-256 instruction: sha256h, sha256h2,
# sha256su0 and sha256su1 on arm64, and sha256rnds2, sha256msg1 and
# sha256msg2 on x86-64.
holds_sha256() {
    grep -qE '^[[:space:]]+sha256(h|h2|su0|su1|rnds2|msg1|msg2)[[:space:]]' "$work/cross.s"
}

# Whether it holds a SHA-512 instruction: sha512h, sha512h2, sha512su0 and
# sha512su1, which arm64 alone has among this tree's targets.
holds_sha512() {
    grep -qE '^[[:space:]]+sha512(h|h2|su0|su1)[[:space:]]' "$work/cross.s"
}

# Whether it holds one of FEAT_SHA3's instructions: eor3, rax1, xar and
# bcax.
holds_sha3() {
    grep -qE '^[[:space:]]+(eor3|rax1|xar|bcax)[[:space:]]' "$work/cross.s"
}

# Whether it holds an instruction that names a 256-bit register, which on
# x86-64 is an AVX or AVX2 instruction.
holds_256_bit() {
    grep -qE '^[[:space:]]+[a-z0-9]+[[:space:]].*%ymm[0-9]' "$work/cross.s"
}

# Whether it holds a BMI1 or BMI2 instruction: andn, bextr, blsi, blsmsk,
# blsr and tzcnt, and bzhi, mulx, pdep, pext, rorx, sarx, shlx and shrx.
holds_bmi() {
    grep -qE '^[[:space:]]+(andn|bextr|blsi|blsmsk|blsr|tzcnt|bzhi|mulx|pdep|pext|rorx|sarx|shlx|shrx)[lq]?[[:space:]]' \
        "$work/cross.s"
}

# Whether it holds ANDN, RORX or NOT, in AT&T syntax with or without a
# size suffix.
holds_andn() {
    grep -qE '^[[:space:]]+andn[lq]?[[:space:]]' "$work/cross.s"
}
holds_rorx() {
    grep -qE '^[[:space:]]+rorx[lq]?[[:space:]]' "$work/cross.s"
}
holds_not() {
    grep -qE '^[[:space:]]+not[bwlq]?[[:space:]]' "$work/cross.s"
}

# Whether $work/cross.o names a symbol, defined or not.
names() { # $1 = symbol
    nm "$work/cross.o" | grep -qE "[[:space:]]$1\$"
}

# Whether $work/cross.o defines a function.
defines() { # $1 = symbol
    nm "$work/cross.o" | grep -qE "[[:space:]]T[[:space:]]$1\$"
}

# Requires $work/cross.o to name each of the calls after the first two
# arguments and none of the same calls with the other ending.
calls() { # $1 = source and target, for the message; $2 = "_hw" or ""; the rest = the calls
    local what=$1 ending=$2 other=_hw symbol
    shift 2
    [ -z "$ending" ] || other=""
    for symbol in "$@"; do
        names "$symbol$ending" || fail "$what does not call $symbol$ending"
        names "$symbol$other" && fail "$what calls $symbol$other"
    done
    return 0
}

x86=x86_64-unknown-linux-gnu
arm64=aarch64-none-elf
sha256_calls=(sha256_update sha256_final sha256_of)
sha384_calls=(sha512_update sha384_final sha384_of)
sha512_entries=(sha512_update_hw sha512_final_hw sha384_final_hw sha512_of_hw sha384_of_hw)
for target in "$x86" "$arm64"; do
    cross_object "$target" src/sha256_hw.c
    for symbol in sha256_update_hw sha256_final_hw sha256_of_hw; do
        defines "$symbol" || fail "src/sha256_hw.c for $target does not define $symbol"
    done
    holds_sha256 || fail "src/sha256_hw.c for $target holds no SHA-256 instruction"
    holds_sha512 && fail "src/sha256_hw.c for $target holds a SHA-512 instruction; only src/sha512_hw.c may"

    cross_object "$target" src/sha512_hw.c
    holds_sha256 && fail "src/sha512_hw.c for $target holds a SHA-256 instruction; only src/sha256_hw.c may"
    if [ "$target" = "$arm64" ]; then
        for symbol in "${sha512_entries[@]}"; do
            defines "$symbol" || fail "src/sha512_hw.c for $target does not define $symbol"
        done
        holds_sha512 || fail "src/sha512_hw.c for $target holds no SHA-512 instruction"
        holds_sha3 &&
            fail "src/sha512_hw.c for $target holds one of FEAT_SHA3's instructions, which CH_CPU_CONSTANT_TIME_SHA512 does not name"
    else
        for symbol in "${sha512_entries[@]}"; do
            defines "$symbol" || fail "src/sha512_hw.c for $target does not define $symbol"
        done
        names sha512_avx2_compress_blocks ||
            fail "src/sha512_hw.c for $target does not call sha512_avx2_compress_blocks; its calls are the ones a session runs under CH_CPU_AVX2"
        names sha512_compress_blocks &&
            fail "src/sha512_hw.c for $target calls sha512_compress_blocks, the plain C the calls without _hw run"
        holds_sha512 && fail "src/sha512_hw.c for $target holds a SHA-512 instruction"
        holds_256_bit &&
            fail "src/sha512_hw.c for $target holds an instruction on a 256-bit register; only src/sha512_avx2.c may"
    fi

    # The kernel sha512_hw.c's x86-64 arm compresses on.
    cross_object "$target" src/sha512_avx2.c
    if [ "$target" = "$x86" ]; then
        defines sha512_avx2_compress_blocks ||
            fail "src/sha512_avx2.c for $target does not define sha512_avx2_compress_blocks"
        holds_256_bit || fail "src/sha512_avx2.c for $target holds no instruction on a 256-bit register"
        holds_bmi &&
            fail "src/sha512_avx2.c for $target holds a BMI1 or BMI2 instruction, which CH_CPU_AVX2 does not state"
    else
        nm "$work/cross.o" | grep -qE '[[:space:]][A-TV-Z][[:space:]]' &&
            fail "src/sha512_avx2.c for $target defines a symbol; the kernel has a body on x86-64 alone"
    fi

    for src in src/sha256.c src/sha512.c src/sha512_compress.c src/sha512_compress_blocks.c src/sha512_avx2.c src/hkdf.c src/keysched.c \
        src/hkdf_hw.c src/keysched_hw.c; do
        cross_object "$target" "$src"
        if holds_sha256 || holds_sha512; then
            fail "$src for $target holds a hash instruction; only src/sha256_hw.c and src/sha512_hw.c may"
        fi
    done

    # hkdf.c under its own names, and its copy, whose SHA-384 calls are
    # sha512_hw.c's on both targets.
    cross_object "$target" src/hkdf.c
    calls "src/hkdf.c for $target" "" "${sha256_calls[@]}" "${sha384_calls[@]}"
    cross_object "$target" src/hkdf_hw.c
    calls "src/hkdf_hw.c for $target" _hw "${sha256_calls[@]}" "${sha384_calls[@]}"
    defines hkdf_extract_hw || fail "src/hkdf_hw.c for $target does not define hkdf_extract_hw"
    defines hkdf_extract && fail "src/hkdf_hw.c for $target defines hkdf_extract, which src/hkdf.c defines"

    cross_object "$target" src/keysched.c
    names hkdf_extract || fail "src/keysched.c for $target does not call hkdf_extract"
    names hkdf_extract_hw && fail "src/keysched.c for $target calls hkdf_extract_hw; under its own names it runs src/hkdf.c"
    cross_object "$target" src/keysched_hw.c
    names hkdf_extract_hw || fail "src/keysched_hw.c for $target does not call hkdf_extract_hw"
    names hkdf_extract && fail "src/keysched_hw.c for $target calls hkdf_extract; the copy runs src/hkdf_hw.c"
    defines ks_handshake_hw || fail "src/keysched_hw.c for $target does not define ks_handshake_hw"
done

# Keccak. sha3_hw.c's six entries, and the calls each of ML-KEM's files
# makes into sha3.h.
sha3_entries=(sha3_256_hw sha3_512_hw shake128_init_hw shake256_init_hw shake_absorb_hw shake_squeeze_hw)
mlkem_keccak_calls=(sha3_256 sha3_512 shake256_init shake_absorb shake_squeeze)
mlkem_poly_keccak_calls=(shake128_init shake256_init shake_absorb shake_squeeze)
for target in "$x86" "$arm64"; do
    for src in src/sha3.c src/mlkem.c src/mlkem_poly.c src/mlkem_poly_native.c src/mlkem_hw.c src/mlkem_poly_hw.c; do
        cross_object "$target" "$src"
        holds_sha3 && fail "$src for $target holds one of FEAT_SHA3's instructions; only src/sha3_hw.c may"
    done
    cross_object "$target" src/mlkem.c
    calls "src/mlkem.c for $target" "" "${mlkem_keccak_calls[@]}"
    cross_object "$target" src/mlkem_poly.c
    calls "src/mlkem_poly.c for $target" "" "${mlkem_poly_keccak_calls[@]}"
    if [ "$target" = "$x86" ]; then
        for src in src/mlkem_hw.c src/mlkem_poly_hw.c; do
            cross_object "$target" "$src"
            nm "$work/cross.o" | grep -qE '[[:space:]][A-TV-Z][[:space:]]' &&
                fail "$src for $target defines a symbol; x86-64 has no SHA-3 instructions to run it on"
        done
        cross_object "$target" src/sha3.c
        holds_bmi && fail "src/sha3.c for $target holds a BMI1 or BMI2 instruction; a session without CH_CPU_BMI1 and CH_CPU_BMI2_ADX runs it"
        cross_object "$target" src/sha3_hw.c
        for symbol in "${sha3_entries[@]}"; do
            defines "$symbol" || fail "src/sha3_hw.c for $target does not define $symbol"
        done
        holds_andn || fail "src/sha3_hw.c for $target holds no ANDN; its chi runs on BMI1 (docs/decisions.md 217)"
        holds_rorx || fail "src/sha3_hw.c for $target holds no RORX; its rotations run on BMI2 (docs/decisions.md 217)"
        holds_not && fail "src/sha3_hw.c for $target holds a NOT; its round is sha3_andn.h's, whose AND-NOT is ANDN"
        continue
    fi
    cross_object "$target" src/sha3_hw.c
    for symbol in "${sha3_entries[@]}"; do
        defines "$symbol" || fail "src/sha3_hw.c for $target does not define $symbol"
    done
    holds_sha3 || fail "src/sha3_hw.c for $target holds none of FEAT_SHA3's instructions"
    if holds_sha256 || holds_sha512; then
        fail "src/sha3_hw.c for $target holds a SHA-256 or SHA-512 instruction, which CH_CPU_CONSTANT_TIME_SHA3 does not name"
    fi
    cross_object "$target" src/mlkem_hw.c
    calls "src/mlkem_hw.c for $target" _hw "${mlkem_keccak_calls[@]}"
    defines mlkem_decaps_hw || fail "src/mlkem_hw.c for $target does not define mlkem_decaps_hw"
    defines mlkem_decaps && fail "src/mlkem_hw.c for $target defines mlkem_decaps, which src/mlkem.c defines"
    # mlkem_vector.c's two transforms, its base multiplication and its sum
    # hash nothing, and both copies of mlkem.c call them (docs/decisions.md
    # 101 and 214). Both copies call the sampler on the two-way Keccak too,
    # the copy with the SHA-3 form (docs/decisions.md 198).
    stray=$(nm "$work/cross.o" | awk '$1 == "U" { print $2 }' | grep -E '^_?mlk_' | grep -vE '_(hw|native)$' |
        grep -vxE '_?mlk_vector_(ntt|invntt|basemul|add)|_?mlk_sample_pair_neon' || true)
    [ -z "$stray" ] || fail "src/mlkem_hw.c for $target calls $stray, which the copy of src/mlkem_poly.c does not define"
    cross_object "$target" src/mlkem_poly_hw.c
    calls "src/mlkem_poly_hw.c for $target" _hw "${mlkem_poly_keccak_calls[@]}"
done

echo "hash-builds: a device object holds the portable hashes alone, src/hash_hw.h refuses a copy outside a host object, src/sha256_hw.c compiles for x86-64 and arm64 with no instruction flag and holds the SHA-256 instructions, src/sha512_hw.c does the same for arm64 with the SHA-512 instructions and none of FEAT_SHA3's and for x86-64 defines the same five calls over src/sha512_avx2.c's kernel, which holds 256-bit instructions and no BMI1 or BMI2 one, no other hash source holds a hash instruction, and each copy calls src/sha256_hw.c's and src/sha512_hw.c's entries; and the same holds for Keccak on FEAT_SHA3 in src/sha3_hw.c on arm64 and ML-KEM's two copies over it, and on x86-64 src/sha3_hw.c holds ANDN and RORX and no NOT, and src/sha3.c no BMI1 or BMI2 instruction"
