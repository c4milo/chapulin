#!/usr/bin/env bash
# The calls that make a host object run the vector NTT, checked the way
# test/chacha-builds.sh checks the vector ChaCha20's. `make check` runs
# it, and it is the catch target of the violations that drop a call
# (docs/decisions.md 101):
#
#   - a device object's mlkem.c, compiled without -DCH_CPU_RUNTIME, must
#     call mlkem_poly.c's two transforms, its base multiplication, its
#     sum and its noise sampler and no vector entry;
#   - a host object's mlkem.c, for x86-64 and for arm64, must call
#     mlk_vector_ntt, mlk_vector_invntt, mlk_vector_basemul,
#     mlk_vector_add (docs/decisions.md 214) and mlk_vector_noise
#     (docs/decisions.md 225) and none of mlkem_poly.c's five, so every
#     session runs the vector path; and so
#     must mlkem_hw.c, its copy over the SHA-3 instructions, for arm64, the
#     one target where that copy has a body, and mlkem_avx2.c, its copy for
#     the four-way Keccak, for x86-64, the one target where that one has a
#     body;
#   - mlkem_avx2.c for x86-64 must call keccak_avx2.c's three entries and
#     not mlk_sample_ntt, so its rows run on the four-way Keccak, and it
#     must call mlk_sample_groups_avx2, its rejection step on AVX2
#     (docs/decisions.md 225), and keccak_avx2.c must define the three;
#     for arm64 both files must
#     define no symbol; and no other source in src/ may include
#     keccak_avx2.h or call its entries (docs/decisions.md 107);
#   - mldsa_avx2.c for x86-64, ML-DSA-87's four-way sampler of A, must
#     call keccak_avx2.c's three entries, and mldsa.c and
#     mldsa_sign_steps.c for x86-64 must call it; for arm64 it must
#     define no symbol, and it is the one other source that may reach the
#     four-way Keccak (docs/decisions.md 178);
#   - for arm64, mlkem.c and mlkem_hw.c must call mlk_sample_pair_neon,
#     mlkem_neon.c and mldsa_neon.c must call keccak_neon.c's entries, and
#     mldsa.c and mldsa_sign_steps.c must call mld_sample_ntt_neon; for
#     x86-64 the three files of the two-way Keccak must define no symbol;
#     and no other source in src/ may include keccak_neon.h or call its
#     entries (docs/decisions.md 198).
#
# The cross targets use the pinned clang, which make resolves, with no
# toolchain beside it, the way lint-wide-multiply compiles for them.
cd "$(dirname "$0")/.." || exit 1

work=$(mktemp -d -t chapulin_mlkem_XXXXXX)
trap 'rm -rf "$work"' EXIT
cc=${CC:-cc}

fail() {
    echo "mlkem-builds: $*" >&2
    exit 1
}

clang_rv=$(make -s --no-print-directory print-clang-rv)
[ -n "$clang_rv" ] || fail "no clang to cross-compile with; see the LLVM_MAJOR pin in tools/toolchain.env"

# The undefined symbols of one object, one name a line, with the leading
# underscore of a Mach-O name taken off.
undefined() { # $1 = object
    nm -u "$1" | awk '{ print $NF }' | sed 's/^_//'
}

# A device object's mlkem.c, on the host's own compiler.
"$cc" -std=c11 -O2 -DCH_RAND_EXTERN -Isrc -Iinclude/chapulin -Iinclude -I. -c src/mlkem.c -o "$work/device.o" ||
    fail "src/mlkem.c does not compile without -DCH_CPU_RUNTIME"
calls=$(undefined "$work/device.o")
for symbol in mlk_poly_ntt mlk_poly_invntt mlk_poly_basemul mlk_poly_add mlk_sample_cbd; do
    grep -qx "$symbol" <<< "$calls" ||
        fail "src/mlkem.c without -DCH_CPU_RUNTIME does not call $symbol; a device object runs src/mlkem_poly.c's loops"
done
for symbol in mlk_vector_ntt mlk_vector_invntt mlk_vector_basemul mlk_vector_add mlk_vector_noise; do
    grep -qx "$symbol" <<< "$calls" &&
        fail "src/mlkem.c without -DCH_CPU_RUNTIME calls $symbol; a device object holds no vector path"
done

# A host object's source, asked of the pinned clang for x86-64 and arm64
# targets whatever the host. It writes $work/cross.o.
cross_object() { # $1 = target, $2 = source
    "$clang_rv" -target "$1" -ffreestanding -nostdlibinc -Itools/freestanding -std=c11 -O2 -Isrc -Iinclude/chapulin -Iinclude -I. \
        -DCH_CPU_RUNTIME -DCH_RAND_EXTERN -c "$2" -o "$work/cross.o" ||
        fail "$2 does not compile for a host object on $1"
}

# Whether the object in $work/cross.o calls the five vector entries and
# none of the loops named by its arguments.
calls_vector_alone() { # $1 = what, $2 $3 $4 $5 $6 = the loops' names in that object
    calls=$(undefined "$work/cross.o")
    for symbol in mlk_vector_ntt mlk_vector_invntt mlk_vector_basemul mlk_vector_add mlk_vector_noise; do
        grep -qx "$symbol" <<< "$calls" ||
            fail "$1 does not call $symbol; every session of a host object runs the vector NTT"
    done
    for symbol in "$2" "$3" "$4" "$5" "$6"; do
        grep -qx "$symbol" <<< "$calls" &&
            fail "$1 calls $symbol; a host object runs the vector NTT in its place"
    done
    return 0
}

for target in x86_64-unknown-linux-gnu aarch64-none-elf; do
    cross_object "$target" src/mlkem.c
    calls_vector_alone "src/mlkem.c for $target" mlk_poly_ntt mlk_poly_invntt mlk_poly_basemul mlk_poly_add \
        mlk_sample_cbd
done
cross_object aarch64-none-elf src/mlkem_hw.c
calls_vector_alone "src/mlkem_hw.c for arm64" mlk_poly_ntt_hw mlk_poly_invntt_hw mlk_poly_basemul_hw mlk_poly_add_hw \
    mlk_sample_cbd_hw

# The copy for the four-way Keccak, and the Keccak it samples the matrix on.
keccak_avx2_entries=(keccak_avx2_shake128_start keccak_avx2_permute keccak_avx2_block)
cross_object x86_64-unknown-linux-gnu src/mlkem_avx2.c
calls_vector_alone "src/mlkem_avx2.c for x86-64" mlk_poly_ntt mlk_poly_invntt mlk_poly_basemul mlk_poly_add \
    mlk_sample_cbd
# The rows call the rejection step on AVX2, which the same object defines, so no undefined symbol
# names it. The pinned clang's assembly of the copy names the call, on any host: an objdump built
# for arm64 reads no x86-64 object.
"$clang_rv" -target x86_64-unknown-linux-gnu -ffreestanding -nostdlibinc -Itools/freestanding -std=c11 -O2 \
    -Isrc -Iinclude/chapulin -Iinclude -I. -DCH_CPU_RUNTIME -DCH_RAND_EXTERN -S src/mlkem_avx2.c \
    -o "$work/cross.s" || fail "src/mlkem_avx2.c does not compile to assembly for x86-64"
grep -qE '^[[:space:]]+callq?[[:space:]]+mlk_sample_groups_avx2' "$work/cross.s" ||
    fail "src/mlkem_avx2.c for x86-64 does not call mlk_sample_groups_avx2; its rows keep candidates on AVX2"
for symbol in "${keccak_avx2_entries[@]}"; do
    grep -qx "$symbol" <<< "$calls" ||
        fail "src/mlkem_avx2.c for x86-64 does not call $symbol; its rows run on the four-way Keccak"
done
grep -qx mlk_sample_ntt <<< "$calls" &&
    fail "src/mlkem_avx2.c for x86-64 calls mlk_sample_ntt; its rows run on the four-way Keccak"
cross_object x86_64-unknown-linux-gnu src/keccak_avx2.c
defined=$(nm "$work/cross.o" | awk '$2 == "T" { print $3 }' | sed 's/^_//')
for symbol in "${keccak_avx2_entries[@]}"; do
    grep -qx "$symbol" <<< "$defined" || fail "src/keccak_avx2.c for x86-64 does not define $symbol"
done
# ML-DSA-87's sampler of A on the four-way Keccak, and its two callers.
cross_object x86_64-unknown-linux-gnu src/mldsa_avx2.c
calls=$(undefined "$work/cross.o")
for symbol in "${keccak_avx2_entries[@]}"; do
    grep -qx "$symbol" <<< "$calls" ||
        fail "src/mldsa_avx2.c for x86-64 does not call $symbol; its entries of A run on the four-way Keccak"
done
for src in src/mldsa.c src/mldsa_sign_steps.c; do
    cross_object x86_64-unknown-linux-gnu "$src"
    undefined "$work/cross.o" | grep -qx mld_sample_ntt_avx2 ||
        fail "$src for x86-64 does not call mld_sample_ntt_avx2; a session with CH_CPU_AVX2 samples A on the four-way Keccak"
done
for src in src/mlkem_avx2.c src/keccak_avx2.c src/mldsa_avx2.c; do
    cross_object aarch64-none-elf "$src"
    nm "$work/cross.o" | grep -qE '[[:space:]][A-TV-Z][[:space:]]' &&
        fail "$src for arm64 defines a symbol; an arm64 object holds no four-way Keccak"
done
# The two-way Keccak of an arm64 host object, its two samplers, and their
# callers (docs/decisions.md 198). keccak_neon.h's inline entries call the
# three below.
keccak_neon_entries=(keccak_neon_shake128_absorb keccak_neon_permute keccak_neon_permute_sha3)
for src in src/mlkem.c src/mlkem_hw.c; do
    cross_object aarch64-none-elf "$src"
    undefined "$work/cross.o" | grep -qx mlk_sample_pair_neon ||
        fail "$src for arm64 does not call mlk_sample_pair_neon; its rows sample the matrix on the two-way Keccak"
done
for src in src/mldsa.c src/mldsa_sign_steps.c; do
    cross_object aarch64-none-elf "$src"
    undefined "$work/cross.o" | grep -qx mld_sample_ntt_neon ||
        fail "$src for arm64 does not call mld_sample_ntt_neon; every session samples A on the two-way Keccak"
done
for src in src/mlkem_neon.c src/mldsa_neon.c; do
    cross_object aarch64-none-elf "$src"
    calls=$(undefined "$work/cross.o")
    for symbol in "${keccak_neon_entries[@]}"; do
        grep -qx "$symbol" <<< "$calls" ||
            fail "$src for arm64 does not call $symbol; its entries run on the two-way Keccak"
    done
done
cross_object aarch64-none-elf src/keccak_neon.c
defined=$(nm "$work/cross.o" | awk '$2 == "T" { print $3 }' | sed 's/^_//')
for symbol in "${keccak_neon_entries[@]}" keccak_neon_block; do
    grep -qx "$symbol" <<< "$defined" || fail "src/keccak_neon.c for arm64 does not define $symbol"
done
for src in src/keccak_neon.c src/mlkem_neon.c src/mldsa_neon.c; do
    cross_object x86_64-unknown-linux-gnu "$src"
    nm "$work/cross.o" | grep -qE '[[:space:]][A-TV-Z][[:space:]]' &&
        fail "$src for x86-64 defines a symbol; an x86-64 object holds no two-way Keccak"
done
# The two samplers alone reach the two-way Keccak, for the reason the
# four-way Keccak takes public input alone (keccak_neon.h).
others=$(cd src && git ls-files -- '*.c' '*.h' | grep -vxE 'keccak_neon(_round)?\.[ch]|mlkem_neon\.c|mldsa_neon\.c' |
    xargs grep -lE '#[[:space:]]*include[[:space:]]*"keccak_neon\.h"|keccak_neon_[a-z0-9_]+[[:space:]]*\(' || true)
[ -z "$others" ] ||
    fail "$(tr '\n' ' ' <<< "$others")reach the two-way Keccak, which src/mlkem_neon.c and src/mldsa_neon.c alone may call: it takes public input alone"
# The copy and mldsa_avx2.c alone reach the four-way Keccak: no other
# source in src/ includes its header or calls its entries. Its lanes reach stack slots no
# wipe clears, so it takes public input alone (keccak_avx2.h).
others=$(cd src && git ls-files -- '*.c' '*.h' | grep -vxE 'keccak_avx2\.[ch]|mlkem_avx2\.c|mldsa_avx2\.c' |
    xargs grep -lE '#[[:space:]]*include[[:space:]]*"keccak_avx2\.h"|keccak_avx2_[a-z0-9_]+[[:space:]]*\(' || true)
[ -z "$others" ] ||
    fail "$(tr '\n' ' ' <<< "$others")reach the four-way Keccak, which src/mlkem_avx2.c's row sampler and src/mldsa_avx2.c alone may call: it takes public input alone"

echo "mlkem-builds: a device object's src/mlkem.c calls src/mlkem_poly.c's loops alone, a host object's src/mlkem.c and its two copies call the five vector entries and none of the loops, and the x86-64 copy and ML-DSA-87's matrix sample their rows on the four-way Keccak, which an arm64 object does not hold, the copy keeps their candidates on AVX2, and an arm64 object samples both matrices on the two-way Keccak"
