#!/usr/bin/env bash
# The calls that make a host object run the vector NTT, checked the way
# test/chacha-builds.sh checks the vector ChaCha20's. `make check` runs
# it, and it is the catch target of the violations that drop a call
# (docs/decisions.md 101):
#
#   - a device object's mlkem.c, compiled without -DCH_CPU_RUNTIME, must
#     call mlkem_poly.c's two transforms and its base multiplication and
#     no vector entry;
#   - a host object's mlkem.c, for x86-64 and for arm64, must call
#     mlk_vector_ntt, mlk_vector_invntt and mlk_vector_basemul and none of
#     mlkem_poly.c's three, so every session runs the vector path; and so
#     must mlkem_hw.c, its copy over the SHA-3 instructions, for arm64, the
#     one target where that copy has a body, and mlkem_avx2.c, its copy for
#     the four-way Keccak, for x86-64, the one target where that one has a
#     body;
#   - mlkem_avx2.c for x86-64 must call keccak_avx2.c's three entries and
#     not mlk_sample_ntt, so its rows run on the four-way Keccak, and
#     keccak_avx2.c must define the three; for arm64 both files must
#     define no symbol; and no other source at the root may include
#     keccak_avx2.h or call its entries (docs/decisions.md 107).
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
"$cc" -std=c11 -O2 -DCH_RAND_EXTERN -I. -c mlkem.c -o "$work/device.o" ||
    fail "mlkem.c does not compile without -DCH_CPU_RUNTIME"
calls=$(undefined "$work/device.o")
for symbol in mlk_poly_ntt mlk_poly_invntt mlk_poly_basemul; do
    grep -qx "$symbol" <<< "$calls" ||
        fail "mlkem.c without -DCH_CPU_RUNTIME does not call $symbol; a device object runs mlkem_poly.c's loops"
done
for symbol in mlk_vector_ntt mlk_vector_invntt mlk_vector_basemul; do
    grep -qx "$symbol" <<< "$calls" &&
        fail "mlkem.c without -DCH_CPU_RUNTIME calls $symbol; a device object holds no vector path"
done

# A host object's source, asked of the pinned clang for x86-64 and arm64
# targets whatever the host. It writes $work/cross.o.
cross_object() { # $1 = target, $2 = source
    "$clang_rv" -target "$1" -ffreestanding -nostdlibinc -Itools/freestanding -std=c11 -O2 -I. \
        -DCH_CPU_RUNTIME -DCH_RAND_EXTERN -c "$2" -o "$work/cross.o" ||
        fail "$2 does not compile for a host object on $1"
}

# Whether the object in $work/cross.o calls the three vector entries and
# none of the loops named by its arguments.
calls_vector_alone() { # $1 = what, $2 $3 $4 = the loops' names in that object
    calls=$(undefined "$work/cross.o")
    for symbol in mlk_vector_ntt mlk_vector_invntt mlk_vector_basemul; do
        grep -qx "$symbol" <<< "$calls" ||
            fail "$1 does not call $symbol; every session of a host object runs the vector NTT"
    done
    for symbol in "$2" "$3" "$4"; do
        grep -qx "$symbol" <<< "$calls" &&
            fail "$1 calls $symbol; a host object runs the vector NTT in its place"
    done
    return 0
}

for target in x86_64-unknown-linux-gnu aarch64-none-elf; do
    cross_object "$target" mlkem.c
    calls_vector_alone "mlkem.c for $target" mlk_poly_ntt mlk_poly_invntt mlk_poly_basemul
done
cross_object aarch64-none-elf mlkem_hw.c
calls_vector_alone "mlkem_hw.c for arm64" mlk_poly_ntt_hw mlk_poly_invntt_hw mlk_poly_basemul_hw

# The copy for the four-way Keccak, and the Keccak it samples the matrix on.
keccak_avx2_entries=(keccak_avx2_shake128_start keccak_avx2_permute keccak_avx2_block)
cross_object x86_64-unknown-linux-gnu mlkem_avx2.c
calls_vector_alone "mlkem_avx2.c for x86-64" mlk_poly_ntt mlk_poly_invntt mlk_poly_basemul
for symbol in "${keccak_avx2_entries[@]}"; do
    grep -qx "$symbol" <<< "$calls" ||
        fail "mlkem_avx2.c for x86-64 does not call $symbol; its rows run on the four-way Keccak"
done
grep -qx mlk_sample_ntt <<< "$calls" &&
    fail "mlkem_avx2.c for x86-64 calls mlk_sample_ntt; its rows run on the four-way Keccak"
cross_object x86_64-unknown-linux-gnu keccak_avx2.c
defined=$(nm "$work/cross.o" | awk '$2 == "T" { print $3 }' | sed 's/^_//')
for symbol in "${keccak_avx2_entries[@]}"; do
    grep -qx "$symbol" <<< "$defined" || fail "keccak_avx2.c for x86-64 does not define $symbol"
done
for src in mlkem_avx2.c keccak_avx2.c; do
    cross_object aarch64-none-elf "$src"
    nm "$work/cross.o" | grep -qE '[[:space:]][A-TV-Z][[:space:]]' &&
        fail "$src for arm64 defines a symbol; an arm64 object holds no four-way Keccak"
done
# The copy alone reaches the four-way Keccak: no other source at the root
# includes its header or calls its entries. Its lanes reach stack slots no
# wipe clears, so it takes public input alone (keccak_avx2.h).
others=$(git ls-files -- '*.c' '*.h' | grep -v / | grep -vxE 'keccak_avx2\.[ch]|mlkem_avx2\.c' |
    xargs grep -lE '#[[:space:]]*include[[:space:]]*"keccak_avx2\.h"|keccak_avx2_[a-z0-9_]+[[:space:]]*\(' || true)
[ -z "$others" ] ||
    fail "$(tr '\n' ' ' <<< "$others")reach the four-way Keccak, which mlkem_avx2.c's row sampler alone may call: it takes public input alone"

echo "mlkem-builds: a device object's mlkem.c calls mlkem_poly.c's loops alone, a host object's mlkem.c and its two copies call the three vector entries and none of the loops, and the x86-64 copy samples its rows on the four-way Keccak, which an arm64 object does not hold"
