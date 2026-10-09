#!/usr/bin/env bash
# ct.h's rules for the two multiplies a host object holds, and what they
# leave each copy of the files built on the widening multiply, checked the
# way test/chacha-builds.sh checks its own. `make
# check` runs it, and it is the catch target of the violations that drop a
# rule (docs/decisions.md 87 and 89).
#
# Each rule is checked on its own, beside a build the same compiler must
# accept, so a failure here is the rule and not a missing header:
#
#   - -DCH_CPU_RUNTIME compiles, and beside -DCH_NATIVE_WIDEMUL it does
#     not: that statement would give the files under their own names the
#     native multiply, which every session without
#     CH_CPU_CONSTANT_TIME_MULTIPLY runs.
#   - -DCH_WIDEMUL_NATIVE_COPY, which widemul_native.h defines, compiles
#     beside -DCH_CPU_RUNTIME and nowhere else.
#   - ct_mul128, the 64x64->128 multiply the wide X25519 field is built
#     on, exists under -DCH_CPU_RUNTIME and nowhere else, so no device
#     object can run it: nothing there states its timing.
#   - Each of the six files under its own names compiles to the same
#     object with -DCH_CPU_RUNTIME as without it. So the copy a host
#     object runs for a session without the multiply bit is the file a
#     WIDEMUL=decomposed device object carries, which lint-wide-multiply
#     measures, and the recorded ceilings hold for it unchanged.
#   - In a host object poly1305_native.c calls the vector Poly1305 under
#     its _native name, and poly1305.c calls it under neither name. A
#     native copy under -DCH_CT_WIDEMUL, which forces the decomposition,
#     does not call it either.
#   - rsa_mont.c in a host object calls rsa_mont64.c's modulus setup and
#     its public operation, and in a device object calls neither: the
#     device arm holds the 32-bit arithmetic itself, and no bit of
#     ch_cfg.cpu picks between the two (docs/decisions.md 95).
#   - rsa_ifma.c, RSA's public operation on AVX-512 IFMA, defines
#     rsa_ifma_public for x86-64 and nothing for arm64, both asked of the
#     pinned clang with no instruction flag whatever the host. For x86-64
#     rsa_mont.c's rsa_vp1_cpu calls it and rsa_vp1, which takes no value,
#     does not; for arm64 neither does. No other RSA source holds a
#     512-bit instruction, and no root source but rsa_mont.c includes
#     rsa_ifma.h or calls into it, so the signer never calls it: its
#     input must be public (rsa_ifma.h).
#   - p256.c in a host object hands the signature it read to
#     p256_wide_verify.c, and in a device object does not: the device arm
#     holds the 32-bit arithmetic itself, and no bit of ch_cfg.cpu picks
#     between the two (docs/decisions.md 96).
#   - p384.c in a host object hands the signature it read to
#     p384_wide_verify.c and calls none of p384_field.c, which has no body
#     there; in a device object it calls p384_field.c and not the 64-bit
#     verifier, and the three 64-bit files have no body (docs/decisions.md
#     97). The Makefile and build.zig each write the three 64-bit files
#     for a TRUST=webpki host object and none of them for a device object.
#   - The Makefile and build.zig each write the native copies, the wide
#     X25519 field, RSA's 64-bit arithmetic and signer and the vector
#     ChaCha20 and both vector Poly1305 paths for a host object and none
#     of them for a device object, and
#     refuse a WIDEMUL value for a host object, and WIDEMUL=runtime and
#     every value of X25519 and of CHACHA for any, each on its own.
cd "$(dirname "$0")/.." || exit 1
# make exports the variables its command line set, and a make that read
# them here would build something else, as test/tx-record-builds.sh says.
unset MAKEFLAGS MFLAGS MAKELEVEL
unset TRANSPORT ROLE TRUST SUITE AES RAND KEX X25519 WIDEMUL CHACHA EXPORTER KEYLOG TX_RECORD
zig=${ZIG:-zig}

work=$(mktemp -d -t chapulin_widemul_XXXXXX)
trap 'rm -rf "$work"' EXIT
tu=$work/ct.c
echo '#include "ct.h"' > "$tu"
cc=${CC:-cc}

# One compile of ct.h alone, syntax only.
ct_builds() { # $1... = extra flags
    "$cc" -std=c11 -I. -fsyntax-only "$@" "$tu" 2>/dev/null
}

if ! ct_builds -DCH_CPU_RUNTIME; then
    echo "widemul-builds: ct.h must compile under -DCH_CPU_RUNTIME" >&2
    exit 1
fi
if ct_builds -DCH_CPU_RUNTIME -DCH_NATIVE_WIDEMUL; then
    echo "widemul-builds: -DCH_CPU_RUNTIME with CH_NATIVE_WIDEMUL compiled; ct.h must refuse it" >&2
    exit 1
fi
if ! ct_builds -DCH_CPU_RUNTIME -DCH_WIDEMUL_NATIVE_COPY; then
    echo "widemul-builds: a native copy must compile under -DCH_CPU_RUNTIME" >&2
    exit 1
fi
if ct_builds -DCH_WIDEMUL_NATIVE_COPY; then
    echo "widemul-builds: a native copy compiled without CH_CPU_RUNTIME; ct.h must refuse it" >&2
    exit 1
fi
# One compile of a unit that calls ct_mul128, syntax only.
mul128_tu=$work/mul128.c
printf '#include "ct.h"\nct_u128 product(uint64_t a, uint64_t b) { return ct_mul128(a, b); }\n' > "$mul128_tu"
if ! "$cc" -std=c11 -I. -fsyntax-only -DCH_CPU_RUNTIME "$mul128_tu" 2>/dev/null; then
    echo "widemul-builds: ct_mul128 must compile under -DCH_CPU_RUNTIME on $cc" >&2
    exit 1
fi
if "$cc" -std=c11 -I. -fsyntax-only "$mul128_tu" 2>/dev/null; then
    echo "widemul-builds: ct_mul128 compiled without CH_CPU_RUNTIME; ct.h must define it for a host object alone" >&2
    exit 1
fi

# Each file under its own names, with and without the host object's define.
# The two objects are compared, not the two assembly texts: gcc numbers a
# label for every function it parses, .LFB6 and the like, so a header that
# defines one more inline function under -DCH_CPU_RUNTIME, as ct.h does
# with ct_mul128, changes the text of a file whose code it does not change.
for f in poly1305.c x25519.c mlkem_poly.c p256_field.c p256_scalar.c rsa_sign.c; do
    "$cc" -std=c11 -O2 -DCH_RAND_EXTERN -I. -c "$f" -o "$work/decomposed.o" || exit 1
    "$cc" -std=c11 -O2 -DCH_RAND_EXTERN -DCH_CPU_RUNTIME -I. -c "$f" -o "$work/host.o" || exit 1
    if ! cmp -s "$work/decomposed.o" "$work/host.o"; then
        echo "widemul-builds: $f compiles to other code under -DCH_CPU_RUNTIME than without it; the copy under its own names must be the decomposed build's" >&2
        exit 1
    fi
done

# Whether an object calls a symbol, read from the undefined symbols nm
# lists. Mach-O names carry a leading underscore.
calls() { # $1 = source, $2 = symbol, $3... = extra flags
    local src=$1 symbol=$2
    shift 2
    "$cc" -std=c11 -O2 -DCH_RAND_EXTERN -I. "$@" -c "$src" -o "$work/object.o" || exit 1
    nm -u "$work/object.o" | grep -qE "(^|[[:space:]_])$symbol\$"
}

# Whether the object of one source defines a symbol.
defines() { # $1 = source, $2 = symbol, $3... = extra flags
    local src=$1 symbol=$2
    shift 2
    "$cc" -std=c11 -O2 -DCH_RAND_EXTERN -I. "$@" -c "$src" -o "$work/object.o" || exit 1
    nm "$work/object.o" | grep -qE "[[:space:]][TDRS][[:space:]]_?$symbol\$"
}

vector_tu=$work/vector.c
printf '#define CH_CPU_RUNTIME\n#include "chacha20_vector.h"\n' > "$vector_tu"
if ! "$cc" -std=c11 -I. -fsyntax-only "$vector_tu" 2>/dev/null; then
    echo "widemul-builds: SKIP the vector call check: $cc targets neither NEON nor SSE2 on a little-endian core"
else
    if ! calls poly1305_native.c poly1305_vector_blocks_native -DCH_CPU_RUNTIME; then
        echo "widemul-builds: poly1305_native.c in a host object does not call poly1305_vector_blocks_native" >&2
        exit 1
    fi
    for symbol in poly1305_vector_blocks poly1305_vector_blocks_native; do
        if calls poly1305.c "$symbol" -DCH_CPU_RUNTIME; then
            echo "widemul-builds: poly1305.c in a host object calls $symbol; only its native copy may" >&2
            exit 1
        fi
    done
    if calls poly1305_native.c poly1305_vector_blocks_native -DCH_CPU_RUNTIME -DCH_CT_WIDEMUL; then
        echo "widemul-builds: poly1305_native.c under -DCH_CT_WIDEMUL calls poly1305_vector_blocks_native" >&2
        exit 1
    fi
fi

# rsa_mont.c's two arms. The host arm calls into rsa_mont64.c, and the
# device arm is the 32-bit arithmetic, which calls nothing outside its
# file but memset and memcpy.
for symbol in rsa_mont64_modulus_init rsa_mont64_modulus_load rsa_mont64_public; do
    if ! calls rsa_mont.c "$symbol" -DCH_CPU_RUNTIME; then
        echo "widemul-builds: rsa_mont.c in a host object does not call $symbol" >&2
        exit 1
    fi
    if calls rsa_mont.c "$symbol"; then
        echo "widemul-builds: rsa_mont.c in a device object calls $symbol; a host object alone holds rsa_mont64.c" >&2
        exit 1
    fi
done

# rsa_ifma.c and the dispatch that calls it, asked of the pinned clang for
# x86-64 and arm64 targets whatever the host, as test/chacha-builds.sh
# asks of the AVX2 kernel.
clang_rv=$(make -s --no-print-directory print-clang-rv)
if [ -z "$clang_rv" ]; then
    echo "widemul-builds: no clang to cross-compile with; see the LLVM_MAJOR pin in tools/toolchain.env" >&2
    exit 1
fi
cross_object() { # $1 = target, $2 = source; writes $work/cross.o and $work/cross.s
    "$clang_rv" -target "$1" -ffreestanding -nostdlibinc -Itools/freestanding -std=c11 -O2 -I. \
        -DCH_CPU_RUNTIME -DCH_RAND_EXTERN -c "$2" -o "$work/cross.o" || exit 1
    "$clang_rv" -target "$1" -ffreestanding -nostdlibinc -Itools/freestanding -std=c11 -O2 -I. \
        -DCH_CPU_RUNTIME -DCH_RAND_EXTERN -S "$2" -o "$work/cross.s" || exit 1
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
        echo "widemul-builds: rsa_mont.c for a host object defines no $1" >&2
        exit 1
        ;;
    esac
}
x86=x86_64-unknown-linux-gnu
arm64=aarch64-none-elf
cross_object "$x86" rsa_ifma.c
if ! nm "$work/cross.o" | grep -qE '[[:space:]]T[[:space:]]_?rsa_ifma_public$'; then
    echo "widemul-builds: rsa_ifma.c for x86-64 does not define rsa_ifma_public" >&2
    exit 1
fi
cross_object "$arm64" rsa_ifma.c
if nm "$work/cross.o" | grep -qE '[[:space:]][A-TV-Z][[:space:]]'; then
    echo "widemul-builds: rsa_ifma.c for arm64 defines a symbol; it has a body on x86-64 alone" >&2
    exit 1
fi
cross_object "$x86" rsa_mont.c
if ! body_names rsa_vp1_cpu rsa_ifma_public; then
    echo "widemul-builds: rsa_vp1_cpu for x86-64 does not call rsa_ifma_public; a session with CH_CPU_AVX512_IFMA runs it" >&2
    exit 1
fi
if body_names rsa_vp1 rsa_ifma_public; then
    echo "widemul-builds: rsa_vp1 for x86-64 calls rsa_ifma_public; it takes no description of the CPU" >&2
    exit 1
fi
cross_object "$arm64" rsa_mont.c
if body_names rsa_vp1_cpu rsa_ifma_public; then
    echo "widemul-builds: rsa_vp1_cpu for arm64 calls rsa_ifma_public, which has a body on x86-64 alone" >&2
    exit 1
fi
for src in rsa.c rsa_pkcs1.c rsa_mont.c rsa_mont64.c rsa_mont64_blocks.c rsa_sign.c rsa_sign64.c; do
    cross_object "$x86" "$src"
    if grep -q '%zmm' "$work/cross.s"; then
        echo "widemul-builds: $src for x86-64 holds a 512-bit instruction; only rsa_ifma.c may" >&2
        exit 1
    fi
done
others=$(git ls-files -- '*.c' '*.h' | grep -v / | grep -vxE 'rsa_ifma\.[ch]|rsa_mont\.c' |
    xargs grep -lE '#[[:space:]]*include[[:space:]]*"rsa_ifma\.h"|rsa_ifma_[a-z0-9_]+[[:space:]]*\(' || true)
if [ -n "$others" ]; then
    echo "widemul-builds: $(tr '\n' ' ' <<< "$others")include rsa_ifma.h or call rsa_ifma_public, which rsa_mont.c's rsa_vp1_cpu alone may call: it takes public input alone" >&2
    exit 1
fi

# p256.c's two arms. The host arm hands r and s to p256_wide_verify.c, and
# the device arm is the 32-bit arithmetic, which calls nothing outside its
# file but the byte reader, memset and memcpy.
if ! calls p256.c p256_wide_verify_rs -DCH_CPU_RUNTIME; then
    echo "widemul-builds: p256.c in a host object does not call p256_wide_verify_rs" >&2
    exit 1
fi
if calls p256.c p256_wide_verify_rs; then
    echo "widemul-builds: p256.c in a device object calls p256_wide_verify_rs; a host object alone holds p256_wide_verify.c" >&2
    exit 1
fi

# p384.c's two arms, and the two fields. The host arm hands r and s to
# p384_wide_verify.c and calls nothing of p384_field.c, which has no body
# in a host object. The device arm is the reverse.
if ! calls p384.c p384_wide_verify_rs -DCH_CPU_RUNTIME || calls p384.c p384_mod_mul -DCH_CPU_RUNTIME; then
    echo "widemul-builds: p384.c in a host object must call p384_wide_verify_rs and nothing of p384_field.c" >&2
    exit 1
fi
if calls p384.c p384_wide_verify_rs || ! calls p384.c p384_mod_mul; then
    echo "widemul-builds: p384.c in a device object must call p384_field.c and not p384_wide_verify_rs; a host object alone holds p384_wide_verify.c" >&2
    exit 1
fi
if defines p384_field.c p384_mont_mul -DCH_CPU_RUNTIME || ! defines p384_field.c p384_mont_mul; then
    echo "widemul-builds: p384_field.c must define its routines in a device object and nothing in a host object" >&2
    exit 1
fi
if ! defines p384_wide_field.c p384_wide_mont_mul -DCH_CPU_RUNTIME || defines p384_wide_field.c p384_wide_mont_mul; then
    echo "widemul-builds: p384_wide_field.c must define its routines in a host object and nothing in a device object" >&2
    exit 1
fi
if ! defines p384_wide_point.c p384_wide_double_mul -DCH_CPU_RUNTIME || defines p384_wide_point.c p384_wide_double_mul; then
    echo "widemul-builds: p384_wide_point.c must define its entries in a host object and nothing in a device object" >&2
    exit 1
fi
if ! defines p384_wide_verify.c p384_wide_verify_rs -DCH_CPU_RUNTIME || defines p384_wide_verify.c p384_wide_verify_rs; then
    echo "widemul-builds: p384_wide_verify.c must define the verifier in a host object and nothing in a device object" >&2
    exit 1
fi

# Whether every word after the first argument is a word of the first.
has_words() { # $1 = a list of words, $2... = the words it must hold
    local list=" $1 " word
    shift
    for word in "$@"; do
        case "$list" in
        *" $word "*) ;;
        *) return 1 ;;
        esac
    done
}
host_words=(-DCH_CPU_RUNTIME poly1305_native.c x25519_wide.c rsa_sign64.c chacha20_vector.c
            chacha20_avx2.c poly1305_vector_native.c poly1305_avx2_native.c rsa_mont64.c rsa_ifma.c)
p384_words=(p384.c p384_field.c p384_wide_field.c p384_wide_point.c p384_wide_verify.c)
server=(ROLE=server TRUST=none)

# What make prints for one set of variables, and nothing when it refuses
# them: the defines, then the sources. HOST_TARGET is the host test's
# result, set here so the lists read the same on every compiler.
lib_lists() {
    make -s --no-print-directory print-lib-def RAND=extern "$@" 2> /dev/null &&
        make -s --no-print-directory print-lib-srcs RAND=extern "$@" 2> /dev/null
}
if ! has_words "$(lib_lists "${server[@]}" HOST_TARGET=yes | tr '\n' ' ')" "${host_words[@]}"; then
    echo "widemul-builds: make must write -DCH_CPU_RUNTIME, the native copies, the wide X25519 field, RSA's 64-bit arithmetic and signer and the vector ChaCha20 and Poly1305 for a host object" >&2
    exit 1
fi
device=$(lib_lists "${server[@]}" HOST_TARGET= WIDEMUL=native | tr '\n' ' ')
case " $device " in
*_native.c* | *x25519_wide.c* | *chacha20_vector.c* | *chacha20_avx2.c* | *poly1305_vector* | *poly1305_avx2* | *rsa_mont64.c* | *rsa_ifma.c* | *rsa_sign64.c*)
    echo "widemul-builds: make writes a native copy, the wide X25519 field, RSA's 64-bit arithmetic or signer or a vector path for a device object" >&2
    exit 1
    ;;
esac
if ! has_words "$device" -DCH_NATIVE_WIDEMUL; then
    echo "widemul-builds: make must write -DCH_NATIVE_WIDEMUL for a device object on WIDEMUL=native" >&2
    exit 1
fi
# P-384 is a TRUST=webpki object's, so the lists that hold or lack its
# 64-bit files are that product's.
if ! has_words "$(lib_lists TRUST=webpki HOST_TARGET=yes | tr '\n' ' ')" "${p384_words[@]}"; then
    echo "widemul-builds: make must write P-384's 64-bit field, points and verifier for a TRUST=webpki host object" >&2
    exit 1
fi
device=$(lib_lists TRUST=webpki HOST_TARGET= | tr '\n' ' ')
case " $device " in
*p384_wide*)
    echo "widemul-builds: make writes P-384's 64-bit files for a device object" >&2
    exit 1
    ;;
esac
if ! has_words "$device" p384.c p384_field.c; then
    echo "widemul-builds: make must write p384.c and p384_field.c for a TRUST=webpki device object" >&2
    exit 1
fi
for refused in WIDEMUL=native WIDEMUL=decomposed; do
    if [ -n "$(lib_lists "${server[@]}" HOST_TARGET=yes "$refused")" ]; then
        echo "widemul-builds: make accepted $refused for a host object" >&2
        exit 1
    fi
done
for refused in X25519=wide X25519=portable CHACHA=vector CHACHA=portable; do
    for object in "HOST_TARGET=yes" "HOST_TARGET="; do
        if [ -n "$(lib_lists "${server[@]}" "$object" "$refused")" ]; then
            echo "widemul-builds: make accepted $refused with $object; the variable is gone" >&2
            exit 1
        fi
    done
done
if [ -n "$(lib_lists WIDEMUL=runtime)" ]; then
    echo "widemul-builds: make accepted WIDEMUL=runtime, which is gone" >&2
    exit 1
fi

# The same questions for build.zig, which writes its lists from the
# configure step and compiles no C, for a target that passes the host test
# and one that fails it. A directory no other script writes.
command -v "$zig" > /dev/null || {
    echo "widemul-builds: $zig is missing; the pin is ZIG_VERSION in tools/toolchain.env" >&2
    exit 1
}
out=bin/zig/widemul-builds
zig_lists() {
    rm -rf "$out"
    "$zig" build lib-lists --summary none --cache-dir bin/zig/root-cache --prefix "$out" \
        -DRAND=extern "$@" > /dev/null 2>&1 || return 0
    cat "$out/lib-def.txt" "$out/lib-srcs.txt" | tr '\n' ' '
}
zig_server=(-DROLE=server -DTRUST=none)
host_target=-Dtarget=aarch64-linux-gnu
device_target=-Dtarget=thumb-freestanding-eabi
if ! has_words "$(zig_lists "${zig_server[@]}" "$host_target")" "${host_words[@]}"; then
    echo "widemul-builds: build.zig must write -DCH_CPU_RUNTIME, the native copies, the wide X25519 field, RSA's 64-bit arithmetic and signer and the vector ChaCha20 and Poly1305 for a host object" >&2
    exit 1
fi
device=$(zig_lists "${zig_server[@]}" "$device_target" -DWIDEMUL=native)
case " $device " in
*_native.c* | *x25519_wide.c* | *chacha20_vector.c* | *chacha20_avx2.c* | *poly1305_vector* | *poly1305_avx2* | *rsa_mont64.c* | *rsa_ifma.c* | *rsa_sign64.c*)
    echo "widemul-builds: build.zig writes a native copy, the wide X25519 field, RSA's 64-bit arithmetic or signer or a vector path for a device object" >&2
    exit 1
    ;;
esac
if ! has_words "$device" -DCH_NATIVE_WIDEMUL; then
    echo "widemul-builds: build.zig must write -DCH_NATIVE_WIDEMUL for a device object on WIDEMUL=native" >&2
    exit 1
fi
if ! has_words "$(zig_lists -DTRUST=webpki "$host_target")" "${p384_words[@]}"; then
    echo "widemul-builds: build.zig must write P-384's 64-bit field, points and verifier for a TRUST=webpki host object" >&2
    exit 1
fi
device=$(zig_lists -DTRUST=webpki "$device_target")
case " $device " in
*p384_wide*)
    echo "widemul-builds: build.zig writes P-384's 64-bit files for a device object" >&2
    exit 1
    ;;
esac
if ! has_words "$device" p384.c p384_field.c; then
    echo "widemul-builds: build.zig must write p384.c and p384_field.c for a TRUST=webpki device object" >&2
    exit 1
fi
for refused in -DWIDEMUL=native -DWIDEMUL=decomposed; do
    if [ -n "$(zig_lists "${zig_server[@]}" "$host_target" "$refused")" ]; then
        echo "widemul-builds: build.zig accepted $refused for a host object" >&2
        exit 1
    fi
done
for refused in -DX25519=wide -DX25519=portable -DCHACHA=vector -DCHACHA=portable; do
    for object in "$host_target" "$device_target"; do
        if [ -n "$(zig_lists "${zig_server[@]}" "$object" "$refused")" ]; then
            echo "widemul-builds: build.zig accepted $refused for $object; the option is gone" >&2
            exit 1
        fi
    done
done
if [ -n "$(zig_lists -DWIDEMUL=runtime)" ]; then
    echo "widemul-builds: build.zig accepted WIDEMUL=runtime, which is gone" >&2
    exit 1
fi
rm -rf "$out"

echo "widemul-builds: ct.h admits a host object without CH_NATIVE_WIDEMUL, and a native copy and the 64x64->128 multiply only inside it, each file under its own names compiles to its decomposed build's code, only poly1305_native.c calls the vector Poly1305, rsa_mont.c calls rsa_mont64.c in a host object alone, rsa_ifma.c has a body for x86-64 alone and only rsa_mont.c's rsa_vp1_cpu calls it, and make and build.zig each write the copies, the wide X25519 field, RSA's 64-bit arithmetic, IFMA public operation and signer and the vector ChaCha20 and Poly1305 for a host object alone, refuse it a WIDEMUL value and refuse every X25519 and CHACHA value"
