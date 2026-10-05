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
#   - p256.c in a host object hands the signature it read to
#     p256_wide_verify.c, and in a device object does not: the device arm
#     holds the 32-bit arithmetic itself, and no bit of ch_cfg.cpu picks
#     between the two (docs/decisions.md 96).
#   - The Makefile and build.zig each write the native copies, the wide
#     X25519 field, RSA's 64-bit arithmetic and signer and the vector
#     ChaCha20 and Poly1305 for a host object and none of them for a
#     device object, and
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

# rsa_mont.c's two arms. The host arm is a call into rsa_mont64.c, and the
# device arm is the 32-bit arithmetic, which calls nothing outside its
# file but memset and memcpy.
for symbol in rsa_mont64_modulus_init rsa_mont64_public; do
    if ! calls rsa_mont.c "$symbol" -DCH_CPU_RUNTIME; then
        echo "widemul-builds: rsa_mont.c in a host object does not call $symbol" >&2
        exit 1
    fi
    if calls rsa_mont.c "$symbol"; then
        echo "widemul-builds: rsa_mont.c in a device object calls $symbol; a host object alone holds rsa_mont64.c" >&2
        exit 1
    fi
done

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
            chacha20_avx2.c poly1305_vector_native.c rsa_mont64.c)
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
*_native.c* | *x25519_wide.c* | *chacha20_vector.c* | *chacha20_avx2.c* | *poly1305_vector* | *rsa_mont64.c* | *rsa_sign64.c*)
    echo "widemul-builds: make writes a native copy, the wide X25519 field, RSA's 64-bit arithmetic or signer or a vector path for a device object" >&2
    exit 1
    ;;
esac
if ! has_words "$device" -DCH_NATIVE_WIDEMUL; then
    echo "widemul-builds: make must write -DCH_NATIVE_WIDEMUL for a device object on WIDEMUL=native" >&2
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
*_native.c* | *x25519_wide.c* | *chacha20_vector.c* | *chacha20_avx2.c* | *poly1305_vector* | *rsa_mont64.c* | *rsa_sign64.c*)
    echo "widemul-builds: build.zig writes a native copy, the wide X25519 field, RSA's 64-bit arithmetic or signer or a vector path for a device object" >&2
    exit 1
    ;;
esac
if ! has_words "$device" -DCH_NATIVE_WIDEMUL; then
    echo "widemul-builds: build.zig must write -DCH_NATIVE_WIDEMUL for a device object on WIDEMUL=native" >&2
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

echo "widemul-builds: ct.h admits a host object without CH_NATIVE_WIDEMUL, and a native copy and the 64x64->128 multiply only inside it, each file under its own names compiles to its decomposed build's code, only poly1305_native.c calls the vector Poly1305, rsa_mont.c calls rsa_mont64.c in a host object alone, and make and build.zig each write the copies, the wide X25519 field, RSA's 64-bit arithmetic and signer and the vector ChaCha20 and Poly1305 for a host object alone, refuse it a WIDEMUL value and refuse every X25519 and CHACHA value"
