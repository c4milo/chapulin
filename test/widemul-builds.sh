#!/usr/bin/env bash
# ct.h's rules for a WIDEMUL=runtime build, and what they leave each copy of
# the files built on the widening multiply, checked the way
# test/x25519-builds.sh and test/chacha-builds.sh check theirs. `make check`
# runs it, and it is the catch target of the violations that drop a rule
# (docs/decisions.md 87).
#
# Each rule is checked on its own, beside a build the same compiler must
# accept, so a failure here is the rule and not a missing header:
#
#   - -DCH_WIDEMUL_RUNTIME compiles, and beside -DCH_NATIVE_WIDEMUL it does
#     not: that statement would give the files under their own names the
#     native multiply, which every answer but CH_WIDEMUL_CONSTANT_TIME runs.
#   - -DCH_WIDEMUL_NATIVE_COPY, which widemul_native.h defines, compiles
#     beside -DCH_WIDEMUL_RUNTIME and nowhere else.
#   - -DCH_WIDEMUL_RUNTIME beside the X25519=wide field, whose
#     CH_NATIVE_MUL128 states its multiply's timing when the object is
#     built, does not compile.
#   - Each of the six files under its own names compiles to the same
#     assembly with -DCH_WIDEMUL_RUNTIME as without it. So the copy a
#     runtime object runs for CH_WIDEMUL_NOT_STATED is the file a
#     WIDEMUL=decomposed object carries, which lint-wide-multiply
#     measures, and the recorded ceilings hold for it unchanged.
#   - Under CHACHA=vector, poly1305_native.c calls the vector Poly1305
#     under its _native name, and poly1305.c calls it under neither name.
#   - The Makefile and build.zig each write -DCH_WIDEMUL_RUNTIME and the
#     native copies for WIDEMUL=runtime, and refuse it beside X25519=wide,
#     each on its own, as ct.h does for a tree with its own build system.
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

if ! ct_builds -DCH_WIDEMUL_RUNTIME; then
    echo "widemul-builds: ct.h must compile under -DCH_WIDEMUL_RUNTIME" >&2
    exit 1
fi
if ct_builds -DCH_WIDEMUL_RUNTIME -DCH_NATIVE_WIDEMUL; then
    echo "widemul-builds: -DCH_WIDEMUL_RUNTIME with CH_NATIVE_WIDEMUL compiled; ct.h must refuse it" >&2
    exit 1
fi
if ! ct_builds -DCH_WIDEMUL_RUNTIME -DCH_WIDEMUL_NATIVE_COPY; then
    echo "widemul-builds: a native copy must compile under -DCH_WIDEMUL_RUNTIME" >&2
    exit 1
fi
if ct_builds -DCH_WIDEMUL_NATIVE_COPY; then
    echo "widemul-builds: a native copy compiled without CH_WIDEMUL_RUNTIME; ct.h must refuse it" >&2
    exit 1
fi
if ! ct_builds -DCH_X25519_WIDE -DCH_NATIVE_MUL128; then
    echo "widemul-builds: -DCH_X25519_WIDE with CH_NATIVE_MUL128 must compile on $cc" >&2
    exit 1
fi
if ct_builds -DCH_WIDEMUL_RUNTIME -DCH_X25519_WIDE -DCH_NATIVE_MUL128; then
    echo "widemul-builds: -DCH_WIDEMUL_RUNTIME with the X25519=wide field compiled; ct.h must refuse it" >&2
    exit 1
fi

# Each file under its own names, with and without the runtime define.
for f in poly1305.c x25519.c mlkem_poly.c p256_field.c p256_scalar.c rsa_sign.c; do
    "$cc" -std=c11 -O2 -DCH_RAND_EXTERN -I. -S "$f" -o "$work/decomposed.s" || exit 1
    "$cc" -std=c11 -O2 -DCH_RAND_EXTERN -DCH_WIDEMUL_RUNTIME -I. -S "$f" -o "$work/runtime.s" || exit 1
    if ! cmp -s "$work/decomposed.s" "$work/runtime.s"; then
        echo "widemul-builds: $f compiles to other code under -DCH_WIDEMUL_RUNTIME than without it; the copy under its own names must be the decomposed build's" >&2
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
printf '#define CH_CHACHA_VECTOR\n#include "chacha20_vector.h"\n' > "$vector_tu"
if ! "$cc" -std=c11 -I. -fsyntax-only "$vector_tu" 2>/dev/null; then
    echo "widemul-builds: SKIP the vector call check: $cc targets neither NEON nor SSE2 on a little-endian core"
else
    runtime_vector=(-DCH_CHACHA_VECTOR -DCH_WIDEMUL_RUNTIME)
    if ! calls poly1305_native.c poly1305_vector_blocks_native "${runtime_vector[@]}"; then
        echo "widemul-builds: poly1305_native.c under CHACHA=vector does not call poly1305_vector_blocks_native" >&2
        exit 1
    fi
    for symbol in poly1305_vector_blocks poly1305_vector_blocks_native; do
        if calls poly1305.c "$symbol" "${runtime_vector[@]}"; then
            echo "widemul-builds: poly1305.c in a WIDEMUL=runtime object calls $symbol; only its native copy may" >&2
            exit 1
        fi
    done
fi
if calls poly1305_native.c poly1305_vector_blocks_native -DCH_WIDEMUL_RUNTIME; then
    echo "widemul-builds: poly1305_native.c without CH_CHACHA_VECTOR calls poly1305_vector_blocks_native" >&2
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
runtime_words=(-DCH_WIDEMUL_RUNTIME poly1305_native.c x25519_native.c)

# What make prints for one set of variables, and nothing when it refuses
# them: the defines, then the sources.
lib_lists() {
    make -s --no-print-directory print-lib-def RAND=extern "$@" 2> /dev/null &&
        make -s --no-print-directory print-lib-srcs RAND=extern "$@" 2> /dev/null
}
if ! has_words "$(lib_lists WIDEMUL=runtime | tr '\n' ' ')" "${runtime_words[@]}"; then
    echo "widemul-builds: make must write -DCH_WIDEMUL_RUNTIME and the native copies for WIDEMUL=runtime" >&2
    exit 1
fi
if [ -n "$(lib_lists WIDEMUL=runtime X25519=wide)" ]; then
    echo "widemul-builds: make accepted WIDEMUL=runtime beside X25519=wide" >&2
    exit 1
fi

# The same two questions for build.zig, which writes its lists from the
# configure step and compiles no C. A directory no other script writes.
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
if ! has_words "$(zig_lists -DWIDEMUL=runtime)" "${runtime_words[@]}"; then
    echo "widemul-builds: build.zig must write -DCH_WIDEMUL_RUNTIME and the native copies for WIDEMUL=runtime" >&2
    exit 1
fi
if [ -n "$(zig_lists -DWIDEMUL=runtime -DX25519=wide)" ]; then
    echo "widemul-builds: build.zig accepted WIDEMUL=runtime beside X25519=wide" >&2
    exit 1
fi
rm -rf "$out"

echo "widemul-builds: ct.h admits WIDEMUL=runtime without CH_NATIVE_WIDEMUL and without the wide field, a native copy only inside it, each file under its own names compiles to its decomposed build's code, only poly1305_native.c calls the vector Poly1305, and make and build.zig each refuse the value beside X25519=wide"
