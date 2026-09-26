#!/usr/bin/env bash
# The range and the refusals of the TX_RECORD axis (docs/decisions.md 71),
# checked the way test/x25519-builds.sh checks ct.h's refusals: the value
# at each edge builds, and the value one past it does not. `make
# tx-record-check` runs it, from the TX_RECORD leg of `make check`, and it
# is the catch target of the violations that widen a refusal:
# test/violations.py runs a script by path and reads its exit status, and
# a make target is not a path.
#
# Three places take the value, and each refuses on its own:
#
#   - the headers, for a firmware tree that compiles these sources with
#     its own build system: cfg.h takes CH_TX_PT from 512 to 16384, and
#     session.h holds a TRANSPORT=quic-nonblocking build at 512.
#   - the Makefile's TX_RECORD: the same range, as a decimal integer with
#     no leading zero, and no value at all beside TRANSPORT=quic-nonblocking.
#   - build.zig's TX_RECORD option, by the Makefile's rule.
#
# It also checks where session.h's CH_TX_STAGE stops being the hello. The
# default classic hello is 617 bytes, so CH_TX_PT=600 seals a record of
# 600 + 1 + 16 = 617 bytes and keeps the hello's 617, and CH_TX_PT=601
# needs 618.
cd "$(dirname "$0")/.." || exit 1
# Each case below names its own variables. make exports the variables its
# command line set, so a run from the TX_RECORD leg of `make check` holds
# TX_RECORD=16384 and its trust mode, transport and role in the
# environment, and a make that read them would build something else.
unset MAKEFLAGS MFLAGS MAKELEVEL
unset TRANSPORT ROLE TRUST SUITE AES RAND KEX X25519 WIDEMUL EXPORTER KEYLOG TX_RECORD
cc=${CC:-cc}
zig=${ZIG:-zig}

fail() {
    echo "tx-record-builds: $*" >&2
    exit 1
}

# One translation unit that reads session.h, and cfg.h through it, and
# asserts the staging size a case passes as STAGE.
tu=$(mktemp -t chapulin_tx_record_XXXXXX).c
trap 'rm -f "$tu"' EXIT
cat > "$tu" << 'EOF'
#include "session.h"
#ifdef STAGE
_Static_assert(CH_TX_STAGE == STAGE, "CH_TX_STAGE is the size the case expects");
#endif
EOF

compiles() {
    "$cc" -std=c11 -I. -fsyntax-only -DCH_RAND_EXTERN "$@" "$tu" 2> /dev/null
}

compiles -DCH_TX_PT=512 || fail "cfg.h must accept CH_TX_PT=512"
compiles -DCH_TX_PT=16384 || fail "cfg.h must accept CH_TX_PT=16384"
if compiles -DCH_TX_PT=511; then
    fail "CH_TX_PT=511 compiled; cfg.h must refuse a value below 512"
fi
if compiles -DCH_TX_PT=16385; then
    fail "CH_TX_PT=16385 compiled; cfg.h must refuse a value above 2^14"
fi
compiles -DCH_TRANSPORT_QUIC_NONBLOCKING -DCH_TX_PT=512 ||
    fail "session.h must accept CH_TX_PT=512 under TRANSPORT=quic-nonblocking"
if compiles -DCH_TRANSPORT_QUIC_NONBLOCKING -DCH_TX_PT=513; then
    fail "CH_TX_PT=513 compiled under TRANSPORT=quic-nonblocking; session.h must hold a QUIC build at 512"
fi

compiles -DSTAGE=617 || fail "the default classic CH_TX_STAGE must stay 617"
compiles -DCH_TX_PT=600 -DSTAGE=617 || fail "CH_TX_PT=600 must keep the 617-byte hello as CH_TX_STAGE"
compiles -DCH_TX_PT=601 -DSTAGE=618 || fail "CH_TX_PT=601 must raise CH_TX_STAGE to its 618-byte sealed record"
compiles -DCH_TRUST_WEBPKI -DCH_TRANSPORT_TCP_NONBLOCKING -DCH_ROLE_SERVER -DCH_ROLE_BOTH \
    -DCH_TX_PT=16384 -DSTAGE=16401 || fail "the TX_RECORD=16384 object's CH_TX_STAGE must be 16401"

# What make print-lib-def prints for one set of variables, and nothing
# when make refuses them.
lib_def() {
    make -s --no-print-directory print-lib-def RAND=extern "$@" 2> /dev/null
}
case " $(lib_def) " in
*" -DCH_TX_PT="*) fail "the default object must not name CH_TX_PT" ;;
esac
for v in 512 16384; do
    case " $(lib_def TX_RECORD=$v) " in
    *" -DCH_TX_PT=$v "*) ;;
    *) fail "make must accept TX_RECORD=$v and write -DCH_TX_PT=$v" ;;
    esac
done
for v in 511 16385 0512 16384x; do
    [ -z "$(lib_def TX_RECORD=$v)" ] || fail "make accepted TX_RECORD=$v"
done
[ -z "$(lib_def TRANSPORT=quic-nonblocking EXPORTER=off TX_RECORD=512)" ] ||
    fail "make accepted TX_RECORD beside TRANSPORT=quic-nonblocking"

# What build.zig writes to lib-def.txt for one set of options, and nothing
# when it refuses them. It runs the configure step and writes two lists,
# and compiles no C.
command -v "$zig" > /dev/null || fail "$zig is missing; the pin is ZIG_VERSION in tools/toolchain.env"
out=bin/zig/tx-record
zig_def() {
    rm -rf "$out"
    "$zig" build lib-lists --summary none --cache-dir bin/zig/root-cache --prefix "$out" \
        -DRAND=extern "$@" > /dev/null 2>&1 || return 0
    tr '\n' ' ' < "$out/lib-def.txt"
}
case " $(zig_def) " in
*" -DCH_TX_PT="*) fail "build.zig's default object must not name CH_TX_PT" ;;
esac
for v in 512 16384; do
    case " $(zig_def -DTX_RECORD=$v) " in
    *" -DCH_TX_PT=$v "*) ;;
    *) fail "build.zig must accept TX_RECORD=$v and write -DCH_TX_PT=$v" ;;
    esac
done
for v in 511 16385 0512 16384x; do
    [ -z "$(zig_def -DTX_RECORD=$v)" ] || fail "build.zig accepted TX_RECORD=$v"
done
[ -z "$(zig_def -DTRANSPORT=quic-nonblocking -DTX_RECORD=512)" ] ||
    fail "build.zig accepted TX_RECORD beside TRANSPORT=quic-nonblocking"
rm -rf "$out"

echo "tx-record-builds: the headers, make and build.zig take CH_TX_PT from 512 to 16384 and refuse" \
    "it past either edge and beside QUIC; CH_TX_STAGE turns from the hello to the sealed record at 601"
