#!/usr/bin/env bash
# Regenerates the memory numbers in docs/performance.md. Everything is
# measured from the code being committed, never hand-computed: struct
# sizes from sizeof, stack peaks from bench/stack.py, which walks the
# real call graph (edges read from the objects' relocations, weighted by
# -fstack-usage frames) instead of any hand-picked chain. Host-native
# today; the cross-compiled ASIC model (pushkin's device-ram.sh) lands
# with the bench. Prints the report and writes bench/results-sram.csv,
# the file make lint-bench-numbers compares against docs/performance.md's
# Memory table (https://github.com/c4milo/chapulin/issues/90) and against
# each stack figure its prose states.
set -euo pipefail
cd "$(dirname "$0")/.."

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

# The receive buffer the table shows; the static working sets add it.
RXBUF=2048

cat > "$TMP/sz.c" <<'EOF'
#include <stdio.h>
#include "tls.h"
int main(void) {
    printf("ch_tls %zu\n", sizeof(ch_tls));
    return 0;
}
EOF
cc -std=c11 -DCH_RAND_EXTERN -I. -o "$TMP/sz" "$TMP/sz.c"
SESSION=$("$TMP/sz" | awk '{print $2}')
cc -std=c11 -DCH_RAND_EXTERN -DCH_KEX_PQ -I. -o "$TMP/sz_pq" "$TMP/sz.c"
SESSION_PQ=$("$TMP/sz_pq" | awk '{print $2}')
# TRUST=webpki carries a larger ClientHello, so a larger TX staging array,
# and it demands a receive buffer of CH_MIN_RXBUF, read from the build
# rather than copied from cfg.h.
cat > "$TMP/floor.c" <<'EOF'
#include <stdio.h>
#include "tls.h"
int main(void) {
    printf("floor %d\n", CH_MIN_RXBUF);
    return 0;
}
EOF
cc -std=c11 -DCH_RAND_EXTERN -DCH_TRUST_WEBPKI -I. -o "$TMP/sz_webpki" "$TMP/sz.c"
SESSION_WEBPKI=$("$TMP/sz_webpki" | awk '{print $2}')
# ROLE=server stages its ServerHello in the TX array, and a hybrid one
# carries a 1120-byte share, so its struct is measured on its own.
cc -std=c11 -DCH_RAND_EXTERN -DCH_ROLE_SERVER -I. -o "$TMP/sz_server" "$TMP/sz.c"
SESSION_SERVER=$("$TMP/sz_server" | awk '{print $2}')
cc -std=c11 -DCH_RAND_EXTERN -DCH_TRUST_WEBPKI -I. -o "$TMP/floor_webpki" "$TMP/floor.c"
RXBUF_WEBPKI=$("$TMP/floor_webpki" | awk '{print $2}')
# SUITE=aesgcm is measured here in the host object, whose ch_cfg holds
# the caller's description of its CPU (docs/decisions.md 89) and which no
# device target builds, so its rows are measured on this host alone. An
# AES=extern suite build can run on a device, and this script does not
# measure one (docs/decisions.md 68). Its secrets, its
# transcript and a ticket's PSK take SHA-384's length, and a webpki
# ClientHello lists two more suites (docs/decisions.md 58).
SUITE_DEFS="-DCH_SUITE_AES_GCM -DCH_CPU_RUNTIME"
# shellcheck disable=SC2086
cc -std=c11 -DCH_RAND_EXTERN -DCH_ROLE_SERVER $SUITE_DEFS -I. -o "$TMP/sz_server_aes" "$TMP/sz.c"
SESSION_SERVER_AES=$("$TMP/sz_server_aes" | awk '{print $2}')
# shellcheck disable=SC2086
cc -std=c11 -DCH_RAND_EXTERN -DCH_TRUST_WEBPKI $SUITE_DEFS -I. -o "$TMP/sz_webpki_aes" "$TMP/sz.c"
SESSION_WEBPKI_AES=$("$TMP/sz_webpki_aes" | awk '{print $2}')
# shellcheck disable=SC2086
cc -std=c11 -DCH_RAND_EXTERN -DCH_TRUST_WEBPKI $SUITE_DEFS -I. -o "$TMP/floor_webpki_aes" "$TMP/floor.c"
RXBUF_WEBPKI_AES=$("$TMP/floor_webpki_aes" | awk '{print $2}')
# The TRUST=webpki and ROLE=server builds as host objects, which the
# Makefile builds for them on arm64 and x86-64. Their ch_cfg holds the
# caller's description of its CPU, and each record direction the answer
# about the widening multiply that description gives, in bytes its
# alignment left unused (docs/decisions.md 87 and 89). A host object runs
# on those two architectures alone, so these rows are host figures.
cc -std=c11 -DCH_RAND_EXTERN -DCH_TRUST_WEBPKI -DCH_CPU_RUNTIME -I. -o "$TMP/sz_webpki_host" "$TMP/sz.c"
SESSION_WEBPKI_HOST=$("$TMP/sz_webpki_host" | awk '{print $2}')
cc -std=c11 -DCH_RAND_EXTERN -DCH_ROLE_SERVER -DCH_CPU_RUNTIME -I. -o "$TMP/sz_server_host" "$TMP/sz.c"
SESSION_SERVER_HOST=$("$TMP/sz_server_host" | awk '{print $2}')
# ch_quic in the object colibri links, ROLE=both TRUST=webpki
# TRANSPORT=quic-nonblocking, without and with the suite: under SUITE=aesgcm each
# QUIC key set records its suite and its section 6.6 count. The report
# prints both; docs/performance.md's table does not carry them.
cat > "$TMP/szq.c" <<'EOF'
#include <stdio.h>
#include "quic.h"
int main(void) {
    printf("ch_quic %zu\n", sizeof(ch_quic));
    return 0;
}
EOF
QUIC_DEFS="-DCH_TRANSPORT_QUIC_NONBLOCKING -DCH_TRUST_WEBPKI -DCH_ROLE_SERVER -DCH_ROLE_BOTH"
# shellcheck disable=SC2086
cc -std=c11 -DCH_RAND_EXTERN $QUIC_DEFS -I. -o "$TMP/szq" "$TMP/szq.c"
QUIC_SESSION=$("$TMP/szq" | awk '{print $2}')
# shellcheck disable=SC2086
cc -std=c11 -DCH_RAND_EXTERN $QUIC_DEFS $SUITE_DEFS -I. -o "$TMP/szq_aes" "$TMP/szq.c"
QUIC_SESSION_AES=$("$TMP/szq_aes" | awk '{print $2}')

# PROFILE=cnsa2 under the two ML-DSA-87 trust modes (docs/decisions.md
# 157), on AES=extern, the profile's device object. Each struct and each
# floor is read from the build. The raw floor holds one certificate of
# CH_X509_MAX bytes and the CA floor two, and each is the buffer the
# static working set adds.
CNSA2_MLDSA_DEFS="-DCH_PROFILE_CNSA2 -DCH_MLKEM_1024 -DCH_SUITE_AES_GCM -DCH_AES_EXTERN"
CNSA2_MLDSA_DEFS="$CNSA2_MLDSA_DEFS -DCH_AES_EXTERN_CONSTANT_TIME -DCH_PIN_MLDSA"
# shellcheck disable=SC2086
cc -std=c11 -DCH_RAND_EXTERN $CNSA2_MLDSA_DEFS -I. -o "$TMP/sz_mldsa" "$TMP/sz.c"
SESSION_MLDSA=$("$TMP/sz_mldsa" | awk '{print $2}')
# shellcheck disable=SC2086
cc -std=c11 -DCH_RAND_EXTERN $CNSA2_MLDSA_DEFS -I. -o "$TMP/floor_mldsa" "$TMP/floor.c"
RXBUF_MLDSA=$("$TMP/floor_mldsa" | awk '{print $2}')
# shellcheck disable=SC2086
cc -std=c11 -DCH_RAND_EXTERN $CNSA2_MLDSA_DEFS -DCH_TRUST_CA -I. -o "$TMP/sz_ca_mldsa" "$TMP/sz.c"
SESSION_CA_MLDSA=$("$TMP/sz_ca_mldsa" | awk '{print $2}')
# shellcheck disable=SC2086
cc -std=c11 -DCH_RAND_EXTERN $CNSA2_MLDSA_DEFS -DCH_TRUST_CA -I. -o "$TMP/floor_ca_mldsa" "$TMP/floor.c"
RXBUF_CA_MLDSA=$("$TMP/floor_ca_mldsa" | awk '{print $2}')

# The same struct on a 32-bit target. The pointer fields are what move, so
# the host number overstates what a device needs, and the README used to
# publish only the host one with a sentence saying a 32-bit target shrinks
# them (https://github.com/c4milo/chapulin/issues/52). Nothing can run an
# rv32 binary here, so the size is read out of the object: a char array
# declared at sizeof(ch_tls) has exactly that size in the symbol table.
RV32_CLANG=$(command -v /opt/homebrew/opt/llvm/bin/clang || command -v clang || true)
RV32_NM=$(command -v llvm-nm || command -v /opt/homebrew/opt/llvm/bin/llvm-nm || true)
SESSION_RV32="unmeasured"
SESSION_RV32_PQ="unmeasured"
SESSION_RV32_WEBPKI="unmeasured"
SESSION_RV32_SERVER="unmeasured"
if [ -n "$RV32_CLANG" ] && [ -n "$RV32_NM" ]; then
    cat > "$TMP/probe.c" <<'PROBE'
#include "session.h"
char probe_ch_tls[sizeof(ch_tls)];
PROBE
    rv32_size() { # $1 = extra defines
        # shellcheck disable=SC2086
        "$RV32_CLANG" -target riscv32-unknown-elf -march=rv32ic -mabi=ilp32 -Os \
            -std=c11 -D_DEFAULT_SOURCE -DCH_RAND_EXTERN $1 -I. -c "$TMP/probe.c" \
            -o "$TMP/probe.o" 2>/dev/null || { echo "unmeasured"; return; }
        # llvm-nm prints the size in hex, and macOS awk has no strtonum.
        local hex
        hex=$("$RV32_NM" --print-size --defined-only "$TMP/probe.o" 2>/dev/null \
              | awk '/probe_ch_tls/ {print $2}')
        if [ -n "$hex" ]; then echo $((16#$hex)); else echo "unmeasured"; fi
    }
    SESSION_RV32=$(rv32_size "")
    SESSION_RV32_PQ=$(rv32_size "-DCH_KEX_PQ")
    SESSION_RV32_WEBPKI=$(rv32_size "-DCH_TRUST_WEBPKI")
    SESSION_RV32_SERVER=$(rv32_size "-DCH_ROLE_SERVER")
fi

echo "session struct:          ${SESSION} B"
echo "static working set:      $((SESSION + RXBUF)) B (with a ${RXBUF} B receive buffer)"
echo "session struct, rv32:    ${SESSION_RV32} B"
echo "session struct (KEX=pq): ${SESSION_PQ} B"
echo "static working set:      $((SESSION_PQ + RXBUF)) B (KEX=pq, ${RXBUF} B receive buffer)"
echo "session struct, rv32:    ${SESSION_RV32_PQ} B (KEX=pq)"
echo "session struct (TRUST=webpki): ${SESSION_WEBPKI} B"
echo "static working set:      $((SESSION_WEBPKI + RXBUF_WEBPKI)) B (TRUST=webpki, its ${RXBUF_WEBPKI} B floor)"
echo "session struct, rv32:    ${SESSION_RV32_WEBPKI} B (TRUST=webpki)"
echo "session struct (ROLE=server): ${SESSION_SERVER} B"
echo "static working set:      $((SESSION_SERVER + RXBUF)) B (ROLE=server, ${RXBUF} B receive buffer)"
echo "session struct, rv32:    ${SESSION_RV32_SERVER} B (ROLE=server)"
echo "session struct (ROLE=server SUITE=aesgcm): ${SESSION_SERVER_AES} B"
echo "static working set:      $((SESSION_SERVER_AES + RXBUF)) B (ROLE=server SUITE=aesgcm, ${RXBUF} B receive buffer)"
echo "session struct (TRUST=webpki SUITE=aesgcm): ${SESSION_WEBPKI_AES} B"
echo "static working set:      $((SESSION_WEBPKI_AES + RXBUF_WEBPKI_AES)) B (TRUST=webpki SUITE=aesgcm, its ${RXBUF_WEBPKI_AES} B floor)"
echo "ch_quic (ROLE=both TRUST=webpki TRANSPORT=quic-nonblocking): ${QUIC_SESSION} B"
echo "ch_quic (the same, SUITE=aesgcm): ${QUIC_SESSION_AES} B"
echo "session struct (TRUST=webpki, host object): ${SESSION_WEBPKI_HOST} B"
echo "static working set:      $((SESSION_WEBPKI_HOST + RXBUF_WEBPKI)) B (TRUST=webpki, host object, its ${RXBUF_WEBPKI} B floor)"
echo "session struct (ROLE=server, host object): ${SESSION_SERVER_HOST} B"
echo "static working set:      $((SESSION_SERVER_HOST + RXBUF)) B (ROLE=server, host object, ${RXBUF} B receive buffer)"
echo "session struct (PROFILE=cnsa2 TRUST=raw-mldsa): ${SESSION_MLDSA} B"
echo "static working set:      $((SESSION_MLDSA + RXBUF_MLDSA)) B (PROFILE=cnsa2 TRUST=raw-mldsa, its ${RXBUF_MLDSA} B floor)"
echo "session struct (PROFILE=cnsa2 TRUST=ca-mldsa): ${SESSION_CA_MLDSA} B"
echo "static working set:      $((SESSION_CA_MLDSA + RXBUF_CA_MLDSA)) B (PROFILE=cnsa2 TRUST=ca-mldsa, its ${RXBUF_CA_MLDSA} B floor)"

# Each stack.py report is saved whole, so the CSV rows below come from the
# same run the report prints. STACK_MAKE names each build by its make
# variables, and stack.py compiles the sources make packages for it. On
# this host the suite builds are host objects, whose caller states the AES
# instructions' timing at run time, so they need no flag of their own.
stack_report() { # $1 = report name, $2.. = VAR=value settings for stack.py
    local name=$1
    shift
    env "$@" python3 bench/stack.py > "$TMP/$name.stack"
}
peak() { # $1 = report name, $2 = entry point -> its peak stack in bytes
    awk -v entry="$2" '$1 == entry { print $2 }' "$TMP/$1.stack"
}

echo "-- default build (TRUST=raw-rsa); ch_connect peak = pinned RSA verify --"
stack_report default
cat "$TMP/default.stack"
echo "-- TRUST=raw-ecdsa build; ch_connect peak = pinned P-256 verify --"
stack_report ecdsa STACK_MAKE=TRUST=raw-ecdsa
head -1 "$TMP/ecdsa.stack"
echo "-- PSK-mode ch_connect (server_auth pruned: PSK never enters it) --"
stack_report psk STACK_PRUNE=hsa_server_auth
head -1 "$TMP/psk.stack"
# The two ca reports print whole, for ch_pubkey_from_pem, which only a ca
# build exports.
echo "-- TRUST=ca-rsa; ch_connect peak = chain verify + leaf frame --"
stack_report ca_rsa STACK_MAKE=TRUST=ca-rsa
cat "$TMP/ca_rsa.stack"
echo "-- TRUST=ca-ecdsa --"
stack_report ca_ecdsa STACK_MAKE=TRUST=ca-ecdsa
cat "$TMP/ca_ecdsa.stack"
echo "-- TRUST=webpki; ch_connect peak includes ML-KEM's K-PKE frames, above the chain walk --"
stack_report webpki STACK_MAKE=TRUST=webpki
head -1 "$TMP/webpki.stack"
grep '^ch_anchors_from_pem' "$TMP/webpki.stack"
# The walks below measure the figures that docs/performance.md states in
# the prose under "What the larger builds pay for". STACK_PRUNE removes the
# functions of the deepest chain, so the walk gives the next deepest one.
# HOST_TARGET= clears the Makefile's host test, so make packages the
# device object, which holds no copies over the SHA-3 instructions.
echo "-- TRUST=webpki without ML-KEM; ch_connect peak = chain walk into a P-384 verify --"
stack_report webpki_without_mlkem STACK_MAKE=TRUST=webpki \
    STACK_PRUNE=mlkem_decaps,mlkem_keygen_dk,mlkem_decaps_hw,mlkem_keygen_dk_hw
head -1 "$TMP/webpki_without_mlkem.stack"
echo "-- TRUST=webpki device object without ML-KEM; peak = chain walk into an RSA-4096 verify --"
stack_report webpki_device_without_mlkem "STACK_MAKE=TRUST=webpki HOST_TARGET=" \
    STACK_PRUNE=mlkem_decaps,mlkem_keygen_dk
head -1 "$TMP/webpki_device_without_mlkem.stack"
echo "-- KEX=pq; ch_connect peak includes ML-KEM's K-PKE frames --"
stack_report pq STACK_MAKE=KEX=pq
head -1 "$TMP/pq.stack"
echo "-- ROLE=server; ch_srv_accept peak is the deeper of the hybrid encapsulation and the RSA-PSS signer --"
stack_report server "STACK_MAKE=ROLE=server TRUST=none"
head -1 "$TMP/server.stack"
grep '^ch_chain_from_pem\|^ch_p256_key_from_pem' "$TMP/server.stack"
echo "-- ROLE=server without rsa_sign64_pss; ch_srv_accept peak = the hybrid encapsulation --"
stack_report server_without_rsa_sign64_pss "STACK_MAKE=ROLE=server TRUST=none" \
    STACK_PRUNE=rsa_sign64_pss
head -1 "$TMP/server_without_rsa_sign64_pss.stack"
echo "-- ROLE=server without rsa_sign64_pss and srv_kex_share; peak = the ECDSA signer --"
stack_report server_without_rsa_sign64_pss_srv_kex_share "STACK_MAKE=ROLE=server TRUST=none" \
    STACK_PRUNE=rsa_sign64_pss,srv_kex_share
head -1 "$TMP/server_without_rsa_sign64_pss_srv_kex_share.stack"
echo "-- ROLE=server device object; no 64-bit signer and no wide P-256 field --"
stack_report server_device "STACK_MAKE=ROLE=server TRUST=none HOST_TARGET="
head -1 "$TMP/server_device.stack"
grep '^ch_p256_key_from_pem' "$TMP/server_device.stack"
echo "-- ROLE=server device object without srv_kex_share; peak = rsa_sign.c's ladder --"
stack_report server_device_without_srv_kex_share "STACK_MAKE=ROLE=server TRUST=none HOST_TARGET=" \
    STACK_PRUNE=srv_kex_share
head -1 "$TMP/server_device_without_srv_kex_share.stack"
echo "-- ROLE=server SUITE=aesgcm; the same walk with SHA-384's schedule and the AES-GCM record path --"
stack_report server_aes "STACK_MAKE=ROLE=server TRUST=none SUITE=aesgcm"
head -1 "$TMP/server_aes.stack"
echo "-- TRUST=webpki SUITE=aesgcm --"
stack_report webpki_aes "STACK_MAKE=TRUST=webpki SUITE=aesgcm"
head -1 "$TMP/webpki_aes.stack"
# The two ML-DSA-87 builds, each walked whole and then without ML-KEM's
# two calls, which shows the deepest chain through the verifier.
CNSA2_PRUNE=STACK_PRUNE=mlkem_decaps,mlkem_keygen_dk
echo "-- PROFILE=cnsa2 TRUST=raw-mldsa; ch_connect peak = ML-KEM-1024's decapsulation --"
stack_report cnsa2_mldsa "STACK_MAKE=PROFILE=cnsa2 AES=extern TRUST=raw-mldsa" \
    STACK_CFLAGS=-DCH_AES_EXTERN_CONSTANT_TIME
head -1 "$TMP/cnsa2_mldsa.stack"
echo "-- the same without ML-KEM; peak = the ML-DSA-87 verify --"
stack_report cnsa2_mldsa_without_mlkem "STACK_MAKE=PROFILE=cnsa2 AES=extern TRUST=raw-mldsa" \
    STACK_CFLAGS=-DCH_AES_EXTERN_CONSTANT_TIME "$CNSA2_PRUNE"
head -1 "$TMP/cnsa2_mldsa_without_mlkem.stack"
echo "-- PROFILE=cnsa2 TRUST=ca-mldsa; ch_connect peak = ML-KEM-1024's decapsulation --"
stack_report cnsa2_ca_mldsa "STACK_MAKE=PROFILE=cnsa2 AES=extern TRUST=ca-mldsa" \
    STACK_CFLAGS=-DCH_AES_EXTERN_CONSTANT_TIME
head -1 "$TMP/cnsa2_ca_mldsa.stack"
echo "-- the same without ML-KEM; peak = the chain's ML-DSA-87 verify --"
stack_report cnsa2_ca_mldsa_without_mlkem "STACK_MAKE=PROFILE=cnsa2 AES=extern TRUST=ca-mldsa" \
    STACK_CFLAGS=-DCH_AES_EXTERN_CONSTANT_TIME "$CNSA2_PRUNE"
head -1 "$TMP/cnsa2_ca_mldsa_without_mlkem.stack"

# The CSV carries every column or nothing: without the rv32 toolchain the
# report above says "unmeasured", and the committed CSV keeps the last
# full measurement.
if [ "$SESSION_RV32" = unmeasured ] || [ "$SESSION_RV32_PQ" = unmeasured ] ||
    [ "$SESSION_RV32_WEBPKI" = unmeasured ] || [ "$SESSION_RV32_SERVER" = unmeasured ]; then
    echo "SKIP bench/results-sram.csv: no rv32 toolchain, so the rv32 column is unmeasured" >&2
    exit 0
fi

row() { # $1 = quantity, $2 = bytes -> one CSV line; refuses a non-number
    case "$2" in
    '' | *[!0-9]*) echo "FAIL: $1 measured as '$2', not a byte count" >&2; return 1 ;;
    esac
    echo "$1,$2"
}
# Written to a temporary file first: redirecting straight at the committed
# file would truncate it before a failing row could stop the run.
TMPOUT="$TMP/results-sram.csv"
{
    echo "quantity,bytes"
    row session_struct_arm64 "$SESSION"
    row session_struct_rv32 "$SESSION_RV32"
    row receive_buffer "$RXBUF"
    row static_working_set_arm64 "$((SESSION + RXBUF))"
    row static_working_set_rv32 "$((SESSION_RV32 + RXBUF))"
    row session_struct_pq_arm64 "$SESSION_PQ"
    row session_struct_pq_rv32 "$SESSION_RV32_PQ"
    row static_working_set_pq_arm64 "$((SESSION_PQ + RXBUF))"
    row static_working_set_pq_rv32 "$((SESSION_RV32_PQ + RXBUF))"
    row session_struct_webpki_arm64 "$SESSION_WEBPKI"
    row session_struct_webpki_rv32 "$SESSION_RV32_WEBPKI"
    row receive_buffer_webpki "$RXBUF_WEBPKI"
    row static_working_set_webpki_arm64 "$((SESSION_WEBPKI + RXBUF_WEBPKI))"
    row static_working_set_webpki_rv32 "$((SESSION_RV32_WEBPKI + RXBUF_WEBPKI))"
    row stack_connect_rsa "$(peak default ch_connect)"
    row stack_connect_ecdsa "$(peak ecdsa ch_connect)"
    row stack_connect_psk "$(peak psk ch_connect)"
    row stack_connect_ca_rsa "$(peak ca_rsa ch_connect)"
    row stack_connect_ca_ecdsa "$(peak ca_ecdsa ch_connect)"
    row stack_connect_webpki "$(peak webpki ch_connect)"
    row stack_connect_webpki_without_mlkem "$(peak webpki_without_mlkem ch_connect)"
    row stack_connect_webpki_device_without_mlkem "$(peak webpki_device_without_mlkem ch_connect)"
    row stack_read "$(peak default ch_read)"
    row stack_connect_pq "$(peak pq ch_connect)"
    row stack_write "$(peak default ch_write)"
    row stack_close "$(peak default ch_close)"
    row session_struct_server_arm64 "$SESSION_SERVER"
    row session_struct_server_rv32 "$SESSION_RV32_SERVER"
    row static_working_set_server_arm64 "$((SESSION_SERVER + RXBUF))"
    row static_working_set_server_rv32 "$((SESSION_RV32_SERVER + RXBUF))"
    row stack_accept_server "$(peak server ch_srv_accept)"
    row stack_accept_server_without_rsa_sign64_pss \
        "$(peak server_without_rsa_sign64_pss ch_srv_accept)"
    row stack_accept_server_without_rsa_sign64_pss_srv_kex_share \
        "$(peak server_without_rsa_sign64_pss_srv_kex_share ch_srv_accept)"
    row stack_accept_server_device "$(peak server_device ch_srv_accept)"
    row stack_accept_server_device_without_srv_kex_share \
        "$(peak server_device_without_srv_kex_share ch_srv_accept)"
    row stack_pubkey_from_pem_ca_rsa "$(peak ca_rsa ch_pubkey_from_pem_tcp_blocking)"
    row stack_pubkey_from_pem_ca_ecdsa "$(peak ca_ecdsa ch_pubkey_from_pem_tcp_blocking)"
    row stack_chain_from_pem "$(peak server ch_chain_from_pem_tcp_blocking)"
    row stack_p256_key_from_pem "$(peak server ch_p256_key_from_pem_tcp_blocking)"
    row stack_p256_key_from_pem_device "$(peak server_device ch_p256_key_from_pem_tcp_blocking)"
    row stack_anchors_from_pem "$(peak webpki ch_anchors_from_pem_tcp_blocking)"
    row session_struct_server_aes_arm64 "$SESSION_SERVER_AES"
    row static_working_set_server_aes_arm64 "$((SESSION_SERVER_AES + RXBUF))"
    row stack_accept_server_aes "$(peak server_aes ch_srv_accept)"
    row session_struct_webpki_aes_arm64 "$SESSION_WEBPKI_AES"
    row receive_buffer_webpki_aes "$RXBUF_WEBPKI_AES"
    row static_working_set_webpki_aes_arm64 "$((SESSION_WEBPKI_AES + RXBUF_WEBPKI_AES))"
    row stack_connect_webpki_aes "$(peak webpki_aes ch_connect)"
    row session_struct_webpki_host_arm64 "$SESSION_WEBPKI_HOST"
    row static_working_set_webpki_host_arm64 "$((SESSION_WEBPKI_HOST + RXBUF_WEBPKI))"
    row session_struct_server_host_arm64 "$SESSION_SERVER_HOST"
    row static_working_set_server_host_arm64 "$((SESSION_SERVER_HOST + RXBUF))"
    row session_struct_cnsa2_mldsa_arm64 "$SESSION_MLDSA"
    row receive_buffer_cnsa2_mldsa "$RXBUF_MLDSA"
    row static_working_set_cnsa2_mldsa_arm64 "$((SESSION_MLDSA + RXBUF_MLDSA))"
    row stack_connect_cnsa2_mldsa "$(peak cnsa2_mldsa ch_connect)"
    row stack_connect_cnsa2_mldsa_without_mlkem "$(peak cnsa2_mldsa_without_mlkem ch_connect)"
    row session_struct_cnsa2_ca_mldsa_arm64 "$SESSION_CA_MLDSA"
    row receive_buffer_cnsa2_ca_mldsa "$RXBUF_CA_MLDSA"
    row static_working_set_cnsa2_ca_mldsa_arm64 "$((SESSION_CA_MLDSA + RXBUF_CA_MLDSA))"
    row stack_connect_cnsa2_ca_mldsa "$(peak cnsa2_ca_mldsa ch_connect)"
    row stack_connect_cnsa2_ca_mldsa_without_mlkem "$(peak cnsa2_ca_mldsa_without_mlkem ch_connect)"
    row stack_pubkey_from_pem_ca_mldsa "$(peak cnsa2_ca_mldsa ch_pubkey_from_pem_tcp_blocking)"
} > "$TMPOUT"
mv "$TMPOUT" bench/results-sram.csv
echo "wrote bench/results-sram.csv" >&2
