#!/usr/bin/env bash
# The FreeRTOS lane's live rung: a TLS 1.3 handshake from a FreeRTOS
# task on QEMU's MPS2-AN385, through FreeRTOS+TCP over the emulated
# LAN9118 and QEMU's user-mode network, to a real openssl s_server on
# the host — the e2e suite's own PSK flags, with application data
# round-tripped through -rev and byte-verified on the device.
#
# The caller (make freertos-check) builds bin/freertos/tls_test and
# hands its path in; this script owns the server lifecycle.
set -euo pipefail
ELF=${1:?usage: qemu-freertos-tls.sh <tls_test.elf>}
QEMU=${QEMU:-$(command -v qemu-system-arm)}
OPENSSL=${OPENSSL:-openssl}

PSK=0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20
PORT=4433

"$OPENSSL" s_server -tls1_3 -ciphersuites TLS_CHACHA20_POLY1305_SHA256 \
    -psk "$PSK" -psk_identity device-42 -nocert -rev -accept "$PORT" -quiet \
    >/dev/null 2>&1 &
SRV=$!
trap 'kill "$SRV" 2>/dev/null || true' EXIT
sleep 1

OUT=$(timeout 90 "$QEMU" -M mps2-an385 -cpu cortex-m3 -nographic -semihosting \
    -nic user -kernel "$ELF" 2>&1 | tr -d '\r') || {
    echo "FAIL qemu-freertos-tls: the guest exited nonzero" >&2
    printf '%s\n' "$OUT" | sed 's/^/  guest: /' >&2
    exit 1
}
printf '%s\n' "$OUT" | grep -q "^PASS$" || {
    echo "FAIL qemu-freertos-tls: no PASS from the guest" >&2
    printf '%s\n' "$OUT" | sed 's/^/  guest: /' >&2
    exit 1
}
echo "qemu-freertos-tls: TLS 1.3 from a FreeRTOS task to live openssl, data verified"
