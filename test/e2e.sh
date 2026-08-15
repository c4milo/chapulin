#!/usr/bin/env bash
# End-to-end: real handshake and app data against openssl s_server running
# TLS 1.3 with an external PSK and our single suite. -rev makes the server
# echo each line reversed, proving app data moves both ways.
set -euo pipefail
cd "$(dirname "$0")/.."

OPENSSL=""
for c in /opt/homebrew/opt/openssl@3/bin/openssl /opt/homebrew/opt/openssl/bin/openssl \
         /usr/local/opt/openssl/bin/openssl openssl; do
    if command -v "$c" >/dev/null 2>&1 && "$c" version 2>/dev/null | grep -q "^OpenSSL 3"; then
        OPENSSL="$c"
        break
    fi
done
if [ -z "$OPENSSL" ]; then
    echo "SKIP e2e: OpenSSL 3 not found (brew install openssl@3)"
    exit 0
fi

PSK=0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20
ID=sapo-01
PORT=14433

"$OPENSSL" s_server -tls1_3 -ciphersuites TLS_CHACHA20_POLY1305_SHA256 \
    -psk "$PSK" -psk_identity "$ID" -nocert -accept "$PORT" -rev -quiet &
SERVER=$!
trap 'kill $SERVER 2>/dev/null || true' EXIT
sleep 1

TICKET=/tmp/ms-e2e-ticket
rm -f "$TICKET"
OUT=$(printf 'hola sapo\n' | ./bin/tlsclient 127.0.0.1 "$PORT" "$PSK" "$ID" "$TICKET" \
    2>/tmp/ms-e2e-err)
if [ "$OUT" != "opas aloh" ]; then
    echo "FAIL e2e: got '$OUT'"
    cat /tmp/ms-e2e-err
    exit 1
fi
grep -q "^ticket:" /tmp/ms-e2e-err || {
    echo "FAIL e2e: no NewSessionTicket surfaced"
    cat /tmp/ms-e2e-err
    exit 1
}
[ -s "$TICKET" ] || {
    echo "FAIL e2e: ticket not saved"
    exit 1
}

# Second connection resumes with the ticket-derived PSK: the server only
# accepts it if our resumption secret, binder label, and age math all
# match its own.
OUT=$(printf 'otra vez\n' | ./bin/tlsclient 127.0.0.1 "$PORT" "@$TICKET" - 2>/tmp/ms-e2e-err2)
if [ "$OUT" != "zev arto" ]; then
    echo "FAIL e2e resumption: got '$OUT'"
    cat /tmp/ms-e2e-err2
    exit 1
fi
grep -q "^resuming" /tmp/ms-e2e-err2 || {
    echo "FAIL e2e resumption: did not use the ticket"
    exit 1
}
echo "e2e: handshake + echo + tickets + resumption OK"
