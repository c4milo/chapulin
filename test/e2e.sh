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

# Pinned-key mode: a self-signed ECDSA P-256 server, authenticated only by
# its provisioned raw public key — no PSK anywhere.
DIR=$(mktemp -d)
trap 'kill $SERVER 2>/dev/null || true; rm -rf "$DIR"' EXIT
"$OPENSSL" ecparam -name prime256v1 -genkey -noout -out "$DIR/key.pem" 2>/dev/null
"$OPENSSL" req -x509 -key "$DIR/key.pem" -subj /CN=sapo -days 1 -out "$DIR/cert.pem" 2>/dev/null
# Raw X||Y: the uncompressed point from the key, minus the 0x04 prefix.
PUB=$("$OPENSSL" ec -in "$DIR/key.pem" -text -noout 2>/dev/null | awk '/^pub:/{f=1;next} f&&/^[^ ]/{f=0} f{gsub(/[ :]/,"");printf "%s",$0}' | cut -c3-130)
[ ${#PUB} -eq 128 ] || {
    echo "FAIL e2e pin: could not extract server public key"
    exit 1
}

PORT2=14435
"$OPENSSL" s_server -tls1_3 -ciphersuites TLS_CHACHA20_POLY1305_SHA256 \
    -cert "$DIR/cert.pem" -key "$DIR/key.pem" -accept "$PORT2" -rev -quiet &
SERVER2=$!
trap 'kill $SERVER $SERVER2 2>/dev/null || true; rm -rf "$DIR"' EXIT
sleep 1

TICKET2=/tmp/ms-e2e-ticket2
rm -f "$TICKET2"
OUT=$(printf 'sin secretos\n' | ./bin/tlsclient 127.0.0.1 "$PORT2" "pin:$PUB" - "$TICKET2" \
    2>/tmp/ms-e2e-err3)
if [ "$OUT" != "soterces nis" ]; then
    echo "FAIL e2e pin: got '$OUT'"
    cat /tmp/ms-e2e-err3
    exit 1
fi
# And the pinned handshake still yields tickets, so reconnects resume.
if [ -s "$TICKET2" ]; then
    OUT=$(printf 'de nuevo\n' | ./bin/tlsclient 127.0.0.1 "$PORT2" "@$TICKET2" - 2>/dev/null)
    if [ "$OUT" != "oveun ed" ]; then
        echo "FAIL e2e pin-resume: got '$OUT'"
        exit 1
    fi
fi

# The real target: Go's crypto/tls, the stack Prometheus terminates with.
if command -v go >/dev/null 2>&1; then
    PORT3=14436
    # Build first so the server starts instantly, and run the binary
    # directly: go run's child would outlive a kill of the subshell and
    # hold pipes open past the script's exit.
    (cd test/goecho && go build -o "$DIR/goecho" .)
    "$DIR/goecho" -cert "$DIR/cert.pem" -key "$DIR/key.pem" \
        -addr "127.0.0.1:$PORT3" >/dev/null 2>&1 &
    SERVER3=$!
    trap 'kill $SERVER $SERVER2 $SERVER3 2>/dev/null || true; rm -rf "$DIR"' EXIT
    for i in $(seq 1 20); do
        nc -z 127.0.0.1 "$PORT3" 2>/dev/null && break
        sleep 0.5
    done
    OUT=$(printf 'hola go\n' | ./bin/tlsclient 127.0.0.1 "$PORT3" "pin:$PUB" - 2>/tmp/ms-e2e-err4)
    if [ "$OUT" != "og aloh" ]; then
        echo "FAIL e2e go: got '$OUT'"
        cat /tmp/ms-e2e-err4
        exit 1
    fi
    GO_LEG=" + go"
else
    GO_LEG=" (go leg skipped)"
fi

echo "e2e: psk + tickets + resumption + pinned-key${GO_LEG} OK"
