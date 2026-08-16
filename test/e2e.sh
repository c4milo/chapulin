#!/usr/bin/env bash
# End-to-end: real handshakes and app data against openssl s_server and a Go
# crypto/tls server, all TLS 1.3 with our single suite. -rev echoes each
# line reversed, proving app data moves both ways.
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

# One temp dir holds every server key, ticket, and stderr file, so two runs
# on the same host never share a path.
DIR=$(mktemp -d)
trap 'kill ${SERVER:-} ${SERVER2:-} ${SERVER3:-} ${SERVER4:-} ${SERVER5:-} 2>/dev/null || true
      rm -rf "$DIR"' EXIT

# Each run takes a disjoint 5-port slot. Multiplying the slot index by 8
# keeps adjacent PIDs from overlapping slots.
PORT=$((20000 + ($$ % 5000) * 8))
PORT2=$((PORT + 1))
PORT3=$((PORT + 2))
PORT4=$((PORT + 3))
PORT5=$((PORT + 4))

PSK=0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20
ID=sapo-01

# Waits until pid listens on port; fails if the process exits first (for
# example when the port was taken and the server could not bind). Uses a
# bash TCP probe so no netcat is required.
wait_listen() {
    local pid=$1 port=$2
    for _ in $(seq 1 40); do
        kill -0 "$pid" 2>/dev/null || {
            echo "FAIL e2e: server on port $port died at startup"
            exit 1
        }
        (exec 3<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null && {
            exec 3>&- 2>/dev/null || true
            return 0
        }
        sleep 0.5
    done
    echo "FAIL e2e: server on port $port never came up"
    exit 1
}

# Runs the client and checks its reply. Args: label, expected reply, stderr
# file, then the client argv. A nonzero exit or a wrong reply prints the
# saved stderr and stops the script — the failure diagnostics stay reachable
# under set -e, which a bare OUT=$(...) assignment would swallow.
expect() {
    local label=$1 want=$2 err=$3
    shift 3
    local out
    if ! out=$(printf '%s\n' "$MSG" | "$@" 2>"$err"); then
        echo "FAIL $label: client exited nonzero"
        cat "$err"
        exit 1
    fi
    if [ "$out" != "$want" ]; then
        echo "FAIL $label: got '$out'"
        cat "$err"
        exit 1
    fi
}

# --- PSK: external key, then resume with the issued ticket ---
"$OPENSSL" s_server -tls1_3 -ciphersuites TLS_CHACHA20_POLY1305_SHA256 \
    -psk "$PSK" -psk_identity "$ID" -nocert -accept "$PORT" -rev -quiet &
SERVER=$!
wait_listen $SERVER "$PORT"

MSG='hola sapo'
expect psk "opas aloh" "$DIR/err" ./bin/tlsclient 127.0.0.1 "$PORT" "$PSK" "$ID" "$DIR/ticket"
grep -q "^ticket:" "$DIR/err" || {
    echo "FAIL e2e: no NewSessionTicket surfaced"
    cat "$DIR/err"
    exit 1
}
[ -s "$DIR/ticket" ] || {
    echo "FAIL e2e: ticket not saved"
    exit 1
}

# The server accepts the ticket-derived PSK only if our resumption secret,
# binder label, and age math all match its own.
MSG='otra vez'
expect resumption "zev arto" "$DIR/err2" ./bin/tlsclient 127.0.0.1 "$PORT" "@$DIR/ticket" -
grep -q "^resuming" "$DIR/err2" || {
    echo "FAIL e2e resumption: did not use the ticket"
    exit 1
}

# --- Pinned key, ECDSA build: a self-signed P-256 server, authenticated
# only by its provisioned raw public key, no PSK anywhere ---
"$OPENSSL" ecparam -name prime256v1 -genkey -noout -out "$DIR/key.pem" 2>/dev/null
"$OPENSSL" req -x509 -key "$DIR/key.pem" -subj /CN=sapo -days 1 -out "$DIR/cert.pem" 2>/dev/null
# Raw X||Y: the uncompressed point from the key, minus the 0x04 prefix.
PUB=$("$OPENSSL" ec -in "$DIR/key.pem" -text -noout 2>/dev/null \
    | awk '/^pub:/{f=1;next} f&&/^[^ ]/{f=0} f{gsub(/[ :]/,"");printf "%s",$0}' | cut -c3-130)
[ ${#PUB} -eq 128 ] || {
    echo "FAIL e2e pin: could not extract server public key"
    exit 1
}

"$OPENSSL" s_server -tls1_3 -ciphersuites TLS_CHACHA20_POLY1305_SHA256 \
    -cert "$DIR/cert.pem" -key "$DIR/key.pem" -accept "$PORT2" -rev -quiet &
SERVER2=$!
wait_listen $SERVER2 "$PORT2"

MSG='sin secretos'
expect pin-ecdsa "soterces nis" "$DIR/err3" \
    ./bin/tlsclient_ecdsa 127.0.0.1 "$PORT2" "pin:$PUB" - "$DIR/ticket2"
# The pinned handshake must also yield tickets, so reconnects resume.
[ -s "$DIR/ticket2" ] || {
    echo "FAIL e2e pin: no ticket after a pinned handshake"
    exit 1
}
MSG='de nuevo'
expect pin-ecdsa-resume "oveun ed" "$DIR/err3" ./bin/tlsclient_ecdsa 127.0.0.1 "$PORT2" "@$DIR/ticket2" -

# --- Pinned key, default build: a self-signed RSA-3072 server, the pin is
# the raw modulus and the signature is RSA-PSS. The cert's own signature
# is the stock PKCS#1 v1.5 self-signature: the client never parses it, so
# only CertificateVerify must be PSS ---
"$OPENSSL" genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 \
    -out "$DIR/rsakey.pem" 2>/dev/null
"$OPENSSL" req -x509 -key "$DIR/rsakey.pem" -subj /CN=chapulin -days 1 \
    -out "$DIR/rsacert.pem" 2>/dev/null
MOD=$("$OPENSSL" rsa -in "$DIR/rsakey.pem" -noout -modulus 2>/dev/null \
    | sed 's/^Modulus=//' | tr 'A-F' 'a-f')
[ ${#MOD} -eq 768 ] || {
    echo "FAIL e2e rsa: could not extract the server modulus"
    exit 1
}

"$OPENSSL" s_server -tls1_3 -ciphersuites TLS_CHACHA20_POLY1305_SHA256 \
    -cert "$DIR/rsacert.pem" -key "$DIR/rsakey.pem" -accept "$PORT4" -rev -quiet &
SERVER4=$!
wait_listen $SERVER4 "$PORT4"

MSG='clave grande'
expect pin-rsa "ednarg evalc" "$DIR/err5" \
    ./bin/tlsclient 127.0.0.1 "$PORT4" "pin:$MOD" - "$DIR/ticket4"
[ -s "$DIR/ticket4" ] || {
    echo "FAIL e2e rsa: no ticket after a pinned handshake"
    exit 1
}
MSG='otra ronda'
expect pin-rsa-resume "adnor arto" "$DIR/err5" ./bin/tlsclient 127.0.0.1 "$PORT4" "@$DIR/ticket4" -

# --- Go's crypto/tls, the stack Prometheus terminates with: once with the
# P-256 cert against the ECDSA build, once with the RSA cert against the
# default build ---
if command -v go >/dev/null 2>&1; then
    # Build first so the server starts instantly, and run the binary
    # directly: go run's child would outlive a kill of the subshell and
    # hold pipes open past the script's exit.
    (cd test/goecho && go build -o "$DIR/goecho" .)
    "$DIR/goecho" -cert "$DIR/cert.pem" -key "$DIR/key.pem" -addr "127.0.0.1:$PORT3" \
        >/dev/null 2>&1 &
    SERVER3=$!
    "$DIR/goecho" -cert "$DIR/rsacert.pem" -key "$DIR/rsakey.pem" -addr "127.0.0.1:$PORT5" \
        >/dev/null 2>&1 &
    SERVER5=$!
    wait_listen $SERVER3 "$PORT3"
    wait_listen $SERVER5 "$PORT5"

    MSG='hola go'
    expect go-ecdsa "og aloh" "$DIR/err4" \
        ./bin/tlsclient_ecdsa 127.0.0.1 "$PORT3" "pin:$PUB" - "$DIR/ticket3"
    # Go issues tickets only when the hello offers psk_dhe_ke; resuming here
    # proves both the offer and the resumption path against Go.
    [ -s "$DIR/ticket3" ] || {
        echo "FAIL e2e go: no ticket from the Go server"
        exit 1
    }
    MSG='una mas'
    expect go-ecdsa-resume "sam anu" "$DIR/err4" ./bin/tlsclient_ecdsa 127.0.0.1 "$PORT3" "@$DIR/ticket3" -

    MSG='go grande'
    expect go-rsa "ednarg og" "$DIR/err6" \
        ./bin/tlsclient 127.0.0.1 "$PORT5" "pin:$MOD" - "$DIR/ticket5"
    [ -s "$DIR/ticket5" ] || {
        echo "FAIL e2e go-rsa: no ticket from the Go server"
        exit 1
    }
    MSG='ultima'
    expect go-rsa-resume "amitlu" "$DIR/err6" ./bin/tlsclient 127.0.0.1 "$PORT5" "@$DIR/ticket5" -
    GO_LEG=" + go x2 + go-resume x2"
else
    GO_LEG=" (go legs skipped)"
fi

echo "e2e: psk + tickets + resumption + pinned ecdsa + pinned rsa${GO_LEG} OK"
