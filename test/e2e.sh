#!/usr/bin/env bash
# End-to-end: real handshakes and app data against openssl s_server and a Go
# crypto/tls server, all TLS 1.3 with our single suite. -rev echoes each
# line reversed, proving app data moves both ways.
set -euo pipefail

# Several openssl calls send stderr to /dev/null so the transcript stays
# readable, which means set -e can kill the run with nothing printed.
# Twice that hid a real break, so say where it happened.
trap 'rc=$?; [ $rc -eq 0 ] || echo "FAIL e2e: aborted at line $LINENO (exit $rc)" >&2' ERR
cd "$(dirname "$0")/.."

# OPENSSL from the environment wins, so a caller can point the suite at
# a specific build; otherwise take the first OpenSSL 3 on the usual
# paths. Either way the choice must be OpenSSL 3.
OPENSSL_WANTED="${OPENSSL:-}"
OPENSSL=""
for c in "$OPENSSL_WANTED" /opt/homebrew/opt/openssl@3/bin/openssl \
         /opt/homebrew/opt/openssl/bin/openssl \
         /usr/local/opt/openssl/bin/openssl openssl; do
    [ -n "$c" ] || continue
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
# Every start_server/start_goecho appends its pid to SRV_PIDS, so this
# kills all of them without a hand-maintained list to fall behind.
SRV_PIDS=""
trap 'kill $SRV_PIDS 2>/dev/null || true; rm -rf "$DIR"' EXIT

# Nothing here picks a port. Each server binds port 0, the kernel
# assigns a free one, and the helpers below read it back — so two runs
# on one machine cannot collide however many servers either starts.
SRV_N=0

PSK=0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20
ID=sapo-01

# Waits until pid listens on port; fails if the process exits first (for
# example when the port was taken and the server could not bind). Uses a
# bash TCP probe so no netcat is required.
# Starts an s_server on a kernel-assigned port. Sets SRV_PID and
# SRV_PORT. Every argument is passed through, so a caller adds only what
# its leg needs. -quiet is deliberately absent: it suppresses the ACCEPT
# line this reads the port from, and the server's chatter goes to a log
# rather than the console anyway.
start_server() {
    SRV_N=$((SRV_N + 1))
    local log="$DIR/server$SRV_N.log"
    "$OPENSSL" s_server "$@" -accept 0 > "$log" 2>&1 &
    SRV_PID=$!
    SRV_PIDS="$SRV_PIDS $SRV_PID"
    disown "$SRV_PID" 2>/dev/null || true
    read_port "$SRV_PID" "$log" 's/^ACCEPT .*:\([0-9][0-9]*\)$/\1/p'
}

# The same for the Go echo server, which prints Go's own Addr().
start_goecho() {
    SRV_N=$((SRV_N + 1))
    local log="$DIR/server$SRV_N.log"
    "$DIR/goecho" "$@" -addr 127.0.0.1:0 > "$log" 2>&1 &
    SRV_PID=$!
    SRV_PIDS="$SRV_PIDS $SRV_PID"
    disown "$SRV_PID" 2>/dev/null || true
    read_port "$SRV_PID" "$log" 's/.*listening on .*:\([0-9][0-9]*\)$/\1/p'
}

# Waits for a just-started server to report the port it bound, and
# leaves it in SRV_PORT. A server that exits first is a configuration
# error worth showing, so its log goes to the console.
read_port() {
    local pid=$1 log=$2 script=$3
    for _ in $(seq 1 40); do
        SRV_PORT=$(sed -n "$script" "$log" 2>/dev/null | head -1)
        [ -n "$SRV_PORT" ] && return 0
        kill -0 "$pid" 2>/dev/null || {
            echo "FAIL e2e: server exited before it reported a port"
            cat "$log"
            exit 1
        }
        sleep 0.25
    done
    echo "FAIL e2e: server never reported a port"
    cat "$log"
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

# Runs the client expecting the handshake to fail with the given ch_err
# code. Args: label, expected code, stderr file, then the client argv.
expect_fail() {
    local label=$1 rc=$2 err=$3
    shift 3
    if printf '%s\n' "$MSG" | "$@" >/dev/null 2>"$err"; then
        echo "FAIL $label: handshake unexpectedly succeeded"
        cat "$err"
        exit 1
    fi
    grep -q "^handshake failed: $rc\$" "$err" || {
        echo "FAIL $label: expected handshake failure $rc"
        cat "$err"
        exit 1
    }
}

# Pin-string extractors for the CA legs. RSA builds pin the modulus as
# lowercase hex; ECDSA builds pin the raw X||Y point from the key.
rsa_modulus() {
    "$OPENSSL" rsa -in "$1" -noout -modulus 2>/dev/null \
        | sed 's/^Modulus=//' | tr 'A-F' 'a-f'
}
# The examples read a pin from a file holding the raw bytes, the way a
# device reads it from provisioned flash; the test client takes hex on
# its command line instead. python3 is already a dependency here.
hex_to_file() {
    python3 -c 'import sys,binascii;open(sys.argv[2],"wb").write(binascii.unhexlify(sys.argv[1]))' "$1" "$2"
}
p256_pub() {
    "$OPENSSL" ec -in "$1" -text -noout 2>/dev/null \
        | awk '/^pub:/{f=1;next} f&&/^[^ ]/{f=0} f{gsub(/[ :]/,"");printf "%s",$0}' | cut -c3-130
}

# --- PSK: external key, then resume with the issued ticket ---
start_server -tls1_3 -ciphersuites TLS_CHACHA20_POLY1305_SHA256 -psk "$PSK" -psk_identity "$ID" -nocert -rev
PORT=$SRV_PORT

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

# --- The examples, run rather than merely compiled. Building them
# catches a changed signature; only running them catches a changed
# meaning, which is the failure a compiled-only example hides. Each
# reuses a server an earlier leg already started.
#
# psk_client runs two sessions of its own: the first on the provisioned
# key, the second on the ticket the first stored, so one run covers both.
# The server is started with the identity psk_client.c's own header
# tells a reader to use, so this leg checks the documented recipe and
# not a variant of it.
start_server -tls1_3 -ciphersuites TLS_CHACHA20_POLY1305_SHA256 -psk "$PSK" -psk_identity device-42 -nocert -rev
PORT16=$SRV_PORT
expect example-psk "opas aloh
opas aloh" "$DIR/err_ex_psk" ./bin/example_psk 127.0.0.1 "$PORT16"
grep -q "connected with a stored ticket" "$DIR/err_ex_psk" || {
    echo "FAIL example-psk: the second session did not resume"
    cat "$DIR/err_ex_psk"
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

start_server -tls1_3 -ciphersuites TLS_CHACHA20_POLY1305_SHA256 -cert "$DIR/cert.pem" -key "$DIR/key.pem" -rev
PORT2=$SRV_PORT

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

start_server -tls1_3 -ciphersuites TLS_CHACHA20_POLY1305_SHA256 -cert "$DIR/rsacert.pem" -key "$DIR/rsakey.pem" -rev
SERVER4=$SRV_PID
PORT4=$SRV_PORT

MSG='clave grande'
expect pin-rsa "ednarg evalc" "$DIR/err5" \
    ./bin/tlsclient 127.0.0.1 "$PORT4" "pin:$MOD" - "$DIR/ticket4"
[ -s "$DIR/ticket4" ] || {
    echo "FAIL e2e rsa: no ticket after a pinned handshake"
    exit 1
}
MSG='otra ronda'
expect pin-rsa-resume "adnor arto" "$DIR/err5" ./bin/tlsclient 127.0.0.1 "$PORT4" "@$DIR/ticket4" -

# --- Rotation (docs/rotation.md): stage a second RSA key as slot B, then
# restart the server on it. Against the old server both pins match slot A;
# against the new one the same client must report slot B — a key switch
# with no client re-provisioning ---
"$OPENSSL" genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 \
    -out "$DIR/rsakey2.pem" 2>/dev/null
"$OPENSSL" req -x509 -key "$DIR/rsakey2.pem" -subj /CN=chapulin -days 1 \
    -out "$DIR/rsacert2.pem" 2>/dev/null
MOD2=$("$OPENSSL" rsa -in "$DIR/rsakey2.pem" -noout -modulus 2>/dev/null \
    | sed 's/^Modulus=//' | tr 'A-F' 'a-f')
[ ${#MOD2} -eq 768 ] || {
    echo "FAIL e2e rotation: could not extract the next modulus"
    exit 1
}

MSG='todavia la vieja'
expect rotate-old "ajeiv al aivadot" "$DIR/err7" \
    ./bin/tlsclient 127.0.0.1 "$PORT4" "pin:$MOD,$MOD2" -
grep -q "^pin slot 1$" "$DIR/err7" || {
    echo "FAIL e2e rotation: old server did not report slot 1"
    cat "$DIR/err7"
    exit 1
}

# The pinned example against the same RSA server, reading its pin from
# a file the way a device reads provisioned flash.
hex_to_file "$MOD" "$DIR/pin_a.bin"
expect example-pinned "gnip" "$DIR/err_ex_pin" \
    ./bin/example_pinned 127.0.0.1 "$PORT4" "$DIR/pin_a.bin"

kill $SERVER4 2>/dev/null || true
wait $SERVER4 2>/dev/null || true
start_server -tls1_3 -ciphersuites TLS_CHACHA20_POLY1305_SHA256 -cert "$DIR/rsacert2.pem" -key "$DIR/rsakey2.pem" -rev
PORT6=$SRV_PORT

MSG='clave nueva'
expect rotate-new "aveun evalc" "$DIR/err7" \
    ./bin/tlsclient 127.0.0.1 "$PORT6" "pin:$MOD,$MOD2" -
grep -q "^pin slot 2$" "$DIR/err7" || {
    echo "FAIL e2e rotation: rotated server did not report slot 2"
    cat "$DIR/err7"
    exit 1
}

# --- CA mode, RSA build: a root -> intermediate -> leaf hierarchy per
# docs/ca.md, all RSA-PSS. The client pins the root modulus and verifies
# the presented chain. s_server must get the intermediate via -cert_chain:
# extra certificates appended to the -cert file are silently dropped.
cat > "$DIR/leaf.cnf" <<'EOF'
keyUsage = critical, digitalSignature
extendedKeyUsage = serverAuth
basicConstraints = CA:FALSE
EOF
cat > "$DIR/int.cnf" <<'EOF'
basicConstraints = critical, CA:TRUE, pathlen:0
keyUsage = critical, keyCertSign, cRLSign
EOF
PSS=(-sha256 -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:32)

"$OPENSSL" genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 \
    -out "$DIR/caroot.key" 2>/dev/null
"$OPENSSL" req -new -x509 -key "$DIR/caroot.key" -subj /CN=fleet-root -days 3650 \
    "${PSS[@]}" -out "$DIR/caroot.pem" 2>/dev/null
"$OPENSSL" genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 \
    -out "$DIR/caint.key" 2>/dev/null
"$OPENSSL" req -new -key "$DIR/caint.key" -subj /CN=fleet-intermediate 2>/dev/null |
"$OPENSSL" x509 -req -CA "$DIR/caroot.pem" -CAkey "$DIR/caroot.key" -days 365 \
    "${PSS[@]}" -extfile "$DIR/int.cnf" -out "$DIR/caint.pem" 2>/dev/null
"$OPENSSL" genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 \
    -out "$DIR/caleaf.key" 2>/dev/null
"$OPENSSL" req -new -key "$DIR/caleaf.key" -subj /CN=controller-01 2>/dev/null |
"$OPENSSL" x509 -req -CA "$DIR/caint.pem" -CAkey "$DIR/caint.key" -days 14 \
    "${PSS[@]}" -extfile "$DIR/leaf.cnf" -out "$DIR/caleaf.pem" 2>/dev/null
# Flat variant: the root signs the same leaf key directly.
"$OPENSSL" req -new -key "$DIR/caleaf.key" -subj /CN=controller-01 2>/dev/null |
"$OPENSSL" x509 -req -CA "$DIR/caroot.pem" -CAkey "$DIR/caroot.key" -days 14 \
    "${PSS[@]}" -extfile "$DIR/leaf.cnf" -out "$DIR/caflat.pem" 2>/dev/null
CAMOD=$(rsa_modulus "$DIR/caroot.key")
[ ${#CAMOD} -eq 768 ] || {
    echo "FAIL e2e ca-rsa: could not extract the root modulus"
    exit 1
}

start_server -tls1_3 -ciphersuites TLS_CHACHA20_POLY1305_SHA256 -cert "$DIR/caleaf.pem" -key "$DIR/caleaf.key" -cert_chain "$DIR/caint.pem" -rev
PORT7=$SRV_PORT
start_server -tls1_3 -ciphersuites TLS_CHACHA20_POLY1305_SHA256 -cert "$DIR/caflat.pem" -key "$DIR/caleaf.key" -rev
PORT8=$SRV_PORT

MSG='cadena firmada'
expect ca-rsa "adamrif anedac" "$DIR/err8" \
    ./bin/tlsclient_ca 127.0.0.1 "$PORT7" "ca:$CAMOD" -
MSG='hoja directa'
expect ca-rsa-flat "atcerid ajoh" "$DIR/err8" \
    ./bin/tlsclient_ca 127.0.0.1 "$PORT8" "ca:$CAMOD" -

# The CA example against the same chain server, reading the root's
# modulus from a file. Its epoch callbacks stay off here: the epoch legs
# below cover that path, and this leg is about the chain check.
hex_to_file "$CAMOD" "$DIR/ca_key.bin"
expect example-ca "odatse" "$DIR/err_ex_ca" \
    ./bin/example_ca 127.0.0.1 "$PORT7" "$DIR/ca_key.bin"
grep -q "CA pin slot 1" "$DIR/err_ex_ca" || {
    echo "FAIL example-ca: did not report the slot that verified"
    cat "$DIR/err_ex_ca"
    exit 1
}

# --- CA slot rotation: slot A holds a stranger's key, slot B the real
# root; the handshake must land on slot 2, mirroring pinned-key rotation.
"$OPENSSL" genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 \
    -out "$DIR/wrongroot.key" 2>/dev/null
"$OPENSSL" req -new -x509 -key "$DIR/wrongroot.key" -subj /CN=other-root -days 3650 \
    "${PSS[@]}" -out "$DIR/wrongroot.pem" 2>/dev/null
WRONGMOD=$(rsa_modulus "$DIR/wrongroot.key")

MSG='segunda ranura'
expect ca-rotation "arunar adnuges" "$DIR/err9" \
    ./bin/tlsclient_ca 127.0.0.1 "$PORT7" "ca:$WRONGMOD,$CAMOD" -
grep -q "^pin slot 2$" "$DIR/err9" || {
    echo "FAIL e2e ca-rotation: client did not report CA slot 2"
    cat "$DIR/err9"
    exit 1
}

# --- CA mode, ECDSA build: the same hierarchy in P-256; OpenSSL signs
# ecdsa-with-SHA256 by default, so the PSS sigopts drop out.
"$OPENSSL" ecparam -name prime256v1 -genkey -noout -out "$DIR/ecroot.key" 2>/dev/null
"$OPENSSL" req -new -x509 -key "$DIR/ecroot.key" -subj /CN=fleet-root -days 3650 \
    -out "$DIR/ecroot.pem" 2>/dev/null
"$OPENSSL" ecparam -name prime256v1 -genkey -noout -out "$DIR/ecint.key" 2>/dev/null
"$OPENSSL" req -new -key "$DIR/ecint.key" -subj /CN=fleet-intermediate 2>/dev/null |
"$OPENSSL" x509 -req -CA "$DIR/ecroot.pem" -CAkey "$DIR/ecroot.key" -days 365 \
    -extfile "$DIR/int.cnf" -out "$DIR/ecint.pem" 2>/dev/null
"$OPENSSL" ecparam -name prime256v1 -genkey -noout -out "$DIR/ecleaf.key" 2>/dev/null
"$OPENSSL" req -new -key "$DIR/ecleaf.key" -subj /CN=controller-01 2>/dev/null |
"$OPENSSL" x509 -req -CA "$DIR/ecint.pem" -CAkey "$DIR/ecint.key" -days 14 \
    -extfile "$DIR/leaf.cnf" -out "$DIR/ecleaf.pem" 2>/dev/null
"$OPENSSL" req -new -key "$DIR/ecleaf.key" -subj /CN=controller-01 2>/dev/null |
"$OPENSSL" x509 -req -CA "$DIR/ecroot.pem" -CAkey "$DIR/ecroot.key" -days 14 \
    -extfile "$DIR/leaf.cnf" -out "$DIR/ecflat.pem" 2>/dev/null
ECROOTPUB=$(p256_pub "$DIR/ecroot.key")
[ ${#ECROOTPUB} -eq 128 ] || {
    echo "FAIL e2e ca-ecdsa: could not extract the root public key"
    exit 1
}

start_server -tls1_3 -ciphersuites TLS_CHACHA20_POLY1305_SHA256 -cert "$DIR/ecleaf.pem" -key "$DIR/ecleaf.key" -cert_chain "$DIR/ecint.pem" -rev
PORT9=$SRV_PORT
start_server -tls1_3 -ciphersuites TLS_CHACHA20_POLY1305_SHA256 -cert "$DIR/ecflat.pem" -key "$DIR/ecleaf.key" -rev
PORT10=$SRV_PORT

MSG='curva chica'
expect ca-ecdsa "acihc avruc" "$DIR/err10" \
    ./bin/tlsclient_ca_ecdsa 127.0.0.1 "$PORT9" "ca:$ECROOTPUB" -
MSG='sin intermedia'
expect ca-ecdsa-flat "aidemretni nis" "$DIR/err10" \
    ./bin/tlsclient_ca_ecdsa 127.0.0.1 "$PORT10" "ca:$ECROOTPUB" -

# --- CA negatives, each a distinct rejection class. First: a leaf from
# a CA the client does not pin fails authentication (CH_EAUTH is -3).
"$OPENSSL" req -new -key "$DIR/caleaf.key" -subj /CN=controller-01 2>/dev/null |
"$OPENSSL" x509 -req -CA "$DIR/wrongroot.pem" -CAkey "$DIR/wrongroot.key" -days 14 \
    "${PSS[@]}" -extfile "$DIR/leaf.cnf" -out "$DIR/wrongleaf.pem" 2>/dev/null
start_server -tls1_3 -ciphersuites TLS_CHACHA20_POLY1305_SHA256 -cert "$DIR/wrongleaf.pem" -key "$DIR/caleaf.key" -rev
PORT11=$SRV_PORT
MSG='no debe pasar'
expect_fail ca-wrong-ca -3 "$DIR/err11" \
    ./bin/tlsclient_ca 127.0.0.1 "$PORT11" "ca:$CAMOD" -

# Second: three certificate entries. The profile admits one or two —
# the root never travels — so leaf + intermediate + root must fail the
# handshake even though every signature would check out (CH_EPROTO, -2).
cat "$DIR/caint.pem" "$DIR/caroot.pem" > "$DIR/chain3.pem"
start_server -tls1_3 -ciphersuites TLS_CHACHA20_POLY1305_SHA256 -cert "$DIR/caleaf.pem" -key "$DIR/caleaf.key" -cert_chain "$DIR/chain3.pem" -rev
PORT12=$SRV_PORT
expect_fail ca-three-entries -2 "$DIR/err12" \
    ./bin/tlsclient_ca 127.0.0.1 "$PORT12" "ca:$CAMOD" -

# Third: a non-canonical re-encoding. Rewrite the flat leaf's TBS length
# as three-byte long form with a leading zero — same value, one more
# byte — and grow the outer length to match. OpenSSL serves the TBS
# bytes it parsed, so the mangled length reaches the wire; a mangled
# OUTER length would be re-encoded minimal and never leave the server.
# The strict decoder must refuse the non-minimal length (CH_EPROTO, -2).
"$OPENSSL" x509 -in "$DIR/caflat.pem" -outform DER -out "$DIR/caflat.der"
python3 - "$DIR/caflat.der" "$DIR/mangled.pem" <<'EOF'
import base64, sys
der = open(sys.argv[1], 'rb').read()
assert der[0] == 0x30 and der[1] == 0x82 and der[4] == 0x30 and der[5] == 0x82
outer = int.from_bytes(der[2:4], 'big') + 1
out = der[:2] + outer.to_bytes(2, 'big') + bytes([0x30, 0x83, 0x00, der[6], der[7]]) + der[8:]
pem = base64.encodebytes(out).decode()
open(sys.argv[2], 'w').write('-----BEGIN CERTIFICATE-----\n' + pem + '-----END CERTIFICATE-----\n')
EOF
start_server -tls1_3 -ciphersuites TLS_CHACHA20_POLY1305_SHA256 -cert "$DIR/mangled.pem" -key "$DIR/caleaf.key" -rev
PORT13=$SRV_PORT
expect_fail ca-noncanonical -2 "$DIR/err13" \
    ./bin/tlsclient_ca 127.0.0.1 "$PORT13" "ca:$CAMOD" -

# --- The monotonic revocation epoch: a leaf whose notBefore is an epoch
# date rather than an issuance time, a bump that revokes it, and the
# replays the bump must kill (docs/ca.md). Epoch 2 is 000103000000Z and
# epoch 3 is 000104000000Z; notAfter stays 491231235959Z so wall-clock
# tooling keeps working.
# Epoch dates need an absolute notBefore, which `x509 -req` gained in
# OpenSSL 3.4. `ca -startdate` would reach further back but needs
# -sigopt for PSS, and issuing v1.5 instead would be a silently wrong
# certificate rather than a failure. So the legs skip on an older
# OpenSSL rather than test a recipe docs/ca.md does not give. CI pins
# the development version, so they always run there.
if "$OPENSSL" x509 -help 2>&1 | grep -q -- '-not_before'; then
    EPOCH_LEGS=yes
else
    EPOCH_LEGS=no
    echo "SKIP ca epoch legs: $("$OPENSSL" version) predates x509 -not_before (needs 3.4)"
fi

epoch_leaf() {
    local date=$1 out=$2
    "$OPENSSL" req -new -key "$DIR/caleaf.key" -subj /CN=controller-01 \
        -out "$DIR/epoch.csr" 2>/dev/null
    "$OPENSSL" x509 -req -in "$DIR/epoch.csr" -CA "$DIR/caint.pem" \
        -CAkey "$DIR/caint.key" -not_before "$date" -not_after 491231235959Z \
        "${PSS[@]}" -extfile "$DIR/leaf.cnf" -out "$out" 2>/dev/null
    [ -s "$out" ] || { echo "FAIL e2e ca-epoch: could not issue at $date"; exit 1; }
}

EPOCH_LEG=""
if [ "$EPOCH_LEGS" = yes ]; then
    EPOCH_LEG=" + ca epoch x6"
epoch_leaf 000103000000Z "$DIR/epoch2.pem"
epoch_leaf 000104000000Z "$DIR/epoch3.pem"

start_server -tls1_3 -ciphersuites TLS_CHACHA20_POLY1305_SHA256 -cert "$DIR/epoch2.pem" -key "$DIR/caleaf.key" -cert_chain "$DIR/caint.pem" -rev
SERVER14=$SRV_PID
PORT14=$SRV_PORT
start_server -tls1_3 -ciphersuites TLS_CHACHA20_POLY1305_SHA256 -cert "$DIR/epoch3.pem" -key "$DIR/caleaf.key" -cert_chain "$DIR/caint.pem" -rev
SERVER15=$SRV_PID
PORT15=$SRV_PORT

# A device provisioned at the current epoch connects and stays put.
echo 2 > "$DIR/epoch.state"
MSG='epoca dos'
expect ca-epoch-equal "sod acope" "$DIR/err14" \
    ./bin/tlsclient_ca 127.0.0.1 "$PORT14" "ca:$CAMOD" - - "$DIR/epoch.state"
grep -q "^epoch 2 store_failed 0$" "$DIR/err14" || {
    echo "FAIL e2e ca-epoch-equal: the epoch moved when it should not have"
    exit 1
}

# A device that lags moves forward, and the new epoch is written.
echo 1 > "$DIR/epoch.state"
expect ca-epoch-advance "sod acope" "$DIR/err14" \
    ./bin/tlsclient_ca 127.0.0.1 "$PORT14" "ca:$CAMOD" - "$DIR/epoch.ticket" "$DIR/epoch.state"
grep -q "^epoch 2 store_failed 0$" "$DIR/err14" || {
    echo "FAIL e2e ca-epoch-advance: the epoch did not move up"
    exit 1
}
[ "$(cat "$DIR/epoch.state")" = 2 ] || {
    echo "FAIL e2e ca-epoch-advance: the epoch was not written"
    exit 1
}

# The bump: the reissued server moves the same device to epoch 3.
MSG='epoca tres'
expect ca-epoch-bump "sert acope" "$DIR/err15" \
    ./bin/tlsclient_ca 127.0.0.1 "$PORT15" "ca:$CAMOD" - - "$DIR/epoch.state"
[ "$(cat "$DIR/epoch.state")" = 3 ] || {
    echo "FAIL e2e ca-epoch-bump: the bump did not persist"
    exit 1
}

# Replaying the pre-bump leaf against the advanced device: revoked
# (CH_EAUTH is -3), even though the certificate is genuine and its
# chain still verifies to the pinned CA.
MSG='epoca dos'
expect_fail ca-epoch-revoked -3 "$DIR/err14" \
    ./bin/tlsclient_ca 127.0.0.1 "$PORT14" "ca:$CAMOD" - - "$DIR/epoch.state"
[ "$(cat "$DIR/epoch.state")" = 3 ] || {
    echo "FAIL e2e ca-epoch-revoked: a rejected leaf moved the epoch"
    exit 1
}

# The ticket saved at epoch 2 dies with the bump: resumption is the one
# path that presents no certificate, so the ticket's own epoch carries
# the check.
expect_fail ca-epoch-ticket -3 "$DIR/err14" \
    ./bin/tlsclient_ca 127.0.0.1 "$PORT15" "@$DIR/epoch.ticket" - - "$DIR/epoch.state"

# An ordinary wall-clock leaf sits thousands of steps past the stored epoch, so
# the jump bound rejects it: a mis-configured issuance tool fails loudly
# instead of poisoning the fleet.
expect_fail ca-epoch-unbounded -3 "$DIR/err7" \
    ./bin/tlsclient_ca 127.0.0.1 "$PORT7" "ca:$CAMOD" - - "$DIR/epoch.state"

kill $SERVER14 $SERVER15 2>/dev/null
fi

# --- Go's crypto/tls, the stack Prometheus terminates with: once with the
# P-256 cert against the ECDSA build, once with the RSA cert against the
# default build ---
if command -v go >/dev/null 2>&1; then
    # Build first so the server starts instantly, and run the binary
    # directly: go run's child would outlive a kill of the subshell and
    # hold pipes open past the script's exit.
    (cd test/goecho && go build -o "$DIR/goecho" .)
    start_goecho -cert "$DIR/cert.pem" -key "$DIR/key.pem"
    PORT3=$SRV_PORT
    start_goecho -cert "$DIR/rsacert.pem" -key "$DIR/rsakey.pem"
    PORT5=$SRV_PORT

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

    # --- Hybrid key exchange: the same RSA cert on a Go server that
    # accepts only X25519MLKEM768, against the KEX=pq client build,
    # ticket resumption included. The classic client offers only
    # x25519, so the pq-only server refuses the handshake and the
    # client fails closed (CH_EPROTO, -2).
    start_goecho -groups x25519mlkem768 -cert "$DIR/rsacert.pem" -key "$DIR/rsakey.pem"
    PORT17=$SRV_PORT

    MSG='hibrido'
    expect go-pq "odirbih" "$DIR/err_pq" \
        ./bin/tlsclient_pq 127.0.0.1 "$PORT17" "pin:$MOD" - "$DIR/ticket_pq"
    [ -s "$DIR/ticket_pq" ] || {
        echo "FAIL e2e go-pq: no ticket from the Go server"
        exit 1
    }
    MSG='otra vuelta'
    expect go-pq-resume "atleuv arto" "$DIR/err_pq" \
        ./bin/tlsclient_pq 127.0.0.1 "$PORT17" "@$DIR/ticket_pq" -
    MSG='no debe pasar'
    expect_fail go-pq-refuses-classic -2 "$DIR/err_pq" \
        ./bin/tlsclient 127.0.0.1 "$PORT17" "pin:$MOD" -
    GO_LEG=" + go x2 + go-resume x2 + go-pq x2 + go-pq-refuses-classic"
else
    GO_LEG=" (go legs skipped)"
fi

# --- The same hybrid exchange against OpenSSL's s_server. `openssl
# list -tls-groups` arrived in 3.5 alongside the group itself, so
# grepping its output for X25519MLKEM768 is the support probe; an older
# OpenSSL skips the leg, and CI's pinned version runs it.
if "$OPENSSL" list -tls-groups 2>/dev/null | grep -qi x25519mlkem768; then
    OPENSSL_PQ_LEG=" + openssl-pq"
    start_server -tls1_3 -ciphersuites TLS_CHACHA20_POLY1305_SHA256 -groups X25519MLKEM768 -cert "$DIR/rsacert.pem" -key "$DIR/rsakey.pem" -rev
    PORT18=$SRV_PORT
    MSG='hibrido openssl'
    expect openssl-pq "lssnepo odirbih" "$DIR/err_pq2" \
        ./bin/tlsclient_pq 127.0.0.1 "$PORT18" "pin:$MOD" -
else
    OPENSSL_PQ_LEG=""
    echo "SKIP openssl pq leg: $("$OPENSSL" version) does not list X25519MLKEM768 (needs 3.5)"
fi

echo "e2e: psk + tickets + resumption + pinned ecdsa + pinned rsa + rotation + ca rsa x2 + ca ecdsa x2 + ca rotation + ca negatives x3${EPOCH_LEG}${GO_LEG}${OPENSSL_PQ_LEG} + examples x3 OK"
