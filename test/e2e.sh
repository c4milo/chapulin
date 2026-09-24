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

# The same for this tree's own server, bin/tlsserver, which prints the
# port in s_server's ACCEPT shape. Sets SRV_LOG as well, because the legs
# read what the server logs about each connection.
start_chserver() {
    SRV_N=$((SRV_N + 1))
    local log="$DIR/server$SRV_N.log"
    ./bin/tlsserver "$@" > "$log" 2>&1 &
    SRV_PID=$!
    SRV_PIDS="$SRV_PIDS $SRV_PID"
    disown "$SRV_PID" 2>/dev/null || true
    read_port "$SRV_PID" "$log" 's/^ACCEPT .*:\([0-9][0-9]*\)$/\1/p'
    SRV_LOG=$log
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

# Fails unless an s_server started with -msg has read exactly one
# ClientHello. A leg calls it after one handshake to show the server sent
# no HelloRetryRequest, which would have brought a second ClientHello.
# Args: label, the server's log.
one_client_hello() {
    local label=$1 log=$2 n
    n=$(grep -c '^<<< .*ClientHello' "$log" || true)
    [ "$n" = 1 ] || {
        echo "FAIL e2e $label: the server read $n ClientHello messages, so the handshake took a HelloRetryRequest"
        cat "$log"
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

# --- TRANSPORT=record: the same PSK handshake, driven by a caller that
# owns the socket. The point of the leg is the comparison: bin/recclient
# and bin/tlsclient reach the same connected session against the same
# server, one with chapulin touching the descriptor and one without.
start_server -tls1_3 -ciphersuites TLS_CHACHA20_POLY1305_SHA256 -psk "$PSK" -psk_identity "$ID" -nocert -rev
MSG='hola sapo'
expect record "opas aloh" "$DIR/err_rec" ./bin/recclient 127.0.0.1 "$SRV_PORT" "$PSK" "$ID"

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

# --- This tree's server, with the same P-256 key and certificate: OpenSSL's
# s_client, then this tree's own pinned client, each make a full handshake
# and then resume the ticket the server issued. s_client prints "Reused"
# only when the server selected its PSK, and the server logs "handshake:
# resumed" only when a ticket authenticated the handshake, which is one
# that sent no Certificate. ---
"$OPENSSL" x509 -in "$DIR/cert.pem" -outform DER -out "$DIR/cert.der"
# The private scalar as 64 hex digits: OpenSSL prints it with a leading 00
# when its top bit is set, and without leading zeros when it is short.
PRIV=$("$OPENSSL" ec -in "$DIR/key.pem" -text -noout 2>/dev/null \
    | awk '/^priv:/{f=1;next} f&&/^[^ ]/{f=0} f{gsub(/[ :]/,"");printf "%s",$0}')
PRIV=$(printf '%064s' "$PRIV" | tr ' ' 0 | tail -c 64)
start_chserver "$DIR/cert.der" "$PRIV" "$PUB"
PORT15=$SRV_PORT
CHSRV_LOG=$SRV_LOG

# Runs s_client against this tree's server with one line on stdin and the
# session file arguments given, and checks the summary line and the reply.
# Args: label, expected summary ("New" or "Reused"), line, reply, then the
# session arguments. -ign_eof keeps s_client reading until the server
# closes, so the ticket that follows the handshake is in the session it
# saves.
s_client_line() {
    local label=$1 summary=$2 line=$3 reply=$4
    shift 4
    printf '%s\n' "$line" | "$OPENSSL" s_client -connect "127.0.0.1:$PORT15" -tls1_3 \
        -ign_eof "$@" > "$DIR/$label.log" 2>&1 || {
        echo "FAIL $label: s_client exited nonzero"
        cat "$DIR/$label.log" "$CHSRV_LOG"
        exit 1
    }
    if ! grep -q "^$summary, TLSv1.3, Cipher is TLS_CHACHA20_POLY1305_SHA256" "$DIR/$label.log" ||
        ! grep -q "^$reply\$" "$DIR/$label.log"; then
        echo "FAIL $label: want a $summary session answering '$reply'"
        cat "$DIR/$label.log" "$CHSRV_LOG"
        exit 1
    fi
}
s_client_line chsrv-openssl New 'hola mundo' 'odnum aloh' -sess_out "$DIR/sess.pem"
s_client_line chsrv-openssl-resume Reused 'otra vez' 'zev arto' -sess_in "$DIR/sess.pem"

MSG='sin secretos'
expect chsrv-chapulin "soterces nis" "$DIR/err15" \
    ./bin/tlsclient_ecdsa 127.0.0.1 "$PORT15" "pin:$PUB" - "$DIR/ticket15"
[ -s "$DIR/ticket15" ] || {
    echo "FAIL chsrv-chapulin: no ticket from this tree's server"
    exit 1
}
MSG='de nuevo'
expect chsrv-chapulin-resume "oveun ed" "$DIR/err15" \
    ./bin/tlsclient_ecdsa 127.0.0.1 "$PORT15" "@$DIR/ticket15" -
# Four connections in order: full, resumed, full, resumed.
[ "$(grep '^handshake: ' "$CHSRV_LOG" | tr '\n' ' ')" = \
  "handshake: full handshake: resumed handshake: full handshake: resumed " ] || {
    echo "FAIL chsrv: the server did not resume both tickets"
    cat "$CHSRV_LOG"
    exit 1
}

# --- The same server's key exchange. It holds X25519MLKEM768 and x25519
# and prefers the hybrid (docs/decisions.md 54), so each s_client group
# list below names the group the server must select, and the server's
# own "group:" line, the last one in its log, says which one ran.
# Args: label, the group code the server must report, the summary, then
# the s_client arguments.
chsrv_group() {
    local label=$1 group=$2 summary=$3
    shift 3
    s_client_line "$label" "$summary" 'grupo' 'opurg' "$@"
    [ "$(grep '^group: ' "$CHSRV_LOG" | tail -1)" = "group: $group" ] || {
        echo "FAIL $label: want the server to select group $group"
        cat "$DIR/$label.log" "$CHSRV_LOG"
        exit 1
    }
}
# A client that lists x25519 alone still gets x25519.
chsrv_group chsrv-openssl-x25519 0x001d New -groups X25519
if "$OPENSSL" list -tls-groups 2>/dev/null | grep -qi x25519mlkem768; then
    CHSRV_PQ_LEG=" + chapulin server pq x4"
    # The hybrid first with its share: selected in one round trip, and a
    # ticket from that connection resumes over the hybrid again.
    chsrv_group chsrv-openssl-pq 0x11ec New -groups X25519MLKEM768:X25519 \
        -sess_out "$DIR/sess_pq.pem"
    chsrv_group chsrv-openssl-pq-resume 0x11ec Reused -groups X25519MLKEM768:X25519 \
        -sess_in "$DIR/sess_pq.pem"
    # A share for each group: the hybrid, though x25519 comes with it.
    chsrv_group chsrv-openssl-pq-both 0x11ec New -groups '*X25519MLKEM768:*X25519'
    # x25519 first, so s_client shares x25519 alone and lists the hybrid
    # after it: the server asks for the hybrid with a HelloRetryRequest,
    # which s_client's -msg trace shows as a second ServerHello.
    chsrv_group chsrv-openssl-pq-retry 0x11ec New -groups X25519:X25519MLKEM768 -msg
    [ "$(grep -c '<<< TLS 1.3, Handshake \[length [0-9a-f]*\], ServerHello' \
        "$DIR/chsrv-openssl-pq-retry.log")" = 2 ] || {
        echo "FAIL chsrv-openssl-pq-retry: want a HelloRetryRequest before the ServerHello"
        cat "$DIR/chsrv-openssl-pq-retry.log"
        exit 1
    }
else
    CHSRV_PQ_LEG=" (chapulin server pq legs skipped)"
    echo "SKIP chapulin server pq legs: $("$OPENSSL" version) does not list X25519MLKEM768 (needs 3.5)"
fi

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
# The classic build reports x25519 (0x001d) as the group that ran.
grep -q "^group 0x001d$" "$DIR/err5" || {
    echo "FAIL e2e rsa: client did not report the x25519 group"
    cat "$DIR/err5"
    exit 1
}
# require_pq in a classic build: ch_connect refuses the config with
# CH_EINVAL (-6) before it sends the ClientHello. The server only takes
# the TCP dial, which the client makes before ch_connect.
expect_fail pin-rsa-require-pq -6 "$DIR/err5b" \
    env REQUIRE_PQ=1 ./bin/tlsclient 127.0.0.1 "$PORT4" "pin:$MOD" -
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

# Provisioning: the decoder must extract the same key from the armour
# openssl just wrote that openssl reports for the key itself. This is
# the only place real openssl-produced PEM reaches ch_pubkey_from_pem;
# every other test armours a vector itself.
PEMMOD=$(./bin/pemkey "$DIR/caroot.pem") || PEMMOD="REJECTED"
if [ "$PEMMOD" = "$CAMOD" ]; then
    echo "ok   ca-rsa-provision"
else
    echo "FAIL ca-rsa-provision: pemkey gave $PEMMOD, openssl gave $CAMOD"
    exit 1
fi
# The leaf is the file an operator pushes by mistake: CA:FALSE, so the
# walk must refuse it rather than pin a controller key as an anchor.
if ./bin/pemkey "$DIR/caleaf.pem" >/dev/null 2>&1; then
    echo "FAIL ca-rsa-provision-leaf: a leaf was accepted as a trust anchor"
    exit 1
fi
echo "ok   ca-rsa-provision-leaf"
# The intermediate is a legitimate anchor (docs/ca.md: pin the
# intermediate when a managed CA signs beyond the fleet).
if ./bin/pemkey "$DIR/caint.pem" >/dev/null 2>&1; then
    echo "ok   ca-rsa-provision-intermediate"
else
    echo "FAIL ca-rsa-provision-intermediate: a real intermediate was refused"
    exit 1
fi

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

PEMPUB=$(./bin/pemkey_ecdsa "$DIR/ecroot.pem") || PEMPUB="REJECTED"
if [ "$PEMPUB" = "$ECROOTPUB" ]; then
    echo "ok   ca-ecdsa-provision"
else
    echo "FAIL ca-ecdsa-provision: pemkey gave $PEMPUB, openssl gave $ECROOTPUB"
    exit 1
fi

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

# --- Web PKI mode (docs/webpki.md): a root -> intermediate -> leaf
# hierarchy the way a public CA issues one, all sha256WithRSAEncryption,
# with the leaf naming its host in subjectAltName. The client carries the
# root as its one anchor, the hostname the leaf names, and a clock inside
# every validity. The negatives after it move one of those three.
WEBPKI_HOSTNAME=webpki.example.test
cat > "$DIR/wpleaf.cnf" <<EOF
keyUsage = critical, digitalSignature
extendedKeyUsage = serverAuth
basicConstraints = CA:FALSE
subjectAltName = DNS:$WEBPKI_HOSTNAME
EOF
cat > "$DIR/wpint.cnf" <<'EOF'
basicConstraints = critical, CA:TRUE, pathlen:0
keyUsage = critical, keyCertSign, cRLSign
EOF

# Splits a self-signed root into the two DER fields a TRUST=webpki anchor
# carries, its subject Name TLV and its SubjectPublicKeyInfo, through
# the script an integrator runs for the same job, so this suite tests
# the recipe examples/webpki_client.c documents and not a copy of it.
webpki_anchor() {
    OPENSSL="$OPENSSL" ./examples/webpki-anchor.sh "$1" "$2" 2>/dev/null
}

"$OPENSSL" genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 \
    -out "$DIR/wproot.key" 2>/dev/null
"$OPENSSL" req -new -x509 -key "$DIR/wproot.key" -subj /CN=webpki-root -days 3650 \
    -sha256 -out "$DIR/wproot.pem" 2>/dev/null
"$OPENSSL" genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 \
    -out "$DIR/wpint.key" 2>/dev/null
"$OPENSSL" req -new -key "$DIR/wpint.key" -subj /CN=webpki-intermediate 2>/dev/null |
"$OPENSSL" x509 -req -CA "$DIR/wproot.pem" -CAkey "$DIR/wproot.key" -days 365 \
    -sha256 -extfile "$DIR/wpint.cnf" -out "$DIR/wpint.pem" 2>/dev/null
"$OPENSSL" genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 \
    -out "$DIR/wpleaf.key" 2>/dev/null
"$OPENSSL" req -new -key "$DIR/wpleaf.key" -subj "/CN=$WEBPKI_HOSTNAME" 2>/dev/null |
"$OPENSSL" x509 -req -CA "$DIR/wpint.pem" -CAkey "$DIR/wpint.key" -days 14 \
    -sha256 -extfile "$DIR/wpleaf.cnf" -out "$DIR/wpleaf.pem" 2>/dev/null
# A second root, so the unknown-anchor leg configures a real anchor that
# signed nothing in this chain.
"$OPENSSL" genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 \
    -out "$DIR/wpother.key" 2>/dev/null
"$OPENSSL" req -new -x509 -key "$DIR/wpother.key" -subj /CN=other-webpki-root -days 3650 \
    -sha256 -out "$DIR/wpother.pem" 2>/dev/null
webpki_anchor "$DIR/wproot.pem" "$DIR/wproot"
webpki_anchor "$DIR/wpother.pem" "$DIR/wpother"

start_server -tls1_3 -ciphersuites TLS_CHACHA20_POLY1305_SHA256 -cert "$DIR/wpleaf.pem" -key "$DIR/wpleaf.key" -cert_chain "$DIR/wpint.pem" -rev
PORT_WEBPKI=$SRV_PORT
WEBPKI_ANCHOR="webpki:$DIR/wproot.name,$DIR/wproot.spki"
WEBPKI_OTHER="webpki:$DIR/wpother.name,$DIR/wpother.spki"
NOW=$(date +%s)

MSG='cadena publica'
WEBPKI_HOST=$WEBPKI_HOSTNAME WEBPKI_NOW=$NOW \
    expect webpki "acilbup anedac" "$DIR/err_wp" \
    ./bin/tlsclient_webpki 127.0.0.1 "$PORT_WEBPKI" "$WEBPKI_ANCHOR" - "$DIR/wpticket"
[ -s "$DIR/wpticket" ] || {
    echo "FAIL e2e webpki: no ticket after a chain handshake"
    exit 1
}

# The ticket that session saved resumes the same hostname under the same
# anchor. The resumed hello offers no signature scheme, so a connected
# session means the server selected the ticket (webpki_ticket.h).
MSG='otra vez publica'
WEBPKI_HOST=$WEBPKI_HOSTNAME WEBPKI_NOW=$NOW \
    expect webpki-resume "acilbup zev arto" "$DIR/err_wp_resume" \
    ./bin/tlsclient_webpki 127.0.0.1 "$PORT_WEBPKI" "$WEBPKI_ANCHOR" "@$DIR/wpticket"
grep -q "^resuming" "$DIR/err_wp_resume" || {
    echo "FAIL e2e webpki-resume: did not use the ticket"
    exit 1
}

# The same ticket under another hostname: its binding names the first,
# so ch_connect refuses the config before a byte leaves (CH_EINVAL).
MSG='otro nombre'
WEBPKI_HOST=other.example.test WEBPKI_NOW=$NOW \
    expect_fail webpki-resume-hostname -6 "$DIR/err_wp_resume_host" \
    ./bin/tlsclient_webpki 127.0.0.1 "$PORT_WEBPKI" "$WEBPKI_ANCHOR" "@$DIR/wpticket"

# --- RFC 7250 raw public keys and SPKI pins (docs/webpki.md, "Raw public
# keys and SPKI pins"). A pin is the SHA-256 of a DER SubjectPublicKeyInfo.
spki_pin() {
    "$OPENSSL" pkey -in "$1" -pubout -outform DER | "$OPENSSL" dgst -sha256 -r | cut -d' ' -f1
}
LEAF_PIN=$(spki_pin "$DIR/wpleaf.key")
INT_PIN=$(spki_pin "$DIR/wpint.key")
OTHER_PIN=$(spki_pin "$DIR/wpother.key")
start_server -tls1_3 -ciphersuites TLS_CHACHA20_POLY1305_SHA256 -cert "$DIR/wpleaf.pem" -key "$DIR/wpleaf.key" -cert_chain "$DIR/wpint.pem" -enable_server_rpk -rev
PORT_RPK=$SRV_PORT

# Pins alone, with no anchor, hostname or clock: the server sends its key
# raw, and the pin names it.
MSG='llave cruda'
WEBPKI_PINS=$LEAF_PIN \
    expect webpki-rpk "adurc evall" "$DIR/err_rpk" \
    ./bin/tlsclient_webpki 127.0.0.1 "$PORT_RPK" webpki:- -
grep -q "^cert type 2$" "$DIR/err_rpk" || {
    echo "FAIL e2e webpki-rpk: the server did not send a raw public key"
    cat "$DIR/err_rpk"
    exit 1
}

# Rotation: the pin that names the key sits second of two.
MSG='segundo pin'
WEBPKI_PINS=$OTHER_PIN,$LEAF_PIN \
    expect webpki-rpk-rotation "nip odnuges" "$DIR/err_rpk_rot" \
    ./bin/tlsclient_webpki 127.0.0.1 "$PORT_RPK" webpki:- -

# A key no pin names.
MSG='pin ajeno'
WEBPKI_PINS=$OTHER_PIN \
    expect_fail webpki-rpk-unpinned -3 "$DIR/err_rpk_unpinned" \
    ./bin/tlsclient_webpki 127.0.0.1 "$PORT_RPK" webpki:- -

# A server that answers the raw key offer with a certificate chain: pins
# alone have no anchor to verify it with (RFC 7250 section 4.2).
MSG='cadena no pedida'
WEBPKI_PINS=$LEAF_PIN \
    expect_fail webpki-rpk-certificate -3 "$DIR/err_rpk_cert" \
    ./bin/tlsclient_webpki 127.0.0.1 "$PORT_WEBPKI" webpki:- -

# Anchors and pins against a server with no raw key: the chain, the name
# and a pin must all pass, and a pin may name the intermediate.
MSG='cadena y pin'
WEBPKI_HOST=$WEBPKI_HOSTNAME WEBPKI_NOW=$NOW WEBPKI_PINS=$INT_PIN \
    expect webpki-pins-chain "nip y anedac" "$DIR/err_pins_chain" \
    ./bin/tlsclient_webpki 127.0.0.1 "$PORT_WEBPKI" "$WEBPKI_ANCHOR" -
grep -q "^cert type 0$" "$DIR/err_pins_chain" || {
    echo "FAIL e2e webpki-pins-chain: expected an X.509 chain"
    cat "$DIR/err_pins_chain"
    exit 1
}
MSG='cadena sin pin'
WEBPKI_HOST=$WEBPKI_HOSTNAME WEBPKI_NOW=$NOW WEBPKI_PINS=$OTHER_PIN \
    expect_fail webpki-pins-chain-unpinned -3 "$DIR/err_pins_chain_unpinned" \
    ./bin/tlsclient_webpki 127.0.0.1 "$PORT_WEBPKI" "$WEBPKI_ANCHOR" -

# Anchors and pins against the raw key server: the client offers the raw
# key first, and the server takes it.
MSG='ambos'
WEBPKI_HOST=$WEBPKI_HOSTNAME WEBPKI_NOW=$NOW WEBPKI_PINS=$LEAF_PIN \
    expect webpki-pins-rpk "sobma" "$DIR/err_pins_rpk" \
    ./bin/tlsclient_webpki 127.0.0.1 "$PORT_RPK" "$WEBPKI_ANCHOR" -
grep -q "^cert type 2$" "$DIR/err_pins_rpk" || {
    echo "FAIL e2e webpki-pins-rpk: the server did not send a raw public key"
    cat "$DIR/err_pins_rpk"
    exit 1
}

# The hostname the caller asked for is not one the leaf names, so the
# name check refuses the chain the signatures would otherwise carry.
MSG='nombre ajeno'
WEBPKI_HOST=other.example.test WEBPKI_NOW=$NOW \
    expect_fail webpki-hostname -3 "$DIR/err_wp_host" \
    ./bin/tlsclient_webpki 127.0.0.1 "$PORT_WEBPKI" "$WEBPKI_ANCHOR" -

# A clock 30 days on: past the leaf's 14-day notAfter and inside every
# other validity, so the leaf's own dates are what refuse it.
MSG='reloj adelantado'
WEBPKI_HOST=$WEBPKI_HOSTNAME WEBPKI_NOW=$((NOW + 30 * 86400)) \
    expect_fail webpki-expired -3 "$DIR/err_wp_expired" \
    ./bin/tlsclient_webpki 127.0.0.1 "$PORT_WEBPKI" "$WEBPKI_ANCHOR" -

# A clock a day back: before the leaf's notBefore, the other end of the
# same rule.
MSG='reloj atrasado'
WEBPKI_HOST=$WEBPKI_HOSTNAME WEBPKI_NOW=$((NOW - 86400)) \
    expect_fail webpki-not-yet-valid -3 "$DIR/err_wp_early" \
    ./bin/tlsclient_webpki 127.0.0.1 "$PORT_WEBPKI" "$WEBPKI_ANCHOR" -

# A real anchor that signed nothing in this chain: the walk runs out of
# entries with no anchor naming an issuer.
MSG='ancla ajena'
WEBPKI_HOST=$WEBPKI_HOSTNAME WEBPKI_NOW=$NOW \
    expect_fail webpki-unknown-anchor -3 "$DIR/err_wp_anchor" \
    ./bin/tlsclient_webpki 127.0.0.1 "$PORT_WEBPKI" "$WEBPKI_OTHER" -

# The webpki example against the same chain server, reading the root's
# two anchor files the way an integrator's program does and taking its
# clock from the host. It sends its own line, "listo", whatever MSG is.
MSG='listo'
expect example-webpki "otsil" "$DIR/err_ex_wp" \
    ./bin/example_webpki 127.0.0.1 "$PORT_WEBPKI" "$WEBPKI_HOSTNAME" \
    "$DIR/wproot.name" "$DIR/wproot.spki"
grep -q "verified up to one of 1 anchors" "$DIR/err_ex_wp" || {
    echo "FAIL example-webpki: did not report the verified chain"
    cat "$DIR/err_ex_wp"
    exit 1
}

# ALPN (RFC 7301): one handshake offers h2 and http/1.1, and the client
# reads back which the server chose. s_server selects by its own -alpn
# order, so each answer needs its own server. This one was started
# without -alpn, so it sends no ALPN extension at all — §3.2 lets a
# server that does not support ALPN leave it out, and the client
# reports no selection instead of failing the handshake.
MSG='sin alpn'
WEBPKI_HOST=$WEBPKI_HOSTNAME WEBPKI_NOW=$NOW WEBPKI_ALPN='h2,http/1.1' \
    expect webpki-alpn-absent "npla nis" "$DIR/err_wp_alpn_absent" \
    ./bin/tlsclient_webpki 127.0.0.1 "$PORT_WEBPKI" "$WEBPKI_ANCHOR" -
grep -q "^alpn none$" "$DIR/err_wp_alpn_absent" || {
    echo "FAIL e2e webpki-alpn-absent: expected no selection"
    cat "$DIR/err_wp_alpn_absent"
    exit 1
}

kill $SRV_PID 2>/dev/null

# The server supports h2 alone, so it selects the first name the client
# offered.
start_server -tls1_3 -ciphersuites TLS_CHACHA20_POLY1305_SHA256 -cert "$DIR/wpleaf.pem" -key "$DIR/wpleaf.key" -cert_chain "$DIR/wpint.pem" -alpn h2 -rev
MSG='alpn h2'
WEBPKI_HOST=$WEBPKI_HOSTNAME WEBPKI_NOW=$(date +%s) WEBPKI_ALPN='h2,http/1.1' \
    expect webpki-alpn-h2 "2h npla" "$DIR/err_wp_alpn_h2" \
    ./bin/tlsclient_webpki 127.0.0.1 "$SRV_PORT" "$WEBPKI_ANCHOR" -
grep -q "^alpn h2$" "$DIR/err_wp_alpn_h2" || {
    echo "FAIL e2e webpki-alpn-h2: expected h2"
    cat "$DIR/err_wp_alpn_h2"
    exit 1
}
kill $SRV_PID 2>/dev/null

# The same offer against a server that supports http/1.1 alone: the
# second name wins, so the reported index is the server's choice and not
# the client's first preference.
start_server -tls1_3 -ciphersuites TLS_CHACHA20_POLY1305_SHA256 -cert "$DIR/wpleaf.pem" -key "$DIR/wpleaf.key" -cert_chain "$DIR/wpint.pem" -alpn http/1.1 -rev
MSG='alpn viejo'
WEBPKI_HOST=$WEBPKI_HOSTNAME WEBPKI_NOW=$(date +%s) WEBPKI_ALPN='h2,http/1.1' \
    expect webpki-alpn-http11 "ojeiv npla" "$DIR/err_wp_alpn_http11" \
    ./bin/tlsclient_webpki 127.0.0.1 "$SRV_PORT" "$WEBPKI_ANCHOR" -
grep -q "^alpn http/1.1$" "$DIR/err_wp_alpn_http11" || {
    echo "FAIL e2e webpki-alpn-http11: expected http/1.1"
    cat "$DIR/err_wp_alpn_http11"
    exit 1
}
kill $SRV_PID 2>/dev/null

# The same hierarchy with an ECDSA leaf, one server per curve. RFC 9846
# section 4.5.2 binds the CertificateVerify scheme to the leaf key, so
# only a P-256 leaf makes the client run ecdsa_secp256r1_sha256, and only
# a P-384 leaf makes it hash the signed content with SHA-384. The RSA
# leaf above runs neither arm. test/webpki_auth_vectors.h signs both
# offline; these two legs are the same arms against a real server.
webpki_ec_leaf() {
    "$OPENSSL" genpkey -algorithm EC -pkeyopt "ec_paramgen_curve:$1" \
        -out "$2.key" 2>/dev/null
    "$OPENSSL" req -new -key "$2.key" -subj "/CN=$WEBPKI_HOSTNAME" 2>/dev/null |
    "$OPENSSL" x509 -req -CA "$DIR/wpint.pem" -CAkey "$DIR/wpint.key" -days 14 \
        -sha256 -extfile "$DIR/wpleaf.cnf" -out "$2.pem" 2>/dev/null
    start_server -tls1_3 -ciphersuites TLS_CHACHA20_POLY1305_SHA256 -cert "$2.pem" -key "$2.key" -cert_chain "$DIR/wpint.pem" -rev
}

# Each leg reads the clock after minting its leaf: openssl writes
# notBefore as the minting instant, and NOW above was read before it.
webpki_ec_leaf P-256 "$DIR/wpleaf256"
MSG='clave p256'
WEBPKI_HOST=$WEBPKI_HOSTNAME WEBPKI_NOW=$(date +%s) \
    expect webpki-p256 "652p evalc" "$DIR/err_wp_p256" \
    ./bin/tlsclient_webpki 127.0.0.1 "$SRV_PORT" "$WEBPKI_ANCHOR" -
kill $SRV_PID 2>/dev/null

webpki_ec_leaf P-384 "$DIR/wpleaf384"
MSG='clave p384'
WEBPKI_HOST=$WEBPKI_HOSTNAME WEBPKI_NOW=$(date +%s) \
    expect webpki-p384 "483p evalc" "$DIR/err_wp_p384" \
    ./bin/tlsclient_webpki 127.0.0.1 "$SRV_PORT" "$WEBPKI_ANCHOR" -
kill $SRV_PID 2>/dev/null

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
    # client fails closed (CH_EPROTO, -2). The pq client runs under
    # require_pq, which its build satisfies, and must report the
    # hybrid group (0x11ec).
    start_goecho -groups x25519mlkem768 -cert "$DIR/rsacert.pem" -key "$DIR/rsakey.pem"
    PORT17=$SRV_PORT

    MSG='hibrido'
    expect go-pq "odirbih" "$DIR/err_pq" \
        env REQUIRE_PQ=1 ./bin/tlsclient_pq 127.0.0.1 "$PORT17" "pin:$MOD" - "$DIR/ticket_pq"
    [ -s "$DIR/ticket_pq" ] || {
        echo "FAIL e2e go-pq: no ticket from the Go server"
        exit 1
    }
    grep -q "^group 0x11ec$" "$DIR/err_pq" || {
        echo "FAIL e2e go-pq: client did not report the X25519MLKEM768 group"
        cat "$DIR/err_pq"
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
        env REQUIRE_PQ=1 ./bin/tlsclient_pq 127.0.0.1 "$PORT18" "pin:$MOD" -
    grep -q "^group 0x11ec$" "$DIR/err_pq2" || {
        echo "FAIL e2e openssl-pq: client did not report the X25519MLKEM768 group"
        cat "$DIR/err_pq2"
        exit 1
    }

    # The web PKI client, which lists both groups and sends a key share
    # for each (docs/decisions.md entries 39 and 51). A chain server with
    # X25519MLKEM768 alone selects the hybrid share, and one with x25519
    # alone selects the x25519 share, each in one round trip: -msg logs
    # the handshake messages, and each server's log shows one ClientHello,
    # so neither sent a HelloRetryRequest. REQUIRE_PQ keeps x25519 off the
    # hello, so the x25519 server finds no common group and the handshake
    # fails.
    start_server -tls1_3 -ciphersuites TLS_CHACHA20_POLY1305_SHA256 -groups X25519MLKEM768 -msg -cert "$DIR/wpleaf.pem" -key "$DIR/wpleaf.key" -cert_chain "$DIR/wpint.pem" -rev
    PORT_WEBPKI_PQ=$SRV_PORT
    LOG_WEBPKI_PQ="$DIR/server$SRV_N.log"
    MSG='dos grupos'
    WEBPKI_HOST=$WEBPKI_HOSTNAME WEBPKI_NOW=$NOW \
        expect webpki-pq "sopurg sod" "$DIR/err_wp_pq" \
        ./bin/tlsclient_webpki 127.0.0.1 "$PORT_WEBPKI_PQ" "$WEBPKI_ANCHOR" -
    grep -q "^group 0x11ec$" "$DIR/err_wp_pq" || {
        echo "FAIL e2e webpki-pq: client did not report the X25519MLKEM768 group"
        cat "$DIR/err_wp_pq"
        exit 1
    }
    one_client_hello webpki-pq "$LOG_WEBPKI_PQ"
    start_server -tls1_3 -ciphersuites TLS_CHACHA20_POLY1305_SHA256 -groups X25519 -msg -cert "$DIR/wpleaf.pem" -key "$DIR/wpleaf.key" -cert_chain "$DIR/wpint.pem" -rev
    PORT_WEBPKI_X25519=$SRV_PORT
    LOG_WEBPKI_X25519="$DIR/server$SRV_N.log"
    MSG='un solo viaje'
    WEBPKI_HOST=$WEBPKI_HOSTNAME WEBPKI_NOW=$NOW \
        expect webpki-x25519 "ejaiv olos nu" "$DIR/err_wp_x25519" \
        ./bin/tlsclient_webpki 127.0.0.1 "$PORT_WEBPKI_X25519" "$WEBPKI_ANCHOR" -
    grep -q "^group 0x001d$" "$DIR/err_wp_x25519" || {
        echo "FAIL e2e webpki-x25519: client did not report the x25519 group"
        cat "$DIR/err_wp_x25519"
        exit 1
    }
    one_client_hello webpki-x25519 "$LOG_WEBPKI_X25519"
    MSG='no debe pasar'
    WEBPKI_HOST=$WEBPKI_HOSTNAME WEBPKI_NOW=$NOW \
        expect_fail webpki-pq-require-pq -2 "$DIR/err_wp_require" \
        env REQUIRE_PQ=1 ./bin/tlsclient_webpki 127.0.0.1 "$PORT_WEBPKI_X25519" "$WEBPKI_ANCHOR" -
    OPENSSL_PQ_LEG="$OPENSSL_PQ_LEG + webpki-pq + webpki-x25519 + webpki-require-pq"
else
    OPENSSL_PQ_LEG=""
    echo "SKIP openssl pq leg: $("$OPENSSL" version) does not list X25519MLKEM768 (needs 3.5)"
fi

# --- The web PKI client that offers both cipher suites (docs/decisions.md
# entry 45). A server that accepts TLS_AES_128_GCM_SHA256 alone selects
# it, and the client keys every record with it. The ChaCha20 chain server
# selects ChaCha20, the first suite the client lists. The client needs the
# AES instructions, so check builds it only where the compiler has them,
# and this leg says so when it is absent.
if [ -x ./bin/tlsclient_webpki_aes ]; then
    start_server -tls1_3 -ciphersuites TLS_AES_128_GCM_SHA256 -cert "$DIR/wpleaf.pem" -key "$DIR/wpleaf.key" -cert_chain "$DIR/wpint.pem" -rev
    PORT_WEBPKI_AES=$SRV_PORT
    MSG='dos suites'
    WEBPKI_HOST=$WEBPKI_HOSTNAME WEBPKI_NOW=$NOW \
        expect webpki-aes "setius sod" "$DIR/err_wp_aes" \
        ./bin/tlsclient_webpki_aes 127.0.0.1 "$PORT_WEBPKI_AES" "$WEBPKI_ANCHOR" -
    grep -q "^suite 0x1301$" "$DIR/err_wp_aes" || {
        echo "FAIL e2e webpki-aes: client did not report TLS_AES_128_GCM_SHA256"
        cat "$DIR/err_wp_aes"
        exit 1
    }
    start_server -tls1_3 -ciphersuites TLS_CHACHA20_POLY1305_SHA256 -cert "$DIR/wpleaf.pem" -key "$DIR/wpleaf.key" -cert_chain "$DIR/wpint.pem" -rev
    PORT_WEBPKI_CHACHA=$SRV_PORT
    MSG='primero chacha'
    WEBPKI_HOST=$WEBPKI_HOSTNAME WEBPKI_NOW=$NOW \
        expect webpki-aes-chacha "ahcahc oremirp" "$DIR/err_wp_chacha" \
        ./bin/tlsclient_webpki_aes 127.0.0.1 "$PORT_WEBPKI_CHACHA" "$WEBPKI_ANCHOR" -
    grep -q "^suite 0x1303$" "$DIR/err_wp_chacha" || {
        echo "FAIL e2e webpki-aes-chacha: client did not report TLS_CHACHA20_POLY1305_SHA256"
        cat "$DIR/err_wp_chacha"
        exit 1
    }
    AES_SUITE_LEG=" + webpki-aes x2"
else
    AES_SUITE_LEG=""
    echo "SKIP webpki-aes legs: bin/tlsclient_webpki_aes is absent (no AES instructions)"
fi

echo "e2e: record + psk + tickets + resumption + pinned ecdsa + chapulin server resume x2 + chapulin server x25519${CHSRV_PQ_LEG} + pinned rsa + require-pq refused + rotation + ca rsa x2 + ca ecdsa x2 + ca rotation + ca negatives x3${EPOCH_LEG} + webpki rsa + webpki-resume x2 + webpki-rpk x7 + webpki ecdsa x2 + webpki negatives x4 + webpki alpn x3${GO_LEG}${OPENSSL_PQ_LEG}${AES_SUITE_LEG} + examples x4 OK"
