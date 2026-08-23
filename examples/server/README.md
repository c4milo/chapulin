# Serving chapulin clients

chapulin is a client. It has no server role, so this directory holds
configuration for servers other people wrote, not code.

Two stacks are covered: OpenSSL 3 and Go's `crypto/tls`. Every command
here comes from [`test/e2e.sh`](../../test/e2e.sh), which runs real
handshakes against both on every `make check`. That script is written
for a test harness. This document is written for someone configuring a
server.

The client-side examples in [`examples/`](../) show the other half.
[`docs/ca.md`](../../docs/ca.md) is the contract for running a CA; read
it before you issue anything.

## The profile a chapulin client offers

chapulin negotiates nothing. Its ClientHello carries exactly one of
everything:

| ClientHello field | value |
| --- | --- |
| `supported_versions` | TLS 1.3 (0x0304) |
| `cipher_suites` | TLS_CHACHA20_POLY1305_SHA256 (0x1303) |
| `supported_groups` | x25519 (0x001d) |
| `key_share` | one x25519 share |
| `psk_key_exchange_modes` | psk_dhe_ke |
| `signature_algorithms` | rsa_pss_rsae_sha256 (0x0804), or ecdsa_secp256r1_sha256 (0x0403) in a `PIN=ecdsa` build. Pinned-key and CA modes only |
| `record_size_limit` | the receive buffer minus 21 bytes, capped at 16385 (RFC 8449) |
| `pre_shared_key` | PSK mode only, last extension |

The ClientHello carries no `server_name`, no ALPN, and no `early_data`.
A server that selects a certificate by SNI serves its default
certificate to every device.

The server must support TLS 1.3, TLS_CHACHA20_POLY1305_SHA256, and
x25519. If it cannot, the handshake fails: the client sends an alert,
wipes its keys, and the application reconnects later. There is no
fallback to anything.

## What the server must not do

Each item names the `ch_err` code the client returns (`cfg.h`).

- **Do not enable 0-RTT.** OpenSSL: never pass `-early_data`, and leave
  `SSL_CTX_set_max_early_data` at its default of 0. Go's server has no
  0-RTT, so there is nothing to switch off.
- **Do not request a client certificate.** chapulin has no client
  certificates. A CertificateRequest fails the handshake with
  `CH_EAUTH` (-3). OpenSSL: no `-verify` or `-Verify`. Go: leave
  `ClientAuth` at `tls.NoClientCert`.
- **Do not put anything else in EncryptedExtensions.** The client
  accepts `record_size_limit` and `supported_groups` there and rejects
  every other extension with an `unsupported_extension` alert and
  `CH_EPROTO` (-2). Both stacks follow this rule on their own, because
  the client offers nothing that would make them answer.
- **Do not send a HelloRetryRequest carrying `key_share`.** The client
  offers x25519 in both `supported_groups` and `key_share`, so no retry
  is ever needed. It accepts one HelloRetryRequest, cookie only; a
  retry that names a group is `CH_EPROTO` (-2). Do not turn on
  stateless HelloRetryRequest cookies.
- **Do not send more than two certificate entries, and never the
  root** (CA mode). Three entries are `CH_EPROTO` (-2) even when every
  signature checks out.
- **Do not sign CertificateVerify with another algorithm.** The client
  offers exactly one and rejects the rest with `CH_EAUTH` (-3).
- **Do not write a record larger than the device's receive buffer.**
  See the next section.

## Record size

The client advertises `record_size_limit` (RFC 8449) equal to its
receive buffer, so a peer that honors the extension can never overflow
that buffer. Neither stack honors it. OpenSSL's headers through 3.6
define no constant for the extension, only RFC 6066's older
`max_fragment_length`; Go's `tls.Config` has no field for it. Both
ignore what the client asked for.

So the server operator enforces the limit by hand. A record whose
header plus body exceeds the receive buffer makes the client return
`CH_ECAP` (-4), and the session is dead.

One record's plaintext must stay at or under `buf_len - 22`: the
5-byte record header, the 1-byte inner content type, and the 16-byte
Poly1305 tag. With the 2048-byte buffer the e2e suite uses, that is
2026 bytes. Record padding, if the server adds any, counts toward the
same 22 bytes of room.

- OpenSSL: `-max_send_frag N` on `s_server`, or
  `SSL_CTX_set_max_send_fragment` in a program. It caps the plaintext
  in each record OpenSSL writes. The range is 512 to 16384 and the
  default is 16384.
- Go: there is no equivalent setting, so cap what the application
  writes. `crypto/tls` sends each `Write` call's bytes as their own
  records and never merges two calls, so a `Write` of N bytes produces
  records of at most N bytes of plaintext. Leave
  `DynamicRecordSizingDisabled` false; setting it true makes every
  record the full 16384. Even with it false, Go grows its record size
  toward 16384 as the connection sends more packets, so capping each
  `Write` is the only control that lasts.

The server's handshake flight has the same limit. Its Certificate
message must fit as well, which is why pinned-key deployments size the
buffer for their server's certificate. The Memory section of the
top-level [`README.md`](../../README.md) gives the measured sizes.

## PSK mode

The device holds a provisioned secret in `cfg.psk` and its label in
`cfg.psk_id`. The handshake runs psk_dhe_ke, so it still does an x25519
exchange and still has forward secrecy. No certificate is involved.

### OpenSSL 3

```sh
PSK=0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20
openssl s_server -accept 4433 \
  -tls1_3 -ciphersuites TLS_CHACHA20_POLY1305_SHA256 -groups x25519 \
  -psk "$PSK" -psk_identity device-42 -nocert \
  -max_send_frag 1024 -rev -quiet
```

- `-psk` takes hex digits with no `0x` prefix. The bytes must equal
  `cfg.psk` exactly. Any length works; the e2e suite uses 32 bytes.
- `-psk_identity` must equal `cfg.psk_id` exactly. `s_server` compares
  it with `strlen`, so an identity containing a NUL byte does not work
  through the command line. A program's own callback has no such limit.
- `-nocert` because a PSK handshake sends no certificate. A server that
  falls back to a certificate gets `CH_EAUTH` (-3): the client pinned
  nothing to check it against.
- `-rev` reverses each line back, which is what the e2e suite tests
  with. A real server runs its own application instead.
- `-groups x25519` and `-max_send_frag` do not appear in
  `test/e2e.sh`. They restrict the server to the profile and cap the
  record size. Add them.

In your own OpenSSL program, a TLS 1.3 external PSK goes through
`SSL_CTX_set_psk_find_session_callback`. The older
`SSL_CTX_set_psk_server_callback` serves TLS 1.2 and below and does
nothing in a TLS 1.3-only server. Build the `SSL_SESSION` with a
SHA-256 ciphersuite: TLS 1.3 binds each PSK to one hash, and
TLS_CHACHA20_POLY1305_SHA256 uses SHA-256. `s_server` sets
TLS_AES_128_GCM_SHA256 on the session, which is also SHA-256, so the
same PSK serves both suites.

### Go crypto/tls

Go cannot serve this mode. `tls.Config` has no external-PSK field, in
Go 1.27 or any earlier release. Its only PSK path is its own session
tickets, and issuing one needs a certificate handshake first. Serve PSK
devices with OpenSSL, or put those devices in pinned-key mode.

## Pinned-key mode

The device holds the server's raw public key in `cfg.server_pubkey`.
The server proves it holds the matching private key by signing
CertificateVerify.

The client never parses the certificate. It hashes the Certificate
message into the transcript and reads nothing out of it: no chain, no
names, no expiry. The certificate can be self-signed, expired, or
issued by a public CA. Only the key matters.

Keep the key pair stable. Renewing a certificate on a fresh key makes
every device's pin fail; with certbot, pass `--reuse-key`. To change
the key on purpose, the device holds a second pin slot — see
[`docs/rotation.md`](../../docs/rotation.md).

### Default build: RSA-PSS, pin the modulus

RSA-2048 through RSA-3072, in steps of 64 bits: `ch_connect` accepts a
modulus of 256 to 384 bytes whose length is a multiple of 8 bytes.
RSA-4096 fails at setup with `CH_EINVAL` (-6).

```sh
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 \
  -out server.key
openssl req -x509 -key server.key -subj /CN=controller-01 -days 365 \
  -out server.crt

# The pin: the modulus as lowercase hex, 768 characters for RSA-3072.
openssl rsa -in server.key -noout -modulus \
  | sed 's/^Modulus=//' | tr 'A-F' 'a-f'
```

Generate an `rsaEncryption` key, which is what `-algorithm RSA`
produces. A key generated with `-algorithm RSA-PSS` is restricted to
PSS, and OpenSSL then signs with rsa_pss_pss_sha256 (0x0809). The
client offers only rsa_pss_rsae_sha256 (0x0804), so that handshake
fails.

The certificate's own signature does not matter. `req -x509` self-signs
with PKCS#1 v1.5 and the client never reads it. Only CertificateVerify
is checked, and TLS 1.3 already forbids v1.5 there.

### PIN=ecdsa build: P-256, pin the raw point

```sh
openssl ecparam -name prime256v1 -genkey -noout -out server.key
openssl req -x509 -key server.key -subj /CN=controller-01 -days 365 \
  -out server.crt

# The pin: X||Y as 128 hex characters. cut -c3- drops the 0x04
# uncompressed-point prefix, which the client does not store.
openssl ec -in server.key -text -noout \
  | awk '/^pub:/{f=1;next} f&&/^[^ ]/{f=0} f{gsub(/[ :]/,"");printf "%s",$0}' \
  | cut -c3-130
```

The curve must be prime256v1 (NIST P-256). Every other curve produces a
signature this build cannot verify.

### Serving it with OpenSSL 3

```sh
openssl s_server -accept 4433 \
  -tls1_3 -ciphersuites TLS_CHACHA20_POLY1305_SHA256 -groups x25519 \
  -cert server.crt -key server.key \
  -max_send_frag 1024 -rev -quiet
```

One command for both key types. OpenSSL picks the signature algorithm
from the key and from the client's `signature_algorithms`, and the
client offers exactly one.

### Serving it with Go crypto/tls

```go
cert, err := tls.LoadX509KeyPair("server.crt", "server.key")
if err != nil {
    log.Fatal(err)
}
ln, err := tls.Listen("tcp", "127.0.0.1:4433", &tls.Config{
    Certificates:     []tls.Certificate{cert},
    MinVersion:       tls.VersionTLS13,
    CurvePreferences: []tls.CurveID{tls.X25519},
    ClientAuth:       tls.NoClientCert,
})
```

[`test/goecho/main.go`](../../test/goecho/main.go) is this server with
an echo loop around it. The e2e suite runs it against both PIN builds.

- There is no `CipherSuites` line because that field covers TLS 1.0
  through 1.2 only; Go's own documentation says TLS 1.3 suites are not
  configurable. None is needed: the client offers one suite, so Go
  selects it.
- `CurvePreferences` defaults to a list that starts with post-quantum
  hybrids. The client lists only x25519 in `supported_groups`, so Go
  selects x25519 either way. Setting the field states the choice.
- `MinVersion` is not optional. Go's default minimum is TLS 1.2, which
  this client never speaks but other traffic to the same port might.

## CA mode (`make TRUST=ca`)

The device pins the public key of a CA you run instead of a server key.
The server sends its own certificate, or that plus the one intermediate
that signed it, and the client verifies the chain up to the pin with a
profiled parser.

[`docs/ca.md`](../../docs/ca.md) is the contract for the CA: signature
algorithm, extension profile, size caps, lifetimes, key custody, and
the operational rules. This section covers only what the server does
with the material the CA issues.

### A hierarchy to test against

The extension profiles, as two files:

```sh
cat > leaf.cnf <<'EOF'
keyUsage = critical, digitalSignature
extendedKeyUsage = serverAuth
basicConstraints = CA:FALSE
EOF

cat > int.cnf <<'EOF'
basicConstraints = critical, CA:TRUE, pathlen:0
keyUsage = critical, keyCertSign, cRLSign
EOF
```

Root, intermediate, and one server certificate. Every signature in the
chain is RSA-PSS with SHA-256 and salt length 32, which is the one
encoding an RSA build accepts:

```sh
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out root.key
openssl req -new -x509 -key root.key -subj /CN=fleet-root -days 3650 \
  -sha256 -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:32 \
  -out root.pem

openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out int.key
openssl req -new -key int.key -subj /CN=fleet-intermediate |
openssl x509 -req -CA root.pem -CAkey root.key -days 365 \
  -sha256 -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:32 \
  -extfile int.cnf -out int.pem

openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out leaf.key
openssl req -new -key leaf.key -subj /CN=controller-01 |
openssl x509 -req -CA int.pem -CAkey int.key -days 14 \
  -sha256 -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:32 \
  -extfile leaf.cnf -out leaf.pem

# The pin: the root's modulus, the same 768 hex characters as before.
openssl rsa -in root.key -noout -modulus \
  | sed 's/^Modulus=//' | tr 'A-F' 'a-f'
```

For a `PIN=ecdsa` build, generate P-256 keys with
`openssl ecparam -name prime256v1 -genkey -noout` and drop the two
`-sigopt` flags: OpenSSL signs ecdsa-with-SHA256 with a P-256 key by
default. Pin the root's raw point with the `openssl ec` recipe above.

A flat hierarchy, where the root signs server certificates directly,
drops the intermediate step. Devices then pin the root key and servers
send one certificate.

### Serving the chain with OpenSSL 3

```sh
openssl s_server -accept 4433 \
  -tls1_3 -ciphersuites TLS_CHACHA20_POLY1305_SHA256 -groups x25519 \
  -cert leaf.pem -key leaf.key -cert_chain int.pem \
  -max_send_frag 1024 -rev -quiet
```

Two OpenSSL behaviors make this fail if you leave them alone:

- Certificates appended to the `-cert` file after the leaf are dropped
  silently, and the client then cannot verify the chain up to its pin.
  The intermediate must come through `-cert_chain`.
- OpenSSL appends CA certificates on its own, the behavior
  `SSL_MODE_NO_AUTO_CHAIN` turns off. If the CA certificate sits in the
  server's store — through `-CAfile`, `-chainCAfile`, or
  `-build_chain` — OpenSSL appends it, the client sees three entries,
  and every device fails closed. Keep the CA certificate out of the
  server's store, or set that mode.

In the flat hierarchy, drop `-cert_chain` and serve the leaf alone.

### Serving the chain with Go crypto/tls

Go sends exactly the certificates listed in
`tls.Certificate.Certificate` and builds no chain of its own.
`LoadX509KeyPair` reads the leaf and then any intermediates that follow
it in the same PEM file, in order:

```sh
cat leaf.pem int.pem > chain.pem
```

```go
cert, err := tls.LoadX509KeyPair("chain.pem", "leaf.key")
```

The rest of the `tls.Config` is the same as pinned-key mode. Stop at
two certificates: appending the root gives three entries and the
handshake fails.

### Buffer size in CA mode

A `TRUST=ca` build raises `CH_MIN_RXBUF` to hold the largest chain it
admits: 3,098 bytes in the RSA build, 1,562 in the ECDSA build. A
device whose buffer is smaller fails at `ch_connect` with `CH_EINVAL`
(-6) rather than mid-handshake. Each certificate the CA issues must
also fit the build's per-certificate cap, which `docs/ca.md` states.

### The revocation epoch

The epoch is opt-in. The CA writes each server certificate's
`notBefore` as a counter instead of an issuance time and adds one step
to revoke; the device refuses any certificate below the highest counter
it has accepted. The server serves what the CA issued and does nothing
else, so the flag that matters is on the issuing command, not on
`s_server`. `docs/ca.md` has the rules, the date arithmetic, and the
rollout order.

One version floor matters here. Setting an absolute `notBefore` on
`openssl x509 -req` needs OpenSSL 3.4 or later, which added
`-not_before` and `-not_after`:

```sh
openssl x509 -req -in server.csr -CA int.pem -CAkey int.key \
  -sha256 -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:32 \
  -not_before 000103000000Z -not_after 491231235959Z \
  -extfile leaf.cnf -out leaf.pem
```

`000103000000Z` is epoch 2. Always use `491231235959Z` for `notAfter`:
the device ignores it, and a 2049 date keeps the encoding UTCTime.
Intermediates and the root keep ordinary dates.

On OpenSSL before 3.4, `openssl ca -startdate` sets an absolute
notBefore and does take `-sigopt` for PSS, but it needs a CA section in
`openssl.cnf` with an index and a serial file. That is a different
workflow rather than a drop-in for `x509 -req`, and `docs/ca.md` does
not give the recipe, so `test/e2e.sh` skips its epoch legs on an
OpenSSL that lacks `x509 -req -not_before` and prints why.

Turning the epoch on is fleet-wide and one-way. Once a device carries
the callbacks, every server certificate it authenticates must have an
epoch-shaped notBefore: an ordinary wall-clock date sits thousands of
steps ahead and fails with `CH_EAUTH`. A date more than
`CH_EPOCH_BOUND` steps above the device's stored epoch fails the same
way, so a mis-configured issuing tool breaks at your first staging
handshake rather than reaching the fleet. A bump also retires every
session ticket issued under the older epoch, so those devices run a
full handshake instead of resuming.

Reissue every server before any device sees the new epoch. A device
moves forward on the first newer certificate it authenticates and then
refuses older ones, so a partial rollout leaves devices unable to talk
to the servers you have not reissued yet.

## Session tickets

All three modes accept tickets, so a reconnect resumes over PSK. In
pinned-key and CA modes that skips the signature verify, the most
expensive step in the handshake.

Both stacks issue tickets by default, and both need the client to offer
psk_dhe_ke first, which chapulin always does. OpenSSL's `-num_tickets`
sets how many the server issues; the default is 2.

Keep ticket identities small. The client drops any identity over
`CH_TICKET_ID_MAX` (320 bytes) without reporting it, because such an
identity cannot fit a later ClientHello, and the device then runs a
full handshake on every reconnect. Stock ticket identities from both
stacks fit.

## Checking a server before devices reach it

Build the host client for the mode you are serving and point it at the
server. It sends each line from stdin and prints what the server
answers, so an echo server prints the line back. Handshake results go
to stderr.

```sh
make bin/tlsclient          # default build, RSA pin
make bin/tlsclient_ecdsa    # PIN=ecdsa
make bin/tlsclient_ca       # TRUST=ca, RSA
make bin/tlsclient_ca_ecdsa # TRUST=ca, PIN=ecdsa

echo hola | ./bin/tlsclient 127.0.0.1 4433 "$PSK_HEX" device-42
echo hola | ./bin/tlsclient 127.0.0.1 4433 "pin:$MODULUS_HEX" -
echo hola | ./bin/tlsclient_ca 127.0.0.1 4433 "ca:$ROOT_MODULUS_HEX" -
```

Pinned and CA modes use no psk-id, so pass `-` for that argument.

A failed handshake prints `handshake failed: N`, where N is the
`ch_err` code from `cfg.h`. Three of them come up while configuring a
server: `-2` (`CH_EPROTO`, the server broke the profile), `-3`
(`CH_EAUTH`, the key or the PSK does not match what the device holds),
and `-4` (`CH_ECAP`, a record larger than the receive buffer).

`./test/e2e.sh` runs the whole suite — both stacks, all three modes,
both PIN builds, key rotation, the CA negatives, and the epoch — and
`make check` runs it for you.
