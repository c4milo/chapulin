# Trusting the server

How a chapulin client decides the server is the one it meant to reach. The mode is chosen at build time with the Makefile `TRUST` variable.

Pick one mode at build time.

**Pre-shared key.** Both sides hold a provisioned secret. The handshake
runs ECDHE-PSK, so it keeps forward secrecy.

**Pinned key** (default). You provision the server's public key. The
pin is public data: it needs integrity, not secrecy. The server signs
the handshake and the client checks that signature against the pin. The
client never parses the server's certificate — no ASN.1, no names, no
expiry. This works against stock servers such as OpenSSL and Go's
`crypto/tls`.

**Pinned CA** (`make TRUST=ca-rsa`). The pin holds the key of a CA you run.
The server sends its certificate, or that plus one intermediate, and
the client checks the chain up to the pin with a small profiled parser.
The check covers signatures and certificate shape only. There is still
no clock and no expiry: freshness comes from reissuing short-lived
certificates on a schedule, so server keys rotate without touching a
device. See [`docs/ca.md`](ca.md).

A third mode, `TRUST=webpki`, verifies a public chain against trust
anchors the caller supplies, with hostnames and validity dates. It is
host-side, not device-side: it needs a clock, a hostname and a receive
buffer measured in kilobytes. [`docs/webpki.md`](webpki.md) states
its profile, its bounds, and what it does not check. The walk consults
the anchors before it reads each next entry, so it stops at the first
anchor that both names the issuer and verifies the signature and leaves
the rest of the flight unread. The object carries every verifier a
public chain needs at once — RSA-PSS, RSA PKCS#1 v1.5, P-256 and
P-384 — so `PIN` selects nothing in it. It resumes only a ticket bound
to the configuration of the session that received it, and refuses any
other PSK (docs/webpki.md, "Resumption"). Its resuming hello offers the
certificate path beside the ticket, so a server that declines the ticket
authenticates with its chain in the same connection, and
`ch_tls.psk_selected` says which one happened. It also takes SPKI pins, and
with them RFC 7250 raw public keys, for a DNS-over-TLS or DNS-over-QUIC
caller: pins alone reach a server whose leaf key the caller pins, sent raw
or in a certificate (docs/decisions.md 65), and pins beside anchors make a
chain pass both checks (docs/webpki.md, "Raw public keys and SPKI pins").
The pins mean the same thing over QUIC as over TCP (docs/decisions.md 64).

One signature algorithm per build. The default verifies RSA-PSS and
pins the raw modulus, 256 to 384 bytes, covering RSA-2048 through
RSA-3072. `make TRUST=raw-ecdsa` verifies P-256 and pins 64 bytes instead.
[RFC 9846](https://www.rfc-editor.org/rfc/rfc9846) requires both algorithms, so between them a chapulin build
can pin any compliant server. Neither build carries the other's
verifier.

All modes accept session tickets, so reconnects resume over PSK. In
pinned mode the client verifies a signature once per ticket lifetime,
not once per connection.

**Revoking without a clock.** The ca modes offer an opt-in counter. The
CA writes each certificate's `notBefore` as a counter it advances, and
a device rejects any certificate below the highest counter it has seen
from an authenticated server. To retire a stolen key, reissue that
server on a fresh key pair and advance the counter.
