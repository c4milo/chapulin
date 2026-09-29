# Using chapulin

The public calls, the configuration each trust mode takes, and what the server role and the QUIC mode provide.

```c
static uint8_t rxbuf[2048];
// PSK mode (provisioned shared key)…
ch_cfg cfg = {
    .psk = psk, .psk_len = 32,
    .psk_id = (const uint8_t *)"device-42", .psk_id_len = 9,
    .buf = rxbuf, .buf_len = sizeof rxbuf,
    .send = my_send, .recv = my_recv, .io = &sock,
    .on_ticket = store_ticket, // optional resumption
};
// …or pinned-key mode: no shared secret, just the server's public key.
// Default build: the RSA modulus (openssl rsa -noout -modulus).
// TRUST=raw-ecdsa build: 64 P-256 bytes (X||Y).
// ch_cfg cfg = { .server_pubkey = modulus, .server_pubkey_len = 384,
//                .buf = rxbuf, ... };
static ch_tls tls;
if (ch_connect(&tls, &cfg) != CH_OK) { /* reconnect later */ }
ch_write(&tls, data, n);
int got = ch_read(&tls, out, sizeof out); // 0: the peer sent close_notify
ch_close(&tls); // sends this side's close_notify and wipes the keys
```

A `TRUST=webpki` build takes no pin, and a PSK only as a ticket it
bound itself. It takes the roots it trusts, the server's hostname and
the time:

```c
// Each anchor is the DER subject Name and the DER SubjectPublicKeyInfo
// cut from a root certificate you embed; 1 to CH_WEBPKI_ANCHOR_MAX (12).
static const ch_trust_anchor roots[] = {
    {amazon_root_ca_1_name, sizeof amazon_root_ca_1_name,
     amazon_root_ca_1_spki, sizeof amazon_root_ca_1_spki},
};
static uint8_t rxbuf[CH_MIN_RXBUF]; // 12,338 bytes in this mode
ch_cfg cfg = {
    .anchors = roots, .anchor_count = 1,
    .hostname = (const uint8_t *)"s3.amazonaws.com", .hostname_len = 16,
    .now_seconds = (uint64_t)time(NULL), // your clock; compared exactly
    .buf = rxbuf, .buf_len = sizeof rxbuf,
    .send = my_send, .recv = my_recv, .io = &sock,
};
```

The hostname is an ASCII hostname of at most 253 bytes; convert a
U-label to its A-label first. `ch_connect` returns `CH_EINVAL` before it
sends a byte when the anchor count is outside 1 to 12, when an anchor
has an empty name or key, when the hostname has any other shape, when
`now_seconds` is 0, when the buffer is under the 12,338-byte floor, when
the config also sets a pin or an epoch callback, and when it sets a PSK
that is not a ticket bound to this hostname and these anchors. To resume,
keep `ch_ticket.binding` beside the ticket's `psk` and `identity`, and
present it in `ch_cfg.ticket_binding` with `resumption = 1`. Keep the
anchors, the hostname and the clock set: a server that declines the
ticket sends its chain, which the client checks as it checks any chain.
`ch_tls.psk_selected` is 1 when the server resumed the ticket and 0 when
the handshake was a full one.
`ch_cfg.spki_pins` takes up to four SPKI pins, each the SHA-256 of a DER
SubjectPublicKeyInfo. With pins set the client offers raw public keys,
and pins with no anchors need no hostname and no clock.
The anchor, hostname, clock and pin fields exist only in a `TRUST=webpki`
build, so a raw or ca build that sets one fails to compile. The hostname
goes out as the ClientHello's `server_name`, and the hello offers five
signature schemes, because a public chain's links may be signed by any
of them.

The same build negotiates the application protocol
([RFC 7301](https://www.rfc-editor.org/rfc/rfc7301), ALPN). Offer the
protocols you speak, in the order you prefer them, and read back which
one the server picked:

```c
static const ch_alpn_protocol protocols[] = {
    {(const uint8_t *)"h2", 2}, {(const uint8_t *)"http/1.1", 8},
};
cfg.alpn_protocols = protocols;
cfg.alpn_count = 2;           // 1 to CH_ALPN_MAX (8); names to 32 bytes
// ... ch_connect ...
if (tls.alpn_selected == CH_ALPN_NONE) {
    // The server selected none: it sent no ALPN extension at all,
    // which RFC 7301 §3.2 allows. Speak your default or close.
} else {
    const ch_alpn_protocol *picked = &protocols[tls.alpn_selected];
}
```

Offering nothing is legal and sends no extension. `ch_connect` returns
`CH_EINVAL` for a count outside 1 to 8, a count without a list or a list
without a count, a name that is NULL, empty or over 32 bytes, and two
names that are equal. A server that selects a protocol you did not offer
fails the handshake with `illegal_parameter`, and an ALPN reply to a
config that offered none fails it with `unsupported_extension`.
[`docs/webpki.md`](webpki.md) has the whole refusal table, and
[`docs/decisions.md`](decisions.md) entry 37 says why this mode
negotiates here and nowhere else.

Built with `SUITE=aesgcm`, the same client offers three cipher suites,
and `ch_tls.suite` reports the one the server selected. It offers them
in its build's order: `TLS_AES_256_GCM_SHA384`, `TLS_AES_128_GCM_SHA256`,
then `TLS_CHACHA20_POLY1305_SHA256` when the build takes `AES=hw` and
defines `CH_NATIVE_AES`, and ChaCha20 first in every other build. Name
another order, or leave a suite out, with `ch_cfg.cipher_suites`:

```c
static const uint16_t suites[] = {SUITE_AES_128_GCM_SHA256, SUITE_CHACHA20_POLY1305_SHA256};
cfg.cipher_suites = suites;
cfg.cipher_suite_count = 2;   // 1 to 3 suites the build holds, none twice
```

`ch_connect` returns `CH_EINVAL` for a code point the build does not
hold, a repeat, a fourth entry, a count without a list or a list without
a count. A server that selects a suite the list left out fails the
handshake with `illegal_parameter`. Nothing in chapulin asks the CPU what
it has; a program that does passes the order it chose.
[`docs/decisions.md`](decisions.md) entry 80 says why the default order
depends on the build.

`ch_tls.group` reports the key-exchange group the ServerHello selected:
`CH_GROUP_X25519` or `CH_GROUP_X25519MLKEM768` (`cfg.h`), and 0 until
the handshake accepts the ServerHello's key_share. Set
`ch_cfg.require_pq` and the handshake fails closed when that group is
not `CH_GROUP_X25519MLKEM768`. Under `KEX=pq` in a raw or ca build the
flag checks at run time what the build promises, because that build
offers the hybrid alone. A `TRUST=webpki` build lists x25519 too, with a
key share, and the flag drops both from its hello, so that hello is the
one-group hello and a server without the hybrid cannot move it. A
classic build cannot satisfy the flag, so `ch_connect` returns
`CH_EINVAL` before it sends a byte.
[`docs/decisions.md`](decisions.md) entry 12 says why a device
build offers one group, entry 39 why the webpki mode offers two, and
entry 53 why it sends a key share for each.

[`docs/porting.md`](porting.md) is the checklist for a new platform: what
you decide, what has a safe default, and how to check on your own target that
the constant-time multiply survived your compiler. It carries a measured case
where it does not.

You provide two blocking socket callbacks with your own timeouts, and
`ch_rand_bytes` (`rand.h`), or under `RAND=session` a source per session
(below). Use the hardware generator if the part has
one, or the seeded generator in `drbg.[ch]` if it does not. The
reference target has no random-number peripheral, and mips32r2 has no
randomness instruction, so it uses the seeded one. That generator
refuses to run unseeded; [`docs/entropy.md`](entropy.md) covers
seed provisioning.

Say which of the three the image uses. `RAND=extern` leaves
`ch_rand_bytes` for you to define, so an image that never wired a
generator fails to link. `RAND=drbg` packages the reference generator
and exports two more calls: `ch_drbg_seed`, for the image to call once
at boot, and `ch_rand_bytes`, for the generator output that
[`docs/entropy.md`](entropy.md)'s seed file and reseed need.
`RAND=session`, for a host, gives each session a source of its own:
`cfg.rand_bytes`, which the library calls as
`rand_bytes(rand_io, p, n)`, beside `cfg.rand_io`. The object then names
no `ch_rand_bytes`, every init call refuses a NULL `rand_bytes` with
`CH_EINVAL`, and sessions on different threads share no entropy state.
Its source is a CSPRNG in production; a seeded stream that replays a
connection is for tests. There is no default: a build naming none
stops at an `#error`.
No build can judge a generator — a weak one completes the handshake,
sends a key share that looks uniform, and returns `CH_OK` — so writing
the choice down is the only part a compiler can hold you to.

Any error kills the session. The stack wipes its keys and you
reconnect. Devices recover by reconnecting anyway, and the rule removes
the whole resumable-error state space from the code and the proofs.

Two calls report what ended a session, for your log (`alert.h`), and
every object exports both, on every transport:

```c
if (ch_connect(&tls, &cfg) != CH_OK) {
    uint8_t ours = ch_alert_sent(&tls);       // the alert this side chose
    uint8_t theirs = ch_alert_received(&tls); // the alert the peer sent
}
```

Each returns 0 when there is none. A session that reads the peer's
fatal alert, in the handshake or after it, fails with `CH_EPROTO` and
sends nothing in answer, because RFC 9846 §6.2 has both sides close the
connection at once; `ch_alert_received` names that alert and
`ch_alert_sent` reads 0. A tcp-nonblocking session passes `&r->t` and a
QUIC session `&q->t`. Over QUIC `ch_alert_sent` answers what
`ch_quic_alert` answers, and `ch_alert_received` reads 0, because QUIC
carries no alert record.

A tcp-nonblocking session that fails in its handshake gives you its alert
as one record to send before you close the connection. After a failed
`ch_record_in`, `ch_record_out` returns that record once and then answers
`CH_EINVAL`. A failed `ch_srv_record_in` has pushed it through
`cfg.srv.on_record_out` before it returns. The record is in the clear
before that side's write key is installed and sealed under the key after,
so send it as it is (`tcp_nonblocking.h`).

## Resuming a ticket

`on_ticket` hands over each ticket once (`ticket.h`). Its `identity`
points into the message and is valid only during the call, so copy the
`ch_ticket` and the identity bytes, and note when the ticket arrived. To
resume, present the copy with the ticket's age in milliseconds:

```c
uint64_t age_ms = now_ms() - kept.received_ms;
cfg.psk = kept.ticket.psk;
cfg.psk_len = kept.ticket.psk_len;
cfg.psk_id = kept.identity;
cfg.psk_id_len = kept.ticket.identity_len;
cfg.resumption = 1;
cfg.ticket_age_ms = age_ms;
cfg.ticket_lifetime_s = kept.ticket.lifetime_s;
cfg.obfuscated_age = ch_ticket_obfuscated_age(&kept.ticket, age_ms);
```

`ch_ticket_obfuscated_age` adds the ticket's `age_add` to the age modulo
2^32, as RFC 9846 §4.3.11.1 asks, and reads `age_add` alone, so a kept
copy whose `identity` pointer no longer points anywhere serves.
`ch_connect`, `ch_record_init` and `ch_quic_init` return `CH_EINVAL`,
before a byte is sent, when the age is above the lifetime or above
`CH_TICKET_LIFETIME_MAX`, 604,800 seconds, which RFC 9846 §4.6.1 makes the
most any ticket lives. A lifetime of 0 means you gave none, and then the
seven days alone apply. No ticket with a lifetime of 0 is handed to
`on_ticket`, because §4.6.1 says to discard one at once.

A CA build also takes `ticket_epoch`, the ticket's `epoch`: the stored
epoch when the ticket arrived. The same three calls return `CH_EINVAL`,
before a byte is sent, when it is below the stored epoch, because an
epoch bump since then retired the ticket ([`docs/ca.md`](ca.md)). Either
refusal, of the age or of the epoch, means the ticket cannot be used
again: drop it and connect in full. A `TRUST=webpki` build also takes
`ticket_binding`.

## Sizing buffers in record mode

A `TRANSPORT=tcp-nonblocking` caller owns the socket and hands records to
`ch_read` whole (`tcp_nonblocking.h`). Two calls and two lengths tell it
how to cut and size its bytes:

- `ch_record_whole_len(p, n)` is the length of the record at the front of
  `p`, header included, or 0 while `p` holds less than that record. Pass
  that many bytes to `ch_read`. A header whose length field is above
  2^14 + 256, which no peer may send, answers 5, the header alone, and
  `ch_read` refuses it.
- `ch_writable_len(&tls, cap)` is the most plaintext one `ch_write` seals
  into `cap` bytes of records, at the smaller of the peer's
  `record_size_limit` and `CH_TX_PT` per record. Pass at most that much
  when your send buffer holds `cap` bytes. Both TCP transports export it.
  Under `SUITE=aesgcm` it also counts the KeyUpdate record below when the
  write crosses an AES-GCM write key's ceiling, so a buffer sized for
  your largest write holds 27 bytes more.
- `CH_ALERT_RECORD_LEN`, 24, is what `ch_close` sends, and what a failing
  `ch_read` sends, unless the peer's fatal alert failed it: that read
  sends nothing. A handshake that fails once its side's write key is
  installed gives one too, through `ch_record_out` or `on_record_out`;
  one that fails before it gives the alert in the clear, 7 bytes. `CH_KEY_UPDATE_RECORD_LEN`, 27, is what `ch_read` sends
  for each KeyUpdate that asks for an answer. A record carries at most
  one KeyUpdate, as its last message (RFC 9846 §5.1), so a record gets
  at most one answer, and a record with bytes after a KeyUpdate fails
  the read.
- Under `SUITE=aesgcm`, `ch_write` sends one KeyUpdate record of its own,
  `CH_KEY_UPDATE_RECORD_LEN` bytes, as the last of the
  `REC_AES_GCM_RECORDS_MAX` records, 2^24, that an AES-GCM write key
  seals, which RFC 9846 §5.5 requires of a sender. It seals the rest of
  that write under the next key, and the peer reads across the change.
  RFC 9846 §4.7.3 lets a sender send 2^48 - 1 KeyUpdates, and a session
  that has sent that many cannot replace a key at its ceiling: that
  `ch_write` returns `CH_ECAP` and fails the session with internal_error.
  QUIC has no TLS KeyUpdate and counts its own AES-GCM packets instead
  ([`docs/quic.md`](quic.md)).

## The server role and QUIC

The `TRANSPORT=quic-nonblocking` client is implemented and checked against RFC 9001's
and RFC 9369's Appendix A vectors; [`docs/quic.md`](quic.md) records its design. A
QUIC *server* now builds too: `ROLE=server` with `TRANSPORT=quic-nonblocking` runs the
TLS 1.3 server handshake over CRYPTO frames and exports twenty-two calls,
two of which mint and check the address validation token a server puts in
a Retry, and two of which are `alert.h`'s. Every QUIC configuration, in
either role, names the version of the client's first Initial packet in
`ch_cfg.quic_original_version`, and every packet call takes the version of
the packet beside its level. A build derives the keys of QUIC version 1 and
version 2. A client switches from its original version to the other once,
before the server's first CRYPTO byte, and a server's caller chooses the
negotiated version once, through `ch_srv_cfg.choose_version`, when the
first ClientHello arrives ([`docs/decisions.md`](decisions.md) 79).
[`docs/quic_server.md`](quic_server.md) states what chapulin owes one,
which is the keys, the packet protection and that token, and nothing above
them. Both
roles have completed handshakes with another implementation, in a test
that lives outside this tree: on 2026-09-23 colibri's `hq-interop` endpoint,
built over a `ROLE=both` object at 9c903d8, fetched three files from aioquic
1.3.0 and served the same three to it, over UDP on one host. That run
negotiated ChaCha20-Poly1305, the one suite that build offered, and
`make check-slow` does not repeat it: this tree's e2e suite still has no
QUIC leg.

The `ROLE=server` build is implemented and completes a handshake;
[`docs/server.md`](server.md) records its design. Given a ticket key
and the caller's clock (`ch_cfg.srv.ticket_key`, `ch_cfg.srv.now_seconds`),
it issues one resumption ticket per connection and resumes its own tickets
under `psk_dhe_ke`, with no Certificate, over all three transports;
`test/e2e.sh` has OpenSSL's `s_client` and this tree's client each resume
against it. Built with
`SUITE=aesgcm` it also selects `TLS_AES_128_GCM_SHA256`, which RFC 9846
section 9.1 makes mandatory to implement, and `TLS_AES_256_GCM_SHA384`, over
all three transports, QUIC included, and `ch_srv_cfg.cipher_suites` sets the
order ([`docs/decisions.md`](decisions.md) entry 58). With no order set it
prefers the order its build's client offers in, AES-256-GCM first under
`AES=hw` with `CH_NATIVE_AES` and ChaCha20 first otherwise (entry 80). The
default build selects ChaCha20 alone and does not meet that section.
[`docs/aes_suite.md`](aes_suite.md) states what the suite rests on and
what it still owes.

Every server build holds X25519MLKEM768, x25519 and secp256r1 and prefers
the hybrid: a client that lists it gets it, in one round trip when its
hello carries the hybrid share, and after a HelloRetryRequest that asks for
it when the hello shares x25519 alone. A client that lists x25519 and not
the hybrid gets x25519. A client that lists secp256r1 and neither of the
others gets secp256r1, the key exchange RFC 9846 section 9.1 makes a MUST,
over the constant-time `p256_ecdh.[ch]`. `ch_tls.group` reports which group
ran, as it does for a client, and [`docs/decisions.md`](decisions.md)
entries 54 and 63 state the trade. `test/e2e.sh` checks each case against
OpenSSL's `s_client`, and a resumed handshake runs the hybrid again.
