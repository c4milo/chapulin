# The QUIC server role

This document scoped `ROLE=server` with `TRANSPORT=quic` before it existed, and
records what it owes now that it does. The Makefile refused the combination when
this was written and no longer does.

**Read "What has since landed" first.** The sections under "What is missing"
below are the original scope, kept because the reasoning in them is still the
reasoning; every item they describe has since been built, and that section
says which. Interop ran outside this tree, through colibri ("Verification
owed" below).

`docs/quic.md` is the client's record and `docs/server.md` the role's. This
one covers only what the two together do not.

## The line chapulin draws, unchanged

`quic.h` states it for the client: chapulin owns every key and every
packet's protection, and the caller owns everything that is not
cryptography. The server role inherits that line exactly. Colibri and rotor
own the transport.

**chapulin does:** the Initial keys in both directions, packet protection
and header protection at all three encryption levels, the Retry integrity
tag both to mint and to check, the Retry token a server mints and checks
("The Retry token" below), the TLS 1.3 server handshake over CRYPTO frames,
key update, key discard, and the §6.6 AEAD limits.

**Colibri and rotor do:** UDP; packet numbers, ACK, loss recovery and
congestion control; flow control and streams; CRYPTO frame reassembly,
including RFC 9000 §7.5's 4096-byte floor; connection IDs and routing; the
decision to send a Retry and to require a token, the Retry packet around
the token, and the answer to a token that does not check; address
validation policy; version negotiation and stateless reset; QPACK and
HTTP/3 framing.

## What already works for a server, unchanged

`quic_gcm.c`, `quic_aes.c`, `quic_keys.c` and `quic_packet.c` hold no role.
They take keys and bytes, so a server links them as they stand.

`quic_initial.c` already derives both labels. `CH_KEY_WRITE` derives under
`"client in"` and `CH_KEY_READ` under `"server in"` (`quic_initial.c:57`,
`quic_initial.c:114`). What is client-shaped is the mapping from direction
to label, not the derivation.

## What has since landed

Three of the pieces this document scoped are implemented, in
`feat(quic): derive Initial keys for either endpoint, and mint a Retry tag`.
They are left described below so the reasoning stays readable, each marked
with what it cost.

**The direction-to-label mapping (was item 1).** `quic_initial_seal` and
`quic_initial_open` take an endpoint, and `aes_public_key_initial` takes one
too, which leaves `quic_aes.c` holding no role at all: a direction and an
endpoint are different questions. Checked against RFC 9001 A.3 byte for
byte, header protection included.

**Retry minting (was item 2).** `quic_retry_tag` writes the tag
`quic_retry_ok` checks, against A.4's printed bytes. One `gcm_seal` serves
both, so minting and checking cannot disagree and no mutant is owed.

**The server's transport parameters (was item 3), in part.** The server's
EncryptedExtensions carries a body its caller supplies, and the ClientHello
parser refuses a client's with `unsupported_extension` because no build here
is a QUIC transport. What cannot land until the driver does is storing the
client's body and handing it to the caller: `cfg.on_transport_params` exists
only under `CH_TRANSPORT_QUIC`, which `srv_cfg.h` refuses together with
`ROLE=server`.

**The client's transport parameters (rest of item 3).** `srv_parser_ext.c`
keeps the body instead of refusing the extension, and the driver hands it to
`cfg.on_transport_params` and closes with `missing_extension` when a hello
carries none, which RFC 9001 section 8.2 requires.

**The driver (was item 4).** `srv_quic.[ch]` runs the flight over CRYPTO
frames, and `quic_fail.[ch]` holds the wipe both drivers share.
`bin/srv_quic_test` feeds this tree's own ClientHello to it and watches the
flight come back: the ServerHello at the Initial level and
EncryptedExtensions, Certificate, CertificateVerify and Finished at the
Handshake level. It also runs one handshake through the client Finished,
over ngtcp2's recorded hellos and a HelloRetryRequest ("The key exchange"
below), and colibri's interop run below drives it against aioquic.

**The Makefile refusal (was item 5), gone.** `ROLE=server` with
`TRANSPORT=quic` builds, links and exports nineteen calls. Two of them are
the Retry token's, which landed after the rest and have a section of their
own below, and one is `ch_quic_seal_close`, which "When the handshake fails"
below covers.

`CH_QUIC_PARAMS_MIN_RXBUF` is still 0, and a chapulin server cannot close
it: it would measure the bodies clients send, which is the other direction.

## The Retry token

colibri runs in the QUIC Interop Runner over one `ROLE=both` object, and the
one case it could not run was `retry` as a server: nothing minted a token,
and colibri holds no key. `quic_token.[ch]` mints and checks one, and
`srv_quic.h` includes its header. Both calls are pure functions over caller
buffers. They take the key and no session, because a Retry precedes every
piece of connection state.

- `ch_srv_quic_token_mint(key, address, address_len, cids, issued_seconds,
  out, cap, out_len)` writes a token of 43 to `CH_QUIC_TOKEN_MAX` (83)
  bytes.
- `ch_srv_quic_token_check(key, token, n, address, address_len,
  now_seconds, lifetime_seconds, cids)` checks one and writes the two
  connection IDs it carries to `*cids`.

`quic_token.h` states both contracts and the layout byte by byte:

```
body  = 0x01 || issued_seconds (8, most significant first)
        || len(ODCID) (1) || ODCID || len(Retry SCID) (1) || Retry SCID
token = body || HMAC-SHA-256(key, "chapulin quic token"
                                  || len(address) (1) || address || body)
```

**What it carries, and why.** A server that sends a Retry keeps no state for
the connection. It needs the Original Destination Connection ID and the
Retry's Source Connection ID again, for the
`original_destination_connection_id` and `retry_source_connection_id`
transport parameters (RFC 9000 §7.3, `rfc9000.txt:1911-1917`). So both
travel in the token, and the check writes them to a `ch_quic_retry_cids`.
The issue instant travels so the check can judge the token's age. The
client's address does not travel: the tag covers it, and the check
recomputes the tag over the address the Initial came from. That is how the
token lets a server check that the source address and port stayed the
same, which §8.1.4 asks of a Retry token (`rfc9000.txt:2444-2446`).

**Integrity, not encryption.** §8.1.4 requires integrity protection against
modification or falsification by clients (`rfc9000.txt:2435-2437`), and it
asks nothing more of a Retry token. Every field the token carries except
the instant already crossed the path in the clear. The rule against fields
an observer can link is for NEW_TOKEN tokens (`rfc9000.txt:2346-2350`),
which this build does not mint. So HMAC-SHA-256, which the object already
carries for the key schedule, is enough, and no cipher is added.

**One type byte.** §8.1.1 requires a server to tell a Retry token from a
NEW_TOKEN token, because the two need different handling
(`rfc9000.txt:2263-2266`). The first byte names the type.
`QUIC_TOKEN_TYPE_RETRY` (0x01) is the one this build mints, and
`QUIC_TOKEN_TYPE_NEW_TOKEN` (0x02) is reserved and refused. The byte also
decides which failure code a bad token gets (below).

**The caller's clock, in seconds.** chapulin reads no clock. The mint takes
`issued_seconds`, and the check takes `now_seconds` and `lifetime_seconds`,
all from one clock the caller reads. The check compares only differences,
so any epoch works if every process that holds the key uses the same one;
Unix time is the plain choice. A token checks when `issued_seconds <=
now_seconds` and `now_seconds - issued_seconds <= lifetime_seconds`: the
lifetime's last second still checks, and a token issued after `now_seconds`
never does. The unit is seconds because `ch_cfg.now_seconds`, the one other
clock the tree takes, counts seconds, and a Retry token lives for seconds.

**No randomness.** The same inputs mint the same bytes, so a seeded
simulation replays a token exactly. §8.1.4 requires a token to be difficult
to guess (`rfc9000.txt:2429`), and the tag provides that: a client without
the key cannot compute it.

**The key.** `CH_QUIC_TOKEN_KEY_LEN` (32) bytes the caller owns, one per
deployment like `ch_srv_cfg.cookie_key`, so a token one process mints
checks in another that holds the same key. The tag input starts with the
label `chapulin quic token`, so a token's tag is never computed over the
same bytes as the HelloRetryRequest cookie's MAC, even under one key.

**Two failure codes, for the RFC's two answers.** The check returns
`CH_EPROTO` for a token that is empty or whose first byte is not
`QUIC_TOKEN_TYPE_RETRY`. That is not a Retry token this server minted, and
§8.1.3 has a server proceed as if the client had no validated address,
which may mean sending a Retry (`rfc9000.txt:2397-2399`). It returns
`CH_EAUTH` for a Retry token that fails a rule: a length that does not
match its length bytes, a tag that does not verify for this key and this
address, or an instant outside the window. §8.1.2 has a server close the
connection with INVALID_TOKEN then, because the client accepts no second
Retry (`rfc9000.txt:2295-2301`). `CH_EINVAL` is the caller's own error: an
address length of 0, or one above `CH_QUIC_TOKEN_ADDRESS_MAX`, which is 18,
an IPv6 address and a port. No refusal writes to `*cids`.

**What the caller still owns.**

- Deciding when to send a Retry, and when to refuse an Initial that carries
  no token.
- The Retry packet around the token: a Source Connection ID that differs
  from the client's Destination Connection ID (`rfc9000.txt:5385-5387`),
  the pseudo-packet, and the tag `ch_srv_quic_retry_tag` writes.
- The address bytes and their encoding, which must be the same for the
  mint and the check.
- The lifetime. §8.1.4 asks a server to accept a Retry token only for a
  short time (`rfc9000.txt:2460-2462`), and the caller picks the number.
- Replay inside the window. §8.1.4 requires replay to be prevented or
  limited (`rfc9000.txt:2458-2460`). The window and the address binding
  limit it; accepting each token once needs state, which a stateless check
  does not keep.
- Closing with INVALID_TOKEN (0x0b, `rfc9000.txt:6805-6806`) on `CH_EAUTH`,
  and treating `CH_EPROTO` as an Initial with no token.
- Encoding the two connection IDs into the server's transport parameters,
  the body it hands chapulin as `cfg.transport_params`. A caller that wants
  one more check compares `retry_scid` with the Destination Connection ID
  of the Initial that carried the token.
- Changing the key. A token minted under the old key then fails with
  `CH_EAUTH`, and a client in the middle of a Retry gets INVALID_TOKEN.

**What checks it.** `test/quic_token_tests.h`, which `bin/srv_quic_test`
and `bin/srv_quic_both_test` run: the round trip at the shortest and longest
connection IDs and addresses; the layout built by hand and compared byte
for byte; another address and another key; a one-bit flip at every byte; every
truncation and one byte too many; a NEW_TOKEN token with a valid tag and
three other type bytes; a connection ID one byte past its cap under a valid
tag; the window at both edges and at the ends of `uint64_t`; and each
length and capacity pair of the mint. `proof/quic_token_harness.c` proves
both calls memory-safe and free of UB over unconstrained inputs, with
SHA-256 as the contract stub. It proves the layout the mint writes, the
reason for each of the check's codes, and the window. It does not prove the
round trip or the address binding, because the stub makes every tag
unconstrained; the tests hold those. Eight `quic-token-` violations in
`test/violations/` each break one rule, and each is caught.

## When the handshake fails

A server that fails reports the alert the way a client does, and seals the
same one CONNECTION_CLOSE per level. `srv_quic.c` fails through `quic_fail`,
the function `quic.c` uses, so a failed server keeps the write keys of each
level it had installed and nothing else. `docs/quic.md`, "When a session
fails", states the rule, the calls colibri makes and what chapulin does not
check, and `docs/decisions.md` entry 57 states why.

Which levels a server can close at depends on where it failed:

- **At a ClientHello.** no_application_protocol (RFC 9001 section 8.1),
  missing_extension for absent transport parameters (section 8.2), and every
  other refusal of the first or the retry hello come before any Handshake
  key exists. The server has Initial keys alone and sends one close, in an
  Initial packet.
- **Inside its own flight.** A failure after the ServerHello goes out, such as
  an `on_crypto_out` that refuses bytes, leaves Initial and Handshake keys.
- **At the client Finished.** A Finished that does not verify, or a KeyUpdate
  or any other message in its place, which h3spec sends, leaves Handshake
  keys and the 1-RTT write keys the server installed with its own Finished,
  and Initial keys unless colibri discarded them first (RFC 9001 section
  4.9.1). RFC 9000 section 10.2.3 asks for the close at each of them
  (`rfc9000.txt:3306-3308`, `rfc9000.txt:3316-3320`).

colibri reads `ch_quic_error_code`, calls `ch_quic_seal_close` once at each of
those levels, sends the packets, and calls `ch_quic_close`. A server sends a
CONNECTION_CLOSE in an Initial packet without padding it: RFC 9000 section
14.1 asks a server to pad only ack-eliciting Initial packets, and a packet
that carries CONNECTION_CLOSE alone is not one (`rfc9000.txt:403-405`). `bin/quic_loop_test` fails this server with
no_application_protocol and with a KeyUpdate in place of the client Finished,
and the client opens every close the server seals.

## Resumption

The QUIC Interop Runner's `resumption` case has a client make a full
handshake, keep the NewSessionTicket, and open a second connection with it,
and the runner fails the case if that second handshake carries a
Certificate. colibri runs it in both roles over one `ROLE=both` object and
refuses 0-RTT. `docs/server.md`, "Resumption", states the server's rules and
`docs/decisions.md` entry 51 the choices; this section says what a QUIC
endpoint does with them.

**colibri's server.** Set `cfg.srv.ticket_key` to 32 bytes of key held for
the deployment, and write the clock into `cfg.srv.now_seconds` before each
`ch_srv_quic_init`. The call to `ch_srv_quic_crypto_in` that delivers the
client Finished then pushes one NewSessionTicket through
`cfg.srv.on_crypto_out` at `CH_LEVEL_APPLICATION`, after the Handshake-level
bytes of that call, and colibri sends it in CRYPTO frames in 1-RTT packets
(RFC 9001 §4.5, `rfc9001.txt:742-744`). The ticket carries no
`early_data`, so no client may send 0-RTT on it. On a later connection that
presents the ticket, the same calls produce a ServerHello at the Initial
level and EncryptedExtensions and Finished at the Handshake level, with no
Certificate and no CertificateVerify, and `ch_tls.psk_selected` reads 1 once
the handshake is done.

**colibri's client.** Set `cfg.on_ticket`. Once `ch_quic_state` reports
`CH_ST_CONNECTED`, hand every 1-RTT CRYPTO byte to
`ch_quic_crypto_in(q, CH_LEVEL_APPLICATION, ...)`, and `on_ticket` fires
once per ticket with its `identity`, `psk` and `age_add`, and under
`TRUST=webpki` its `binding`; copy them during the callback. To resume,
configure the next `ch_quic_init` with `psk` set to the 32-byte PSK,
`psk_id` to the identity, `resumption` to 1 and `obfuscated_age` to the
ticket's age in milliseconds plus `age_add`, and offer the same ALPN
protocol, because the server resumes a ticket only under the protocol it
was issued under. Under `TRUST=raw-ecdsa` leave both `server_pubkey` slots
unset: a raw-mode configuration authenticates one way, and here that way is
the PSK. Under `TRUST=webpki` keep the anchors, the hostname and the clock
as for a full handshake and set `ticket_binding` to the stored binding;
`ch_quic_init` refuses a ticket whose binding does not match them, which is
what `docs/webpki.md`, "Resumption", describes for TCP.

**A declined ticket.** A server passes a ticket over when it cannot open
it, when it has expired on the server's clock, or when the connection
negotiates another ALPN protocol. What happens next depends on the
client's trust mode. A `TRUST=raw-ecdsa` resuming ClientHello offers the
ticket and no signature scheme, so this server has no certificate to send
and answers `missing_extension`; the client closes, and the caller
reconnects without the ticket. A `TRUST=webpki` resuming ClientHello
offers the five signature schemes beside the ticket, so this server
sends its certificate and the same connection completes as a full
handshake, which the client checks against its anchors, hostname and
clock (`docs/decisions.md` entry 55). `ch_tls.psk_selected` reads 0 on
both ends.

**What checks it.** `bin/quic_loop_test` runs this tree's QUIC client
against this tree's QUIC server in one `ROLE=both TRUST=raw-ecdsa` process:
the full handshake, the ticket at the 1-RTT level, the resumed handshake
with two Handshake-level messages and keys that open each other's 1-RTT
packets, a second ticket whose lifetime ended where the first one's did, a
protocol mismatch refused, and no ticket without a clock.
`bin/quic_loop_webpki` runs the same pair under `TRUST=webpki`, with the
server presenting the r2 corpus chain and signing with its leaf key: a
full handshake whose ticket is bound to the client's configuration, which
is only true if `ch_quic_init` took its hash, the resumed handshake, and a
server with another ticket key that declines the ticket and completes a
full handshake in the same connection, refused when the chain fails the
client's hostname or anchor. Neither test sends a packet; colibri's
runner does.

## The key exchange

A QUIC server runs the key exchange the other two server drivers run
(`docs/server.md`, "Key exchange", and `docs/decisions.md` entry 54). It
holds X25519MLKEM768 and x25519, selects the hybrid for any client that
lists it and x25519 for one that lists x25519 alone, and asks with a
HelloRetryRequest when the hello carried no share for the group it chose.
`ch_tls.group` reports the group once the ServerHello has gone out, and
`ch_quic.t.group` is where a caller reads it. No call and no configuration
field changed, and `KEX` selects nothing for this build either.

**What changes for colibri.** Three things, and none of them is an API
change.

- The ServerHello it receives through `cfg.srv.on_crypto_out` at
  `CH_LEVEL_INITIAL` is up to 1,216 bytes when the server selects the
  hybrid, against 128 before, because it carries a 1,120-byte key share.
  That is more than one 1,200-byte Initial packet holds beside its header,
  tag and ACK, so colibri carries the bytes in CRYPTO frames across more
  than one Initial packet. RFC 9000 permits a server several Initial
  packets for this (`rfc9000.txt:5203-5206`), and a CRYPTO frame's offset
  is what lets the client put them back in order (§19.6,
  `rfc9000.txt:6131-6133`).
- The ClientHello it hands to `ch_srv_quic_crypto_in` carries the client's
  1,216-byte hybrid share when the client offers the hybrid, which RFC
  9001 §4.3 notes can span Initial packets (`rfc9001.txt:662-670`). The
  whole message must fit `cfg.buf_len`: `CH_MIN_RXBUF` sizes a QUIC
  server's buffer for the messages a client receives and not for this
  one, so colibri sizes it for the largest hello it accepts. A client that
  shares both groups carries a key_share extension of 1,262 bytes on its
  own, and a `TRUST=webpki` chapulin client's QUIC hello is at most 2,625
  bytes (`CH_HELLO_MAX` in that build).
- A client that lists the hybrid and shares x25519 alone now gets a
  HelloRetryRequest at the Initial level where it used to get a
  ServerHello, and its second ClientHello arrives at the Initial level
  again. That is the retry path a client with an empty `client_shares`
  list always took, so colibri already delivers both hellos. The second
  hello may carry its extensions in another order: ngtcp2's interop
  client moves `supported_versions` to the front. The server accepts
  that, because its frozen digest takes the extensions in ascending type
  order (`docs/decisions.md` entry 59). Before that entry the server
  refused the reordered hello with illegal_parameter, and every ngtcp2
  handshake that needed a retry failed in colibri's interop runs.

The QUIC server's `ch_quic` grows from 2,712 to 2,816 bytes on arm64: its
TX array must hold the 1,216-byte ServerHello, and the handshake state
holds the 32-byte ML-KEM shared secret between the ServerHello and the key
schedule.

**What checks it.** `bin/quic_loop_webpki` resumes a ticket with the
webpki client, which shares both groups, and requires both ends to report
X25519MLKEM768 over an Initial-level ServerHello that carries the
1,120-byte share. `bin/quic_loop_test` requires x25519 from the raw-ecdsa
client, which lists x25519 alone, for the full handshake and the resumed
one. `bin/srv_quic_test` drives the same flight with this tree's
x25519-only hello. It also replays the two ClientHellos ngtcp2's interop
client sent colibri's server on 2026-09-24 (`test/srv_quic_retry_vectors.h`):
the first draws a HelloRetryRequest for X25519MLKEM768 whose bytes match
colibri's server's up to the cookie's frozen digest, and the second,
reordered, completes the handshake through the client Finished, with this
server's cookie and the test's own key share written over the recorded
ones. No interop run has put the hybrid through colibri's UDP path yet;
that run is colibri's to make.

## What is missing

### 1. The direction-to-label mapping

A server writes under `"server in"` and reads under `"client in"`, the
mirror of what `quic_initial.h:76-77` states. Tens of lines, and RFC 9001
Appendix A prints a vector for each direction, so both are checkable against
published bytes.

### 2. Retry minting

`quic_retry.h` exposes `quic_retry_ok` alone, which verifies. A server
computes the same tag and sends it: one `gcm_seal` over the pseudo-packet,
without the `ct_memeq` that follows it in `quic_retry.c`. Tens of lines, and
Appendix A.4's printed tag checks minting and checking against each other.

### 3. The server's transport parameters

The client sends its own body and receives the server's through
`cfg.on_transport_params` (`cfg.h:485`). A server does the mirror: its
EncryptedExtensions carries a body the caller supplies, and the client's
body is handed to the caller the same way.

This is also where `CH_QUIC_PARAMS_MIN_RXBUF` stops being 0. `cfg.h:115`
carries that open marker because no real body has been measured in either
direction; a server sees real client bodies, so it is the first thing that
can measure one.

### 4. The driver

`quic.c` (400 lines), `quic_step.c` (206) and `quic_config.c` (186) drive
the client state machine by encryption level, with 858 lines of harness
under them. A server needs the equivalent over `srv_flight.c`'s handlers.

What makes this a driver rather than a rewrite: `srv_flight.h` is one
function per handshake message, not per record. That is the same property
that let `handshake_flight.c` serve both transports for the client, and it
was fixed when `srv_flight.h` landed, before this document existed.

Two decisions the client's driver does not force. `docs/server.md` open
question ten left both open when this was written, and the sizes below
decided them.

**The server pushes its flight through a callback; it does not stage it.**
The client stages one whole message in `ch_tls.tx` and the caller pulls it
with `ch_quic_crypto_out`. A server cannot: `CH_TX_STAGE` is between 617
and 2589 bytes depending on the build, and one Certificate message carries
a chain larger than that. `srv_flight.c` already streams that chain a
fragment at a time through `send_sealed`, because it never fits one record
either.

So a QUIC server build gives `ch_cfg` a `on_crypto_out(io, level, bytes,
n)` sink, and `send_sealed` and `send_plain_record` call it instead of
`io_send_all`. RFC 9001 §4.1.3 takes the unprotected content of handshake
records as the content of CRYPTO frames, and a CRYPTO frame is a byte
stream, so a message split across calls is what the transport already
expects. The sink takes the same re-entrancy rule `cfg.h` states for
`on_level_ready` and `on_transport_params`, and for the same reason.

The cost is that the two roles read differently: the client pulls, the
server pushes. The certificate chain is what forces it, and a reader who
asks why should find that here rather than infer it.

**The server reuses the `ch_quic_` names.** `ROLE` and `TRANSPORT` are one
value per build, so a server build compiles one driver and a client build
the other; `tls.h` already shares `ch_read`, `ch_write` and `ch_close`
across the roles and declares `ch_connect` and `ch_srv_accept` only in the
build that has one. The server driver lands as `srv_quic.c` beside
`quic.c` with its own step table in `srv_quic_step.[ch]`, and the public
names stay as `quic.h` spells them. A server adds one call the client has
no use for, `ch_quic_retry_tag`, which mints what `ch_quic_retry_ok`
checks.

The step table is shorter than the client's, because a server reads three
messages and writes the rest: `SQ_STEP_AWAIT_CLIENT_HELLO`,
`SQ_STEP_AWAIT_RETRY_HELLO`, `SQ_STEP_AWAIT_CLIENT_FINISHED` and
`SQ_STEP_COMPLETE`. Each send happens inside the step that read the
message it answers.

Expect the server's driver and harnesses to cost about what the client's
did.

### 5. The Makefile refusal

Gone, and the standard it was held to was met first: the axis was not
claimed until `bin/srv_quic_test` showed a whole flight leaving the driver.
The interop item below records its first finished handshake against another
implementation.

## Verification owed

- RFC 9001 Appendix A vectors for both Initial directions and for a minted
  Retry tag.
- A CBMC harness per new file, each measured under `proof/run.sh`'s flags
  before its launch line lands, and each recorded in
  `proof/reach-floors.txt` if it does not converge.
- The sequence differential against the Lean oracle, the way
  `quic_step.[ch]` is checked.
- Interop. On 2026-09-23 colibri's `tools/quic_aioquic.sh` ran colibri's
  `hq-interop` endpoint over a `ROLE=both` object at 9c903d8 against aioquic
  1.3.0 on one host: as client it fetched three files, and as server, with
  an ECDSA P-256 leaf, it served them and closed cleanly. That is an outside
  peer, which two chapulin endpoints testing each other are not, since two
  implementations sharing a bug agree with each other. It is colibri's
  test: `test/quic_driver_test.c:1` still says no QUIC server speaks to the
  client test, and `test/e2e.sh` still has no QUIC leg.

## What this does not scope

A QUIC server that accepts arbitrary clients needs
`TLS_AES_128_GCM_SHA256`, for the reason `docs/aes_suite.md` gives: RFC 9846
§9.1 makes it mandatory to implement and this tree holds one suite. That
work is independent of everything above and can land before or after it.
