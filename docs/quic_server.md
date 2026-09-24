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
Handshake level. What no test here covers yet is the client Finished, which
needs a real client's transcript; colibri's interop run below drives it
against aioquic.

**The Makefile refusal (was item 5), gone.** `ROLE=server` with
`TRANSPORT=quic` builds, links and exports eighteen calls. Two of them are
the Retry token's, which landed after the rest and have a section of their
own below.

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
question ten left both open; the sizes below decide them.

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
