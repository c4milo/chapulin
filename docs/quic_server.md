# The QUIC server role

This document scopes `ROLE=server` with `TRANSPORT=quic`. Nothing in it is
implemented, and `Makefile:445` refuses the combination today:

```
$(error ROLE=server runs over TLS records only; use TRANSPORT=tls)
```

`docs/quic.md` is the client's record and `docs/server.md` the role's. This
one covers only what the two together do not.

## The line chapulin draws, unchanged

`quic.h` states it for the client: chapulin owns every key and every
packet's protection, and the caller owns everything that is not
cryptography. The server role inherits that line exactly. Colibri and rotor
own the transport.

**chapulin does:** the Initial keys in both directions, packet protection
and header protection at all three encryption levels, the Retry integrity
tag both to mint and to check, the TLS 1.3 server handshake over CRYPTO
frames, key update, key discard, and the §6.6 AEAD limits.

**Colibri and rotor do:** UDP; packet numbers, ACK, loss recovery and
congestion control; flow control and streams; CRYPTO frame reassembly,
including RFC 9000 §7.5's 4096-byte floor; connection IDs and routing; the
decision to send a Retry and everything inside its token, of which chapulin
computes and checks the integrity tag alone; address validation policy;
version negotiation and stateless reset; QPACK and HTTP/3 framing.

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

`CH_QUIC_PARAMS_MIN_RXBUF` is still 0, and a chapulin server cannot close
it: it would measure the bodies clients send, which is the other direction.

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

`quic.c` (397 lines), `quic_step.c` (206) and `quic_config.c` (186) drive
the client state machine by encryption level, with 858 lines of harness
under them. A server needs the equivalent over `srv_flight.c`'s handlers.

What makes this a driver rather than a rewrite: `srv_flight.h` is one
function per handshake message, not per record. That is the same property
that let `handshake_flight.c` serve both transports for the client, and it
was fixed when `srv_flight.h` landed, before this document existed.

Expect the server's driver and harnesses to cost about what the client's
did.

### 5. The Makefile refusal

`Makefile:445` goes when the driver lands, and not before. Items 1 to 3
above are in and it still stands, because a build that cannot run a
handshake has no business claiming the axis. Until then the
error is correct and should stay.

## Verification owed

- RFC 9001 Appendix A vectors for both Initial directions and for a minted
  Retry tag.
- A CBMC harness per new file, each measured under `proof/run.sh`'s flags
  before its launch line lands, and each recorded in
  `proof/reach-floors.txt` if it does not converge.
- The sequence differential against the Lean oracle, the way
  `quic_step.[ch]` is checked.
- Interop, which neither side has. `test/quic_driver_test.c:1` says no QUIC
  server speaks to the client test, and `test/e2e.sh` has no QUIC leg at
  all. A chapulin server and a chapulin client can test each other, and that
  is worth having, but two implementations sharing a bug agree with each
  other. An outside peer is what settles it.

## What this does not scope

A QUIC server that accepts arbitrary clients needs
`TLS_AES_128_GCM_SHA256`, for the reason `docs/aes_suite.md` gives: RFC 9846
§9.1 makes it mandatory to implement and this tree holds one suite. That
work is independent of everything above and can land before or after it.
