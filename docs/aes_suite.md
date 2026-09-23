# TLS_AES_128_GCM_SHA256

This document scoped a second cipher suite before any of it existed.
`docs/quic.md`, "What the AES axis proves", is the record of what the AES
sources rest on, and this document says what changes when a traffic key is
passed to them.

## Status

Most of the scope has landed since:

- The record layer runs the suite (234ec4e), keyed at the length it fixes,
  and a KeyUpdate keeps it (e591002).
- The server selects it from a client that offers no ChaCha20 (9aa1f65) and
  keys its records with it (e591002).
- A `SUITE=aesgcm TRUST=webpki` client offers it beside ChaCha20
  (`docs/decisions.md` entry 45), the decision "Negotiation" below left
  open.
- The build refuses the suite over QUIC and in a raw or ca client.

Still not done, of what this document lists: the rename of `quic_aes.[ch]`
and `quic_gcm.[ch]`; a CBMC harness over the record layer's suite
selection; an e2e leg in which a real client negotiates the suite with this
tree's server; and `bench/sram.sh` re-measured for a suite build. The
sections below keep the original scoping text, and their file and line
references are as they were when it was written.

## Why the tree needs it

RFC 9846 §9.1 makes `TLS_AES_128_GCM_SHA256` mandatory to implement
(`rfc9846.txt:4540-4543`). A client that offers that suite and nothing else
is conformant, and this tree refuses it: `handshake_message.c:44` writes one
suite and `srv_parser.h:71` defines one bit. A server that accepts arbitrary
clients therefore does not meet §9.1 today, and `srv_parser.h:64-66` says so
rather than claiming otherwise.

Colibri serves APIs to clients it does not control, so this is a
requirement. It is not one for the client role: a client picks what it
offers, and the device builds offer ChaCha20-Poly1305 on purpose.

## What already exists

- The AES-128 key expansion and forward cipher of FIPS 197, in three
  implementations the `AES` axis picks between: `quic_aes_soft.c`,
  `quic_aes_hw.c` and `quic_aes_extern.c`.
- `AEAD_AES_128_GCM` and GHASH in `quic_gcm.c`, checked against SP 800-38D
  and the Wycheproof AES-GCM suite on four legs.
- The compile-time refusal this change switches on. `ct.h:87-92` errors
  unless `CH_AES_HW` and `CH_NATIVE_AES` are both set, because the `AES=soft`
  S-box is indexed with the key and a traffic key is secret. That refusal
  landed before the suite so that the build which adds one stops the
  compiler instead of taking whatever the Makefile defaulted to.
- The server's selection, already declared. `srv_parser.h:52-71` reports the
  client's offer as one bit per suite and states that
  `SRV_SUITE_AES_128_GCM` drops in beside the existing bit "with no other
  declaration in this header changing": `selection.suite` already carries
  the code point and `selection.hash_len` the length the suite fixes.

One simplification costs nothing and is worth stating plainly: both suites
hash with SHA-256, so the key schedule needs no hash agility.
`TLS_AES_256_GCM_SHA384` would need it, and §9.1 makes that one a SHOULD.

## What is missing

### The type INV-26 rests on

`aes_public_key` is the type `quic_aes.[ch]` and `quic_gcm.[ch]` take. Its
body lives in `quic_aes_key.h` alone, so only three files can build one, and
`make lint-quic-surface` refuses a file that spells the body itself. INV-26
admits AES into this tree on the claim that every key it sees is public. A
traffic key is not, so the claim must change with the code.

Two shapes:

1. A second type, `aes_traffic_key`, whose only constructor is in the record
   layer, and INV-26 restated as two rules: the three public keys any build
   may use, and the traffic key only a build that asserts hardware AES may
   use.
2. One type, with the build asserting the timing for every use of it.

Prefer the first. The lint already refuses a file that names a key body, and
a second type keeps the compiler deciding which call sites may hold which
key, rather than a reviewer.

### The rename

`quic_aes.[ch]` becomes `aes.[ch]` and `quic_gcm.[ch]` becomes `gcm.[ch]`:
they stop being QUIC-only the moment a TLS record reads them.
`docs/server.md:1485` already writes `ROLE_ADD` with `aes.c` and `gcm.c`, so
the rename was planned before this document. `lint-quic-partition` and
`lint-quic-surface` both read the names and move with it.

### The record layer

`record.c` fixes one AEAD. It derives `AEAD_KEY` 32 bytes and `AEAD_NONCE`
12 (`record.c:7-8`) and calls `aead_seal` and `aead_open` directly
(`record.c:56`, `record.c:82`). AES-128-GCM takes a 16-byte key, the same
12-byte nonce and the same 16-byte tag, so three things change and nothing
else:

- `rec_dir` carries the selected suite.
- `rec_dir.key` stays 32 bytes, the larger of the two, and the derive writes
  the suite's length.
- Seal and open pick the AEAD by the suite.

The nonce construction is the same for both suites — the sequence number
XORed into the low bytes of the IV — so `nonce_of` does not change.

### Negotiation

The server side is declared and unimplemented: `srv_parse_client_hello`
reports the offered bits and `srv_select` reads them.

The client side is a separate decision this document does not make.
`handshake_message.c:44` writes one suite and `handshake_parser.c:138`
refuses any other, which is CLAUDE.md's rule that a client offers exactly
one of everything. `TRUST=webpki` already breaks that rule twice because a
public endpoint forces it. A client that must talk to an endpoint offering
only AES would need the same break a third time; nothing Colibri needs today
asks for it.

### Where the suite cannot go

`AES=hw` needs the instructions. The `m3` and `freertos` lanes target cores
without them, where `quic_aes_hw.c` is an `#error`, so no device build
carries this suite and `ct.h:87-92` is what stops one from trying.

## Verification owed

- RFC 8448 carries `TLS_AES_128_GCM_SHA256` traces. The record layer gets
  those vectors beside the ChaCha20 ones it holds.
- The Wycheproof AES-GCM suite already covers the AEAD on four legs. It
  needs no change; say so rather than adding a second arm.
- A CBMC harness over the record layer's suite selection, measured under
  `proof/run.sh`'s flags before its launch line lands.
- `.violation` mutants, one per rule this change adds: a build that selects
  the suite without the hardware, a seal and an open that disagree about the
  suite, and a derive that writes 32 bytes of a 16-byte key.
- An e2e leg against a real peer that negotiates the suite. `test/e2e.sh`
  has the pattern for openssl and Go peers.
- `bench/sram.sh` re-measured. The round keys and the GHASH table cost SRAM
  a ChaCha20 build does not pay, and CLAUDE.md forbids estimating that
  number.

## What changes in `docs/invariants.md`

INV-26 today claims every key AES sees is public. It becomes two claims. The
first is unchanged and covers the three keys RFC 9001 fixes for QUIC Initial
packets, their header protection and the Retry integrity tag. The second
admits one traffic key, under a build that sets `CH_SUITE_AES_GCM`, which
`ct.h:87-92` refuses unless the AES instructions are present and the build
asserts their timing. The mechanism section gains the second type and the
lint that holds it; the check section gains the mutants above.
