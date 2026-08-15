# matasapos

A TLS 1.3 client for devices with a few kilobytes of SRAM to spare. Sapo
is Colombian for the guy who listens in; matasapos kills them.

It speaks exactly one profile: TLS 1.3, `TLS_CHACHA20_POLY1305_SHA256`,
x25519 key exchange, and one of two authentication modes — ECDHE-PSK
(`psk_dhe_ke`) with a provisioned key, or a **pinned server key**: the
server's raw P-256 public key is provisioned like a PSK would be, the
server proves possession by signing the handshake (CertificateVerify),
and its certificate is hashed into the transcript but never parsed — no
ASN.1, no chains, no names, no expiry. Pinned mode handshakes with stock
cert-based endpoints (Go's `crypto/tls`, OpenSSL) with no shared secret
and no PSK-terminating sidecar; tickets still arrive, so reconnects
resume via PSK either way and the ECDSA verify is paid once per ticket
lifetime. No 0-RTT, no negotiation surface — the client offers one of
everything and the server takes it or the handshake fails closed. C11
and libc only, zero heap: the session struct plus a caller-provided
receive buffer is the entire working set, and the client tells the
server that buffer's size via `record_size_limit` (RFC 8449) so a peer
can never send a record it cannot hold. (One sizing note for pinned
mode: the peer's Certificate message must fit the receive buffer — a
self-signed leaf is ~600 bytes; CA chains need a bigger buffer.)

The RFC MUSTs a minimal client cannot shed are all in: HelloRetryRequest
with cookie echo and transcript restart, KeyUpdate in both directions,
NewSessionTicket parsing with resumption-PSK derivation handed to the
application, and RFC 9257 binder discipline over the truncated
ClientHello.

`test/e2e.sh` proves the profile against real peers: PSK handshake,
ticket resumption, and pinned-key handshakes against both OpenSSL 3 and
Go's `crypto/tls` (the stack Prometheus terminates with), application
data both ways throughout.

## Memory

Measured, not estimated (host arm64; 32-bit targets shrink the pointer
fields):

| what | bytes |
|---|---|
| `ms_tls` session struct (includes 534 B TX staging) | 976 |
| caller receive buffer (you choose; 2048 shown) | 2048 |
| **total static working set** | **3024** |
| peak transient stack, `ms_connect` (pinned mode: P-256 verify) | 3312 |
| peak transient stack, `ms_connect` (PSK mode: x25519 ladder) | 2608 |
| peak transient stack, `ms_read` (worst: KeyUpdate rekey) | 1632 |
| peak transient stack, `ms_write` / `ms_close` | 736 / 688 |

Regenerate with `bench/sram.sh`, which walks the real call graph
(objdump-extracted edges weighted by `-fstack-usage` frames) — a
hand-picked chain understated `ms_read` by half until the graph walk
replaced it.

No malloc anywhere, no VLAs, no alloca. For comparison, the smallest
published TLS 1.3 PSK working sets elsewhere: wolfSSL ~6.2 kB heap plus
buffers, mbedTLS ~9–15 kB and cannot run without an allocator, and both
park a 16 kB record buffer next to that unless the peer cooperates.
`docs/landscape.md` has the full survey with sources.

## Verification

`make prove` runs CBMC over every module as part of `make check`. Each
harness drives the module with unconstrained inputs at the documented
bound and proves memory safety (bounds, pointer validity) and absence of
UB (signed overflow, undefined shifts, division) for every input in that
space, plus the functional claims below. Bounded proof, honest bounds:
where a bound is the module's real maximum the proof is total for that
code; where it is not, the bound is stated here.

The suite is layered, mlkem-native style: leaf modules are proven
concrete; hkdf and record are proven against contract-checking stubs of
the already-proven layer below (each stub asserts pointer and size
validity and havocs outputs, so upper proofs never depend on crypto
values).

| harness | proves | bound |
|---|---|---|
| ct | memeq ≡ plain comparison, wipe zeroizes, no UB | all inputs ≤ 64 B |
| buf | any 12-op reader/writer sequence safe, len ≤ cap invariant | buffers ≤ 64 B |
| sha256 | no UB for any two-chunk split | messages ≤ 96 B |
| hkdf (two harnesses) | hmac/extract and expand/expand-label no UB over the proven sha256 contract | keys ≤ 96 B, out ≤ 96 B (all structural paths) |
| handshake | the driver — record pump, cross-record reassembly, HRR restart, state machine, both auth modes — safe on ANY record stream, over the proven io/record/keysched/p256 contracts | 96 B receive buffer |
| chacha20 | no UB, in-place, any counter | ≤ 160 B (3 blocks) |
| poly1305 | no UB for any three-chunk split, 64-bit products bounded | messages ≤ 80 B |
| aead | seal/open round-trip, forged tag ⇒ zero bytes written, backward-overlap decrypt (the record layer's in-place mode) | pt ≤ 64 B, aad ≤ 32 B |
| x25519 | field-op memory safety concrete; int64-overflow impossibility as a separate lemma with full checks (SAT can't do both at once on 256 symbolic multiplies) | limbs ≤ 2^24 |
| p256 | DER parser and limb marshalling safe on hostile signatures (concrete); CIOS carry lemma with full checks; the 256-step scalar mults compose the proven pieces | sigs ≤ 80 B |
| record | seal across contract; rec_open safe on fully hostile bytes, padding strip over any AEAD output | records ≤ 160 B |
| hsparse | ServerHello + EncryptedExtensions parsers safe on hostile bytes | messages ≤ 256 B |

The proofs already earned their keep once: CBMC flagged `carry()`'s
`c << 16` on a negative `c` — UB every compiler happens to tolerate —
now a well-defined multiply.

What is tested but not yet proved, stated plainly:

- x25519 functional correctness rests on the RFC 7748 vectors including
  the 1,000-iteration chain, plus the fact that this exact limb scheme
  (TweetNaCl's) carries a prior Coq/VST functional proof by Schwabe et
  al. The tight limb-growth invariant connecting mul outputs to add/sub
  inputs is an open proof task (`proof/` slow tier).
- tls.c's post-handshake pump is covered by e2e, the mock-transport unit
  tests, and the posths fuzzer; its CBMC harness is the last one missing.
- P-256 functional correctness rests on RFC 6979 vectors plus the oracle
  minting fresh signatures the C must accept; the scalar-mult loops
  compose proven pieces but are not run whole under CBMC.
- Constant time is by construction (no secret-dependent branches or
  indices; no AES precisely because of its tables), enforced by the
  `ct.[ch]` chokepoints, and checked statistically by `make timing`
  (Welch's t over interleaved secret classes) — evidence, not proof.
  P-256 verification is deliberately variable-time: every input is
  public.

Nothing else in this space carries whole-stack machine-checked memory
safety; the closest prior art is AWS's CBMC proofs for the FreeRTOS core
libraries and mlkem-native, which is the methodology copied here.

## The differential oracle

`spec/` is an executable Lean 4 specification of everything matasapos
computes — SHA-256, HKDF and the RFC 8446 §7.1 key schedule, ChaCha20,
Poly1305 (accumulator as plain `Nat` mod 2^130−5), the AEAD, record
framing, and x25519 written as definitional `Nat` arithmetic mod
2^255−19. It was written from the RFC text under a hard independence
rule (no reading the C), each module carries its RFC vectors as a
selftest, and the key schedule is additionally pinned to RFC 8448's
published trace values — which a bug shared by C and spec could not
co-satisfy.

`make diff` builds the spec with `lake`, runs its selftests, then drives
~2,750 random-input comparisons (including P-256 signatures the spec mints that the C must accept) between every C module and the spec over
a pipe (deterministic seed; part of `make check`, skipped when elan is
not installed). This is the Cedar model: proofs establish memory safety,
vectors establish point correctness, and the oracle establishes that the
C computes the same *function* as a spec simple enough to audit against
the RFC by eye.

## Using it

```c
static uint8_t rxbuf[2048];
// PSK mode (provisioned shared key)…
ms_cfg cfg = {
    .psk = psk, .psk_len = 32,
    .psk_id = (const uint8_t *)"device-42", .psk_id_len = 9,
    .buf = rxbuf, .buf_len = sizeof rxbuf,
    .send = my_send, .recv = my_recv, .io = &sock,
    .on_ticket = store_ticket, // optional resumption
};
// …or pinned-key mode: no shared secret, just the server's raw P-256
// public key (X||Y), provisioned once.
// ms_cfg cfg = { .server_pubkey = pin64, .buf = rxbuf, ... };
static ms_tls tls;
if (ms_connect(&tls, &cfg) != MS_OK) { /* reconnect later */ }
ms_write(&tls, data, n);
int got = ms_read(&tls, out, sizeof out);
ms_close(&tls);
```

The platform provides two socket callbacks (blocking, bounded by its own
timeouts) and `ms_rand_bytes` (rand.h) wired to its TRNG. Every error is
fatal to the session by design — wipe, reconnect, done. That is how a
device actually recovers, and it removes the entire resumable-error state
space from the code and the proofs.

## Building

`make check` = build + lint (clang-tidy, clang-format, cppcheck, all
warnings as errors, fix-or-drop policy) + unit tests (RFC vectors) + e2e
against OpenSSL 3 + CBMC proofs. See `CLAUDE.md` for the house rules.

## Non-goals

0-RTT (the IETF IoT profile says MUST NOT anyway), DTLS, X.509, raw
public keys, cipher agility, server role. One honest caveat: the IETF
TLS 1.3 IoT profile's mandatory suite is AES-128-CCM-8; matasapos is
ChaCha-only by design (no tables, constant time on anything), which is
the right call when you control both ends — and a deliberate
incompatibility when you don't. An AES-CCM build flag would be the first
thing v2 discusses.
