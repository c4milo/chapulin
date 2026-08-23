# chapulin

[![coverage](.github/badges/coverage.svg)](https://github.com/c4milo/chapulin/actions/workflows/check.yml?query=branch%3Amain)

A TLS 1.3 client for devices with a few kilobytes of RAM. Named after
El Chapulín Colorado: small, unassuming, and it protects you from the
bad guys.

chapulin speaks one profile and negotiates nothing:
`TLS_CHACHA20_POLY1305_SHA256` with x25519 key exchange. The server
takes it or the handshake fails. There is no 0-RTT.

It uses C11 and libc only, and never calls `malloc`. The working set is
one session struct plus one receive buffer you provide.

## Trusting the server

Pick one mode at build time.

**Pre-shared key.** Both sides hold a provisioned secret. The handshake
runs ECDHE-PSK, so it keeps forward secrecy.

**Pinned key** (default). You provision the server's public key. The
pin is public data: it needs integrity, not secrecy. The server signs
the handshake and the client checks that signature against the pin. The
client never parses the server's certificate — no ASN.1, no names, no
expiry. This works against stock servers such as OpenSSL and Go's
`crypto/tls`.

**Pinned CA** (`make TRUST=ca`). The pin holds the key of a CA you run.
The server sends its certificate, or that plus one intermediate, and
the client checks the chain up to the pin with a small profiled parser.
The check covers signatures and certificate shape only. There is still
no clock and no expiry: freshness comes from reissuing short-lived
certificates on a schedule, so server keys rotate without touching a
device. See [`docs/ca.md`](docs/ca.md).

One signature algorithm per build. The default verifies RSA-PSS and
pins the raw modulus, 256 to 384 bytes, covering RSA-2048 through
RSA-3072. `make PIN=ecdsa` verifies P-256 and pins 64 bytes instead.
[RFC 9846](https://www.rfc-editor.org/rfc/rfc9846) requires both algorithms, so between them a chapulin build
can pin any compliant server. Neither build carries the other's
verifier.

All modes accept session tickets, so reconnects resume over PSK. In
pinned mode the client verifies a signature once per ticket lifetime,
not once per connection.

**Revoking without a clock.** `TRUST=ca` offers an opt-in counter. The
CA writes each certificate's `notBefore` as a counter it advances, and
a device rejects any certificate below the highest counter it has seen
from an authenticated server. To retire a stolen key, reissue that
server on a fresh key pair and advance the counter.

## Memory

[`bench/sram.sh`](bench/sram.sh) measures every number below on arm64. A 32-bit target
shrinks the pointer fields.

| what | bytes |
|---|---|
| `ch_tls` session struct (includes 534 B TX staging) | 1056 |
| receive buffer you provide (2048 shown; floor `CH_MIN_RXBUF`) | 2048 |
| **total static working set** | **3104** |
| peak stack, `ch_connect` (RSA-3072 verify) | 5168 |
| peak stack, `ch_connect` (`PIN=ecdsa`) | 3648 |
| peak stack, `ch_connect` (PSK) | 2592 |
| peak stack, `ch_connect` (`TRUST=ca`, RSA / ECDSA) | 5760 / 3952 |
| peak stack, `ch_read` (worst case: KeyUpdate rekey) | 1632 |
| peak stack, `ch_write` / `ch_close` | 736 / 688 |

You size the receive buffer, and the client advertises that size as its
`record_size_limit` ([RFC 8449](https://www.rfc-editor.org/rfc/rfc8449)), so a peer can never send a record the
buffer cannot hold. One extra rule in pinned mode: the server's
Certificate message must also fit. A self-signed P-256 certificate
needs about 600 bytes and an RSA-3072 one about 1.2 kB, so the 2 kB
buffer above covers both. A `TRUST=ca` build knows its own worst case
and derives the floor for you: `CH_MIN_RXBUF` becomes 3,098 bytes
(RSA) or 1,562 (ECDSA), so a buffer too small for the largest chain
fails at setup rather than mid-handshake.

The script computes each entry point's worst case from the object
code's call graph. It does not rely on a hand-picked call chain. The
RSA verify holds the deepest frames, so it sets the `ch_connect` peak
in the default build; it runs once per ticket lifetime and every byte
unwinds before `ch_connect` returns.

For comparison: wolfSSL needs about 6.2 kB of heap plus buffers, and
mbedTLS needs 9 to 15 kB and cannot run without an allocator. Both need
a 16 kB record buffer unless the peer supports `record_size_limit`.
[`docs/landscape.md`](docs/landscape.md) holds the survey with sources.

## Speed and flash

[`bench/insn-mips.sh`](bench/insn-mips.sh) and [`bench/device-ram.sh`](bench/device-ram.sh) cross-compile for mips32r2
(the RTL8382-class core) and measure on the real ISA. Cost is published
as instruction counts, not guessed milliseconds. The millisecond column
assumes 500 MHz and one instruction per cycle, which is optimistic for
an in-order core, so read it as a lower bound.

| work | instructions | ms (500 MHz, 1 IPC) |
|---|---|---|
| AEAD seal, per 1 KB record | 47 k | 0.1 |
| SHA-256, per 1 KB | 68 k | 0.14 |
| x25519 scalar multiply | 28.7 M | 57 |
| RSA-3072 PSS verify (default) | 11.6 M | 23 |
| P-256 verify (`PIN=ecdsa`) | 46.0 M | 92 |
| full pinned handshake crypto (default) | 69.7 M | 139 |

Flash is 26.4 kB for the default build (`.text` + `.rodata`, `-Os`).
The `PIN=ecdsa` build trades 2.3 kB of RSA for 6.1 kB of P-256 and
totals 30.1 kB.

Public-key work dominates. Every handshake runs two x25519 for forward
secrecy, whichever mode it is in, so about 115 ms is the recurring
floor and 82% of the pinned handshake's crypto. The signature verify is
paid only on the first pinned connection; resumptions skip it. Record
crypto is about 0.1 ms per kilobyte, which is negligible beside the
handshake. Because a device typically opens one long-lived connection,
chapulin keeps the 16-bit-limb x25519 for its machine-checked overflow
proof rather than a faster wide-limb version. Many short connections
would change that trade.

## Verification

Four layers cover four different failure classes.

**Proofs cover memory safety.** Twenty of the twenty-three library
sources are compiled into a [CBMC](https://www.cprover.org/cbmc/) harness, which proves them free of
out-of-bounds access, invalid pointers, bad shifts, and division by
zero, for every input within the harness's bound. Signed overflow is
checked too, except in the one harness that turns it off (see the
x25519 row). `hsmsg.c`, `io.c`, and `keysched.c` have no harness.
`make check` regenerates the source-by-source table in
`bin/proof-coverage.md`. Where a bound equals the module's real
maximum, the proof covers all inputs.

The proofs run in two tiers. `make check` runs the fast tier and gates
every push. `make prove-slow` runs the seven long ones, which CI runs
nightly. A slow-tier row below carries the verdict of the last nightly
leg that finished, not of the current commit. A harness that starts and
returns no verdict proves nothing, and this table cannot tell that
apart from one that passed — so for the slow rows, read the nightly.

| harness | proves | bound |
|---|---|---|
| ct | memeq matches a plain compare, wipe zeroizes | inputs ≤ 64 B |
| buf | any 12-operation reader/writer run stays safe; length never exceeds capacity | buffers ≤ 64 B |
| sha256 | safe for any two-chunk split | messages ≤ 96 B |
| hkdf (two harnesses) | hmac/extract and expand/expand-label safe over the proven sha256 contract | keys ≤ 96 B; output ≤ 96 B, expand: slow tier |
| handshake | the driver stays safe on any record stream: pump, reassembly, HRR restart, state machine, in PSK and pinned-key mode. The `TRUST=ca` driver has a harness but no launch line, so it is unproven | 96 B receive buffer, slow tier |
| chacha20 | safe at any counter, including in place | ≤ 160 B |
| poly1305 | safe for any three-chunk split; 64-bit products stay in range | messages ≤ 80 B |
| aead (three harnesses) | seal/open round-trips; a forged tag writes zero bytes; backward-overlap decrypt works | plaintext ≤ 64 B, aad ≤ 32 B, slow tier |
| x25519 | field operations are memory-safe, with the signed-overflow class turned off (slow tier); a separate lemma proves mul's int64 accumulation and fold cannot overflow (fast tier). Nothing proves signed overflow in carry, add, sub or pack | limbs ≤ 2^24 |
| p256 | the DER parser and limb marshalling stay safe on hostile signatures; a carry lemma covers the Montgomery multiply | signatures ≤ 80 B |
| rsa (two harnesses) | the PSS decode and limb marshalling stay safe with the RSAVP1 result replaced by arbitrary bytes | 384 B modulus, every byte hostile |
| record | seal works across its contract; rec_open stays safe on fully hostile bytes | records ≤ 160 B |
| hsparse, eeparse | the ServerHello and EncryptedExtensions parsers stay safe on hostile bytes | messages ≤ 256 B |
| tlspost | the post-handshake parser stays safe on hostile decrypted bytes and consumes no more than its input | messages ≤ 128 B |
| drbg | the generator stays safe for any request, seeded and across rekeys | requests ≤ 96 B |
| x509der (two harnesses) | every DER primitive stays safe on hostile bytes and honors the pointer contracts the walker rests on, in both builds | inputs ≤ 448 B |
| x509parse (two harnesses) | the certificate walker stays safe on any entry list, primitives stubbed to their proven contracts | ECDSA: ≤ 256 B; RSA: ≤ 840 B, slow tier |

CBMC found one real bug during development: `carry()` left-shifted a
negative value, which is undefined behavior even though compilers
tolerate it. The code multiplies instead now.

**Vectors cover known answers.** Unit tests replay [RFC 8448](https://www.rfc-editor.org/rfc/rfc8448)'s traces
message by message: the shared secret, every derived secret at its
transcript snapshot, both Finished MACs, and the ticket's resumption
PSK, plus the PSK binder chain and the HelloRetryRequest restart. Those
traces use AES-128-GCM, which chapulin excludes, so the replay stops at
secrets and MACs and never opens a record.

**A Lean spec covers what the code computes.** See below.

**These rest on tests, not proofs:**

- x25519 and P-256 and RSA functional correctness. Each rests on
  published vectors ([RFC 7748](https://www.rfc-editor.org/rfc/rfc7748) including the 1,000-iteration chain,
  [RFC 6979](https://www.rfc-editor.org/rfc/rfc6979), OpenSSL-produced PSS at 2048 and 3072 bits) plus fresh
  signatures the Lean spec mints and the C must accept. CBMC proves
  the pieces; it does not run a scalar multiplication or a 3072-bit
  exponentiation whole. For x25519 the limb-growth invariant, which
  connects multiply outputs to add/sub inputs, is still an open proof
  task.
- The connected-phase driver. The post-handshake parser is proven on
  hostile bytes, but the `ch_read` / `ch_write` / `ch_close` loop
  around it — the record pump and cross-record reassembly — does not
  converge as one CBMC formula. It rests on end-to-end runs, the
  mock-transport unit tests, and the fuzzer.
- Constant-time behavior. It comes from construction: no branch and no
  memory index depends on a secret, and the stack avoids AES because of
  its lookup tables. `make timing` checks this with a Welch's t-test,
  which is evidence, not proof. P-256 and RSA verification are
  variable-time on purpose, since all of their inputs are public.

Three more suites run on every push and add evidence rather than
proof. [Wycheproof](https://github.com/C2SP/wycheproof)'s attack-derived cases (`make wycheproof`, about 1,600
across x25519, ChaCha20-Poly1305, HKDF-SHA256, P-256 and RSA-PSS).
AddressSanitizer and UndefinedBehaviorSanitizer over every
deterministic suite (`make san-check`), with a committed canary proving
the sanitizer is armed. And the same suites on big-endian mips32r2
under qemu (`make cross-check`), so the deployment ISA checks the
byte-exact vectors too. Line coverage is measured and gated in CI.

## The differential oracle

[`spec/`](spec/) is an executable [Lean 4](https://lean-lang.org/) specification of everything chapulin
computes: SHA-256, HKDF and the key schedule, ChaCha20, Poly1305, the
AEAD, record framing, x25519, P-256, RSA-PSS, and the grammar of the
four handshake messages a server sends. It follows the RFC text and
never the C, because a differential oracle only works when a shared
misreading cannot make both sides agree.

`make diff` builds the spec, runs its selftests, then drives about
6,000 random-input comparisons between the C and the spec over a pipe,
from a fixed seed. Some rows are signatures the spec mints and the C
must accept: the spec holds the private keys and signs, and the C, which
can only verify, must accept every genuine signature and reject every
mutated one. About 730 rows feed the certificate parser generated DER —
uniform bytes, edits at random TLV sites, and leaves the spec re-signs.
Nobody knows those answers in advance, so the C answers first and the
spec must reproduce it.

The spec also carries theorems about itself, so an agreement between C
and spec transfers a proven fact rather than a matching answer. The
theorems constrain the model, not the C: they stop a spec regression
from quietly weakening the oracle. [`spec/CONTRACT.md`](spec/CONTRACT.md) lists them.

The state machine gets the same treatment one level up.
[`spec/Spec/Handshake.lean`](spec/Spec/Handshake.lean) models the message-ordering rules as a step
function, and [`test/hsseq_test.c`](test/hsseq_test.c) enumerates every server message
sequence the model admits — all eleven letters to depth 5, and the six
handshake letters to depth 6, in both modes, 466,286 in all. It renders
each as real records over a mock transport, runs the real client, and
requires its verdict to match the model's. The worst TLS bugs on record
were ordering bugs of exactly this kind: early-CCS, skipped Finished,
the SMACK/FREAK class. Memory-safety proofs and golden-path end-to-end
tests both miss them.

[`test/e2e.sh`](test/e2e.sh) runs the real thing against real peers: PSK, ticket
resumption, and pinned handshakes on both PIN builds, against OpenSSL 3
and Go, moving application data both ways. `TRUST=ca` clients run chain
handshakes against OpenSSL, including CA slot rotation.

## Using it

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
// PIN=ecdsa build: 64 P-256 bytes (X||Y).
// ch_cfg cfg = { .server_pubkey = modulus, .server_pubkey_len = 384,
//                .buf = rxbuf, ... };
static ch_tls tls;
if (ch_connect(&tls, &cfg) != CH_OK) { /* reconnect later */ }
ch_write(&tls, data, n);
int got = ch_read(&tls, out, sizeof out);
ch_close(&tls);
```

You provide two blocking socket callbacks with your own timeouts, and
`ch_rand_bytes` (`rand.h`). Use the hardware generator if the part has
one, or the seeded generator in `drbg.[ch]` if it does not — the
RTL8382-class reference target has none. It refuses to run unseeded;
[`docs/entropy.md`](docs/entropy.md) covers seed provisioning.

Any error kills the session. The stack wipes its keys and you
reconnect. Devices recover by reconnecting anyway, and the rule removes
the whole resumable-error state space from the code and the proofs.

## Building

`make check` runs the gate: build with warnings as errors, linters,
unit tests, end-to-end against OpenSSL and Go, the differential oracle,
and the fast proof tier.

Other targets:

- `make lib` packages the library as one relocatable object
  (`bin/chapulin.o`) exporting exactly the four public calls. Every
  internal symbol is localized, and `lib-check` fails if the export
  list ever grows. Compose with `PIN=ecdsa` and `TRUST=ca`.
- `make prove-slow` runs the seven long proofs. The runner caches by
  content, so an incremental run re-proves only what changed
  (`PROVE_NO_CACHE=1` forces a full run). It uses [kissat](https://github.com/arminbiere/kissat) when
  installed, which reaches the same verdicts faster;
  `PROVE_SOLVER=builtin` and `PROVE_SOLVER=smt2` pick the other back
  ends.
- `make timing` runs the constant-time check. Run it on an idle
  machine.
- `make fuzz` smoke-runs the libFuzzer harnesses.
- `make cxx-check` builds `chapulin.hpp`, an optional header-only C++
  wrapper. It forwards to the same C calls with no runtime cost, is
  freestanding, and compiles under `-fno-exceptions -fno-rtti`. It
  gives you a session that wipes its keys when it leaves scope.
- `make hooks`, once after clone, enables the commit-msg hook.

See [`CLAUDE.md`](CLAUDE.md) for the house rules.

## Non-goals

chapulin does not implement 0-RTT, DTLS, general X.509 path building,
CA bundles, public-CA trust, CRL or OCSP revocation, client
certificates, cipher agility, the server role, or any insecure
fallback. [`docs/decisions.md`](docs/decisions.md) records every trade and why.

Two caveats worth knowing before you adopt it.

The IoT profile's mandatory suite is AES-128-CCM-8, and chapulin is
ChaCha-only, because ChaCha needs no lookup tables and runs in constant
time on any core. That works when you control both ends and fails
against a server that insists on AES. An AES-CCM build flag is the
likeliest v2 addition.

Pin the key of a server whose key is stable. Automatic rotation, such
as Let's Encrypt defaults, breaks pins. [`docs/rotation.md`](docs/rotation.md) shows how
the two-slot pin makes a planned rotation safe, and `TRUST=ca` absorbs
routine key churn entirely.

## Contributing and security

[CONTRIBUTING.md](CONTRIBUTING.md) states the quality bar and the workflow.
[`docs/invariants.md`](docs/invariants.md) catalogs the invariants a change must never break;
`make lint-invariants` enforces the machine-checkable ones. Report
vulnerabilities through [SECURITY.md](SECURITY.md), never the public tracker.

## License

Apache-2.0. See [LICENSE](LICENSE).
