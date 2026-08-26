# chapulin

[![coverage](.github/badges/coverage.svg)](https://github.com/c4milo/chapulin/actions/workflows/check.yml?query=branch%3Amain)

A TLS 1.3 client for devices with a few kilobytes of RAM. Named after
El Chapulín Colorado: small, unassuming, and it protects you from the
bad guys.

chapulin speaks one profile and negotiates nothing:
`TLS_CHACHA20_POLY1305_SHA256` with x25519 key exchange, or the
X25519MLKEM768 hybrid instead when you build `make KEX=pq`. One group
per build, never both in one ClientHello. The server takes it or the
handshake fails. There is no 0-RTT.

It uses C11 and libc only, and never calls `malloc`. The working set is
one session struct plus one receive buffer you provide.

## Why this exists

Much of the internet's attack traffic comes from bot networks built out
of embedded devices — routers, cameras, sensors — that someone else
controls. They are easy to take over, and they stay taken over.

Transport security is not the whole answer, but going without it is a
large part of the problem, and the reason vendors go without is usually
price or size.

The small, well-supported embedded TLS stacks are commercial: SEGGER
emSSL, SharkSSL, Tuxera. The widely deployed open one, wolfSSL, is
GPLv3 or a licence fee, and proprietary firmware pays the fee. The
permissively licensed stacks do not close the gap either. BearSSL is
MIT, heap-free, and the closest design ancestor, but it still has no
TLS 1.3 in 2026. picotls and Mbed TLS have TLS 1.3 and cannot run
without an allocator, Mbed TLS at 9 to 15 kB of working RAM.

So a vendor with a few kilobytes of SRAM and no budget for middleware
ships plaintext, or something hand-rolled, and the device joins the
next bot network.

chapulin answers that narrow case: TLS 1.3 in about 3 kB of static
working set, no heap, Apache-2.0, and proofs an auditor can check
rather than trust. [`docs/landscape.md`](docs/landscape.md) surveys the field with sources.

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
| `ch_tls` under `KEX=pq` (includes 1806 B TX staging) | 2328 |
| **total static working set, `KEX=pq`** (2048 buffer) | **4376** |
| peak stack, `ch_connect` (RSA-3072 verify) | 5168 |
| peak stack, `ch_connect` (`PIN=ecdsa`) | 3648 |
| peak stack, `ch_connect` (PSK) | 2592 |
| peak stack, `ch_connect` (`TRUST=ca`, RSA / ECDSA) | 5760 / 3952 |
| peak stack, `ch_read` (worst case: KeyUpdate rekey) | 1632 |
| peak stack, `ch_write` / `ch_close` | 736 / 688 |

The hybrid build costs more of both. The session struct grows because
the ClientHello carries a 1,216-byte key share and is built whole into
one staging array, and the stack grows because ML-KEM's K-PKE encrypt
holds three polynomial vectors and two polynomials: 5,744 bytes in that
one frame, against a 2,560-byte budget for every other build (INV-19
carries the per-build numbers). Its `ch_connect` peak is **not measured
yet**: `bench/stack.py` reads arm64 relocations and reports nothing
usable on other hosts, so the whole-chain number has to come from the
reference machine. Until it does, 5,744 bytes is the floor, not the
peak. A device that cannot spare it builds the classic key exchange.

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

**Proofs cover memory safety.** Twenty-four of the twenty-eight C
sources are compiled into a [CBMC](https://www.cprover.org/cbmc/) harness, which proves them free of
out-of-bounds access, invalid pointers, bad shifts, and division by
zero, for every input within the harness's bound. Signed overflow is
checked too, except in the three x25519 mul harnesses that turn it off
(see the x25519 row). `handshake_message.c`, `io.c`, `keysched.c`, and
`tls.c` have no harness.
`make check` regenerates the source-by-source table in
`bin/proof-coverage.md`. Where a bound equals the module's real
maximum, the proof covers all inputs.

The proofs run in two tiers. `make check` runs the fast tier and gates
every push. `make prove-slow` runs the slow-tier legs, which CI runs
nightly, one job each. [`docs/proofs.md`](docs/proofs.md) is the
harness playbook: the measured cost model and the rules that keep a
formula solvable. A slow-tier row below carries the verdict of the last nightly
leg that finished, not of the current commit. A harness that starts and
returns no verdict proves nothing, and this table cannot tell that
apart from one that passed — so for the slow rows, read the nightly.

| harness | proves | bound |
|---|---|---|
| ct | memeq matches a plain compare, wipe zeroizes | inputs ≤ 64 B |
| buf | any 12-operation reader/writer run stays safe; length never exceeds capacity | buffers ≤ 64 B |
| sha256 | safe for any two-chunk split | messages ≤ 96 B |
| sha3 (two harnesses) | every mode is safe for a one-call message and XOF output from a fresh context; the SHAKE streaming calls are safe from any context state — arbitrary lanes, either rate, every position — for split absorbs and squeezes | one-call: messages ≤ 200 B, output ≤ 400 B; streaming: chunks ≤ 32 B |
| mlkem (six harnesses) | keygen, encaps, and decaps are safe for every seed, message, and hostile key or ciphertext, with the polynomial layer stubbed to its contracts; the polynomial layer is safe over full-range int16 coefficients — a superset of anything the KEM layer passes it, so no coefficient value can overflow the reduction arithmetic. Sampling, reductions, and coding prove in the fast tier; the NTT, the two halves of its inverse, and the base multiplication, whose chained-product overflow proofs are the SAT-hard part, each prove in their own slow-tier formula | the full domain: every input is a fixed-size array, and the sampling read stops at its 1536-byte cap |
| hkdf (two harnesses) | hmac/extract and expand/expand-label safe over the proven sha256 contract | keys ≤ 96 B, hmac/extract messages ≤ 48 B; expand/expand-label output ≤ 96 B and info ≤ 64 B (the contract bound), expand: slow tier |
| handshake | the driver stays safe on any record stream: record reading, reassembly, HRR restart, state machine, in PSK and pinned-key mode. The `TRUST=ca` driver has a harness but no launch line, so it is unproven, and no harness builds with `-DCH_KEX_PQ` at all — the hybrid driver's share expansion and decapsulation carry no proof, only the differential, the sequence enumeration and the e2e legs | 96 B receive buffer, slow tier |
| chacha20 | safe at any counter, in place and into a distinct buffer | ≤ 160 B |
| poly1305 | safe for any three-chunk split; 64-bit products stay in range | messages ≤ 80 B |
| aead (three harnesses) | seal/open round-trips; a forged tag writes zero bytes; backward-overlap decrypt works. These are structural, so the bound is small: 16 B crosses the Poly1305 block boundary and the forge case fires at one byte. Sealing fully in place (`pt == ct`, the shape every outgoing record uses) is **not proven**: `proof/aead_inplace_harness.c` states it, but the formula has returned no verdict, so it carries no launch line | plaintext ≤ 16 B, aad ≤ 16 B, slow tier |
| x25519 (five harnesses) | carry, add, sub, pack, cswap, and unpack are safe with every check on, add and sub in the ladder's aliased shape too, and the ladder's scalar bit index stays in bounds (fast tier); mul's index walk is safe in every caller aliasing shape — distinct, output aliasing either input, and sqr's all-one-object — with the signed-overflow class off (slow tier, one shape set per formula), and a separate lemma proves mul's int64 accumulation and fold cannot overflow (fast tier). The ladder's limb-growth composition is still an open task | limbs ≤ 2^24; into carry, ≤ 2^58 |
| p256 | the DER parser and limb marshalling stay safe on hostile signatures; a carry lemma covers the Montgomery multiply | signatures ≤ 80 B |
| rsa (two harnesses) | the PSS decode and limb marshalling stay safe with the RSAVP1 result replaced by arbitrary bytes | 384 B modulus, every byte hostile except the top one, which each call pins to one of the three alignment shapes the decode takes — a symbolic top bit was measured at 7 GB of CNF |
| record | seal works across its contract and returns, not traps, over the whole direction state — any key, IV, and sequence number, the saturation refusal included — and any claimed buffer size; rec_open stays safe on fully hostile bytes, into a separate buffer and in place, the shape both shipped callers use | records ≤ 160 B |
| handshake_parser, eeparse, certparse | the ServerHello, EncryptedExtensions, Certificate, and CertificateVerify parsers stay safe on hostile bytes, and the certificate list and signature slices they hand back lie inside the message. The 256-byte bound cannot hold a hybrid key_share, so the `KEX=pq` arm of the ServerHello parser is unproven | messages ≤ 256 B |
| handshake_post | the post-handshake parser stays safe on hostile decrypted bytes and consumes no more than its input | messages ≤ 128 B |
| drbg | the generator stays safe for any request, seeded and across rekeys | requests ≤ 96 B |
| x509der (two harnesses) | every DER primitive stays safe on hostile bytes at the rbuf shape its caller hands it, honors the pointer contracts the walker rests on, and consumes no more than the per-primitive cap the walker proof replays, in both builds | inputs ≤ 448 B; keyusage at its 256 B extnValue cap |
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
  around it — record reading and cross-record reassembly — does not
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
computes: SHA-256, SHA-3 and both SHAKE XOFs, ML-KEM-768, HKDF and the
key schedule, ChaCha20, Poly1305, the AEAD, record framing, x25519,
P-256, RSA-PSS, and the grammar of the
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
function, and [`test/handshake_sequence_test.c`](test/handshake_sequence_test.c) enumerates every server message
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
  list ever grows. Compose with `PIN=ecdsa`, `TRUST=ca` and `KEX=pq`.
- `make prove-slow` runs the slow-tier proofs, one per nightly job. The runner caches by
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
