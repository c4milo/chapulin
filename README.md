# chapulin

[![coverage](.github/badges/coverage.svg)](https://github.com/c4milo/chapulin/actions/workflows/check.yml?query=branch%3Amain)

A TLS 1.3 client for devices with a few kilobytes of RAM. Named after
El Chapulín Colorado: small, unassuming, and it protects you from the
bad guys.

chapulin speaks one profile and negotiates nothing:
`TLS_CHACHA20_POLY1305_SHA256` with x25519 key exchange, or the
X25519MLKEM768 hybrid ([RFC 10024](https://www.rfc-editor.org/rfc/rfc10024))
instead when you build `make KEX=pq`. One group
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

What changed is the attacker's cost. Reading firmware for mistakes, and
turning one vendor's mistake into a fleet-wide one, is now cheap enough
to do at scale. Side channels moved the same way: machine learning cuts
the traces a power analysis needs by orders of magnitude, so a leak that
was theoretical because nobody would gather a million traces is worth
gathering a thousand for. A defect that survived because exploiting it
was tedious does not survive any more.

That is the case for proving rather than asserting. The profile here is
small enough to state exactly, which is what makes it small enough to
check: every module carries a CBMC harness, the crypto runs against a
Lean specification on every build, and the verification section below
says what is proved, at what bound, and what is only tested. Where a
guarantee does not hold, it says so.

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
| `ch_tls` session struct (includes 622 B TX staging) | 1144 |
| receive buffer you provide (2048 shown; floor `CH_MIN_RXBUF`) | 2048 |
| **total static working set** | **3192** |
| `ch_tls` under `KEX=pq` (includes 1806 B TX staging) | 2328 |
| **total static working set, `KEX=pq`** (2048 buffer) | **4376** |
| peak stack, `ch_connect` (RSA-3072 verify) | 5056 |
| peak stack, `ch_connect` (`PIN=ecdsa`) | 3536 |
| peak stack, `ch_connect` (PSK) | 2480 |
| peak stack, `ch_connect` (`TRUST=ca`, RSA / ECDSA) | 5504 / 3696 |
| peak stack, `ch_read` (worst case: KeyUpdate rekey) | 1712 |
| peak stack, `ch_connect` (`KEX=pq`) | 15808 |
| peak stack, `ch_write` / `ch_close` | 736 / 688 |

The hybrid build costs more of both. The session struct grows because
the ClientHello carries a 1,216-byte key share and is built whole into
one staging array, and the stack grows because ML-KEM's K-PKE encrypt
holds three polynomial vectors and two polynomials: 5,744 bytes in that
one frame, against a 2,560-byte budget for every other build (INV-19
carries the per-build numbers). The whole chain peaks at 15,808 bytes,
through `mlkem_decaps` into K-PKE encrypt and Keccak, so the hybrid
build needs about three times the stack of the classic one rather than
the single frame's 5,744. A device that cannot spare it builds the
classic key exchange.

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
| AEAD seal, per 1 KB record | 74 k | 0.15 |
| SHA-256, per 1 KB | 68 k | 0.14 |
| x25519 scalar multiply | 40.3 M | 81 |
| RSA-3072 PSS verify (default) | 11.6 M | 23 |
| P-256 verify (`PIN=ecdsa`) | 46.0 M | 92 |
| full pinned handshake crypto (default) | 93.0 M | 186 |
| ML-KEM-768 keygen (`KEX=pq`) | 3.2 M | 6 |
| ML-KEM-768 decapsulate (`KEX=pq`) | 3.6 M | 7 |
| full hybrid handshake crypto (`KEX=pq`) | 103.1 M | 206 |

The multiply decomposition that keeps secrets off a variable-time
`umull` sets the first and third rows. Measured against the same
benchmark without it: AEAD seal costs 56% more, x25519 41% more, and
the whole pinned handshake 33% more, or 47 ms at 500 MHz. SHA-256 and
both signature verifies are unchanged, because SHA-256 does not
multiply and the verifies read only public bytes.

Flash is 29.0 kB for the default build (`.text` + `.rodata`, `-Os`),
of which the multiply decomposition is 1.7 kB, nearly all of it
poly1305's unrolled block. The `PIN=ecdsa` build trades 2.3 kB of RSA
for 5.9 kB of P-256 and totals 32.6 kB.

The hybrid key exchange costs less than its wire size suggests. `KEX=pq`
adds two ML-KEM key expansions and one decapsulation — the key pair lives
as a 64-byte seed and is re-expanded rather than stored, which
[`docs/decisions.md`](docs/decisions.md) 24 explains — for 10.1 M
instructions, 11% over the classic handshake. One ML-KEM-768 keygen is
an order of magnitude cheaper than one x25519 on this core, because
chapulin keeps the 16-bit-limb ladder for its machine-checked overflow
proof.

Public-key work dominates. Every handshake runs two x25519 for forward
secrecy, whichever mode it is in, so about 161 ms is the recurring
floor and 87% of the pinned handshake's crypto. The signature verify is
paid only on the first pinned connection; resumptions skip it. Record
crypto is about 0.15 ms per kilobyte, which is negligible beside the
handshake. Because a device typically opens one long-lived connection,
chapulin keeps the 16-bit-limb x25519 for its machine-checked overflow
proof rather than a faster wide-limb version. Many short connections
would change that trade.

## Verification

Four layers cover four different failure classes.

**Proofs cover memory safety.** Twenty-eight of the twenty-nine C
sources are compiled into a [CBMC](https://www.cprover.org/cbmc/) harness, which proves them free of
out-of-bounds access, invalid pointers, bad shifts, and division by
zero, for every input within the harness's bound. Signed overflow is
checked too, except in the three x25519 mul harnesses that turn it off
(see the x25519 row). `tls.c` is the one source with no harness: the
post-handshake parser moved to its own file and took the harness with
it, leaving the four public calls unproven.
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
| sha256 | safe for any two-chunk split | messages ≤ 96 B — every fill state the padding path can see, since fill is the length mod 64 and 0..96 covers all 64 residues |
| sha3 (two harnesses) | every mode is safe for a one-call message and XOF output from a fresh context; the SHAKE streaming calls are safe from any context state — arbitrary lanes, either rate, every position — for split absorbs and squeezes | one-call: messages ≤ 200 B, output ≤ 400 B; streaming: chunks ≤ 32 B |
| mlkem (six harnesses) | keygen, encaps, and decaps are safe for every seed, message, and hostile key or ciphertext, with the polynomial layer stubbed to its contracts; the polynomial layer is safe over full-range int16 coefficients — a superset of anything the KEM layer passes it, so no coefficient value can overflow the reduction arithmetic. Sampling, reductions, and coding prove in the fast tier; the NTT, the two halves of its inverse, and the base multiplication, whose chained-product overflow proofs are the SAT-hard part, each prove in their own slow-tier formula | the full domain: every input is a fixed-size array, and the sampling read stops at its 1536-byte cap |
| hkdf (two harnesses) | hmac/extract and expand/expand-label safe over the proven sha256 contract | keys ≤ 96 B, hmac/extract messages ≤ 48 B; expand/expand-label output ≤ 96 B and info ≤ 64 B (the contract bound), expand: slow tier |
| handshake | the driver stays safe on any record stream: HRR restart, the state machine, and the flight's own arithmetic, in PSK and pinned-key mode. Record reading and message reassembly are stubbed here to the contract the `handshake_record` leg proves — compiling them multiplies this formula by the product of their loop bounds, past any runner. The `TRUST=ca` driver has a harness but no launch line, so it is unproven | 96 B receive buffer, slow tier |
| hybrid_secret | the `KEX=pq` shared-secret derivation is safe for any stored seed, any server ciphertext and any server share, and a refused key exchange wipes all 64 bytes rather than leaving half a secret on the stack (INV-3). ML-KEM and x25519 are stubbed to their contracts, which their own harnesses prove. This is the only leg that builds `-DCH_KEX_PQ`: the rest of the hybrid driver carries the differential, the sequence enumeration and the e2e legs, not a proof | the full domain, fast tier |
| key_share | the `KEX=pq` arm of the ServerHello key_share parser is safe on any extension bytes, and an accepted share hands back a whole readable ML-KEM ciphertext lying inside the bytes the parser consumed — the contract `hybrid_secret` depends on, so neither proof rests on it as an assumption | extension ≤ 1,132 B, the full hybrid share, fast tier |
| hello_build | the ClientHello builder writes nothing outside the caller's buffer at any capacity, for every cookie and PSK identity a caller may pass, and returns either zero or a length that fits. It also checks the bound itself: at `CH_HELLO_MAX` the build always succeeds, so the constant `handshake.c` asserts `CH_TX_STAGE` against is sufficient, not merely plausible | capacity ≤ `CH_HELLO_MAX`, identity ≤ 320 B, cookie ≤ 128 B |
| chacha20 | safe at any counter, in place and into a distinct buffer | ≤ 160 B — three blocks, full, full, partial |
| poly1305 | safe for any three-chunk split; 64-bit products stay in range | messages ≤ 80 B — five blocks, crossing the buffered-block path in every alignment. The five-call shape `aead.c` uses is no longer exercised by a proof: the aead harnesses stub Poly1305, so that shape rests on the unit vectors, Wycheproof and the differential |
| aead (three harnesses) | seal/open round-trips; a forged tag writes zero bytes; backward-overlap decrypt works. ChaCha20 and Poly1305 are stubbed to their contracts — a keystream that is the same for the same key, nonce and counter, and a tag that is a function of the bytes absorbed — which their own harnesses prove. Compiling them in returned no verdict in five hours; the stubbed formulas take about three seconds. What the stubs give up, and why the composition is an argument rather than a machine-checked step, is stated at the top of `proof/aead_stubs.h`. Sealing fully in place (`pt == ct`, the shape every outgoing record uses) is **not proven**: `proof/aead_inplace_harness.c` states it, but the formula has returned no verdict, so it carries no launch line | plaintext ≤ 16 B, aad ≤ 16 B, fast tier |
| x25519 (five harnesses) | carry, add, sub, pack, cswap, and unpack are safe with every check on, add and sub in the ladder's aliased shape too, and the ladder's scalar bit index stays in bounds (fast tier); mul's index walk is safe in every caller aliasing shape — distinct, output aliasing either input, and sqr's all-one-object — with the signed-overflow class off (slow tier, one shape set per formula), and a separate lemma proves mul's int64 accumulation and fold cannot overflow (fast tier). Every one of these holds only inside the limb range in the next column, and nothing proves the ladder keeps its limbs there — see the conditional-proof note below | limbs ≤ 2^24; into carry, ≤ 2^58 |
| p256 | the DER parser and limb marshalling stay safe on hostile signatures; a carry lemma covers the Montgomery multiply | signatures ≤ 80 B |
| rsa (two harnesses) | the PSS decode and limb marshalling stay safe with the RSAVP1 result replaced by arbitrary bytes | 384 B modulus, every byte hostile except the top one, which each call pins to one of the three alignment shapes the decode takes — a symbolic top bit was measured at 7 GB of CNF |
| record | seal works across its contract and returns, not traps, over the whole direction state — any key, IV, and sequence number, the saturation refusal included — and any claimed buffer size; rec_open stays safe on fully hostile bytes, into a separate buffer and in place, the shape both shipped callers use | records ≤ 160 B |
| handshake_record | the record reader stays safe on any stream a peer can send — compaction, CCS tolerance, the quiet cap, in-place decryption, and reassembly across records — and a message it yields lies wholly inside `cfg.buf` with a length that agrees with its own 3-byte header. `hsr_transcript_hash` leaves the running transcript byte for byte as it found it. io_read_record and rec_open are stubbed to the contracts the `io` and `record` legs prove | 12 B receive buffer, `CH_QUIET_CAP` 1 |
| handshake_parser, eeparse, certparse | the ServerHello, EncryptedExtensions, Certificate, and CertificateVerify parsers stay safe on hostile bytes, and the certificate list and signature slices they hand back lie inside the message. The 256-byte bound cannot hold a hybrid key_share, so the `KEX=pq` arm is driven by its own `key_share` leg instead | messages ≤ 256 B |
| handshake_post | the post-handshake parser stays safe on hostile decrypted bytes and consumes no more than its input | messages ≤ 128 B |
| drbg | the generator stays safe for any request, seeded and across rekeys | requests ≤ 96 B |
| x509der (two harnesses) | every DER primitive stays safe on hostile bytes at the rbuf shape its caller hands it, honors the pointer contracts the walker rests on, and consumes no more than the per-primitive cap the walker proof replays, in both builds | inputs ≤ 448 B; keyusage at its 256 B extnValue cap |
| x509parse (two harnesses) | the certificate walker stays safe on any entry list, primitives stubbed to their proven contracts. Only the ECDSA build proves the full two-entry flight; the RSA bound holds one maximum certificate plus framing, so its two-entry walk rests on the ECDSA proof and the walker being identical outside the SPKI arm | ECDSA: ≤ 256 B, two entries; RSA: ≤ 840 B, one entry, slow tier |

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
  exponentiation whole.
- **x25519's field-op proofs are conditional, and nothing discharges the
  condition.** Each one holds inside a stated limb range: `carry` at
  `|limb| < 2^58`, and add, sub and pack at `< 2^24`. `x25519_mul`'s
  lemma proves mul's accumulation and 38x fold land under 2^58, which is
  what `carry` assumes, so those two meet. The step above them does not.
  `ladder` runs 255 rounds of cswap, add, sub, mul, sqr and carry, and
  `inv` 254 more, and nothing checks the limbs it hands each operation
  are inside that operation's assumed range. The harness header calls the
  ~2^17 the ladder is believed to produce an observation, not a checked
  claim. So a missing `carry()` after a chain of adds would leave every
  x25519 harness passing.
  Unwinding the composition was measured and does not work: one ladder
  step, and half of one, each demand more than about 14 GB, and the
  demand does not fall with the multiply count, so shaving the step down
  is not the lever. CBMC function contracts would close it by never
  building the composed formula, and `docs/proofs.md` records why this
  tree does not carry proof annotations in shipped source. Until that
  trade changes, the limb-growth invariant is an assumption the x25519
  proofs rest on, held by the RFC 7748 vectors and the differential
  rather than by a checker.
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
  On a core with no hardware multiplier the compiler turns every `*`
  into a runtime-library call that branches on its operands, which would
  undo this in poly1305, x25519 and ML-KEM; `softmul.c` supplies
  constant-time `__mulsi3` and `__muldi3` under those names, so they
  replace the library's at link time. `make lint-runtime-symbols` builds
  for rv32ic and fails on any runtime call beyond the one that remains,
  `__udivsi3`, which sha3 uses for `% 5` over public loop counters.
  A multiplier that exists but is variable-time is the other half. ARM's
  Cortex-M3 `umull` returns sooner when both operands are below 65536,
  with further undocumented exits on zero and powers of two, and 32-bit
  x86 and PowerPC have the same shape; the M3's 32-to-32 `mul` does not.
  So `ct.h` builds every widening product out of four 16x16 pieces, and
  poly1305, x25519 and ML-KEM emit no wide multiply on the M3 or on
  mips32r2 — `make lint-wide-multiply` disassembles for both and holds
  the count at zero. What is left is the 32-to-32 multiply, which ARM
  documents as single-cycle on the M3. mips32r2 does not document its
  own, so the decomposition narrows that part's exposure rather than
  closing it; `ct.h` says so. Every target gets the decomposition unless
  its build passes `CH_NATIVE_WIDEMUL`, and there is no list of
  architectures exempt by name: RISC-V publishes Zkt to attest
  data-independent latency, Arm publishes FEAT_DIT and Intel DOITM, and
  all three exist because the base architectures do not promise it, so
  no architecture macro carries the claim. The Makefile passes that flag
  for host test binaries, where nothing secret is at risk and solver
  time is, and filters it out of the packaged object. That cost is
  measured, not assumed: 33% of the pinned handshake's crypto and 1.7 kB
  of flash, itemised under Speed and flash above.

  The decomposition is also what carries every other proof to the
  target. Those formulas verify the single-multiply form, since the
  proof runner asserts `CH_NATIVE_WIDEMUL` on the development machine,
  so they describe what ships only if the two forms compute the same
  function. `proof/ctwidemul_harness.c` proves that: UB and shift range
  at full 32-bit width, and the products themselves against the C
  operator at 8-bit operands, the widest bound whose formula converges.
  `make timing` measures the decomposed path rather than the host's
  native one.
- The quality of the random bytes, which rests on nothing here at all.
  `ch_rand_bytes` is the image's to supply, and no check in a library
  can grade it: a weak generator completes the handshake, sends a key
  share that looks uniform on the wire, and returns `CH_OK`. Two things
  narrow the gap and neither closes it. The build makes the choice
  explicit instead of silent — `RAND=extern` or `RAND=drbg`, no default
  — and every draw in `handshake.c` is compared against all-zero, which
  catches a hook that returned without writing. A weak generator passes
  both. [`docs/entropy.md`](docs/entropy.md) carries the rest.

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

[`docs/porting.md`](docs/porting.md) is the checklist for a new platform: what
you decide, what has a safe default, and how to check on your own target that
the constant-time multiply survived your compiler. It carries a measured case
where it does not.

You provide two blocking socket callbacks with your own timeouts, and
`ch_rand_bytes` (`rand.h`). Use the hardware generator if the part has
one, or the seeded generator in `drbg.[ch]` if it does not — the
RTL8382-class reference target has none. It refuses to run unseeded;
[`docs/entropy.md`](docs/entropy.md) covers seed provisioning.

Say which of the two the image uses. `RAND=extern` leaves
`ch_rand_bytes` for you to define, so an image that never wired a
generator fails to link. `RAND=drbg` packages the reference generator
and exports a fifth call, `ch_drbg_seed`, for the image to call once at
boot. There is no default: a build naming neither stops at an `#error`.
No build can judge a generator — a weak one completes the handshake,
sends a key share that looks uniform, and returns `CH_OK` — so writing
the choice down is the only part a compiler can hold you to.

Any error kills the session. The stack wipes its keys and you
reconnect. Devices recover by reconnecting anyway, and the rule removes
the whole resumable-error state space from the code and the proofs.

## Building

`make check` runs the gate: build with warnings as errors, linters,
unit tests, end-to-end against OpenSSL and Go, the differential oracle,
and the fast proof tier.

Other targets:

- `make lib RAND=extern` packages the library as one relocatable object
  (`bin/chapulin.o`) exporting exactly the four public calls. Every
  internal symbol is localized, and `lib-check` fails if the export
  list ever grows. `RAND=drbg` packages the reference generator instead
  and exports `ch_drbg_seed` as a fifth call. `RAND` is the one build
  variable with no default. Compose with `PIN=ecdsa`, `TRUST=ca` and
  `KEX=pq`.
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
