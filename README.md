# chapulin

[![coverage](https://raw.githubusercontent.com/c4milo/chapulin/badges/.github/badges/coverage.svg)](https://github.com/c4milo/chapulin/actions/workflows/check.yml?query=branch%3Amain)

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

[`bench/sram.sh`](bench/sram.sh) measures every number below and writes
them to [`bench/results-sram.csv`](bench/results-sram.csv);
`make lint-bench-numbers` fails when this table disagrees with that file.
The session struct is measured twice, once native on arm64 and once for
rv32ic — the byte-count constants do not move, only the pointer fields, so
a 32-bit device needs 80 bytes less than the host figure in either build.
The stack peaks are arm64 only: `bench/stack.py` reads arm64 relocations,
so an rv32 peak needs tooling that does not exist yet.

| what | arm64 | rv32 |
|---|---|---|
| `ch_tls` session struct (includes 622 B TX staging) | 1144 | 1064 |
| receive buffer you provide (2048 shown; floor `CH_MIN_RXBUF`) | 2048 | 2048 |
| **total static working set** | **3192** | **3112** |
| `ch_tls` under `KEX=pq` (includes 1806 B TX staging) | 2328 | 2248 |
| **total static working set, `KEX=pq`** (2048 buffer) | **4376** | **4296** |
| peak stack, `ch_connect` (RSA-3072 verify) | 5056 |
| peak stack, `ch_connect` (`PIN=ecdsa`) | 3536 |
| peak stack, `ch_connect` (PSK) | 2432 |
| peak stack, `ch_connect` (`TRUST=ca`, RSA / ECDSA) | 5504 / 3696 |
| peak stack, `ch_read` (worst case: KeyUpdate rekey) | 1712 |
| peak stack, `ch_connect` (`KEX=pq`) | 15808 |
| peak stack, `ch_write` / `ch_close` | 912 / 864 |

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

Provisioning with `ch_pubkey_from_pem` needs three more caller-side
buffers, none of them part of the static working set above and none of
them live between calls: the staged PEM text (up to `CH_PEM_MAX`,
3,136 bytes RSA or 1,600 ECDSA), a scratch array for the decoded
certificate (`CH_X509_MAX`, 1,536 or 768), and the key slot the device
already needed (`CH_X509_KEY_MAX`, 384 or 64). The scratch must not be
`cfg.buf` while a session is live: `ch_read` serves unread plaintext
out of that buffer across calls. The call itself measures 576 bytes of
stack, reported by `bench/stack.py` beside the other public calls.

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

[`bench/insn-mips.sh`](bench/insn-mips.sh) and [`bench/device-ram.sh`](bench/device-ram.sh) cross-compile for mips32r2,
the reference target's ISA (32-bit, big-endian, in-order), and measure
on that ISA. Cost is published as instruction counts, not guessed
milliseconds. The millisecond column assumes 500 MHz and one
instruction per cycle on that core, which is optimistic for an in-order
design, so read it as a lower bound. Every count is a property of what
one compiler emits, so each column names its compiler. The mips32r2
column is Alpine's clang 22 at `-Os` (`CLANG_MAJOR` in
[`bench/toolchain.env`](bench/toolchain.env)); the flash figures below
come from clang 23 at `-Os` (`LLVM_MAJOR` in
[`tools/toolchain.env`](tools/toolchain.env)), the clang the codegen
lints run.
[`bench/insn-m3.sh`](bench/insn-m3.sh) measures the same operations as
thumbv7m instruction counts on QEMU's Cortex-M3, the core the m3 and
freertos CI lanes execute, built with the pinned Arm GNU Toolchain
15.3.rel1 gcc (`ARM_GNU_VERSION`) at `-O2`.
[`bench/insn-rv32.sh`](bench/insn-rv32.sh) measures them a third time
as rv32imac instruction counts: the 32-bit little-endian build the
riscv32 CI lane ships, compiled by the pinned Bootlin gcc 14.3.0
(`RV32_TC_VERSION`) at `-Os` and run under qemu-riscv32 user mode. All
three instruction columns run the multiply decomposition firmware
ships.

| work | mips32r2 insns | ms (500 MHz, 1 IPC) | Cortex-M3 insns | rv32imac insns |
|---|---|---|---|---|
| AEAD seal, per 1 KB record | 82 k | 0.16 | 68 k | 107 k |
| SHA-256, per 1 KB | 68 k | 0.14 | 57 k | 90 k |
| x25519 scalar multiply | 38.9 M | 78 | 27.4 M | 51.4 M |
| RSA-3072 PSS verify (default) | 11.6 M | 23 | 8.4 M | 13.2 M |
| P-256 verify (`PIN=ecdsa`) | 46.0 M | 92 | 26.7 M | 42.6 M |
| full pinned handshake crypto (default) | 90.2 M | 180 | 63.8 M | 117.0 M |
| ML-KEM-768 keygen (`KEX=pq`) | 3.2 M | 6 | 2.7 M | 3.6 M |
| ML-KEM-768 decapsulate (`KEX=pq`) | 3.6 M | 7 | 3.0 M | 4.1 M |
| full hybrid handshake crypto (`KEX=pq`) | 100.4 M | 201 | 72.2 M | 128.3 M |

The multiply decomposition that keeps secrets off a variable-time
`umull` sets the first and third rows in every instruction column.
Measured against the same benchmark with the native multiply instead:
on mips32r2, AEAD seal costs 73% more, x25519 36% more, and the whole
pinned handshake 29% more, or 41 ms at 500 MHz; on the Cortex-M3, AEAD
seal costs 93% more, x25519 129% more, and the pinned handshake 94%
more; on rv32imac, AEAD seal costs 66% more, x25519 137% more, and the
pinned handshake 104% more. SHA-256 and both signature verifies are
unchanged, because SHA-256 does not multiply and the verifies read only
public bytes.

Flash is 27.9 kB for the default build (`.text` + `.rodata`, `-Os`),
of which the multiply decomposition is 2.3 kB, nearly all of it
poly1305's unrolled block. The `PIN=ecdsa` build trades 2.2 kB of RSA
for 5.8 kB of P-256 and totals 31.4 kB.

The hybrid key exchange costs less than its wire size suggests. `KEX=pq`
adds two ML-KEM key expansions and one decapsulation — the key pair lives
as a 64-byte seed and is re-expanded rather than stored, which
[`docs/decisions.md`](docs/decisions.md) 24 explains — for 10.2 M
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

**Proofs cover memory safety.** Thirty of the thirty-one C
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

The proofs run in two tiers. `make check-slow` runs the fast tier
through `make prove`; CI runs it on every push to main but not on a
pull request, which gets `make check` and no proof leg. `make
prove-slow` runs the slow-tier legs, which CI runs nightly, one job
each. [`docs/proofs.md`](docs/proofs.md) is the
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
| x25519 (ten harnesses) | carry, add, sub, pack, cswap, and unpack are safe with every check on, add and sub in the ladder's aliased shape too, and the ladder's scalar bit index stays in bounds (fast tier); mul's index walk is safe in every caller aliasing shape — distinct, output aliasing either input, and sqr's all-one-object — with the signed-overflow class off (slow tier, one shape set per formula), and a separate lemma proves mul's int64 accumulation and fold cannot overflow (fast tier). Every one of these holds only inside the limb range in the next column, and `x25519_step` and `x25519_tail` prove the ladder keeps its limbs there: one loop step, on the shipped `step()`, takes any state with every limb in (-2^17, 2^17) back into that bound and hands mul only operands under 2^18; mul's output, one `invert` round, and the final multiply and pack do the same. The 255 steps and 254 rounds follow by induction from a base case read off `ladder()`'s prologue. Both harnesses replace mul's multiply with a magnitude contract (`proof/x25519_stubs.h`) that `x25519_mul` discharges on the native multiply and `x25519_mul_ct` on the shipped decomposition — see the note below | limbs ≤ 2^24; into carry, ≤ 2^58; between the ladder's operations, < 2^17 |
| p256 | the DER parser and limb marshalling stay safe on hostile signatures; a carry lemma covers the Montgomery multiply | signatures ≤ 80 B |
| rsa (two harnesses) | the PSS decode and limb marshalling stay safe with the RSAVP1 result replaced by arbitrary bytes | 384 B modulus, every byte hostile except the top one, which each call pins to one of the three alignment shapes the decode takes — a symbolic top bit was measured at 7 GB of CNF |
| record | seal works across its contract and returns, not traps, over the whole direction state — any key, IV, and sequence number, the saturation refusal included — and any claimed buffer size; rec_open stays safe on fully hostile bytes, into a separate buffer and in place, the shape both shipped callers use | records ≤ 160 B |
| handshake_record | the record reader stays safe on any stream a peer can send — compaction, CCS tolerance, the quiet cap, in-place decryption, and reassembly across records — and a message it yields lies wholly inside `cfg.buf` with a length that agrees with its own 3-byte header. `hsr_transcript_hash` leaves the running transcript byte for byte as it found it. io_read_record and rec_open are stubbed to the contracts the `io` and `record` legs prove | 12 B receive buffer, `CH_QUIET_CAP` 1 |
| handshake_parser, eeparse, certparse | the ServerHello, EncryptedExtensions, Certificate, and CertificateVerify parsers stay safe on hostile bytes, and the certificate list and signature slices they hand back lie inside the message. The 256-byte bound cannot hold a hybrid key_share, so the `KEX=pq` arm is driven by its own `key_share` leg instead | messages ≤ 256 B |
| handshake_post | the post-handshake parser stays safe on hostile decrypted bytes and consumes no more than its input | messages ≤ 128 B |
| drbg | the generator stays safe for any request, seeded and across rekeys | requests ≤ 96 B |
| x509der (two harnesses) | every DER primitive stays safe on hostile bytes at the rbuf shape its caller hands it, honors the pointer contracts the walker rests on, and consumes no more than the per-primitive cap the walker proof replays, in both builds | inputs ≤ 448 B; keyusage at its 256 B extnValue cap |
| x509parse (two harnesses) | the certificate walker stays safe on any entry list, primitives stubbed to their proven contracts. Only the ECDSA build proves the full two-entry flight; the RSA bound holds one maximum certificate plus framing, so its two-entry walk rests on the ECDSA proof and the walker being identical outside the SPKI arm | ECDSA: ≤ 256 B, two entries; RSA: ≤ 840 B, one entry, slow tier |
| pem_step (two harnesses) | `b64_value` returns exactly what RFC 4648 §4's alphabet table returns, on all 256 bytes; `pad_ok` is exactly §3.5's rule; and one body character preserves the decoder's accounting invariant from any state it admits, so induction carries that invariant to any input length | unbounded — one character, any state |
| pem (two harnesses) | the PEM decoder stays safe on hostile bytes at the shipped caps and honors its contract: a success yields a non-empty length inside the caller's array, every rejection yields zero, and an input over `CH_PEM_MAX` is refused before a byte is read | inputs ≤ 64 B (see the limit below) |
| x509ca (two harnesses) | the provisioning walk stays safe on any input and honors its contract: a success yields a key inside `CH_X509_KEY_MAX`, and every rejection yields zero with the key wiped. DER primitives stubbed to the contracts the `x509der` leg proves, and the SPKI stub deliberately returns lengths outside the real range so the entry's own bound check is what keeps the copy in range | any input; decoded certificate ≤ `CH_X509_MAX` |

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

- PEM input longer than 64 bytes. The decoder is a per-character state
  machine over symbolic bytes, the shape bounded model checking pays
  most for — measured at roughly the third power of the input length,
  so the shipped 3,136-byte cap is out of reach. 64 is the floor that
  still works: the shortest accepting input is 58 bytes, and at 56 the
  success arm is unreachable and its assertion passes vacuously while
  the run still reports success. What carries past 64 is stated in
  `proof/pem_harness.c`: `pem.c` does no raw buffer arithmetic, so
  memory safety is `buf.c`'s, and `pem_step` proves the per-character
  invariant from an arbitrary state. What does not carry is the
  boundary sequence at lengths this bound never reaches, which
  `test/diff_pem.h` exercises to `CH_PEM_MAX` against the Lean oracle
  instead. No fuzz target covers this parser, on purpose: the
  differential drives the same domain against an oracle that checks
  the verdict and the bytes, where a fuzzer checks only for a crash,
  and a sixth target would push the nightly fuzz job past the budget
  `lint-fuzz-budget` holds.

- x25519 and P-256 and RSA functional correctness. Each rests on
  published vectors ([RFC 7748](https://www.rfc-editor.org/rfc/rfc7748) including the 1,000-iteration chain,
  [RFC 6979](https://www.rfc-editor.org/rfc/rfc6979), OpenSSL-produced PSS at 2048 and 3072 bits) plus fresh
  signatures the Lean spec mints and the C must accept. CBMC proves
  the pieces; it does not run a scalar multiplication or a 3072-bit
  exponentiation whole.
- **x25519's ladder proof abstracts the multiply to its magnitude.** Each
  field-op proof holds inside a stated limb range: `carry` at `|limb| <
  2^58`, and add, sub, mul and pack at `< 2^24`. `x25519_step` and
  `x25519_tail` prove the ladder stays inside them, and the machine-checked
  part is one loop step and one `invert` round, each from any state with
  every limb in (-2^17, 2^17) back into it, on the shipped `step`,
  `sqr`, `mul` and `pack`. The 255 steps and 254 rounds are an induction
  over that, and its base case — `a = d = 1`, `c = 0`, `b` the unpacked
  point — is read from five lines of `ladder()`, not checked. The
  abstraction: mul's 256 products per call put 2,560 symbolic multiplies
  in one step, and that formula returned no verdict past 14 GB, so
  `proof/x25519_stubs.h` replaces `ct_widemul_s` with a contract —
  operands under 2^18, product in [-2^36, 2^36) — and two harnesses prove
  `ct_widemul_s` meets it, each with every check on and at the contract's
  own operand range: `x25519_mul` on the native `(int64_t)a * b` arm the
  proof runner compiles, and `x25519_mul_ct` on the 16x16 decomposition
  firmware ships ([#145](https://github.com/c4milo/chapulin/issues/145)).
  A bound is a cheaper question than equality: `ctwidemul`'s proof that
  the two forms compute the same product converges only at 8-bit
  operands; the decomposition's product bound proves at the full range
  in 128 s. No
  property in the ladder harnesses reads a product's value, only bounds,
  so the composition loses nothing the stub header does not state. The stub
  also checks each operand after mul's narrowing to int32; the header
  says why no limb reaches that narrowing outside its exact range.
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
  every secret-touching source for rv32ic under the pinned clang and
  holds, file by file, the runtime calls each may make: `__mulsi3` in
  poly1305, x25519 and mlkem_poly, `__udivsi3` in sha3 for `% 5` over
  public loop counters, and none anywhere else; it also checks that
  `softmul.c` still defines the two names it admits. It measures clang.
  Under the Bootlin riscv32 gcc at `-Os`, `softmul.c` used to recurse:
  gcc rewrote `__muldi3`'s mask select `a & (0 - bit)` as `a * bit`,
  which on that core is a call to `__muldi3` from inside `__muldi3`.
  The mask is now an arithmetic shift of the bit, a form gcc keeps at
  every optimization level, and the rv32ic spec of
  `make lint-wide-multiply-gcc` counts under that gcc the calls to
  `__muldi3` in every secret-touching file and holds `softmul.c` at
  zero, so the rewrite cannot come back unseen. `docs/porting.md` shows
  the count per file.
  A multiplier that exists but is variable-time is the other half. ARM's
  Cortex-M3 `umull` returns sooner when both operands are below 65536,
  with further undocumented exits on zero and powers of two, and 32-bit
  x86 and PowerPC have the same shape; the M3's 32-to-32 `mul` does not.
  So `ct.h` builds every widening product out of four 16x16 pieces.
  `make lint-wide-multiply` compiles every secret-touching source — the
  chain from ct.c to tls.c, drbg.c and softmul.c, twenty-four files —
  for Cortex-M3, mips32r2 and rv32imac and counts, per file, the
  widening multiplies, the divisions and the calls into the compiler's
  64-bit division runtime, matching each opcode as a prefix so a
  condition-code suffix cannot hide one. Under the pinned clang every
  file is at zero except sha3, whose public `% 5` is one multiply-high.
  `make lint-wide-multiply-gcc` runs the same count under the gcc each
  CI lane ships -- the Arm GNU gcc for the Cortex-M3, Ubuntu's gcc for
  mips32r2 and the Bootlin gcc for rv32imac and rv32ic -- and at `-Os`
  every file is at zero there too, except sha3's `% 5`, which each gcc lowers
  to five hardware divisions, or on rv32ic to five calls to `__modsi3`. It was not always so: gcc fused the
  decomposition's 64-bit cross-product sum back into `umlal`, and
  rewrote the sign mask `x & (0 - bit)` in `ct_widemul_s` and in
  x25519's `cswap` as a multiply by the secret bit, eight widening
  multiplies on the M3 and one on rv32imac, until the rework in `ct.h`
  and `x25519.c` removed both forms
  ([#106](https://github.com/c4milo/chapulin/issues/106));
  `test/violations/inv16-widemul-mid-widened.violation` puts the old
  sum back and requires the gcc gate to object. The gate compiles at
  `-Os`, and the mips gcc spec runs once more at `-O2`, where that gcc
  inlines `ct_widemul` into poly1305's block and puts two of its 75
  `product + x` sums through `madd`, a multiply-accumulate through the
  64-bit HI/LO pair, on the same 16-bit operands. The gate holds that
  count at two as a record, not an allowance: the one form that hands
  gcc no such sum costs 38% of AEAD seal on mips32r2, and
  `docs/porting.md` has the measurements and the violation the `-O2`
  spec alone catches
  ([#122](https://github.com/c4milo/chapulin/issues/122)).
  The same pass counts the conditional branches each compiler emits
  — `b<cond>`, `cbz`, `cbnz` and IT blocks on arm, `beq`, `bne` and
  the compare-with-zero forms on mips, the six base branches and the
  compressed pair on rv32 — in the twelve arithmetic files under the
  record layer, and holds each file at a ceiling measured per
  compiler. Those ceilings are public loop control, not zero: the
  block loops, x25519's ladder, Keccak's counters and softmul's fixed
  iterations. So the gate holds that no count grows, not that no
  branch exists, and what the ceilings record is that the
  compare-carries in `ct_widemul_opaque` and the sign masks in
  `ct_widemul_s` and `poly1305_final` compile to a predicated
  instruction, `sltu` or a shift under every compiler measured --
  each compiler's choice, with no check on it until the count
  ([#141](https://github.com/c4milo/chapulin/issues/141)).
  `test/violations/inv16-poly1305-final-sign-branch.violation` writes
  the final select as an `if` on the last limb's sign and every spec's
  count rises by one; `inv16-widemul-s-sign-branch` does the same to
  `ct_widemul_s`, and clang lowers it back to the mask while every gcc
  emits two branches in x25519, so only the gcc gate objects. What is
  left is the 32-to-32 multiply, which ARM documents as single-cycle
  on the M3. mips32r2 does not document its own, so on that core the
  decomposition narrows the exposure rather than closing it; `ct.h`
  says so, and that is the stated assumption, by decision
  (https://github.com/c4milo/chapulin/issues/53): a vendor statement
  on the multiply's timing would close it, and nothing in this tree
  can. Every target gets the decomposition unless
  its build passes `CH_NATIVE_WIDEMUL`, and there is no list of
  architectures exempt by name: RISC-V publishes Zkt to attest
  data-independent latency, Arm publishes FEAT_DIT and Intel DOITM, and
  all three exist because the base architectures do not promise it, so
  no architecture macro carries the claim. The Makefile passes that flag
  for host test binaries, where nothing secret is at risk and solver
  time is, and filters it out of the packaged object. That cost is
  measured, not assumed: 29% of the pinned handshake's crypto and 2.3 kB
  of flash, itemised under Speed and flash above.

  The decomposition is also what carries every other proof to the
  target. Those formulas verify the single-multiply form, since the
  proof runner asserts `CH_NATIVE_WIDEMUL` on the development machine,
  so they describe what ships only if the two forms compute the same
  function. `proof/ctwidemul_harness.c` proves that: UB and shift range
  at full 32-bit width, and the products themselves against the C
  operator at 8-bit operands, the widest bound whose formula converges.
  The x25519 ladder proofs need less than equality: their contract on
  `ct_widemul_s` is a product bound, and `x25519_mul_ct` proves it on the
  decomposition at the ladder's full operand range.
  `make timing` measures the decomposed path rather than the host's
  native one. `make ct-widemul-check`, in `check-slow`, rebuilds the
  unit, ML-KEM and Wycheproof binaries with `CH_CT_WIDEMUL`, so the
  RFC 7748, RFC 8439 and RFC 8448 vectors, the FIPS 203 known answers
  and the Wycheproof cases are also checked over the decomposition as
  poly1305, x25519 and mlkem_poly inline it — evidence at those inputs,
  while the equality proof stays at 8-bit operands.
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
the sanitizer is armed. Line coverage is measured and gated in CI.

## Supported platforms

Supported means the suites run there in CI on every pull request and
every merge to main — a claim each row's job re-earns per commit, not
a compatibility list:

| platform | how the suites run | CI job |
| --- | --- | --- |
| Linux x86_64 | natively, plus every lint, proof gate and sanitizer | `check`, `san` |
| Linux arm64 | natively, the whole deterministic roster (`make suite-check`) | `arm64` |
| mips32r2 (big-endian) | cross-built, under qemu user mode (`make cross-check`) | `mips` |
| riscv32 | cross-built with Bootlin's pinned musl toolchain, under qemu user mode | `riscv32` |
| Cortex-M3 (bare metal) | unmodified suites through newlib semihosting on QEMU's MPS2-AN385 (`make m3-check`) | `m3` |
| FreeRTOS on Cortex-M3 | the pinned kernel boots, two static tasks must interleave, and a task completes a TLS 1.3 handshake through FreeRTOS+TCP to a live `openssl s_server`, application data verified (`make freertos-check`) | `freertos` |

Two suites stay off the bare-metal rows because they fork a `diffspec`
child; every Linux row runs them. macOS is the development host and
runs everything but is not a deployment target. For a platform not
listed, [`docs/porting.md`](docs/porting.md) is the checklist, and the
Cortex-M3 lane is the template for wiring a new emulated target.

## The differential oracle

[`spec/`](spec/) is an executable [Lean 4](https://lean-lang.org/) specification of everything chapulin
computes: SHA-256, SHA-3 and both SHAKE XOFs, ML-KEM-768, HKDF and the
key schedule, ChaCha20, Poly1305, the AEAD, record framing, x25519,
P-256, RSA-PSS, the grammar of the
four handshake messages a server sends, and the provisioning path —
RFC 7468 armour with RFC 4648 base64, and the certificate walk that
turns one PEM block into the key bytes a pin slot takes. It follows the RFC text and
never the C, because a differential oracle only works when a shared
misreading cannot make both sides agree.

`make diff` builds the spec, runs its selftests, then drives about
7,400 random-input comparisons between the C and the spec over a pipe,
from a fixed seed. Some rows are signatures the spec mints and the C
must accept: the spec holds the private keys and signs, and the C, which
can only verify, must accept every genuine signature and reject every
mutated one. About 730 rows feed the certificate parser generated DER —
uniform bytes, edits at random TLV sites, and leaves the spec re-signs.
Nobody knows those answers in advance, so the C answers first and the
spec must reproduce it. The provisioning rows work the same way, on
certificates the spec mints and the driver armours at every line width
the decoder admits.

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
one, or the seeded generator in `drbg.[ch]` if it does not. The
reference target has no random-number peripheral, and mips32r2 has no
randomness instruction, so it uses the seeded one. That generator
refuses to run unseeded; [`docs/entropy.md`](docs/entropy.md) covers
seed provisioning.

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
  list ever changes. The list is per build on two axes: `RAND=drbg`
  packages the reference generator and exports `ch_drbg_seed`, and
  `TRUST=ca` exports `ch_pubkey_from_pem` for provisioning, so a
  `TRUST=ca RAND=drbg` object exports six. `RAND` is the one build
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
