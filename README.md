# chapulin

[![coverage](https://raw.githubusercontent.com/c4milo/chapulin/badges/.github/badges/coverage.svg)](https://github.com/c4milo/chapulin/actions/workflows/check.yml?query=branch%3Amain)

A TLS 1.3 client for devices with a few kilobytes of RAM. Named after
El Chapulín Colorado: small, unassuming, and it protects you from the
bad guys.

chapulin speaks one profile and negotiates nothing:
`TLS_CHACHA20_POLY1305_SHA256` with x25519 key exchange, or the
X25519MLKEM768 hybrid ([RFC 10024](https://www.rfc-editor.org/rfc/rfc10024))
instead when you build `make KEX=pq`. A device build offers one group,
never both in one ClientHello, and the server takes it or the handshake
fails. The host-side `TRUST=webpki` mode offers both in every build, with
a key share for each, so a server picks either in one round trip
([`docs/decisions.md`](docs/decisions.md) entries 39 and 51), and under
`SUITE=aesgcm` it also offers `TLS_AES_128_GCM_SHA256` on a host whose AES
instructions the build vouches for (entry 45). There is no 0-RTT.

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

**Pinned CA** (`make TRUST=ca-rsa`). The pin holds the key of a CA you run.
The server sends its certificate, or that plus one intermediate, and
the client checks the chain up to the pin with a small profiled parser.
The check covers signatures and certificate shape only. There is still
no clock and no expiry: freshness comes from reissuing short-lived
certificates on a schedule, so server keys rotate without touching a
device. See [`docs/ca.md`](docs/ca.md).

A third mode, `TRUST=webpki`, verifies a public chain against trust
anchors the caller supplies, with hostnames and validity dates. It is
host-side, not device-side: it needs a clock, a hostname and a receive
buffer measured in kilobytes. [`docs/webpki.md`](docs/webpki.md) states
its profile, its bounds, and what it does not check. The walk consults
the anchors before it reads each next entry, so it stops at the first
anchor that both names the issuer and verifies the signature and leaves
the rest of the flight unread. The object carries every verifier a
public chain needs at once — RSA-PSS, RSA PKCS#1 v1.5, P-256 and
P-384 — so `PIN` selects nothing in it. It resumes only a ticket bound
to the configuration of the session that received it, and refuses any
other PSK (docs/webpki.md, "Resumption"). Its resuming hello offers the
certificate path beside the ticket, so a server that declines the ticket
authenticates with its chain in the same connection, and
`ch_tls.psk_selected` says which one happened. It also takes SPKI pins, and
with them RFC 7250 raw public keys, for a DNS-over-TLS caller: pins alone
reach a server that has no public certificate, and pins beside anchors
make a chain pass both checks (docs/webpki.md, "Raw public keys and SPKI
pins").

One signature algorithm per build. The default verifies RSA-PSS and
pins the raw modulus, 256 to 384 bytes, covering RSA-2048 through
RSA-3072. `make TRUST=raw-ecdsa` verifies P-256 and pins 64 bytes instead.
[RFC 9846](https://www.rfc-editor.org/rfc/rfc9846) requires both algorithms, so between them a chapulin build
can pin any compliant server. Neither build carries the other's
verifier.

All modes accept session tickets, so reconnects resume over PSK. In
pinned mode the client verifies a signature once per ticket lifetime,
not once per connection.

**Revoking without a clock.** The ca modes offer an opt-in counter. The
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
a 32-bit device needs 72 bytes less than the host figure in either device
build. `TRUST=webpki` adds pointer-sized fields to `ch_cfg`, pointers
and `size_t` lengths,
so that build needs 104 bytes less than the host figure on rv32.
The stack peaks are arm64 only: `bench/stack.py` reads arm64 relocations,
so an rv32 peak needs tooling that does not exist yet.

| what | arm64 | rv32 |
|---|---|---|
| `ch_tls` session struct (includes 622 B TX staging) | 1144 | 1072 |
| receive buffer you provide (2048 shown; floor `CH_MIN_RXBUF`) | 2048 | 2048 |
| **total static working set** | **3192** | **3120** |
| `ch_tls` under `KEX=pq` (includes 1806 B TX staging) | 2328 | 2256 |
| **total static working set, `KEX=pq`** (2048 buffer) | **4376** | **4304** |
| `ch_tls` under `TRUST=webpki` (includes 2399 B TX staging) | 3040 | 2936 |
| **total static working set, `TRUST=webpki`** (12338 buffer, its floor) | **15378** | **15274** |
| peak stack, `ch_connect` (RSA-3072 verify) | 4992 |
| peak stack, `ch_connect` (`TRUST=raw-ecdsa`) | 3824 |
| peak stack, `ch_connect` (PSK) | 2768 |
| peak stack, `ch_connect` (`TRUST=ca-rsa` / `TRUST=ca-ecdsa`) | 5472 / 3984 |
| peak stack, `ch_connect` (`TRUST=webpki`) | 16416 |
| peak stack, `ch_read` (worst case: KeyUpdate rekey) | 1696 |
| peak stack, `ch_connect` (`KEX=pq`) | 15872 |
| peak stack, `ch_write` / `ch_close` | 912 / 864 |
| `ch_tls` under `ROLE=server` (includes 1221 B TX staging) | 1968 | 1816 |
| **total static working set, `ROLE=server`** (2048 buffer) | **4016** | **3864** |
| peak stack, `ch_srv_accept` (`ROLE=server`) | 10304 |

The hybrid build costs more of both. The session struct grows because
the ClientHello carries a 1,216-byte key share and is built whole into
one staging array, and the stack grows because ML-KEM's K-PKE encrypt
holds three polynomial vectors and two polynomials: 5,744 bytes in that
one frame, against a 2,560-byte budget for every other build (INV-19
carries the per-build numbers). The whole chain peaks at 15,872 bytes,
through `mlkem_decaps` into K-PKE encrypt and Keccak, so the hybrid
build needs about three times the stack of the classic one rather than
the single frame's 5,744. A device that cannot spare it builds the
classic key exchange. A `TRUST=webpki` build carries the hybrid in every
build, so it pays both costs too.

A `ROLE=server` build pays them as well, because every server holds the
hybrid ([`docs/decisions.md`](docs/decisions.md) 54). Its ServerHello is
built in the clear in the same staging array, and the hybrid one carries a
1,120-byte share, so the array holds 1,216 bytes of message behind the
record header. `ch_srv_accept` peaks at 10,304 bytes, through the
encapsulation to the client's key into K-PKE encrypt and Keccak, above
the 5,280 its RSA-PSS signer reaches with the encapsulation pruned from
the call graph (`STACK_PRUNE=srv_kex_share`).

You size the receive buffer, and the client advertises that size as its
`record_size_limit` ([RFC 8449](https://www.rfc-editor.org/rfc/rfc8449)), so a peer can never send a record the
buffer cannot hold. One extra rule in pinned mode: the server's
Certificate message must also fit. A self-signed P-256 certificate
needs about 600 bytes and an RSA-3072 one about 1.2 kB, so the 2 kB
buffer above covers both. A ca-mode build knows its own worst case
and derives the floor for you: `CH_MIN_RXBUF` becomes 3,112 bytes
(RSA) or 1,576 (ECDSA), the largest Certificate message plus the record
that completes it, so a buffer too small for the largest chain fails at
setup rather than mid-handshake. A `TRUST=webpki` build derives 12,338
bytes the same way, four certificates at its 3,072-byte cap, and its
session struct carries a larger TX staging array for the `server_name`
and ALPN extensions and for both key shares, the 1,216-byte hybrid one
and a 32-byte x25519 one ([`docs/decisions.md`](docs/decisions.md) 51).
Its `ch_connect` peaks at 16,416 bytes, through ML-KEM's decapsulation,
above the 7,152 its chain walk into an RSA-4096 verify reaches, the
widest modulus a public root carries.

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
ships. Each script also builds the same driver with
`-DCH_NATIVE_WIDEMUL` and records that count beside the shipped one,
as the CSV's `native_insns` column; the sentence under the table is
rendered from the two, and `make lint-bench-numbers` fails when the
prose and the CSVs disagree, as it does for every cell of the table.

| work | mips32r2 insns | ms (500 MHz, 1 IPC) | Cortex-M3 insns | rv32imac insns |
|---|---|---|---|---|
| AEAD seal, per 1 KB record | 82 k | 0.16 | 68 k | 107 k |
| SHA-256, per 1 KB | 68 k | 0.14 | 57 k | 90 k |
| x25519 scalar multiply | 38.9 M | 78 | 27.4 M | 51.4 M |
| RSA-3072 PSS verify (default) | 11.6 M | 23 | 8.4 M | 13.2 M |
| P-256 verify (`TRUST=raw-ecdsa`) | 46.0 M | 92 | 26.7 M | 42.6 M |
| full pinned handshake crypto (default) | 90.2 M | 180 | 63.8 M | 117.0 M |
| ML-KEM-768 keygen (`KEX=pq`) | 3.2 M | 6 | 2.7 M | 3.6 M |
| ML-KEM-768 decapsulate (`KEX=pq`) | 3.6 M | 7 | 3.0 M | 4.1 M |
| full hybrid handshake crypto (`KEX=pq`) | 100.4 M | 201 | 72.2 M | 128.3 M |

The multiply decomposition that keeps secrets off a variable-time
`umull` sets the first and third rows in every instruction column.
Measured against the same benchmark with the native multiply instead:
on mips32r2, AEAD seal costs 73% more, x25519 36% more, and the
pinned handshake 29% more, or 41 ms at 500 MHz; on the Cortex-M3, AEAD
seal costs 93% more, x25519 129% more, and the pinned handshake 94%
more; on rv32imac, AEAD seal costs 66% more, x25519 137% more, and the
pinned handshake 104% more. SHA-256 and both signature verifies are
unchanged, because SHA-256 does not multiply and the verifies read only
public bytes.

Flash is 28.0 kB for the default build (`.text` + `.rodata`, `-Os`),
of which the multiply decomposition is 2.3 kB, nearly all of it
poly1305's unrolled block: the `total (CH_NATIVE_WIDEMUL)` row of
[`bench/results-device.csv`](bench/results-device.csv) sizes the same
modules over the native multiply. The `TRUST=raw-ecdsa` build trades 2.2 kB
of RSA for 5.8 kB of P-256 and totals 31.5 kB.

The hybrid key exchange costs less than its wire size suggests. `KEX=pq`
adds two ML-KEM key expansions and one decapsulation — the key pair lives
as a 64-byte seed and is re-expanded rather than stored, which
[`docs/decisions.md`](docs/decisions.md) 24 explains — for 10.2 M
instructions, 11% over the classic handshake. One ML-KEM-768 keygen is
an order of magnitude cheaper than one x25519 on this core, because
chapulin keeps the 16-bit-limb ladder for its machine-checked overflow
proof.

Public-key work dominates. Every handshake runs two x25519 for forward
secrecy, whichever mode it is in, so about 156 ms is the recurring
floor and 86% of the pinned handshake's crypto. The signature verify is
paid only on the first pinned connection; resumptions skip it. Record
crypto is about 0.15 ms per kilobyte, which is negligible beside the
handshake. Because a device typically opens one long-lived connection,
chapulin keeps the 16-bit-limb x25519 as the default and the device
path, for its machine-checked overflow proof and because a 32-bit core
has no wider multiply to run a faster field on. A 64-bit host that
opens many short connections can build `X25519=wide` instead (decision
52): five 51-bit limbs whose products run on the 64x64->128 multiply.
On an Apple M1 Pro a scalar multiplication takes 34 µs there against
953 µs in the default build, and the client side of a pinned RSA-3072
handshake falls from 2.57 ms to 0.77 ms
([`bench/notes-primitives.md`](bench/notes-primitives.md)).

## Verification

Four layers cover four different failure classes.

**Proofs cover memory safety.** Seventy-four of the eighty-eight C sources in
the tree root are compiled into a [CBMC](https://www.cprover.org/cbmc/) harness that a launch line runs,
which proves them free of out-of-bounds access, invalid pointers, bad
shifts, and division by zero, for every input within the harness's
bound. Signed overflow is checked too, except in the three x25519 mul
harnesses that turn it off (see the x25519 row). The `X25519=wide`
field's harnesses also check unsigned wrap, which C defines and the
other checks never see, because that field's bounds are all on
unsigned values (see the x25519_wide row). Fourteen sources are in
no such harness. `tls.c` has none at all: the post-handshake parser
moved to its own file and took the harness with it, leaving the four
public calls unproven.
`srv_parser.c`, `srv_flight.c` and `srv_rec.c` each have one whose
formula returns no verdict, which the `srv_parser (the walk)`,
`srv_flight` and `srv_rec` rows below state. `srv_out.c`, `srv_quic.c`,
`rec.c`, `rec_frame.c` and `rec_step.c` have none; `bin/srv_flight_test`,
`bin/srv_quic_test`, `bin/srv_rec_test` and `bin/rec_loop_test` test
them instead. `quic_aes_hw.c` calls the
compiler's AES intrinsics, which CBMC cannot unwind, and
`bin/aes_equiv_test` holds it to `quic_aes_soft.c` instead;
`quic_ghash_hw.c` runs GHASH on the carry-less multiply intrinsics, and
`bin/ghash_equiv_test` holds it to `quic_gcm.c`'s proven portable
multiply; `quic_aes_extern.c` forwards to a `ch_aes_block` the caller
writes, so there is no body here to prove. `webpki_cfg.c` has no harness
either. `build.c` holds one const record and no function, so there is
no path for a harness to drive; `lib-check` reads every field back.
`make check` counts all fourteen and regenerates the source-by-source
table in `bin/proof-coverage.md`. Where a bound equals the module's real
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
| sha256 | safe for any two-chunk split | messages ≤ 96 B — every fill state the padding path can see, since fill is the length mod 64 and 0..96 covers all 64 residues, slow tier |
| sha512 (two harnesses) | the framing — block assembly across a two-chunk split, the padding and the 128-bit length — is safe for both SHA-512 and SHA-384 with the compression function stubbed to its contract; the compression function is safe over any state and any block, which discharges that stub | framing: messages ≤ 192 B — every fill state the padding path can see, since fill is the length mod 128 and 0..192 covers all 128 residues, slow tier; compression: the full domain, fast tier |
| p384 (two harnesses) | what p256's two prove, at twelve limbs: every piece of `p384_ecdsa_verify` that attacker bytes reach — the strict-DER parser, the marshalling, the field and group arithmetic in every aliasing shape the code uses, the on-curve check — over fully nondet limbs and points, and the bit-walk index for every scalar bit; the CIOS carry lemma behind `p384_mont_mul` for any uint32 operands. The two 384-iteration loop drivers, `point_mul` and `p384_mod_inverse`, are not unrolled; their bodies are the proven pieces | signatures ≤ 112 B (a valid one is ≤ 104), full-range limbs and points, scalar bits 0..383 |
| p256_ecdh | the three public entries over the scalar and point layers stubbed to their contracts (`p256_scalar_stubs.h`, `p256_point_stubs.h`): memory safety over any 65 peer bytes and any 32 scalar bytes, that each entry answers 0 or 1, and that a refusal leaves no private key, no public key and no shared secret behind, for every verdict the stubbed arithmetic can give. The ladder and the point decode are `p256_point`'s | any 65-byte point, any 32-byte scalar, full-range points, scalar bits 0..255 |
| rsa_pkcs1 (two harnesses) | the shipped `rsa_pkcs1_verify` end to end — the size gate, the odd-modulus check, the DigestInfo choice, the range check, the encode-and-compare — over any modulus, digest, signature and claimed lengths, with RSAVP1 stubbed to the contract `rsa_mul` proves, and the encoder at the shortest admitted modulus; `rsa_pkcs1_webpki` is the same harness at the `CH_TRUST_WEBPKI` bound | n_len at the 384-byte limit and at the 512-byte limit of a `CH_TRUST_WEBPKI` build, each the binding case for its bound as for `rsa`; both admitted digest lengths |
| webpki_spki | `webpki_read_spki` over any bytes, with the real DER primitives. A success leaves the reader's error clear and consumes exactly the length of the returned key's canonical encoding, at most 550 bytes (the largest SubjectPublicKeyInfo the modulus gate admits). Every part of that encoding has a minimum size, so the equality leaves no container room for a byte after its last field. The key lies inside the consumed bytes and has its algorithm's shape: an RSA modulus of 256 to `CH_RSA_MODULUS_MAX` bytes in steps of 8 with its top and low bits set, a 64-byte P-256 point or a 96-byte P-384 point. Whether the point is on the curve is tested, not proved. `p256_ecdsa_verify` and `p384_ecdsa_verify` check it, and the `p256` and `p384` harnesses call that check for memory safety with no assertion on its result. `test/webpki_sigalg_test.c` gives `webpki_verify` signatures forged for the point (1, 0), which only the curve check refuses | inputs ≤ `CH_WEBPKI_CERT_MAX` (3,072 B), `CH_RSA_MODULUS_MAX` 512 |
| webpki_sigalg | `webpki_read_sigalg` over any bytes: a success yields one of the four algorithms and consumes exactly its encoding. `webpki_verify` over any certificate and signer, the key in an anchor buffer or in the certificate buffer, with both hashes and the three verifiers stubbed to their contracts: a TBS over the cap, an unknown algorithm or a key of the other family reaches no hash and no verifier; the hash is the one the algorithm names, over the DER SEQUENCE header for the TBS length, checked against bytes the harness writes itself, and then exactly the TBS; the verifier is the one the key's algorithm names, and it gets the signer's key and the certificate's signature at their own lengths; `p256_ecdsa_verify` gets the digest's first 32 bytes and `p384_ecdsa_verify` the SHA-384 digest or 16 zero bytes then the SHA-256 digest (FIPS 186-4 §6.4); the verdict is the verifier's | inputs ≤ `CH_WEBPKI_CERT_MAX`, TBS lengths to one byte past it |
| sha3 (two harnesses) | every mode is safe for a one-call message and XOF output from a fresh context; the SHAKE streaming calls are safe from any context state — arbitrary lanes, either rate, every position — for split absorbs and squeezes | one-call: messages ≤ 200 B, output ≤ 400 B; streaming: chunks ≤ 32 B |
| mlkem (six harnesses) | keygen, encaps, and decaps are safe for every seed, message, and hostile key or ciphertext, with the polynomial layer stubbed to its contracts; the polynomial layer is safe over full-range int16 coefficients — a superset of anything the KEM layer passes it, so no coefficient value can overflow the reduction arithmetic. Sampling, reductions, and coding prove in the fast tier; the NTT, the two halves of its inverse, and the base multiplication, whose chained-product overflow proofs are the SAT-hard part, each prove in their own slow-tier formula | the full domain: every input is a fixed-size array, and the sampling read stops at its 1536-byte cap |
| hkdf (two harnesses) | hmac/extract and expand/expand-label safe over the proven sha256 contract | keys ≤ 96 B, hmac/extract messages ≤ 48 B; expand/expand-label output ≤ 96 B and info ≤ `HKDF_INFO_MAX`, which is 54 at the default label cap of 12 — the cap this leg is proved at; `EXPORTER=on` raises the cap to 32 and the bound to 74, and no launched leg proves that domain (see `keysched_exporter`), expand: slow tier |
| keysched | every `ks_*` entry point is memory-safe and UB-free over unconstrained secrets and lengths, with hkdf real and sha256 stubbed to its contract; at the default label cap of 12. Nothing here asserts what the outputs hold | secrets 32 B |
| keysched_exporter | **not proved.** `proof/keysched_exporter_harness.c` runs the leg above under `EXPORTER=on`, which adds `ks_exp_master` and `ks_exporter` and widens hkdf's label cap to 32, and its formula returns no verdict: none in 10 minutes with the label length free, none in 7 min 50 s with it fixed at 13 and 32. `proof/run.sh` records both. The two calls are covered by `bin/exporter_test` instead, whose four vectors are cross-checked against an independent from-spec implementation rather than published, since RFC 9846 prints none | — |
| handshake | the driver stays safe on any record stream: HRR restart, the state machine, and the flight's own arithmetic, in PSK and pinned-key mode. Record reading and message reassembly are stubbed here to the contract the `handshake_record` leg proves — compiling them multiplies this formula by the product of their loop bounds, past any runner. The ca-mode driver has a harness but no launch line, so it is unproven | 96 B receive buffer, slow tier |
| hybrid_secret | the `KEX=pq` shared-secret derivation is safe for any stored seed, any server ciphertext and any server share, a refused key exchange wipes all 64 bytes rather than leaving half a secret on the stack (INV-3), and both exits leave the 64-byte ML-KEM seed zero. ML-KEM and x25519 are stubbed to their contracts, which their own harnesses prove. This is the only leg that builds `-DCH_KEX_PQ`: the rest of the hybrid driver carries the differential, the sequence enumeration and the e2e legs, not a proof | the full domain, fast tier |
| key_share (two launch lines) | the `KEX=pq` arm of the ServerHello key_share parser is safe on any extension bytes, and on acceptance it records the hybrid group (`info.group == CH_GROUP_X25519MLKEM768`, the value `ch_tls.group` reports and `ch_cfg.require_pq` compares) and returns a whole readable ML-KEM ciphertext inside the bytes it consumed — the contract `hybrid_secret` assumes, so this proof discharges that assumption. `key_share_webpki` builds the same harness under `-DCH_TRUST_WEBPKI`, where the arm also accepts a ServerHello selecting x25519, whose share that build's hello carries beside the hybrid one: an x25519 share is exactly the group, the length and 32 bytes, with no ciphertext pointer. In both builds a HelloRetryRequest key_share is refused. That `ch_cfg.require_pq` refuses an x25519 selection is `hsf_accept_server_hello`'s check, which `bin/webpki_session_test` tests and no proof covers | extension ≤ 1,132 B, the full hybrid share, fast tier |
| hello_build (two harnesses) | the ClientHello builder writes nothing outside the caller's buffer at any capacity, for every cookie and PSK identity a caller may pass, and returns either zero or a length that fits. It also checks the bound itself: at `CH_HELLO_MAX` the build always succeeds, so the constant `handshake.c` asserts `CH_TX_STAGE` against is sufficient, not merely plausible. `hello_build_webpki` is the same harness under `-DCH_TRUST_WEBPKI`, with the server_name extension over any hostname, the ALPN extension over any offer, the five signature schemes, which a resuming hello carries beside the ticket too, and both key shares or, under `require_pq`, the hybrid one alone, against that build's `CH_HELLO_MAX` of 2,394; there the bound is tight, because the assertion moved to `CH_HELLO_MAX - 1` fails. That `pre_shared_key` is the last extension is tested, in `test/session_cfg_tests.h` and `test/webpki_session_cases.h`, and **not proved**: the assertion over the hello's last bytes gave kissat a formula that returned no verdict in nine minutes at 5.7 GB | capacity ≤ `CH_HELLO_MAX`, identity ≤ 320 B, cookie ≤ 128 B, hostname ≤ 253 B, 8 ALPN names ≤ 32 B each |
| chacha20 | safe at any counter, in place and into a distinct buffer | ≤ 160 B — three blocks, full, full, partial |
| poly1305 | safe for any three-chunk split; 64-bit products stay in range | messages ≤ 80 B — five blocks, crossing the buffered-block path in every alignment. The five-call shape `aead.c` uses is no longer exercised by a proof: the aead harnesses stub Poly1305, so that shape rests on the unit vectors, Wycheproof and the differential |
| aead (three harnesses) | seal/open round-trips; a forged tag writes zero bytes; backward-overlap decrypt works. ChaCha20 and Poly1305 are stubbed to their contracts — a keystream that is the same for the same key, nonce and counter, and a tag that is a function of the bytes absorbed — which their own harnesses prove. Compiling them in returned no verdict in five hours; the stubbed formulas take about three seconds. What the stubs give up, and why the composition is an argument rather than a machine-checked step, is stated at the top of `proof/aead_stubs.h`. Sealing fully in place (`pt == ct`, the shape every outgoing record uses) is **not proven**: `proof/aead_inplace_harness.c` states it, but the formula has returned no verdict, so it carries no launch line | plaintext ≤ 16 B, aad ≤ 16 B, fast tier |
| quic_aes | the AES-128 key schedule and forward cipher and both `aes_public_key` constructors are safe over unconstrained inputs, in the aliasing shape the callers use (`in == out`) and at every Destination Connection ID length RFC 9000 §17.2 admits, plus the first length past the cap, where the call refuses without reading the pointer. HKDF is stubbed to its contract (`proof/quic_aes_stubs.h`), which the three `hkdf` harnesses prove; `TRANSPORT=quic` only | connection IDs ≤ `CH_QUIC_DCID_MAX` (20 B), the rest of the domain fixed-size, fast tier |
| quic_retry | `quic_retry_ok` reads only inside the pseudo-packet and the tag it is handed and commits no undefined behavior; it answers 1 for the tag `gcm_seal` computed over that pseudo-packet, and 0 for a tag that differs in one byte, at any position and by any nonzero amount. `gcm_seal` and `aes_public_key_retry` are contract stubs the harness defines, and the `gcm_seal` stub asserts what RFC 9001 §5.8 fixes at this one call site: the key `aes_public_key_retry` wrote, the nonce §5.8 prints, the caller's whole pseudo-packet as associated data, and an empty plaintext. That the AEAD meets that contract is what the `quic_gcm` harnesses and RFC 9001 Appendix A.4 carry, not this one; `TRANSPORT=quic` only | pseudo-packets ≤ 64 B, fast tier |
| quic_token | `ch_srv_quic_token_mint` writes only inside the caller's buffer, writes the type byte, the issue instant, both lengths and both connection IDs where `quic_token.h`'s layout puts them, writes nothing on a refusal, and never refuses a capacity of `CH_QUIC_TOKEN_MAX`. `ch_srv_quic_token_check` reads only inside the token and the address, answers `CH_EINVAL` for exactly the address lengths outside 1 to `CH_QUIC_TOKEN_ADDRESS_MAX`, `CH_EPROTO` only for a token that is not a Retry token and `CH_EAUTH` only for one that is, writes nothing on any refusal, and answers `CH_OK` only for a token whose length its two length bytes fix, whose connection IDs fit their arrays, and whose issue instant is at most the lifetime before now and not after it. SHA-256 is the contract stub, so the tag is unconstrained: that a minted token checks, and that another address or key does not, are tested in `test/quic_token_tests.h` and **not proved**; `ROLE=server` or `ROLE=both` with `TRANSPORT=quic` only | any address length, any connection ID length a byte holds, any instant and lifetime; tokens ≤ 84 B, one past `CH_QUIC_TOKEN_MAX`; fast tier |
| quic_initial | `quic_initial_seal` and `quic_initial_open` read and write only inside their buffers, commit no undefined behavior, and answer one of the codes their header documents, over unconstrained connection-ID, packet-number, header, payload, capacity and packet lengths. Two properties beside safety: a refusal writes neither output, and a successful open reports a plaintext length inside the packet it was handed. The eight calls the two entries make are stubbed to their contracts (`proof/quic_initial_stubs.h`) — `quic_aes` and the three `quic_gcm` harnesses prove four of them, and `quic_packet.c`'s own harness proves the header protection pair and the packet number pair. What the derivation, the seal and the mask compute is checked against RFC 9001 Appendix A.2's client Initial packet in `test/quic_vectors.c` instead; `TRANSPORT=quic` only | headers ≤ 6 B, payloads ≤ 6 B, packets ≤ 28 B — two bytes either side of §5.4.2's sample bound — connection IDs ≤ `CH_QUIC_DCID_MAX` (20 B), fast tier |
| quic_driver | `quic.c`'s fifteen public entries and its input loop are safe and free of undefined behavior over any saved state and any caller argument: the unread window stays inside `cfg.buf`, `CH_EINVAL` changes nothing and names one of the three refusals `quic.h` lists, every other error leaves the session dead with no secret, nothing staged and nothing unread, and a level delivered out of order reports RFC 9001 §4.1.3's PROTOCOL_VIOLATION. The QUIC arm of `handshake_record.c` and all of `quic_config.c` are compiled in; `hsq_advance`, the two flight handlers `ch_quic_init` calls and the packet calls are contract stubs (`proof/quic_driver_stubs.h`), and `quic_step` proves the table against the same `hsq_advance` contract, so the two read as a pair; `TRANSPORT=quic` only | 12 B receive buffer, 32 B staged message, fast tier |
| quic_step (two harnesses) | `hsq_advance` is safe over any saved state, a step number no step wrote included: it consumes its message, raises the step or waits for the retry hello, never raises `t.state`, touches no packet counter, stages nothing on an error, and at the Finished step stages the client Finished at the Handshake level, moves to 1-RTT, reports that level in both directions and writes the back pointer again after the wipe. Every flight handler and the three `quic_keys.c` derivations are contract stubs; `quic_step_ca` is the same harness under a ca mode, where `hsa_epoch_commit` runs and the wipe bound is that build's larger `handshake_state`; `TRANSPORT=quic` only | 12 B receive buffer, fast tier |
| quic_gcm (five harnesses) | Three carry a launch line and two do not. `quic_gcm_safety` proves that `gcm_seal`, `gcm_open` and `gcm_ghash` read and write only inside their buffers and commit no undefined behavior, for any key schedule, any nonce, and both aliasing shapes the header admits: separate buffers, and `pt == ct`, which is how `quic_initial.c` decrypts a payload in place. `quic_gcm_refusal` proves that `gcm_open` is all-or-nothing: for any tag at all, a call that returns 0 writes no plaintext byte. The same harness runs twice more, once per arm, with a define that asserts that arm is unreachable; both runs must fail. `quic_ghash` proves the same safety for GHASH alone, at sixteen blocks per argument, where the whole-module formula gets two. Two properties are not proved: that a genuine seal opens back to the plaintext it sealed, and that a forged tag is refused. `proof/quic_gcm_harness.c` and `proof/quic_gcm_forge_harness.c` state them, but neither formula returns a verdict, so neither carries a launch line, and `proof/run.sh` records both measurements. Those two rest on tests instead: SP 800-38D's four AES-128 cases, RFC 9001 Appendix A.2's client Initial packet and A.4's Retry tag, 67 Wycheproof cases on all four build legs, and the Lean differential. Every harness compiles the portable GHASH. An `AES=hw` build runs `quic_ghash_hw.c`'s GHASH on the carry-less multiply instead, which no harness reads; `bin/ghash_equiv_test` holds it to the portable one byte for byte, and the vectors, the Wycheproof `AES=hw` leg and `bin/diff_quic_hw` run over it | plaintext and associated data ≤ 32 B each for safety and refusal — two blocks, every length either side of the block boundary, on both arguments; ≤ 256 B each for `quic_ghash` |
| x25519 (ten harnesses) | carry, add, sub, pack, cswap, and unpack are safe with every check on, add and sub in the ladder's aliased shape too, and the ladder's scalar bit index stays in bounds (fast tier); mul's index walk is safe in every caller aliasing shape — distinct, output aliasing either input, and sqr's all-one-object — with the signed-overflow class off (slow tier, one shape set per formula), and a separate lemma proves mul's int64 accumulation and fold cannot overflow (fast tier). Every one of these holds only inside the limb range in the next column, and `x25519_step` and `x25519_tail` prove the ladder keeps its limbs there: one loop step, on the shipped `step()`, takes any state with every limb in (-2^17, 2^17) back into that bound and hands mul only operands under 2^18; mul's output, one `invert` round, and the final multiply and pack do the same. The 255 steps and 254 rounds follow by induction from a base case read off `ladder()`'s prologue; `x25519_step` is a slow-tier leg and `x25519_tail` a fast one. Both harnesses replace mul's multiply with a magnitude contract (`proof/x25519_stubs.h`) that `x25519_mul` discharges on the native multiply and `x25519_mul_ct` on the shipped decomposition — see the note below | limbs ≤ 2^24; into carry, ≤ 2^58; between the ladder's operations, < 2^17 |
| x25519_wide (seven harnesses) | the `X25519=wide` field (`x25519_wide.c`, INV-34), with `--unsigned-overflow-check` on every line. On the real 64x64->128 multiply, `mul` and `sqr` over any operands whose limbs are under 2^54 wrap nothing — every column sum stays under 2^115 and every carry under 2^64 — and leave limbs 0, 2, 3 and 4 under 2^51 and limb 1 under 2^51 + 2^13; add, sub, `mul_a24`, cswap, unpack and pack are safe at the same bounds, cswap swaps exactly when its bit is 1, and pack writes a value below p. `x25519_wide_step` proves one loop step, on the shipped `step()`, from any state inside INV-34's bounds back into them, `x25519_wide_invert` the whole inversion chain, and `x25519_wide_tail` the output form of every product and the final multiply and pack; those three replace the multiply with a contract, operands under 2^55 and 2^60 to a product under 2^115, which `x25519_wide_mul128` proves on the real multiply. The 255 steps follow by induction from a base case read off `x25519_wide_ladder()`'s prologue. One step over the real products also converged, in 64 s at 4.5 GB, and has no launch line | operand limbs < 2^54; between the ladder's operations, limb 1 < 2^51 + 2^20 and every other limb < 2^51; fast tier |
| p256 | the DER parser and limb marshalling stay safe on hostile signatures; a carry lemma covers the Montgomery multiply | signatures ≤ 80 B |
| p256_field | the constant-time field arithmetic, which is written as masks and is proved as masks: the limb add and subtract, the conditional subtraction of p, the select, `p256_fe_cmov`, `p256_fe_cswap` and the three predicates each match a reference that writes the same choice as a branch, so an inverted mask fails here; `p256_fe_add`, `p256_fe_sub` and `p256_fe_neg` take elements below p to an element below p; the byte marshalling round trips; and every routine is memory-safe and UB-free over full-range limbs in each aliasing shape a point routine uses. The Montgomery product's value is **not proved** — equality of two multipliers is the SAT instance that does not converge (`docs/proofs.md`) — so it rests on `test/p256_field_test.c`'s vectors, which run over both forms of `ct_widemul`, and its carry chain on the `p256_mul` lemma. `p256_fe_inv`'s 256 rounds are not unrolled; each round body is that multiply, and the exponent bit index is proved in bounds for every round | full-range limbs, any 32 bytes, exponent bits 0..255 |
| p256_scalar | the signer's arithmetic mod the group order, concrete: every masked choice equals a reference that writes the same choice as a branch, both predicates equal `==`, the byte round trip, and the two contracts `p256_sign.c` rests on — that `p256_scalar_reduce` lands any 256-bit value below n, and that `p256_scalar_add` leaves a scalar. The Montgomery product is memory-safe with **no assertion on its value**: equality of two multipliers is the hard SAT instance, so its value rests on `test/p256_sign_test.c`'s vectors against Python's integers. `p256_scalar_inverse`'s 256 rounds are not unrolled; only its exponent index expressions are proven in bounds | full-range limbs, every aliasing shape `p256_sign.c` uses, exponent bits 0..255 |
| p256_point (two harnesses) | `p256_point_add` and `p256_point_affine` over the field stubbed to its contract, in all four aliasing shapes including both inputs the same object, which is the doubling the ladder performs; and `p256_point_ladder`, one round of `p256_point_mul` on the shipped `ladder_round` for any scalar, any three points and any bit index in [0, 255], so the index and the shift are proven in bounds and every mask the round builds is 0 or all ones at every `p256_fe_cswap`. The 256-round loop calls nothing but that round; unrolled whole it returned no verdict in 42 minutes | full-range coordinates |
| p256_sign | the RFC 6979 generator and the DER writer with the arithmetic stubbed: the generator spends the same number of HMAC calls whatever the candidate nonces were, which is the constant-time claim about the retry; the DER writer stays inside `P256_SIG_MAX`, writes a minimal INTEGER, and refuses a short capacity rather than truncating, with no byte written past it. Whether a signature is genuine is **not proved** here; `test/p256_sign_test.c` checks that against RFC 6979 A.2.5 and Python, and the Wycheproof lane hands every signature to the independent verifier in `p256.c` | any key, any message hash, any capacity ≤ `P256_SIG_MAX` |
| rsa (four harnesses) | the PSS decode and limb marshalling stay safe with the RSAVP1 result replaced by arbitrary bytes; `rsa_webpki` and `rsa_mul_webpki` are the same two harnesses at the `CH_TRUST_WEBPKI` bound, `CH_RSA_MODULUS_MAX` of 512 | 384 B modulus, and 512 B under `CH_TRUST_WEBPKI`, every byte hostile except the top one, which each call pins to one of the three alignment shapes the decode takes — a symbolic top bit was measured at 7 GB of CNF |
| rsa_sign | the signer's limb marshalling and every limb helper — the borrow, the masked subtract, the comparison and the conditional swap — stay safe over fully nondet limbs at 96 limbs; `mask_of_bit` returns all ones or all zeros and nothing else, and `below` answers the one bit that mask admits; the ladder's exponent byte index stays inside `d` for every bit position the loop reads; the PSS encoder writes inside the encoded message at the largest one it builds, with SHA-256 stubbed to its contract; and a carry lemma covers the CIOS accumulation for any uint32 operands. `mont_mul` whole, `mont_r2` and `rsa_sp1` above them are **not driven**: a symbolic modexp does not leave symbolic execution and `mont_r2`'s shift loop runs 6,144 times, so their arithmetic rests on that lemma, on the Wycheproof signing vectors and on `test/rsa_sign_test.c`. Nothing here proves the timing claim `rsa_sign.h` makes; `make lint-wide-multiply` holds that, by counting the wide multiplies and the conditional branches the file compiles to | 384 B modulus (96 limbs), full-range limbs, exponent bit positions 0..8*n_len-1, encoded message at `CH_RSA_MODULUS_MAX` |
| record | seal works across its contract and returns, not traps, over the whole direction state — any key, IV, and sequence number, the saturation refusal included — and any claimed buffer size; rec_open stays safe on fully hostile bytes, into a separate buffer and in place, the shape both shipped callers use | records ≤ 160 B, slow tier |
| handshake_record | the record reader stays safe on any stream a peer can send — compaction, CCS tolerance, the quiet cap, in-place decryption, and reassembly across records — and a message it yields lies wholly inside `cfg.buf` with a length that agrees with its own 3-byte header. `hsr_transcript_hash` leaves the running transcript byte for byte as it found it. io_read_record and rec_open are stubbed to the contracts the `io` and `record` legs prove | 12 B receive buffer, `CH_QUIET_CAP` 1, slow tier |
| handshake_parser, handshake_parser_suite, eeparse, certparse, eeparse_webpki, eeparse_alpn, certparse_webpki | the ServerHello, EncryptedExtensions, Certificate, and CertificateVerify parsers stay safe on hostile bytes, and the certificate list and signature slices they hand back lie inside the message. The `_webpki` harnesses prove the `TRUST=webpki` arms, the empty server_name acknowledgement and the three CertificateVerify schemes, and `certparse_webpki` also proves that an accepted scheme is one of those three. The three `eeparse` harnesses also prove the EncryptedExtensions alert contract: the parser keeps the caller's seeded alert or writes unsupported_extension, a `TRUST=webpki` arm may also write decode_error and illegal_parameter, the second for an ALPN name or a server certificate type outside the offer. The parser writes no other alert. `eeparse_webpki` also proves that an accepted server certificate type is the caller's seed or one the offer holds. `eeparse_alpn` proves the ALPN arm where it lives, over one extension body rather than a whole message: against an offer of up to 8 protocol names of up to 32 bytes, every byte and every length symbolic, an accepted body names a protocol the offer holds, a refused one leaves the caller's `CH_ALPN_NONE`, and the alert is the caller's seed or one of the arm's two. Driving that offer through the whole extension loop multiplies the two bounds and returned no verdict in 21 minutes, so the loop around the arm is `eeparse_webpki`'s, at its 256-byte message with an empty offer. The 256-byte bound cannot hold a hybrid key_share, so the `KEX=pq` arm is driven by its own `key_share` leg instead. `handshake_parser_suite` is `handshake_parser` in the `SUITE=aesgcm TRUST=webpki` client, and also proves that an accepted ServerHello or retry carries ChaCha20 or AES-128-GCM, the two suites that client offers | messages ≤ 256 B; the ALPN arm one extension body ≤ 40 B against 8 names ≤ 32 B each |
| handshake_post | the post-handshake parser stays safe on hostile decrypted bytes and consumes no more than its input | messages ≤ 128 B |
| srv_accept | `ch_srv_accept` and `ch_srv_check` stay safe over an unconstrained `ch_cfg` — every pointer NULL or live, every length any `size_t`, an ALPN offer at `CH_ALPN_MAX` names of `CH_ALPN_NAME_MAX` bytes — and `srv_handshake` drives the flight in one order: a configuration it refuses reaches no handler and leaves a dead session, a handshake that fails after a handler ran wipes the record keys and leaves a dead session, and only a flight that reached `srv_complete` answers `CH_OK`. The fourteen `srv_flight.h` handlers, `srv_resume.h`'s ticket call, `srv_auth.h`'s two entry points, `rec_seal` and `io_send_all` are contract stubs the harness defines, so **no message this server writes is proved here**; the `srv_flight` leg below is where those handlers are real; `ROLE=server` only | ALPN offers ≤ 8 names of ≤ 32 B |
| srv_kex | the server's key exchange, `srv_kex.c`, stays safe over any groups and shares a parsed ClientHello reports and every verdict its two primitives return, and computes what `srv_kex.h` states: X25519MLKEM768 whenever the client listed it and x25519 only when it listed x25519 alone; an x25519 share that is `h->pub`; a hybrid share that is the ciphertext and then `h->pub`, encapsulated to the key the hello carried; a refused encapsulation key that keeps no ML-KEM secret; input keying material that is the ML-KEM secret and then the x25519 one, computed against the x25519 value that ends the client's share, which is RFC 10024's order; and, on both exits, a wiped ML-KEM secret and x25519 key pair, with the whole 64-byte secret wiped on a refusal (INV-3, INV-17). ML-KEM, x25519 and `ch_rand_bytes` are stubbed to their contracts, as in `hybrid_secret`; `ROLE=server` only | every group and share a hello can report, fast tier |
| srv_rec | **not proved.** `proof/srv_rec_harness.c` exists and its formula returns no verdict with the record loop, the message loop and the step table in one solve: none in 11 minutes at `--unwind 8` over 12-byte buffers, none in 9 min 52 s at 6.2 GB at `--unwind 4` over 8-byte buffers. `proof/run.sh` records what was tried and the layered split it needs. `srv_rec.c` and `rec_frame.c` are covered by `bin/srv_rec_test` and `bin/rec_loop_test` and two `.violation` mutants instead | — |
| srv_flight | **not proved.** `proof/srv_flight_harness.c` exists and its formula returns no verdict with all fifteen handlers real: no answer in 55 minutes at `--unwind 40`, none at 20 or 18. `proof/run.sh` records what was tried and the layered split it needs. The handlers are covered by `bin/srv_flight_test` and four `.violation` mutants instead | — |
| srv_parser_ext | every reader of `srv_parser_ext.c` stays safe and free of UB over an unconstrained extension body, any extension type and any offset the walk can hand it, and each answers `CH_OK` or `CH_EPROTO` | bodies ≤ 24 B |
| srv_ticket | `srv_ticket_seal` writes only inside the caller's buffer and writes either nothing or the whole `SRV_TICKET_LEN`-byte ticket, which it always writes when the capacity and the ALPN length allow; `srv_ticket_open` reads only inside the bytes it is given, answers `CH_OK` only for a ticket of exactly `SRV_TICKET_LEN` bytes whose first is `SRV_TICKET_VERSION` and whose ALPN length fits its field, and leaves the contents zeroed on a refusal. The AEAD is a contract stub, so that a sealed ticket opens under its own key and under no other is tested in `test/srv_ticket_tests.h` and **not proved**; `ROLE=server` only | tickets ≤ 105 B, one past `SRV_TICKET_LEN`, and any contents; fast tier |
| srv_resume | `srv_select_auth` walks any identities and binders lists without reading past either, selects a ticket only under `psk_dhe_ke` with a ticket key and a clock, names an index inside the list, and answers `CH_OK` with a way to authenticate, `CH_EAUTH` with decrypt_error, or `CH_EPROTO` with missing_extension or handshake_failure; `srv_send_new_session_ticket` sends at most one ticket, none without a key and a clock, with a lifetime of 1 to `SRV_TICKET_LIFETIME`. `srv_ticket.c`, the key schedule and the builders are contract stubs, so which binder matches is tested in `test/srv_resume_tests.h` and **not proved**; `ROLE=server` only | identities ≤ 117 B, one whole ticket and a short entry; binders ≤ 35 B; slow tier |
| srv_parser (the walk) | **not proved.** `proof/srv_parser_walk_harness.c` exists and its formula returns no verdict at any `fill_nondet` bound large enough to cover the SHA-256 stub's context; `proof/run.sh` records what was measured. The walk is covered by `bin/srv_test` and twenty `.violation` mutants instead | — |
| drbg | the generator stays safe for any request, seeded and across rekeys | requests ≤ 96 B |
| x509der (two harnesses) | every DER primitive stays safe on hostile bytes at the rbuf shape its caller hands it, honors the pointer contracts the walker rests on, and consumes no more than the per-primitive cap the walker proof replays, in both builds | inputs ≤ 448 B; keyusage at its 256 B extnValue cap |
| x509parse (two harnesses) | the certificate walker stays safe on any entry list, primitives stubbed to their proven contracts. Only the ECDSA build proves the full two-entry flight; the RSA bound holds one maximum certificate plus framing, so its two-entry walk rests on the ECDSA proof and the walker being identical outside the SPKI arm | ECDSA: ≤ 256 B, two entries; RSA: ≤ 840 B, one entry; both slow tier |
| pem_step (two harnesses) | `b64_value` returns exactly what RFC 4648 §4's alphabet table returns, on all 256 bytes; `pad_ok` is exactly §3.5's rule; and one body character preserves the decoder's accounting invariant from any state it admits, so induction carries that invariant to any input length | unbounded — one character, any state |
| pem (two harnesses) | the PEM decoder stays safe on hostile bytes at the shipped caps and honors its contract: a success yields a non-empty length inside the caller's array, every rejection yields zero, and an input over `CH_PEM_MAX` is refused before a byte is read | inputs ≤ 64 B (see the limit below) |
| x509ca (two harnesses) | the provisioning walk stays safe on any input and honors its contract: a success yields a key inside `CH_X509_KEY_MAX`, and every rejection yields zero with the key wiped. DER primitives stubbed to the contracts the `x509der` leg proves, and the SPKI stub deliberately returns lengths outside the real range so the entry's own bound check is what keeps the copy in range | any input; decoded certificate ≤ `CH_X509_MAX` |
| webpki_time | the `TRUST=webpki` Time reader stays safe on hostile bytes from any reader state, any position and either err value included, and a success leaves err clear, consumes exactly one Time TLV (15 or 17 bytes) and yields a packed date inside [19500101000000, 99991231235959]; the clock packer stays safe over every uint64, its clamp at 9999-12-31T23:59:59Z included, and yields a value inside the same range. That the packer keeps the order of clocks is **not proven** here: asserted over two nondet clocks, it returned no verdict in 30 minutes. The evidence for that order is `Spec.WebpkiTime.packSeconds_mono` and the differential (below) | Time bytes ≤ 40 B; the clock at its full range |
| webpki_name | the `TRUST=webpki` hostname shape check stays safe over any host and honors the contract `webpki_match_san` depends on: a name it accepts is 1..253 bytes of `[A-Za-z0-9.-]`, so it holds no NUL and no `*`, and every `-` in it has a byte other than a dot on each side, so no label starts or ends with `-`; and the per-entry dNSName compare, both its exact and its wildcard arm, stays safe over any presented name against any host | host ≤ `CH_HOSTNAME_MAX` (253 B), the real bound; presented name ≤ `CH_WEBPKI_EXT_TLV_MAX` (1024 B), the Extension bound, which no dNSName inside an Extension exceeds |
| webpki_san | the subjectAltName walk, in two parts like `pem_step` and `pem`: reading one GeneralName entry — its tag, its length, its content, the dNSName compare — is safe from any reader state, any position and either err value included. An entry it accepts starts with one of the nine GeneralName tags, leaves err clear, and moves the position forward by two or more bytes and never past the end, which is why the loop ends. `webpki_match_san` whole — the SEQUENCE header, its length check, the loop over entries — is safe on any bytes. The host is short in both parts: the walk passes it to the compare without change and reads no byte of it, and `webpki_name` proves that compare with a 253-byte host and a presented name of up to 1024 bytes (see the note below) | one entry at `CH_WEBPKI_EXT_TLV_MAX` (1024 B), the real bound; the whole walk ≤ 32 B — at 64 B the unrolled loop returned no verdict in 16 minutes, and before the split the walk at 1024 B was still being converted at 30 minutes; host ≤ 16 B |
| webpki_cert | `webpki_parse_certificate` over any bytes and any arm value, with the four readers it hands fields to (`webpki_read_sigalg`, `webpki_read_time`, `webpki_read_spki`, `webpki_read_extensions`) stubbed to the contracts their own harnesses prove and the DER primitives real. It returns `CH_OK` or `CH_EPROTO`, and a refusal leaves `ALERT_BAD_CERTIFICATE` or sets `ALERT_UNSUPPORTED_CERTIFICATE`. A success leaves the alert untouched and is at most `CH_WEBPKI_CERT_MAX` bytes. tbs lies inside the certificate; issuer, subject, the key and a non-NULL san lie inside tbs; the signature is non-empty, inside the certificate and after tbs. notBefore is no later than notAfter, the algorithm values are in range, and is_ca is the arm normalized to 0 or 1 with that arm's extensions seen. Asserting 0 at the success tail fails, so the tail is reached. The stubbed `webpki_read_extensions` contract is proven only at `webpki_ext_walk`'s bound (see the note below) | certificates ≤ 3,073 B, the real bound and the first length refused |
| webpki_ext (three harnesses) | the certificate extension walk, in parts like `webpki_san`. `webpki_ext` proves the pieces that read one element: one KeyPurposeId from any reader state, which, when accepted, leaves err clear and moves the position forward by three bytes or more and never past the end, so the purposes loop ends; `x509_read_extension` at the 1024-byte cap from any reader state, whose accepted Extension takes 7 to 1024 bytes with its extnID and extnValue inside them; basicConstraints over any extnValue, cA 0 or 1 and a pathLenConstraint from −1 to 32767; and the whole purposes loop. `webpki_ext_one` judges one Extension from any reader state and any walk state before it: a refusal names one of the two alerts, and an accepted one consumes 7 to 1024 bytes, adds at most one seen bit not already set, moves san only with its bit and inside the consumed bytes, and moves is_ca and path_len only with basicConstraints, is_ca equal to the arm. `webpki_ext_walk` runs `webpki_read_extensions` whole, the field read from its first byte: on `CH_OK` the arm's required extensions were seen, is_ca equals the arm, path_len is −1 on the leaf, and san is inside the consumed bytes and present on the leaf. Asserting 0 on each arm's success tail fails both, so both are reached. All three are slow-tier legs | one KeyPurposeId, `x509_read_extension` and basicConstraints at `CH_WEBPKI_EXT_TLV_MAX` (1024 B), the real bound; the purposes loop ≤ 64 B; one judged Extension ≤ 96 B — at 128 B no verdict in 31 minutes; the whole walk ≤ 48 B, which holds the leaf's shortest accepted field of 47 B — from any reader state it converged at 40 B and returned no verdict at 48 B in 31 minutes, and from the first byte it returned none at 64 B in 30 minutes |
| webpki_chain | `webpki_verify_chain` over any CertificateEntry list and any anchor array, with the five calls it makes (`webpki_parse_certificate`, `webpki_read_spki`, `webpki_verify`, `webpki_match_san`, `webpki_pack_seconds`) stubbed to the contracts their own harnesses prove. It returns `CH_OK`, `CH_EPROTO` or `CH_EAUTH`; a refusal names one of the four alerts `webpki.h`'s table lists; a success keeps the caller's alert and copies out a leaf key of at most `CH_WEBPKI_KEY_MAX` bytes under one of the three key algorithms. Asserting 0 at the success tail fails, so the tail is reached. Which chains it accepts is **not proved** here: the verify and match stubs answer an unconstrained verdict, so the formula says nothing about soundness. `Spec.Webpki.verifyChain_ok` states that an accepted chain has a verified signature path to an anchor, and `test/webpki_chain_test.c` and `test/diff_webpki_chain.h` test it over the corpus | lists ≤ 48 B, which holds eight framed entries of 6 bytes each, so both the `CH_WEBPKI_FLIGHT_ENTRIES` refusal and the `CH_WEBPKI_CHAIN_MAX` one are inside it; 2 anchors of ≤ 8 B each |
| certverify_webpki | the `TRUST=webpki` CertificateVerify arm of `handshake_auth.c`, over every signature scheme value and every leaf key family: a signature reaches a verifier only under the scheme the leaf key's family can produce, the verifier that runs is that family's own, and the signed content takes SHA-384 for a P-384 leaf and SHA-256 for every other. The record reader, the two hashes and the three verifiers are stubs the harness defines, each asserting what the arm passes it; `handshake_record`, `sha256`, `sha512` and the three verifier harnesses prove them, so whether a signature is genuine is **not proved** here. `test/webpki_auth_test.c` tests that over real chains and real signatures | CertificateVerify messages ≤ 12 B, leaf keys ≤ `CH_WEBPKI_KEY_MAX` |
| webpki_ticket | the `TRUST=webpki` resumption rule in `webpki_ticket.c`: the configuration hash reads only inside the hostname and the anchors the config names, and `webpki_resumption_ok` reads a presented ticket's PSK and binding only after the shape check admits them. It answers 0 or 1, and 1 only for a config whose PSK fields are all unset or that presents a ticket of the shape `webpki_ticket.h` states. SHA-256 is the contract stub, so which bindings match is **not proved** here; `test/webpki_resume_cases.h` tests that against a known answer computed outside this tree | hostname ≤ 253 B, 1 to 12 anchors with name and spki ≤ 4 B each, every PSK field NULL or set, fast tier |

CBMC found one real bug during development: `carry()` left-shifted a
negative value, which is undefined behavior even though compilers
tolerate it. The code multiplies instead now.

**Vectors cover known answers.** Unit tests replay [RFC 8448](https://www.rfc-editor.org/rfc/rfc8448)'s traces
message by message: the shared secret, every derived secret at its
transcript snapshot, both Finished MACs, and the ticket's resumption
PSK, plus the PSK binder chain and the HelloRetryRequest restart. Those
traces use AES-128-GCM, which the default build excludes, so the replay
stops at secrets and MACs; `bin/aes_suite_test` opens one of their records
under `SUITE=aesgcm`.

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
  exponentiation whole. The `X25519=wide` field rests on the same
  vectors, on its own Wycheproof leg and Lean differential binary, and
  on `bin/x25519_equiv_test`, which in `make check` compares it with the
  16-limb field over 12,175 inputs: the RFC vectors and the 1,000-round
  chain, every low-order and non-canonical u-coordinate, 10,000 random
  scalar and u-coordinate pairs, and 1,000 random scalars on the base
  point.
- P-256 ECDH functional correctness, for the same reason. The 355
  Wycheproof `ecdh_secp256r1` cases and `test/p256_ecdh_test.c`'s
  Python-computed key pairs and shared secrets are what says the ladder
  computes the right point; the proofs cover its memory safety and its
  range check. That the complete addition formula is complete — that it
  is correct when a point is added to itself or to the point at
  infinity, which is what lets the ladder run without a branch — is
  Renes, Costello and Batina's theorem, tested here and not machine
  checked.
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
  compressed pair on rv32 — in the sixteen arithmetic files under the
  record layer, the twelve on the TLS path and the four AES and GCM
  sources a `TRANSPORT=quic` build compiles, and holds each file at a
  ceiling measured per compiler. Those ceilings are public loop
  control, not zero: the block loops, x25519's ladder, Keccak's
  counters and softmul's fixed iterations. So the gate holds that no
  count grows, not that no
  branch exists, and what the ceilings record is that the
  compare-carries in `ct_widemul_opaque`, the sign masks in
  `ct_widemul_s` and `poly1305_final`, and the two select masks in
  `quic_gcm.c`'s `multiply_by_subkey` compile to a predicated
  instruction, `sltu` or a shift under every compiler measured --
  each compiler's choice, with no check on it until the count
  ([#141](https://github.com/c4milo/chapulin/issues/141)).
  `test/violations/inv16-poly1305-final-sign-branch.violation` writes
  the final select as an `if` on the last limb's sign and every spec's
  count rises by one; `inv16-widemul-s-sign-branch` does the same to
  `ct_widemul_s`, and clang lowers it back to the mask while every gcc
  emits two branches in x25519, so only the gcc gate objects;
  `inv16-ghash-subkey-select-branch` writes `multiply_by_subkey`'s
  first mask as an `if` on the accumulator bit, and every clang
  spec's count for `quic_gcm.c` rises. What is
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
  measured, not assumed: the pinned handshake's crypto costs 29% more
  on mips32r2, and the decomposition is 2.3 kB of flash, itemised
  under Speed and flash above.

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
  The `X25519=wide` field is the one secret-bearing source none of those
  specs can build, since it needs `unsigned __int128`. It multiplies on
  the 64x64->128 instruction, and `ct.h` refuses the build unless it
  defines `CH_NATIVE_MUL128`, its own statement that this instruction
  runs in constant time: Arm lists MUL and UMULH as data-independent
  while PSTATE.DIT is set, and Intel lists MUL and MULX in its DOIT
  instructions, which on recent parts hold only while the operating
  system enables DOITM. `make lint-wide-multiply` compiles the file for
  arm64 and x86-64 under the pinned clang and holds its divisions and
  128-bit runtime calls at zero and its branch count at the loop
  control it has, and `inv16-x25519-wide-cswap-branch` shows the count
  sees a `cswap` written as an `if`. No gcc measures it.
  `make timing` measures the decomposed path rather than the host's
  native one. `make ct-widemul-check`, in `check-slow`, rebuilds the
  unit, ML-KEM and Wycheproof binaries with `CH_CT_WIDEMUL`, so the
  RFC 7748, RFC 8439 and RFC 8448 vectors, the FIPS 203 known answers
  and the Wycheproof cases are also checked over the decomposition as
  poly1305, x25519 and mlkem_poly inline it — evidence at those inputs,
  while the equality proof stays at 8-bit operands.
- The `TRUST=webpki` subjectAltName walk against a full-length
  hostname. `webpki_name` proves the per-entry dNSName compare with
  the host at its real 253-byte bound and the presented name at 1024
  bytes. `webpki_san` proves the walk over a whole GeneralNames with a
  host of at most 16 bytes: one formula holding both wrote a 7.9 GB
  CNF at a 64-byte GeneralNames, because every entry of the walk
  repeats the compare against the whole host. No proof covers the two
  together. The argument that they compose is that the walk passes
  host and host_len to the compare without change and reads no byte
  of host. That is a fact about a twenty-line function, checked by
  reading, not by a solver. `test/diff_webpki.h` adds evidence: it
  compares the walk with the Lean model over hosts and presented names
  drawn from the seven-byte alphabet that file names. The clock packer's order,
  a later clock never packing lower, has the same kind of evidence:
  `Spec.WebpkiTime.packSeconds_mono` and the same differential, as the
  `webpki_time` row says.
- The `TRUST=webpki` extension walk over a full-size extensions field.
  The pieces that read one element are proved at the real 1024-byte
  bound, but a proof that composes them unrolls every reader below it,
  because a harness cannot replace the walk's statics with their
  contracts: `webpki_ext_one` judges one Extension of at most 96 bytes
  and `webpki_ext_walk` walks a field of at most 48 bytes. The S3 leaf's
  subjectAltName Extension alone is 653 bytes. The argument for any
  length is induction over the per-element contracts the pieces prove,
  the position moving forward and never past the end with err clear,
  checked by reading. `webpki_ext_walk` also starts its reader at the
  buffer's first byte, where `webpki_parse_certificate` hands it a
  reader in the middle of the TBS; the walk reads its bytes only
  through rbuf, which reads at `p + off` either way. `webpki_cert` stubs
  the walk to the contract `webpki_ext_walk` proves, so the certificate
  parser inherits both gaps. `test/webpki_cert_test.c` and `test/diff_webpki_cert.h` add
  evidence: every corpus and captured certificate, boundary mutants at
  each cap, single-byte changes and random extension lists, against the
  Lean model.
- Which chains the `TRUST=webpki` walk accepts. `webpki_chain` proves the
  walk memory-safe and UB-free over any entry list and any anchors, and
  proves the shape of what it returns, but its stubs for
  `webpki_verify` and `webpki_match_san` answer an unconstrained
  verdict, so the formula says nothing about which chains reach
  `CH_OK`. Putting the real verifiers in the formula would put an RSA
  and two ECDSA verifications inside it, which no harness in this tree
  converges on. `Spec.Webpki.verifyChain_ok` states the property
  instead — an accepted chain has a verified signature path to an
  anchor, with every step parsed under the issuer arm, covering the
  clock, named by the certificate below it and inside its own
  pathLenConstraint, and its leaf matched the caller's hostname through
  a dNSName of its own subjectAltName — and Lean's kernel checks that
  proof.
  `test/webpki_chain_test.c` and `test/diff_webpki_chain.h` add
  evidence at the bytes: the 25 minted chains, the 5 captured ones and
  their clock, hostname, anchor, entry and byte mutations.
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
proof. [Wycheproof](https://github.com/C2SP/wycheproof)'s attack-derived cases (`make wycheproof`, 5,221
across x25519, ChaCha20-Poly1305, HKDF-SHA256, HMAC-SHA256, ECDSA over P-256 and P-384 at every digest length a
certificate signature can pair with either curve, RSA-PSS and RSA PKCS#1 v1.5 up to RSA-4096, and
ML-KEM-768). The x25519 suite's 518 cases run a second time over the `X25519=wide` field, in its own binary. The HMAC-SHA256 suite calls `hmac_sha256` directly, so the MAC that Finished, the binders,
the QUIC Retry token, the HelloRetryRequest cookie and the webpki ticket binding compute is tested on its
own and not only through HKDF. The same lane signs every P-256 message in that corpus with `p256_sign` and hands the result to `p256_ecdsa_verify`, which shares no arithmetic with the signer; Wycheproof publishes no ECDSA signing vectors, so the signer's known answers are RFC 6979 A.2.5 and Python's integers in `test/p256_sign_test.c`.
Wycheproof tests no plain hash, so SHA-384 and SHA-512 rest on the
FIPS 180-4 examples and RFC 6234 §8.5 in `test/sha512_test.c`, with the
padding and block boundaries of the 128-byte block checked either side.
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

[`spec/lean/`](spec/lean/) is an executable [Lean 4](https://lean-lang.org/) specification of everything chapulin
computes: SHA-256, SHA-384 and SHA-512, SHA-3 and both SHAKE XOFs,
ML-KEM-768, HKDF and the
key schedule, ChaCha20, Poly1305, the AEAD, record framing, x25519,
the AES-128 forward cipher of FIPS 197, AEAD_AES_128_GCM and the GHASH
under it (NIST SP 800-38D), and the RFC 9001 Initial keys a
`TRANSPORT=quic` build derives from that cipher,
P-256, RSA-PSS, the grammar of the
four handshake messages a server sends, the provisioning path —
RFC 7468 armour with RFC 4648 base64, and the certificate walk that
turns one PEM block into the key bytes a pin slot takes — and, for
`TRUST=webpki`, the public-key and signature-algorithm readers, the
certificate signature verify over RSA PKCS#1 v1.5, P-256 and P-384, and
the one-certificate parser with its extension walk. It follows the RFC text and
never the C, because a differential oracle only works when a shared
misreading cannot make both sides agree.

`make diff` builds the spec, runs its selftests, then drives 19,864
random-input comparisons between the C and the spec over a pipe,
from a fixed seed. It then runs the `TRANSPORT=quic` rows, 387 over the
AES block, the Initial keys, AES-128-GCM and GHASH, twice: once under the
build's `AES` value and once under `AES=hw`, the instructions and the
carry-less multiply, where the compiler has them. Last it runs the
x25519 rows ten times over the `X25519=wide` field, 1,500
comparisons, where the compiler has `unsigned __int128`; the spec
computes over natural numbers mod p, so one model serves both fields.
`make diff-ecdsa`, `make diff-pq` and `make
diff-webpki` rebuild the same driver under `TRUST=raw-ecdsa`, `KEX=pq` and
`TRUST=webpki`, whose parsers take other arms, and the nightly runs
them. The spec depends on Mathlib, so run `lake exe cache
get` inside `spec/lean/` once after clone to download Mathlib's compiled
files; until then every spec target stops and names that command. Some
rows are signatures the spec mints and the C must accept: the spec holds
the private keys and signs, and the C, which can only verify, must
accept every genuine signature and reject every mutated one. About 730
rows feed the certificate parser generated DER — uniform bytes, edits at
random TLV sites, and leaves the spec re-signs. Nobody knows those
answers in advance, so the C answers first and the spec must reproduce
it. The provisioning rows work the same way, on certificates the spec
mints and the driver armours at every line width the decoder admits.
6,941 rows feed the `TRUST=webpki` certificate parser: every
corpus and captured certificate under both arms, single-byte changes of
them, and random extension lists inside one corpus certificate. Each
reply carries every field's offset into the certificate, so the C's
pointers are compared, not only its verdict.

The spec also carries theorems about itself, so an agreement between C
and spec transfers a proven fact rather than a matching answer. The
theorems constrain the model, not the C: they stop a spec regression
from quietly weakening the oracle. [`spec/lean/CONTRACT.md`](spec/lean/CONTRACT.md) lists them.

The state machine gets the same treatment one level up.
[`spec/lean/Spec/Handshake.lean`](spec/lean/Spec/Handshake.lean) models the message-ordering rules as a step
function, and [`test/handshake_sequence_test.c`](test/handshake_sequence_test.c) enumerates every server message
sequence the model admits — all eleven letters to depth 5, and the six
handshake letters to depth 6, in both modes, 466,286 in all. It renders
each as real records over a mock transport, runs the real client, and
requires its verdict to match the model's. The worst TLS bugs on record
were ordering bugs of exactly this kind: early-CCS, skipped Finished,
the SMACK/FREAK class. Memory-safety proofs and golden-path end-to-end
tests both miss them.

[`test/e2e.sh`](test/e2e.sh) runs the real thing against real peers: PSK, ticket
resumption, and pinned handshakes on both pinned algorithms, against OpenSSL 3
and Go, moving application data both ways. The ca-mode clients run chain
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
// TRUST=raw-ecdsa build: 64 P-256 bytes (X||Y).
// ch_cfg cfg = { .server_pubkey = modulus, .server_pubkey_len = 384,
//                .buf = rxbuf, ... };
static ch_tls tls;
if (ch_connect(&tls, &cfg) != CH_OK) { /* reconnect later */ }
ch_write(&tls, data, n);
int got = ch_read(&tls, out, sizeof out);
ch_close(&tls);
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
[`docs/webpki.md`](docs/webpki.md) has the whole refusal table, and
[`docs/decisions.md`](docs/decisions.md) entry 37 says why this mode
negotiates here and nowhere else.

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
[`docs/decisions.md`](docs/decisions.md) entry 12 says why a device
build offers one group, entry 39 why the webpki mode offers two, and
entry 53 why it sends a key share for each.

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
  (`bin/chapulin.o`) exporting exactly the four public calls and one data
  symbol, `ch_build`. Every internal symbol is localized, and `lib-check`
  fails if the export list ever changes. The calls are per build on
  three axes: `RAND=drbg` packages the reference generator and exports
  `ch_drbg_seed`, and a ca mode exports `ch_pubkey_from_pem` for
  provisioning, so a `TRUST=ca-rsa RAND=drbg` object exports six calls.
  `TRUST=webpki` exports the four calls and no provisioning call.
  `EXPORTER=on` adds `ch_export`, the exporter of RFC 9846 §7.5, and 32
  bytes to `ch_tls`; it is off
  by default, so the figures above are a build that exports nothing,
  and it refuses `TRANSPORT=quic`, whose object compiles no `tls.c`
  (decision 43). `KEYLOG=on` hands each traffic secret to a
  `ch_keylog` hook the image defines, for an NSS key log; it adds no
  export, it imports the hook, and it is refused for a client in a raw
  or ca trust mode (decision 44, INV-29). `WIDEMUL=native` defines
  `CH_NATIVE_WIDEMUL` in the object: the builder states that this
  part's widening multiply runs in constant time, and every widening
  product then uses the CPU's multiply instead of 16x16 pieces (`ct.h`).
  The default, `WIDEMUL=decomposed`, makes no claim about the part.
  `RAND` is the one build variable with no default. Compose with
  `TRUST=raw-ecdsa`, `TRUST=ca-rsa` or `TRUST=webpki`, and `KEX=pq`;
  the `TRUST=webpki` object carries every verifier, which is why that
  value names no algorithm. `X25519=wide` replaces the default 16-limb
  X25519 field with `x25519_wide.c`'s five 51-bit limbs, for a 64-bit
  host: `ct.h` stops the build unless the compiler has
  `unsigned __int128` and the build adds `-DCH_NATIVE_MUL128` to
  `CFLAGS`, its statement that the part's 64x64->128 multiply runs in
  constant time in the mode the part runs in (decision 52, INV-34). The
  Makefile never writes that define itself. It also carries both key exchange groups,
  so `make TRUST=webpki` refuses a `KEX` value, which would select
  nothing there (decision 53); set `ch_cfg.require_pq` for the hybrid
  alone. `KEX` chooses the group of a raw or ca client only, and
  `ROLE=server` and `ROLE=both` refuse it too, because a server role
  holds both groups in every build (decision 54).
- `ch_build` is the object's build record (`build.h`): the axes it was
  compiled with, the sizes of `ch_cfg`, `ch_tls`, `ch_ticket`,
  `ch_record`, `ch_quic` and `ch_rsa_priv`, and the bounds a program
  sizes its buffers from. A program that links the object compiles the
  headers under defines it writes itself, and a define it forgets
  changes those sizes while the program still links. So call
  `ch_build_matches(&ch_build)` once at startup and stop when it returns
  0; a program in another language compares the same fields with the
  `CH_BUILD_` macros. No library call reads the record, and decision 56
  says what it holds and what it leaves out.
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
CA bundles, CRL or OCSP revocation, client certificates, cipher
agility, the server role, or any insecure fallback. The device modes,
the raw and ca modes, do not implement public-CA trust; the
host-side `TRUST=webpki` mode does, against anchors the caller
supplies, and [`docs/webpki.md`](docs/webpki.md) lists what it does not
check. [`docs/decisions.md`](docs/decisions.md) records every trade and why.
The `TRANSPORT=quic` client is implemented and checked against RFC 9001's
Appendix A vectors; [`docs/quic.md`](docs/quic.md) records its design. A
QUIC *server* now builds too: `ROLE=server` with `TRANSPORT=quic` runs the
TLS 1.3 server handshake over CRYPTO frames and exports eighteen calls,
two of which mint and check the address validation token a server puts in
a Retry.
[`docs/quic_server.md`](docs/quic_server.md) states what chapulin owes one,
which is the keys, the packet protection and that token, and nothing above
them. Both
roles have completed handshakes with another implementation, in a test
that lives outside this tree: on 2026-09-23 colibri's `hq-interop` endpoint,
built over a `ROLE=both` object at 9c903d8, fetched three files from aioquic
1.3.0 and served the same three to it, over UDP on one host. That run
negotiated ChaCha20-Poly1305, the one suite the QUIC mode offers, and
`make check-slow` does not repeat it: this tree's e2e suite still has no
QUIC leg.

The `ROLE=server` build is implemented and completes a handshake;
[`docs/server.md`](docs/server.md) records its design. Given a ticket key
and the caller's clock (`ch_cfg.srv.ticket_key`, `ch_cfg.srv.now_seconds`),
it issues one resumption ticket per connection and resumes its own tickets
under `psk_dhe_ke`, with no Certificate, over all three transports;
`test/e2e.sh` has OpenSSL's `s_client` and this tree's client each resume
against it. Built with
`SUITE=aesgcm` it also selects `TLS_AES_128_GCM_SHA256`, which RFC 9846
section 9.1 makes mandatory to implement; the default build selects
ChaCha20 alone and does not meet that section.
[`docs/aes_suite.md`](docs/aes_suite.md) states what the suite rests on and
what it still owes.

Every server build holds X25519MLKEM768 and x25519 and prefers the
hybrid: a client that lists it gets it, in one round trip when its hello
carries the hybrid share, and after a HelloRetryRequest that asks for it
when the hello shares x25519 alone. A client that lists x25519 alone gets
x25519. `ch_tls.group` reports which group ran, as it does for a client,
and [`docs/decisions.md`](docs/decisions.md) entry 54 states the trade.
`test/e2e.sh` checks each case against OpenSSL's `s_client`, and a
resumed handshake runs the hybrid again.

Two caveats worth knowing before you adopt it.

The IoT profile's mandatory suite is AES-128-CCM-8, and chapulin's
device builds are ChaCha-only, because ChaCha needs no lookup tables and
runs in constant time on any core. `SUITE=aesgcm` adds AES-128-GCM, not
CCM-8, and only where the core has AES instructions. That works when you control both ends and fails
against a server that insists on AES. An AES-CCM build flag is the
likeliest v2 addition.

Pin the key of a server whose key is stable. Automatic rotation, such
as Let's Encrypt defaults, breaks pins. [`docs/rotation.md`](docs/rotation.md) shows how
the two-slot pin makes a planned rotation safe, and a ca mode absorbs
routine key churn entirely.

## Contributing and security

[CONTRIBUTING.md](CONTRIBUTING.md) states the quality bar and the workflow.
[`docs/invariants.md`](docs/invariants.md) catalogs the invariants a change must never break;
`make lint-invariants` enforces the machine-checkable ones.
[`docs/impact.md`](docs/impact.md) covers `make impact`, which prints the
gates a change can break so the inner loop runs those instead of the
whole slow tier; it never replaces `make check` or `make check-slow`.
Report vulnerabilities through [SECURITY.md](SECURITY.md), never the
public tracker.

## License

Apache-2.0. See [LICENSE](LICENSE).
