# chapulin

A TLS 1.3 client for devices with a few kilobytes of static RAM (SRAM)
to spare. Named after El Chapulín Colorado: small, unassuming, and it
protects you from the bad guys.

chapulin speaks one profile: TLS 1.3 with
`TLS_CHACHA20_POLY1305_SHA256` and x25519 key exchange. It offers no
alternatives and negotiates nothing. The server accepts the profile or
the handshake fails closed. There is no 0-RTT.

The client authenticates the server in one of two modes:

- **Pre-shared key (PSK).** Both sides hold a provisioned secret and run
  ECDHE-PSK (`psk_dhe_ke`), so the handshake keeps forward secrecy.
- **Pinned key.** You provision the server's raw public key instead of a
  secret. The pin is public data: it needs integrity, not secrecy. The
  server proves possession of the private key by signing the handshake
  (CertificateVerify), and the client checks that signature against the
  pin. The client hashes the server's certificate into the transcript
  but never parses it: no ASN.1, no chains, no names, no expiry. Pinned
  mode works against stock certificate-based endpoints such as Go's
  `crypto/tls` and OpenSSL.

The pinned key is one signature algorithm per build. The default build
verifies RSA-PSS (`rsa_pss_rsae_sha256`) and pins the raw modulus, 256
to 384 bytes, so one binary covers RSA-2048 through RSA-3072 — the keys
stock endpoints actually hold. `make PIN=ecdsa` builds the P-256
alternative (`ecdsa_secp256r1_sha256`, a 64-byte X||Y pin) instead;
these are the two signature algorithms [RFC 9846](https://www.rfc-editor.org/rfc/rfc9846) requires every TLS 1.3
implementation to support, so between them a chapulin build can pin any
compliant server. Neither build carries the other's verifier.

Both modes receive session tickets, so reconnects resume over PSK. In
pinned mode the client therefore pays the signature verification once
per ticket lifetime, not per connection.

The stack uses C11 and libc only, with zero heap. The working set is one
session struct plus one receive buffer that the caller provides. The
client advertises the buffer's size as its `record_size_limit`
([RFC 8449](https://www.rfc-editor.org/rfc/rfc8449)), so a peer can never send a record the buffer cannot hold.
Pinned mode adds one sizing rule: the server's Certificate message must
fit the receive buffer. A self-signed P-256 leaf needs about 600 bytes
and a self-signed RSA-3072 leaf about 1.2 kB, so the 2 kB buffer below
covers both; a CA chain needs a buffer sized to the whole chain, because
the certificates arrive even though the client never reads them.

The client honors the RFC requirements that even a minimal client must
keep: HelloRetryRequest with cookie echo and transcript restart,
KeyUpdate in both directions, NewSessionTicket parsing with
resumption-PSK derivation handed to the application, and [RFC 9257](https://www.rfc-editor.org/rfc/rfc9257)
binder rules over the truncated ClientHello.

[`test/e2e.sh`](test/e2e.sh) exercises the profile against real peers. It runs a PSK
handshake, ticket resumption, and pinned-key handshakes — RSA-3072 with
the default client, P-256 with the `PIN=ecdsa` client — against both
OpenSSL 3 and Go's `crypto/tls`, and it moves application data both
ways throughout.

## Memory

[`bench/sram.sh`](bench/sram.sh) measures every number below on the host (arm64); 32-bit
targets shrink the pointer fields.

| what | bytes |
|---|---|
| `ch_tls` session struct (includes 534 B TX staging) | 1008 |
| caller receive buffer (you choose; 2048 shown) | 2048 |
| **total static working set** | **3056** |
| peak transient stack, `ch_connect` (default: RSA-3072 verify) | 5200 |
| peak transient stack, `ch_connect` (`PIN=ecdsa`: P-256 verify) | 3680 |
| peak transient stack, `ch_connect` (PSK mode: x25519 ladder) | 2608 |
| peak transient stack, `ch_read` (worst case: KeyUpdate rekey) | 1632 |
| peak transient stack, `ch_write` / `ch_close` | 736 / 688 |

The script computes each entry point's worst case from the object code's
call graph, weighted by `-fstack-usage` frames. It does not rely on a
hand-picked call chain. The RSA verify holds the deepest frames in the
stack (the 96-limb Montgomery working arrays), so it sets the
`ch_connect` peak in the default build; the verify runs once per ticket
lifetime and every byte of it unwinds before `ch_connect` returns.

The stack never calls malloc and never uses variable-length arrays or
alloca. For comparison, the smallest published TLS 1.3 PSK working sets
elsewhere: wolfSSL needs about 6.2 kB of heap plus buffers; mbedTLS
needs 9 to 15 kB and cannot run without an allocator; both need a 16 kB
record buffer unless the peer supports `record_size_limit`.
[`docs/landscape.md`](docs/landscape.md) holds the full survey with sources.

## On the device

[`bench/insn-mips.sh`](bench/insn-mips.sh) and [`bench/device-ram.sh`](bench/device-ram.sh) cross-compile for
mips32r2 (the RTL8382-class core) and measure on the real ISA:
deterministic qemu instruction counts and `-Os` section sizes. CPU cost
is published as instruction counts, not guessed milliseconds; the
millisecond column assumes 500 MHz and one instruction per cycle, which
is optimistic for an in-order core, so read it as a lower bound.

| work | instructions | ms (500 MHz, 1 IPC) |
|---|---|---|
| AEAD seal, per 1 KB record | 47 k | 0.1 |
| SHA-256, per 1 KB | 68 k | 0.14 |
| x25519 scalar multiply | 28.7 M | 57 |
| RSA-3072 PSS verify (default build) | 11.6 M | 23 |
| P-256 signature verify (`PIN=ecdsa` build) | 46.0 M | 92 |
| full pinned handshake crypto (default build) | 69.7 M | 139 |

Flash is 26.4 kB for the default build (`.text` + `.rodata`, mips32r2
`-Os`): handshake 5.0 kB, x25519 3.3 kB, rsa + rsa_mont 2.3 kB, the rest
smaller. The `PIN=ecdsa` build swaps the 2.3 kB of rsa for p256's
6.1 kB, totaling 30.1 kB.

Public-key work dominates the handshake. Every handshake runs two x25519
(ECDHE, for forward secrecy) whether it is a fresh PSK connection, a
resumption, or pinned mode, so ~115 ms of x25519 is the recurring floor
and 82% of the pinned handshake's crypto. The signature verify is paid
only on the first pinned connection; resumptions present a ticket and
skip it. RSA verification is cheap by construction — the public exponent
65537 costs 17 modular multiplies, where P-256 runs two full scalar
multiplications — which is why the default build verifies 4× faster
while also being smaller. Record crypto is ~0.1 ms per kilobyte,
negligible next to the handshake. For a device that opens one long-lived
connection this is a once-per-connection cost, so chapulin keeps the
16-bit-limb x25519 for its machine-checked overflow proof rather than a
faster wide-limb version; a workload of many short connections would
change that trade. The compiler already emits ideal `maddu` accumulator
chains for the 32-bit-limb code (poly1305, the P-256 and RSA Montgomery
multiplies) and keeps ChaCha20's state in registers, so no hand-tuning
is left on the table there.

## Verification

The C Bounded Model Checker (CBMC) proves every module memory-safe and
free of undefined behavior, for every input within each harness's
documented bound. Memory safety covers array bounds and pointer
validity; undefined behavior covers signed overflow, invalid shifts, and
division by zero. Where a bound equals the module's real maximum, the
proof covers all inputs. Where it does not, the table states the bound.

The proofs run in two tiers. `make check` runs the fast tier, the proofs
that finish in seconds to a few minutes. `make prove-slow` runs the four
long ones (handshake driver, aead, x25519, hkdf expand). CI runs both
tiers.

The suite layers its proofs the way mlkem-native does. CBMC proves the
leaf modules directly. Upper layers (hkdf, record, the handshake driver)
run against stubs that assert the proven contract of the layer below and
return arbitrary values, so no upper proof depends on cryptographic
values.

| harness | proves | bound |
|---|---|---|
| ct | memeq matches a plain comparison, wipe zeroizes, no undefined behavior | all inputs ≤ 64 B |
| buf | any 12-operation reader/writer sequence stays safe; length never exceeds capacity | buffers ≤ 64 B |
| sha256 | safe for any two-chunk split | messages ≤ 96 B |
| hkdf (two harnesses) | hmac/extract and expand/expand-label safe over the proven sha256 contract | keys ≤ 96 B, output ≤ 96 B |
| handshake | the driver stays safe on any record stream: record pump, cross-record reassembly, HRR restart, state machine, both auth modes | 96 B receive buffer |
| chacha20 | safe, including in-place use, at any counter | ≤ 160 B (3 blocks) |
| poly1305 | safe for any three-chunk split; 64-bit products stay in range | messages ≤ 80 B |
| aead | seal/open round-trips; a forged tag writes zero bytes; backward-overlap decrypt works (the record layer's in-place mode) | plaintext ≤ 64 B, aad ≤ 32 B |
| x25519 | field operations are memory-safe (direct proof); a separate lemma proves the int64 arithmetic cannot overflow | limbs ≤ 2^24 |
| p256 | the DER parser and limb marshalling stay safe on hostile signatures (direct proof); a carry lemma covers the Montgomery multiply | signatures ≤ 80 B |
| rsa (two harnesses) | the PSS decode — range checks, MGF1 masking, salt walk, H′ compare — and the limb marshalling stay safe with the RSAVP1 result replaced by arbitrary bytes; a carry lemma covers the Montgomery multiply | 384 B modulus, every byte hostile |
| record | seal works across its contract; rec_open stays safe on fully hostile bytes | records ≤ 160 B |
| hsparse | the ServerHello parser stays safe on hostile bytes | messages ≤ 256 B |
| eeparse | the EncryptedExtensions parser stays safe on hostile bytes | messages ≤ 256 B |
| tlspost | the post-handshake parser (NewSessionTicket, KeyUpdate) stays safe on hostile decrypted bytes and consumes no more than its input | messages ≤ 128 B |
| drbg | the reference generator stays safe for any request, seeded and across rekeys | requests ≤ 96 B |

CBMC found one real bug during development: `carry()` left-shifted a
negative value (`c << 16`), which is undefined behavior in C even though
compilers tolerate it. The code now multiplies instead, with the same
code generation.

The following claims rest on tests, not proofs:

- x25519 functional correctness rests on the [RFC 7748](https://www.rfc-editor.org/rfc/rfc7748) vectors, including
  the 1,000-iteration chain. The limb scheme (TweetNaCl's) also carries
  a prior Coq/VST functional proof by Schwabe et al. The limb-growth
  invariant that connects multiply outputs to add/sub inputs remains an
  open proof task.
- The post-handshake parser (handle_post_handshake) is proven on hostile bytes
  (the tlspost harness). The surrounding ch_read/ch_write/ch_close driver
  — the record pump and cross-record reassembly — does not converge as one
  CBMC formula, so it rests on e2e, the mock-transport unit tests, and the
  posths fuzzer.
- P-256 functional correctness rests on [RFC 6979](https://www.rfc-editor.org/rfc/rfc6979) vectors plus fresh
  signatures that the Lean spec mints and the C must accept. The
  scalar-multiplication loops compose proven pieces, but CBMC does not
  run them whole.
- RSA functional correctness rests on OpenSSL-produced vectors at both
  2048 and 3072 bits plus fresh PSS signatures that the Lean spec mints
  and the C must accept. The PSS decode is proven on hostile bytes and
  the Montgomery multiply carries its carry lemma, but CBMC does not run
  the 3072-bit exponentiation whole.
- Constant-time behavior comes from construction: no branch and no
  memory index depends on a secret, and the stack avoids AES because of
  its lookup tables. `make timing` checks this statistically (Welch's
  t-test over interleaved secret classes). That is evidence, not proof.
  P-256 and RSA verification are variable-time on purpose: all of their
  inputs are public.

No other stack in this space carries whole-stack machine-checked memory
safety. The closest prior art is AWS's CBMC work on the FreeRTOS core
libraries and on mlkem-native, and this suite copies that method.

## The differential oracle

`spec/` is an executable Lean 4 specification of everything chapulin
computes: SHA-256, HKDF and the RFC 9846 §7.1 key schedule, ChaCha20,
Poly1305 (the accumulator is a plain `Nat` mod 2^130−5), the AEAD,
record framing, x25519, P-256, and RSA-PSS, all as definitional `Nat`
arithmetic. The spec follows the RFC text and never the C, because a
differential oracle only works when a shared misreading cannot make both
sides agree. Each module carries its RFC vectors as a selftest, and the
key schedule also matches [RFC 8448](https://www.rfc-editor.org/rfc/rfc8448)'s published trace values. The spec
also carries theorems about itself — AEAD round-trip and rejection
soundness, the record round-trip at the AEAD layer, output lengths, and
the handshake model's safety invariants (see [`spec/CONTRACT.md`](spec/CONTRACT.md), "Proven
properties") — so an agreement between C and spec transfers a proven
fact, not just a matching answer.

The unit tests replay RFC 8448's traces at the transcript level: the
section 3 1-RTT handshake message by message — the ECDHE shared secret,
every derived secret at its transcript snapshot, both Finished MACs, and
the ticket's resumption PSK — plus the section 4 PSK binder chain over
that ticket and the section 5 HelloRetryRequest transcript restart. The
traces protect records with AES-128-GCM, which chapulin excludes, so the
replay stops at secrets and MACs and never opens a record. RFC 8448
signs with an RSA-1024 key, below rsa_pss_verify's 2048-bit floor; the
tests check that the public API refuses the key, then verify the trace's
CertificateVerify one layer down, through the raw RSAVP1 modexp and a
test-local PSS check.

`make diff` builds the spec with `lake`, runs its selftests, and then
drives about 3,000 random-input comparisons between every C module and
the spec over a pipe, with a deterministic seed. The comparisons include
P-256 and RSA-PSS signatures that the spec mints and the C must accept —
the spec holds the private keys and signs; the C, which can only verify,
must accept every signature and reject every mutated one. The target
runs inside `make check` and skips itself when elan is not installed.

The handshake state machine gets the same treatment one level up.
[`spec/Spec/Handshake.lean`](spec/Spec/Handshake.lean) models RFC 9846 §4's message-ordering rules as an
explicit step function, and [`test/hsseq_test.c`](test/hsseq_test.c) enumerates every server
message sequence to depth 5 — 354,312 sequences across both auth modes —
renders each as real TLS records over a mock transport (genuine key
schedule and Finished MACs; only the pinned-mode signature check is
scripted), runs the real client, and requires its accept/reject verdict
to match the model's. The worst TLS implementation bugs on record were
exactly such ordering bugs (early-CCS, skipped Finished — the
SMACK/FREAK class), invisible to memory-safety proofs and golden-path
e2e alike.

The layers cover different failure classes. Proofs cover memory safety.
Vectors cover known answers. The oracles check that the C computes the
same functions — and accepts the same message orderings — as a short
spec that a reviewer can read next to the RFC.

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
// …or pinned-key mode: no shared secret, just the server's raw public
// key, provisioned once. Default build: the RSA modulus (openssl rsa
// -noout -modulus). PIN=ecdsa build: 64 P-256 bytes (X||Y).
// ch_cfg cfg = { .server_pubkey = modulus, .server_pubkey_len = 384,
//                .buf = rxbuf, ... };
static ch_tls tls;
if (ch_connect(&tls, &cfg) != CH_OK) { /* reconnect later */ }
ch_write(&tls, data, n);
int got = ch_read(&tls, out, sizeof out);
ch_close(&tls);
```

The platform provides two blocking socket callbacks, bounded by its own
timeouts, and implements `ch_rand_bytes` (rand.h): from a hardware
random number generator when the part has one, or from the seeded
fast-key-erasure generator in `drbg.[ch]` when it does not — the
RTL8382-class reference target has no such peripheral. [`docs/entropy.md`](docs/entropy.md)
covers seed provisioning; the generator refuses to run unseeded. Every error kills the session: the stack wipes its
keys and the caller reconnects. Devices recover by reconnecting anyway,
and the rule removes the entire resumable-error state space from the
code and the proofs.

## Building

`make check` runs the whole gate:

- build, with all warnings as errors
- lint: clang-tidy, clang-format, cppcheck, commitlint
- unit tests (RFC vectors)
- e2e against OpenSSL 3 and Go
- the Lean differential oracle
- the fast proof tier

C++ callers can use `chapulin.hpp`, an optional header-only wrapper that
forwards to the same C calls with no runtime cost. It is freestanding
and compiles under `-fno-exceptions -fno-rtti`; its value is a session
that wipes its keys when it leaves scope, plus byte-view read/write and a
typed result. `make cxx-check` builds it against the packaged library.

Separate targets: `make lib` packages the library as one relocatable
object (`bin/chapulin.o`) that exports exactly the four public calls —
every internal symbol is localized, and `lib-check` (part of `check`)
fails if the export list ever grows. `make PIN=ecdsa lib` packages the
P-256 pinned build instead of the RSA default; the object carries only
the selected verifier. `make prove-slow` runs the four
long proofs. The proof runner caches results by content — a harness whose
preprocessed sources, flags, and checker version are byte-identical to
its last successful run is skipped, so an incremental `make check`
re-proves only what changed (`PROVE_NO_CACHE=1` forces a full run) — and
schedules jobs by memory weight against the machine's budget, so a big
machine runs the whole fast tier at once. It uses kissat as the SAT back
end when installed (`brew install kissat`; verdicts are
solver-independent, kissat just reaches them faster); `PROVE_SOLVER=builtin`
forces CBMC's built-in solver and `PROVE_SOLVER=smt2` routes through z3's
incremental SMT back end instead. `make timing` runs the constant-time check (load-sensitive, so
run it on an idle machine). `make fuzz` smoke-runs the libFuzzer
harnesses. `make hooks`, once after clone, enables the commit-msg hook.
See [`CLAUDE.md`](CLAUDE.md) for the house rules.

## Non-goals

[`docs/decisions.md`](docs/decisions.md) records every trade this stack has made and why;
this section is the short version.

chapulin does not implement: 0-RTT (the IETF IoT profile forbids it),
DTLS, X.509 chain validation, CA bundles, revocation, client
certificates, cipher agility, the server role, or any insecure-fallback
option. Pinned mode accepts a certificate but never parses it; the
signature check against the provisioned key is the authentication.

Two caveats. First, the IETF TLS 1.3 IoT profile's mandatory suite is
AES-128-CCM-8, and chapulin is ChaCha-only because ChaCha needs no
lookup tables and runs in constant time on any core. That choice works
when you control both ends and fails against a server that insists on
AES; an AES-CCM build flag is the most likely v2 addition. Second, pin
the key of a server whose key is stable. Automatic key rotation, such as
Let's Encrypt defaults, breaks pins.

## License

Apache-2.0. See [LICENSE](LICENSE).
