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
- **Pinned key.** You provision the server's raw P-256 public key
  instead of a secret. The pin is public data: it needs integrity, not
  secrecy. The server proves possession of the private key by signing
  the handshake (CertificateVerify), and the client checks that
  signature against the pin. The client hashes the server's certificate
  into the transcript but never parses it: no ASN.1, no chains, no
  names, no expiry. Pinned mode works against stock certificate-based
  endpoints such as Go's `crypto/tls` and OpenSSL.

Both modes receive session tickets, so reconnects resume over PSK. In
pinned mode the client therefore pays the ECDSA verification once per
ticket lifetime, not per connection.

The stack uses C11 and libc only, with zero heap. The working set is one
session struct plus one receive buffer that the caller provides. The
client advertises the buffer's size as its `record_size_limit`
(RFC 8449), so a peer can never send a record the buffer cannot hold.
Pinned mode adds one sizing rule: the server's Certificate message must
fit the receive buffer. A self-signed leaf needs about 600 bytes; a CA
chain needs a larger buffer.

The client honors the RFC requirements that even a minimal client must
keep: HelloRetryRequest with cookie echo and transcript restart,
KeyUpdate in both directions, NewSessionTicket parsing with
resumption-PSK derivation handed to the application, and RFC 9257
binder rules over the truncated ClientHello.

`test/e2e.sh` exercises the profile against real peers. It runs a PSK
handshake, ticket resumption, and pinned-key handshakes against both
OpenSSL 3 and Go's `crypto/tls`, and it moves application data both
ways throughout.

## Memory

`bench/sram.sh` measures every number below on the host (arm64); 32-bit
targets shrink the pointer fields.

| what | bytes |
|---|---|
| `ch_tls` session struct (includes 534 B TX staging) | 976 |
| caller receive buffer (you choose; 2048 shown) | 2048 |
| **total static working set** | **3024** |
| peak transient stack, `ch_connect` (pinned mode: P-256 verify) | 3344 |
| peak transient stack, `ch_connect` (PSK mode: x25519 ladder) | 2608 |
| peak transient stack, `ch_read` (worst case: KeyUpdate rekey) | 1632 |
| peak transient stack, `ch_write` / `ch_close` | 736 / 688 |

The script computes each entry point's worst case from the object code's
call graph, weighted by `-fstack-usage` frames. It does not rely on a
hand-picked call chain.

The stack never calls malloc and never uses variable-length arrays or
alloca. For comparison, the smallest published TLS 1.3 PSK working sets
elsewhere: wolfSSL needs about 6.2 kB of heap plus buffers; mbedTLS
needs 9 to 15 kB and cannot run without an allocator; both need a 16 kB
record buffer unless the peer supports `record_size_limit`.
`docs/landscape.md` holds the full survey with sources.

## On the device

`bench/insn-mips.sh` and `bench/device-ram.sh` cross-compile for
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
| P-256 signature verify | 46.0 M | 92 |
| full pinned handshake crypto | 104 M | 208 |

Flash is 30 kB (`.text` + `.rodata`, mips32r2 `-Os`): p256 6.1 kB,
handshake 5.0 kB, x25519 3.3 kB, the rest smaller.

Public-key work dominates the handshake. Every handshake runs two x25519
(ECDHE, for forward secrecy) whether it is a fresh PSK connection, a
resumption, or pinned mode, so ~115 ms of x25519 is the recurring floor.
The P-256 verify (92 ms) is paid only on the first pinned connection;
resumptions present a ticket and skip it. Record crypto is ~0.1 ms per
kilobyte, negligible next to the handshake. For a device that opens one
long-lived connection this is a once-per-connection cost, so chapulin
keeps the 16-bit-limb x25519 for its machine-checked overflow proof
rather than a faster wide-limb version; a workload of many short
connections would change that trade. The compiler already emits ideal
`maddu` accumulator chains for the 32-bit-limb code (poly1305, the P-256
Montgomery multiply) and keeps ChaCha20's state in registers, so no
hand-tuning is left on the table there.

## Verification

The C Bounded Model Checker (CBMC) proves every module memory-safe and
free of undefined behavior, for every input within each harness's
documented bound. Memory safety covers array bounds and pointer
validity; undefined behavior covers signed overflow, invalid shifts, and
division by zero. Where a bound equals the module's real maximum, the
proof covers all inputs. Where it does not, the table states the bound.

The proofs run in two tiers. `make check` runs the eleven proofs that
finish in seconds to a few minutes. `make prove-slow` runs the four long
ones (handshake driver, aead, x25519, hkdf expand). CI runs both tiers.

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
| record | seal works across its contract; rec_open stays safe on fully hostile bytes | records ≤ 160 B |
| hsparse | the ServerHello and EncryptedExtensions parsers stay safe on hostile bytes | messages ≤ 256 B |

CBMC found one real bug during development: `carry()` left-shifted a
negative value (`c << 16`), which is undefined behavior in C even though
compilers tolerate it. The code now multiplies instead, with the same
code generation.

The following claims rest on tests, not proofs:

- x25519 functional correctness rests on the RFC 7748 vectors, including
  the 1,000-iteration chain. The limb scheme (TweetNaCl's) also carries
  a prior Coq/VST functional proof by Schwabe et al. The limb-growth
  invariant that connects multiply outputs to add/sub inputs remains an
  open proof task.
- The post-handshake pump in tls.c rests on e2e, the mock-transport unit
  tests, and the posths fuzzer. Its CBMC harness is the last one
  missing.
- P-256 functional correctness rests on RFC 6979 vectors plus fresh
  signatures that the Lean spec mints and the C must accept. The
  scalar-multiplication loops compose proven pieces, but CBMC does not
  run them whole.
- Constant-time behavior comes from construction: no branch and no
  memory index depends on a secret, and the stack avoids AES because of
  its lookup tables. `make timing` checks this statistically (Welch's
  t-test over interleaved secret classes). That is evidence, not proof.
  P-256 verification is variable-time on purpose: all of its inputs are
  public.

No other stack in this space carries whole-stack machine-checked memory
safety. The closest prior art is AWS's CBMC work on the FreeRTOS core
libraries and on mlkem-native, and this suite copies that method.

## The differential oracle

`spec/` is an executable Lean 4 specification of everything chapulin
computes: SHA-256, HKDF and the RFC 8446 §7.1 key schedule, ChaCha20,
Poly1305 (the accumulator is a plain `Nat` mod 2^130−5), the AEAD,
record framing, x25519, and P-256, all as definitional `Nat` arithmetic.
The spec follows the RFC text and never the C, because a differential
oracle only works when a shared misreading cannot make both sides agree.
Each module carries its RFC vectors as a selftest, and the key schedule
also matches RFC 8448's published trace values.

`make diff` builds the spec with `lake`, runs its selftests, and then
drives about 2,750 random-input comparisons between every C module and
the spec over a pipe, with a deterministic seed. The comparisons include
P-256 signatures that the spec mints and the C must accept. The target
runs inside `make check` and skips itself when elan is not installed.

The three layers cover different failure classes. Proofs cover memory
safety. Vectors cover known answers. The oracle checks that the C
computes the same function as a short spec that a reviewer can read next
to the RFC.

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
// …or pinned-key mode: no shared secret, just the server's raw P-256
// public key (X||Y), provisioned once.
// ch_cfg cfg = { .server_pubkey = pin64, .buf = rxbuf, ... };
static ch_tls tls;
if (ch_connect(&tls, &cfg) != CH_OK) { /* reconnect later */ }
ch_write(&tls, data, n);
int got = ch_read(&tls, out, sizeof out);
ch_close(&tls);
```

The platform provides two blocking socket callbacks, bounded by its own
timeouts, and wires `ch_rand_bytes` (rand.h) to its hardware random
number generator. Every error kills the session: the stack wipes its
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
fails if the export list ever grows. `make prove-slow` runs the four
long proofs; set `PROVE_SOLVER=smt2` to route proofs through z3's
incremental SMT back end, which streams the formula and lowers peak
memory. `make timing` runs the constant-time check (load-sensitive, so
run it on an idle machine). `make fuzz` smoke-runs the libFuzzer
harnesses. `make hooks`, once after clone, enables the commit-msg hook.
See `CLAUDE.md` for the house rules.

## Non-goals

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
