# Security invariants

[docs/decisions.md](decisions.md) answers "why is it built this way".
This document answers "what must a change never break", and
[.semgrep/invariants.yml](../.semgrep/invariants.yml) makes part of
the answer executable: `make lint-invariants` fails CI when a change
breaks a machine-checkable entry.

Each entry has four fields. **Claim** is the invariant. **Mechanism**
is what enforces it. **Check** is what guards it, graded honestly on
this scale, strongest first:

1. *type system* — a violation does not compile.
2. *structural arithmetic* — the property holds by construction; there
   is no code path that could break it without rewriting the
   construction.
3. *CBMC* — proved over all inputs at the harness's documented bound.
4. *semgrep-structural* — a call-graph or state rule; catches any
   syntactic violation, honest or not.
5. *semgrep-tripwire* — an identifier ban; catches honest drift, not a
   determined reintroduction under another name.
6. *convention + t-test* — code review holds the line; `make timing`
   gives statistical evidence after the fact.

**Violation** is what a breaking PR looks like, so review knows the
smell. Machine-enforced entries name their rule id; the rest say
which convention holds them.

## Unrepresentable by API shape

### INV-1 — one sealing path

- **Claim.** Record protection is the only path that seals or opens
  bytes, and nonce and tag sizes cannot be wrong.
- **Mechanism.** `aead_seal`/`aead_open` take `nonce[12]` and a fixed
  16-byte tag by type; only `record.c` calls them.
- **Check.** Type system for the sizes; semgrep-structural (`inv-1-seal-only-in-record`)
  for the single-caller rule.
- **Violation.** A PR calls the AEAD directly from a new module "just
  for one message", bypassing sequence-number and length discipline.
- See [decisions: Cryptography](decisions.md#cryptography).

### INV-2 — zero heap, caller-owned memory

- **Claim.** The library never allocates. All state lives in the
  caller's `ch_tls` and record buffer; no OS facilities are assumed.
- **Mechanism.** Absence of any allocator call; the freestanding
  include set (no stdio.h, stdlib.h, time.h in library sources).
- **Check.** Semgrep-structural (`inv-2-no-allocator`, and
  `inv-2-freestanding` for the include set); lib-check catches an unexpected import.
- **Violation.** A PR includes stdlib.h for a "temporary" buffer or
  qsort, and the SRAM story silently stops being true.
- See [decisions: Memory and runtime](decisions.md#memory-and-runtime).

### INV-3 — the x25519 zero-check is the return value

- **Claim.** A key exchange landing on a small-order point (an
  all-zero shared secret) cannot be missed.
- **Mechanism.** `x25519()` returns 0 on an all-zero shared secret
  and 1 otherwise; the single call site in `handshake.c` fails the
  handshake unless it returns 1. Wycheproof's small-order battery
  exercises the rejection.
- **Check.** Structural arithmetic (the check is the return value,
  not a side channel of it); convention holds the call site to
  checking it.
- **Violation.** A PR adds a second x25519 call site that drops the
  return code.
- See [decisions: Cryptography](decisions.md#cryptography).

### INV-4 — randomness only through the hook

- **Claim.** All randomness flows through `ch_rand_bytes`, consumed
  at exactly two audited sites (key-share scalar, ClientHello
  random), both in `handshake.c`.
- **Mechanism.** The hook is the only randomness import; the library
  defines no fallback.
- **Check.** Semgrep-structural (`inv-4-randomness-sites`): no `ch_rand_bytes` call
  outside `handshake.c`.
- **Violation.** A PR conjures a nonce or padding bytes from a new
  call site nobody audits for seeding requirements.
- See [docs/entropy.md](entropy.md).

## Deleted by absence

### INV-5 — no ASN.1, no X.509

- **Claim.** The stack contains no certificate or ASN.1 parser.
  Pinned mode hashes the certificate into the transcript and never
  reads it.
- **Mechanism.** Absence. The one DER reader (`der_parse` in
  `p256.c`) reads exactly one ECDSA-Sig-Value, rejects non-minimal
  lengths, and parses nothing else.
- **Check.** Semgrep-tripwire (`inv-5-no-certificate-parsing`): the identifiers `asn1_`,
  `x509`, `der_parse` outside p256.c.
- **Violation.** A PR "just reads the SubjectPublicKeyInfo" and the
  largest historical TLS bug class walks in.
- See [decisions: Trust model](decisions.md#trust-model).

### INV-6 — no PKCS#1 v1.5

- **Claim.** RSA exists only as PSS verify. No v1.5 signature or
  encryption padding, ever.
- **Mechanism.** Absence; `rsa.c` implements EMSA-PSS decode only.
- **Check.** Semgrep-tripwire: the identifier `pkcs1`, in the shared
  `inv-5-no-certificate-parsing` rule.
- **Violation.** A PR adds v1.5 verify "for compatibility" with an
  old server, importing Bleichenbacher-shaped risk.
- See [decisions: Cryptography](decisions.md#cryptography).

### INV-7 — no negotiation

- **Claim.** One cipher suite, one group, one version, one signature
  algorithm per build. The client offers exactly one of everything;
  the server takes it or the handshake fails closed.
- **Mechanism.** Absence of selection code; the PIN build flag picks
  the sigalg at compile time, never at runtime.
- **Check.** Convention; hsstrict asserts the reject on any
  ServerHello that picks anything else.
- **Violation.** A PR accepts a second cipher suite value in
  ServerHello and downgrade surface exists again.
- See [decisions: Protocol surface](decisions.md#protocol-surface).

### INV-8 — no legacy protocol

- **Claim.** No TLS 1.2, no renegotiation, no compression, no 0-RTT.
- **Mechanism.** Absence; the supported_versions extension pins 1.3
  and the parser rejects everything else.
- **Check.** Convention plus hsstrict negative cases.
- **Violation.** A PR handles a 1.2 alert "gracefully" instead of
  failing closed.
- See [decisions: Protocol surface](decisions.md#protocol-surface).

### INV-9 — no padding sent

- **Claim.** chapulin never emits record padding; the padding strip
  on receive is the only padding code.
- **Mechanism.** Absence of a padding writer; `rec_seal` appends
  content type and tag only.
- **Check.** Convention; the RFC 8448 byte-identical replays would
  move on any added byte.
- **Violation.** A PR pads for traffic-analysis resistance and the
  SRAM and replay-vector numbers quietly change.
- See [decisions: Protocol surface](decisions.md#protocol-surface).

## Structural arithmetic

### INV-10 — nonce discipline

- **Claim.** Nonce = static IV xor sequence number; the counter is
  monotonic, wrap-guarded, reset only by rekey; KeyUpdate epochs are
  capped at 2^48−1.
- **Mechanism.** Structural arithmetic in `record.c`;
  `rec_dir_update` is the only reset; the epoch cap lives in
  `handle_key_update`.
- **Check.** CBMC (record and tlspost harnesses cover the guards);
  semgrep-structural (`inv-10-seq-reset-only-in-record`): no
  `.seq = 0` assignment outside record.c.
- **Violation.** A PR resets a sequence counter from the handshake
  layer to "fix" a desync, and a nonce repeats under one key.
- See [decisions: Cryptography](decisions.md#cryptography).

### INV-11 — transcript and secret schedule

- **Claim.** A message joins the transcript only after acceptance,
  and secrets snapshot at exactly the RFC-defined points.
- **Mechanism.** Structural: the hash update sits after the parse
  returns success; the key-schedule calls sit at fixed places in
  `run()`.
- **Check.** Structural arithmetic; the RFC 8448 replays pin the
  resulting secrets byte-for-byte.
- **Violation.** A PR hashes a message before validating it, and a
  rejected message influences derived keys.
- See [decisions: Assurance](decisions.md#assurance).

### INV-12 — TX and RX share no memory

- **Claim.** Send and receive directions share no buffers or key
  state.
- **Mechanism.** Structural: `rec_dir` is per-direction; `t->tx` and
  the receive buffer are distinct objects.
- **Check.** Structural arithmetic; CBMC's pointer checks would flag
  an aliased write in the harnessed paths.
- **Violation.** A PR reuses the receive buffer to build an outgoing
  message mid-handshake and a compaction step corrupts it.
- See [decisions: Memory and runtime](decisions.md#memory-and-runtime).

## Fail-closed

### INV-13 — no resumable errors

- **Claim.** Every error kills the session: alert, wipe, dead. There
  is no error a caller can retry past.
- **Mechanism.** Fail-closed policy; `tlsi_fail` is the single
  funnel.
- **Check.** Convention; hsseq's 354k-sequence run asserts no
  sequence revives a failed session.
- **Violation.** A PR returns a "soft" error that leaves keys live so
  the caller can retry a read.
- See [decisions: Engineering](decisions.md#engineering).

### INV-14 — the refusal set

- **Claim.** The client refuses: Certificate in PSK mode,
  CertificateRequest, psk_ke without DHE, a cookieless HRR, a second
  HRR, dual auth configs, and an even RSA pin.
- **Mechanism.** Fail-closed policy, each refusal an explicit branch
  with its alert.
- **Check.** hsstrict table cases per refusal; CBMC proves the
  branches memory-safe.
- **Violation.** A PR relaxes one refusal for interop with a broken
  server.
- See [decisions: Protocol surface](decisions.md#protocol-surface).

### INV-15 — CH_ASSERT survives release

- **Claim.** Programmer-error invariants stay armed in production;
  there is no NDEBUG build that strips them.
- **Mechanism.** `CH_ASSERT` never compiles away
  ([ch_assert.h](../ch_assert.h)); a device maps `ch_assert_fail` to
  its fault handler.
- **Check.** Convention; the HKDF Wycheproof skips demonstrate the
  asserts firing on out-of-domain input.
- **Violation.** A PR wraps CH_ASSERT in `#ifdef DEBUG` to save
  bytes.
- See [decisions: Engineering](decisions.md#engineering).

## Timing

### INV-16 — constant time where secrets flow

- **Claim.** No branch and no memory index depends on a secret.
  Comparisons on secret data go through `ct_memeq`, selects through
  branchless masks. Variable time is allowed only where every input
  is public, stated at the call site — P-256 and RSA verify, and the
  HRR-magic compare in hsparse.c.
- **Mechanism.** Constant-time construction; ChaCha20/Poly1305/x25519
  have no table lookups by design.
- **Check.** Semgrep-structural (`inv-16-no-variable-time-compare`) bans
  memcmp/strcmp in
  library sources, with hsparse.c allowlisted for its public-data
  compare; `make timing` (Welch's t-test) gives statistical evidence.
  Semgrep cannot know a buffer is secret — the real guards remain
  construction and the t-test.
- **Violation.** A PR compares a binder or tag with memcmp because
  the linker size looked better.
- See [decisions: Cryptography](decisions.md#cryptography).

## Lifetime and state

### INV-17 — secrets die at phase boundaries

- **Claim.** Handshake secrets are wiped at CONNECTED; every failure
  path wipes through `tlsi_wipe`; the DRBG erases its key forward
  after each output.
- **Mechanism.** Fail-closed policy plus fast-key-erasure
  construction in drbg.c.
- **Check.** Convention; the wipe sits in the single `tlsi_fail`
  funnel, so review of that one function covers every error path.
- **Violation.** A PR adds an early return between fail and wipe.
- See [decisions: Memory and runtime](decisions.md#memory-and-runtime).

### INV-18 — no library-global mutable state

- **Claim.** All state lives in the caller's `ch_tls`. The library
  object carries no top-level mutable variable, so sessions cannot
  interfere and the whole stack is reentrant per session.
- **Mechanism.** Structural; the reference DRBG (`drbg.c`) is the
  sole documented exception and ships outside the packaged library
  object.
- **Check.** Semgrep (`inv-18-no-global-mutable-state`): top-level non-const `static` in
  library sources, drbg.c allowlisted. It is exactly the check that
  would have flagged the DRBG's globals automatically. Graded
  between structural and tripwire: it is a column-anchored regex
  (clang-format puts file-scope declarations at column 0), because
  the C grammar parses const-qualified custom typedefs
  inconsistently. Function-scope statics are not caught; review
  holds that line.
- **Violation.** A PR caches "just one" precomputed table in a
  static and two sessions share fate.
- See [decisions: Memory and runtime](decisions.md#memory-and-runtime).

### INV-19 — bounded stack

- **Claim.** No VLAs, no recursion, and no function frame over the
  budget: 2,560 bytes (measured worst today: `rsa_vp1` at 2,400).
- **Mechanism.** Compiler-enforced: `-Wvla` in global CFLAGS bans
  variable frames everywhere, and `make lint-stack` compiles every
  library source under `-Wframe-larger-than=2560`, so the README's
  stack numbers are a compile-time contract, not a bench
  observation. Host test mains are exempt from the frame budget;
  they keep vector tables in their frames.
- **Check.** Type-system grade (the compiler refuses); bench/sram.sh
  measures the whole-call-chain peaks the README reports.
- **Violation.** A PR sizes a scratch buffer from a length field, or
  adds a frame that silently outgrows the smallest supported SRAM.
- See [decisions: Memory and runtime](decisions.md#memory-and-runtime).
