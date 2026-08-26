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
4. *Lean theorem* — proved over every input, unbounded, but of the
   `spec/` model rather than the C. It reaches the C only through the
   differential's agreement, so it ranks here: stronger than a
   syntactic rule about what the code says, weaker than CBMC about
   what the code does.
5. *semgrep-structural* — a call-graph or state rule; catches any
   syntactic violation, honest or not.
6. *semgrep-tripwire* — an identifier ban; catches honest drift, not a
   determined reintroduction under another name.
7. *convention + t-test* — code review holds the line; `make timing`
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
  and 1 otherwise. One call site compiles per build, both in
  `handshake.c`: the hybrid secret under `KEX=pq`, the classic key
  exchange otherwise. Each fails the handshake unless it returns 1.
  Wycheproof's small-order battery exercises the rejection.
- **Check.** Structural arithmetic (the check is the return value,
  not a side channel of it); convention holds the call site to
  checking it.
- **Violation.** A PR adds a second x25519 call site that drops the
  return code.
- See [decisions: Cryptography](decisions.md#cryptography).

### INV-4 — randomness only through the hook

- **Claim.** All randomness flows through `ch_rand_bytes`, consumed
  at exactly three audited sites, all in `handshake.c`: the
  key-share scalar, the ClientHello random, and the ML-KEM (d, z)
  seed, which only the `KEX=pq` build draws. Every draw carries the
  same all-zero check against a hook that writes nothing.
- **Mechanism.** The hook is the only randomness path into the library,
  and which side defines it is a declared build choice with no default.
  `RAND=extern` leaves it an undefined import, so an image that never
  wired a generator fails to link; `RAND=drbg` satisfies it with the
  reference generator in `drbg.c`, which faults on an unseeded draw.
  Neither build carries a fallback that quietly produces bytes.
- **Check.** Semgrep-structural (`inv-4-randomness-sites`): no `ch_rand_bytes` call
  outside `handshake.c`.
- **Violation.** A PR conjures a nonce or padding bytes from a new
  call site nobody audits for seeding requirements.
- See [docs/entropy.md](entropy.md).

## Deleted by absence

### INV-5 — one profiled certificate parser

- **Claim.** Exactly one certificate parser exists, and it accepts
  exactly the own-CA profile: X.509 v3, one or two CertificateEntry
  items with empty per-entry extensions — the leaf alone, or the
  leaf plus the one intermediate that signed it — anchored at the CA with
  the build's one algorithm, canonical DER on every decoded field,
  keyUsage and extendedKeyUsage required, no name matching, no
  clock. Any widening of that grammar is the violation, whether it
  lands inside the parser or beside it. Raw-pin builds compile none
  of it: they hash the certificate into the transcript and never
  read it.
- **Mechanism.** The length-first canonical-DER decoder in
  `x509_der.c` (definite lengths, minimal encodings, exact-fill of
  every container; rejection precedes interpretation) plus the
  pinned profile constants in `x509.c`, byte-compared, never
  matched loosely. The only DER reader outside the cert files
  (`der_parse` in `p256.c`) reads exactly one ECDSA-Sig-Value and
  parses nothing else.
- **Check.** Semgrep-tripwire (`inv-5-profiled-cert-parser`): calls
  to identifiers matching `x509_`, `asn1_`, or `der_` outside
  p256.c, x509.c, and x509_der.c. Grammar widening inside the cert
  files is held by the boundary-pair tests and review; the rule
  catches a second parser growing elsewhere.
- **Violation.** A PR accepts a second CertificateEntry, an
  absent-params AlgorithmIdentifier, or an unknown critical
  extension "for compatibility" — or "just reads the
  SubjectPublicKeyInfo" from a new module and the largest
  historical TLS bug class walks in unprofiled.
- See [decisions: Trust model](decisions.md#trust-model).

### INV-6 — no PKCS#1 v1.5

- **Claim.** RSA exists only as PSS verify. No v1.5 signature or
  encryption padding, ever — the certificate profile included.
- **Mechanism.** Absence; `rsa.c` implements EMSA-PSS decode only,
  and `x509.c`'s pinned signature AlgorithmIdentifier names
  RSASSA-PSS, so a v1.5-signed leaf fails the byte compare.
- **Check.** Semgrep-tripwire (`inv-6-no-pkcs1`): the identifier
  `pkcs1`, with no cert-file exemption.
- **Violation.** A PR adds v1.5 verify "for compatibility" with an
  old server, importing Bleichenbacher-shaped risk.
- See [decisions: Cryptography](decisions.md#cryptography).

### INV-20 — the certificate parser stays contained

- **Claim.** `x509_verify_leaf` is the parser's one public entry,
  called only from `handshake_auth.c`, and the library never reads a
  clock: certificate validity is CA reissuance policy, not a
  device-side time check.
- **Mechanism.** Single-entry design — the DER primitives sit
  behind the profile walker, and the walker sits behind one
  function. `x509_read_time` checks the Time shape and ignores the
  digits. `x509_read_time_epoch` does read them, but only as a
  counter to compare against stored state (INV-21); nothing
  compares a certificate to now, so no code path wants a clock.
- **Check.** Semgrep-structural (`inv-20-cert-entry-point`): no
  `x509_verify_leaf` call outside handshake_auth.c, with x509.c
  excluded as the definition site. Semgrep-tripwire
  (`inv-20-no-time-calls`): calls to `time`, `clock_gettime`,
  `gettimeofday`, `localtime`, or `gmtime` in library sources,
  complementing `inv-2-freestanding`'s time.h include ban at the
  call level; test/timing_test.c calls `clock_gettime` legitimately and
  sits in the standard excludes.
- **Violation.** A PR compares an epoch date against a device clock
  the firmware cannot trust — the epoch is an ordering, not a time —
  or calls the verifier from a new site that skips the handshake's
  alert and wipe discipline.
- See [decisions: Trust model](decisions.md#trust-model).

### INV-21 — the stored epoch only moves forward, and only for an authenticated server

- **Claim.** Under the epoch callbacks, `ch_tls.epoch` never
  decreases within or across sessions, and it changes only after a
  handshake authenticates the peer.
- **Mechanism.** Two functions, deliberately split. `epoch_check`
  runs on the chain verdict and only rejects — below the stored epoch is
  `ALERT_CERTIFICATE_REVOKED`, not an allowed date or past
  `CH_EPOCH_BOUND` is `ALERT_BAD_CERTIFICATE` —
  because a CA-signed certificate is public and proves nothing
  about who presented it. Both live in `handshake_auth.c`.
  `hsa_epoch_commit` performs the one
  assignment and the one store, and `run` calls it after
  `expect_finished`, so CertificateVerify and Finished have already
  proved a real server is there. `ch_connect` refuses an epoch that
  storage cannot supply or that is not an allowed epoch.
- **Check.** `CH_ASSERT` — `hsa_epoch_commit` faults unless
  `expect_finished` already set `server_finished_ok`, so a commit
  moved earlier aborts before it can write, on every CA handshake,
  whether or not the epoch callbacks are configured. It is a runtime
  abort, not a compile error: the misplaced call still builds.
  `test_epoch_cfg` covers the config gates and asserts nothing
  persists at connect time; the e2e `ca-epoch-*` legs move a real
  device forward, then replay the pre-bump leaf and the pre-bump
  ticket against it and require both to fail — they cover the replay
  direction, not the commit point; the x509der harness proves the
  reader's value stays in range, which is what keeps the stored epoch
  plus the bound inside uint32.
  Not covered: an author who moves the commit and moves or duplicates
  the `server_finished_ok = 1` alongside it defeats the assert, and
  nothing checks the monotonicity comparison itself — inverting
  `h->leaf.epoch <= t->epoch` leaves the assert silent, and only the
  e2e `ca-epoch-equal` leg objects.
- **Violation.** A PR moves the update back into `hsa_server_auth` for
  symmetry with the rejects, letting a replayed certificate advance
  a device's persistent state (`make test-invariants` runs this one,
  as `inv21-epoch-commit-in-server-auth`); or a build sets
  `CH_EPOCH_BOUND` outside the range the `_Static_assert` in cfg.h
  admits.
- See [decisions: Trust model](decisions.md#trust-model).

### INV-7 — no negotiation

- **Claim.** One cipher suite, one group, one version, one signature
  algorithm per build. The client offers exactly one of everything;
  the server takes it or the handshake fails closed.
- **Mechanism.** Absence of selection code; the PIN build flag picks
  the sigalg at compile time, never at runtime.
- **Check.** Convention; handshake_strict asserts the reject on any
  ServerHello that picks anything else.
- **Violation.** A PR accepts a second cipher suite value in
  ServerHello and downgrade surface exists again.
- See [decisions: Protocol surface](decisions.md#protocol-surface).

### INV-8 — no legacy protocol

- **Claim.** No TLS 1.2, no renegotiation, no compression, no 0-RTT.
- **Mechanism.** Absence; the supported_versions extension pins 1.3
  and the parser rejects everything else.
- **Check.** Convention plus handshake_strict negative cases.
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
- **Check.** CBMC (record and handshake_post harnesses cover the guards);
  Lean theorem (`Spec.Record.nonce_inj`): distinct sequence numbers
  below 2^64 give distinct nonces, so a repeat needs a repeated
  counter, not a colliding construction — the counter half stays with
  the mechanisms below; semgrep-structural
  (`inv-10-seq-reset-only-in-record`): no `.seq = 0` assignment
  outside record.c.
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
- **Check.** Convention; handshake_sequence's 466k-sequence run asserts no
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
- **Check.** handshake_strict table cases per refusal; CBMC proves the
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
- **Check.** Convention. The HKDF Wycheproof cases outside the
  asserted domain are excluded from the run precisely because the
  asserts would fault on them; the exclusion documents the boundary,
  it does not exercise the assert.
- **Violation.** A PR wraps CH_ASSERT in `#ifdef DEBUG` to save
  bytes.
- See [decisions: Engineering](decisions.md#engineering).

## Timing

### INV-16 — constant time where secrets flow

- **Claim.** No branch and no memory index depends on a secret.
  Comparisons on secret data go through `ct_memeq`, selects through
  branchless masks. Variable time is allowed only where every input
  is public, stated at the call site — P-256 and RSA verify, and the
  HRR-magic compare in handshake_parser.c.
- **Mechanism.** Constant-time construction; ChaCha20/Poly1305/x25519
  have no table lookups by design.
- **Check.** Semgrep-structural (`inv-16-no-variable-time-compare`) bans
  memcmp/strcmp in library sources, with handshake_parser.c allowlisted for its
  public-data compare — the allowlist is file-wide, so review holds the
  line on any new compare added to that file; `make timing` (Welch's
  t-test) gives statistical evidence.
  Semgrep cannot know a buffer is secret — the real guards remain
  construction and the t-test.
- **Violation.** A PR compares a binder or tag with memcmp because
  the linker size looked better.
- See [decisions: Cryptography](decisions.md#cryptography).

### INV-23 — no division in the ML-KEM module

- **Claim.** The ML-KEM sources contain no `/` and no `%` operator.
  Every modular reduction is a Barrett or Montgomery multiply-shift
  against a named constant, and every loop bound is a written-out
  literal.
- **Mechanism.** KyberSlash (2024) was a family of timing leaks from
  compilers emitting a division instruction on secret-derived values
  in Kyber's compression step; libraries that reduced by
  multiply-shift were unaffected. A rule on the operator is coarser
  than a rule on secrecy, and that is the point: semgrep cannot know
  which values are secret, so the module gives up the operators
  entirely and the question never comes up.
- **Check.** Semgrep-structural (`inv-23-no-division-in-mlkem`): any
  `/`, `%`, `/=`, or `%=` in an `mlkem*` source fails the lint.
- **Violation.** A PR compresses a coefficient with `x % MLKEM_Q`
  because it reads better than the Barrett sequence, and a target's
  divider leaks the coefficient through its cycle count.

### INV-22 — the server's flight arrives in one order

- **Claim.** The client accepts exactly the server message orders
  RFC 9846 §4 allows and no others: one ServerHello, one
  EncryptedExtensions, no certificate flight under PSK, Certificate
  then CertificateVerify then Finished when the server authenticates
  with a certificate, at most one HelloRetryRequest and only as the
  opening message, no ticket, key update, or application data before
  the Finished, and nothing after a close_notify. The order is the
  same whether the certificate is checked against a pinned server key
  (TRUST=raw) or a pinned CA (TRUST=ca).
- **Mechanism.** `handshake.c` reads the flight as a straight line —
  `hello_exchange`, then `hsa_server_auth`, then `expect_finished` — and
  each step compares the message type against the one it expects,
  answering `ALERT_UNEXPECTED_MESSAGE` otherwise. There is no state
  variable to desynchronize; the order is the call order. Every one of
  those type checks sits outside the `CH_TRUST_CA` conditionals, which
  only add chain verification between Certificate and
  CertificateVerify, so both trust builds compile the same order from
  the same lines.
- **Check.** Lean theorem (17 in `Spec/Handshake.lean`, over every
  trace the model admits; `accepts_decompose` bounds the flight at 4
  messages in the spec's `psk` Mode and 6 in its `pinned` Mode);
  `handshake_sequence_test`, exhaustive over 466,286 sequences — all eleven letters
  to depth 5, and the six handshake letters to depth 6 so the longest
  flight the model admits is reached — in both auth modes, comparing
  the real client's verdict against that model. It links TRUST=raw
  only, so the CA build's order rests on the shared lines named above
  plus the e2e run, not on the oracle; CBMC (`handshake` harness) for
  memory safety only, not for order.
- **Violation.** A PR relaxes one type check to tolerate a message a
  peer "usually" sends early, and a flight with a skipped
  CertificateVerify authenticates. This is the SMACK and FREAK class:
  invisible to memory-safety proofs and to a golden-path e2e run.
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
  build's budget: 2,560 bytes for every build except `KEX=pq`
  (measured worst there: `rsa_vp1` at 2,400), and 6,144 for `KEX=pq`
  (measured worst: `mlk_pke_encrypt` at 5,744). ML-KEM's own working
  memory sets that ceiling — K-PKE encrypt holds three polynomial
  vectors and two polynomials — but chapulin's hybrid plumbing clears
  2,560 as well: `ch_handshake` at 3,456 and `send_client_hello` at
  2,672, the latter holding the re-expanded decapsulation key. A
  device that cannot spare the budget builds the classic key
  exchange.
- **Mechanism.** Compiler-enforced: `-Wvla` in global CFLAGS bans
  variable frames everywhere, and `make lint-stack` compiles the
  sources this build packages, under the defines it packages them
  with, at `-Wframe-larger-than=$(STACK_BUDGET)`, so the README's
  stack numbers are a compile-time contract, not a bench
  observation. Until the hybrid build landed the recipe iterated
  `$(SRCS)` without `$(LIB_DEF)`, so it measured the default build
  whatever PIN, TRUST or KEX asked for and no variant was ever
  checked; the pq frames are what exposed it. Host test mains are
  exempt from the frame budget; they keep vector tables in their
  frames.
- **Check.** Type-system grade (the compiler refuses); bench/sram.sh
  measures the whole-call-chain peaks the README reports.
- **Violation.** A PR sizes a scratch buffer from a length field, or
  adds a frame that silently outgrows the smallest supported SRAM.
- See [decisions: Memory and runtime](decisions.md#memory-and-runtime).
