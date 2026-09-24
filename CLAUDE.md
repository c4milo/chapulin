# chapulin rules

chapulin is a TLS 1.3-only client for devices with a few kB of SRAM to
spare, named after El Chapulín Colorado: small, unassuming, protective.
Home: github.com/c4milo.

- C11, libc only. No third-party code, no OS assumptions beyond the
  caller-supplied I/O callbacks. The target is a bare-metal MCU or an
  lwIP-class socket stack.
- Zero heap. No malloc anywhere, ever — one static `ch_tls` session
  struct plus a caller-provided record buffer is the entire working set.
  bench/sram.sh measures the README's memory numbers; never estimate
  them, and re-measure when the code changes.
- One profile, no negotiation surface: TLS 1.3, TLS_CHACHA20_POLY1305_SHA256,
  one key-exchange group, and one of two auth modes — ECDHE-PSK
  (psk_dhe_ke) or a server key checked against CertificateVerify. The
  Makefile TRUST variable chooses how that server key is trusted, and
  where a key is pinned the same value names the algorithm that verifies
  it: TRUST=raw-rsa (default) and TRUST=raw-ecdsa pin the key itself,
  TRUST=ca-rsa and TRUST=ca-ecdsa pin a CA key the chain must reach, and
  TRUST=webpki verifies a public chain against caller-supplied anchors.
  The raw and ca modes are the device modes and read no clock and no
  names; webpki is the host-side mode, and it needs a clock, a hostname
  and a receive buffer far larger than a device carries. docs/webpki.md
  states its profile and what it does not check.
  The rsa half is RSA-PSS up to 3072 bits (`rsa.[ch]`) and the ecdsa half
  is ECDSA P-256 (-DCH_PIN_ECDSA, `p256.[ch]`) — never both in one raw or
  ca library object, though test binaries compile both so both stay
  tested. TRUST=webpki names no algorithm, and a public chain is why: the
  links of one chain are signed by different algorithm families, so that
  object carries `rsa.[ch]`, `rsa_pkcs1.[ch]`, `p256.[ch]` and
  `p384.[ch]` at once. A server object names none either, because
  ch_srv_check verifies both provisioned identities at boot. The
  algorithm is half of a TRUST value rather than an axis of its own
  precisely because it selects nothing in those two builds, and a
  separate axis let a build ask for a verifier it would not get. The key exchange is one group per
  build, chosen by the Makefile KEX variable: x25519 (default) or the
  X25519MLKEM768 hybrid (KEX=pq, -DCH_KEX_PQ, `mlkem.[ch]`) — never both
  in one raw or ca ClientHello, so a pq device and a classic-only server
  fail closed against each other. No X.509 parsing outside the certificate
  files: the canonical DER reader in x509_der.[ch], the profile verifier
  in x509.[ch] and the provisioning reader in x509_ca.[ch] under
  the ca modes, and the chain verifier in webpki.[ch] with its pieces under
  TRUST=webpki. x509_ca.[ch] reaches no verdict and no session reaches
  it (pinned mode hashes
  the certificate into the transcript, never reads it), no RFC 7250
  raw-public-key certificate types outside TRUST=webpki (below), no
  0-RTT, no compression, no renegotiation-era anything. Within a mode the client offers exactly one
  of everything; the server takes it or the handshake fails closed.
  TRUST=webpki breaks that rule five times. It offers several signature
  schemes, because it cannot know
  which family signed the chain the server will send, and it offers the
  list of ALPN protocols the caller configured, because it cannot know
  which one the endpoint speaks; the server picks one and
  ch_tls.alpn_selected reports it. docs/decisions.md 37 states what that
  negotiation surface costs. Under KEX=pq it also lists x25519 after the
  hybrid (CH_KEX_TWO_GROUPS) and sends the hybrid share alone, and a
  HelloRetryRequest naming x25519 moves it there; ch_cfg.require_pq
  drops x25519 from the hello and restores the fail-closed pairing
  (docs/decisions.md 39). Under SUITE=aesgcm it lists
  TLS_AES_128_GCM_SHA256 after ChaCha20 (CH_CLIENT_TWO_SUITES), keys
  every record direction with the suite the ServerHello selected, and
  ch_tls.suite reports it (docs/decisions.md 45); a raw or ca client
  refuses SUITE=aesgcm. With SPKI pins (ch_cfg.spki_pins, the SHA-256 of
  a DER SubjectPublicKeyInfo) it offers RFC 7250 raw public keys in
  server_certificate_type, beside X.509 when anchors are set too, and
  ch_tls.server_cert_type reports the server's choice: a raw key needs a
  pin that names it, and a chain beside pins needs a pin on the path it
  verified as well as the walk. Pins alone are a whole configuration, with
  no anchor, clock or hostname (docs/decisions.md 49).
- One concern per file pair, dependencies pointing down only:
  `ct.[ch]` (constant-time bytes) ← `sha256.[ch]` + `sha3.[ch]` +
  `sha512.[ch]`/`sha512_compress.[ch]` (SHA-384 and SHA-512; the
  TRUST=webpki build packages them, other builds keep them test-only) ←
  `mlkem.[ch]`/`mlkem_poly.[ch]` (ML-KEM-768; the KEX=pq build packages
  them with `sha3.[ch]`, other builds keep them test-only) ← `hkdf.[ch]`
  (HMAC + HKDF + TLS labels) ← `chacha20.[ch]` + `poly1305.[ch]` +
  `quic_aes.[ch]` with `quic_aes_key.h` (the `aes_public_key` type, whose
  body sits in the second header alone, and the two constructors that
  write one, TRANSPORT=quic; INV-26 names the three keys it may see) +
  `quic_aes_block.h` with one of `quic_aes_soft.c`, `quic_aes_hw.c` or
  `quic_aes_extern.c` (the AES-128 key expansion and forward cipher of
  FIPS 197, over plain bytes; the Makefile AES variable picks one)
  ← `aead.[ch]` (RFC 8439 seal/open) + `quic_gcm.[ch]`
  (AEAD_AES_128_GCM and GHASH, TRANSPORT=quic) with `quic_ghash_hw.[ch]`
  (GHASH's multiply and data loop on the carry-less multiply, AES=hw
  alone) ← `x25519.[ch]` + `p256.[ch]` +
  `rsa.[ch]`/`rsa_mont.c` (pinned-mode verify) + `p384.[ch]`/
  `p384_field.[ch]` + `rsa_pkcs1.[ch]` (the chain signatures a public
  CA writes, TRUST=webpki) ←
  `pem.[ch]` (RFC 7468 armour and RFC 4648 base64, decode only) +
  `x509_der.[ch]` (canonical DER, read by both certificate verifiers) +
  `x509.[ch]` (profiled certificate verify, the ca modes) +
  `webpki.[ch]` with `webpki_cert.c`, `webpki_ext.c`, `webpki_name.c`,
  `webpki_sigalg.c`, `webpki_spki.c` and `webpki_time.c` (chain verify
  against caller-supplied anchors, TRUST=webpki) + `webpki_ticket.[ch]`
  (the binding that holds a resumption ticket to the configuration that
  received it, TRUST=webpki) + `webpki_pin.[ch]` (SPKI pins and RFC 7250
  raw public keys, TRUST=webpki) + `webpki_cfg.[ch]` (the mode's ch_cfg
  declarations and the rules ch_connect checks, TRUST=webpki) ←
  `record.[ch]`
  (record layer) ← `handshake_parser.[ch]` (message parsers) ←
  `handshake_record.[ch]` (record reading and message reassembly) ←
  `handshake_auth.[ch]` (server authentication: the Certificate and
  CertificateVerify flight, the CA build's revocation epoch, and the
  webpki build's chain walk and hostname check) ←
  `handshake.[ch]` (client state machine) ←
  `handshake_post.[ch]` (NewSessionTicket and KeyUpdate, the messages
  that arrive after the handshake) ← `tls.[ch]`
  (public API) ← demo/test mains. Firmware takes everything below
  `tls.[ch]` as-is and supplies I/O callbacks and `ch_rand_bytes`.
  One pair sits off that chain rather than in it: `x509_ca.[ch]`
  (provisioning — one PEM certificate to the key bytes
  `ch_cfg.server_pubkey` takes) reads `pem.[ch]` and `x509.[ch]`, and
  no library source reads it. A CA-mode build exports its
  `ch_pubkey_from_pem` as a fifth public call, which firmware calls
  while provisioning and no session reaches.
- Everything that touches secret bytes is constant time: no secret-
  dependent branches, no secret-dependent memory indices. Comparisons go
  through `ct_memeq` and wipes through `ct_wipe`; constant-time selects,
  where needed, are branchless mask arithmetic inline (x25519's `cswap`,
  poly1305's final reduction), never an `if`. A core with no hardware
  multiplier turns `*` into a runtime-library call that branches on its
  operands, so `softmul.c` supplies constant-time `__mulsi3`/`__muldi3`
  under the compiler's own names; it compiles to nothing where the
  instruction exists. A multiplier that exists and is variable-time is
  the other half: `ct.h` builds widening products from 16x16 pieces
  unless the build asserts `CH_NATIVE_WIDEMUL`, which test binaries do
  and firmware does only with a vendor statement, and
  `lint-wide-multiply` holds the count at its recorded ceiling per
  file and compiler, and beside it the conditional-branch count of
  every arithmetic file, so a branch a compiler emits for a select
  shows as a count that grows.
  ChaCha20/Poly1305/x25519 are constant time by construction — keep them
  that way. AES is admitted for one purpose: the keys RFC 9001 fixes for
  QUIC Initial packets (§5.2), their header protection (§5.4.3) and the
  Retry integrity tag (§5.8). Every key those three use is public — it
  comes from a salt the RFC prints and a connection ID that travels in
  the clear, or the RFC prints the key itself — so a table lookup indexed
  by one leaks nothing an observer does not already hold. That is the
  whole reason the table is allowed at all: the public-key argument is
  what carries it, never a claim that the lookup is constant time. An
  AES=hw build has no table and no such trade, and an AES=extern build
  cannot state its timing at all, so the public-key argument is what
  carries every AES value and INV-26 bounds all three the same way. No key from
  the TLS key schedule is passed to AES outside a SUITE=aesgcm build, and
  that build takes AES=hw and states its timing (below).
  What holds that: `quic_aes.[ch]` and `quic_gcm.[ch]` take a key type,
  `aes_public_key`, whose body lives in `quic_aes_key.h` alone, so only
  `quic_aes.c`, `quic_initial.c` and `quic_retry.c` can build one. A file
  that names the incomplete type gets a compiler error; a file that
  spells the body itself gets none, because C diagnoses no mismatched
  struct definition across translation units, so `make lint-quic-surface`
  is what refuses that shape and the include that reaches the body
  however it is spelled. `ch_quic` stores no key: it keeps the
  Destination Connection ID and each packet call derives what it needs on
  its own stack. INV-26 states the rule and what review still owes, the
  Semgrep rule holds the calls, and `.violation` mutants prove each check
  fires. `quic_aes.c`, `quic_aes_soft.c`, `quic_aes_extern.c` and
  `quic_gcm.c` sit in `WIDEMUL_CEILING` and `BRANCH_SRCS`, so a compiler
  that lowers one of their masked selects to a branch shows as a count
  that grows; `quic_aes_hw.c` and `quic_ghash_hw.c` cannot join, because
  every spec targets a core with no AES or carry-less multiply
  instructions.
  The Makefile AES variable chooses the implementation the way TRUST
  chooses the pinned algorithm, and never two in one object: `soft` is
  this S-box, `hw` uses the compiler's own intrinsics under
  `__ARM_FEATURE_AES` or `__AES__`, and `extern` takes a caller-supplied
  `ch_aes_block`, the way `ch_rand_bytes` takes entropy, so a vendor AES
  peripheral needs no code here. `hw` also moves GHASH off `quic_gcm.c`'s
  portable multiply onto the carry-less multiply, in `quic_ghash_hw.c`:
  PMULL under `__ARM_FEATURE_AES`, which the Arm C Language Extensions
  put in the AES extension, and PCLMULQDQ under `__PCLMUL__`, which
  x86-64 turns on with `-mpclmul` beside `-maes`. Those macros are the
  whole detection, and the choice is the compiler's at build time:
  nothing here probes a CPU and nothing asks an operating system. An
  arm64 core cannot answer the question itself — reading
  ID_AA64ISAR0_EL1 from EL0 takes SIGILL — so runtime detection means
  per-OS code this tree cannot carry and which the bare-metal m3 and
  freertos lanes have nobody to ask. A consumer compiles chapulin into
  its own build, so it already chooses `-march=armv8-a+crypto` or
  `-maes -mpclmul`; a build without the flags takes AES=soft and stays
  correct, and AES=hw without the instructions is an #error rather than
  a silent fall back. CBMC cannot read an intrinsic, so the proofs stay
  on the software path and AES=hw is held to it by
  `test/aes_equiv_test.c` and `test/ghash_equiv_test.c`, by the published
  vectors in `bin/quic_test_hw`, by the Wycheproof AES-GCM suite on that
  leg and by the AES=hw differential, `bin/diff_quic_hw`. docs/quic.md,
  "What the AES axis proves", states what each value rests on and what
  none of it proves.
  A secret-key AES suite needs the instructions and needs somebody to
  say they are constant time — TLS_AES_128_GCM_SHA256, which strict RFC
  9846 §9.1 server conformance asks for. The AES axis does not enable
  it: only a SUITE=aesgcm build carries it, and INV-26 admits its one
  traffic key there beside the three public keys. `ct.h` is where the
  terms are written, beside the same rule for the widening multiply.
  A build says it carries such a suite with `-DCH_SUITE_AES_GCM`, and
  that build is a compile error unless it also takes AES=hw and defines
  `CH_NATIVE_AES`. The second is the build's assertion that this part's
  AES instructions and its carry-less multiply run in constant time, the
  way `CH_NATIVE_WIDEMUL` asserts the widening multiply:
  `__ARM_FEATURE_AES`, `__AES__` and `__PCLMUL__` say the instructions
  exist and say nothing about their latency, so firmware defines it only
  with a vendor statement that covers both. One define carries both
  because AES-GCM needs both under one key (docs/decisions.md 50). The
  record layer, the server's selection and the webpki client's offer run
  it under those terms, and a QUIC build refuses it, because QUIC packet
  protection here runs ChaCha20 alone.
- Proofs are mandatory, not optional, but they run in `check-slow`
  rather than `check`: `check` holds a one-minute budget so it stays
  usable as the inner loop, and the fast proof tier alone costs
  thirty minutes. A change is not finished until `check-slow` passes,
  and the nightly runs it. Every module carries a
  CBMC harness in `proof/` proving memory safety and absence of UB
  (bounds, pointer validity, arithmetic overflow, division) over
  unconstrained inputs at the module's real bound. Crypto primitives
  additionally prove functional equivalence to a tiny reference spec at
  bounded sizes, plus RFC test vectors in `test/unit_test.c`. The README's
  verification section states exactly what is proved, at what bounds, and
  what is only tested — never overclaim.
- Write harnesses by docs/proofs.md. The rules that keep formulas
  solvable: SAT cost tracks the multiply count per formula, so split
  along it; store nondet values through the object's own type, never a
  byte-pointer fill of a typed object; havoc every operand freshly
  before every call; cover the aliasing shapes real callers use; and
  measure each launch line with `/usr/bin/time -v` under run.sh's exact
  flags before committing it — a launch line whose formula has not been
  seen to converge proves nothing.
- A crypto or protocol change touches three surfaces, not one. When you
  change behavior in a C module, update in the same commit: (1) the code,
  (2) its Lean spec in `spec/lean/` if the change alters what the spec models
  or its stated domain, and (3) the tests — unit vectors, the differential
  driver in `test/diff_test.c` (keep its input domain inside what both C and
  spec agree on), and the CBMC harness if the contract moved. A fix that
  the spec and oracle do not know about is a divergence the differential
  run cannot catch. Boundary changes get an exact boundary test (the last
  valid value works, the first invalid one fails). When a mutation
  experiment shows a rule no test guards, land the mutant as a
  `.violation` file in `test/violations/` — the framework for this
  exists; never propose a new one. `test/violations.py` applies the
  edit, rebuilds, and requires the named target to fail, and an edit
  whose old text no longer matches fails as stale instead of passing
  silently.
- All parsing goes through the bounds-checked `rbuf` reader and all output
  bytes through the `wbuf` writer; no raw buffer arithmetic outside them.
  Never assume host endianness; emit and read multi-byte values
  byte-by-byte.
- Operational errors (bad peer input, short buffers, I/O failure) return
  `ch_err` codes and fail closed — alert, wipe keys, dead session.
  `CH_ASSERT` is for programmer-error invariants only, seeded at contract
  points, never in per-byte paths.
- Record size discipline: the client always sends `record_size_limit`
  (RFC 8449) sized to the caller's buffer. A peer record over the limit is
  a protocol error, not a resize.
- RFC MUSTs we keep even though this is minimal, per role. A client:
  HelloRetryRequest handling, KeyUpdate receipt, NewSessionTicket
  parse-and-expose (resumption is just another PSK here), RFC 9257
  binder discipline. A server: HelloRetryRequest generation under an
  integrity-protected cookie, the dummy change_cipher_spec a client's
  non-empty session id obliges, KeyUpdate receipt, and a binder checked
  in constant time over the truncated ClientHello before it accepts one
  of its own tickets (docs/server.md, "Resumption").
- Write all prose — README, docs, comments, commit messages — in active
  voice with plain words, following Google's Technical Writing One and
  Two: short sentences with one idea each, terms defined before use,
  lists for list-like content, strong verbs, no rhetorical flourishes or
  metaphors.
- Name what literally happens. The failure mode is a vague spatial
  metaphor standing in for a plain verb: a value "reaches" storage
  instead of being written, a change is "folded in" instead of added, a
  boundary becomes a "seam" instead of the constant it is. Before an
  abstract word, ask what literally happens and write that. Literal uses
  stay — a device really cannot reach a server. This matters most in
  comments, where an auditor cannot check the metaphor against anything.
- One name per thing, and it is the name in the code. Never invent prose
  shorthand for something a field or constant already names: write "the
  stored epoch" for `ch_tls.epoch`, never "the mark". A second name
  makes the reader hold a glossary the compiler cannot check, and it
  rots as soon as the field is renamed. When two related values need
  telling apart, take both names from the code (`epoch` and
  `epoch_seen`), not from a metaphor.
- Every GitHub issue reference carries its full URL
  (`https://github.com/c4milo/chapulin/issues/53`), never the bare
  hash-and-number form. A reader holding only the source tree cannot
  resolve a bare number. Markdown may keep the short form as the link
  label; C, shell and Makefile comments spell the URL out. `make
  lint-issue-links` enforces this, and it reads this file too, so the
  rule is stated without an example of what it forbids.
- Dev tooling lives in `tools/`, never at the repo root: the lint helper
  scripts and the node packages commitlint needs. `tools/` is not built
  into the library. Shell scripts stay with the thing they operate on
  (`bench/`, `proof/`, `test/`), because that is where a reader looks for
  them. `make lint-shellcheck` runs shellcheck over every one of them,
  including the git hooks.
- Linters follow fix-or-drop: fix the finding, or disable the check in
  `.clang-tidy` with its reason. Never `NOLINT` in code.
- CI pins the same tool versions the development machine runs. Every
  version lives in `tools/toolchain.env`, which the Makefile includes and
  the workflows load through `.github/actions/load-pins`, so one line
  moves both. `make lint-pins` fails if a
  workflow hardcodes a version that file already carries, if a job reads
  a pin without loading it, or if a script or step downloads a pinned
  file and no hash check follows, and `make lint-toolchain` fails if the resolved
  checker is not the pinned one. Never adapt code or suppressions to an
  older checker: a bump is work to do, which is why
  .github/workflows/toolchain-pins.yml opens a pull request and never
  merges it.
- CI compiles with gcc on purpose, even though development machines run
  clang: chapulin's consumers are firmware trees whose vendor SDKs ship
  gcc cross-compilers, so gcc-only diagnostics belong in CI, not in a
  consumer's build. Between local clang and CI gcc, both major compiler
  families stay covered without a second CI leg. Do not switch CI to
  clang for convenience.
- Commits are Conventional Commits (feat/fix/docs/test/refactor/perf/
  build/ci/chore), enforced by commitlint via `.githooks/commit-msg`
  (`make hooks` once after clone) and `make lint-commits` in check.
  Bodies stay short: at most three short paragraphs and about 80 words,
  wrapped at 100 columns. The diff shows the what, so never restate it.
  Use plain English and the voice of one engineer telling another why
  the change exists. Reasoning that outlives the commit belongs in
  `docs/`, not the body: state the why in a sentence and name the
  document. Write the body from the diff; never trim a long draft down,
  because editing anchors on the draft and lands long every time.
- Every change passes `make check` (lint, unit, strict-parser and
  Wycheproof vectors, the packaged-object export list) before it is
  committed, and `make check-slow` (proofs, e2e against a real TLS 1.3
  server, the spec differential, the sequence enumerations, the invariant
  violation builds) before it is called done. Neither is optional; they
  are split by duration, so `check` answers in about a minute and
  `check-slow` runs in the nightly.
- The code optimizes for third-party audit: when compact and
  auditable conflict, auditable wins. A predicate-named function is
  pure; state changes get their own line. Prefer a byte-compare
  against a named constant over decode-and-judge. The naming,
  complexity, and prose rules below all serve this.
- Functions stay at cognitive complexity 15 or less; hand-written files
  under 500 lines. `spec/` is exempt from the line count: both limits
  serve third-party audit of the C, and in a proof file the audited
  unit is the theorem statement, not the tactic script under it — Lean's
  kernel checks that. Judge a spec module by whether each statement
  reads in a few lines and carries no hypothesis it does not need; a
  long proof of a short statement costs an auditor nothing.
  spec/lean/CONTRACT.md is the styleguide for writing in spec/ — follow its
  "Writing proofs here" section, including the second pass that
  shrinks a green proof's script with the statement frozen.
- Names spell words out. Module prefixes stay short — they are C's
  namespaces (`ch_`, `ks_`, `rec_`, `rb_`/`wb_`, `hsp_`, `ct_`) — but
  the stem after the prefix is real words: `parse_server_hello`, not
  `parse_sh`; `record_len`, not `recn`. No vowel-dropping, no ad-hoc
  abbreviation. Domain vocabulary the RFCs themselves use stays as the
  RFCs spell it (`pt`, `aad`, `iv`, `psk`, `hrr`, `verify_data`,
  `obfuscated_age`). One-letter names only for loop indices; `rc` for
  return codes is C idiom and stays. `_len` always counts
  bytes — the API's one length unit, never elements or bits. No
  quantity crosses the API in two units. When counts coexist,
  each names what it counts (`ext_count`); an operation's sole byte
  count may stay the idiomatic `n`.
- `chapulin.hpp` is an optional, header-only C++ wrapper: freestanding
  (only <cstddef>/<cstdint>), -fno-exceptions -fno-rtti, zero heap, no
  runtime cost over the C calls. It never gains logic the C core lacks —
  it forwards to the C API and adds only RAII cleanup, byte views, and
  typed results. `make cxx-check` compiles it against the packaged
  library object as part of check.
