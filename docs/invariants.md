# Security invariants

[docs/decisions.md](decisions.md) answers "why is it built this way".
This document answers "what must a change never break", and
[.semgrep/invariants.yml](../.semgrep/invariants.yml) makes part of
the answer executable: `make lint-invariants` fails CI when a change
breaks a machine-checkable entry.

A rule checks only what Semgrep parsed. Semgrep reports a file it
cannot parse as a warning and exits 0, so `lint-invariants` reads the
scan's JSON with `tools/semgrep-parse.py` and fails when a file did not
parse. Seven files parse only in part: an `#ifdef` inside a parameter
list, or a function's closing brace inside one `#if` arm, makes Semgrep
skip a few lines. The script's `PARTIAL` list names each file and its
construct. A call on a skipped line passes every rule, and a partial
parse of any file the list does not name fails.

Each entry has four fields. **Claim** is the invariant. **Mechanism**
is what enforces it. **Check** is what guards it, graded honestly on
this scale, strongest first:

1. *type system* — a violation does not compile.
2. *structural arithmetic* — the property holds by construction; there
   is no code path that could break it without rewriting the
   construction.
3. *CBMC* — proved over all inputs at the harness's documented bound.
4. *Lean theorem* — proved over every input, unbounded, but of the
   `spec/lean/` model rather than the C. It reaches the C only through the
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

An entry that names a temporary state goes when that state does, and its
number is never reused. INV-28, "a stub never reports success", was the
one such entry. It held the `TRANSPORT=quic-nonblocking` and then the `ROLE=server`
stubs to refusals, and it retired with the commit that implemented the
last `ROLE=server` stub, as the entry said it would.

## Unrepresentable by API shape

### INV-1 — one sealing path

- **Claim.** Record protection is the only path that seals or opens
  bytes, and nonce and tag sizes cannot be wrong. Two named callers sit
  beside it, each with a nonce rule of its own: `quic_packet.c`, which
  protects a QUIC packet where there is no record layer, and
  `srv_ticket.c`, which seals a server's resumption ticket under the
  ticket key with a random 96-bit nonce drawn for that ticket alone
  (`srv_ticket.h` states when the key must rotate).
- **Mechanism.** `aead_seal`/`aead_open` take `nonce[12]` and a fixed
  16-byte tag by type; only `record.c`, `quic_packet.c` and
  `srv_ticket.c` call them.
- **Check.** Type system for the sizes; semgrep-structural (`inv-1-seal-only-in-record`)
  for the named-caller rule.
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
  all-zero shared secret) cannot be missed, and neither can a P-256
  point that is not on the curve.
- **Mechanism.** `x25519()` returns 0 on an all-zero shared secret
  and 1 otherwise. One call site compiles per raw or ca build, in
  `handshake_flight.c`: the hybrid secret under `KEX=pq`, the classic
  key exchange otherwise. A `TRUST=webpki` build compiles two, the
  hybrid secret in `handshake_flight.c` and the x25519 one in
  `handshake_groups.c`, one per x25519-bearing group its ServerHello may
  select. A server role compiles one, in `srv_kex.c`'s `srv_kex_secret`,
  which runs for either group it selects: against the client's x25519
  share, or against the x25519 value that ends the client's hybrid share.
  Each fails the handshake unless it returns 1, and the server's refusal
  wipes all 64 bytes of the input keying material, which the `srv_kex`
  harness proves.
  Wycheproof's small-order battery exercises the rejection. The clamp
  and the check sit in `x25519.c` for both X25519 fields:
  `x25519_wide.c` computes the ladder over a scalar `x25519.c` has
  clamped and reports nothing, and `bin/x25519_equiv_test` requires both
  fields to return 0 on every low-order point.
  secp256r1 has the same shape (docs/decisions.md 63). `p256_ecdh()`
  returns 0, with its 32 output bytes zero, for a peer point whose form
  byte is not 0x04, whose coordinates are not below p, or which is not
  on the curve, the checks RFC 9846 §4.3.8.2 requires
  (rfc9846.txt:2277-2286); the point at infinity has no 65-byte encoding.
  Two call sites compile, one per role: `handshake_groups.c`'s
  `p256_secret` on a webpki client and `srv_kex_secret` on a server, and
  each fails the handshake with illegal_parameter unless it returns 1. A
  server also checks the client's point with `p256_ecdh_point_valid` in
  `srv_kex_share`, before its ServerHello and before it draws a key.
  Wycheproof's `ecdh_secp256r1` suite exercises the arithmetic's
  refusals.
- **Check.** Structural arithmetic (the check is the return value,
  not a side channel of it); convention holds the call site to
  checking it. The `handshake_groups` and `srv_kex` harnesses prove a
  refused P-256 exchange leaves no byte of the secret.
  `inv03-client-p256-point-unchecked` drops the client's verdict and
  `bin/webpki_session_test` fails; `inv03-srv-p256-point-unchecked`
  drops the server's early check and `bin/srv_flight_test` fails.
- **Violation.** A PR adds a second x25519 call site that drops the
  return code, or a P-256 call site that computes over a point it did not
  check.
- See [decisions: Cryptography](decisions.md#cryptography).

### INV-4 — randomness only through the hook

- **Claim.** The library takes every random byte from `ch_rand_bytes`.
  It calls the hook at exactly ten sites in six files. A client draws at
  four of them:
  - `hsf_begin` in `handshake_flight.c` draws the x25519 key-share
    scalar and the ClientHello random, and in the `KEX=pq` and
    `TRUST=webpki` builds the ML-KEM (d, z) seed: three calls.
    `ch_connect`, `ch_record_init` and `ch_quic_init` call it.
  - `draw_p256_key` in `handshake_groups.c` draws the `TRUST=webpki`
    client's P-256 scalar, only when a HelloRetryRequest names
    secp256r1 (decisions.md 63).

  A server draws at the other six:
  - `srv_begin` in `srv_flight.c` draws the x25519 key-share scalar.
    `ch_srv_accept`, `ch_srv_record_init` and `ch_srv_quic_init` call
    it.
  - `srv_send_server_hello` in `srv_flight.c` draws the ServerHello
    random. These two sites draw the values `hsf_begin` draws for a
    client, for the same reasons, so they take the same audit.
  - `encapsulate` in `srv_kex.c` draws the 32 bytes of ML-KEM
    encapsulation randomness, only when the server selects
    X25519MLKEM768, and wipes them once the encapsulation has run
    (decisions.md 54). A client never draws these bytes, because a
    client decapsulates.
  - `p256_share` in `srv_kex.c` draws the P-256 scalar, only when the
    server selects secp256r1 (decisions.md 63).
  - `srv_send_new_session_ticket` in `srv_resume.c` draws 24 bytes in
    one call per ticket: the ticket's AEAD nonce, its `ticket_age_add`
    and its `ticket_nonce`. It draws only when the caller set
    `cfg.srv.ticket_key` and `cfg.srv.now_seconds`.
  - `emsa_pss_encode` in `rsa_sign.c` draws the 32-byte RSA-PSS salt
    each time `rsa_pss_sign` signs with the server's RSA identity.
    `ch_srv_check` signs once at boot when that identity is
    provisioned, and `srv_sign_certificate_verify` signs once per
    handshake whose CertificateVerify uses rsa_pss_rsae_sha256.
    `p256_sign.c` draws nothing: it derives each ECDSA nonce from the
    key and the message by RFC 6979.

  Every site checks for a hook that returns without writing: CH_ASSERT
  fires when the drawn bytes are all zero. The two
  P-256 sites check a range instead. They draw again when a candidate
  falls outside [1, n-1], zero included, up to `P256_ECDH_DRAWS` times,
  and CH_ASSERT fires after the last one. A working generator fails
  that many draws with probability below 2^-128.
- **Mechanism.** `ch_rand_bytes` is the library's only source of random
  bytes, and which side defines it is a declared build choice with no
  default. `RAND=extern` leaves it an undefined import, so an image that
  defines no generator fails to link. `RAND=drbg` defines it with the
  reference generator in `drbg.c`, which faults on an unseeded draw.
  Its `ch_drbg_seed` takes the SHA-256 of the whole seed as the
  generator key, so every source the image concatenates into the seed
  counts, and faults on a seed shorter than `CH_DRBG_SEED_MIN`, 32
  bytes (decisions.md 66). Neither build carries a fallback that
  quietly produces bytes. The
  `ROLE` and `TRUST` axes choose which of the six files a packaged
  object compiles:
  - `ROLE=client` compiles `handshake_flight.c`, and `TRUST=webpki`
    adds `handshake_groups.c`.
  - `ROLE=server` compiles `srv_flight.c`, `srv_kex.c`, `srv_resume.c`
    and `rsa_sign.c` on every transport.
  - `ROLE=both` compiles both sets.
- **Check.** Semgrep-structural, in two rules.
  `inv-4-randomness-files` refuses a `ch_rand_bytes` call in any file
  other than `handshake_flight.c`, `handshake_groups.c`, `srv_flight.c`,
  `srv_kex.c`, `srv_resume.c` and `rsa_sign.c`. It excludes `drbg.c`
  because that file defines the hook. `inv-4-randomness-calls` reads
  only those six files and refuses a call outside the eight functions
  the claim names, a fourth call in `hsf_begin`, and a second call in
  any of the other seven. It counts a call in a branch, a loop or a
  block the same as one at the top of the function.
  `test/lint-invariants.sh` fails on each of four violations:
  - `inv04-draw-in-handshake-post` adds a call to `handshake_post.c`.
  - `inv04-draw-in-srv` adds a call to `srv.c`.
  - `inv04-second-draw-in-srv-flight` adds a second call to
    `srv_send_server_hello`.
  - `inv04-fourth-draw-in-hsf-begin` adds a fourth call to `hsf_begin`.

  `lib-check` requires a `RAND=extern` object to import `ch_rand_bytes`
  and a `RAND=drbg` object to define and export it, and links
  `test/entropy_recipe.c`, docs/entropy.md's boot-seed recipe, against
  the `RAND=drbg` object. `bin/drbg_test` checks the output of two
  seeds against known answers computed outside this tree, and the floor
  at exactly 32 bytes and 31. It fails on each of three violations:
  - `inv04-drbg-seed-copied` copies the first 32 seed bytes into the
    key instead of hashing the seed.
  - `inv04-drbg-seed-floor-lowered` takes a 31-byte seed.
  - `inv04-drbg-seed-floor-raised` refuses a 32-byte seed.
- **Violation.** A PR conjures a nonce or padding bytes from a new
  call site nobody audits for seeding requirements, or keys the
  generator from part of the seed.
- See [docs/entropy.md](entropy.md).

## Deleted by absence

### INV-5 — one certificate verifier, one provisioning reader

- **Claim.** Exactly one certificate *verifier* exists, and it accepts
  exactly the own-CA profile: X.509 v3, one or two CertificateEntry
  items with empty per-entry extensions — the leaf alone, or the
  leaf plus the one intermediate that signed it — anchored at the CA with
  the build's one algorithm, canonical DER on every decoded field,
  keyUsage and extendedKeyUsage required, no name matching, no
  clock. Any widening of that grammar is the violation, whether it
  lands inside the verifier or beside it. One other module reads
  certificate DER: the provisioning reader in `x509_ca.c`, which
  reaches no verdict — it returns key bytes, never a decision — leaves
  the certificate's signature, dates and names unread, and is
  unreachable from any path peer input takes. Raw-pin builds compile
  neither: they hash the certificate into the transcript and never
  read it. The `TRUST=webpki` chain verifier ([webpki.md](webpki.md))
  is a second verifier with its own public profile: `webpki_time.c`
  reads validity dates, `webpki_name.c` matches hostnames against
  subjectAltName, `webpki_spki.c` reads a public key and
  `webpki_sigalg.c` a signature algorithm, the last two by byte compare
  against the canonical encodings the mode admits. `webpki_cert.c` reads
  one certificate's fields and hands each to its reader, and
  `webpki_ext.c` reads its extensions: it decodes keyUsage,
  extendedKeyUsage and basicConstraints, records subjectAltName, and
  refuses every other critical extension. `webpki.c` is the walk over
  them: it frames the CertificateEntry list, checks the leaf's clock and
  hostname, and walks issuers until an anchor both names the issuer and
  verifies the signature. It is the mode's one entry point for a chain
  the anchors judge, the way `x509_verify_leaf` is the ca mode's. A
  configuration of SPKI pins alone judges a chain by its leaf's key
  (docs/decisions.md 65): `webpki_pin.c` frames the list through
  `webpki_read_leaf_entry` and reads the leaf through
  `webpki_read_certificate_key`, which is `webpki_cert.c`'s own field
  readers stopped after subjectPublicKeyInfo. It reads the same grammar,
  no further, and adds no reader. The raw and ca
  objects filter these files out, and `lint-trust-separation` checks
  that.
- **Mechanism.** The length-first canonical-DER decoder in
  `x509_der.c` (definite lengths, minimal encodings, exact-fill of
  every container; rejection precedes interpretation) plus pinned
  profile constants, byte-compared, never matched loosely: the
  verifier's in `x509.c`, the reader's in `x509_ca.c` (version,
  basicConstraints and keyUsage object identifiers, `cA` TRUE). The
  reader's containment is a fact about includes: `x509_ca.h` and
  `pem.h` are included by no library source except `x509_ca.c`
  itself, so no session reaches it. The `TRUST=webpki` chain
  verifier reads the same DER through the same primitives in its
  `webpki_*.c` files ([webpki.md](webpki.md)), and only that mode's
  object will package them. The only other DER readers (the `der_parse`
  in `p256.c` and the one in `p384.c`) each read exactly one
  ECDSA-Sig-Value and parse nothing else.
- **Check.** Semgrep-tripwire (`inv-5-profiled-cert-parser`): calls
  to identifiers that begin with `x509_`, `asn1_` or `der_`, or carry
  one of the three right after an underscore, outside
  p256.c, p384.c, x509.c, x509_der.c, x509_ca.c, webpki.h,
  webpki_time.c, webpki_name.c, webpki_spki.c, webpki_sigalg.c,
  webpki_ext.c and webpki_cert.c. The rule reads a name component
  rather than a substring, because `quic_header_protect` ends "header"
  in the letters the DER prefix spells and is no parser;
  .semgrep/invariants.c holds that case as an `ok:` line.
  Semgrep-structural
  (`inv-20-provisioning-entry`) holds the containment half. Grammar
  widening inside those files is held by the boundary-pair tests in
  test/x509_ca_tests.h, test/webpki_spki_test.c,
  test/webpki_cert_mutants.h and test/webpki_ext_mutants.h, by the off-curve
  keys in test/webpki_sigalg_test.c, and by review, as x509.c's always
  has been; the tripwire catches a reader growing outside them. Which
  object packages which reader is held by `make lint-trust-separation`:
  the raw and ca objects carry no `webpki_*.c` file and the webpki
  object carries no `pem.c`, `x509.c` or `x509_ca.c`, with the webpki
  file list read from git rather than from the Makefile's own filter
  (`inv05-webpki-source-in-raw`), and every root `webpki*.c` file git
  tracks must appear in `WEBPKI_SRCS` (`inv05-webpki-source-unlisted`).
  inv05-webpki-leaf-key-reads-extensions makes the pins-alone key reader
  parse the whole TBSCertificate, and the webpki_cert_key harness, which
  asserts the extensions reader never runs there, objects.
  Two of the rows where the webpki profile is stricter than openssl
  ([webpki.md](webpki.md)) have their own guards over the corpus:
  `inv05-webpki-sha1-signature` admits sha1WithRSAEncryption and
  `inv05-webpki-rsa-1024-modulus` lowers the modulus floor, and
  bin/webpki_chain_test's `sha1_signature` and `rsa_1024_leaf` rows
  object to each.
- **Violation.** A PR accepts a second CertificateEntry, an
  absent-params AlgorithmIdentifier, or an unknown critical
  extension "for compatibility" — or a library source calls
  `ch_pubkey_from_pem`, putting the provisioning reader on a path
  peer input can reach, or the reader grows a verdict instead of
  returning bytes.
- See [decisions: Trust model](decisions.md#trust-model).

### INV-6 — PKCS#1 v1.5 as verify only, in rsa_pkcs1.c and its one caller

- **Claim.** The device modes see RSA as PSS verify only: no v1.5
  signature or encryption padding, the certificate profile included.
  PKCS#1 v1.5 signature verify exists in one file, `rsa_pkcs1.c`,
  because the captured AWS and GCS chains are signed with it
  ([webpki.md](webpki.md)). Its one caller is `webpki_sigalg.c`, which
  calls it for a certificate signed with `sha256WithRSAEncryption` or
  `sha384WithRSAEncryption`. Neither the raw nor the ca object packages
  either file; the `TRUST=webpki` object is the one that does. No
  v1.5 encryption padding exists anywhere.
- **Mechanism.** `rsa.c` implements EMSA-PSS decode only, and
  `x509.c`'s pinned signature AlgorithmIdentifier names RSASSA-PSS,
  so a v1.5-signed leaf fails the byte compare in the ca mode.
  `rsa_pkcs1.c` verifies by building the expected encoded message
  and comparing every one of its `n_len` bytes with `ct_memeq`; it
  never parses the padding it receives, which is the step a lax
  verifier gets wrong.
- **Check.** Semgrep-tripwire (`inv-6-no-pkcs1`): the identifier
  `pkcs1` outside `rsa_pkcs1.c` and `webpki_sigalg.c`, with no
  exemption for the device modes' cert files. The webpki ClientHello
  offers `rsa_pkcs1_sha256` and `rsa_pkcs1_sha384` for certificate
  signatures, and `hsp_parse_certificate_verify` refuses both in
  CertificateVerify, as RFC 9846 §4.3.3 requires;
  bin/handshake_strict_webpki's rows hold that refusal
  (`inv06-certificate-verify-pkcs1`).
- **Violation.** A PR adds v1.5 verify to `rsa.c` or to the ca-mode
  profile "for compatibility" with an old server, or adds v1.5
  decryption anywhere, importing Bleichenbacher-shaped risk.
- See [decisions: Cryptography](decisions.md#cryptography).

### INV-20 — the certificate parser stays contained

- **Claim.** `x509_verify_leaf` is the one entry the handshake
  reaches, called only from `handshake_auth.c`. A CA-mode build
  exports a second entry, `ch_pubkey_from_pem`, which firmware calls
  while provisioning and no library source calls at all. Either way
  the library never reads a clock: certificate validity is CA
  reissuance policy, not a device-side time check.
- **Mechanism.** Two entries, each contained by a different fact.
  The DER primitives sit behind the profile walker and the walker
  sits behind one function, which only `handshake_auth.c` calls. The
  TRUST=webpki leaf rule under SPKI pins alone is contained the same
  way: `webpki_read_certificate_key` has one caller,
  `webpki_verify_leaf_pin`, which has one caller, `handshake_auth.c`,
  and neither reads a clock (docs/decisions.md 65). The
  provisioning reader sits above them in `x509_ca.c` as a side
  branch: nothing in the library includes its header, so a session
  cannot reach it however the firmware uses it. `x509_read_time` checks the Time shape and ignores the
  digits. `x509_read_time_epoch` does read them, but only as a
  counter to compare against stored state (INV-21); nothing
  compares a certificate to now, so no code path wants a clock.
- **Check.** Semgrep-structural (`inv-20-cert-entry-point`): no
  `x509_verify_leaf` call outside handshake_auth.c, with x509.c
  excluded as the definition site. Semgrep-structural
  (`inv-20-webpki-leaf-pin-entry`, `inv-20-webpki-leaf-key-reader`): no
  `webpki_verify_leaf_pin` call outside handshake_auth.c and no
  `webpki_read_certificate_key` call outside webpki_pin.c, each with its
  definition site excluded. Semgrep-structural
  (`inv-20-provisioning-entry`): no `ch_pubkey_from_pem` call in any
  library source, with x509_ca.c excluded as the definition site. Semgrep-tripwire
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

### INV-27 — the QUIC mode stays in files named quic*

- **Claim.** Every root source and header that only a `TRANSPORT=quic-nonblocking`
  build compiles is named `quic*`, and no other root file is one. So
  `git ls-files 'quic*'` names every file the mode owns, and a reader
  sees where the QUIC code is without reading the build. Two lists in
  the Makefile hold the mode's text under other names, and a reader who
  wants all of it reads them too: `QUIC_SHARED`, the files both
  transports compile, and `QUIC_CONDITIONAL`, the shared files that
  carry a `#ifdef CH_TRANSPORT_QUIC_NONBLOCKING` arm. `handshake_flight.[ch]` is
  `QUIC_SHARED`: the QUIC mode adds it, both transports compile it, and
  it carries no prefix for that reason. `aes.[ch]` is
  `QUIC_CONDITIONAL`: a suite build compiles its cipher over every
  transport, and only a QUIC build compiles the entries that build the
  Initial and Retry keys and run header protection. The other AES and
  GCM sources a suite build compiles carry no prefix for the same
  reason. `quic_aes_soft.c` and `quic_aes_extern.c` keep it: a
  `SUITE=aesgcm` build refuses both (INV-26), so only a QUIC build
  compiles them.
- **Mechanism.** The preprocessor decides, not a list. A file is
  QUIC-only when it declares nothing without `-DCH_TRANSPORT_QUIC_NONBLOCKING` and
  gains something with it. The mode's own files put their whole body
  inside one `#ifdef CH_TRANSPORT_QUIC_NONBLOCKING`, so a TCP build compiles them
  to nothing, includes included. The files both transports share fence
  their QUIC arms instead and still declare their TLS text.
  `handshake_flight.[ch]` holds the flight handlers both drivers call,
  so no protocol rule exists twice; giving it the prefix would claim a
  TCP build does not compile it, which is false. The AES and GCM sources
  guard their body on the transport or on `-DCH_SUITE_AES_GCM`, so the
  lint reads each one with the defines a suite build passes
  (`QUIC_EXTRA_DEFINES`), and a file a suite build compiles reads as
  shared.
- **Check.** Semgrep-tripwire grade (`make lint-quic-partition`,
  `tools/quic-partition.py`), and the mutants below measure it rather
  than claim it. The lint preprocesses every root `.c` and `.h` file
  twice, once without the transport define and once with it, and
  compares the two outputs against each other. Comparing each against
  empty instead would pass a QUIC-only declaration added to a file that
  already declares something, which is the likeliest way the partition
  breaks. `-fdirectives-only` keeps a macro the QUIC build does not
  define from reading as changed text, and the line markers keep a
  file's includes from answering for the file. It reports a `quic*`
  file that declares something without the define, a file outside the
  prefix that declares something only with it, a file that gains a
  transport arm and is in neither list, a `QUIC_CONDITIONAL` entry
  whose file has stopped carrying one, and a `quic*` file that `HDRS`
  does not name, which is how the formatter would stop reading it. It
  prints the counts it found, so no count is written down here. Three
  mutants in `test/violations/` require `test/lint-quic-partition.sh`
  to fail, and the fast tier runs all three: `inv27-quic-type-above-guard`
  writes a typedef above `quic_initial.h`'s transport guard,
  `inv27-quic-declaration-in-tls-header` adds a `ch_quic_` declaration
  to `tls.h` inside a transport arm, and `inv27-quic-include-above-guard`
  moves `quic_retry.h`'s `#include` lines above its guard.

  What it does not catch. It reads whole files, so a QUIC-only function
  inside a file both transports compile is invisible: a QUIC arm added
  to `session.c` passes, and review is what catches that. A file that
  gates its body on a `CH_QUIC_`-prefixed macro it does not define is
  reported as one the lint cannot judge rather than judged, because the
  lint defines `CH_TRANSPORT_QUIC_NONBLOCKING` and nothing else. And the rule is a
  naming rule: a determined author who writes the mode under other
  names defeats it, which is what the tripwire grade means
  (`docs/invariants.md:25-26`).
- **Violation.** A PR adds `transport_keys.h`, a header only a QUIC
  build compiles, under a name without the prefix, and
  `git ls-files 'quic*'` stops naming every file the mode owns.
- See [decisions: Engineering](decisions.md#engineering).

### INV-28 — the tcp-nonblocking transport calls no I/O callback during the handshake

- **Claim.** A `TRANSPORT=tcp-nonblocking` build runs its whole handshake without
  calling `ch_cfg.send` or `ch_cfg.recv`. The caller feeds bytes in and
  takes bytes out: a client through `ch_record_in` and `ch_record_out`,
  a server through `ch_srv_record_in` and `ch_srv_cfg.on_record_out`.
  Both callbacks are still required at configuration time, because
  `ch_read` and `ch_write` call them once the session is connected, and
  by then the caller holds the bytes. Once connected, `ch_read` calls
  `cfg.send` in two cases alone: the reply to a KeyUpdate whose sender
  asked for one (RFC 9846 §4.7.3), and the alert of a failure. The
  peer's close_notify is neither. The `ch_read` that reads it sends
  nothing, and `ch_close` sends this side's close_notify through
  `cfg.send` in one call, whenever the caller makes it (INV-22). A
  caller whose `cfg.send` holds only input while `ch_read` runs, as
  colibri's does, therefore sees no send it did not ask for when the
  peer closes.
- **Mechanism.** The blocking driver is not in the object. `handshake.c`
  is filtered out by `TRANSPORT_FILTER`, `srv_handshake.c` by the server
  arm, and `tls.c` and `srv.c` guard their accept and connect calls out.
  What remains reaches the socket only through `srv_out.c`'s `emit`,
  whose tcp-nonblocking arm calls the caller's sink. The compatibility
  change_cipher_spec a server owes a client that sent a
  legacy_session_id goes the same way, through `srv_out_record`; it
  went through `cfg.send` until colibri found it against Go's
  crypto/tls client. This is the invariant the
  mode exists for: a callback that blocks inside a completion-based
  event loop stalls every connection that loop holds, and there is no
  thread to park it on.
- **Check.** `bin/srv_tcp_nonblocking_test` supplies a `send` and a
  `recv` that fail the run if the driver ever calls them, so the claim
  is measured rather than argued.
  `test/violations/srv-tcp-nonblocking-out-blocks-the-caller.violation`
  makes `emit` send instead of pushing and requires that binary to fail.
  `test/violations/inv28-srv-ccs-through-cfg-send.violation` sends the
  change_cipher_spec through `cfg.send`, and the binary's hello with a
  32-byte legacy_session_id catches it. `bin/tcp_nonblocking_loop_test`
  measures both drivers at once: it runs this tree's client driver
  against this tree's server driver in one process, over the pinned auth
  mode, and counts the socket calls of both. A whole handshake completes
  in two rounds with none. That is also the only place the two drivers
  meet -- `bin/srv_tcp_nonblocking_test` reads the server's records and
  never hands them to a client -- so a server flight the client refuses
  fails in `check` rather than in an interop run.
  `test/violations/record-in-waits-for-the-rest.violation` is the client's
  mirror of the server mutant above: it makes `ch_record_in` call
  `cfg.recv` to wait for the rest of a message, which still completes
  the handshake, and requires that binary to fail.
  `bin/tlsclient_tcp_nonblocking` still covers the client against a real
  server in `check-slow`.
  `bin/tcp_nonblocking_loop_test` also counts each end's send calls
  after the handshake (`test/tcp_nonblocking_close_tests.h`): none while
  the peer's close_notify is read, one per `ch_write`, and one for
  `ch_close`.
  `test/violations/inv22-read-answers-close-notify.violation` makes
  that `ch_read` send a close_notify and requires the binary to fail.

  That is the behavioral half, that neither driver calls a callback. The
  mechanism half, that a tcp-nonblocking object holds no blocking driver to
  call one with, carries its own mutant:
  `inv28-webpki-connect-unguarded` deletes the `#ifndef
  CH_TRANSPORT_TCP_NONBLOCKING` around the webpki `ch_connect` and requires
  `test/lib-check-webpki-tcp-nonblocking.sh` to fail, because the compiled call
  imports the `ch_handshake` this variant does not compile
  ([171](https://github.com/c4milo/chapulin/issues/171)). That leg is
  the only client object with `ch_record_init` and no `ch_connect`, so
  no other build reports it.
- **Violation.** A PR adds a `recv` call to a tcp-nonblocking step so the
  driver can wait for the rest of a message, or routes one message of
  the server's flight through `io_send_all` because it is small.
- See [decisions: Engineering](decisions.md#engineering).

### INV-29 — the key log is the only way a secret leaves, and it names the right connection

- **Claim.** A `KEYLOG=on` build hands each of the four traffic secrets
  to `ch_keylog` once per handshake, at its suite's hash length, filed
  under the ClientHello's random, and both ends of one connection log the same random and the
  same secret under each label. No other path gives a secret to the
  caller. A device client cannot be built with it.
- **Mechanism.** Four calls, one per secret, at the two places
  `ks_handshake` and `ks_master` run in `handshake_flight.c` and
  `srv_flight.c`, which every driver reaches, tcp-blocking, tcp-nonblocking and QUIC
  alike. Each role copies the random into `handshake_state.client_random`
  before it loses the original: the client before the key exchange
  wipes `h->random`, the server from the parsed hello. `keylog.h` and
  the Makefile refuse `CH_KEYLOG` without a server role or
  `TRUST=webpki`.
- **Check.** `bin/tcp_nonblocking_loop_test` runs both ends in one process and
  requires eight rows, one per label per end, with one random and one
  secret per label across the two, and no zero secret. It also requires
  a client that refused CertificateVerify to have logged its handshake
  secrets and no application secret.
  `test/violations/keylog-random-after-the-wipe.violation` restores the
  first build's bug, logging the random after the wipe, and requires
  that binary to fail.
- **Violation.** A PR logs a secret the format has no label for, logs
  from a driver rather than from the handler that derived the secret, or
  reads the random at a point where one role has already wiped it.
- This is not an exception to INV-17. The wipes still run; the key log
  hands a secret out before its wipe, and only in a build that asked.
- See [decisions: Engineering](decisions.md#engineering), entry 44.

### INV-7 — no negotiation

- **Claim.** One cipher suite and one version per build, and in the raw
  and ca modes one group and one signature algorithm. The client offers
  exactly one of everything; the server takes it or the handshake fails
  closed. The host-side `TRUST=webpki` mode offers several signature
  schemes (decisions.md 36), several application protocols (37), two
  groups with a key share for each and secp256r1 listed after them with
  none (39, 53, 63), under `SUITE=aesgcm`
  three cipher suites (45, 58), and in a resuming hello the ticket and the
  certificate path beside it (55), so the server may resume or
  authenticate with its chain in the same connection. There a ServerHello selects either shared
  group, or the hybrid alone under `ch_cfg.require_pq`, and a
  HelloRetryRequest may ask for a cookie, for secp256r1, or for both; after
  a retry that names secp256r1 the ServerHello must select it. It carries
  ChaCha20, AES-128-GCM or AES-256-GCM, and the same one as a retry
  before it. A
  server role selects rather than offers, and its group order is fixed
  (decisions.md 54, 63): X25519MLKEM768 whenever the client lists it,
  x25519 when the client lists x25519 and not the hybrid, secp256r1 only
  when the client lists neither, and a HelloRetryRequest that names the
  group when the hello carried no share for it, so a hello that lists the
  hybrid and shares x25519 alone is asked for the hybrid rather than
  answered over x25519. Its suite order is ChaCha20, then
  AES-128-GCM, then AES-256-GCM, and it selects the first of them the
  client listed, or the first of `ch_srv_cfg.cipher_suites` when the
  caller names an order (decisions.md 58). It never selects a suite the
  client did not list.
- **Mechanism.** Absence of selection code; the TRUST build flag picks
  the sigalg of a raw or ca build at compile time, never at runtime.
  The two-group offer is the `CH_KEX_TWO_GROUPS` arms of
  `handshake_message.c`, `handshake_parser.c` and `handshake_flight.c`,
  with `handshake_groups.c`. A raw or ca parser refuses a
  HelloRetryRequest that names a group, and the webpki parser refuses one
  that names any group but secp256r1; `hsg_selected_group_ok` holds the
  ServerHello to the group of a share the hello it answers carried. The
  three-suite offer is the `CH_CLIENT_AES_SUITES`
  arms of `handshake_message.c` and `handshake_parser.c`, and
  `handshake_state.suite` records the suite a retry or ServerHello
  named. The server's choice is `srv_first_offered_suite` in `suite.h`,
  which walks the server's order and takes the first suite the parsed
  offer holds, and `srv_parse_client_hello` reads `cipher_suites` once. The resuming offer is the `CH_TRUST_WEBPKI` arm of
  `handshake_message.c`, which writes `signature_algorithms` and
  `server_certificate_type` in every hello and `pre_shared_key` last,
  and a raw or ca hello offers a ticket alone.
- **Check.** The differential (`inv07-second-cipher-suite.violation`)
  and handshake_sequence assert the reject on any ServerHello that picks
  another suite or group. `bin/webpki_session_test` drives the
  two-group offer against a mock server, and four mutants require it to
  fail: a hello that lists x25519 without its share, a parser that takes
  a retry naming a shared group, and `require_pq` keeping x25519 in the
  hello or taking a ServerHello that selects it. Three more guard the
  third group: `inv07-first-hello-shares-p256` sends a secp256r1 share in
  the first hello, `inv07-require-pq-lists-secp256r1` keeps secp256r1 in a
  `require_pq` hello, and `inv07-retry-names-shared-group` now takes a
  retry naming x25519 as one naming secp256r1; `bin/webpki_session_test`
  fails on each. `key_share_webpki` proves the parser's x25519 and
  secp256r1 shapes beside the hybrid one, and its retry shape, and the
  `handshake_groups` harness proves which group a ServerHello may select
  before and after a retry.
  `bin/webpki_session_aes` drives the three-suite offer, and two mutants
  require it to fail: a parser that takes `TLS_AES_128_CCM_SHA256`, and
  a ServerHello whose suite differs from the retry's. `srv_select_suite`
  proves the server's walk over every offer and every order of up to
  three code points: the suite it names is offered, held, in the order,
  and the first such. `inv07-srv-selects-unoffered-suite` takes the
  first suite of the order whether or not the client listed it, and
  `bin/srv_flight_test_aes` fails on it; `bin/webpki_loop_aes` feeds the
  server h3spec's offer, `TLS_AES_256_GCM_SHA384`,
  `TLS_AES_128_GCM_SHA256` and `TLS_AES_128_CCM_SHA256`, and requires
  AES-128-GCM.
  `handshake_parser_suite` proves an accepted message carries an
  offered suite. `bin/webpki_resume_test`'s mock server refuses a hello
  with no `signature_algorithms` with handshake_failure, as dns.google
  did when cocuyo measured it on 2026-09-24, and
  `inv07-webpki-resume-hello-drops-schemes` requires the test to fail
  when the resuming hello drops the schemes; `test/session_cfg_tests.h`
  holds the raw and ca resuming hello to the bytes it had before entry
  55, by digest, in `bin/unit`, `bin/unit_ca` and `bin/unit_pq`. The server's order is `srv_kex_group`'s, which the
  `srv_kex` harness proves over every groups and shares pair a parsed
  hello can report, and `bin/srv_flight_test` drives each row of it.
  `inv07-srv-x25519-despite-hybrid-share` takes x25519 whenever the
  client shared it, `inv07-srv-skips-hybrid-retry` answers over the
  x25519 share instead of asking for the hybrid, and
  `inv07-srv-p256-before-x25519` prefers secp256r1 to x25519; the test
  fails on each. `bin/tcp_nonblocking_loop_test` feeds this tree's
  tcp-nonblocking server hand-written hellos that list secp256r1 alone
  and beside x25519. `test/e2e.sh` runs the same rows against OpenSSL's
  `s_client`, and the webpki client against an OpenSSL server that holds
  P-256 alone.
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
  resulting secrets byte-for-byte. In a `-DCH_SUITE_AES_GCM` build every
  handshake site that keys a direction passes the suite the ServerHello
  named, through `REC_DIR_INIT_SUITE`, and `rec_dir_update` keeps the
  direction's suite. `inv11-srv-keys-chacha-after-aes.violation` keys the
  server's handshake directions with ChaCha20 after it chose AES-GCM,
  and `inv11-key-update-drops-suite.violation` rekeys through
  `rec_dir_init`; `bin/srv_flight_test_aes` and `bin/aes_suite_test`
  each open the result under a reader keyed on its own. The schedule runs
  at the hash of the suite the ServerHello named, SHA-384 for
  `TLS_AES_256_GCM_SHA384` (decisions.md 58), and five mutants hold that:
  `inv11-hkdf-sha384-arm-runs-sha256` runs HKDF's SHA-384 arm on
  SHA-256 (`bin/hkdf384_test`), `inv11-record-key-update-sha256` runs
  "traffic upd" at `SHA256_LEN` (`bin/aes_suite_test`),
  `inv11-client-retry-transcript-sha256` writes the retry's synthetic
  message at `SHA256_LEN` and `inv11-client-psk-hash-unchecked` takes a
  PSK under a suite of another hash (`bin/webpki_session_aes`), and
  `inv11-srv-ticket-any-hash` resumes a ticket under a suite of another
  hash (`bin/webpki_loop_aes`). `transcript384` proves the transcript's
  two hashes and the retry's restart. The schedule
  rests on HMAC-SHA-256 and HMAC-SHA-384, which the Wycheproof suite checks directly, and
  `bin/unit` pins its key-length boundary: a 64-byte key used as it is
  and a 65-byte key hashed first (RFC 2104 §2).
  `hmac-key-block-boundary.violation` and
  `hmac-key-over-block-unhashed.violation` move that boundary one byte
  each way. A server that ran X25519MLKEM768 extracts the handshake
  secret from the ML-KEM shared secret and then the x25519 one, RFC
  10024's order; the `srv_kex` harness proves where each half lands, and
  `inv11-srv-hybrid-halves-swapped.violation` swaps them, which
  `bin/srv_flight_test` catches by deriving the client's keys from the
  ServerHello's own bytes. A PSK binder covers every byte of the hello
  before its binders list, so `pre_shared_key` is the last extension
  (RFC 9846 §4.3.11). That is tested and not proved: `bin/unit` and
  `bin/webpki_session_test` read the extension order of a built hello,
  and `inv11-webpki-psk-not-last` requires `bin/webpki_resume_test`,
  whose mock checks every binder it reads, to fail when the webpki
  certificate path is written after the ticket.
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

### INV-24 — the x25519 ladder stays inside its proven limb range

- **Claim.** Between the ladder's operations every limb of `a`, `b`,
  `c`, `d` and `x` lies in (-2^17, 2^17), and mul receives no operand
  outside (-2^18, 2^18). Every x25519 field-op proof holds only inside
  a stated limb range (the verification table in the README), so a
  limb that leaves it turns those verdicts into statements about
  inputs the code no longer produces.
- **Mechanism.** mul ends in two carry passes, which leave limbs 1..15
  in [0, 2^16) and limb 0 in [-38, 2^16 + 38); one add or sub of two
  such values stays under 2^18; and `step()` applies at most one add
  or sub to a value before the next mul takes it.
- **Check.** CBMC: `x25519_step` proves one loop step from any state
  inside the range lands inside it again, and `x25519_tail` proves
  mul's output form, one `invert` round and the final multiply and
  pack do the same
  ([#50](https://github.com/c4milo/chapulin/issues/50)). The unit
  vectors notice a limb only once it passes 2^31 and mul's narrowing
  to int32 truncates it; the fourteen bits between the proven bound
  and that point are watched by the proofs alone.
- **Violation.** A PR drops one of mul's two carry passes to save
  cycles, or replaces the step's last square with an add, and the
  ladder hands the field ops limbs their proofs never covered. `make
  test-invariants-proof-backed` runs both, as `inv24-x25519-mul-one-carry`
  and `inv24-x25519-step-sqr-as-add`, through `proof/prove-one.sh`, which
  runs one harness and fails unless it verifies; the nightly gives that
  class its own job.
- This entry is the `X25519=portable` field's, the default. INV-34 is
  the same claim for `X25519=wide`.

### INV-34 — the X25519=wide ladder stays inside its proven limb range

- **Claim.** In an `X25519=wide` build, between the ladder's operations
  limbs 0, 2, 3 and 4 of `a`, `b`, `c` and `d` lie in [0, 2^51), limb 1
  lies in [0, 2^51 + 2^20), and every limb of `x` lies in [0, 2^51).
  Every product the field computes takes a first operand under 2^55 and
  a second under 2^60, so every product is under 2^115, and no unsigned
  value wraps. On the real multiply the bounds are tighter: `mul` and
  `sqr` on operands whose limbs are under 2^54 make every product under
  38 * 2^108, every column sum under 77 * 2^108 (under 2^115) and every
  carry between columns under 2^64, and leave limb 1 under
  2^51 + 2^13. The field computes in `uint64_t` and `unsigned __int128`,
  where C defines every wrap, so a limb that leaves these ranges does
  not fault: it computes a wrong value.
- **Mechanism.** `carry_columns` keeps each column's low 51 bits and
  carries the rest to the next column 128 bits wide, so no bit of a sum
  is dropped; the top carry comes in at the bottom times 19 and the last
  carry stops at limb 1. `add` of two such results stays under 2^53.
  `sub` computes a + 2p - b, and a result of `mul` never has a limb above
  2p's. `step()` applies at most one `add` or `sub` to a value before the
  next product takes it, so every operand the ladder hands a product is
  under 2^53.
- **Check.** CBMC, with `--unsigned-overflow-check` on every launch line,
  which is what turns a wrap into a property. `x25519_wide_step` proves
  one loop step on the shipped `step()`, from any state inside the
  bounds back into them, and `x25519_wide_invert` the whole inversion
  chain in place. `x25519_wide_tail` proves the output form of `mul`,
  `sqr` and `mul_a24` from any operands under 2^54, in the aliasing
  shapes the ladder uses, and the final multiply and `pack`. Those three
  replace the multiply with the contract in
  `proof/x25519_wide_stubs.h`, and `x25519_wide_mul128` proves the real
  `ct_mul128` meets it. `x25519_wide_mul` and `x25519_wide_sqr` prove the
  tighter bounds on the real multiply, and `x25519_wide_ops` the linear
  ops, `unpack`, and that `pack` writes a value below p. The base case,
  `a = d = 1`, `c = 0` and `b = x`, is read from
  `x25519_wide_ladder()`'s prologue. The values are held by
  `bin/x25519_equiv_test` against the 16-limb field, and by the RFC
  7748, Wycheproof and Lean differential runs over this field.
- **Violation.** A PR drops `carry_columns`' last carry, so limb 0 keeps
  all of r0 and the value stays right while the limb passes 2^51; or it
  folds the top carry in times 38, the 16-limb field's constant for
  2^256. `make test-invariants` runs both: `inv34-x25519-wide-carry-dropped`
  through `proof/prove-one.sh x25519_wide_step`, in the nightly's
  proof-backed job, and `inv34-x25519-wide-fold-not-19` through
  `bin/x25519_equiv_test`.
- See [decisions: Engineering](decisions.md#engineering), entry 52.

### INV-35 — the build record holds what the object was compiled with

- **Claim.** Every packaged object exports its build record under a
  symbol name that carries its transport, `ch_build_info_tcp_blocking`,
  `ch_build_info_tcp_nonblocking` or `ch_build_info_quic_nonblocking`, and each of its fields holds what
  `build.h` computes under that object's defines: the record format, one
  bit per build define that changes a public layout or bound, the sizes
  of `ch_cfg`, `ch_tls`, `ch_ticket`, `ch_record`, `ch_quic` and
  `ch_rsa_priv`, and four bounds. A consumer that computes the same
  values under its own defines, through `ch_build_matches(&ch_build)` or
  field by field, reads equal values exactly when its defines give the
  object's layouts, bounds and axes, and a consumer compiled for another
  transport names another record and does not link. No library source
  reads the record or calls the comparison.
- **Mechanism.** Each value has one definition. `build.h` writes it as a
  `CH_BUILD_` macro, `build.c` sets the field of the same name from that
  macro, and a consumer's compile computes the same macro under its own
  defines. `CH_BUILD_AXES` is the one place a define is mapped to its
  bit, and `build.h`'s `ch_build` macro is the one place a transport is
  mapped to its record's name. `PUBLIC_BUILD` puts the record in every
  variant's export list and `TRANSPORT_NAMED` gives it the transport's
  name there, the link stamp holds that list so an edit to it relinks
  the object, and every `lint-trust-separation` row requires `build.c`.
- **Check.** `lib-check` links `test/build_test.c` against every object
  it checks, and every leg of `make check` builds it three times:
  compiled under the object's own defines, where it must read a record
  equal to its headers; compiled with `CH_PIN_ECDSA` moved, where it must
  read a difference; and compiled with the transport moved, where it
  must fail to link and the link must name the other transport's record.
  The test also restates the axes from its own defines, one line per
  define, because a `CH_BUILD_AXES` that forgets a define leaves the
  object and every consumer in agreement. `test/lib-pair-check.sh` links
  a tcp-nonblocking and a QUIC object into one image and requires each half
  to read its own object's record. Four mutants in `test/violations/` are
  each caught by `test/lib-check-webpki-tcp-nonblocking.sh`:
  `inv35-build-record-omits-axis` drops the tcp-nonblocking bit from
  the record, `inv35-build-record-stale-size` writes `sizeof(ch_tls)` as
  a number, `inv35-build-record-not-exported` drops the record from
  `PUBLIC`, and `inv35-build-axes-forget-define` drops the
  tcp-nonblocking term from `CH_BUILD_AXES`. A fifth,
  `inv35-build-record-shared-name`, gives the QUIC transport's build record
  the tcp-nonblocking transport's name, and `test/lib-pair-check.sh` catches it.
  `bin/hpp_test` calls the C++ forwarder on the `cxx-check` legs.
- **Violation.** A PR writes a field of `build.c` as a number, adds a
  define that moves a public layout without a bit in `CH_BUILD_AXES`,
  adds a public struct or bound that the record does not hold, or gives
  two transports' records one name. The checks above catch the first and
  the last. They catch the second only once the test's own list names
  the define, and nothing catches the third: review holds `build.h`'s
  list.
- The record compares layouts and bounds, not behavior, and defines, not
  revisions: headers from another commit are caught only where a size, a
  bound or a bit moved.
- See [decisions: Engineering](decisions.md#engineering), entries 56 and
  61.

## Fail-closed

### INV-13 — no resumable errors

- **Claim.** Every error kills the session: alert, wipe, dead. There
  is no error a caller can retry past. The two non-blocking transports
  also return results that are not errors and leave the session live,
  and their headers list them: `tcp_nonblocking.h` for
  `TRANSPORT=tcp-nonblocking` and `quic.h` for `TRANSPORT=quic-nonblocking`.
  Each one means the call changed nothing, the packet was dropped
  (`CH_QUIC_DISCARD`, RFC 9001 §5.5), or no record has arrived yet
  (`CH_RECORD_AGAIN`). A failed QUIC session stays dead: it keeps only the
  write keys INV-17 names, for one CONNECTION_CLOSE per level, and no call
  revives it.
- `CH_RECORD_AGAIN` is the one returned after work was done, so its
  terms are exact. `ch_read` returns it only when `cfg.recv` returns 0
  before a record's first byte. Every record read before that has been
  opened and handled: a NewSessionTicket went to `on_ticket`, a
  KeyUpdate changed the keys, and the first part of a message split
  across records waits at the front of `cfg.buf`, with
  `ch_tls.post_fill` counting its bytes. A 0 after a record's first byte
  is `CH_EIO` and a dead session.
- **Mechanism.** Fail-closed policy; `tlsi_fail` is the single
  funnel. `io_read_record` is the only source of `CH_RECORD_AGAIN`, and
  `dispatch_one_record` and `post_handshake` in `tls.c` are the only
  places that return it without calling `tlsi_fail`.
- **Check.** Convention; handshake_sequence's 466k-sequence run asserts no
  sequence revives a failed session. `bin/tcp_nonblocking_loop_test`
  (`test/tcp_nonblocking_read_tests.h`) reads a ticket-only record and
  then nothing, a ticket split across two records, and a record cut off
  after three bytes. Three violations each break one term:
  `inv13-record-read-dies-between-records`,
  `inv13-record-read-drops-a-split-message` and
  `inv13-record-again-inside-a-record`.
- **Violation.** A PR returns a "soft" error that leaves keys live so
  the caller can retry a read.
- See [decisions: Engineering](decisions.md#engineering).

### INV-14 — the refusal set

- **Claim.** The client refuses: a Certificate after a ServerHello
  that selected the PSK, CertificateRequest, psk_ke without DHE, a
  cookieless HRR, a second HRR, dual auth configs, and an even RSA pin.
  A raw or ca client also refuses, with handshake_failure, a ServerHello
  that does not select the PSK its hello offered. A TRUST=webpki client
  continues that ServerHello as a full handshake, and checks the chain,
  the clock, the hostname, the anchors and any SPKI pins exactly as for
  a hello with no ticket (docs/decisions.md 55); it refuses a
  pre_shared_key naming an identity other than 0 with
  illegal_parameter. A TRUST=webpki build
  also refuses a config that sets a pin or an epoch callback, or a
  length field of one of them, a PSK that is not a ticket bound to the
  config's hostname, anchors and SPKI pins (`webpki_resumption_ok`,
  webpki_ticket.h), a config whose clock (`now_seconds`) is 0 while it
  sets anchors, and a
  server_name acknowledgement that carries data. Its EncryptedExtensions
  parser also refuses a server_name acknowledgement when the ClientHello
  sent no server_name, which a configuration without a hostname does,
  and a server_certificate_type (RFC 7250) when the ClientHello offered
  no certificate type, both with unsupported_extension; a
  server_certificate_type whose body is not one byte, with decode_error;
  and one naming a type the ClientHello did not offer, with
  illegal_parameter. The type an accepted one names is what
  `ch_tls.server_cert_type` reports, and X.509 when the server sent
  none. The web PKI fields exist only in that build, so a raw or ca
  build that sets one fails to compile rather than returning
  CH_EINVAL. `check_certificate_verify` (handshake_auth.c) refuses a
  CertificateVerify whose signature scheme is not the one the leaf key's
  family can produce, and it checks the signature that passes under that
  family's own verifier over the digest the scheme names, so a signature
  over any other digest is refused too. `webpki_verify_chain` fails
  closed with unknown_ca when the entries run out or CH_WEBPKI_CHAIN_MAX
  is reached before an anchor verifies a signature, with
  certificate_expired when `now_seconds` lies outside an issuer's
  validity and not only the leaf's, and with unsupported_extension when
  any CertificateEntry, a trailing one included, carries a non-empty
  extensions vector. A QUIC server's Retry token check
  (`ch_srv_quic_token_check`, `quic_token.c`) refuses a token that is
  empty or whose first byte is not the Retry type with `CH_EPROTO`, and
  a Retry token whose length does not match its length bytes, whose
  connection ID is longer than `CH_QUIC_DCID_MAX`, whose tag does not
  verify for the key and the client's address, or whose issue instant is
  after now or more than the lifetime before it with `CH_EAUTH`. Neither
  refusal writes the connection IDs the caller would read. A server
  (`srv_select_auth`, `srv_resume.c`) considers a PSK only under
  `psk_dhe_ke`, and only with a ticket key and a clock; it passes over,
  without failing the handshake, a ticket of any length but
  `SRV_TICKET_LEN`, one that does not open under the ticket key, one
  issued after its clock or more than `SRV_TICKET_LIFETIME` seconds
  before it, one whose suite it does not hold, and one whose ALPN
  protocol is not the one this connection selected; and it refuses the
  binder of the ticket it selected with decrypt_error when that binder
  is absent, is not 32 bytes, or does not compare equal under
  `ct_memeq`. A hello left with no ticket and no scheme a provisioned
  identity signs is missing_extension when it carried no
  signature_algorithms and handshake_failure when it did. A server's
  ClientHello parser refuses a key share of any length but its group's,
  32 bytes for x25519 and 1,216 for X25519MLKEM768, with
  illegal_parameter, and `srv_kex_share` refuses an encapsulation key
  that fails FIPS 203 §7.2's modulus check with illegal_parameter, as
  RFC 10024 asks. `bin/srv_test` holds both lengths at the boundary
  pair, and `bin/srv_flight_test` holds the modulus at 3,328 taken and
  3,329 refused; `srv-parser-share-length-floor` and
  `srv-kex-ek-check-dropped` require each to fail. The same parser
  refuses a ClientHello of more than `SRV_CLIENT_HELLO_EXT_MAX` (128)
  extensions with illegal_parameter, on a first hello and a retried one
  and on every server path, before the duplicate check runs
  (docs/decisions.md 59).
- **Mechanism.** Fail-closed policy, each refusal an explicit branch
  with its alert.
- **Check.** handshake_strict table cases per refusal; CBMC proves the
  branches memory-safe. The TRUST=webpki config and server_name
  refusals have boundary rows in test/webpki_session_cases.h and
  bin/handshake_strict_webpki, each guarded by an `inv14-` violation.
  The ticket rule is bin/webpki_resume_test and
  bin/webpki_resume_tcp_nonblocking, one test over both TCP drivers: a binding checked against a known
  answer, the shape rows at each boundary, a ticket refused under
  another hostname, other anchors or another ticket's binding, and a
  resumed handshake whose own ticket resumes the next one. Ten
  `inv14-webpki-ticket-`, `inv14-webpki-connect-` and
  `inv14-webpki-record-init-` violations guard it; the webpki_ticket
  CBMC harness proves the rule memory-safe and its verdict limited to
  an unset config or a ticket of the stated shape.
  `ch_quic_init` applies the same configuration rules through
  `webpki_cfg_ok` (docs/decisions.md 64). bin/quic_loop_webpki holds
  them over QUIC at each boundary: `CH_SPKI_PIN_MAX` pins with anchors
  and alone, `CH_WEBPKI_ANCHOR_MAX` anchors and `CH_HOSTNAME_MAX` bytes
  of hostname under pins alone each accepted and one more refused, a
  pinned session's ticket resumed under its pins and refused under another
  pin set or none, and an ALPN offer of no protocol refused, which RFC
  9001 §8.1 forbids a QUIC client. inv14-quic-spki-pin-cap,
  inv14-quic-ticket-pins-unbound, inv14-quic-session-hash-unpinned and
  inv14-quic-webpki-empty-alpn require it to fail. The quic_config_webpki CBMC harness proves
  `quic_config_ok` memory-safe over any configuration, its `CH_OK`
  limited to one that keeps these rules, and `webpki_resumption_ok` run
  only after the pin, hostname and anchor rules hold;
  inv14-webpki-cfg-resumption-first requires it to fail.
  The declined-PSK rule is test/psk_decline_tests.h, which drives
  hsf_accept_server_hello directly in bin/unit, bin/unit_ca, bin/unit_pq
  and bin/webpki_resume_test and expects the mode's answer;
  inv14-raw-accepts-declined-psk requires bin/unit to fail when a raw
  client accepts a decline, and the handshake_psk harness proves that
  every raw PSK session that connects reports `psk_selected`, so a
  declined ticket never yields a session. A decline under
  another hostname and under an anchor that carries the root's Name over
  another key fails in bin/webpki_resume_test,
  bin/webpki_resume_tcp_nonblocking, bin/webpki_loop_tcp_nonblocking and
  bin/quic_loop_webpki, and
  inv14-webpki-decline-skips-hostname and
  inv14-webpki-decline-skips-anchor require the first to fail when the
  fallback skips either check.
  The CertificateVerify rules are bin/webpki_auth_test, which drives
  hsa_server_auth over one corpus chain per leaf key family with the
  signatures in test/webpki_auth_vectors.h: an accepted row per family,
  each of them again under every scheme the family cannot produce, and a
  signature over the content hashed the other way. The
  certverify_webpki CBMC harness proves the same two rules over every
  scheme value and every leaf key byte. Three violations guard them,
  and each fails both that test and that harness:
  inv14-webpki-certificate-verify-scheme,
  inv14-webpki-certificate-verify-sha384 and
  inv14-webpki-certificate-verify-p384-key. The walk's own fail-closed
  answer is bin/webpki_chain_test's anchor_key_mismatch row, guarded by
  inv14-webpki-chain-unverified; its issuer validity rows,
  issuer_expired and issuer_not_yet_valid, are guarded by
  inv14-webpki-issuer-validity, and its list framing test by
  inv14-webpki-entry-extensions. The ALPN rules have boundary rows in
  the same two binaries — test/handshake_strict_alpn.h for the reply and
  test/webpki_session_cases.h for the config and the reported selection
  — and nine violations guard them: inv14-alpn-unoffered-protocol,
  inv14-alpn-empty-name, inv14-alpn-list-length,
  inv14-alpn-extension-trailing, inv14-alpn-without-offer,
  inv14-alpn-duplicate-name, inv14-alpn-name-length,
  inv14-alpn-count-cap and inv14-alpn-selection-unseeded. The
  server_name and server_certificate_type rules have boundary rows in
  test/handshake_strict_cert_type.h, which bin/handshake_strict_webpki
  runs: the acknowledgement with and without server_name sent, each
  offered type accepted, the type an offer lacks and the values 1, 3,
  7, 8 and 255 refused with 47, bodies of 0 and 2 bytes refused with 50,
  and a selection with no offer refused with 110.
  bin/webpki_encrypted_exts_test drives hsf_read_encrypted_extensions
  over each configuration shape and reads the type the session reports.
  The eeparse_webpki CBMC harness proves, over every offer and every
  message up to 256 bytes, that an accepted message leaves the caller's
  type or names one the offer holds. Seven violations guard them:
  inv14-server-cert-type-without-offer, inv14-server-cert-type-length,
  inv14-server-cert-type-unoffered, inv14-server-name-ack-unsent,
  inv14-server-cert-type-not-reported, inv14-server-cert-type-unseeded
  and inv14-server-name-sent-constant.
  A `ROLE=server` build's ClientHello parser (`srv_parser.c` and
  `srv_parser_ext.c`) has the same shape with the sides swapped. It
  refuses only what RFC 9846 makes a server abort on — malformed
  framing, a second extension of one type, a missing required
  extension, `pre_shared_key` out of last position or without
  `psk_key_exchange_modes`, a share of the wrong length or for a group
  `supported_groups` did not list, a `legacy_compression_methods` that
  is not one zero byte, and a `supported_versions` without 0x0304 — and
  it ignores every suite, group, scheme, version, mode and extension it
  does not know (`rfc9846.txt:1299`, `rfc9846.txt:4636-4637`), so a
  hello carrying GREASE code points still negotiates. One extension is
  the exception, and it comes from another document: RFC 9001 §8.2
  requires a fatal `unsupported_extension` from an implementation that
  understands `quic_transport_parameters` when the transport is not QUIC
  (`rfc9001.txt:1945-1949`), and every build here runs over TLS records,
  because `srv_cfg.h` refuses `CH_ROLE_SERVER` together with
  `CH_TRANSPORT_QUIC_NONBLOCKING`. So the parser recognizes that one type in order
  to refuse it, rather than ignoring it. One refusal comes from no RFC:
  a ClientHello of more than `SRV_CLIENT_HELLO_EXT_MAX` (128)
  extensions, unknown ones included, is illegal_parameter, checked
  before every rule on the extensions themselves, because the duplicate
  check and the frozen digest each cost the square of the count
  (docs/decisions.md 59). After a HelloRetryRequest,
  `srv_check_retry_hello` refuses with illegal_parameter a second
  ClientHello whose head or covered extensions differ from the first's,
  compared as a set through the frozen digest, and accepts one that
  carries the same extensions in another order (docs/decisions.md 59).
  test/srv_parser_tests.h holds one case per refusal, the boundary pair
  of every length rule, and the ignore rule. Twenty `srv-parser-`
  violations require bin/srv_test to object when one of those rules is
  relaxed, the ignore rule included: sixteen carry this invariant, three
  carry INV-25 because they are the exact-fill rules, and one carries
  INV-8 because it is the 1.3-only rule.
  The retry rule is test/srv_quic_retry_tests.h, which bin/srv_quic_test
  runs over the two ClientHellos ngtcp2's interop client sent colibri's
  server: the reordered second hello completes the handshake, the first
  hello's order is accepted, and one covered byte changed, one covered
  extension dropped, one added, one head byte changed and one extension
  sent twice are refused. test/srv_parser_reader_tests.h holds the digest
  to a vector over the covered extensions in ascending type order. The
  srv_parser_frozen CBMC harness proves, over every extension block up to
  24 bytes, that `srv_ext_duplicate` answers 1 on a whole block exactly
  when two types match, and that the walk hashes each covered extension
  of a block without a duplicate once, whole, in strictly ascending type
  order. srv-parser-frozen-wire-order and srv-parser-duplicate-accepted
  require bin/srv_quic_test to fail, srv-parser-frozen-skips-lowest-type
  requires bin/srv_test to fail, and srv-retry-frozen-memcmp carries
  INV-16 for the reason srv-cookie-memcmp does.
  The count bound has a boundary pair on every server path: 128
  extensions accepted and 129 refused in test/srv_parser_reader_tests.h
  (bin/srv_test), in bin/srv_tcp_nonblocking_test, and in
  test/srv_quic_retry_count_tests.h (bin/srv_quic_test), where ngtcp2's
  retried hello at 129 carries the first hello's covered set, so only
  the count refuses it. The srv_parser_count CBMC harness proves the
  count exact and bounded, and srv_parser_walk proves that neither walk
  whose cost is the square of the count runs over more extensions than
  the bound. srv-parser-ext-max-off-by-one,
  srv-parser-ext-max-refuses-bound and srv-parser-ext-max-after-walk
  require bin/srv_test to fail, srv-parser-ext-max-removed requires
  bin/srv_quic_test to fail, and srv-parser-ext-max-after-duplicate
  requires the srv_parser_walk proof to fail.
  The Retry token's refusals are test/quic_token_tests.h, which
  bin/srv_quic_test runs: a one-bit flip at every byte, every truncation,
  another address and another key, a valid-tagged token of the reserved
  NEW_TOKEN type, a connection ID one byte past its cap under a valid
  tag, and the window at both edges. The quic_token CBMC harness proves,
  over every token and every instant, that CH_EPROTO answers only a
  token that is not a Retry token and CH_EAUTH only one that is, that a
  CH_OK token lies inside the window and its connection IDs inside their
  arrays, and that no refusal writes the connection IDs. Seven
  violations guard the rules:
  quic-token-tag-compared-with-itself, quic-token-address-unbound,
  quic-token-lifetime-off-by-one, quic-token-future-accepted,
  quic-token-type-unchecked and quic-token-cids-written-on-failure fail
  bin/srv_quic_test, and quic-token-cid-length-unbounded fails the
  harness. An eighth, quic-token-memcmp, carries INV-16, because it
  keeps every answer and changes only the compare's timing.
  The server's ticket rules are test/srv_resume_tests.h, which
  bin/srv_flight_test runs over real tickets: each passed-over shape,
  the lifetime at its last valid second and its first invalid one, a
  ticket one second in the future, psk_ke alone, no clock and no key,
  the ALPN binding both ways, the order rule over three identities, and
  a binder one bit off, 33 bytes long, over another transcript or
  absent. bin/tcp_nonblocking_loop_test, bin/quic_loop_test and
  bin/quic_loop_webpki run the same rules between this tree's client
  and server, and test/e2e.sh has OpenSSL's s_client resume against
  bin/tlsserver. The srv_ticket and srv_resume CBMC harnesses prove
  both files memory-safe over any ticket bytes and any offer, and prove
  that a ticket is selected only under psk_dhe_ke with a key and a
  clock, that a selected ticket leaves no signature scheme selected,
  and that a binder refusal is decrypt_error. The `srv-resume-` and
  `srv-ticket-` violations guard the rules, and
  srv-resume-binder-memcmp carries INV-16 for the reason
  quic-token-memcmp does.
- **Violation.** A PR relaxes one refusal for interop with a broken
  server, or makes the server refuse a ClientHello for carrying
  something it does not know.
- See [decisions: Protocol surface](decisions.md#protocol-surface).

### INV-33 — an SPKI pin names the server key, on the path the walk read or on the leaf

- **Claim.** A TRUST=webpki client with SPKI pins (`ch_cfg.spki_pins`)
  accepts a server key only when one pin is the SHA-256 of that key's
  whole DER SubjectPublicKeyInfo (RFC 7858 §4.2). Under the RFC 7250
  RawPublicKey type the pins are the whole check, and the Certificate
  message's list is exactly one CertificateEntry of 1 to
  `CH_WEBPKI_SPKI_MAX` bytes with an empty extensions vector, which
  `webpki_read_spki` fills exactly. The client refuses a second entry, a
  trailing byte or an oversized entry with bad_certificate, an extensions
  vector with unsupported_extension, a malformed or refused key with
  unsupported_certificate, and a key no pin names with bad_certificate.
  Under the X.509 type a chain must first pass the walk (INV-14), and
  then a pin must name the key of one of the `path_entries` certificates
  the walk read, the leaf first, or of the anchor at `anchor_index` that
  verified the last of them. A certificate the server sent after that
  path does not count. RFC 8310 §6.4 asks a client with a name and pins
  to require both, and this is how. With pins and no anchors, an X.509
  chain passes only when a pin names its leaf's key, entry 0, read only
  as far as its SubjectPublicKeyInfo, and CertificateVerify then verifies
  under that key (docs/decisions.md 65). A pin on any other entry or on a
  root names nothing there and is refused with bad_certificate, the list
  framing refuses what the walk's refuses, and a leaf key or signature
  algorithm the reader refuses is unsupported_certificate. A
  `TRANSPORT=quic-nonblocking` client applies the same rules, because
  `ch_quic_init` checks the configuration with `webpki_cfg_ok` and the
  QUIC step table calls the same `hsa_server_auth` (docs/decisions.md
  64).
- **Mechanism.** `webpki_server_key` (`handshake_auth.c`) chooses the
  rule by `ch_tls.server_cert_type`. `webpki_verify_raw_key` frames its
  one entry with `webpki_read_entry`, the reader the walk frames every
  entry with. `webpki_verify_chain` writes `path_entries` and
  `anchor_index` in the one branch that returns CH_OK, and
  `webpki_path_pinned` reads back only the first `path_entries` entries,
  each under the arm the walk parsed it under, then that anchor's key.
  With no anchors `webpki_server_key` calls `webpki_verify_leaf_pin`,
  which frames the list with `webpki_read_leaf_entry`, the walk's own
  framing, reads entry 0 with `webpki_read_certificate_key`, which stops
  after the SubjectPublicKeyInfo, and hashes that TLV alone.
  `webpki_spki_pinned` compares every pin through `ct_memeq` and does not
  stop at the first match. The key every rule accepts is the one
  `check_certificate_verify` verifies the signature under.
- **Check.** bin/webpki_auth_test drives hsa_server_auth through
  test/webpki_auth_pins.h: each key family's raw key accepted with its
  pin first or second of two and refused with none; each framing and
  reader refusal with its alert; the `CH_WEBPKI_SPKI_MAX` boundary pair;
  each accepted chain accepted with a pin on its leaf, its intermediate or
  its anchor; and a pin only on a certificate appended past the path, on
  an anchor that named the issuer and verified nothing, or on nothing,
  refused. bin/webpki_chain_test's test/webpki_chain_path.h pins
  `path_entries` and `anchor_index` on the corpus, on the captures, whose
  chains end at anchors 0, 2, 3 and 4, and on a root re-keyed under one
  Name. The webpki_pin CBMC harness proves both calls memory-safe at their
  real bounds and their verdict and alert pairs, that an accepted raw list
  is one entry whose bytes a pin hashes to, and that path pinning parses
  nothing past `path_entries` and hashes the anchor at `anchor_index`.
  The webpki_chain harness proves `path_entries` is the count of
  certificates the walk parsed and that the anchor at `anchor_index`
  verified the last one. spec/lean/Spec/WebpkiPin.lean models both rules and
  proves the raw one sound, and the differential compares the C and the
  model on the `webpki_raw` op and on `webpki_chain`'s path and pin
  verdict. The leaf rule under pins alone: test/webpki_leaf_pins.h runs
  every CertificateVerify row under a pin on its leaf to the row's own
  verdict, a signature the leaf key did not make included, and refuses a
  pin on the intermediate, the anchor's key or nothing with
  bad_certificate; it accepts leaves the walk refuses for a name, an
  extension or a date, refuses a refused key, counts entry 0 alone and
  refuses the walk's framing faults. bin/webpki_loop_tcp_nonblocking runs a leaf
  pin and an intermediate pin against this tree's tcp-nonblocking
  server, and test/e2e.sh against `openssl s_server`. The webpki_leaf_pin
  harness proves the call memory-safe and its verdict and alert pairs,
  that the key reader runs once and on entry 0, and that an accepted list
  hashed the leaf's SubjectPublicKeyInfo and returns its key; the
  webpki_cert_key harness proves that reader never calls the
  extensions reader. spec/lean/Spec/WebpkiPin.lean models the rule as
  `verifyLeafPin` and proves it sound, and the differential compares it
  with the C on the `webpki_leaf` op. Over QUIC, bin/quic_loop_webpki
  runs the chain rules against this tree's QUIC server
  (test/quic_loop_pins.h): a pin on the leaf, the intermediate or the
  anchor accepted, the last of `CH_SPKI_PIN_MAX` pins accepted, and a pin
  on nothing, on an anchor that verified nothing or on a CA certificate
  appended past the path refused with bad_certificate; under pins alone
  a pin on the leaf accepted and its ticket resumed under that pin alone,
  and a pin on the intermediate, the root or nothing refused. That server
  sends no raw public key, so the raw rule runs end to end over TCP
  alone. Fifteen `inv33-` violations guard the rules.
  inv33-quic-pins-ignored-on-chain and inv33-quic-pins-alone-leaf-refused
  change a QUIC build alone, which no TCP test sees, and require
  bin/quic_loop_webpki to fail.
- **Violation.** A PR accepts a raw key or a chain on the name alone,
  counts a certificate the walk never read, compares a pin with a key
  other than the one the walk or the reader returned, lets a pin on a CA
  key pass under pins alone, or skips CertificateVerify under the pinned
  leaf key.
- docs/server.md names INV-30 to INV-32 for server rules it plans, so
  this entry takes the next number after them.

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

### INV-25 — every reader fills its container

- **Claim.** A reader that decodes a container's fields requires those
  fields to fill it. A byte left inside a DER TLV, a TLS extension's
  `extension_data`, a length-prefixed vector or a handshake message
  body is a refusal, not something to ignore. Without the rule two
  encodings name one value: a certificate carrying a third Time inside
  its Validity SEQUENCE parses as the two dates beside it, and a
  NewSessionTicket with a byte after its extensions vector is handed to
  the application as a whole message. A field the profile skips unread
  is not an exception — `x509_skip` reads a whole TLV and
  `hsp_parse_encrypted_exts` reads `supported_groups` by its own
  length, so the container still ends where the field ends. The refusal
  is a `ch_err` return like any other bad peer input, so it kills the
  session: `handle_ticket` returns `CH_EPROTO` for a message its own
  fields do not fill, the same answer the KeyUpdate arm beside it gives
  a body that is not one byte long. It returns `CH_OK` and delivers
  nothing only for a message that does fill itself and that this client
  still cannot use, such as one whose nonce is longer than
  `SHA256_LEN`.
- **Mechanism.** Every container is read through an `rbuf` built over
  its own slice, and the reader that built it compares `rb_left` before
  it returns: `rb_left(&r) == 0` at the end, or a `len != rb_left(&r)`
  equality at the header. `pem.c` is the one reader whose check runs in
  a function it calls, `read_tail`. `webpki.c`'s `read_entries` is the
  one whose loop is the statement: it runs until the reader is empty and
  returns on every framing failure, so a success means the entries
  filled the list, and the list carries no length of its own to compare.
- **Check.** `make lint-exact-fill` (`tools/exact-fill.py`) reports a
  library function that builds an `rbuf` over a slice and never compares
  `rb_left` on it for equality, with that file's `ALLOWED` table holding
  the one reader that checks in a callee, `pem.c`'s, and its `WALKED`
  table the one that walks to the end, `webpki.c`'s. A `WALKED` entry
  holds only while the `while (rb_left(&r) > 0)` loop is still there, so
  a reader that stops walking is reported again. Semgrep-tripwire
  grade, and the exit codes below measure it rather than claim it. It
  catches a reader landed with no check at all; a reader whose only
  `rb_left` is a `while (rb_left(&r) > 0)` walk or a `> 0` guard on an
  optional field, which describes every list reader in the tree; and a
  check written against a different reader than the one it opened. It
  misses the deletion of one of several equality checks on one `rbuf`.
  Applying the four recorded webpki mutants to the sources and running
  the lint,
  `inv05-webpki-spki-trailing-byte` and
  `inv05-webpki-validity-trailing-byte` exit 1 and
  `inv05-webpki-rsa-key-trailing-byte` and
  `inv05-webpki-basic-constraints-past-sequence` exit 0, because in each
  of those two the reader's other equality survives the edit. The lint
  also cannot tell whether a check is right — `!= 0` where `== 0` was
  meant, a check on a path the parser can skip, or one that runs before
  the last field is read — and it merges a function's `#ifdef` arms,
  so a check in one arm answers for both.

  Boundary pairs hold what the lint cannot, one per container, in both
  directions: a container one byte longer than its fields fill, and a
  container whose length stops before its own fields do, which the
  closing `rb_left` never sees. `test/x509_exact_fill.h` covers the ca
  mode's reader and `test/x509_ca_tests.h` the provisioning reader,
  `test/webpki_cert_mutants.h`, `test/webpki_ext_mutants.h`,
  `test/webpki_spki_test.c` and `test/webpki_time_test.c` the webpki
  readers, `test/webpki_cert_key_mutants.h` the reader a leaf pinned
  with no anchor goes through, which skips the fields after the key as
  whole TLVs that must still fill their containers, `test/handshake_strict_test.c` the ServerHello and
  EncryptedExtensions vectors and the Certificate list,
  `test/p384_test.c` the P-384 signature, and
  `test/session_post_tests.h` the NewSessionTicket. `make diff` reads
  four of those containers a second time, against the Lean spec:
  `test/diff_handshake_certificate.h` puts a trailing octet past the
  certificate list and past the CertificateVerify signature, and
  `test/diff_handshake_parser.h` puts bytes inside the ServerHello and
  EncryptedExtensions messages and outside their extension vectors.

  The `inv25-` and `inv05-webpki-*` mutants in `test/violations/` require
  a named test to object, and each names one: `handshake_strict_test`
  for the Certificate list and the EncryptedExtensions vector,
  `x509strict` for the ca mode's Validity, `webpki_cert_test`,
  `webpki_spki_test` and `webpki_time_test` for the webpki readers,
  `p384_test` for the signature, `unit` for the NewSessionTicket, and
  `test/lint-exact-fill.sh` for the two shapes the lint itself is meant
  to report. Two readers in the list above carry no mutant yet: the
  ServerHello extension vector and the provisioning reader in
  `x509_ca.c`.
- **Violation.** A PR adds a reader that decodes what it needs and
  returns, leaving the rest of the container unread because "the
  length already bounds it".
- See [decisions: Trust model](decisions.md#trust-model).

## Timing

### INV-16 — constant time where secrets flow

- **Claim.** No branch and no memory index depends on a secret, and no
  instruction the compiler emits for one does either. Comparisons on
  secret data go through `ct_memeq`, selects through branchless masks.
  Variable time is allowed only where every input is public, stated at
  the call site — P-256 and RSA verify, the HRR-magic compare in
  handshake_parser.c and the ALPN name compare in
  handshake_parser_ee.c.
  That second half is why `ct.h` builds widening products out of 16x16
  pieces on every architecture, unless the build asserts
  `CH_NATIVE_WIDEMUL` for a part whose own widening multiply is
  constant-time. No architecture macro carries that claim, so the header
  names no architecture: the header records why, and the Makefile passes
  the flag for host test binaries only, filtering it out of the packaged
  object. A Cortex-M3 ran 35 variable-time products before and runs none
  in poly1305, mlkem_poly or x25519 now, under clang and under the Arm
  GNU gcc alike: gcc fused eight of them back until the rework in ct.h
  and x25519.c removed the two forms it rewrote
  ([#106](https://github.com/c4milo/chapulin/issues/106)). One remains
  in sha3 under every compiler, `% 5` over Keccak's public loop
  counters, which divides no secret.
  The decomposition is also what makes every other proof describe the
  target: those formulas verify the single-multiply form, and
  `proof/ctwidemul_harness.c` proves the two forms compute the same
  product at 8-bit operands, the widest bound whose formula converges.
  The x25519 ladder proofs rest on a product bound instead, and
  `proof/x25519_mul_ct_harness.c` proves it on the decomposition at the
  ladder's full operand range.
  The `X25519=wide` field multiplies on a different instruction, the
  64x64->128 multiply, and `ct.h` refuses that build unless it asserts
  `CH_NATIVE_MUL128`, the same claim about that instruction, and unless
  the compiler has `unsigned __int128`. `test/x25519-builds.sh` checks
  both refusals in `make check` (decision 52).
- **Mechanism.** Constant-time construction; ChaCha20/Poly1305/x25519
  have no table lookups by design.
- **Check.** Semgrep-structural (`inv-16-no-variable-time-compare`) bans
  memcmp/strcmp in library sources, with handshake_parser.c and
  handshake_parser_ee.c allowlisted for their public-data compares — the
  allowlist is file-wide, so review holds the line on any new compare
  added to either file; `make timing` (Welch's
  t-test) gives statistical evidence.
  Semgrep cannot know a buffer is secret — the real guards remain
  construction and the t-test.
  Those two see source text and one host's timing, and neither can see
  what the compiler emits, which is the gap this invariant was missing:
  KyberSlash and the Cortex-M3 multiply are both instruction selection,
  not source. Two build-time checks close it, each over every source a
  secret passes through (`CODEGEN_SRCS` in the Makefile;
  `lint-codegen-partition` holds every library source in that list or
  in `WIDEMUL_PUBLIC`, the public-key and certificate sources that
  multiply over bytes the peer sent in the clear, and never in both).
  `lint-wide-multiply` compiles for Cortex-M3, mips32r2 and rv32imac
  under the pinned clang, and `lint-wide-multiply-gcc` under the gcc
  each CI lane ships, and counts per file the widening multiplies, the
  divisions and the 64-bit division runtime calls, each opcode matched
  as a prefix so `umullne` counts as `umull`; every file holds a
  recorded ceiling, zero except sha3's public `% 5` and, under the
  mips gcc at `-O2`, the two `madd` poly1305's block gets on 16-bit
  operands ([#122](https://github.com/c4milo/chapulin/issues/122)).
  The same pass counts the conditional branches — `b<cond>`, `cbz`,
  `cbnz`, the table branches and the IT instruction on arm; `beq`,
  `bne` and the compare-with-zero forms on mips; the six base branches
  and the compressed pair on rv32 — in the twelve arithmetic files
  under the record layer (`BRANCH_SRCS`) and holds each at a ceiling
  measured per compiler (`BRANCH_CEILING`). Those ceilings are not
  zero: ct.c's two loops, the block loops, x25519's ladder, Keccak's
  round and lane counters and softmul's fixed 32 and 64 iterations all
  branch on public counts, and the count cannot tell those from a
  branch on a limb. What it holds is that no count grows. What the
  ceilings record is a choice each compiler made: the compare-carries
  in `ct_widemul_opaque` and the sign masks in `ct_widemul_s`, `cswap`
  and `poly1305_final` are branch-free in C, and every compiler in the
  table lowers them to a predicated instruction, `sltu` or a shift —
  until this count, nothing held it to that
  ([#141](https://github.com/c4milo/chapulin/issues/141)).
  `inv16-poly1305-final-sign-branch` writes the final select as an
  `if` on the last limb's sign and the count rises by one under all
  eight specs; `inv16-widemul-s-sign-branch` writes `ct_widemul_s`'s
  corrections as `if`s on the operands' signs, which clang lowers back
  to the mask and every gcc lowers to two branches in x25519, so only
  the gcc gate sees it.
  No spec above can compile `x25519_wide.c`, because none of their
  targets has `unsigned __int128`, so two 64-bit specs compile it and
  nothing else (`WIDE64_CEILING`): arm64 and x86-64 under the pinned
  clang, with the defines an `X25519=wide` build states. They hold its
  divisions and 128-bit runtime calls at zero and its conditional
  branches at 16 and 20, every one loop control over a public count.
  `inv16-x25519-wide-cswap-branch` writes that field's `cswap` as an
  `if` on the scalar bit and both counts rise by two. No gcc spec
  measures the file: no CI lane runs a 64-bit gcc through
  `lint-wide-multiply-gcc`.
  `lint-runtime-symbols` builds for rv32ic, where
  there is no multiplier at all, and holds per file the runtime-library
  calls it may make — `softmul.c` supplies constant-time `__mulsi3` and
  `__muldi3` so the library's branching ones are never linked, and the
  gate asserts it still defines them; the rv32ic gcc spec holds
  `softmul.c` at zero calls to `__muldi3`, because gcc at `-Os` once
  emitted one from inside `__muldi3` itself. Twenty `inv16-*` violations
  in `test/violations/` prove each detection catches its mutant, among
  them `inv16-x25519-wide-without-timing-assertion`, which drops `ct.h`'s
  refusal of an `X25519=wide` build without `CH_NATIVE_MUL128` and which
  `test/x25519-builds.sh` catches. Four
  of them catch only under a gcc gate: `inv16-widemul-mid-widened` and
  `inv16-widemul-s-sign-branch` under `lint-wide-multiply-gcc`'s Arm
  gcc, `inv16-widemul-compare-carries` in the mips lane, and
  `inv16-softmul-mask-as-negate` in the riscv32 lane. Both count
  instructions; neither checks an answer. `make
  ct-widemul-check` (in `check-slow`) runs the unit, ML-KEM and
  Wycheproof vectors over the decomposition itself, which every other
  host binary compiles out, and `make test-invariants` requires it to
  fail on a dropped carry in either recombination and on a narrowed
  `ct_widemul_opaque` operand.
- **Violation.** A PR compares a binder or tag with memcmp because
  the linker size looked better.
- See [decisions: Cryptography](decisions.md#cryptography).

### INV-26 — AES sees three public keys, and traffic keys only under a suite build

- **Claim.** Under `TRANSPORT=quic-nonblocking` this tree carries an AES-128, and
  every key it is given is public. `aes.c` derives the keys and
  `gcm.c` builds the AEAD on them; the key expansion and the block
  cipher sit in whichever of `quic_aes_soft.c`, `aes_hw.c` and
  `quic_aes_extern.c` the Makefile `AES` variable picked, behind the
  contract `aes_block.h` states. Under `AES=hw`, GHASH's multiply by
  the hash subkey also moves out of `gcm.c`, into `ghash_hw.c`
  on the carry-less multiply, behind `ghash_hw.h`; the hash subkey
  is the forward cipher of a zero block under the same key, so it is
  public exactly when that key is. Only `AES=soft` is table-driven,
  and the claim below is what lets that one exist; it binds all three
  the same way, because `AES=extern` cannot state its timing either. There are three: the packet protection key and the header
  protection key, both expanded from `HKDF-Extract` over RFC 9001
  §5.2's printed salt and the Destination Connection ID the caller
  supplied, and the 16-byte constant RFC 9001 §5.8 prints for the Retry
  integrity tag. RFC 9001 §5 draws the conclusion for the first two
  itself: anyone can compute them, so Initial packets have no
  confidentiality or integrity protection. Outside a
  `-DCH_SUITE_AES_GCM` build no traffic secret `keysched.c` derives is
  passed to AES, and AES is never a cipher suite. No field of `ch_quic`
  holds an AES key, and no AES key outlives the call that built it.

  A `-DCH_SUITE_AES_GCM` build adds the second claim, and the traffic
  keys of two suites. That build holds `TLS_AES_128_GCM_SHA256` and
  `TLS_AES_256_GCM_SHA384` (decisions.md 45 and 58), so AES runs under
  keys the TLS key schedule derives, 16 or 32 bytes by the suite, and
  every one is secret: `record.c`'s record key, and under
  `TRANSPORT=quic-nonblocking` `quic_packet.c`'s packet protection key and header
  protection key for the Handshake and 1-RTT levels (RFC 9001 §5.3,
  §5.4.3). The Initial level keeps AES-128-GCM under its public keys in
  every build. Three things bound the traffic keys. `ct.h` refuses the
  define unless the build takes `AES=hw` and also defines
  `CH_NATIVE_AES`, which is the build asserting that this part's AES
  instructions and its carry-less multiply run in constant time — so
  the table-driven `AES=soft` S-box never sees a secret key, and neither
  does `AES=extern`, which cannot state its timing. The key has its own type, `aes_traffic_key`,
  whose body lives in `aes_traffic_key.h` alone, so it cannot be passed
  where an `aes_public_key` is expected or the reverse. And `record.c`
  and `quic_packet.c` expand it on their own frame at each use and wipe
  it there, so no schedule outlives the record, the packet or the mask it
  protected, and no `rec_dir`, `quic_keys` or `quic_hp_key` holds one.

  The mechanism grew with the claim, and the growth is the cost. Two
  headers give a key a body: `aes_public_key.h` for `aes_public_key`, which
  `aes.c`, `quic_initial.c`, `quic_retry.c` and `gcm.c`
  include, and `aes_traffic_key.h` for `aes_traffic_key`, which
  `aes.c`, `gcm.c`, `record.c` and `quic_packet.c` include.
  `tools/quic-footprint.py` holds each list, and `make
  lint-quic-surface` fails on any other reader. `gcm.c` reads the
  round keys out of either key type to run the AEAD. What holds is the
  part that matters: no file outside those lists can build a key of
  either kind, `inv-26-aes-public-keys-only` still matches every call
  into the `aes_` and `gcm_` families but the two traffic families,
  outside the public-key callers, and
  `inv-26-aes-traffic-keys-only` matches every call into the
  `aes_traffic_` and `gcm_traffic_` families outside `record.c` and
  `quic_packet.c`.

  A TLS cipher suite whose AEAD is AES-GCM encrypts application data
  under `hkdf_expand_label(hash_len, secret, "key", ...)` over a traffic
  secret, the key the first claim keeps from AES. `-DCH_SUITE_AES_GCM` is
  how a build declares such a suite, and `ct.h` refuses it unless the
  build also takes `AES=hw` and asserts `CH_NATIVE_AES`. The rest of this
  entry says what that build owes and what holds it. `docs/server.md`,
  "AES-GCM becomes a cipher suite carrying user data, in two key sizes",
  is the design record.
- **Mechanism.** No stored key is the first part, and the compiler is
  the second.

  `ch_quic` stores the Destination Connection ID, in `initial_dcid` and
  `initial_dcid_len`, and no Initial key. `quic_initial.c` and
  `quic_retry.c` build the one key each call needs on their own stack
  and let it die with the frame. So there is no long-lived key object to
  overwrite, which is what the earlier design left open: `ch_quic` held
  `initial_rx` and `initial_tx`, any file that saw the session struct
  could write `q->initial_tx.key.round_keys`, and `quic_initial.c` then
  passed that struct to `aes_encrypt_block` as a permitted caller.
  `test/violations/inv26-secret-into-stored-key.violation` is that
  exact edit and requires `test/quic-builds.sh` to fail.

  The type is now opaque outside three sources. `aes.h` declares
  `typedef struct aes_public_key aes_public_key;` and stops;
  `aes_public_key.h` holds the body, and `aes.c`, `quic_initial.c`
  and `quic_retry.c` are the only sources that include it. Every other
  file sees an incomplete type, so `aes_public_key k;`,
  `aes_public_key k[1];`, `*dst = *src;` and any write to a field are
  each a compiler error rather than a pattern someone has to match.
  Zero heap does not forbid this, because nothing stores a key by value
  any more: the three sources that need the body are the three that
  build a key on a stack frame, and they include the header that has
  it.

  The memory cost is measured and the time cost is not.
  `sizeof(ch_quic)` falls from 2,688 to 1,976 bytes, because two
  364-byte `aes_public_key` values become 21 bytes of connection ID.
  Deriving per use costs one HKDF-Extract, three HKDF-Expand-Label calls
  and two key expansions per packet per direction, and no bench in this
  tree times them. One `aes_public_key` is 364 bytes against a
  2,560-byte budget, and `make lint-stack TRANSPORT=quic-nonblocking` measures every
  frame that builds one in each `make check`.

  **What the change does not do.** A covered file can write a traffic
  secret into `q->initial_dcid` instead, and the constructor will derive
  an AES key from it. That is safer than the shape it replaces, and the
  reason is what sits between the two. In the old shape the bytes
  written landed in `round_keys`, `add_round_key` exclusive-ored round
  key 0 into a counter block the attacker knows, and `sub_bytes` indexed
  the 256-byte S-box with `counter ^ key`; cache-line timing on that
  index returns the high bits of the key bytes, which are the secret's
  own bytes. In the new shape the bytes written are the input to
  `hkdf_extract`, then to three `hkdf_expand_label` calls, before
  `aes_expand_round_keys` runs. `hkdf.c` is HMAC-SHA-256 throughout: the one branch in
  `hmac_sha256` reads `key_len`, the loops run counts the caller chose,
  and the only table `sha256.c` holds, `K[64]`, is indexed by the round
  number. Two checks hold that rather than leaving it argued.
  `WIDEMUL_CEILING` carries `hkdf.c:0` and `sha256.c:0`, so neither file
  may emit a wide multiply at all, and `lint-wide-multiply` records each
  file's conditional-branch count per compiler and target — 13 and 17 on
  m3 with the pinned clang — and fails when one grows, which is how a
  branch a compiler puts on secret bytes shows. So the value the S-box is
  indexed with is
  an HKDF output, and an attacker who recovers it holds the Initial
  packet protection key — which RFC 9001 §5 says anyone can compute
  anyway — and would have to invert HMAC-SHA-256 to get back to what
  was written. The write is still wrong and still breaks the
  connection; it no longer leaks the secret through the table.

  Three more checks hold the rule from other directions.
  `lint-quic-surface` reads the premise the Semgrep rule rests on.
  `lint-codegen-partition` keeps `aes.c`, `gcm.c`, the
  three AES implementations and `ghash_hw.c` in `WIDEMUL_PUBLIC`,
  the list whose own comment says a secret arriving in any of these is a
  design change, so moving one of them to `WIDEMUL_CEILING` is a diff a
  reviewer looks for. That also says what these six files do not get: no codegen gate
  compiles them, so `lint-wide-multiply` counts no branch of theirs. A
  change that gave AES a secret key would owe those entries. `lib-check` diffs
  the packaged object's exports against `PUBLIC`, which holds no `aes_`
  or `gcm_` symbol, so no caller outside this tree reuses the cipher on
  something else.
  `lint-trust-separation` holds the `AES` axis to one implementation per
  object. All three define the same two entries, so a second one would
  not link, but a linker says nothing about which implementation an
  object ended up with; the lint reads the packaged source list per axis
  value instead. Its `AES=hw` row requires `ghash_hw.c` beside
  `aes_hw.c`, and every other row bans it.
  `test/violations/aes-two-implementations-in-one-object.violation` is
  the mutant that proves it fires, and
  `aes-hw-diverges-from-soft.violation` breaks the `AES=hw` key
  expansion and requires `bin/aes_equiv_test` to fail, which is what
  holds the path no proof reaches (docs/quic.md, "What the AES axis
  proves"). `ghash-hw-reduction-constant.violation` and
  `ghash-hw-cross-product-halves-swapped.violation` break the `AES=hw`
  GHASH multiply and require `bin/ghash_equiv_test` to fail.
  `ghash-hw-falls-back-to-portable.violation` lets an `AES=hw` build of
  `gcm.c` run the portable multiply and requires
  `test/quic-builds.sh` to fail, and
  `ghash-hw-source-unpackaged.violation` drops `ghash_hw.c` from
  the `AES=hw` sources and requires `test/lint-trust-separation.sh` to
  fail.

  **What a secret AES key needs, and what holds it.** The entry above
  used to say only that moving these files out of `WIDEMUL_PUBLIC` was a
  diff a reviewer looks for. Four of the five have moved, and the rest of
  the list is here so the suite build's bill is written down rather than
  rediscovered.

  *One implementation, not three.* `AES=soft` reads a 256-byte S-box at an
  index computed from the key. `aes_expand_round_keys` substitutes the
  key's own bytes before a block runs, so the leak is there before any
  plaintext exists, and `sub_bytes` substitutes `counter ^ round_key` once
  per round. `gcm_ghash` inherits it: the hash subkey H is
  `aes_encrypt_block` of a zero block, so an `AES=soft` build leaks H
  through the same table even though `multiply_by_subkey` is branchless
  and index-free. `AES=extern` cannot state its timing at all, because
  what `ch_aes_block` costs belongs to the peripheral. So `AES=hw` is the
  only value a secret key may take, and `ct.h` is where that is written:
  `-DCH_SUITE_AES_GCM` without `CH_AES_HW` is a compile error, not a
  silent fall back to the default.

  *The instruction's timing is asserted, not detected.* `__ARM_FEATURE_AES`
  and `__AES__` say the AES instructions exist, and `__ARM_FEATURE_AES`
  and `__PCLMUL__` say the carry-less multiply exists. None says the
  latency is independent of the operands, and the architectures do not
  promise it either -- Arm publishes FEAT_DIT and Intel publishes DOITM because
  the base architectures leave it to the implementation. `ct.h` already
  refuses that inference for the widening multiply and asks the build for
  `CH_NATIVE_WIDEMUL` instead
  ([#53](https://github.com/c4milo/chapulin/issues/53)). The AES path
  follows it: `CH_NATIVE_AES` is the build's assertion, for the AES
  instructions and for the carry-less multiply GHASH runs on under
  `AES=hw` (`docs/decisions.md` entry 50), firmware defines it only with
  a vendor statement that covers both, and `ct.h` refuses
  `-DCH_SUITE_AES_GCM` without it. This is an assertion and not a check,
  and it is the weakest link in the list; what it buys is that the claim
  is written in the image's build files by someone who can answer for it,
  rather than inferred from a macro that does not carry it.

  *The codegen gates now measure these files.* `aes.c`,
  `quic_aes_soft.c`, `quic_aes_extern.c` and `gcm.c` moved from
  `WIDEMUL_PUBLIC` into `WIDEMUL_CEILING` at 0, and into `BRANCH_SRCS`
  with a measured branch count per spec in `BRANCH_CEILING`. Before that
  no gate compiled them, so nothing held `multiply_by_subkey`'s two masks
  to a branchless lowering -- the same select `lint-wide-multiply` holds
  for `poly1305_final` and `cswap`. `aes_hw.c` and `ghash_hw.c`
  stay in `WIDEMUL_PUBLIC` because they cannot join: every spec targets a
  core without the AES or carry-less multiply instructions, where each
  file is its own `#error`. `test/aes_equiv_test.c`,
  `test/ghash_equiv_test.c`, the published vectors in `bin/quic_test_hw`,
  the Wycheproof AES-GCM suite on that leg and `bin/diff_quic_hw` are what
  hold them, and none of them is a timing measurement.

  *Key material is wiped where a secret could sit.* `gcm.c` wipes the
  hash subkey, the running multiple in the GF(2^128) multiply, the
  keystream block, the tag mask and the tag it computed for comparison;
  `aes_hw.c` wipes its key-schedule word and its cipher state;
  `ghash_hw.c` wipes the object that holds the hash subkey, the
  accumulator and the unreduced product once at the end of each entry,
  not once per block. Two
  places deliberately hold no wipe. `quic_aes_soft.c` holds none because
  `ct.h` keeps every secret key away from it, so the stores would cost a
  device something for nothing. `aes_public_key_initial` holds none
  because it derives the Initial keys and nothing else, and those are
  public under every build. Nothing in this tree checks that a wipe is
  present; review does.

  *The round keys themselves are still the caller's.* The round keys live
  in an `aes_public_key` on a `quic_initial.c` or `quic_retry.c` stack
  frame, and both files are stubs today, so there is no frame to wipe and
  no entry that wipes one. The commit that implements them owes that call.
- **Check.** The compiler, `make lint-quic-surface`,
  `make lint-trust-separation`, `make lint-wide-multiply`, and a
  Semgrep tripwire (`inv-26-aes-public-keys-only`) over every library
  source but `quic_initial.c` and `quic_retry.c`, the two permitted
  callers, with `aes.c`, `gcm.c`, the three AES
  implementations and `ghash_hw.c` excluded as the definition
  sites.

  What `ct.h` refuses, and `test/quic-builds.sh` is the catch target for
  all three lines: `-DCH_SUITE_AES_GCM` without `CH_AES_HW`, and
  `-DCH_SUITE_AES_GCM` without `CH_NATIVE_AES`. The script compiles one
  translation unit that reads `ct.h` and nothing else, four times -- the
  build that states both must compile, and each refusal is checked on its
  own so a build that dropped one cannot hide behind the other.
  `inv26-aes-suite-without-hardware.violation` deletes the first `#error`
  and `inv26-aes-suite-without-vendor-statement.violation` the second, and
  each requires that script to fail.
  `inv16-ghash-subkey-select-branch.violation` writes
  `multiply_by_subkey`'s mask as an `if` on the accumulator bit and
  requires `test/lint-wide-multiply.sh` to fail, which is what the new
  `BRANCH_SRCS` entries buy.

  The same two refusals hold over QUIC, where `quic_packet.c` hands AES
  the Handshake and 1-RTT keys: `test/quic-builds.sh` compiles
  `quic_packet.c` under the suite with `AES=hw` and `CH_NATIVE_AES` and
  requires it to compile, and without `CH_NATIVE_AES` and requires ct.h
  to refuse it. `inv26-quic-suite-without-vendor-statement.violation`
  lets a QUIC build past the second refusal. `quic_aes_soft.c` refuses
  the suite on its own, for a tree that compiles it without reading
  ct.h, and `inv26-soft-aes-under-suite.violation` removes that refusal;
  the script fails on both.

  What holds the traffic keys. `inv26-traffic-key-into-public-entry`
  seals a record through `gcm_seal`, the public-key entry, and requires
  `test/lint-invariants.sh` to fail.
  `inv26-traffic-key-header-extra-reader` includes `aes_traffic_key.h`
  in `handshake_post.c` and requires `test/lint-quic-surface.sh` to
  fail. `inv26-aes256-test-define-in-object` packages the software
  AES-256 and requires `test/lint-trust-separation.sh` to fail.
  `aes256-traffic-key-wrong-round-count` records AES-128's round count
  beside an AES-256 schedule and requires the `aes_traffic` proof
  to fail, and `aes256-schedule-one-round-key-short` stops the `AES=hw`
  AES-256 expansion one round key short and requires
  `bin/aes_equiv_test` to fail. `inv26-quic-hp-key-cut-to-aes128` keys
  QUIC header protection with 16 bytes under every AES suite and
  requires `bin/quic_suite_test`, which checks an AES-256 packet byte for
  byte against an independent computation, to fail; the
  `quic_packet_suite` proof asserts the key length too.

  What the compiler refuses, in any source that does not include
  `aes_public_key.h`: declaring an `aes_public_key`, declaring an array of
  them, assigning one, and writing a field of one. `quic.h` declares no
  member of that type, so `q->initial_tx.key.round_keys` names nothing.

  What the Semgrep rule reads, in two branches. The family is `aes_`,
  `gcm_` and `ch_aes_`; the third is there because an `AES=extern`
  build leaves `ch_aes_block` to the image, and a library source calling
  it would run AES on a key of its choosing exactly as a call to `aes_`
  would. The three implementation sources join `aes.c` and
  `gcm.c` on the exclude list, as definition sites.
  - *A call* to a name beginning `aes_`, `gcm_` or `ch_aes_`.
    `test/violations/inv26-aes-on-traffic-key.violation` seals a 1-RTT
    packet with `aes_encrypt_block` over a `quic_keys` set,
    `inv26-gcm-on-traffic-key.violation` opens one with `gcm_open`, and
    `inv26-aes-mask-on-1rtt-path.violation` writes `quic_hp_mask` with
    the §5.4.3 AES form over a key `quic_hp_key_init` derived from a
    traffic secret. Each requires `test/lint-invariants.sh` to fail.
  - *The same name as a value*: `&aes_encrypt_block`, a function pointer
    initialized or assigned from the name, the name passed as an
    argument. The call branch reads none of these, because the later
    call through the pointer names no `aes_` symbol at all, so taking
    the address alone used to defeat the rule.
    `inv26-aes-entry-taken-as-value.violation` is that edit and requires
    `test/lint-invariants.sh` to fail.

  The rule carried two initializer patterns, `aes_public_key $K = ...;`
  and `aes_key_schedule $K = ...;`, and they are gone. An initializer
  needs the type's body, and outside the three sources there is no body,
  so the branch had nothing left to catch that the compiler does not
  catch first.

  What `make lint-quic-surface` reads, so the rule's own premise is
  checked rather than assumed. It fails when `aes.h`,
  `aes_block.h`, `gcm.h` or `ghash_hw.h` declares a
  function or a function-like macro outside the `aes_`, `gcm_` and
  `ch_aes_` family, because the rule matches names;
  `inv26-cipher-entry-off-prefix.violation` adds a `quic_encrypt_block`
  entry and requires `test/lint-quic-surface.sh` to fail. It fails when
  either header gives a type a body, because that would put a key back
  within reach of every file that includes them. And it fails when any
  root source outside `aes.c`, `quic_initial.c` and `quic_retry.c`
  includes `aes_public_key.h`, which is the one line that undoes the
  opacity; `inv26-key-header-fourth-reader.violation` adds that include
  to `quic_packet.c` and requires `test/lint-quic-surface.sh` to fail.
  `tools/quic-footprint.py` holds all three comparisons and prints their
  counts.

  One check holds the admitted code rather than its callers:
  `proof/aes_harness.c` proves the key expansion memory-safe at its
  real bound, and `inv26-aes-schedule-past-round-keys.violation` runs
  the schedule one word past `round_keys` and requires
  `proof/prove-one.sh aes` to fail.

  **What review still owes.** Three shapes, and no check in this tree
  reads any of them.
  - *A function-like macro whose body holds the call.* A source that is
    not one of the two permitted callers writes
    `#define MASK(k, s, o) aes_encrypt_block_hp(k, s, o)` and calls
    `MASK`. Semgrep parses C expressions, not macro bodies, so neither
    branch fires. `lint-quic-surface` reads the macros `aes.h` and
    `gcm.h` declare, not the macros other files define.
  - *Token pasting.* `#define CIPHER(stem) aes_##stem`, called as
    `CIPHER(encrypt_block)(...)`, puts no `aes_` identifier in the file
    at all, so there is no name for the rule to read.
  - *A traffic secret written into `initial_dcid`.* The field is public
    by design and the derivation is constant time, so the leak the
    invariant exists to prevent does not follow, but the write is still
    a key the TLS key schedule derived being fed to this path. A diff
    that writes `initial_dcid` from anything but a connection ID the
    caller passed is the shape to stop.

  Tripwire grade, for the reason INV-5 states: the Semgrep rule matches
  names, so it catches honest drift, not a reintroduction under another
  name. The compiler's half of this invariant is not a tripwire — an
  incomplete type refuses every spelling of the same edit — but the
  allowlist that keeps it incomplete is one, and a fourth name added to
  `KEY_HOLDERS` in `tools/quic-footprint.py` is a diff a reviewer looks
  for.
- **Violation.** A PR reuses `aes_encrypt_block` for the 1-RTT header
  protection mask, or seals a Handshake packet with `gcm_seal`, so a key
  `keysched.c` derived indexes a lookup table and the gain
  `docs/decisions.md` entry 6 states is gone.
- See [decisions: Cryptography](decisions.md#cryptography) and
  [quic](quic.md).

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
  EncryptedExtensions, no certificate flight after a ServerHello that
  selected the PSK, Certificate then CertificateVerify then Finished
  when the server authenticates with a certificate, which under
  TRUST=webpki includes a server that declined the ticket the hello
  offered, at most one HelloRetryRequest and only as the
  opening message, no ticket, key update, or application data before
  the Finished, and no record read after a close_notify. The order is
  the same whether the certificate is checked against a pinned server
  key (a raw mode) or a pinned CA (a CA mode).
- A close_notify closes its sender's direction and no other (RFC 9846
  §6, rfc9846.txt:3767-3768, and §6.1, rfc9846.txt:3857-3864), and this
  holds for either role, because the client and the server read through
  the one `ch_read`. The `ch_read` that reads the peer's close_notify
  returns 0, sends nothing and leaves `ch_tls.state` at
  `CH_ST_CONNECTED` with `ch_tls.read_closed` set. Every later
  `ch_read` returns 0 without calling `cfg.recv`, so a record the peer
  sends after its close_notify is never read, which is how §6.1's rule
  that such data MUST be ignored is kept (rfc9846.txt:3837-3839).
  `ch_write` keeps sending, and `ch_close` sends this side's
  close_notify and sets `CH_ST_CLOSED`.
- **Mechanism.** The server writes its own flight in the order the
  client reads it, by call position in `srv_handshake.c`,
  `srv_tcp_nonblocking.c` and `srv_quic.c`, and sends its one
  NewSessionTicket after the client Finished verifies and never with the
  flight. `handshake.c` reads the flight as a straight line —
  `hello_exchange`, then `hsa_server_auth`, then `expect_finished` — and
  each step compares the message type against the one it expects,
  answering `ALERT_UNEXPECTED_MESSAGE` otherwise. There is no state
  variable to desynchronize; the order is the call order. Every one of
  those type checks sits outside the `CH_TRUST_CA` conditionals, which
  only add chain verification between Certificate and
  CertificateVerify, so both trust builds compile the same order from
  the same lines. All three client drivers take the one fork in the
  order from `ch_tls.psk_selected`, which `hsf_accept_server_hello`
  writes from the ServerHello, and not from `cfg.psk`, which says only
  what the hello offered. After the handshake, `tls.c`'s
  `dispatch_one_record` answers a close_notify with `close_read_side`,
  which wipes the read secrets and sets `read_closed`, and `ch_read` tests
  `read_closed` before it reads a record. Nothing on that path calls
  `ch_close` or `tlsi_send_alert`, and `ch_write` does not test
  `read_closed`.
- **Check.** Lean theorem (17 in `Spec/Handshake.lean`, over every
  trace the model admits; `accepts_decompose` bounds the flight at 4
  messages in the spec's `psk` Mode and 6 in its `pinned` Mode);
  `handshake_sequence_test`, exhaustive over 466,286 sequences — all eleven letters
  to depth 5, and the six handshake letters to depth 6 so the longest
  flight the model admits is reached — in both auth modes, comparing
  the real client's verdict against that model. It links a raw-mode
  only, so the CA build's order rests on the shared lines named above
  plus the e2e run, not on the oracle; CBMC (`handshake` harness) for
  memory safety only, not for order. The server's side is tested, not
  proved: a resumed flight of EncryptedExtensions and Finished alone is
  counted by bin/tcp_nonblocking_loop_test and bin/quic_loop_test and resumed by
  s_client in test/e2e.sh, and three `srv-certificate-on-resumed-`
  violations, one per driver, require each to object to a Certificate in
  it. The TRUST=webpki fork is tested per driver: the declined-ticket
  rows of bin/webpki_resume_test, bin/webpki_resume_tcp_nonblocking,
  bin/webpki_loop_tcp_nonblocking and bin/quic_loop_webpki, and test/e2e.sh's
  webpki-resume-declined leg against a second s_server.
  `inv22-webpki-decline-fails-closed`, `inv22-webpki-fallback-reports-psk`
  and one `inv22-*-driver-forks-on-cfg-psk` violation per driver require
  them to fail, and the quic_step harness proves the QUIC table takes
  the fork from `psk_selected`.
  The server reads the client's side the same way: a tcp-nonblocking server
  stops at the record that completes the handshake, so application data
  the client sends in the same delivery as its Finished is left for
  `ch_read` rather than read by the finished handshake.
  `test/tcp_nonblocking_coalesced_tests.h` delivers the Finished and one
  application record in one `ch_srv_record_in` call, and
  `test/violations/inv22-srv-record-in-reads-past-finished.violation`
  keeps the loop going past the Finished and requires
  `bin/tcp_nonblocking_loop_test` to fail. A QUIC server refuses what the
  same delivery carries after the Finished instead, because RFC 9001
  §4.1.3 makes those bytes data at a level it is leaving, and it refuses
  them before `srv_complete` empties `cfg.buf`. `test/quic_loop_close.h`
  delivers a Finished and a KeyUpdate in one `ch_srv_quic_crypto_in` call
  and requires 0x010a (RFC 9001 §6) and no ticket, and
  `test/violations/inv22-srv-quic-drops-bytes-after-finished.violation`
  removes the refusal and requires `bin/quic_loop_test` to fail.
  The close_notify rule is tested three ways, not proved: `tls.c` has
  no harness (README, "These rest on tests, not proofs"). `bin/unit`'s
  `test_peer_close_notify` (`test/session_post_tests.h`) queues a record
  behind the close_notify and requires every later `ch_read` to return 0
  with the record unread, no send call, and `ch_write` and `ch_close`
  to send under the write key. `bin/tcp_nonblocking_loop_test`
  (`test/tcp_nonblocking_close_tests.h`) closes one direction at a time
  between the two tcp-nonblocking drivers and counts each end's send calls, so the
  `ch_read` that reads a close_notify is measured to send nothing, on
  the client and on the server. `test/e2e.sh`'s go-half-close leg runs
  it against Go's `CloseWrite`, which sends a close_notify and keeps
  reading: the server logs the lines the client sent after that
  close_notify, then the client's own. Three violations each break one
  term: `inv22-read-answers-close-notify`, which `bin/tcp_nonblocking_loop_test`
  catches, and `inv22-read-past-close-notify` and
  `inv22-write-refused-after-close-notify`, which `bin/unit` catches.
- **Violation.** A PR relaxes one type check to tolerate a message a
  peer "usually" sends early, and a flight with a skipped
  CertificateVerify authenticates. This is the SMACK and FREAK class:
  invisible to memory-safety proofs and to a golden-path e2e run. Or a
  PR answers the peer's close_notify with an immediate close_notify of
  its own, as TLS 1.2 required, which drops what this side still had
  to send and sends from inside a read.
- See [decisions: Cryptography](decisions.md#cryptography).

## Lifetime and state

### INV-17 — secrets die at phase boundaries

- **Claim.** Handshake secrets are wiped at CONNECTED; every failure
  path wipes through `tlsi_wipe`, or through `quic_fail` under
  `TRANSPORT=quic-nonblocking`; the DRBG erases its key forward after each output.
  The peer's close_notify is a phase boundary for the read direction
  alone. Nothing is read after it (INV-22), so the `ch_read` that reads
  it wipes every secret only a read uses: `ch_tls.rd`, `rd_secret` and
  `res_master`, which only taking a NewSessionTicket uses. It keeps `wr` and
  `wr_secret`, because the write direction stays open, and `exp_master`,
  because `ch_export` is not a read; `ch_close` wipes all of them, and
  so does a failure.
  The one exception is the QUIC failure path's write keys. `quic_fail`
  keeps, at each level whose write bit in `ch_quic.levels_ready` is set,
  the bytes that level seals with: `initial_dcid` and `initial_dcid_len`
  at the Initial level, `handshake_tx` and `handshake_hp_tx`, and `app_tx`
  and `app_hp_tx`. It wipes the write keys of a level whose bit is clear,
  every read key, `hs` and the traffic secrets, and clears every read bit.
  The kept keys serve one CONNECTION_CLOSE packet per level, which
  `ch_quic_seal_close` seals and then wipes that level's keys and clears
  its bit; `ch_quic_close` wipes any left (docs/decisions.md 57).
- **Mechanism.** Fail-closed policy plus fast-key-erasure
  construction in drbg.c. Under `TRANSPORT=quic-nonblocking`, both drivers fail
  through `quic_fail`, and the write bit is what admits the one close.
- **Check.** Convention; the wipe sits in the single `tlsi_fail`
  funnel, so review of that one function covers every error path. The
  QUIC exception is checked three ways. The `quic_driver` proof shows
  that every failure path in `quic.c` leaves no read key, no read bit,
  no traffic secret and no write key at a level without its bit, and that
  `ch_quic_seal_close` seals only for a failed session, once per level,
  wiping that level's keys. `bin/quic_driver_test` and
  `bin/quic_loop_test` (`test/quic_loop_close.h`) read the session's bytes
  after the failure and after each seal, for the client and for the
  server. Five violations each break one rule:
  `inv17-quic-fail-keeps-read-key`, `inv17-quic-close-sealed-twice`,
  `inv17-quic-close-keeps-write-key` and `inv17-quic-open-after-failure`,
  which `bin/quic_driver_test` catches, and
  `inv17-srv-quic-fails-without-close-keys`, which `bin/quic_loop_test`
  catches. One
  wipe inside a phase has a test: a `TRUST=webpki` client wipes the
  ML-KEM seed once the ServerHello selects x25519, and
  `inv17-x25519-keeps-mlkem-seed` requires `bin/webpki_session_test` to
  fail when it does not. A server that ran X25519MLKEM768 keeps the ML-KEM
  shared secret in `handshake_state.mlkem_ss` from the ServerHello to the
  key schedule, and `srv_kex_secret` wipes it on both exits with the
  x25519 key pair; the `srv_kex` harness proves it, and
  `inv17-srv-keeps-mlkem-secret` requires `bin/srv_flight_test` to fail
  when the wipe goes. The 32 bytes of encapsulation randomness die inside
  the call that drew them. The P-256 scalar of a secp256r1 exchange
  (decisions.md 63) lives in `handshake_state.p256_priv` from the draw to
  the key schedule on both sides: a webpki client draws it when a retry
  names secp256r1, wipes the first hello's x25519 and ML-KEM key pairs
  then, and wipes the scalar in `handshake_groups.c`'s `p256_secret`; a
  server draws it in `srv_kex_share` and wipes it in `srv_kex_secret`,
  each on both exits. The `handshake_groups` and `srv_kex` harnesses prove
  both wipes, and `inv17-client-keeps-p256-scalar` and
  `inv17-srv-keeps-p256-scalar` require `bin/webpki_session_test` and
  `bin/srv_flight_test` to fail when either goes. A `TRUST=webpki` client whose ticket a server
  declines wipes the PSK's early secret and binder key in
  `hsf_accept_server_hello`, the moment the ServerHello declines, and
  derives the early secret of no PSK in their place;
  `inv17-webpki-decline-keeps-psk-early-secret` requires
  `bin/webpki_resume_test` to fail when they survive. The read-direction
  wipe at the peer's close_notify sits in `tls.c`'s `close_read_side`,
  and `bin/unit`'s `test_peer_close_notify` reads the session's bytes
  after it: `rd`, `rd_secret` and `res_master` all zero, `wr` and
  `wr_secret` byte for byte what they were. Two violations each break
  one half: `inv17-close-notify-keeps-read-key` and
  `inv17-close-notify-wipes-write-key`, which `bin/unit` catches.
- **Violation.** A PR adds an early return between fail and wipe, or
  lets a failed QUIC session keep a read key, or a write key past its
  one close, or keeps the read key once the peer's close_notify has
  arrived, or wipes the write key there.
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
  build's budget. The budget is 2,560 bytes by default (measured worst:
  `rsa_vp1` at 2,400); 3,072 under `KEX=pq`, where
  `hsf_build_client_hello` holds ML-KEM's 2,400-byte decapsulation key
  (measured 2,640 with clang 23 on arm64); and 4,096 under
  `TRUST=webpki`, whose `rsa_vp1` verifies RSA-4096 over 128 limbs
  (measured 3,168 with clang 23 on arm64 and 3,128 with Arm GNU gcc 16.2
  on the Cortex-M3). ML-KEM's own sources, `KEX_HYBRID_SRCS`, get 6,656
  in every build that carries them, `KEX=pq`, every `TRUST=webpki`
  object (decisions.md 53) and every server role (decisions.md 54):
  K-PKE encrypt holds three polynomial vectors
  and two polynomials (measured worst: `mlk_pke_encrypt` at 5,744 with
  gcc 13.3 and 6,224 with clang 21 and 23 on arm64). That ceiling is
  per file, so a new buffer in any other file of those objects still
  fails at its build's budget. A server's own sources keep the 2,560-byte
  device budget: the largest, `srv_send_server_hello`, holds the
  1,120-byte hybrid share it answers with (measured 1,232 with clang 23
  on arm64). A device client that cannot spare the budget builds the
  classic key exchange; a server has no classic-only build.
- **Mechanism.** Compiler-enforced: `-Wvla` in global CFLAGS bans
  variable frames everywhere, and `make lint-stack` compiles the
  sources this build packages, under the defines it packages them
  with, at `-Wframe-larger-than=$(STACK_BUDGET)`, or
  `$(STACK_BUDGET_KEX_HYBRID)` for the ML-KEM sources, so the README's
  stack numbers are a compile-time contract, not a bench
  observation. Until the hybrid build landed the recipe iterated
  `$(SRCS)` without `$(LIB_DEF)`, so it measured the default build
  whatever PIN, TRUST or KEX asked for and no variant was ever
  checked; the pq frames are what exposed it. Host test mains are
  exempt from the frame budget; they keep vector tables in their
  frames.
- **Check.** Type-system grade (the compiler refuses); bench/sram.sh
  measures the whole-call-chain peaks the README reports. `make check`
  runs lint-stack for the build it was given through `lint`, and runs
  `make lint-stack TRUST=webpki` as a leg of its own, so plain `make
  check`, the target `make ci` runs on a pull request, holds the
  4,096-byte budget too. `make lint-stack ROLE=server TRUST=none` is
  another leg, the one that compiles the server's sources.
- **Violation.** A PR sizes a scratch buffer from a length field, or
  adds a frame that silently outgrows the smallest supported SRAM.
  `test/violations/inv19-webpki-object-frame.violation` is that mutant:
  a 5,000-byte buffer in `p256_ecdsa_verify`, which an rsa mode filters
  out of every other object, so only the `TRUST=webpki` leg compiles the
  file and objects.
- See [decisions: Memory and runtime](decisions.md#memory-and-runtime).
