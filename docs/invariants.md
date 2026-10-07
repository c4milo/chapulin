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
  caller's session struct, which INV-18 names per transport with its
  one exception, and in `cfg.buf`; no OS facilities are assumed.
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

### INV-4 — randomness only through one draw path

- **Claim.** The library takes every random byte through `rand_draw`
  (`rand_draw.h`), which calls the one source the build's entropy
  pattern names: `ch_rand_bytes` under `RAND=extern` and `RAND=drbg`,
  and under `RAND=session` the `rand_bytes` of the session's own
  `ch_cfg`, handed that session's `rand_io`. It draws at exactly ten
  sites in six files. A client draws at four of them:
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
  - `sign_rsa_pss` in `srv_auth.c` draws the 32-byte RSA-PSS salt each
    time the server signs with its RSA identity, and hands it to
    `rsa_pss_sign`, which draws nothing itself (decisions.md 77).
    `ch_srv_check` signs once at boot when that identity is
    provisioned, and `srv_sign_certificate_verify` signs once per
    handshake whose CertificateVerify uses rsa_pss_rsae_sha256.
    `p256_sign.c` draws nothing: it derives each ECDSA nonce from the
    key and the message by RFC 6979.

  Every site checks for a source that returns without writing:
  CH_ASSERT fires when the drawn bytes are all zero, and for the salt
  `rsa_pss_sign` checks the bytes it is handed. The two P-256 sites
  check a range instead. They draw again when a candidate falls outside
  [1, n-1], zero included, up to `P256_ECDH_DRAWS` times, and CH_ASSERT
  fires after the last one. A working generator fails that many draws
  with probability below 2^-128.

  Under `RAND=session` a session draws from its own source alone, and
  nothing falls back to `ch_rand_bytes`: the object neither defines nor
  imports it, and every init call and `ch_srv_check` refuse a NULL
  `rand_bytes` with `CH_EINVAL` before they draw or send anything.
- **Mechanism.** Which source `rand_draw` calls is a declared build
  choice with no default. `RAND=extern` leaves `ch_rand_bytes` an
  undefined import, so an image that defines no generator fails to
  link. `RAND=drbg` defines it with the reference generator in
  `drbg.c`, which faults on an unseeded draw. Its `ch_drbg_seed` takes
  the SHA-256 of the whole seed as the generator key, so every source
  the image concatenates into the seed counts, and faults on a seed
  shorter than `CH_DRBG_SEED_MIN`, 32 bytes (decisions.md 66).
  `RAND=session` puts the source in each session's `ch_cfg`, and
  `rand.h` then declares no `ch_rand_bytes`, so a library call to it
  does not compile. No build carries a fallback that quietly produces
  bytes. The `ROLE` and `TRUST` axes choose which of the six files a
  packaged object compiles:
  - `ROLE=client` compiles `handshake_flight.c`, and `TRUST=webpki`
    adds `handshake_groups.c`.
  - `ROLE=server` compiles `srv_flight.c`, `srv_kex.c`, `srv_resume.c`
    and `srv_auth.c` on every transport.
  - `ROLE=both` compiles both sets.
- **Check.** Semgrep-structural, in three rules.
  `inv-4-one-draw-path` refuses a `ch_rand_bytes` call anywhere but
  `rand_draw`'s body in `rand_draw.h`; it excludes `drbg.c`, which
  defines the hook. `inv-4-randomness-files` refuses a `rand_draw` call
  in any file other than `handshake_flight.c`, `handshake_groups.c`,
  `srv_flight.c`, `srv_kex.c`, `srv_resume.c` and `srv_auth.c`.
  `inv-4-randomness-calls` reads only those six files and refuses a call
  outside the eight functions the claim names, a fourth call in
  `hsf_begin`, and a second call in any of the other seven. It counts a
  call in a branch, a loop or a block the same as one at the top of the
  function. `test/lint-invariants.sh` fails on each of five violations:
  - `inv04-draw-in-handshake-post` adds a call to `handshake_post.c`.
  - `inv04-draw-in-srv` adds a call to `srv.c`.
  - `inv04-second-draw-in-srv-flight` adds a second call to
    `srv_send_server_hello`.
  - `inv04-fourth-draw-in-hsf-begin` adds a fourth call to `hsf_begin`.
  - `inv04-hook-outside-rand-draw` has `encapsulate` call
    `ch_rand_bytes` itself.

  `lib-check` requires a `RAND=extern` object to import `ch_rand_bytes`,
  a `RAND=drbg` object to define and export it, and a `RAND=session`
  object to name neither it nor `ch_drbg_seed`, defined or imported. It
  links `test/entropy_recipe.c`, docs/entropy.md's boot-seed recipe,
  against the `RAND=drbg` object, and `test/build_test.c`, which defines
  no hook under `CH_RAND_SESSION`, against the `RAND=session` one.
  `test/lib-check-rand-session.sh` fails on
  `inv04-session-object-imports-hook`, where `srv_begin` calls
  `ch_rand_bytes` itself. The `RAND=session` builds of the three loop
  tests, `bin/tcp_blocking_loop_session`,
  `bin/tcp_nonblocking_loop_session` and `bin/quic_loop_session`, hand
  each session a seeded stream of its own (`test/rand_session.h`) and
  count every draw against the source its `rand_io` names. They require
  each side's draws at its own source, the hello randoms on the wire to
  be those sources' draws, none at the hook and none at no source; two
  handshakes from the same seeds to send the same bytes both ways, and a
  different seed on either side to change both; each init call and
  `ch_srv_check` to refuse a NULL `rand_bytes` and to take a NULL
  `rand_io`; and the RSA-PSS signature to be the one `rsa_pss_sign`
  computes over the server source's draw. They fail on each of four
  violations:
  - `inv04-session-draw-from-hook` has `hsf_begin` draw the ClientHello
    random from `ch_rand_bytes`.
  - `inv04-session-init-accepts-no-source` drops the check from
    `tlsi_config_ok`.
  - `inv04-session-pss-salt-from-hook` has `sign_rsa_pss` draw the salt
    from `ch_rand_bytes`.
  - `inv04-session-draw-ignores-context` has `rand_draw` pass NULL for
    the session's `rand_io`.

  `bin/drbg_test` checks the reference generator's output for two seeds
  against known answers computed outside this tree, and the floor at
  exactly 32 bytes and 31. It fails on each of three violations:
  - `inv04-drbg-seed-copied` copies the first 32 seed bytes into the
    key instead of hashing the seed.
  - `inv04-drbg-seed-floor-lowered` takes a 31-byte seed.
  - `inv04-drbg-seed-floor-raised` refuses a 32-byte seed.
- **Violation.** A PR conjures a nonce or padding bytes from a new
  call site nobody audits for seeding requirements, draws from the
  image's hook in a build where each session names its own source,
  accepts a session with no source, or keys the generator from part of
  the seed.
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
  reason, `aes_extern.c` among them: a `SUITE=aesgcm AES=extern` build
  compiles it over every transport. `quic_aes_soft.c` keeps the prefix:
  a `SUITE=aesgcm` build refuses it (INV-26), so only a QUIC build
  compiles it.
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
  The alert of a handshake failure leaves the same way (INV-13).
  Both callbacks are still required at configuration time, because
  `ch_read` and `ch_write` call them once the session is connected, and
  by then the caller holds the bytes. Once connected, `ch_read` calls
  `cfg.send` in two cases alone: the reply to a KeyUpdate whose sender
  asked for one (RFC 9846 §4.7.3), and the alert of a failure. The
  peer's close_notify is neither, and neither is the peer's fatal
  alert, which fails the session with no alert sent (INV-22). The
  `ch_read` that reads either sends nothing, and `ch_close` sends this
  side's close_notify through `cfg.send` in one call, whenever the
  caller makes it. A caller whose `cfg.send` holds only input while
  `ch_read` runs, as colibri's does, therefore sees no send it did not
  ask for when the peer closes or aborts.
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

- **Claim.** One cipher suite and one TLS version, 1.3, per build, and in
  the raw and ca modes one group and one signature algorithm. A
  `TRANSPORT=quic-nonblocking` build's QUIC version is the caller's value,
  like the encryption level: every packet call takes the version of the
  packet beside its level, and chapulin chooses neither (decisions.md 79).
  It derives the keys of the versions `quic_version_derived` admits,
  version 1 and version 2; it refuses an original version it does not
  derive, a packet in a version its level does not admit, and a Retry in
  any version but the original, and a client switches to the other version
  once, before the server's first CRYPTO byte. A server's caller chooses
  the negotiated version once, through `ch_srv_cfg.choose_version`, after
  the first ClientHello's transport parameters and before anything is
  selected or sent, and an answer the build does not derive fails the
  session. The client offers
  exactly one of everything; the server takes it or the handshake fails
  closed. The host-side `TRUST=webpki` mode offers several signature
  schemes (decisions.md 36), several application protocols (37), two
  groups with a key share for each and secp256r1 listed after them with
  none (39, 53, 63), under `SUITE=aesgcm`
  three cipher suites (45, 58, 80), and in a resuming hello the ticket and the
  certificate path beside it (55), so the server may resume or
  authenticate with its chain in the same connection. The three suites
  go in the build's order, AES-256-GCM, AES-128-GCM, then ChaCha20 in a
  host object whose caller sets `CH_CPU_CONSTANT_TIME_AES`, ChaCha20 alone
  in a host object without that bit, and ChaCha20, AES-128-GCM, then
  AES-256-GCM on `AES=extern`, or in the caller's
  `ch_cfg.cipher_suites`, which names 1 to 3 suites the build holds,
  none twice. There a ServerHello selects either shared
  group, or the hybrid alone under `ch_cfg.require_pq`, and a
  HelloRetryRequest may ask for a cookie, for secp256r1, or for both; after
  a retry that names secp256r1 the ServerHello must select it. It carries
  a suite the hello listed, and the same one as a retry before it. A
  server role selects rather than offers, and its group order is fixed
  (decisions.md 54, 63): X25519MLKEM768 whenever the client lists it,
  x25519 when the client lists x25519 and not the hybrid, secp256r1 only
  when the client lists neither, and a HelloRetryRequest that names the
  group when the hello carried no share for it, so a hello that lists the
  hybrid and shares x25519 alone is asked for the hybrid rather than
  answered over x25519. Its suite order is the one its build's client
  offers in, and it selects the first of them the client listed, or the
  first of `ch_srv_cfg.cipher_suites` when the caller names an order
  (decisions.md 58, 80). It never selects a suite the client did not
  list. A host session without `CH_CPU_CONSTANT_TIME_AES` holds ChaCha20
  alone: its client offers no AES-GCM suite, and its server selects none,
  from a default order or from a retry cookie (decisions.md 81 and 89).
- **Mechanism.** Absence of selection code; the TRUST build flag picks
  the sigalg of a raw or ca build at compile time, never at runtime.
  The QUIC version rules sit in two places: `quic_version.h`'s
  `quic_version_derived`, which `ch_quic_init`, `ch_srv_quic_init`,
  `ch_quic_switch_version`, `ch_srv_quic_retry_tag` and the Initial and
  Retry derivations ask, and `quic.c`'s `version_ok`, which the three
  packet calls ask before they read a byte: the negotiated version at every
  level, and the original one at the Initial level too. The server's
  choice is `srv_quic.c`'s `choose_version`, which asks
  `quic_version_derived` of the caller's answer, and `step_client_hello`
  is its one call site, between `take_transport_params` and `srv_select`.
  The two-group offer is the `CH_KEX_TWO_GROUPS` arms of
  `handshake_message.c`, `handshake_parser.c` and `handshake_flight.c`,
  with `handshake_groups.c`. A raw or ca parser refuses a
  HelloRetryRequest that names a group, and the webpki parser refuses one
  that names any group but secp256r1; `hsg_selected_group_ok` holds the
  ServerHello to the group of a share the hello it answers carried. The
  three-suite offer is the `CH_CLIENT_AES_SUITES`
  arms of `handshake_message.c` and `handshake_parser.c`: the hello
  writes the suites `hs_offered_suites` names, the caller's list or
  `suite.h`'s `suite_default_order`, `webpki_cfg.c` holds the caller's
  list to the build's suites, and `hsf_read_server_hello` holds a retry
  or a ServerHello to the listed ones (`hs_suite_offered`).
  `handshake_state.suite` records the suite a retry or ServerHello
  named. The server's choice is `srv_first_offered_suite` in `suite.h`,
  which walks the server's order, `suite_default_order` unless the
  caller names one, and takes the first suite the parsed
  offer holds, and `srv_parse_client_hello` reads `cipher_suites` once.
  `SUITE_AES_FIRST` in `suite.h` marks the build whose default order puts
  AES-256-GCM first; the build's defines decide it, and nothing probes
  the CPU at run time. The resuming offer is the `CH_TRUST_WEBPKI` arm of
  `handshake_message.c`, which writes `signature_algorithms` and
  `server_certificate_type` in every hello and `pre_shared_key` last,
  and a raw or ca hello offers a ticket alone.
- **Check.** The differential (`inv07-second-cipher-suite.violation`)
  and handshake_sequence assert the reject on any ServerHello that picks
  another suite or group. The QUIC version rules are tested through the
  public calls: `bin/quic_driver_test` (`test/quic_version_tests.h`)
  refuses 0, the values beside version 1 and version 2 and a version RFC
  9000 reserves at init, at the switch, at each packet call at the Initial
  and the Handshake level and at `ch_quic_retry_ok`, and opens an Initial
  packet in the original version. It switches a version 1 client to
  version 2 and opens the server Initial packet RFC 9369 Appendix A.3
  prints, holds each Handshake key to the one version 2's labels derive,
  and refuses the switch after one server byte, after the ServerHello
  step with the receive buffer empty, on a failed session and a second
  time; `bin/srv_quic_test` and `bin/srv_quic_both_test`
  (`test/srv_quic_version_tests.h`) refuse the underived versions at
  `ch_srv_quic_init` and `ch_srv_quic_retry_tag`, start a session in
  either derived version, and refuse a server session's switch. They hold
  `choose_version` to one call after the transport parameters and before
  any byte goes out, in each direction and for the original version; a
  NULL callback to the original version; each underived answer to
  `CH_EIO` with internal_error and nothing sent; a hello the selection
  then refuses to a choice all the same; and ngtcp2's recorded retry
  round to one call, a retry only a client switched to version 2 opens,
  and a Handshake level that admits version 2 alone.
  `bin/quic_loop_test` refuses a 1-RTT packet in the other version at both
  ends, and runs whole handshakes in version 2 with a key update at each
  end: one that starts there, and one packet by packet between a version 1
  client and a server that chooses version 2, which switches the client on
  the Version field of the server's first Initial packet; a client that
  does not switch opens none of that server's packets
  (`test/quic_loop_version.h`);
  and `bin/quic_test` refuses the underived versions at the two Initial
  derivations and the Retry tag, and holds version 2's salt, labels,
  Retry key and nonce to RFC 9369 Appendix A. The `quic_driver` harness
  proves the refusals over any saved version and any version a caller
  passes, the switch's six conditions and its one success included, and
  the `quic_initial`, `quic_retry`, `quic_step` and `quic_config_webpki`
  harnesses prove their files' share. Twenty-eight `inv07-quic-` and
  `inv07-srv-quic-` violations each drop one rule or swap one version 2
  value for version 1's, and a test fails on each: the switch's server,
  failed-session, second-switch, server-byte and ServerHello conditions,
  the Initial level's original version, the Handshake keys, the 1-RTT
  keys and the key update under the negotiated version, version 2's
  salt, labels, key update label, Retry key and Retry nonce, and the
  server's choice made after `srv_select`, made again for the retried
  hello and taken unchecked among them.
  `bin/webpki_session_test` drives the
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
  AES-256-GCM, and `bin/webpki_loop_aes_extern` requires AES-128-GCM.
  The two orders (decisions.md 80): `bin/webpki_session_test`,
  `bin/webpki_session_aes` and `bin/webpki_session_aes_extern` hold the
  hello's cipher_suites bytes to each build's default, and
  `test/webpki_loop_order.h` feeds the server a hello that lists the
  three suites in each of their six orders, in the three webpki loop
  builds, and requires the first suite of the server's default order.
  The caller's list meets each rule at its edge in
  `bin/webpki_session_aes`, `bin/webpki_loop_aes` and
  `bin/quic_loop_aes`: one, two and three suites are offered as listed,
  and a fourth entry, an unheld code point, a repeat and a count without
  its list are `CH_EINVAL`; a ServerHello or a retry that names a suite
  the list left out is illegal_parameter. `hello_build_suite` proves the
  builder over every list shape, and `quic_config_webpki_suite` proves
  that `ch_quic_init` takes a list only in the shape webpki_cfg.h states.
  Eight mutants require a test to fail:
  `inv07-client-default-order-chacha-first`,
  `inv07-srv-default-order-chacha-first`,
  `inv07-extern-default-order-aes-first`,
  `inv07-default-order-aes128-first`,
  `inv07-client-list-admits-unheld-suite`,
  `inv07-client-list-admits-repeat`, `inv07-client-offer-ignores-list`
  and `inv07-client-takes-unlisted-suite`. `test/e2e.sh` has OpenSSL's
  `s_server` select AES-256-GCM from the host client, ChaCha20 from
  the `AES=extern` one and AES-128-GCM from either under
  `WEBPKI_SUITES=1301,1303`, and has this tree's server select its own
  first suite from an `s_client` that lists AES-128-GCM first.
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
  ServerHello and downgrade surface exists again, takes back a suite
  the caller's `ch_cfg.cipher_suites` left out of the hello, lets a
  QUIC packet call admit a packet in a version its level does not admit,
  or lets a server's version choice come after the selection or go
  unchecked.
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
  move on any added byte. `rec_seal` copies the plaintext with one
  `memmove`, and `rec-seal-copy-short` copies a byte less and requires
  `bin/aes_suite_test`, which seals the published records through it, to
  fail.
- **Violation.** A PR pads for traffic-analysis resistance and the
  SRAM and replay-vector numbers quietly change.
- See [decisions: Protocol surface](decisions.md#protocol-surface).

## Structural arithmetic

### INV-10 — nonce discipline

- **Claim.** Nonce = static IV xor sequence number; the counter is
  monotonic, wrap-guarded, reset only by rekey; KeyUpdate epochs are
  capped at 2^48−1. An AES-GCM write key seals at most
  `REC_AES_GCM_RECORDS_MAX` records, 2^24, counted whatever their size,
  and the last of them is the KeyUpdate that retires it (RFC 9846 §5.5,
  `rfc9846.txt:3743-3753`; docs/decisions.md 78). A key at that ceiling
  after 2^48−1 KeyUpdates fails its session. ChaCha20-Poly1305 has no
  ceiling but the wrap.
- **Mechanism.** Structural arithmetic in `record.c`;
  `rec_dir_update` is the only reset; the epoch cap is
  `HSPOST_SEND_EPOCHS_MAX`, which `handle_key_update` and `ch_write`
  both read. `rec_seal` refuses an AES-GCM record at or past the
  ceiling, beside the wrap. `ch_write` (`tls_write.c`) reads
  `records_before_key_update` before each record it seals, and when an
  AES-GCM key has no data record left, `key_update_at_ceiling` sends a
  KeyUpdate at the key's last sequence number through
  `hspost_send_key_update`, which seals, sends and rekeys, or fails the
  session with internal_error and `CH_ECAP` when the cap is spent. Every
  other record sealed under an application write key is a single one
  that takes at most that last sequence number.
- **Check.** CBMC (record and handshake_post harnesses cover the guards);
  Lean theorem (`Spec.Record.nonce_inj`): distinct sequence numbers
  below 2^64 give distinct nonces, so a repeat needs a repeated
  counter, not a colliding construction — the counter half stays with
  the mechanisms below; semgrep-structural
  (`inv-10-seq-reset-only-in-record`): no `.seq = 0` assignment
  outside record.c. The ceiling:
  - CBMC: `record_suite` proves that `rec_seal` refuses the wrap and an
    AES-GCM record at or past the ceiling and nothing else, at any
    sequence number; `writable_len_suite` proves, at its bound, that
    `ch_write` seals no data record at an AES-GCM key's last sequence
    number, sends the KeyUpdate there and nowhere else, never under
    ChaCha20, and leaves the key with that last sequence number free.
  - Tests: `test/key_limit_cases.h` runs in `bin/tcp_blocking_key_limit`,
    `bin/webpki_loop_aes` and `bin/webpki_loop_aes_extern`. Under both
    AES-GCM suites each end of a connection writes across the ceiling
    while the peer reads on, one write of three records sends one
    KeyUpdate, and at the cap the write fails; ChaCha20 sends none at the
    same sequence numbers. `bin/aes_suite_test` holds `rec_seal`'s
    refusal to its exact boundary. `test/zig-consumer/loop_key_limit.zig`
    has each end write across the ceiling through the Zig API (INV-36).
  - Violations: `inv10-aes-gcm-ceiling-no-key-update`,
    `inv10-aes-gcm-ceiling-rekey-unsent`,
    `inv10-aes-gcm-ceiling-one-record-late`,
    `inv10-aes-gcm-ceiling-past-epoch-cap`,
    `inv10-chacha-under-aes-gcm-ceiling` and
    `inv10-aes-gcm-seal-past-ceiling`.
  - The count of records a key has left, up to 2^24 - 1, sits in a
    `size_t`, so `ct.h` refuses any build whose `size_t` has fewer than
    32 bits. `test/size-floor.sh`, run by `make lint-size-floor`, requires
    `ct.h` to stop compiling for msp430, whose `size_t` is 16 bits, and to
    compile for armv7m. `inv10-size-t-floor-dropped` removes the refusal,
    and the script objects.
- **Violation.** A PR resets a sequence counter from the handshake
  layer to "fix" a desync, and a nonce repeats under one key. Or it
  moves an AES-GCM write key to its next key at the ceiling without the
  KeyUpdate, and the peer cannot open the next record.
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

### INV-38 — a record is never larger than either end allows

- **Claim.** A record this endpoint sends carries at most the smaller
  of `CH_TX_PT` and the plaintext the peer's `record_size_limit`
  allows. A record it receives fits the buffer its own
  `record_size_limit` advertised, or it is refused, never truncated.
  `CH_TX_PT` is 512 unless the build raises it with `TX_RECORD`. Every
  build refuses a value below 512 or above 2^14, the most plaintext RFC
  9846 §5.1 lets one record carry, and a `TRANSPORT=quic-nonblocking`
  build, which seals no TLS record, refuses any value but 512
  (docs/decisions.md 71). A caller that sizes its own buffers asks C
  rather than restating the rule (docs/decisions.md 72):
  `ch_writable_len` answers the most plaintext one `ch_write` sends in
  `cap` bytes of records, the KeyUpdate record `ch_write` sends at an
  AES-GCM write key's ceiling included (INV-10); `ch_record_whole_len`
  answers where the record at the front of the caller's bytes ends, and
  `REC_HDR` for a length field above 2^14 + 256, which no peer may send;
  and
  `CH_ALERT_RECORD_LEN` and `CH_KEY_UPDATE_RECORD_LEN` are the wire
  lengths of one sealed alert record and one sealed KeyUpdate record, 24
  and 27 bytes.
- **Mechanism.**
  - The range: `cfg.h` asserts 512 to 16384, `session.h` asserts 512
    in a QUIC build, and the Makefile's and `build.zig`'s `TX_RECORD`
    refuse the same values.
  - The staging array: `session.h` sizes `ch_tls.tx` (`CH_TX_STAGE`) to
    the larger of the build's largest hello and one sealed record of
    `CH_TX_PT` bytes, and asserts that it holds `CH_TX_PT + 1 +
    AEAD_TAG`.
  - The send limit: `peer_limit` starts at `CH_TX_PT` in `handshake.c`,
    `srv_handshake.c` and both tcp-nonblocking drivers. The client's
    `parse_record_size_limit` (`handshake_parser_ee.c`) and the server's
    `read_record_size_limit` (`srv_parser_ext.c`) lower it to the
    peer's value less the content-type byte, never raise it, and refuse
    a value under 64 (RFC 8449 §4).
  - The writers: `ch_write` (`tls_write.c`) and the server's
    `srv_out_limit` (`srv_out.c`) cut every write at the smaller of
    `peer_limit` and `CH_TX_PT`. The server's Certificate writer,
    `srv_frag`, holds `SRV_FRAG_MAX` (512) bytes whatever `CH_TX_PT` is,
    so a raised `CH_TX_PT` adds nothing to the handshake's stack (INV-19).
  - The framing calls: `ch_write` and `ch_writable_len` read the send
    limit through one helper, `record_plaintext_max` (`tls_write.c`), and
    the AES-GCM ceiling through another, `records_before_key_update`.
    `ch_writable_len` counts `REC_OVERHEAD` per record, the length
    `rec_seal` adds, and `CH_KEY_UPDATE_RECORD_LEN` once when the write
    it sizes crosses the ceiling; it counts no second KeyUpdate, so its
    answer stops at the records the key has left and
    `REC_AES_GCM_RECORDS_MAX - 1` more (tls.h).
    `ch_record_whole_len` (`tcp_nonblocking_frame.c`) reads the length
    field through the `rbuf` reader. `tls_write.c` asserts the two record
    lengths are 24 and 27.
  - The receive limit: each role advertises its buffer's room after the
    record header and the tag, capped at 2^14 + 1, in `handshake.c`,
    `srv_handshake.c` and both tcp-nonblocking drivers; a QUIC build
    sends none. A record the buffer cannot hold is refused:
    `io_read_record` returns `CH_ECAP`, and the tcp-nonblocking drivers
    send record_overflow.
- **Check.** Type system for the range and the staging array: a value
  outside it does not compile. Tests and mutants for the rest:
  - `test/tx-record-builds.sh` compiles the headers at 511, 512, 16384
    and 16385 and under QUIC, and runs the same values through make and
    `build.zig`. `inv38-tx-record-past-2-14`,
    `inv38-tx-record-quic-accepted`,
    `inv38-tx-record-makefile-quic-accepted` and
    `inv36-zig-build-tx-record-past-2-14` require it to fail.
  - `bin/webpki_loop_tx_record` sends `CH_TX_PT` bytes as one record
    and `CH_TX_PT + 1` as two, and a server writing to a client whose
    `record_size_limit` allows 12,316 bytes of plaintext sends 12,316
    in one record and 12,317 in two. `inv19-srv-frag-sized-by-tx-record` requires it to
    fail.
  - `bin/srv_test` holds the server's parser to the wire value less
    one and to the floor of 64. `srv-parser-record-size-limit-units`
    and `srv-parser-record-size-limit-floor` require it to fail.
  - CBMC: `srv_accept` proves that the server's `peer_limit` never
    exceeds `CH_TX_PT` after the client's limit is stored.
  - CBMC: `record_whole_len` proves `ch_record_whole_len`'s whole
    contract for every `n` up to 2^20, and `writable_len` runs
    `ch_writable_len`'s answer through the real `ch_write` for every
    `cap` up to 1,603 bytes and every `peer_limit` from 63.
    `writable_len_suite` does the same in the `SUITE=aesgcm` build for
    every `cap` up to three records of the session's own limit, a
    KeyUpdate record and one byte, over each suite and every write
    sequence number below the ceiling, the KeyUpdate record included.
    `inv38-whole-len-one-byte-short` and
    `inv38-writable-len-overhead-short` require each to fail.
  - Lean theorem: `spec/lean/Spec/TlsWrite.lean` models
    `ch_writable_len`, `records_fill` and `fill_across_key_update` with
    one `let` per C local, and proves that no sum or product they
    compute wraps a `size_t` of 15 bits or more (`recordsFill_fits`,
    `fillAcrossKeyUpdate_fits`) and that the answer is at most `cap`
    (`writableLen_le_cap`), at every `cap`, every limit from 1 to 16384
    and every room. `test/diff_writable_len.h` holds the model to the C
    in `bin/diff` and, under `SUITE=aesgcm` at `CH_TX_PT=16384`, in
    `bin/diff_webpki_aes`. `inv38-writable-len-last-record-no-overhead`
    requires `bin/diff` to fail.
  - `bin/unit` sweeps every `cap` up to three records and one byte at
    limits of 63, 200 and `CH_TX_PT`, checks the answer at `SIZE_MAX`,
    and checks that `ch_close` and a KeyUpdate answer send 24 and 27
    bytes; `bin/tcp_nonblocking_loop_test` holds `ch_record_whole_len` to
    a record one byte short, a whole one, the largest the RFC allows and
    the first length past it. `inv38-writable-len-ignores-peer-limit` and
    `inv38-whole-len-oversize-waits` require them to fail.
  - `test/key_limit_cases.h` sweeps every `cap` up to three records, a
    KeyUpdate record and one byte at the ceiling and one and two records
    before it, and checks the exact rows: at the ceiling a record of one
    byte costs a KeyUpdate record too, and one record before it the
    first record does not. `inv38-writable-len-skips-key-update`
    requires `bin/tcp_blocking_key_limit` to fail.
  - `test/zig-consumer/loop_key_limit.zig` holds the Zig API's
    `writableLen` to the same rows two records before the ceiling, and
    `write` to refusing whole an output one byte short of the records it
    seals, the KeyUpdate record among them.
    `inv38-zig-writable-len-skips-key-update`, the same edit, requires
    `test/zig-build-check.sh` to fail.
- **Violation.** A PR raises `CH_TX_PT` past 2^14, sizes a stack
  buffer by `CH_TX_PT`, lets a peer's `record_size_limit` raise the
  send size rather than lower it, or truncates a record the receive
  buffer cannot hold.
- See [decisions: Memory and runtime](decisions.md#memory-and-runtime),
  entries 22, 71, 72 and 78.

### INV-24 — the x25519 ladder stays inside its proven limb range

- **Claim.** Between the ladder's operations every limb of `a`, `b`,
  `c`, `d` and `x` lies in (-2^17, 2^17), and mul receives no operand
  outside (-2^18, 2^18). Every x25519 field-op proof holds only inside
  a stated limb range (its entry in docs/verification.md), so a
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
- This entry is the 16-limb field's, which every object holds. INV-34 is
  the same claim for the wide field a host object holds beside it.

### INV-34 — the wide X25519 ladder stays inside its proven limb range

- **Claim.** In a host object's wide X25519 field (`x25519_wide.c`),
  between the ladder's operations
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

### INV-41 — a host object's RSA arithmetic wraps no sum and gives the portable code's answers

- **Claim.** `rsa_mont64.c`, the Montgomery arithmetic on 64-bit limbs
  that a host object runs for `rsa_vp1`, computes for every odd modulus
  the bytes `rsa_mont.c`'s 32-bit arithmetic computes, which stays the
  reference. `rsa_sign64.c`, the signer on those limbs that a host
  session runs when it states its multiply, computes a signature from
  the key's primes by the Chinese remainder theorem, and writes for
  every key and every encoded message the bytes `rsa_sign.c`'s ladder
  writes from n and d, which stays the reference too. No sum in
  `rsa_mont64.c` wraps: a product of two limbs is at most
  (2^64 - 1)^2, and with a limb of the running sum and a carry added it
  is at most 2^128 - 1. The file computes in `uint64_t` and `unsigned
  __int128`, where C defines every wrap, so a sum that left that range
  would not fault: it would compute a wrong value.
- **Mechanism.** Every product is one `ct_mul128`. A round of
  `rsa_mont64_mont_mul` adds one product, one limb and one carry in each
  of its two sums, and its top step adds two carries to a limb that is 0,
  1 or 2. `rsa_mont64_mont_square` keeps that pass and adds a_i V_i in
  a round, with V_i = a_i B^i + 2 (a_{i+1} B^{i+1} + ... + a_{k-1}
  B^{k-1}), each sum still a product, a limb and a carry, and a top limb
  that reaches 2. A subtraction adds the complement of the subtrahend and one,
  so its limbs carry where a borrow would wrap. `rsa_mont.c` compiles to
  a call into this file under `-DCH_CPU_RUNTIME` and to the 32-bit
  arithmetic without it, so an object holds one of the two. Its host arm
  computes R^2 for a modulus whose top bit is set by a long division of
  its own, whose estimate of each quotient limb is at most 2 above the
  limb, and takes `rsa_mont64_modulus_init` for any other modulus.
  `rsa_sign64.c` multiplies only through that file. It reduces the
  encoded message modulo each prime with three multiplications and a
  sum, raises each to dp or dq, reading the exponent one hexadecimal
  digit a step, squaring four times and multiplying by the table entry
  the digit names, and joins the halves by Garner's formula, which
  `rsa_mont64.c`'s sum, difference and plain product compute. It
  compiles `rsa_sign.c`'s PSS encoder around that, so the two signers
  encode alike. A host object holds both signers, and `widemul.h` picks
  one for a session from its multiply bit (INV-16).
- **Check.** CBMC, with `--unsigned-overflow-check` on the lines whose
  claim is a sum: `rsa_mont64_sums` runs the shipped multiplication at
  four limbs over any operands, `rsa_mont64_ops` the comparison, the
  subtraction, the doubling and the byte marshalling at the build's
  bound, and `rsa_mont64_mul128` proves the real `ct_mul128` meets the
  bound the others take as a contract (`proof/rsa_mont64_stubs.h`).
  `rsa_mont64_mul`, `rsa_mont64_init` and `rsa_mont64_public` prove the
  memory accesses of the multiplication and the square, the modulus
  setup and the public operation at that bound, and `rsa_mont_host`
  those of the host arm's `rsa_vp1` with its division. The values are
  held by `bin/rsa_equiv_test`, which compiles both arms of `rsa_mont.c`
  into one binary and requires the same bytes from each over random
  moduli at every length, moduli at the limb edges, a modulus whose
  division takes the largest estimate, moduli of every bit length near a
  limb boundary, and the signatures 0, 1 and n - 1, whose powers are
  known, and holds the square to the multiplication of a number by
  itself at every limb count; by `bin/rsa_test_host` and
  `bin/rsa_pkcs1_test_host`, the
  two verifiers' openssl vectors on the 64-bit arm; and by the Wycheproof
  host leg. `test/widemul-builds.sh` holds each arm to its object.
  For the signer, `rsa_sign64_window` proves, with the wrap check on,
  that a digit is the half of the byte its index names and that the read
  of the table writes the entry at its index, `rsa_sign64_power` proves
  the exponentiation's memory accesses at the longest exponent and at
  the largest limb count, and `rsa_sign64_crt` those of the reduction,
  the recombination, the key test and the signature's check, each over
  contracts of `rsa_mont64.c`'s entries (`proof/rsa_sign64_stubs.h`).
  `rsa_mont64_ops`, `rsa_mont64_sums` and `rsa_mont64_mul` hold the sum,
  the difference and the plain product as they hold the multiplication.
  `bin/rsa_sign_equiv_test` requires the ladder's bytes from the 64-bit
  signer under four keys openssl minted, RSA-2048, RSA-2112, whose
  primes are half a limb past a whole number, RSA-3072 and RSA-4096,
  over the messages 0, 1 and n - 1 and random ones. It holds the window
  to the ladder under random moduli of 256 bytes over exponents whose
  digits sit at an edge, and at smaller sizes to a square-and-multiply
  that keeps no table. `bin/rsa_sign_test_host` requires OpenSSL's
  signatures from both signers, the Wycheproof host leg runs the private
  operation on each from Wycheproof's keys, and `bin/diff_rsa_sign64`,
  in `make diff`, requires the Lean spec's signatures from each.
- **Violation.** A PR adds both carries into one sum, which can then
  pass 2^128; makes the running sum one limb short; subtracts with a
  borrow that wraps; copies a product out without its last subtraction;
  drops the running sum's top limb; squares R^2's seed four times where
  five are needed; stops the low limb's inverse one step short; lets
  the division of R^2 divide past 2^64 where it caps the estimate; or
  drops the top bit of 2a from a square's round, or reads it at the
  limb above the square. `make test-invariants` runs the last seven as
  `inv41-rsa-mont64-final-subtract-dropped`,
  `inv41-rsa-mont64-top-limb-dropped`, `inv41-rsa-mont64-r2-four-squarings`,
  `inv41-rsa-mont64-inverse-five-steps`,
  `inv41-rsa-mont-r2-estimate-not-capped`,
  `inv41-rsa-mont64-square-top-bit-dropped` and
  `inv41-rsa-mont64-square-next-limb-from-double`, through `bin/rsa_equiv_test`,
  and the first three as `inv41-rsa-mont64-carries-in-one-sum`,
  `inv41-rsa-mont64-sum-one-limb-short` and
  `inv41-rsa-mont64-borrow-wraps`, through `proof/prove-one.sh`, in the
  nightly's proof-backed job. Or a PR starts the read of the table at
  its second entry, or reads the low half of each exponent byte first:
  `inv41-rsa-sign64-table-read-skips-entry-zero` and
  `inv41-rsa-sign64-digits-low-half-first`, which
  `bin/rsa_sign_equiv_test` catches. Or it reduces the message's high
  limbs with R^2 where R^3 is needed, `inv41-rsa-crt-half-reduced-with-r2`:
  the signature's check then refuses every signature (INV-42), and the
  same binary reports it.
- See [decisions: Engineering](decisions.md#engineering), entries 95, 103 and 106.

### INV-42 — a host object returns no RSA signature it has not verified

- **Claim.** `rsa_sign64_sp1`, the private operation a host session runs
  by the Chinese remainder theorem when it states its multiply, writes a
  signature only after it raised it to the public exponent modulo n and
  found the encoded message. A signature that fails that check is an
  error: the call returns 0 and writes no byte of it, `rsa_sign64_pss`
  returns 0, and the session fails closed with internal_error (INV-13).
  The key it signs with has primes whose product is its modulus, which
  `rsa_sign64_key_ok` tests before every signature and at every init
  and `ch_srv_check`.
- **Mechanism.** A CRT signature computed with one wrong half differs
  from the right one modulo one prime alone, so the difference between
  its 65537th power and the message shares that prime with n, and one
  such value factors the modulus (Boneh, DeMillo and Lipton). A fault in
  the arithmetic makes one, and so does a key whose dp, dq or qinv does
  not belong to its modulus. The check's power is `rsa_mont64_public`,
  the arithmetic the verifier runs, which is constant time in its base,
  and the comparison is `ct_memeq`; the power is wiped. The candidate
  stays in a buffer of the call's own until the check passes.
  `srv_sign_certificate_verify` wipes its output and answers `CH_EAUTH`
  when a signer returns 0, and `ch_srv_check` signs once with each
  provisioned key, so a key with a wrong integer is refused before a
  session starts. A device object's signer has no CRT and no check, and
  `rsa_sign.h` says why.
- **Check.** `bin/rsa_sign_test_host` changes one bit of each of the five
  CRT integers of an RSA-2048 and an RSA-2112 key, at its first byte,
  its last and one between. From the 64-bit signer it requires an error,
  every byte of the output buffer as it was and the length as it was,
  and from the key test a refusal of a changed prime. Under the answer
  that runs the ladder the same calls must sign, because the ladder
  reads none of the five. `bin/rsa_sign_equiv_test` and the Wycheproof
  host leg require the check to pass on every signature a good key
  makes. No test can show that a comparison leaves out a byte or a
  limb: a faulted candidate's power differs from the message in nearly
  every byte, and a changed bit of a prime moves the low limbs of the
  product. So CBMC's `rsa_sign64_crt` states three things over what the
  contracts of `rsa_mont64.c` may write, at both shapes of the limb
  counts: the check raises the whole candidate modulo the key's modulus
  and passes exactly when every byte of the power is the message's;
  `write_if_verified`, the one function that writes a signature, leaves
  every byte of the caller's buffer as it was unless the check passed,
  and then the buffer holds the candidate; and the key test admits a key
  exactly when every limb of the product is the modulus's. The check
  answers a fault that changes the signature. It does not answer one
  that skips the check, and no test here injects a fault into a running
  signature: a changed key integer stands in for one.
- **Violation.** A PR compares the encoded message with itself, writes
  the candidate to the caller's buffer before the check, or admits a key
  without comparing the product of its primes:
  `inv42-rsa-crt-check-compares-nothing`,
  `inv42-rsa-crt-signature-written-before-check` and
  `inv42-rsa-crt-key-test-skips-product`, each of which
  `bin/rsa_sign_test_host` catches. Or it compares all but the last
  byte of the power, or all but the top limb of the product, which every
  test passes: `inv42-rsa-crt-check-skips-last-byte` and
  `inv42-rsa-crt-key-test-skips-top-limb`, each of which the
  `rsa_sign64_crt` proof refutes.
- See [decisions: Engineering](decisions.md#engineering), entry 95.

### INV-43 — a host object's ECDSA P-256 verifier gives the portable code's verdict

- **Claim.** `p256_wide_verify.c`, which a host object runs for
  `p256_ecdsa_verify` in every session, answers for every key, hash and
  signature what `p256.c`'s 32-bit arithmetic answers, which stays the
  reference. It refuses what FIPS 186-4 6.4.2 refuses before any
  arithmetic, an r or an s outside 1..n-1, a coordinate at or above p
  and a key off the curve, and it refuses an R at infinity.
- **Mechanism.** `p256.c` reads the DER signature with one reader for
  both arms and hands r and s to the arm its build compiled: a call into
  `p256_wide_verify.c` under `-DCH_CPU_RUNTIME`, and its own 32-bit
  arithmetic without it, so an object holds one of the two. The host arm
  computes on the wide P-256 field: `p256_wide_scalar.c` for s's inverse
  and the two products, `p256_wide_point.c` for the key's decoding,
  `p256_wide_verify_point.c` for the sum u1·G + u2·Q and the test that
  its x is r modulo n, and `p256_scalar.c` for the range predicates and
  the reductions modulo n. The sum is one pass over both scalars' signed
  digits on Jacobian points, variable time on purpose: every input is
  public, so no bit of `ch_cfg.cpu` picks the arm and no caller states
  the multiply's timing for it. Each addition tests for a point at
  infinity, two equal points and two negatives, which its formula leaves
  out, and takes them by a branch (decisions 96 and 104).
- **Check.** `bin/p256_verify_equiv_test` compiles both arms into one
  binary and requires one verdict from them, and the verdict each case
  names, over signatures `p256_sign.c` wrote, signatures the test
  computed on a third arithmetic with the scalars at their edges, the
  two cases where u1·G and u2·Q are equal or negatives, five cases over
  four keys whose multiples meet the sum inside the pass, so that an
  addition there has two equal operands or two negatives, r and s at the
  ends of their range, keys no point encodes and DER no reader takes.
  The Wycheproof host leg runs Wycheproof's ECDSA P-256 vectors on the
  host arm, among them the signatures whose k·G has an X of n or more.
  CBMC's `p256_wide_verify` proves, over contracts of the wide entries,
  the refusals no test can hold: 0 for an r or an s outside 1..n-1 with
  no arithmetic run, 0 for a key the decoder refused and for a sum at
  infinity, no x asked of a sum at infinity, and only scalars below n
  handed to the wide scalar routines and the sum.
  `p256_wide_verify_point` and `p256_wide_verify_digits` prove the
  points' formulas, their table reads and the digits memory-safe, and
  each digit zero or odd in [-15, 15]. `test/widemul-builds.sh` compiles
  `p256.c` either side of the define and holds each arm to its object.
- **Violation.** A PR multiplies G by u2 and the key by u1; checks r's
  range and not s's, which gives one signature a second encoding;
  compares R's x with r and never with r + n; multiplies a hash it did
  not reduce; compares the x of a sum at infinity; admits zero for r and
  s; computes on a key the decoder refused; leaves u1·G out of the sum;
  compares R's x with s; exchanges r and s at the entry; chooses
  `p256.c`'s arm on a define no build passes; or, in an addition of the
  pass, gives the point at infinity for two equal points, doubles two
  negatives, or runs the formula on a sum at infinity. The sixteen
  `inv43-*` violations are these. Ten fail `bin/p256_verify_equiv_test`,
  one the Wycheproof host leg, one `test/widemul-builds.sh`, and four
  the `p256_wide_verify` proof, which holds what a random signature does
  not show: a hash of n or more is one hash in 2^32, and with a check of
  r, s or the key gone the arithmetic after it gives an x that matches r
  one time in 2^256.

### INV-44 — a host object's ECDSA P-384 verifier gives the portable code's verdict

- **Claim.** `p384_wide_verify.c`, which a host object runs for
  `p384_ecdsa_verify` in every session, answers for every key, hash and
  signature what `p384.c`'s 32-bit arithmetic answers, which stays the
  reference. It refuses what FIPS 186-4 6.4.2 refuses before any
  arithmetic, an r or an s outside 1..n-1, a coordinate at or above p
  and a key off the curve, and it refuses a sum at infinity. Each
  routine of `p384_wide_field.c` leaves the number the routine of the
  same name in `p384_field.c` leaves.
- **Mechanism.** `p384.c` reads the DER signature with one reader for
  both arms and hands r and s to the arm its build compiled: a call into
  `p384_wide_verify.c` under `-DCH_CPU_RUNTIME`, and its own 32-bit
  arithmetic without it. `p384_field.c` has a body in a device object
  alone and the three 64-bit files in a host object alone, so an object
  holds one arithmetic. The host arm computes on six 64-bit limbs:
  `p384_wide_field.c` for both moduli, and `p384_wide_point.c` for the
  key, for u1·G + u2·Q in one pass over both scalars' signed digits,
  and for the comparison of the sum's x with r, which tests X against
  r·Z² and against (r + n)·Z² when r + n is below p. All of it is
  variable time, as `p384.c` is: every input is public, so no bit of
  `ch_cfg.cpu` picks the arm and no caller states the multiply's timing
  for it (decision 97).
- **Check.** `bin/p384_equiv_test` compiles both arms and both fields
  into one binary. It requires each routine of the field to leave
  `p384_field.c`'s number, for both moduli, on every pair of thirteen
  operands at the moduli's edges and on random pairs, in each shape of
  its arguments, and each constant to be one number at both widths. It
  then requires one verdict from the two verifiers, and the verdict
  each case names, over signatures of random scalars with one bit
  changed, scalars chosen either side of a digit's window and just
  under n, keys for which an addition inside the pass meets its own
  operand or its negative, hashes at and above n, a point whose x is
  above n, the values of r that are one modulus away from a point's x,
  r and s at the ends of their range, keys no point encodes, a key off
  the curve under the signature its multiple makes, and DER no reader
  takes. `bin/p384_test_host` runs the RFC 6979 vectors on the host
  arm, and the Wycheproof host leg runs Wycheproof's ECDSA P-384
  vectors on it. CBMC's `p384_wide_field` proves that no sum in the
  field wraps; `p384_wide_point` and `p384_wide_digits` that the points
  hand the field operands below p and read their table and their
  digits in bounds; and `p384_wide_verify`, over contracts of the
  points, the refusals no test can hold: 0 for an r or an s outside
  1..n-1 with no arithmetic run, and only scalars below n handed to the
  field. `test/widemul-builds.sh` compiles `p384.c` and each field
  either side of the define and holds each to its object.
- **Violation.** In the field, a PR changes the high half of the
  constant that clears a round's low limb; drops a round's last carry;
  returns the plain subtraction's carry for its borrow; or leaves the
  carry out of the sum's, or the top limb out of the product's, last
  subtraction. In the points, it adds a negative digit's multiple;
  drops the digit a carry out of bit 383 makes; answers infinity for
  two equal points, or a double for a point and its negative; takes
  r + n modulo 2^384, or at p and above, or never, for x's second
  value; or takes a key off the curve or with a coordinate at p. In the
  verifier, it exchanges the two scalars; compares x with s; compares x
  for a sum at infinity; computes on a key the decoder refused; admits
  zero, or n, for r and s; or multiplies a hash it did not reduce. At
  the entry, it exchanges r and s, chooses `p384.c`'s arm on a define
  no build passes, or keeps `p384_field.c`'s body in a host object. The
  twenty-four `inv44-*` violations are these. Nineteen fail
  `bin/p384_equiv_test`, two `test/widemul-builds.sh`, and three the
  `p384_wide_verify` proof: with one of those three applied every test
  passes, because zero and n give the verdict a refusal gives, and the
  Montgomery product reduces a hash that was not.

### INV-45 — sha3.c computes FIPS 202

- **Claim.** In every object, `sha3.c`'s permutation is Keccak-f[1600]
  and its sponge moves the bytes FIPS 202 moves. The round, written out
  lane by lane, is the standard's round for every state and every round
  constant. The table holds the standard's 24 constants in their order.
  Absorbing and squeezing eight bytes at a time leave the lanes and the
  output that one byte at a time leaves.
- **Mechanism.** One round is straight-line code: the five column
  parities, theta XORed into each lane in place, each lane rotated by
  its offset and read into the `b` that pi names, chi back into the
  array, and the round constant. `block_xor` and `block_bytes` move
  bytes between a message and the lanes in three steps: one byte at a
  time up to a lane's first byte, eight bytes at a time, and the bytes
  that do not fill a lane. Both name each byte of a lane by its place,
  so no object reads a lane in its host's byte order. No build chooses
  between two forms: every object compiles this one (decision 98).
- **Check.** CBMC's `sha3_round` proves the round equal to
  `proof/sha3_reference.h`'s for every state and every constant. That
  reference is the standard's five step algorithms as loops, with the
  rho offsets and the round constants computed by the standard's rules
  and read from no table. The same harness compares the table with the
  reference's constants and evaluates 24 rounds from the state of zeros
  against the reference's. `bin/sha3_equiv_test` holds the permutation,
  both digests and both XOFs to the reference's sponge, which moves one
  byte at a time, over 6,043 outputs: 3,602 states, a message of every
  length from 0 to 420 bytes and 200 random longer ones, and 600 SHAKE
  streams absorbed and squeezed in pieces of random lengths. The
  sanitizer build runs it, and the mips lane runs it on a big-endian
  core. `bin/sha3_test` runs the FIPS 202 vectors, and the spec
  differential runs every mode against the Lean model. `sha3` and
  `sha3_stream` prove every path memory-safe.
- **Violation.** A PR changes one rho offset; clears a bit of one round
  constant; stops a round short; XORs another column's theta value into
  a lane; exchanges chi's two neighbours; puts two bytes of a lane in
  each other's place; counts lanes from the block's first byte in a
  partly filled block, absorbing or squeezing; squeezes a second block
  without the permutation; moves the last pad bit; or takes eight bytes
  where fewer remain. The eleven `inv45-*` violations are these. Six
  fail `bin/sha3_equiv_test`, one `bin/sha3_test`, three the
  `sha3_round` proof and one the `sha3_stream` proof.

### INV-46 — a host object's ML-KEM NTT arithmetic gives the portable code's coefficients

- **Claim.** `mlkem_vector.c`, which a host object runs for ML-KEM's
  forward and inverse transforms and its base multiplication in every
  session, writes for every input of int16 coefficients the coefficients
  `mlkem_poly.c`'s loops write, which stay the reference and a device
  object's path.
- **Mechanism.** `mlkem.c` calls the three through static functions,
  which call `mlk_vector_ntt`, `mlk_vector_invntt` and
  `mlk_vector_basemul` under `-DCH_CPU_RUNTIME` and `mlkem_poly.c`'s
  three without it, so an object runs one of the two. Each lane computes
  the scalar Montgomery and Barrett values exactly, by the identities
  decision 101 states, and each step reads the twiddle factors the loops
  read from the one table in `mlkem_zetas.h`. The path runs no branch and
  computes no address from a coefficient (INV-16).
- **Check.** `bin/mlkem_vector_equiv_test` runs both transforms both
  ways on 7,029 polynomials each and compares every coefficient: every
  coefficient at one of five values, one coefficient at one of four edge
  values at each of the 256 positions, and 2,000 random polynomials
  from each of all of int16, [0, q) and [-2, 2]. It runs the base
  multiplication both ways on 5,049 pairs: every pair of the five
  values, among them -32768 times -32768, one coefficient at an edge
  value at each position against another edge value, and 2,000 random
  pairs from all of int16 and 2,000 from the ranges an NTT's output and
  a matrix entry hold. `make check` runs it on
  the host's instruction set, `make san-check` under the sanitizers, and
  `test/aes-runtime-qemu.sh mlkem-vector` on SSE2 and NEON under qemu.
  `bin/mlkem_test_host` and the Wycheproof host leg run the published
  ML-KEM-768 vectors on the path. `test/mlkem-builds.sh` compiles
  `mlkem.c` both ways, and `make lint-trust-separation` holds
  `mlkem_vector.c` to the host object.
- **Violation.** A PR has `mlkem.c` call a loop in a host object, for
  either transform or the base multiplication; reads the twiddle factor
  one entry off in the layer of span 8, or four entries off in the base
  multiplication; gives the two blocks of the layer of span 16 each
  other's factor; drops the forward transform's last reduction; ends the
  inverse with another factor than 1441; reduces a product of two odd
  coefficients with the even ones' constant; or, in one instruction set,
  drops the halving or the rounding of a reduction, splits coefficients
  into the wrong lanes, subtracts the wrong half of a product, keeps the
  low halves of the wide products, or multiplies two coefficients on
  SQDMULH, which saturates. The eighteen `inv46-*` violations are these.
  Three fail `test/mlkem-builds.sh`, six `bin/mlkem_vector_equiv_test` on
  either instruction set, and nine `test/docker-aes-runtime-qemu.sh
  mlkem-vector`, which runs the arm a machine's own compiler does not
  read.

### INV-48 — the four-way Keccak takes public input alone and gives sha3.c's streams

- **Claim.** `keccak_avx2.c`, which an x86-64 host object runs for
  ML-KEM's matrix in a session whose `ch_cfg.cpu` holds `CH_CPU_AVX2`,
  computes for every seed and pair of indices the SHAKE128 stream
  `sha3.c` computes, and takes nothing but public input: its one caller,
  `mlkem_avx2.c`'s row sampler, hands it the seed rho, which the
  encapsulation key carries in the clear, and two indices.
  `mlkem_avx2.c`, `mlkem.c` compiled once more with that sampler, writes
  the keys, ciphertexts and secrets `mlkem.c` writes.
- **Mechanism.** The round in `keccak_avx2.c` is `sha3.c`'s, line for
  line, on four lanes at once, and reads the round constants `sha3.c`
  reads, from `keccak_round_constants.h`. The row sampler runs each block
  of each stream through `mlk_sample_groups`, the rejection step
  `mlk_sample_ntt` runs, until every entry holds 256 coefficients or its
  stream has given `MLK_SAMPLE_GROUPS` groups. `mlkem.c` leaves
  `mlk_matvec_row` alone to the copy (`CH_MLKEM_AVX2_COPY`), so the
  copy's noise, hashes and arithmetic are `mlkem.c`'s text on `sha3.c`,
  and `mlkem.h`'s entries run the copy exactly where the value holds
  `CH_CPU_AVX2`. The four-way Keccak keeps lanes in stack slots its
  compiler picks, which no wipe clears, and that is why no secret may
  reach it (decision 107).
- **Check.** `bin/mlkem_avx2_equiv_test` compares ten blocks of each of
  the four streams with `sha3.c`'s SHAKE128 for 200 random seeds, each
  state with an index pair of its own; the copy's key generation,
  encapsulation and decapsulation with `mlkem.c`'s for 200 random seeds
  under each answer a compression runs under, the implicit-reject secret
  included; and the three session calls under a value with
  `CH_CPU_AVX2` and one without. It counts the sampled entries whose
  stream needs a fourth block and fails if there are none. `make check`
  runs it on an x86-64 host with AVX2, `make san-check` under the
  sanitizers, and `test/aes-runtime-qemu.sh mlkem-avx2` under qemu on
  any machine. `bin/x86_kernels_test` counts the copy's calls under
  seventeen values. `test/mlkem-builds.sh` requires the copy's rows to
  call the four-way Keccak and not `mlk_sample_ntt`, both files to hold
  nothing on arm64, and no other source at the root to include
  `keccak_avx2.h` or call its entries, and `make lint-trust-separation`
  holds both files to the host object.
- **Violation.** A PR rotates a lane by the wrong count or shuffles the
  wrong bytes for the rotation by 8; drops chi's complement or iota;
  writes the wrong domain bits or pad bit at the start; hands a state the
  wrong index; reads a block's bytes from the wrong state; parses one
  group too few of a block; swaps the indices of A and A^T in the copy;
  has `mlkem.h`'s entries run the copy without the bit or the portable
  calls with it; samples the copy's rows on `sha3.c`; or includes
  `keccak_avx2.h` in a source that reads secrets. The fifteen `inv48-*`
  violations are these. Eleven fail `test/docker-aes-runtime-qemu.sh
  mlkem-avx2`, two `test/docker-aes-runtime-qemu.sh x86-kernels`, and two
  `test/mlkem-builds.sh`.

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
  `TRANSPORT_NAMED` gives `ch_ticket_obfuscated_age` its transport's name
  the way it gives the record, and `inv35-ticket-age-not-transport-named`,
  which drops it from the list, is caught by
  `test/lib-check-webpki-tcp-nonblocking.sh`.
  `test/hpp_test.cpp` calls the C++ forwarder on the `cxx-check` legs.
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

### INV-36 — build.zig packages the object `make lib` packages

- **Claim.** For a configuration both builds accept, the object
  `build.zig` produces compiles the same sources under the same defines as
  `make lib`, exports the same names, and holds the same build record.
  Every other symbol it defines is local, so one image links a Zig-built
  object of each of two transports, as it links make's. The module
  `chapulin` that the package exports is the Zig API, and it carries the
  object, so a program that imports it links the object once and adds none
  of its own. Its `chapulin.c` declares every name the object exports, and
  every function it declares under a `ch_` name is one the object exports
  or imports, so a program that calls a function the object lacks fails to
  compile rather than to link. Its types have the layout the object's
  build record describes. `chapulin.c` is translated from `x509_ca.h` and
  `drbg.h` only where the object exports their call, and for any other
  object each declares no `ch_` function the object lacks, so a C program
  of that object that calls one fails to compile too. The API declares a
  Zig call for each C call it covers, forwards to that call, maps each
  code the call returns to one error, builds `ch_cfg` only from the
  fields each value names, and keeps no TLS rule of its own: a record's
  length, a write's size and a ticket's age come from the C calls that
  compute them. Both builds give a `TRUST=webpki` client, `ROLE=server`
  and `ROLE=both` the host object, `-DCH_CPU_RUNTIME`, on a target that
  passes the host test, arm64 or x86-64 with NEON or SSE2 on a
  little-endian core and `unsigned __int128`, and give every other product
  and every other target the portable object; `cpu_cfg.h` stops the
  define for a target that fails the test (decisions.md 89).
- **Mechanism.** `build.zig` repeats the Makefile's axis blocks, one
  function per block, and writes the lists it compiles to `lib-srcs.txt`
  and `lib-def.txt`. `tools/localize_symbols.zig` makes every defined
  global but the public names local, as `objcopy -G` and `nmedit -s` do
  for make, and refuses an object it cannot rewrite in full. translate-c
  makes `chapulin.c` from the headers that declare the object's exports
  and imports, under every `-D` of the one flag list the sources compile
  with. Each public header declares a call only under the defines of the
  objects that define it: by role and by transport, as `tls.h`,
  `tcp_nonblocking.h`, `quic.h` and `srv.h` guard their calls, by trust
  mode, as `x509_ca.h` declares `ch_pubkey_from_pem` under `CH_TRUST_CA`,
  and by entropy pattern, as `drbg.h` declares `ch_drbg_seed` under
  `CH_RAND_DRBG` and `rand.h` declares no `ch_rand_bytes` under
  `CH_RAND_SESSION`. A test binary that runs the provisioning walk outside a
  CA build defines `CH_X509_CA_TEST`, which no object's defines include.
  `build.zig` copies `chapulin.zig`, `chapulin_record.zig`,
  `chapulin_quic.zig` and `chapulin_ticket.zig` into a directory of the
  configuration's own, roots
  the module there, and adds the object to it with `addObjectFile`. The
  Makefile runs the host test on `$(CC)`'s predefined macros
  (`HOST_TARGET`) and `build.zig` on the resolved target's architecture
  and features (`hostTarget`), and each tells a device client apart by
  its role and trust mode (`DEVICE_CLIENT`, `deviceClient`). A command
  line that sets `HOST_TARGET` empty gets the portable object of a host
  product on a host.
- **Check.** `make lint-zig-build` runs `test/zig-build-check.sh`, which
  builds the default object, the four colibri links, stompy's
  `TX_RECORD=16384` object and a `SUITE=aesgcm` record-mode object both
  ways and compares their sources, defines
  and exports, links `test/build_test.c` against each Zig object under
  make's defines, and links two Zig objects of different transports into
  one image and runs it. It builds `test/zig-consumer`, a Zig project
  that depends on the package and adds no object, against each object:
  `matches.zig` compiles only when `chapulin.c` declares every export
  and declares no `ch_` function the object neither exports nor imports,
  the imports those `nm -u` lists, and runs `ch_build_matches` over its
  types; `unit.zig` checks each value's `toCfg` against the `ch_cfg`
  written out field by field, the Ticket constructors' bounds, the
  error of every code, and compiles every declaration the object has;
  `loop.zig` runs a client and a server
  of each `ROLE=both` object against each other through the API alone,
  in record mode and over QUIC (`docs/zig.md`, "How it is checked"), and
  under `SUITE=aesgcm` has each side write across its AES-GCM write key's
  ceiling, where `writableLen` must count the KeyUpdate record to the
  byte and `write` must refuse whole an output one byte short of the
  records it seals; and
  `pair.zig` imports the modules of two transports and starts a client on
  each through its API. Where `chapulin.c` leaves out `x509_ca.h` or
  `drbg.h`, the script translates that header with `zig translate-c`
  under the same defines and refuses a `ch_` function the result
  declares that the object neither exports nor imports. Before
  `matches.zig`, `tools/public-constants.py` lists every length and cap
  the public headers' comments name in the regions the object compiles,
  and fails when the consumer cannot see one; `matches.zig` then
  declares and evaluates each. check-slow runs the script over every
  `lib-check` leg's configuration too.
  The same target runs `test/localize-check.sh`, which compares the
  localizer with `llvm-objcopy -G` on nine ELF targets and with
  `llvm-objcopy -G` and `nmedit -s` on two Mach-O ones, and links every
  result. Eight mutants in `test/violations/` are each caught by one of
  the two scripts: `inv36-zig-build-drops-source`,
  `inv36-zig-build-adds-define`, `inv36-zig-build-keeps-internal-global`,
  `inv36-zig-module-drops-define` and `inv36-zig-module-misses-header`
  edit `build.zig`, `inv36-public-header-names-hidden-length` names a
  length in `srv_cfg.h` that no public header defines, and
  `inv36-localize-elf-keeps-weak-global` and
  `inv36-localize-macho-keeps-external-bit` edit the localizer. The
  comparison builds only values both builds accept, so
  `test/tx-record-builds.sh` holds `build.zig`'s `TX_RECORD` refusals to
  the Makefile's, and `inv36-zig-build-tx-record-past-2-14` requires it
  to fail. Thirteen more break the API, the module, the public headers or
  the reverse check in `matches.zig`, and `test/zig-build-check.sh`
  catches each:
  `inv36-zig-module-drops-object` takes the object off the module, so
  every consumer program fails to link; `inv36-zig-api-drops-ticket-age`
  leaves `ch_cfg.ticket_age_ms` at 0 in `Client.toCfg`, so a stale ticket
  resumes; `inv36-zig-api-write-seals-part` seals the part of `pt` that
  fits where `write` must refuse it whole;
  `inv36-zig-api-write-sizes-without-key-update` sizes `write`'s output
  in Zig rather than through `ch_writable_len`, without the KeyUpdate
  record, which only the `SUITE=aesgcm` loop's write across the ceiling
  notices;
  `inv36-zig-api-auth-proto-swapped` swaps two codes in the error table;
  `inv36-zig-api-close-without-notify` closes without a close_notify;
  `inv36-zig-api-ticket-drops-binding` zeroes a copied ticket's binding,
  so it no longer resumes; `inv36-zig-api-ticket-drops-quic-version`
  zeroes a copied ticket's QUIC version, so `ch_quic_init` refuses it;
  `inv36-zig-api-ticket-slot-kept` leaves
  the resumption PSK in the slot after `takeTicket` and `recordClose`;
  `inv36-header-client-driver-in-server` declares the client's driver in
  `tcp_nonblocking.h` for a `ROLE=server` object, and
  `inv36-header-connect-in-tcp-nonblocking` declares `ch_connect` in a
  `TRANSPORT=tcp-nonblocking` one, which matches.zig refuses in each;
  `inv36-zig-reverse-check-inverted` turns that refusal around, so the
  default object's `ch_connect` fails it, which shows the walk over
  `chapulin.c` runs the comparison; and
  `inv36-header-pubkey-from-pem-outside-ca` declares `ch_pubkey_from_pem`
  outside a CA build, which the script's translation of `x509_ca.h`
  refuses for the default object. The script also catches
  `inv38-zig-writable-len-skips-key-update` (INV-38).
  The host test has rows of its own. `lint-trust-separation` sets
  `HOST_TARGET` to `yes` and to empty on each row's command line, and
  requires `-DCH_CPU_RUNTIME` of a `TRUST=webpki` client, `ROLE=server`,
  `ROLE=both` with a raw client half and `ROLE=both` with a webpki one on
  a host target alone, and of no device client on either.
  `test/host-builds.sh` compiles `cpu_cfg.h` under the define on this
  host's compiler and for six targets the pinned clang builds, each of
  the first five failing one probe, and requires the header to refuse
  each of the six, the Makefile to pass no define under a compiler for
  any of them, and `build.zig` to pass it for this host and for arm64 and
  x86-64 Linux and not for a Cortex-M3 or a big-endian arm64 core.
  `lint-zig-build` compares the two builds' defines on this host, where
  both run the test. Six mutants break the host test, and each is
  caught: `inv36-host-define-on-device-client` and
  `inv36-host-define-dropped` by `test/lint-trust-separation.sh`,
  `inv36-cpu-cfg-admits-another-architecture`,
  `inv36-host-test-skips-the-vector-probe` and
  `inv36-zig-host-test-takes-big-endian` by `test/host-builds.sh`, and
  `inv36-zig-host-define-on-device-client` by `test/zig-build-check.sh`.
  The slot's `std.crypto.secureZero` has no mutant of its own. Storing
  null leaves an optional's payload undefined, and what Zig 0.16.0
  writes there depends on the backend: LLVM wrote zeros in every mode
  measured, and Zig's own x86_64 backend, the default for a Debug build
  on Linux x86_64, wrote 0xAA. So dropping the call fails the loop only
  on that backend, and a mutant that drops it would go uncaught on any
  other host. The call keeps the rule for a backend that writes the
  flag alone. It runs after the null store, because on the x86_64
  backend the store overwrites zeros written before it.
- **Violation.** A PR changes an axis in the Makefile and not in
  `build.zig`, or the reverse, or teaches the localizer a symbol it leaves
  global, or translates the module under other defines or headers than
  the object's, or a public header names a length its consumer cannot
  see. For the API, a PR adds a rule C does not hold, such as a record
  length or a ticket age computed in Zig, maps a code to another error,
  sets a `ch_cfg` field no value names, or tells a program to add the
  object the module already carries. For the headers, a PR declares a
  call in an object that does not define it. The checks catch the change
  in each configuration they build. A combination of values that
  neither list builds is caught by nothing until a dependent builds it.
- See [decisions: Engineering](decisions.md#engineering), entries 69, 70
  and 73.

### INV-37 — a stamp skips a check only on inputs the check passed on

- **Claim.** `make check` skips a lint, a Wycheproof leg or a
  packaged-object leg only when every input it reads is byte for byte
  what it was when that check last passed. A skip never stands in for a
  run over an input the check did not see.
- **Mechanism.** `tools/stamp.py` keys a check on a SHA-256 over the
  inputs its Makefile line names: the bytes of the files git lists for a
  pathspec, the output of a command such as a tool's `--version` or a
  compile run with `-E`, the command itself, the variables make was given
  and the environment's compilers, flags and `PATH`. A stamp holds
  content, never a time, so a same-second edit that make 3.81 cannot see
  still changes the key. `tools/tidy-each.py` keys each translation unit
  on every file `clang -M` lists for it, system headers included.
  `lint-cppcheck-run` gives cppcheck a build directory per command line
  and absolute paths, so each file keeps its own saved analysis and the
  whole-program pass reads all of them. `lint-wide-multiply` keeps each
  compile's assembly under a key over the preprocessed source and
  computes its counts on every run. A stamp is written only after the
  check passes and only when its key reads the same before and after the
  run. CI starts each job with no `bin/`, so CI runs every check in full.
- **Check.** Three mutants in `test/violations/` each change an input
  that a narrower key would miss: `inv37-tidy-header-finding` edits a
  header and not the sources that include it, caught by
  `test/lint-tidy.sh`; `inv37-cppcheck-cross-file-null` edits a caller
  whose null argument cppcheck reports only by joining it to a callee
  read from the build directory, caught by `test/lint-cppcheck.sh`; and
  `inv37-wycheproof-vector-flipped` edits the vector generator and no C
  source, caught by `test/wycheproof.sh`. Those catch scripts run one
  lint alone, without `lint-toolchain`, so `lint-tidy` and `lint-cppcheck`
  each fail on a checker whose `--version` is not the pin, before they
  read a stamp (`REQUIRE_PINNED`). `test/pinned-checkers.sh`, run by
  `make lint-pinned-checkers`, hands each lint an older and a newer
  stand-in and requires each run to fail and name the pin;
  `inv37-tidy-takes-unpinned-checker` and
  `inv37-cppcheck-takes-unpinned-checker` remove the check, and the
  script objects. Every other lint violation in that directory runs
  through its lint's stamp too, since each catch script calls the stamped
  make target, so each of those mutants shows its lint's key sees the
  edit.
- **Violation.** A PR adds a stamp whose inputs leave out a file the
  check reads, for one a script the check sources or a header outside
  the pathspec, or a tool whose version string does not change. The
  mutants catch a key that leaves out headers, the build directory's
  saved analysis or generated vectors; a new stamp is held by review to
  the rule in `tools/stamp.py`: name more inputs, never fewer.
- See `tools/stamp.py` and the Makefile's comment above `check`.

### INV-40 — a build outside check links what its sources call

- **Claim.** A program that a recipe or a script builds outside
  `make check` takes its sources from a list a rule that check builds
  links, or `make check` builds the program itself. So a call that one
  source gains into another fails `make check` before it breaks such a
  build. The three differential arms and `test/spec_coverage.py` are
  the exception: they share `bin/diff`'s list, which `make check-slow`
  builds.
- **Mechanism.** The lanes that rebuild a test check builds take that
  test's sources from the variable the test's own rule reads:
  `san-check`, `cross-check`, `m3-check`, `coverage`, the
  `CH_CT_WIDEMUL` builds, the host object's binaries and the Wycheproof legs
  read `DRBG_TEST_SRCS`, `RSA_TEST_SRCS`, `WYCHEPROOF_SRCS` and the
  rest, and the three differential arms read `DIFF_SRCS`, which
  `bin/diff` reads. The
  scripts ask make: `bench/aead.sh` and `bench/record.sh` read
  `AES_HW_SRCS`, `test/aes-runtime-qemu.sh` reads the lists its six
  binaries' rules link, `bench/insn-m3.sh`, `bench/insn-mips.sh` and
  `bench/insn-rv32.sh` read `INSN_SRCS` and `INSN_DEF`, and
  `test/spec_coverage.py` links `DIFF_SRCS`. What a script still lists
  itself, `make check` builds without running it: `check-script-builds`
  runs `test/script-builds.sh`, which runs `bench/aead.sh --build`,
  `bench/record.sh --build`, `bench/primitives.sh --build` and
  `test/qemu-m3.sh --build`, and builds `bench/insn_driver.c` from
  `INSN_SRCS` and `INSN_DEF`.
- **Check.** `inv40-aead-calls-hkdf` gives `aead.c` a call into
  `hkdf.c`, which the list `test/qemu-m3.sh` keeps leaves out, and
  `test/script-builds.sh` catches it: the script's host build stops
  linking.
- **Violation.** A PR writes a recipe that names a test's sources
  itself rather than through the test's variable, or adds a script that
  compiles a list of its own and that `test/script-builds.sh` does not
  build. Review holds both: no lint reads a recipe or a script for a
  literal source list.
- The host builds check the lists, not each target's flags: a call a
  source makes only on a device core, such as one `softmul.c` would make
  where the core has no multiplier, links on the host whatever the list
  says. `proof/run.sh` names each harness's sources itself, because a
  harness chooses which callees are stubs, and it rejects a result whose
  log names a callee with no body.
- The host builds do not check a target's headers either. The
  Cortex-M3 build of `test/qemu-m3.sh` compiles with `-nostdlibinc`, so
  a source that gains a libc header compiles on the host and not there:
  `ct_wipe.c` gained `<string.h>`, and `test/qemu/libc/string.h` now
  declares what `test/qemu/m3_runtime.c` defines. Only the script's run
  builds for the Cortex-M3, so on CI the script fails where a tool it
  needs is missing, and skips only on a development machine. CI's check
  job once skipped it, for a linker the script looked for under another
  name, and the broken build went unseen. `inv40-qemu-m3-skips-on-ci`
  turns the failure back into a skip, and `test/script-builds.sh`
  catches it: it runs the script with `CI` set and no linker, and
  requires it to fail.
- See [decisions: Engineering](decisions.md#engineering), entry 88.

### INV-47 — a full harness or an audit covers every shipped source

- **Claim.** Every source a packaged object compiles is compiled by a
  CBMC harness that `proof/run.sh` launches with the `full` check set.
  That set checks for out-of-bounds access, invalid pointers, bad
  shifts, division by zero and signed overflow. The harness proves them
  absent only in the calls it drives, in the build it compiles, at its
  bound, so part of a source can stay unproved: a call no harness
  drives, or an arm that only another build compiles. Each harness's
  entry (docs/verification.md, "Harnesses") states what it proves and
  at what bound. A source no such harness compiles is a copy of one
  that passes, its text compiled once more under a header of renames,
  or it carries an `AUDITED` entry in `tools/proof-cover.py`: what
  holds its signed arithmetic, written by someone who read the file,
  and which test holds the file to the proven code. `.clang-tidy` turns
  `bugprone-signed-bitwise` off on the strength of this claim.
- **Mechanism.** `make lint-proof-cover` runs `tools/proof-cover.py`.
  It asks the Makefile's `print-lib-srcs` for the sources of each build
  in `BUILDS` (`tools/shipped_sources.py`), a list of builds that between
  them take every value of every axis that picks a source, and adds each
  source whose text one of those includes. `make impact` reads the same
  set, so the plan for a change to one of those sources runs this lint. It
  fails when a root `.c` file is in none of them, so a source that a
  `LIB_SRCS +=` line adds under a build the list lacks fails too. It
  reads the `full` launch lines and the sources each harness includes,
  and on every run it reads each file `COPIES` names and fails one that
  holds a line of its own or includes a source other than the one named.
- **Check.** `inv47-sha3-hw-audit-dropped` deletes `sha3_hw.c`'s
  `AUDITED` entry, and `test/lint-proof-cover.sh` catches it. A host
  object packages `sha3_hw.c` through `hash_hw_of` on a `LIB_SRCS +=`
  line, the kind of line the lint did not read while it parsed the
  Makefile's assignments itself.
- **Violation.** A PR adds a source, or a build value that packages
  one, with neither a harness nor an `AUDITED` entry, or it moves a
  source's last `full` launch line to a narrower check set. An `AUDITED`
  entry is checked for presence only, so review holds what it says: a
  file that changes shape owes a fresh reading.

## Fail-closed

### INV-13 — no resumable errors

- **Claim.** Every error kills the session: alert, wipe, dead. There
  is no error a caller can retry past. The failure records the alert it
  chose, which `ch_alert_sent` reports (alert.h), and the call that
  failed sends that alert as one record: sealed under this side's write
  key once there is one, in the clear before it, and with no key left
  after the wipe (docs/decisions.md 76). A send the caller's transport
  refused is this side's failure, and every driver records
  internal_error for it, the NewSessionTicket a server pushes after the
  client Finished included. The peer's fatal alert
  kills the session with no alert of this side's, sent or recorded, and
  `ch_alert_received` reports the peer's (INV-22). Three kinds of result are not
  errors in that sense, and each public header says which of its codes
  are which, call by call; cfg.h states the rule beside the codes:
  - A refusal on entry, `CH_EINVAL`, which sent nothing. An init call,
    `ch_connect`, `ch_record_init`, `ch_quic_init`, `ch_srv_accept`,
    `ch_srv_record_init` or `ch_srv_quic_init`, leaves its session failed
    until the next init; every other call leaves the session as it was.
    No call returns `CH_EINVAL` after it has sent a byte: a server
    checks at init every identity fact its flight would otherwise meet
    (INV-14), and its flight answers its own refusals with `CH_EAUTH`
    (docs/decisions.md 74). A CA build's resuming ticket whose
    `ticket_epoch` is below the stored epoch is a refusal on entry too
    (docs/ca.md): `ch_connect`, `ch_record_init` and `ch_quic_init` each
    return `CH_EINVAL` for it and leave `CH_EPOCH_REVOKED` in
    `ch_tls.epoch_status`. A first ClientHello too long for `ch_tls.tx`
    would be one too, because each client entry builds that hello before
    it sends or stages a byte, but no accepted configuration makes one:
    the configuration check holds a PSK identity to `CH_TICKET_ID_MAX`
    bytes (INV-14, docs/decisions.md 84). The two
    non-blocking entries zero their session on a refusal but for
    `ch_tls.epoch`, `epoch_seen` and `epoch_status`
    (`tcp_nonblocking_refuse_init`, `quic_refuse_init`).
  - A call on a session that cannot take it, which changes nothing:
    `CH_EPROTO` for bytes delivered to a session that failed or closed,
    and from `ch_read` and `ch_write` before the handshake completes,
    which in a `TRANSPORT=tcp-nonblocking` build leaves the handshake
    running; `CH_EINVAL` where the call's header says so.
  - The non-blocking transports' results that leave the session live:
    `CH_ECAP` from a call whose own output buffer was short, a packet
    dropped (`CH_QUIC_DISCARD`, RFC 9001 §5.5), and no record yet
    (`CH_RECORD_AGAIN`).

  A failed QUIC session stays dead: it keeps only the write keys INV-17
  names, for one CONNECTION_CLOSE per level, and no call revives it.
- `CH_RECORD_AGAIN` is the one returned after work was done, so its
  terms are exact. `ch_read` returns it only when `cfg.recv` returns 0
  before a record's first byte. Every record read before that has been
  opened and handled: a NewSessionTicket went to `on_ticket`, a
  KeyUpdate changed the keys, and the first part of a message split
  across records waits at the front of `cfg.buf`, with
  `ch_tls.post_fill` counting its bytes. A 0 after a record's first byte
  is `CH_EIO` and a dead session.
- **Mechanism.** Fail-closed policy with one funnel per driver family:
  `tlsi_fail` for the record layer and the blocking drivers,
  `tcp_nonblocking_fail` for the tcp-nonblocking handshake drivers and
  `quic_fail` for the QUIC ones. Each funnel writes `ch_tls.alert_sent`,
  the one field `ch_alert_sent` reads, and `quic_fail` writes the same
  description to `ch_quic.alert`. `tlsi_fail` sends the alert through
  `cfg.send`. `tcp_nonblocking_fail` writes it as one record before its
  wipe, sealed under `ch_tls.wr` when `ch_tls.keys` is set and in the
  clear otherwise, and the driver that called it emits the record the
  way it emits its others: the client stages it in `ch_tls.tx` for
  `ch_record_out`, and the server pushes it through
  `cfg.srv.on_record_out`. `tlsi_fail` and `tcp_nonblocking_fail` write
  and send nothing once `ch_tls.alert_received` is set. Each send writes
  internal_error where the transport refused it: `srv_out.c` for every
  server record and CRYPTO push, `send_staged` in `handshake.c` for the
  blocking client, `take_key_update` for `ch_read`'s KeyUpdate reply,
  and `ch_write` itself. The two non-blocking servers return a failed
  ticket before they wipe `hs`, so `tcp_nonblocking_fail` and
  `quic_fail` read its alert. Each entry
  checks its configuration or its arguments before it sends a byte, and
  returns early, changing nothing, when the session cannot take the
  call. `io_read_record` is the only source of `CH_RECORD_AGAIN`, and
  `dispatch_one_record` in `tls.c` and `hspost_read` in
  `handshake_post.c` are the only places that return it without calling
  `tlsi_fail`.
- **Check.** Convention; handshake_sequence's 466k-sequence run asserts no
  sequence revives a failed session. `bin/tcp_nonblocking_loop_test`
  (`test/tcp_nonblocking_read_tests.h`) reads a ticket-only record and
  then nothing, a ticket split across two records, and a record cut off
  after three bytes. Three violations each break one term:
  `inv13-tcp-nonblocking-read-dies-between-records`,
  `inv13-tcp-nonblocking-read-drops-a-split-message` and
  `inv13-record-again-inside-a-record`. `inv13-ch-write-soft-io-error`
  returns a failed send from `ch_write` without the funnel, and
  `bin/unit` fails. The server's flight returns no `CH_EINVAL`:
  `bin/srv_auth_test` and `bin/srv_flight_test` require `CH_EAUTH` from
  each refusal inside it, and `inv13-srv-signer-refusal-einval`, which
  returns `CH_EINVAL` from a signer's refusal again, requires
  `bin/srv_auth_test` to fail. The entry refusals are INV-14's, each
  with its tests. The retired ticket has a boundary pair at each client
  entry: a ticket at the stored epoch is taken, and one a step below it
  gets `CH_EINVAL` with no byte sent or staged, no alert recorded and
  `CH_EPOCH_REVOKED` in `epoch_status`.
  `bin/unit_ca` (`test/session_cfg_tests.h`) holds `ch_connect` to it,
  and `bin/ticket_epoch_tcp_nonblocking` and `bin/ticket_epoch_quic`
  (`test/ticket_epoch_test.c`) hold `ch_record_init` and `ch_quic_init`.
  `inv13-ticket-epoch-refusal-eauth` returns `CH_EAUTH` from
  `ch_connect` for that ticket again, and `bin/unit_ca` fails.
  `inv13-tcp-nonblocking-refusal-zeroes-epoch` and
  `inv13-quic-refusal-zeroes-epoch` zero the epoch fields in a refusal
  again, and the two ticket epoch binaries fail. No test reaches the
  drivers' branches for a hello too long for `ch_tls.tx`, first or
  retried, because no accepted configuration does; INV-14's identity
  bound, with its own boundary rows and violations, is what keeps them
  unreachable. Each
  funnel's recorded alert is tested:
  `bin/unit` (`test/session_alert_tests.h`) reads `ch_alert_sent` after
  `tlsi_fail` sent decode_error, unexpected_message and internal_error,
  `bin/tcp_blocking_loop_test` after each blocking driver's
  unexpected_message, `bin/tcp_nonblocking_loop_test` after each
  handshake failure below, and `bin/quic_driver_test` and
  `bin/quic_loop_test` after each QUIC role's failure, where it equals
  `ch_quic_alert`. `inv13-fail-records-no-alert`,
  `inv13-tcp-nonblocking-fail-records-no-alert` and
  `inv13-quic-fail-records-no-alert` each drop one funnel's write, and
  `bin/unit`, `bin/tcp_nonblocking_loop_test` and `bin/quic_driver_test`
  catch them. A refused send is tested in each driver, and each test
  requires internal_error:
  - `bin/unit` (`test/session_hello_tests.h`,
    `test/session_alert_tests.h`) fails `ch_connect`'s hello and
    `ch_read`'s KeyUpdate reply;
  - `bin/srv_flight_test` fails the blocking server's ServerHello and
    ticket;
  - `bin/srv_tcp_nonblocking_test` fails the tcp-nonblocking
    ServerHello, and `bin/tcp_nonblocking_loop_test` its
    EncryptedExtensions and ticket;
  - `bin/quic_loop_test` (`test/quic_loop_close.h`) fails the QUIC
    server's ticket, which must report 0x0150.

  `inv13-client-refused-send-keeps-default-alert`,
  `inv13-key-update-reply-refused-keeps-default-alert`,
  `inv13-srv-refused-record-keeps-default-alert` and
  `inv13-srv-quic-refused-push-keeps-default-alert` each drop one send's
  internal_error, and `inv13-tcp-nonblocking-ticket-failure-wipes-its-alert`
  and `inv13-srv-quic-ticket-failure-wipes-its-alert` wipe the ticket's
  alert before `tcp_nonblocking_fail` or `quic_fail` reads it; each is
  caught. The tcp-nonblocking
  alert record is tested between the two drivers:
  `bin/tcp_nonblocking_loop_test` and `bin/tcp_nonblocking_loop_pq`
  (`test/tcp_nonblocking_failure_alert_tests.h`) fail each side at the
  last check before its write key and the first after it, and at a
  wrong pin, a client Finished and a refused ticket push after it. Each
  failure emits one record: `REC_HDR + 2` bytes in the clear before the
  key, and `CH_ALERT_RECORD_LEN` bytes after it that open to 2 bytes of
  plaintext under a copy of the peer's read key. `ch_record_out` hands the client's
  record over once and then answers `CH_EINVAL`, and the other side reads
  each record through `ch_alert_received`. `test/zig-consumer/loop_record.zig`
  runs failures on both sides of each key through the Zig API and
  collects the server's record through `outputLen()`. Four violations
  each break one term, and `bin/tcp_nonblocking_loop_test` catches each:
  `inv13-tcp-nonblocking-alert-clear-after-key`,
  `inv13-tcp-nonblocking-seals-after-wipe`,
  `inv13-tcp-nonblocking-client-stages-no-alert` and
  `inv13-tcp-nonblocking-server-pushes-no-alert`.
- **Violation.** A PR returns a "soft" error that leaves keys live so
  the caller can retry a read, or adds a failure path that records no
  alert, or one that sends an alert after the peer's fatal alert, or
  leaves a tcp-nonblocking alert for the caller to send, who holds no
  key to protect it with, or answers a retired ticket on one client
  entry with a code or an epoch report the other two do not leave, or
  records a peer's fault for a send its own transport refused.
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
  verify for the key, the QUIC version and the client's address, which
  is what a token minted under the other version gives, or whose issue
  instant is after now or more than the lifetime before it with
  `CH_EAUTH`. Neither refusal writes the connection IDs the caller would
  read, and both token calls refuse a version the build derives no keys
  for with `CH_EINVAL`. A server
  (`srv_select_auth`, `srv_resume.c`) considers a PSK only under
  `psk_dhe_ke`, and only with a ticket key and a clock; it passes over,
  without failing the handshake, a ticket of any length but
  `SRV_TICKET_LEN`, one that does not open under the ticket key, one
  issued after its clock or more than `SRV_TICKET_LIFETIME` seconds
  before it, one whose suite it does not hold, one whose ALPN
  protocol is not the one this connection selected, and one whose QUIC
  version is not the one this connection negotiated, 0 over TCP, which
  RFC 9369 §5 asks of a server (`rfc9369.txt:276-281`); and it refuses the
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
  (docs/decisions.md 59). Every client entry, `ch_connect`,
  `ch_record_init` and `ch_quic_init`, refuses with `CH_EINVAL` and
  sends nothing a configuration with `resumption` set whose
  `ticket_age_ms` is above `ticket_lifetime_s` seconds or above
  `CH_TICKET_LIFETIME_MAX` seconds, seven days, where a lifetime of 0 is
  none given (`hspost_ticket_age_ok`, handshake_post.h). Each also
  refuses, the same way, a PSK whose identity is not 1 to
  `CH_TICKET_ID_MAX` bytes: `psk_id_len_ok` in `tls.c` and
  `quic_config.c` in the raw and ca modes, and `ticket_shape_ok` under
  `TRUST=webpki`. RFC 9846 §4.3.11 gives an identity at least one byte
  (rfc9846.txt:2468-2471), and `hello_build` proves that `CH_HELLO_MAX`
  holds every hello whose identity is in that range, so the bound keeps
  every ClientHello a client builds inside `ch_tls.tx` (docs/decisions.md
  84). `ch_quic_init`
  also refuses, with `CH_EINVAL` and nothing sent, a configuration with
  `resumption` set whose `ticket_quic_version` is not its
  `quic_original_version`, 0 included, because RFC 9369 §5 forbids a
  client to start a connection in one QUIC version with a ticket from
  another (`rfc9369.txt:268-271`); `handle_ticket` writes the connection's
  negotiated version into each `ch_ticket` it hands over. The
  post-handshake parser hands `on_ticket` no NewSessionTicket whose
  `ticket_lifetime` is 0, which RFC 9846 §4.6.1 says to discard at once,
  and `ch_ticket_obfuscated_age` adds the ticket's `age_add` to the age
  modulo 2^32 (docs/decisions.md 72). In either role the same parser
  refuses a KeyUpdate whose request_update is neither 0 nor 1 with
  illegal_parameter, before it rekeys (§4.7.3, rfc9846.txt:3362-3365):
  `bin/unit` reads 0 and 1 as requests and requires illegal_parameter for
  2 and 255, and `inv14-key-update-illegal-value-unexpected` requires
  `bin/unit` to fail when it answers unexpected_message. The same parser
  refuses a KeyUpdate whose body is not one byte and a NewSessionTicket
  whose fields do not fill it with decode_error, which §6 requires for a
  message that does not parse (rfc9846.txt:3785-3788): `bin/unit`
  requires it for KeyUpdate bodies of 0 and 2 bytes and for three
  malformed tickets, and `inv14-key-update-length-unexpected` and
  `inv14-ticket-framing-unexpected` require `bin/unit` to fail when
  either answers unexpected_message. The `handshake_post` harness proves
  those two are the only alerts the parser writes, each on a refusal. A
  server's `ch_read` refuses a
  NewSessionTicket with unexpected_message, because RFC 9846 §4.7.1
  gives the message to the server to send (rfc9846.txt:3194-3196) and §4
  refuses one out of order (rfc9846.txt:1054-1058); each server entry
  sets `ch_tls.server`, so a `ROLE=both` object tells its sessions apart.
  `bin/tcp_blocking_loop_test` and `bin/tcp_nonblocking_loop_test` send
  one to `ch_srv_accept`'s and `ch_srv_record_init`'s sessions and require
  unexpected_message and no `on_ticket` call, and
  `inv14-server-takes-client-ticket`,
  `inv14-srv-accept-leaves-session-unmarked` and
  `inv14-srv-record-init-leaves-session-unmarked` each require one of
  them to fail. Every server entry,
  `ch_srv_accept`, `ch_srv_record_init` and `ch_srv_quic_init`, and the
  boot check `ch_srv_check`, refuses with `CH_EINVAL` and sends nothing a
  configuration with a provisioned identity its flight could not sign
  with or send (`srv_identities_usable`, srv_auth.h): key lengths other
  than srv_cfg.h's or an RSA `pub_len` above `SRV_SIG_MAX`, a private
  key its signer refuses (`p256_sign_key_ok`, `rsa_pss_sign_key_ok`),
  or a chain a Certificate message cannot carry (`srv_certificate_fits`,
  srv_message.h): an empty certificate, one with no bytes pointer, or
  entries whose frames and bytes pass the room the handshake header's
  3-byte length leaves. The flight's own refusal of such an identity
  returns `CH_EAUTH` with internal_error, never `CH_EINVAL`
  (docs/decisions.md 74). `ch_quic_init` and `ch_srv_quic_init` refuse
  with `CH_EINVAL`, and send nothing, an original QUIC version this build
  derives no keys for, 0 among them; INV-7 states the version rules. INV-38
  states the refusals of a `CH_TX_PT` or a `record_size_limit` out of
  range, and INV-39 the refusal of a message before a key change that
  does not end its record. In a host
  object every init call and `ch_srv_check` refuse with `CH_EINVAL`, and
  send nothing, a `ch_cfg.cpu` without `CH_CPU_PROBED`, 0 among them, and
  one with a bit outside `CH_CPU_DEFINED`, the bits the object defines
  for its architecture: `CH_CPU_AVX2` or `CH_CPU_VAES` on arm64,
  `CH_CPU_CONSTANT_TIME_SHA512` or `CH_CPU_CONSTANT_TIME_SHA3` on x86-64,
  or a bit a later release adds, and in a `SUITE=aesgcm` host object a caller's
  suite list that names an AES-GCM suite under a `ch_cfg.cpu` without
  `CH_CPU_CONSTANT_TIME_AES` (decisions.md 81 and 89).
- **Mechanism.** Fail-closed policy, each refusal an explicit branch
  with its alert.
- **Check.** handshake_strict table cases per refusal; CBMC proves the
  branches memory-safe. The ticket age rule has boundary rows at each
  client entry: `bin/unit` for `ch_connect`,
  `bin/tcp_nonblocking_loop_test` for `ch_record_init`,
  `bin/webpki_resume_test` and `bin/webpki_resume_tcp_nonblocking` for
  the webpki definition over both TCP drivers, and `bin/quic_loop_test`
  and `bin/quic_loop_webpki` for `ch_quic_init`. `bin/unit` also holds
  the lifetime of 0 and of 1 second on the parser, and the obfuscated
  age's sum modulo 2^32. The quic_config_webpki CBMC harness proves the
  verdict over any age and lifetime, and the handshake_post harness that
  no ticket with a lifetime of 0 is handed over. Eight violations guard
  them: inv14-ticket-age-tcp-unchecked, inv14-ticket-age-webpki-unchecked,
  inv14-ticket-age-quic-unchecked, inv14-ticket-age-seven-days-dropped,
  inv14-ticket-age-lifetime-ignored, inv14-ticket-age-low-bits,
  inv14-ticket-lifetime-zero-handed-over and
  inv14-ticket-obfuscated-age-drops-add. The PSK identity bound has
  boundary rows at each client entry, where an identity of
  `CH_TICKET_ID_MAX` bytes is taken and one of `CH_TICKET_ID_MAX + 1` or
  0 bytes is refused: `bin/unit`, `bin/unit_ca` and `bin/unit_pq`
  (`test/session_hello_tests.h`) for `ch_connect`,
  `bin/tcp_nonblocking_loop_test` for `ch_record_init` and
  `bin/quic_driver_test` for `ch_quic_init`. Four violations move one
  bound each: inv14-psk-identity-over-cap-tcp,
  inv14-psk-identity-empty-tcp, inv14-psk-identity-over-cap-quic and
  inv14-psk-identity-empty-quic. The TRUST=webpki config and server_name
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
  inv14-webpki-certificate-verify-p384-key. Every client trust mode builds
  the signed content in `hsa_hash_signed_content`, and bin/diff compares
  its digest with the spec's `hs_verify_content` hashed under the same
  scheme; inv14-certificate-verify-content-separator drops the zero
  byte after the context string, and bin/diff fails. The walk's own
  fail-closed answer is bin/webpki_chain_test's anchor_key_mismatch
  row, guarded by inv14-webpki-chain-unverified; its issuer validity rows,
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
  keeps every answer and changes only the compare's timing. The version
  binding is test/quic_token_tests.h's version case: the same inputs
  under version 1 and version 2 mint the same bytes up to the tag, each
  token checks under its own version and is CH_EAUTH under the other,
  and 0, the values beside version 1 and version 2 and a reserved
  version are CH_EINVAL at both calls with nothing written.
  quic-token-version-unbound, a check that computes the tag under
  version 1 whatever it is given, fails bin/srv_quic_test, and the
  quic_token harness proves CH_EINVAL exact over every version.
  bin/quic_loop_test sends a version 1 Retry with its token, checks the
  token under version 1 and refuses it under version 2, and then
  negotiates version 2.
  The server's ticket rules are test/srv_resume_tests.h, which
  bin/srv_flight_test runs over real tickets: each passed-over shape,
  the lifetime at its last valid second and its first invalid one, a
  ticket one second in the future, psk_ke alone, no clock and no key,
  the ALPN binding both ways, the order rule over three identities, and
  a binder one bit off, 33 bytes long, over another transcript or
  absent. bin/tcp_nonblocking_loop_test, bin/quic_loop_test and
  bin/quic_loop_webpki run the same rules between this tree's client
  and server, and test/e2e.sh has OpenSSL's s_client resume against
  bin/tlsserver. The QUIC version a ticket binds has rows on both
  transports: bin/srv_flight_test passes over a ticket that records
  version 1 at a TCP server and resumes the same ticket at 0, and
  bin/srv_test and bin/srv_flight_test hold the body's version field and
  a TCP ticket's 0. test/quic_loop_ticket_versions.h, which
  bin/quic_loop_test and bin/quic_loop_webpki run, takes a ticket from a
  connection the server moved to version 2, requires version 2 in the
  client's copy and in the server's sealed body, refuses it at
  `ch_quic_init` in a version 1 connection and with a version of 0, and
  resumes it in a version 2 connection; and a version 1 ticket offered to
  a server that chooses version 2 is passed over, which a raw client
  answers by failing closed and a webpki client by completing over its
  chain in version 2. The srv_ticket and srv_resume CBMC harnesses prove
  both files memory-safe over any ticket bytes and any offer, and prove
  that a ticket is selected only under psk_dhe_ke with a key and a
  clock, that a selected ticket leaves no signature scheme selected,
  that a binder refusal is decrypt_error, and, in the TCP build the
  harness compiles, that a selected ticket and an issued one record
  version 0. The quic_config_webpki harness proves `ch_quic_init`'s
  ticket version rule over every version. The `srv-resume-` and
  `srv-ticket-` violations guard the rules, srv-resume-quic-version-unbound
  and srv-resume-ticket-records-original-version among them, and
  inv14-quic-ticket-version-unchecked and inv14-ticket-quic-version-unset
  guard the client's half; srv-resume-binder-memcmp carries INV-16 for
  the reason quic-token-memcmp does.
  The server's identity rules are test/srv_identity_tests.h, which
  bin/srv_auth_test runs: each rule's last admitted configuration and
  its first refused one, the ECDSA scalar at 1 and n - 1 admitted and at
  0 and n refused, one certificate of 2^24 - 10 bytes admitted and one
  byte more refused, and every refused one refused by `ch_srv_check`
  and by `ch_srv_accept` before either callback runs.
  bin/srv_tcp_nonblocking_test signs its flight at an RSA `pub_len` of
  `SRV_SIG_MAX` and refuses one byte more at `ch_srv_record_init`, and
  bin/srv_quic_test sends a one-byte certificate and refuses an empty
  one at `ch_srv_quic_init`, each with nothing sent. bin/p256_sign_test
  and bin/rsa_sign_test hold each key test to its signer's answer at
  every boundary key. The srv_message CBMC harness proves
  `srv_certificate_fits` exact over entries of any length, and srv_auth
  proves `srv_identities_usable` memory-safe, where an assert against
  either of its two answers fails.
  inv14-srv-identity-check-dropped and inv14-srv-rsa-modulus-unbounded
  require bin/srv_tcp_nonblocking_test to fail, inv14-srv-empty-certificate
  bin/srv_quic_test, and inv14-srv-chain-bound-one-past and
  inv14-srv-p256-key-unchecked bin/srv_auth_test;
  inv13-srv-signer-refusal-einval carries the flight's code.
  The host object's `ch_cfg.cpu` has rows at every init call and
  `ch_srv_check` in the host binaries: test/tcp_blocking_loop_cpu.h for
  `ch_connect`, `ch_srv_accept` and `ch_srv_check`,
  test/tcp_nonblocking_loop_cpu.h for `ch_record_init` and
  `ch_srv_record_init`, test/quic_loop_cpu.h for `ch_quic_init`,
  `ch_srv_quic_init` and `ch_srv_check`, and test/webpki_session_cpu.h for
  the webpki `ch_connect`. Each refuses 0, every defined bit but
  `CH_CPU_PROBED`, the first bit past `CH_CPU_CONSTANT_TIME_SHA3`, the top
  bit and each bit of the other architecture, the two x86-64 bits on
  arm64 and the SHA-512 and SHA-3 bits on x86-64, and takes
  `CH_CPU_PROBED` alone and every bit the architecture defines, which
  test/test_cpu.h writes out apart from `cpu_cfg.h`. Eight `inv14-cpu-` violations drop the rule at each of the
  five places it is written, admit 0, admit an undefined bit, or give each
  architecture the other's bits, and a row catches each. Three more move
  one hash bit in one architecture's set, which the rows of the other
  architecture cannot see, so test/host-builds.sh reads `CH_CPU_DEFINED`
  for both under the pinned clang and compares each set with the bits it
  writes out.
- **Violation.** A PR relaxes one refusal for interop with a broken
  server, or makes the server refuse a ClientHello for carrying
  something it does not know, or lets a client entry take a PSK
  identity the ClientHello it stages cannot hold.
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
  framing refuses what the walk's refuses but for the entry count and
  the entry size, where it takes any count and every entry up to
  `CH_WEBPKI_LEAF_PIN_CERT_MAX` bytes, and a leaf key or signature
  algorithm the reader refuses is unsupported_certificate. The walk
  keeps `CH_WEBPKI_FLIGHT_ENTRIES` and `CH_WEBPKI_CERT_MAX`. A
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
  which frames every entry with `webpki_read_leaf_entry`, the walk's own
  framing without its `CH_WEBPKI_FLIGHT_ENTRIES` cap and with
  `CH_WEBPKI_LEAF_PIN_CERT_MAX`, the largest entry a Certificate message
  holds, in place of `CH_WEBPKI_CERT_MAX`, because it keeps only the
  leaf; reads entry 0 with `webpki_read_certificate_key`, which stops
  after the SubjectPublicKeyInfo and passes the same cap to
  `read_certificate_head`, where `webpki_parse_certificate` passes
  `CH_WEBPKI_CERT_MAX`; and hashes that TLV alone.
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
  extension, a date or their size, refuses a refused key, counts entry 0
  alone, accepts five and nine entries, past the walk's cap, and refuses
  the walk's framing faults on every entry, the ninth included. The
  corpus leaf over `CH_WEBPKI_CERT_MAX`, 5,558 bytes, passes as the
  leaf, under eight intermediates and after the r2 leaf; the r2 leaf
  rebuilt at `CH_WEBPKI_LEAF_PIN_CERT_MAX` bytes passes as entry 0 and
  after the leaf, and one byte longer is refused in both places.
  bin/webpki_chain_test refuses that corpus leaf under the walk, as the
  leaf and as a trailing entry, and bin/webpki_cert_test holds the key
  reader to both sides of `CH_WEBPKI_LEAF_PIN_CERT_MAX` and the full
  parser to both sides of `CH_WEBPKI_CERT_MAX`.
  bin/webpki_loop_tcp_nonblocking runs a leaf
  pin and an intermediate pin against this tree's tcp-nonblocking
  server, and test/e2e.sh against `openssl s_server`. That server also
  presents the corpus leaf over `CH_WEBPKI_CERT_MAX`: a pin on its key
  completes the handshake with the 6,106-byte Certificate reassembled in
  the client's `CH_MIN_RXBUF` buffer, and the same chain from a server
  that signs with another key is refused with decrypt_error.
  fuzz/fuzz_webpki_leaf_pin.c, which the nightly runs, drives
  `webpki_verify_leaf_pin` over generated lists and up to
  `CH_SPKI_PIN_MAX` pins. Its seeds are every corpus and captured list,
  that large leaf's included, and the r2 leaf rebuilt at
  `CH_WEBPKI_LEAF_PIN_CERT_MAX`, each after the pin of its leaf's key
  where the key reader reads the leaf. fuzz/fuzz_webpki_raw_key.c, which
  the nightly also runs, drives `webpki_verify_raw_key` the same way. Its
  seeds are the 27 distinct keys of the raw rows and the corpus, each the
  one entry of a list after its own pin, and one entry a byte past
  `CH_WEBPKI_SPKI_MAX` after `CH_SPKI_PIN_MAX` pins. The webpki_leaf_pin
  harness proves the call memory-safe and its verdict and alert pairs,
  that the key reader runs once and on entry 0, and that an accepted list
  hashed the leaf's SubjectPublicKeyInfo and returns its key; the
  webpki_cert_key harness proves that reader never calls the
  extensions reader, over any certificate up to one byte past
  `CH_WEBPKI_LEAF_PIN_CERT_MAX`. spec/lean/Spec/WebpkiPin.lean models the
  rule as `verifyLeafPin` with `leafPinCertificateMax` and proves it
  sound, and the differential compares it with the C on the
  `webpki_leaf` op, the corpus leaf over `CH_WEBPKI_CERT_MAX` and the r2
  leaf rebuilt on both sides of the pins-alone cap included. Over QUIC, bin/quic_loop_webpki
  runs the chain rules against this tree's QUIC server
  (test/quic_loop_pins.h): a pin on the leaf, the intermediate or the
  anchor accepted, the last of `CH_SPKI_PIN_MAX` pins accepted, and a pin
  on nothing, on an anchor that verified nothing or on a CA certificate
  appended past the path refused with bad_certificate; under pins alone
  a pin on the leaf accepted and its ticket resumed under that pin alone,
  a pin on the corpus leaf over `CH_WEBPKI_CERT_MAX` accepted, the same
  chain from a server that signs with another key refused with
  decrypt_error, and a pin on the intermediate, the root or nothing
  refused. That server sends no raw public key, so the raw rule runs end
  to end over TCP alone. Twenty-nine `inv33-` violations guard the rules.
  inv33-quic-pins-ignored-on-chain, inv33-quic-pins-alone-leaf-refused,
  inv33-quic-pins-alone-leaf-walk-cap and
  inv33-quic-pins-alone-skips-certificate-verify change a QUIC build
  alone, which no TCP test sees, and require bin/quic_loop_webpki to
  fail. inv33-tcp-nonblocking-pins-alone-leaf-walk-cap and
  inv33-tcp-nonblocking-pins-alone-skips-certificate-verify change a
  tcp-nonblocking build alone, which no tcp-blocking test sees, and
  require bin/webpki_loop_tcp_nonblocking to fail.
- **Violation.** A PR accepts a raw key or a chain on the name alone,
  counts a certificate the walk never read, compares a pin with a key
  other than the one the walk or the reader returned, lets a pin on a CA
  key pass under pins alone, skips CertificateVerify under the pinned
  leaf key, holds pins alone to the walk's `CH_WEBPKI_CERT_MAX`, or lets
  the walk take `CH_WEBPKI_LEAF_PIN_CERT_MAX`.
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

### INV-39 — the message before a key change ends its record

- **Claim.** RFC 9846 §5.1 says handshake messages MUST NOT span key
  changes: an implementation MUST check that each message immediately
  before a key change ends its record, and MUST end the connection with
  unexpected_message when one does not (`rfc9846.txt:3464-3470`). Every
  TCP read path keeps it, in both roles and on both TCP transports:
  - a client refuses bytes after the ServerHello, before it derives the
    handshake keys, and bytes after the server Finished, before it
    commits a CA build's epoch or sends its own Finished;
  - a server refuses bytes after a ClientHello it answers with a
    ServerHello, before any ServerHello goes out, and bytes after the
    client Finished, before `srv_complete` installs the application
    read key;
  - `ch_read`, in either role, refuses a KeyUpdate with bytes after it
    in its record, before it rekeys or answers, so one record never gets
    two KeyUpdate answers.

  A ClientHello answered with a HelloRetryRequest precedes no key
  change, because the read key does not change before the second
  ClientHello, so nothing checks it; the second ClientHello is checked
  like any hello a ServerHello answers. A KeyUpdate split across two
  records under one key ends the second record, which is legal. QUIC
  carries no records, and RFC 9001 §4.1.3 puts the rule on encryption
  levels instead (`rfc9001.txt:488-493`): `quic.c`'s and `srv_quic.c`'s
  `drive`, and `srv_quic.c`'s `step_client_finished`, refuse CRYPTO
  bytes left unread at a level the session leaves with
  PROTOCOL_VIOLATION, or 0x010a when they open a KeyUpdate.
- **Mechanism.** `hsr_check_record_end` (`handshake_record.c`) answers
  `CH_OK` when no handshake byte is unread, and otherwise writes
  unexpected_message and returns `CH_EPROTO`. The four TCP drivers call
  it at those points: `run` in `handshake.c`, `step_server_hello` and
  `step_finished` in `tcp_nonblocking_step.c`, `hello_exchange`,
  `retry_round` and `auth_flight` in `srv_handshake.c`, and
  `server_flight` and `step_client_finished` in `srv_tcp_nonblocking.c`.
  `srv_handshake.c` sends the ServerHello from two call sites, one per
  hello path (`srv_flight.h` says why), and checks the hello just before
  each. No byte unread means the message ended its record because both
  TCP readers take a record whole and take the next one only while the
  bytes they hold end in a partial message: `hsr_next_msg` fetches a
  record only then, and a tcp-nonblocking driver runs every whole
  message one record completes before it takes the next.
  `handshake_record.h` states the one exception, the client's
  HelloRetryRequest step, and why it refuses nothing legal.
  `handle_post_handshake` (`handshake_post.c`) makes the same check on
  its own input, `off + 4 + msg_len == n`, because `hspost_read` appends
  a record only while its bytes end in a partial message, so `n` is
  where the newest record ends.
- **Check.** CBMC for the KeyUpdate: the `handshake_post` harness proves
  that a KeyUpdate rekeys only as the last message of any input up to
  128 bytes. The drivers' harnesses, `handshake_psk`, `handshake_pin`
  and `srv_accept`, prove the drivers memory-safe over both answers of
  the check, stubbed to its contract; the reassembly argument above
  rests on reading, not on a proof. Boundary tests hold each check at
  the record's end and one byte past it:
  - `bin/unit` (`test/session_record_end_tests.h`) for the KeyUpdate:
    one that ends its record is answered, and one with a byte after it,
    two in one record, and one followed by the first byte of a ticket
    whose rest comes under the next key are refused before any answer;
    a KeyUpdate split across two records, and a ticket then a KeyUpdate
    in one record, are read;
  - `bin/tcp_nonblocking_loop_test`
    (`test/tcp_nonblocking_record_end_tests.h`) for both tcp-nonblocking
    drivers, and for the record colibri sent a connected server, two
    KeyUpdates that each ask for an answer;
  - `bin/tcp_blocking_loop_test` for both tcp-blocking drivers, each
    run against the other role's flight handlers, and for the blocking
    server's second ClientHello after a HelloRetryRequest, over hellos
    `test/tcp_blocking_retry_tests.h` writes;
  - `bin/quic_driver_test` and `bin/srv_quic_test` for the QUIC drivers'
    level checks: a ServerHello and a ClientHello whose Initial delivery
    carries one byte more get 0x0a, and the same deliveries without it
    go on. `test/quic_loop_close.h` holds the server's check after the
    client Finished.

  Twelve violations, one per check, require those tests to fail:
  `inv39-key-update-with-bytes-after-it`,
  `inv39-tcp-blocking-server-hello-with-bytes-after-it`,
  `inv39-tcp-blocking-finished-with-bytes-after-it`,
  `inv39-tcp-nonblocking-server-hello-with-bytes-after-it`,
  `inv39-tcp-nonblocking-finished-with-bytes-after-it`,
  `inv39-srv-tcp-blocking-client-hello-with-bytes-after-it`,
  `inv39-srv-tcp-blocking-retry-hello-with-bytes-after-it`,
  `inv39-srv-tcp-blocking-client-finished-with-bytes-after-it`,
  `inv39-srv-tcp-nonblocking-client-hello-with-bytes-after-it`,
  `inv39-srv-tcp-nonblocking-client-finished-with-bytes-after-it`,
  `inv39-quic-server-hello-with-bytes-after-it` and
  `inv39-srv-quic-client-hello-with-bytes-after-it`;
  `inv22-srv-quic-drops-bytes-after-finished` holds the QUIC server's
  check after the client Finished.
- **Violation.** A PR resets `cfg.buf` after a Finished because nothing
  legal follows one, or handles every message in a record before it
  looks at what the last one did to the keys, and a message that starts
  under one key finishes under the next.
- See [decisions: Protocol surface](decisions.md#protocol-surface).

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
  ([#106](https://github.com/c4milo/chapulin/issues/106)). sha3 holds
  none either: its round is written out lane by lane, which left no
  `% 5` over Keccak's lane counters in it (decision 98).
  The decomposition is also what makes every other proof describe the
  target: those formulas verify the single-multiply form, and
  `proof/ctwidemul_harness.c` proves the two forms compute the same
  product at 8-bit operands, the widest bound whose formula converges.
  The x25519 ladder proofs rest on a product bound instead, and
  `proof/x25519_mul_ct_harness.c` proves it on the decomposition at the
  ladder's full operand range.
  The wide X25519 field multiplies on a different instruction, the
  64x64->128 multiply. `ct.h` defines that multiply for a host object
  alone, where the session's `CH_CPU_CONSTANT_TIME_MULTIPLY` bit states
  it with the 32x32 one, and `widemul.h` runs the field for a session
  with the bit alone. `test/widemul-builds.sh` checks in `make check`
  that a unit outside a host object cannot call it (decisions 52 and 89).
  A host object computes ChaCha20 on NEON or SSE2 in every session, with
  the operations the portable loop uses, adds, exclusive-ors and fixed
  rotations on every lane, so the path asks for no statement and no bit
  picks it. `chacha20_vector.h` refuses a build for a target with neither
  instruction set or a big-endian one, and `test/chacha-builds.sh`
  checks both refusals, that a host object's `chacha20_xor` calls the
  path, and that a device object's calls none (decisions 82 and 89). On
  x86-64 a session whose caller set `CH_CPU_AVX2` computes the keystream
  on `chacha20_avx2.c`'s kernel, the same operations in 256-bit vectors,
  which states no timing either (decision 90).
  A host object's vector Poly1305 multiplies on NEON's UMULL and UMLAL or
  SSE2's PMULUDQ, so it runs only for a session whose caller set
  `CH_CPU_CONSTANT_TIME_MULTIPLY`, which states that every widening
  multiply the session runs, scalar or vector, takes a time that does not
  depend on its operands. `poly1305_vector.h` turns the path on only
  where `CH_CPU_RUNTIME` and ct.h's `CH_WIDEMUL_NATIVE` meet, which is a
  host object's native copy, so `CH_CT_WIDEMUL` turns it off with the
  scalar multiply, and a device object on `WIDEMUL=native` never holds
  it. `test/widemul-builds.sh` checks that `poly1305_native.c` calls the
  path and that `poly1305.c` under its own names does not, and
  `test/chacha-builds.sh` that a device object's `poly1305.c` calls none
  (decisions 83 and 89).
  A host object holds both multiplies, and the caller's
  `CH_CPU_CONSTANT_TIME_MULTIPLY` bit in `ch_cfg.cpu` picks one for each
  operation of a session (decisions 87 and 89). `poly1305.c`,
  `mlkem_poly.c` and `rsa_sign.c` each compile under their own names on
  the decomposition, as a `WIDEMUL=decomposed` device object compiles
  them, and again as a native copy, `<file>_native.c`, on the native
  multiply, scalar and vector.
  `widemul_of_cpu` gives `WIDEMUL_CONSTANT_TIME` for a `ch_cfg.cpu` that
  holds the bit and `WIDEMUL_NOT_STATED` for any other value, the 0 a
  wiped record direction holds included. `widemul_answer` gives a session
  the answer of its own `ch_cfg.cpu`, and a record direction and a QUIC
  packet call carry the session's value and ask the same function.
  `widemul.h` runs the native copy for `WIDEMUL_CONSTANT_TIME` alone,
  with one branch per operation on that answer, so every other byte runs
  the decomposition. `ct.h` refuses
  `CH_NATIVE_WIDEMUL` in a host object and a native copy outside one.
  `x25519.c` has no native copy: X25519's second copy in a host object is
  `x25519_wide.c`'s field, which the same answer picks, so a session with
  the bit runs X25519 on the 64x64->128 multiply and one without it on
  the 16-limb field over the decomposition. P-256 has no native copy
  either: `p256_field.c`, `p256_scalar.c` and `p256_point.c` compile
  under their own names alone, and the second copy is the wide files,
  `p256_wide_field.c`, `p256_wide_scalar.c`, `p256_wide_point.c` and
  `p256_wide_mul.c`, four limbs of 64 bits on the same 64x64->128
  multiply (decision 94). The same answer picks them, at the point's five
  entries and the scalar's two that multiply. A device object holds one
  multiply, the one its `WIDEMUL` value names, the 16-limb field and
  `chacha20.c`'s loop; no host object takes that variable, and no object
  takes `X25519` or `CHACHA`.
- **Mechanism.** Constant-time construction; ChaCha20/Poly1305/x25519
  have no table lookups by design. The one table a secret picks from, a
  host object's multiples of the P-256 generator, is read whole: every
  entry of a row, in a fixed order, with the entry kept by mask
  (decision 94).
- **Check.** Semgrep-structural (`inv-16-no-variable-time-compare`) bans
  memcmp/strcmp in library sources, with handshake_parser.c and
  handshake_parser_ee.c allowlisted for their public-data compares — the
  allowlist is file-wide, so review holds the line on any new compare
  added to either file; `make timing` (Welch's
  t-test) gives statistical evidence.
  `inv-16-p256-wide-no-subscript-by-digit` refuses a subscript by a
  digit's index in `p256_wide_mul.c`, the one file that reads the table
  of multiples of G and the eight multiples of a peer's point. A read by
  index gives the right value in the same time and with one branch
  fewer, so no vector, proof, branch count or t-test sees it, and the
  address it loads names bits of a nonce to the cache.
  `inv16-p256-wide-table-read-by-index` and
  `inv16-p256-wide-multiple-read-by-index` make that edit, and the rule
  catches both. `make timing` runs the same t-test over a key generation,
  a key exchange and a signature on the wide P-256 files
  (`bin/timing_p256_wide`), which a scan that passes over the entries a
  digit does not name fails.
  `make lint-p256-wide` holds the form of the wide P-256 files' two
  carry steps that each compiler reads (`tools/p256-wide-carry.py`): the
  overflow builtins under clang, and under gcc two intrinsics for x86-64
  and a 128-bit sum for any other machine. gcc expands a builtin to an
  add and a jump on the add's carry, a limb's, and removes the jump only
  where its if-conversion passes run, so at `-Og` the wide files held 73
  such jumps on the builtins, and no check here counts those files'
  branches under a 64-bit gcc (decision 94). Every value is the same on
  each form, so no test binary sees which one gcc read.
  `inv16-p256-wide-gcc-reads-the-builtins` and
  `inv16-p256-wide-gcc-x86-64-reads-the-builtins` hand gcc the builtins,
  and the lint catches both. What each form computes is held apart from
  which one a compiler reads: `bin/p256_equiv_test` runs the form its
  compiler picks, `bin/p256_equiv_test_sum` the sums,
  `bin/p256_equiv_test_builtin` the builtins, and
  `test/docker-aes-runtime-qemu.sh p256-equiv` the intrinsics as gcc
  compiles them for x86-64 and the sums as it compiles them for arm64,
  each under qemu. Five `p256-wide-carry-*` violations break one form
  each.
  `inv-16-p256-wide-no-borrow-from-zero` refuses the borrow of a
  subtraction from a constant zero in the wide P-256 files: on the
  builtins, gcc 13.3 and 15.2 for x86-64 compiled that borrow to a jump
  on the value subtracted, a limb of a coordinate, at `-O2`, where the
  passes run. gcc reads the builtins no more, and the rule stays for a
  build that names them (decision 94).
  `inv16-p256-wide-zero-mask-borrows-from-zero` and
  `inv16-p256-wide-neg-borrows-from-zero` write the two routines that
  did, and the rule catches both.
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
  recorded ceiling, zero except tls_write.c's one public division
  (decision 72) and, under the mips gcc at `-O2`, the two `madd`
  poly1305's block gets on 16-bit
  operands ([#122](https://github.com/c4milo/chapulin/issues/122)).
  The same pass counts the conditional branches — `b<cond>`, `cbz`,
  `cbnz`, the table branches and the IT instruction on arm; `beq`,
  `bne` and the compare-with-zero forms on mips; the six base branches
  and the compressed pair on rv32 — in the twelve arithmetic files
  under the record layer (`BRANCH_SRCS`) and holds each at a ceiling
  measured per compiler (`BRANCH_CEILING`). Those ceilings are not
  zero: ct_memeq's loop and ct_wipe's test of n, the block loops,
  x25519's ladder, Keccak's round and lane counters and softmul's fixed
  32 and 64 iterations all branch on public counts, and the count cannot
  tell those from a
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
  clang, with the host object's define. They hold its
  divisions and 128-bit runtime calls at zero and its conditional
  branches at 16 and 20, every one loop control over a public count.
  `inv16-x25519-wide-cswap-branch` writes that field's `cswap` as an
  `if` on the scalar bit and both counts rise by two. No gcc spec
  measures the file: no CI lane runs a 64-bit gcc through
  `lint-wide-multiply-gcc`. The same two specs compile
  `chacha20_vector.c`, whose intrinsics no 32-bit spec targets, and hold
  its conditional branches at 40 on arm64 and 23 on x86-64, all loop
  control over public counts or tests of the byte count. CBMC cannot
  read an intrinsic, so `bin/chacha20_equiv_test` holds that path's
  output to `chacha20.c`'s; four `chacha-vector-*` violations break its
  last partial row, its counter, one lane's XOR and its order of writes,
  and the test catches each. They compile `chacha20_avx2.c` as well,
  and hold it at 23 on x86-64 and at 0 on arm64, where it has no body.
  They compile `poly1305_vector.c`'s native copy too, and hold its
  conditional branches at 4 on each, the contract check at its entry and
  its group loop, all on the byte count; its multiplies are the ones the
  caller's multiply bit states, so the count leaves them out. Under its
  own names the file has no body, and the count holds that at 0.
  `bin/poly1305_equiv_test` holds its
  accumulator to `poly1305.c`'s, and six `poly1305-vector-*` violations
  break its powers, its carries, its lanes, its contract and its limb
  bounds, and the test catches each.
  The same two specs compile the six wide P-256 files, and hold their
  divisions and 128-bit runtime calls at zero and their conditional
  branches at 7, 3, 3, 12, 0 and 0 on each: loop control over a public
  count, the two public tests of a peer's point, whether a caller asked
  for Y, and the test for a scalar's top window, which reads the window's
  number. `inv16-p256-wide-table-scan-skips-unselected` and
  `inv16-p256-wide-multiple-scan-skips-unselected` each make one of the
  two scans pass over the entries a digit does not name, and the count
  of `p256_wide_mul.c` rises to 13.
  `inv16-p256-wide-double-branches-on-infinity` writes the doubling's
  masked move for the point at infinity as an `if` on Z1's zero mask,
  and the count of `p256_wide_point.c` rises past its 3. CBMC reads these files, so they have
  harnesses of their own
  (docs/verification.md, "p256_wide"), and `bin/p256_equiv_test` holds
  every routine to the 32-bit files on the same inputs.
  They compile `rsa_mont64.c` as well, RSA's Montgomery arithmetic on
  64-bit limbs, and hold its conditional branches at 32 on each: loop
  control over limb counts, byte counts, the doublings
  `rsa_mont64_modulus_init` counts from its bits argument and the
  squarings, and the two `CH_ASSERT`s on public lengths.
  `inv16-rsa-mont64-subtract-branch` writes the subtraction that ends a
  multiplication as an `if`, and `inv16-rsa-crt-difference-branch` the
  step that adds the modulus back to a difference; both counts rise by
  one under each.
  They compile `rsa_sign64.c` too, the signer on those limbs, and hold
  its conditional branches at 26 on arm64 and 27 on x86-64: loop control
  over the table's entries, the exponents' digits, the four squarings
  and the limbs, the `CH_ASSERT`s on public lengths, one of which is two
  tests on x86-64, the key test's three on the modulus's length and two
  of its bits, the seven of `rsa_sign.c`'s encoder, which it compiles,
  and one on whether the signature passed its check, which the caller
  sees as the return value.
  The count does not hold the read of the table by itself. A read that
  stops at the entry it wants compiles to the same counts. And the
  first form of `table_select`, which used each mask as it computed it,
  compiled under clang for x86-64 to a comparison of the entry's
  position with the digit and a branch on it, and the ceiling for that
  spec then, 29, was recorded from that build (decision 95). So a Semgrep
  rule, `inv-16-rsa-table-read`, refuses five things: a subscript of the
  table that is no constant and no loop counter; an `if`, a conditional
  expression or a statement that leaves a loop inside `table_select`; a
  mask there that is taken straight from `mask_of_bit` and not read back
  through the volatile pointer; a `table_select` that does not end by
  writing zero through that pointer; and a write to its output that is
  not the select of an entry under its mask, or a call there to anything
  but `mask_of_bit`, which INV-17 gives the reason for.
  `inv16-rsa-sign64-table-read-by-index` copies the one entry the digit
  names, `inv16-rsa-sign64-table-read-stops-early` leaves the scan at
  it, `inv16-rsa-sign64-table-mask-not-hidden` uses each mask as it
  computed it, with no pointer, and
  `inv16-rsa-sign64-table-mask-not-read-back` writes the mask through
  the pointer and uses the value it computed, and `lint-invariants`
  catches each. `bin/timing_rsa_sign64`, which `make
  timing` runs, times the read under an exponent of zero bytes against
  random ones. The conditional branches of both files were read in the
  assembly of nine builds, and each depends on a length, a counter, a
  `CH_ASSERT` or a verdict the caller sees: the pinned clang 23 at `-Os`
  and at `-O2` for arm64 and x86-64, Apple clang 21 at `-O2` for both,
  gcc 13.3 at `-O2` for both and clang 18 at `-O2` for arm64. A build
  outside that list is held by the rule and by the counts of the two
  specs. Two older violations invert
  the dispatch that picks a signer for a session,
  `inv16-widemul-dispatch-rsa-pss-sign-inverted` and
  `inv16-widemul-dispatch-rsa-sp1-inverted`, and a third the dispatch of
  the key test, `inv16-widemul-dispatch-rsa-key-ok-inverted`, which would
  multiply a key's primes on the native multiply in a session that did
  not state it. `bin/widemul_runtime_test`, which counts the calls into
  each signer, catches all three.
  `lint-runtime-symbols` builds for rv32ic, where
  there is no multiplier at all, and holds per file the runtime-library
  calls it may make — `softmul.c` supplies constant-time `__mulsi3` and
  `__muldi3` so the library's branching ones are never linked, and the
  gate asserts it still defines them; the rv32ic gcc spec holds
  `softmul.c` at zero calls to `__muldi3`, because gcc at `-Os` once
  emitted one from inside `__muldi3` itself. Both clang lints stop on a
  clang or llvm-nm at another version than the pin before they count
  anything (`REQUIRE_PINNED`), because a catch script runs each one alone,
  without `lint-toolchain`; `test/pinned-checkers.sh` hands them older and
  newer stand-ins. Twenty-three of the `inv16-*` violations
  in `test/violations/` prove each detection catches its mutant, among
  them `inv16-mul128-outside-host-object`, which defines `ct.h`'s
  64x64->128 multiply outside a host object and which
  `test/widemul-builds.sh` catches, and
  `inv16-wide-multiply-takes-unpinned-clang`,
  `inv16-runtime-symbols-takes-unpinned-clang` and
  `inv16-runtime-symbols-takes-unpinned-llvm-nm`, which drop those version
  checks. Four
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
  A host object's native copies hold branch ceilings of their own under
  the two 64-bit specs, read against the file under its own names, which
  keeps the ceilings above. No 32-bit spec compiles a copy, because a
  host object targets arm64 or x86-64.
  `test/widemul-builds.sh`, in `make check`, requires that file to
  compile to the same assembly with the host object's define as without
  it, `ct.h`'s two refusals, the vector Poly1305 in `poly1305_native.c`
  alone, and the Makefile's and `build.zig`'s lists and refusals: the
  copies, the wide X25519 field and the vector ChaCha20's two files for a
  host object alone, no `WIDEMUL` value for one, and no `X25519` or
  `CHACHA` value for any object.
  `bin/widemul_runtime_test` counts the calls into
  each copy: the native copies alone under the constant-time answer, the
  decomposition alone under every other byte, and it holds
  `widemul_answer`, and the two AEAD entries that take a `ch_cfg.cpu`, to
  the multiply bit alone, at the bit by itself and beside every other
  bit. The host loop binaries count
  each end's calls over whole handshakes, so a record direction, a
  packet or a signature that does not carry the answer its session's
  `ch_cfg.cpu` gives shows as a call into the other copy.
  `lint-trust-separation` admits the native copies, the wide field, the
  wide P-256 files and the vector ChaCha20's files in the host rows
  alone. Fifty-eight `INV-16`
  violations break those rules: each dispatcher inverted, the answer read
  from another bit or from none, the answer dropped at each init call and
  at each layer that passes it, each `ct.h` refusal, the copies, the wide
  field and the vector ChaCha20 the Makefile lists, the `WIDEMUL` value a
  host object refuses and the `X25519` and `CHACHA` values every object
  refuses, and each is caught. Two more, `inv16-aead-seal-cpu-drops-avx2`
  and `inv16-aead-open-cpu-drops-avx2`, make an AEAD entry hand its
  ChaCha20 no `ch_cfg.cpu`; only an x86-64 binary can tell, and
  `bin/x86_kernels_test` catches both (docs/verification.md, "The x86-64
  kernels").
  A host object holds SHA-256 on the CPU's SHA-256 instructions,
  `sha256_hw.c`, beside `sha256.c`: FEAT_SHA256 on arm64, and the SHA
  extensions with SSSE3 and SSE4.1 on x86-64. An arm64 host object with
  `SUITE=aesgcm` holds SHA-384 and SHA-512 on FEAT_SHA512's
  instructions, `sha512_hw.c`, beside `sha512.c` (decision 93). A hash
  reads HMAC keys and traffic secrets, so each hash's instructions run
  only for a session whose caller set that hash's bit,
  `CH_CPU_CONSTANT_TIME_SHA256` or `CH_CPU_CONSTANT_TIME_SHA512`, which
  states that they take a time that does not depend on their operands in
  the mode the session's thread runs in. `sha256.h`'s
  `sha256_on_instructions` and `sha512.h`'s `sha512_on_instructions`
  each read one bit, and `hkdf.h`'s `hash_on_instructions` reads the bit
  of the hash a call's `hash_len` names. The entries that end
  `sha256.h`, `sha512.h`, `hkdf.h` and `keysched.h` each take the
  session's `ch_cfg.cpu` first and branch once on one of the three, and
  `hkdf_hw.c` and `keysched_hw.c` are those files compiled once more
  with their hash calls on the instructions (`hash_hw.h`). A session
  that states one hash's instructions runs the other hash on the
  portable code. `sha512_hw.c`'s target attribute turns on FEAT_SHA3's
  four instructions beside FEAT_SHA512's, a compiler writes them for an
  exclusive OR in plain C, and the SHA-512 bit does not name them, so
  the file computes no exclusive OR and its object holds none of the
  four. A call that takes no value runs the portable code in
  every object, so a caller with no session's value runs no hash
  instruction. Neither file reads a table with a secret index, and both
  branch on lengths alone: the two 64-bit specs hold `sha256_hw.c`'s
  conditional branches at 8 on each, `sha512_hw.c`'s at 12 on arm64 and
  0 on x86-64, where it has no body, the HKDF copy's at 16 and the key
  schedule copy's at 0, and each branch was read against its source.
  `bin/hash_runtime_test` and `bin/hash_runtime_exporter_test` count the
  calls into each path of each hash under 129 `ch_cfg.cpu` values, and
  `test/hash-builds.sh` holds each hash's instructions to its file and
  each copy's calls to the `_hw` names, for x86-64 and arm64 under the
  pinned clang (docs/verification.md, "The hash instructions").
  `p256_sign_cpu`, which a host object's server signs through, hands
  the session's value to each HMAC of its RFC 6979 nonce
  (decision 102).
  Nineteen violations break those rules.
  `inv16-sha256-instructions-without-bit` inverts the SHA-256 predicate
  and `inv16-sha256-reads-sha512-bit` reads another hash's bit;
  `inv16-hkdf-extract-entry-inverted` and
  `inv16-ks-exporter-entry-inverted` each invert one entry,
  `inv16-record-keys-direction-under-every-bit` keys a record direction
  under a value with every bit, and `inv16-p256-sign-nonce-on-portable`
  hands the nonce's HMACs 0 in place of the session's value. The
  counting tests catch those six.
  `inv16-sha512-instructions-without-bit`,
  `inv16-sha512-reads-sha256-bit` and
  `inv16-sha512-update-entry-inverted` do the same to `sha512.h`, and
  `inv16-sha384-call-follows-sha256-bit` answers for a SHA-384 call with
  the SHA-256 bit. Only an arm64 object compiles what those four edit, so
  the counting tests catch them built for arm64, under `qemu-aarch64`.
  `inv16-hash-copy-final-on-portable` and
  `inv16-hash-copy-sha384-final-on-portable` each leave one of a copy's
  hash calls on the portable code, and
  `inv16-sha256-hw-without-target` and `inv16-sha512-hw-without-target`
  each drop a file's target attribute, and
  `inv16-sha512-hw-runs-sha3-instruction` computes a round's sum through
  FEAT_SHA3's EOR3; `test/hash-builds.sh` catches the five.
  `inv16-sha512-hw-packaged-without-suite` packages `sha512_hw.c`
  in a host object none of whose calls runs it, and
  `lint-trust-separation` catches it.
  `inv16-transcript-hashed-under-every-bit` hashes a client's first
  message under a value with every bit, which no count sees, and the
  qemu lane catches it on a CPU model without the SHA extensions.
  `sha256-hw-round-constant-off-by-one` and
  `sha512-hw-round-constant-off-by-one` each change one constant, and
  `bin/sha2_equiv_test` catches them under `qemu-x86_64` and
  `qemu-aarch64`, whose `max` models have the instructions on every
  host.
  An arm64 host object that clang compiled holds Keccak-f[1600] on
  FEAT_SHA3's four instructions, `sha3_hw.c`, beside `sha3.c`, and
  `mlkem.c` and `mlkem_poly.c` a second time, as `mlkem_hw.c` and
  `mlkem_poly_hw.c`, with their SHA-3 and SHAKE calls on it
  (`keccak_hw.h`, decision 99). ML-KEM hashes its secret seeds, so those
  instructions run only for a session whose caller set
  `CH_CPU_CONSTANT_TIME_SHA3`. `sha3.h`'s `sha3_on_instructions` reads
  that bit, and the entries that end `sha3.h` and `mlkem.h` take the
  session's `ch_cfg.cpu` first and branch once on it. `sha3_hw.c` reads
  no table with a secret index and branches on lengths, positions in a
  block and the rate alone: the arm64 spec holds its conditional branches
  at 31, and the two copies' at 15 and 35, the counts of the files they
  copy, and each branch was read against its source. For x86-64, and in
  an arm64 object another compiler built, the three files define nothing
  and the bit picks nothing. `test/hash-builds.sh` holds FEAT_SHA3's
  instructions to `sha3_hw.c` and each copy's calls to the `_hw` names,
  for arm64 under the pinned clang. The qemu lane builds the two loops
  with clang for arm64 and runs them on cortex-a72, which has no
  FEAT_SHA3: the rows without the bit pass, and the rows with it die of
  SIGILL. Two violations break those rules.
  `inv16-mlkem-copy-absorb-on-portable` leaves the copies' absorb on the
  portable code, and `test/hash-builds.sh` catches it.
  `inv16-sha3-instructions-without-bit` inverts the predicate, and the
  qemu lane catches it on cortex-a72. No binary counts which path each
  ML-KEM call takes, as `bin/hash_runtime_test` does for SHA-2.
- **Violation.** A PR compares a binder or tag with memcmp because
  the linker size looked better.
- See [decisions: Cryptography](decisions.md#cryptography).

### INV-26 — AES sees three public keys, and traffic keys only under a suite build

- **Claim.** Under `TRANSPORT=quic-nonblocking` this tree carries an AES-128, and
  every key it is given is public. `aes.c` derives the keys and
  `gcm.c` builds the AEAD on them; the key expansion and the block
  cipher sit in `quic_aes_soft.c` or `aes_extern.c`, whichever a device
  object's Makefile `AES` variable picked, or in a host object's
  `aes_hw.c`, behind the contract `aes_block.h` states. In a host object,
  for a schedule on the AES instructions, GHASH's multiply by the hash
  subkey also moves out of `gcm.c`, into `ghash_hw.c`
  on the carry-less multiply, behind `ghash_hw.h`, and counter mode's
  whole blocks and the seal's and the open's whole passes into `gcm_hw.c`, behind
  `gcm_hw.h`, which take the round keys `gcm.c` passes; the hash subkey
  is the forward cipher of a zero block under the same key, so it is
  public exactly when that key is. Only the table, `quic_aes_soft.c`, is
  table-driven, and the claim below is what lets that one exist; outside
  a suite build it binds every implementation the same way, because
  `AES=extern` cannot state its timing either. There are three, and each has a QUIC version 1 form and a
  version 2 form: the packet protection key and the header protection
  key, both expanded from `HKDF-Extract` over the version's printed salt,
  RFC 9001 §5.2's or RFC 9369 §3.3.1's, and the Destination Connection ID
  the caller supplied, under the version's printed labels, and the
  16-byte constant the version prints for the Retry integrity tag, RFC
  9001 §5.8's or RFC 9369 §3.3.3's (`rfc9369.txt:158-188`). RFC 9001 §5
  draws the conclusion for the first two itself: anyone can compute them,
  so Initial packets have no confidentiality or integrity protection.
  RFC 9369 changes only printed inputs, the salt, the labels and the
  Retry key and nonce, and the connection ID still travels in the clear,
  so the conclusion holds for version 2's as it does for version 1's; its
  §8 says version 2 changes no security property of version 1
  (`rfc9369.txt:320-321`). A version picks its constants by a table read
  in `aes.c` and `quic_retry.c`, and the version is itself a value the
  caller read off the wire. Outside a
  `-DCH_SUITE_AES_GCM` build no traffic secret `keysched.c` derives is
  passed to AES, and AES is never a cipher suite. No field of `ch_quic`
  holds an AES key, and no AES key outlives the call that built it.

  A QUIC host object is the one that holds two of the implementations:
  `aes_hw.c` with `ghash_hw.c`, `gcm_hw.c` and `gcm_vaes.c`, compiled so
  that only their own functions carry the AES instructions, and
  `quic_aes_soft.c` beside them (docs/decisions.md 81 and 89). The
  `CH_CPU_CONSTANT_TIME_AES` bit of the session's `ch_cfg.cpu` puts each
  Initial key on one of them: the instructions with the bit, and the
  table without it. The Retry key runs on the table whatever the bits
  say. Every key those two run is public, so the claim above holds for
  both, and a session without the bit runs no AES instruction and no
  carry-less multiply.

  On x86-64 a host object's AES-GCM has a second path over whole blocks:
  `gcm_vaes.c`'s kernels, two blocks to a 256-bit register on VAES and
  VPCLMULQDQ (docs/decisions.md 90). A key's schedule records the low
  byte of its session's `ch_cfg.cpu`, which holds every bit an object
  defines. `aes_public_key_initial` writes it for an Initial key, and
  `record.c` and `quic_packet.c` write it into each traffic key through
  `aes_traffic_key_init_cpu`. `gcm_vaes.h`'s `gcm_use_vaes` reads that
  byte and answers for the kernels only where it holds `CH_CPU_VAES` and
  `CH_CPU_CONSTANT_TIME_AES` both, and `gcm.c` asks it only for a
  schedule the instructions run. The AES bit's statement covers the
  256-bit forms, so the kernels add no statement, and `CH_CPU_VAES`
  without the AES bit runs nothing. The kernels take the keys the 128-bit
  loops take, so the two claims bound them the same way.

  A `-DCH_SUITE_AES_GCM` build adds the second claim, and the traffic
  keys of two suites. That build holds `TLS_AES_128_GCM_SHA256` and
  `TLS_AES_256_GCM_SHA384` (decisions.md 45 and 58), so AES runs under
  keys the TLS key schedule derives, 16 or 32 bytes by the suite, and
  every one is secret: `record.c`'s record key, and under
  `TRANSPORT=quic-nonblocking` `quic_packet.c`'s packet protection key and header
  protection key for the Handshake and 1-RTT levels (RFC 9001 §5.3,
  §5.4.3). The Initial level keeps AES-128-GCM under its public keys in
  every build. Three things bound the traffic keys. `ct.h` refuses the
  define unless the build is a host object, whose sessions run AES-GCM
  only under their caller's `CH_CPU_CONSTANT_TIME_AES`, the caller
  stating that this CPU's AES instructions and its carry-less multiply
  run in constant time in the mode its thread runs in, or takes
  `AES=extern` and defines `CH_AES_EXTERN_CONSTANT_TIME`, which is the
  build asserting that the peripheral behind the image's `ch_aes_block`
  runs in constant time. So the table-driven `AES=soft` S-box never sees
  a secret key, a host object's table never does either, and the image's
  hook sees one only in a build whose author has stated the peripheral's
  timing; no mechanism in this tree can observe that timing
  (docs/decisions.md entries 68 and 89). The
  key has its own type, `aes_traffic_key`,
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
  build is a host object, whose caller states the timing in `ch_cfg.cpu`,
  or takes `AES=extern` and asserts `CH_AES_EXTERN_CONSTANT_TIME`. The rest of this
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
  `lint-trust-separation` holds a device object to one implementation.
  The table and `aes_extern.c` define the same two entries, so a second
  one would not link, but a linker says nothing about which implementation
  an object ended up with; the lint reads the packaged source list per
  build instead. Its host rows require `ghash_hw.c`, `gcm_hw.c` and
  `gcm_vaes.c` beside `aes_hw.c`, and every device row bans them. Those
  rows admit the one pair of implementations an object may hold: the QUIC
  host rows require the instructions' four sources and `quic_aes_soft.c`
  together, the TCP suite host row requires the first four and bans the
  table, and a build that names an `AES` value for a host object must be
  refused. `aes-runtime-table-in-tcp-object.violation` puts the table in
  that TCP suite object, `aes-host-quic-object-loses-table.violation`
  drops it from the QUIC one, and `aes-host-object-takes-aes-value.violation`
  lets a host object take an `AES` value; `test/lint-trust-separation.sh`
  fails each.
  `test/violations/aes-two-implementations-in-one-object.violation` is
  the mutant that proves it fires, and
  `aes-hw-diverges-from-soft.violation` breaks the host object's key
  expansion and requires `bin/aes_equiv_test` to fail, which is what
  holds the path no proof reaches (docs/quic.md, "What the AES axis
  proves"). `ghash-hw-reduction-constant.violation` and
  `ghash-hw-cross-product-halves-swapped.violation` break the host
  object's GHASH multiply, and `ghash-hw-powers-reversed.violation` and
  `ghash-hw-partial-block-dropped.violation` break its loop over data, the
  first by running a pass's blocks against the powers of H in the wrong
  order and the second by dropping a last partial block; all four require
  `bin/ghash_equiv_test` to fail.
  `ghash-hw-falls-back-to-portable.violation` lets a host object's
  `gcm.c` run the portable multiply on a schedule the instructions run
  and requires `test/quic-builds.sh` to fail, and
  `ghash-hw-source-unpackaged.violation` drops `ghash_hw.c` from the host
  object's sources and requires `test/lint-trust-separation.sh` to
  fail. `aes-hw-counter-short-pass-dropped.violation` and
  `aes-hw-counter-wrap-carries-into-iv.violation` break `aes_hw.c`'s
  counter mode over whole blocks, which runs eight blocks a pass, and
  require `bin/aes_equiv_test` to fail, and
  `aes-hw-counter-falls-back-to-one-block.violation` lets a host
  object's `gcm.c` run every block through the one-block cipher and
  requires `test/quic-builds.sh` to fail.

  **What a secret AES key needs, and what holds it.** The entry above
  used to say only that moving these files out of `WIDEMUL_PUBLIC` was a
  diff a reviewer looks for. Four of the five have moved, and the rest of
  the list is here so the suite build's bill is written down rather than
  rediscovered.

  *The instructions and the peripheral, not the table.* `AES=soft` reads a 256-byte S-box at an
  index computed from the key. `aes_expand_round_keys` substitutes the
  key's own bytes before a block runs, so the leak is there before any
  plaintext exists, and `sub_bytes` substitutes `counter ^ round_key` once
  per round. `gcm_ghash` inherits it: the hash subkey H is
  `aes_encrypt_block` of a zero block, so an `AES=soft` build leaks H
  through the same table even though `multiply_by_subkey` is branchless
  and index-free. The AES instructions run no table. `AES=extern` runs no
  cipher in this tree at all: what `ch_aes_block` costs belongs to the
  peripheral, and this tree cannot state it. So a host object's
  instructions and `AES=extern` are where a secret key may go, each under
  its own statement below, and `ct.h` is where that is written:
  `-DCH_SUITE_AES_GCM` with neither `CH_CPU_RUNTIME` nor `CH_AES_EXTERN`
  is a compile error, not a silent fall back to the default. A host
  object runs every traffic key on the instructions:
  `aes_traffic_key_init` records them in the key's schedule whatever the
  bits say, so the table beside them in a QUIC object never sees one. It
  records no description of the CPU, so a key runs the 128-bit loops
  until `aes_traffic_key_cpu` writes the session's.

  *The instruction's timing is asserted, not detected.* `__ARM_FEATURE_AES`
  and `__AES__` say the AES instructions exist, and `__ARM_FEATURE_AES`
  and `__PCLMUL__` say the carry-less multiply exists. None says the
  latency is independent of the operands, and the architectures do not
  promise it either -- Arm publishes FEAT_DIT and Intel publishes DOITM because
  the base architectures leave it to the implementation. `ct.h` already
  refuses that inference for the widening multiply and asks the build for
  `CH_NATIVE_WIDEMUL` instead
  ([#53](https://github.com/c4milo/chapulin/issues/53)). The AES path
  follows it: `CH_CPU_CONSTANT_TIME_AES` is the caller's statement, for
  the AES instructions and for the carry-less multiply GHASH runs on
  (`docs/decisions.md` entries 50 and 89), made for the CPU it probed and
  the mode its thread runs in, and a host session without it holds
  ChaCha20 alone and runs no AES-GCM suite. This is a statement and not a
  check, and it is the weakest link in the list; what it buys is that the
  claim is written in the caller's code by someone who can answer for the
  CPU, rather than inferred from a macro that does not carry it. The
  build's own statement, `CH_NATIVE_AES`, is gone, and `ct.h` stops a
  build that still writes it.

  *The peripheral's timing is asserted too, and nothing here can observe
  it.* Under `AES=extern` every AES block, public key or traffic key,
  runs in the image's `ch_aes_block`, and this tree holds no line of it.
  `CH_AES_EXTERN_CONSTANT_TIME` is the build's statement that the
  peripheral behind that hook runs in constant time for AES-128 and
  AES-256 keys, and `ct.h` refuses `-DCH_SUITE_AES_GCM` on `AES=extern`
  without it. It names the peripheral, not the AES instructions and the
  carry-less multiply, which an `AES=extern` object runs neither of
  (docs/decisions.md entry 68). It claims
  nothing about GHASH: under `AES=extern`, GHASH runs on `gcm.c`'s
  portable multiply, 128 masked steps per block with no table and no
  multiply instruction, which the branch count below holds. It claims
  nothing about what the hook or the peripheral keeps after a call either,
  such as a key register or a cached expansion; `aes_block.h` leaves that
  to the image. No test, proof or gate in this tree times a peripheral,
  so this statement is the whole of the claim, and it is as weak as
  `CH_CPU_CONSTANT_TIME_AES` is.

  *The codegen gates now measure these files.* `aes.c`,
  `quic_aes_soft.c`, `aes_extern.c` (then `quic_aes_extern.c`) and `gcm.c` moved from
  `WIDEMUL_PUBLIC` into `WIDEMUL_CEILING` at 0, and into `BRANCH_SRCS`
  with a measured branch count per spec in `BRANCH_CEILING`. Before that
  no gate compiled them, so nothing held `multiply_by_subkey`'s two masks
  to a branchless lowering -- the same select `lint-wide-multiply` holds
  for `poly1305_final` and `cswap`. `aes_hw.c`, `ghash_hw.c` and
  `gcm_hw.c` stay in `WIDEMUL_PUBLIC` because they cannot join: every spec
  targets a
  core without the AES or carry-less multiply instructions, where each
  file is its own `#error`. `test/aes_equiv_test.c`,
  `test/ghash_equiv_test.c`, the published vectors in `bin/quic_test_hw`,
  the Wycheproof AES-GCM suite on that leg and `bin/diff_quic_hw` are what
  hold them, and none of them is a timing measurement. `aes_extern.c`
  joined the codegen gates under the suite build's defines, so the count
  reads its AES-256 pair too; it holds no select and no branch, only two
  copies and a call. What it calls is the part no gate here reads.

  *Key material is wiped where a secret could sit.* `gcm.c` wipes the
  hash subkey, the running multiple in the GF(2^128) multiply, the
  keystream block, the tag mask and the tag it computed for comparison;
  `aes_hw.c` wipes its key-schedule word and its cipher state;
  `ghash_hw.c` wipes the object that holds the hash subkey, its powers,
  the accumulator and the sums of products before each reduction once at
  the end of each entry, not once per block. Under `AES=extern` a schedule holds the traffic key
  itself, not an expansion of it, and the same `ct_wipe` of the whole
  `aes_traffic_key` in `record.c` and `quic_packet.c` wipes it;
  `aes_extern.c` keeps no copy of its own. What the hook or the
  peripheral keeps is the image's to clear (`aes_block.h`). Two
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
  implementations, `ghash_hw.c`, `gcm_hw.c`, `gcm_vaes.c` and
  `gcm_vaes.h` excluded as the definition sites. The header is there for
  its three inline entries, which call `gcm_hw.c`'s loops or
  `gcm_vaes.c`'s kernels for `gcm.c`; a call to one of the three from any
  other library source still matches the rule in that source.

  What `ct.h` refuses, and `test/quic-builds.sh` is the catch target for
  every line: `-DCH_SUITE_AES_GCM` with neither `CH_CPU_RUNTIME` nor
  `CH_AES_EXTERN`, `-DCH_SUITE_AES_GCM` on `AES=extern` without
  `CH_AES_EXTERN_CONSTANT_TIME`, and `CH_NATIVE_AES` in any build. The
  script compiles one translation unit that reads `ct.h` and nothing
  else: the host object and `AES=extern` with its statement must
  compile, each refusal is checked on its own so a build that dropped one
  cannot hide behind the other, and the peripheral's statement is offered
  to `AES=soft`, where it must not count.
  `inv26-aes-suite-without-hardware.violation` deletes the `AES=soft`
  `#error` and `inv26-aes-extern-suite-without-vendor-statement.violation`
  the `AES=extern` one. `inv26-soft-suite-takes-extern-statement.violation`
  lets the peripheral's statement stand in on `AES=soft`, and
  `inv26-native-aes-admitted.violation` lets `CH_NATIVE_AES` compile
  again. `aes_block.h` refuses `CH_AES_HW` and `CH_AES_RUNTIME`, which
  chose the instructions when the object was built, and a host object
  beside `AES=extern`; `aes-gone-defines-admitted.violation` and
  `aes-host-beside-extern-admitted.violation` remove each refusal. Each
  requires that script to fail. `aes-extern-suite-statement-in-makefile.violation`
  writes `CH_AES_EXTERN_CONSTANT_TIME` into every `AES=extern` object's
  defines, and `test/lint-trust-separation.sh` fails it: every suite row
  bans the statement, because only the firmware author may make it.
  `inv16-ghash-subkey-select-branch.violation` writes
  `multiply_by_subkey`'s mask as an `if` on the accumulator bit and
  requires `test/lint-wide-multiply.sh` to fail, which is what the new
  `BRANCH_SRCS` entries buy.

  The same two refusals hold over QUIC, where `quic_packet.c` hands AES
  the Handshake and 1-RTT keys: `test/quic-builds.sh` compiles
  `quic_packet.c` under the suite in a host object and requires it to
  compile, and on `AES=soft` and requires ct.h to refuse it, and the same
  pair on `AES=extern` with and without `CH_AES_EXTERN_CONSTANT_TIME`.
  `inv26-quic-suite-on-table.violation` lets a QUIC build past the
  `AES=soft` refusal and
  `inv26-quic-extern-suite-without-vendor-statement.violation` past the
  `AES=extern` one. `quic_aes_soft.c` refuses
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
  to fail, and `aes256-schedule-one-round-key-short` stops the host
  object's AES-256 expansion one round key short and requires
  `bin/aes_equiv_test` to fail. `inv26-quic-hp-key-cut-to-aes128` keys
  QUIC header protection with 16 bytes under every AES suite and
  requires `bin/quic_suite_test`, which checks an AES-256 packet byte for
  byte against an independent computation, to fail; the
  `quic_packet_suite` proof asserts the key length too.

  What holds the host object's two ciphers. `bin/aes_runtime_test`
  compiles `quic_aes_soft.c`, `aes_hw.c`, `ghash_hw.c` and `gcm_hw.c`
  under counting entries and runs RFC 9001 and RFC 9369 Appendix A with
  the `CH_CPU_CONSTANT_TIME_AES` bit and without it, and the SP 800-38D
  and FIPS 197 vectors under traffic keys: without the bit no call goes
  to the instructions or the carry-less multiply, with it the table runs
  no Initial key, and the table runs no traffic key.
  `test/aes-runtime-qemu.sh` runs that binary and both suite loop
  binaries, built for x86-64, under `qemu-x86_64` on a CPU model without
  AES-NI, PCLMULQDQ and AVX2, where the rows without the bit pass and the
  rows with it die of SIGILL; CI's mips job runs it on every push. On arm64,
  where no QEMU model drops the AES extension, `test/aes-runtime-disasm.sh`
  in CI's arm64 and macOS jobs finds the AES and PMULL instructions in
  `aes_hw.c`'s, `ghash_hw.c`'s and `gcm_hw.c`'s functions alone. The
  `aes_runtime` proof holds the same three rules over every 32-bit
  `ch_cfg.cpu`, and `srv_select_runtime` and `quic_config_webpki_suite`
  hold the default order and the `ch_cfg.cpu` rule. `inv26-runtime-absent-runs-aes-instructions`,
  `inv26-runtime-absent-runs-carryless-multiply`,
  `inv26-runtime-absent-runs-counter-blocks` and
  `inv26-runtime-traffic-key-on-table` require `bin/aes_runtime_test` to
  fail, `inv26-runtime-absent-expands-on-instructions` requires
  `proof/prove-one.sh aes_runtime` to fail, and
  `inv26-runtime-initial-seal-ignores-answer`, which seals every QUIC
  Initial packet in `quic.c` as though the caller had set the bit,
  requires `test/docker-aes-runtime-qemu.sh` to fail.

  What holds the x86-64 kernels to their bits. `test/quic-builds.sh`
  compiles `gcm.c` for x86-64 and requires calls to all six entries, the
  three kernels and `gcm_hw.c`'s three, and none from `gcm_hw.c` to a
  kernel; `inv26-vaes-runs-without-cpu-bits` and
  `inv26-vaes-ignores-cpu-bits`, a `gcm_use_vaes` that answers 1 or 0 for
  every byte, leave three of the six out, and `inv26-vaes-without-target`
  drops the kernels' target attribute. `bin/aes_runtime_test` reads the
  byte each schedule records: `inv26-initial-key-drops-cpu` leaves an
  Initial key's unwritten, `inv26-traffic-key-init-keeps-cpu` leaves a
  traffic key's as the frame held it, and
  `inv26-traffic-key-cpu-unwritten` makes `aes_traffic_key_cpu` write
  nothing. `bin/x86_kernels_test` counts the calls into each kernel under
  every `ch_cfg.cpu` value, on any x86-64 CPU, because its counting
  entries run the 128-bit loops. It catches `inv26-vaes-without-aes-bit`
  and `inv26-vaes-without-vaes-bit`, a predicate that reads one bit of
  the two, and `inv26-record-seal-key-drops-cpu`,
  `inv26-record-open-key-drops-cpu`, `inv26-packet-seal-key-drops-cpu`
  and `inv26-packet-open-key-drops-cpu`, a traffic key built with no
  byte. Only an x86-64 binary compiles those branches, so each names
  `test/docker-aes-runtime-qemu.sh x86-kernels` as its catch, which
  builds and runs that binary in a container on any host.
  `test/aes-runtime-qemu.sh` also runs both suite loops on a CPU model
  without AVX2, where the rows with the AES bit pass on the 128-bit
  loops and the rows that add `CH_CPU_VAES` die of SIGILL.

  What holds `aes_extern.c`. `test/aes_extern_hook.c` is the hook every
  `AES=extern` test binary links: `quic_aes_soft.c`'s cipher under other
  names, for both key lengths, which aborts the binary on any other
  length. Over it run FIPS 197, SP 800-38D and RFC 9001 Appendix A in
  `bin/quic_test_extern`, which also checks what each expansion writes at
  the exact bound `aes_block.h` states; RFC 8448's record in
  `bin/aes_suite_test_extern`; the QUIC suite computation in
  `bin/quic_suite_test_extern`; both loop tests; the Wycheproof AES-GCM
  suite; the AES rows of the Lean differential in `bin/diff_quic_extern`;
  and e2e's client and server legs against OpenSSL under each suite.
  `aes-extern-256-cipher-passes-128-key.violation` tells the hook an
  AES-256 key is 16 bytes, `aes-extern-256-expansion-stores-16.violation`
  stores half of an AES-256 key; each requires `bin/quic_test_extern` to
  fail. A store one byte past the AES-128 schedule has no violation file,
  because gcc refuses it at compile time under `-Werror=array-bounds`;
  under clang the marker byte in `bin/quic_test_extern` catches it. The
  `aes_extern` proof holds the four entries to the hook's contract over a
  stub of it. None of this is a timing measurement, and the hook these
  tests link is a stand-in: what the image's peripheral computes is the
  image's to test.

  What the compiler refuses, in any source that does not include
  `aes_public_key.h`: declaring an `aes_public_key`, declaring an array of
  them, assigning one, and writing a field of one. `quic_session.h`, which
  declares `ch_quic`, declares no member of that type, so
  `q->initial_tx.key.round_keys` names nothing.

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
  `aes_block.h`, `gcm.h`, `ghash_hw.h` or `gcm_hw.h` declares a
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
- An error alert closes the connection on both sides at once (RFC 9846
  §6.2, rfc9846.txt:3890-3893), and this holds for either role and
  every TCP driver. An error alert is any 2-byte alert record whose
  description is neither close_notify nor user_canceled, whatever its
  level byte (§6, rfc9846.txt:3779-3782). The call that reads one, in
  the handshake or after it, returns `CH_EPROTO`, wipes, marks the
  session failed, sends nothing (a tcp-nonblocking session stages and
  pushes no alert record), and records the description in
  `ch_tls.alert_received` for `ch_alert_received` (alert.h). The
  handshake reads an alert in the clear even once its read key is
  installed, because a peer that failed before it installed its own
  write key has none to protect it with. A record of the alert type that
  is not one 2-byte alert is not an alert (§5.1,
  rfc9846.txt:3475-3478), and the reader answers it with decode_error
  (rfc9846.txt:3785-3788).
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
  `read_closed`. Every other alert record goes to `hsr_refuse_alert`
  (handshake_record.c), which all four TCP readers call: the two
  handshake readers, `tls.c`'s `read_alert` and `handshake_post.c`'s
  reader of a split message. It checks the length and writes
  `alert_received`, and the two funnels that could answer, `tlsi_fail`
  and `tcp_nonblocking_fail`, send and write nothing once that field is
  set.
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
  no harness (docs/verification.md, "What rests on tests, not proofs").
  `bin/unit`'s `test_peer_close_notify` (`test/session_post_tests.h`)
  queues a record behind the close_notify and requires every later
  `ch_read` to return 0 with the record unread, no send call, and
  `ch_write` and `ch_close` to send under the write key.
  `bin/tcp_nonblocking_loop_test` (`test/tcp_nonblocking_close_tests.h`)
  closes one direction at a time between the two tcp-nonblocking drivers
  and counts each end's send calls, so the `ch_read` that reads a
  close_notify is measured to send nothing, on the client and on the
  server. `test/e2e.sh`'s go-half-close leg runs it against Go's
  `CloseWrite`, which sends a close_notify and keeps reading: the server
  logs the lines the client sent after that close_notify, then the
  client's own. Three violations each break one term:
  `inv22-read-answers-close-notify`, which
  `bin/tcp_nonblocking_loop_test` catches, and
  `inv22-read-past-close-notify` and
  `inv22-write-refused-after-close-notify`, which `bin/unit` catches.
  The error alert rule is tested, not proved, over the same three
  binaries and the blocking loop. `bin/unit` (`test/session_alert_tests.h`)
  reads a connected session's error alert at level 2, at level 1 and
  with an unknown description, and one between two records of a split
  message: no send call, the keys wiped, and the description in
  `ch_alert_received`. It reads alert records of one byte and of three,
  either side of the 2 bytes that are one alert, and requires one
  decode_error. `bin/tcp_blocking_loop_test`
  (`test/tcp_blocking_alert_tests.h`) and `bin/tcp_nonblocking_loop_test`
  (`test/tcp_nonblocking_alert_tests.h`) run the same two lengths in each
  handshake: the client reads the alert in place of the server's flight
  and under the server's handshake key, and the server reads it in place
  of the ClientHello, in the clear after its flight and under the
  client's handshake key. The tcp-nonblocking one also reads it after
  the handshake on both ends, and requires each end to stage and push
  nothing after a fatal alert and to emit decode_error after a 3-byte
  one. Six violations each break one term:
  `inv22-fail-answers-peer-alert` and `inv22-peer-alert-not-recorded`,
  which `bin/unit` catches; `inv22-alert-length-unchecked`, which
  `bin/unit` catches; `inv22-tcp-nonblocking-owes-answer-to-peer-alert`
  and `inv22-tcp-nonblocking-drops-clear-alert-once-keyed`, which
  `bin/tcp_nonblocking_loop_test` catches; and
  `inv22-blocking-drops-clear-alert-once-keyed`, which
  `bin/tcp_blocking_loop_test` catches.
- **Violation.** A PR relaxes one type check to tolerate a message a
  peer "usually" sends early, and a flight with a skipped
  CertificateVerify authenticates. This is the SMACK and FREAK class:
  invisible to memory-safety proofs and to a golden-path e2e run. Or a
  PR answers the peer's close_notify with an immediate close_notify of
  its own, as TLS 1.2 required, which drops what this side still had
  to send and sends from inside a read. Or a PR answers the peer's
  fatal alert with one of its own, or drops an alert in the clear
  because the read key is already installed.
- See [decisions: Cryptography](decisions.md#cryptography), and entry 75
  for the alert rule.

## Lifetime and state

### INV-17 — secrets die at phase boundaries

- **Claim.** Handshake secrets are wiped at CONNECTED; every failure
  path wipes through `tlsi_wipe`, or through `quic_fail` under
  `TRANSPORT=quic-nonblocking`; the DRBG erases its key forward after each output.
  A tcp-nonblocking handshake failure wipes through `tcp_nonblocking_wipe`
  right after it has sealed the alert record it sends, so the driver
  emits that record and keeps no key (INV-13).
  A failure on the peer's fatal alert is one of those paths: it sends
  nothing (INV-22) and wipes as every other failure does, which
  `bin/unit`'s `test/session_alert_tests.h` checks key byte by key byte.
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
  Wipes inside a call have tests too. The vector Poly1305
  wipes the powers of the one-time key's r that it computes, r^2, r^3
  and r^4, when each call ends (decision 83). `bin/poly1305_equiv_test`
  copies the stack below a call and requires none of them there, and
  `poly1305-vector-keeps-powers` drops the wipe and the test catches it.
  `rsa_mont64.c` and `rsa_sign64.c` wipe every array they hold a value
  computed from an RSA key in, twenty-three wipes: the multiplication's
  running sum, with the round's multiple above it; the square's running
  sum and its copy of twice the operand (decision 106); the public
  operation's base and power, which in the signer's check are a
  candidate and what it was raised to; the exponentiation's table and
  the entry its last step read; the reduction's two products and R^3;
  the recombination's qinv and factor; the key test's two primes and
  their product; the check's power; and in `rsa_sign64_sp1` the two
  primes' modulus records, the message's limbs, the two halves, and the
  candidate as limbs and as bytes. Any one of those with the message
  factors the modulus, the candidate when its check failed.
  `bin/rsa_sign_equiv_test` copies the stack below a call and requires
  no two limbs side by side of a value the call held, in seven runs
  under each of an RSA-2048, an RSA-2112 and an RSA-4096 key: a
  signature; a signature under a key with one bit of dp changed, which
  the check refuses; the key test; the key test with one bit of q
  changed, which it refuses; and the reduction, the exponentiation and
  the recombination each called on its own, because inside a signature a
  later call's frame is written over theirs
  (`test/rsa_sign_equiv_pieces.c`). One violation file drops each wipe
  but the square's running sum:
  `inv17-rsa-mont64-running-sum-wipe-dropped`,
  `inv17-rsa-mont64-square-double-wipe-dropped`,
  `inv17-rsa-mont64-public-base-wipe-dropped`,
  `inv17-rsa-mont64-public-power-wipe-dropped`,
  `inv17-rsa-sign64-table-wipe-dropped`,
  `inv17-rsa-sign64-last-entry-wipe-dropped`, and under
  `inv17-rsa-crt-` the names `reduction-low`, `reduction-high`,
  `reduction-r3`, `recombination-qinv`, `recombination-factor`,
  `key-test-p`, `key-test-q`, `key-test-product`, `check-power`,
  `prime-record`, `second-prime-record`, `message-limbs`, `first-half`,
  `second-half`, `refused-signature-limbs` and `refused-candidate`, each
  ending in `-wipe-dropped`. The test catches each under Apple clang 21
  for arm64 and x86-64 and under gcc 13.3 for both, except the square's
  two (decision 106): it catches both of those under Apple clang 21 for
  arm64, and under gcc 13 for x86-64 it catches the dropped wipe of 2a
  and not that of the running sum, whose bytes a later call's frame
  writes over before the test looks. CI's mutants job runs gcc 13 for
  x86-64, so the running sum's wipe has no violation file. `table_select` ends
  by writing zero through the pointer its masks went through, so the
  limb behind it does not end on the last one; no test can look for a
  limb of all ones or of zeros, so the Semgrep rule of INV-16 holds that
  write, and `inv17-rsa-sign64-table-mask-left-in-limb` drops it. One
  limb alone is no finding in those runs, because no wipe written in C
  names a register a callee saved or a slot the compiler picked; run
  with `CH_RSA_RESIDUE_LIMBS=1` they look for one, which is how the
  slots that `rsa_mont64_mont_mul`'s volatile reads removed were found
  (decision 95).
  A value shorter than a limb is one those runs cannot look for, and
  the first form of `table_select` left one: clang for arm64 kept the
  digit a step read in a register a callee saves, across a call it made
  from the loop that wrote zeros to the output, and the next
  multiplication saved that register in its frame. So the binary makes
  nine more runs for each key, each one call under two inputs that
  differ in a secret and in nothing a caller sees, and requires the two
  stacks equal in every byte (`test/rsa_sign_equiv_differential.h`):
  the exponentiation under dp and under dq and of two bases, a
  signature under a key and under it with its primes exchanged, a
  signature of two messages, a refused signature under two wrong keys,
  the key test under exchanged primes and under two wrong keys, the
  reduction modulo each prime and the recombination under exchanged
  primes. `table_select` now writes its output in one statement and
  calls nothing. `inv17-rsa-sign64-digit-kept-in-frame` keeps the digit
  in a local of the exponentiation, and the nine runs catch it;
  `inv17-rsa-sign64-table-read-zeroes-first` restores the loop of zeros,
  and the Semgrep rule of INV-16 catches it, because only clang for
  arm64 makes that loop a byte that differs.
  Two things no run holds. A register no callee saves keeps what the
  last arithmetic left in it, and code that runs later may store it:
  Darwin's stack probe stores two, so the comparison leaves out the 16
  bytes the probe of its own copy writes. And a compiler that was not
  asked to optimize keeps every local in its frame, where no wipe names
  it: built at `-O0` the nine runs differ in 8 to 249 bytes each. The
  binary makes no run over the stack in such a build or under
  AddressSanitizer, by the answer `test/stack_residue.c` gives every
  such search, and this claim is for an optimized object.
  That binary compiles `ct_wipe.c` into the same unit as the vector
  Poly1305, so the compiler can inline `ct_wipe` at the end of the call,
  as link-time optimization would. `ct-wipe-plain-memset` makes
  `ct_wipe` call `memset` by name instead of through `ct_wipe.c`'s
  volatile function pointer; the compiler then deletes the call as a
  store nothing reads, and the test catches it under Apple clang 21 and
  gcc 13 (decision 91).
  The wide P-256 files wipe every object they name that held a secret,
  and a compiler also keeps limbs in stack slots no `ct_wipe` can name.
  So `widemul.h` calls `p256_wide_wipe_below` after each wide call whose
  operands are secret, which wipes the `P256_WIDE_BELOW_LEN` bytes of
  stack under the dispatcher's caller, where the frames of that call lay
  (decision 94). `bin/p256_equiv_test` requires each wide entry to write
  inside that length, requires zero below each of the six dispatchers,
  and looks below a signature and a key exchange for any 64-bit limb of
  the private scalar, the nonce, its inverse, z + r d and the shared X
  coordinate. Six `inv17-p256-wide-*-leaves-its-stack` violations each
  drop one dispatcher's wipe, and the binary catches each.
  A session with the multiply bit still runs `p256_scalar_add` and
  `p256_scalar_reduced_mask` on the 32-bit limbs, which multiply nothing.
  Each names a temporary that gives its operand to whoever reads it: the
  sum z + r d, that sum less n, and the private scalar or the nonce less
  n. So those two routines and the conditional subtraction they share
  with `p256_scalar_reduce` wipe the three arrays (`p256_scalar.h`,
  decision 94). The same binary looks for a limb of each difference too.
  A temporary's lifetime ends with its call, and whether a limb of it
  stays depends on the compiler, so `proof/p256_scalar_harness.c` counts
  the bytes `ct_wipe` is handed after each routine. Three
  `inv17-p256-scalar-*` violations each drop one wipe, and the proof
  catches each.
  Inside the host object's GHASH, `ghash_hw.c`'s data loop computes the powers
  of H it needs, adds up each pass's products in the same state, and wipes
  both with H when each call ends. It reads each power from that state
  through a volatile lvalue, because both compilers, holding the eight in
  registers across a pass, copied some to stack slots of their own.
  `bin/ghash_equiv_test` copies the stack below one call and requires no
  power of H, no power's two halves added and none of the last pass's sums
  in it. `ghash-hw-powers-wipe-skipped` stops that wipe before the powers,
  `ghash-hw-sums-past-wipe` moves the sums past its end, and
  `ghash-hw-powers-held-in-registers` reads the powers through an ordinary
  pointer; each requires the binary to fail. `gcm_hw.c`'s one-pass seal
  and open keep their powers, sums and each pass's keystream in one state
  they wipe when the call ends, and write each pass's output over its
  keystream, so no keystream stays live to that wipe; the same binary
  copies the stack below one seal and one open and requires none of them
  there, the last pass's keystream included.
  An AES-GCM open decrypts while it hashes, so a tag that does not match
  finds the plaintext written, and that plaintext exclusive-ored with the
  ciphertext is the keystream of the nonce. `gcm.c` wipes those n bytes
  before it returns 0 (gcm.h, docs/decisions.md 85). `bin/quic_test`'s
  SP 800-38D vectors forge one tag bit and require zeros after the call,
  and `gcm-open-keeps-plaintext` drops the wipe and requires that binary
  to fail. `bin/quic_suite_test` forges the tag of a packet with a second
  packet after it in one datagram, and requires the failed open to leave
  the header unprotected, as it does before the AEAD runs, zeros in the
  payload, and the tag and the packet after it as they arrived.
  `sha256_hw.c` and `sha512_hw.c` each keep every value their
  compression function computes from a block in one `block_state`, and
  wipe it when the call ends: the message schedule, the working
  variables and the state the block began with. Under HMAC the first
  block is the key, and the state after it stands for the key (decision
  93). Each reads the state a block began with through a volatile
  lvalue, because gcc 13 on x86-64, holding that state in a register
  across SHA-256's sixty-four rounds, put one half in a stack slot of
  its own. `sha256_of_hw`, `sha384_of_hw` and `sha512_of_hw` also wipe
  the context they hash in. `bin/sha2_equiv_test` copies the stack below
  five kinds of SHA-256 call and six kinds of SHA-512 call, and requires
  no four 32-bit words in a row, or two 64-bit ones, that the call
  computed from its input (`test/sha2_equiv_residue.h`,
  `test/sha2_equiv_residue512.h`). Eight violations each undo one of
  those. `inv17-sha256-hw-block-state-kept` and
  `inv17-sha512-hw-block-state-kept` drop the wipe of a `block_state`;
  `inv17-sha256-hw-whole-message-context-kept`,
  `inv17-sha384-hw-whole-message-context-kept` and
  `inv17-sha512-hw-whole-message-context-kept` the wipe of a context;
  `inv17-sha256-hw-start-state-in-spill-slot` the volatile read; and
  `inv17-sha256-hw-round-input-outside-block-state` and
  `inv17-sha512-hw-round-sum-outside-block-state` each move one value of
  a round out of the `block_state`. The binary catches each under
  `qemu-x86_64` or `qemu-aarch64`, the target its edit shows on. No
  violation drops `sha512_hw.c`'s volatile read: on arm64 neither
  compiler measured puts the state in a slot of its own without it.
  `sha256.c`'s `compress` wipes neither its schedule array nor its
  working variables, `sha512_compress.c`'s the same, and `sha256_of`,
  `sha384_of` and `sha512_of` do not wipe their contexts (`sha256.h`,
  `sha512.h`); decision 93 leaves those files as they were.
  `sha3_hw.c` keeps the 25 lanes of a state in registers from a
  message's first whole block to its last and writes them to the
  caller's state alone, and `sha3.c`'s `sha3_256` and `sha3_512`, which
  the file compiles once more, wipe the state they hash in. Keccak-f[1600]
  is a permutation, so one whole state gives back each state before it,
  as far back as the input, which under ML-KEM is a secret seed.
  `bin/sha3_hw_equiv_test` copies the stack below six kinds of call and
  requires no 64-bit word there that the call computed: a lane of any
  state, a column's parity, a value theta adds, or a lane after theta,
  rho or chi of any round (`test/sha3_hw_equiv_residue.h`). gcc 13 keeps
  lanes in stack slots of its own choosing in every form of the file
  tried, so only clang compiles it (decision 99). Two violations undo the
  rule. `inv17-sha3-digest-state-kept` drops `sha3.c`'s wipe, and
  `inv17-sha3-hw-lane-in-stack-slot` writes one lane to a slot of its own
  each round. The binary catches both, built with clang for arm64 and run
  under `qemu-aarch64`.
- **Violation.** A PR adds an early return between fail and wipe, or
  lets a failed QUIC session keep a read key, or a write key past its
  one close, or keeps the read key once the peer's close_notify has
  arrived, or wipes the write key there, or returns from a failed AES-GCM
  open without wiping the plaintext it wrote.
- See [decisions: Memory and runtime](decisions.md#memory-and-runtime).

### INV-18 — no library-global mutable state

- **Claim.** All state lives in the session struct the caller passes:
  `ch_tls` under `TRANSPORT=tcp-blocking`, `ch_record` under
  `TRANSPORT=tcp-nonblocking` and `ch_quic` under
  `TRANSPORT=quic-nonblocking`, in either role. `ch_record` and
  `ch_quic` each hold a `ch_tls` beside the driver state that survives
  a return (`tcp_nonblocking.h`, `quic_session.h`), and a call that
  takes no session, such as `ch_srv_check` or the Retry token calls,
  keeps nothing between calls. The library object carries no
  top-level mutable variable outside `drbg.c`, so sessions cannot
  interfere and the whole stack is reentrant per session.
- **Mechanism.** Structural; the reference DRBG (`drbg.c`) is the
  sole documented exception: its key and its seeded flag are
  file-scope variables that every session in the image shares, and
  only a `RAND=drbg` object packages it. A `RAND=session` object
  carries no generator at all: every draw goes to the source the
  session's own `ch_cfg` names (INV-4), so sessions on different
  threads share no entropy state.
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
  on the Cortex-M3). Those two frames are the 32-bit arithmetic's, which a
  device object compiles. A host object's `rsa_vp1` calls `rsa_mont64.c`,
  whose largest frame is `rsa_mont64_public`'s: 848 bytes at the device
  bound and 1,104 at the `TRUST=webpki` one (Apple clang 21, arm64).
  `rsa_sign64.c`, which a host object alone holds, gets 6,656: a CRT
  signature holds a modulus record for each prime, the message, both
  halves and the candidate at once (measured worst: `rsa_sign64_sp1` at
  4,368 at the 384-byte bound and 5,776 at the 512-byte one with Apple
  clang 21 on arm64, and 4,544 and 6,016 with gcc 13.3 on x86-64), and
  its exponentiation a table of sixteen powers, each as long as a prime
  (3,408 and 4,496, and 3,328 and 4,416).
  ML-KEM's own sources, `KEX_HYBRID_SRCS`, get 6,656
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
  `$(STACK_BUDGET_KEX_HYBRID)` for the ML-KEM sources and
  `$(STACK_BUDGET_RSA_SIGN64)` for the 64-bit RSA signer, so
  docs/performance.md's stack numbers are a compile-time contract, not a bench
  observation. Until the hybrid build landed the recipe iterated
  `$(SRCS)` without `$(LIB_DEF)`, so it measured the default build
  whatever PIN, TRUST or KEX asked for and no variant was ever
  checked; the pq frames are what exposed it. Host test mains are
  exempt from the frame budget; they keep vector tables in their
  frames.
- **Check.** Type-system grade (the compiler refuses); bench/sram.sh
  measures the whole-call-chain peaks docs/performance.md reports, and
  `make lint-stack-walk` checks that bench/stack.py, which walks each
  chain, follows a call and a tail call on a fixture, keeps two static
  functions of one name in two objects apart, names the calls it counts
  no frame for, and compiles the sources and the defines make packages
  for the build it walks. `make check`
  runs lint-stack for the build it was given through `lint`, and runs
  `make lint-stack TRUST=webpki` as a leg of its own, so plain `make
  check`, the target CI's `check` job runs, holds the 4,096-byte budget
  too. `make lint-stack ROLE=server TRUST=none` is
  another leg, the one that compiles the server's sources. The
  `TX_RECORD` leg runs it on the `TRUST=webpki ROLE=both` object at
  `TX_RECORD=16384`, the one axis that exists to make a buffer larger.
  `srv_frag`, the one stack buffer `CH_TX_PT` used to size, keeps
  `SRV_FRAG_MAX`, 512 bytes, whatever `CH_TX_PT` is (decisions.md 71).
  `inv19-srv-frag-sized-by-tx-record` sizes it by `CH_TX_PT` again, and
  `bin/webpki_loop_tx_record`, whose handshakes count the Certificate's
  three records, fails.
- **Violation.** A PR sizes a scratch buffer from a length field, or
  adds a frame that silently outgrows the smallest supported SRAM.
  `test/violations/inv19-webpki-object-frame.violation` is that mutant:
  a 5,000-byte buffer in `p256_ecdsa_verify`, which an rsa mode filters
  out of every other object, so only the `TRUST=webpki` leg compiles the
  file and objects. A published peak can also read low when the walk
  misses an edge. `inv19-stack-walk-first-instruction-jump` makes
  bench/stack.py read the placeholder target objdump prints on a branch
  at a function's first instruction, as it once did,
  `inv19-stack-walk-static-callee-global` drops every call to a static
  function, and `inv19-stack-walk-no-build-defines` compiles a
  `TRUST=raw-ecdsa` walk without `-DCH_PIN_ECDSA`. A peak can read high
  as well. `inv19-stack-walk-static-by-symbol` merges the static
  functions of one name in several objects, and
  `inv19-stack-walk-extra-source` compiles a source the build does not
  package; the walk once did both, and put the `TRUST=raw-ecdsa` peak at
  3,824 bytes where it is 3,104. `make lint-stack-walk` fails on each.
- See [decisions: Memory and runtime](decisions.md#memory-and-runtime).
