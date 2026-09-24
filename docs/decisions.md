# Design decisions

Every entry here is a trade we made on purpose: what it costs, and what
it buys. Changing one means re-arguing the trade, not just editing the
code. The README states what the stack does; this file states why it
does nothing more.

## Protocol surface

1. **TLS 1.3 only, one profile, nothing negotiated.** Cost: no interop
   with TLS 1.2-only peers. Gain: no downgrade or agility surface. The
   client offers exactly one of everything; the server takes it or the
   handshake fails closed.
2. **No 0-RTT, no compression, no renegotiation-era features.** Cost:
   none we accept (the IETF IoT profile forbids 0-RTT anyway). Gain:
   replay and compression-oracle bug classes are structurally absent.
3. **The MUSTs stay despite minimalism**: HelloRetryRequest with
   transcript restart, KeyUpdate both directions, NewSessionTicket with
   resumption, RFC 9257 binder discipline. Cost: real complexity. Gain:
   a conforming client, not a toy that works until it meets a strict
   server.
4. **The stack tracks RFC 9846**, the 2026 revision of TLS 1.3 (no wire
   changes; same version number). The audit against its tightened
   requirements: fresh KeyShare per connection and no legacy version
   negotiation were already true by design; the sender-side KeyUpdate
   epoch cap and reading through user_canceled to the close_notify were
   implemented; the receive-side epoch cap is deliberately not enforced,
   exactly as the RFC requires of receivers. Section citations follow
   9846's numbering.
5. **Strict parsing.** Trailing bytes in an extension, duplicate
   extension types, and malformed CCS are fatal; streams that make no
   progress hit hard caps. Cost: no tolerance for sloppy peers. Gain:
   RFC decode errors actually fail, and a hostile stream cannot pin the
   client forever.

## Cryptography

6. **ChaCha20-Poly1305 only as a cipher suite; AES exists for QUIC's
   public-key packets alone.** Cost: the IoT profile's mandatory AES-CCM
   suite and AES-only servers. Gain: constant time by construction on any
   core for every secret this tree holds — no lookup table is ever indexed
   with a key from the TLS key schedule, so there is no timing story to
   defend. The one AES in the tree protects QUIC Initial packets and checks
   the Retry tag, where RFC 9001 §5 states the keys are public, and entry
   38 and INV-26 state how the build keeps it there. An AES-CCM build flag
   is the most likely future concession, and it would not reuse that AES.
7. **x25519 in 16-bit limbs (the TweetNaCl scheme).** Cost: about 57 ms
   per scalar multiplication on the mips32r2 reference target, where
   wider limbs would be faster. Gain: a machine-checked overflow lemma
   and citable prior formal work on the same scheme. Provability over
   speed; revisit if the workload becomes many short connections.
8. **One pinned signature algorithm per build**: RSA-PSS by default,
   P-256 behind `make TRUST=raw-ecdsa`, never both. Cost: switching means
   rebuilding. Gain: no signature-algorithm negotiation surface and a
   smaller binary. RSA won the default on measurement — its verify is
   4x faster and 3.5 kB smaller in flash than P-256's — and RSA is what
   stock endpoints hold.
9. **RSA is verify-only**: exponent fixed at 65537, moduli of 256 to
   384 bytes, the pin is the raw modulus, no PKCS#1 v1.5, deliberately
   variable time. Cost: exotic keys are unsupported. Gain: a tiny
   fixed-shape verifier with no ASN.1 in it. DER handling lives in
   `x509_der.c` alone, and only CA-mode builds package that file;
   `rsa.c` stays ASN.1-free in every build. Variable time is safe
   because every input to verification is public.
10. **No Ed25519.** Cost: none today — no real server-certificate
   population uses it, and PSK already covers endpoints we control.
   Gain: no second hash function (Ed25519 needs SHA-512) and no third
   pin mode. `TRUST=webpki` does carry SHA-512, because a public chain's
   signatures use SHA-384; the gain stays whole for the device modes,
   and docs/webpki.md says why Ed25519 stays out of the public chain
   too.

11. **Rejection sampling reads a fixed 1536-byte XOF budget per
    polynomial.** FIPS 203's SampleNTT reads an unbounded SHAKE128
    stream; `mlk_sample_ntt` stops after `MLK_SAMPLE_GROUPS` (512)
    three-byte groups. Cost: a seed that needed more than 1536 bytes
    would leave the polynomial's tail holding the caller's values —
    and no reachable seed does: 704 bytes already put the probability
    of needing more below 2^-128 (C2SP/CCTV's bound), and the
    adversarial unluckysample vector, built to need over 575 bytes,
    passes. Gain: every loop in the ML-KEM module has a static bound,
    so the CBMC harness proves memory safety with unwinding
    assertions on rather than assuming an unproven loop bound.
12. **Hybrid key exchange is a build, not a negotiation.** `make
    KEX=pq` offers X25519MLKEM768 alone; the share carries the
    ML-KEM-768 bytes first, as RFC 10024 orders them, despite the
    name. Classic builds offer x25519 alone. No build offers both
    groups. Cost: a pq build cannot talk to a classic-only server,
    and a classic build cannot talk to a pq-only server; each pairing
    fails the handshake closed. Gain: no group negotiation, the same
    rule the rest of the profile follows (entry 1).

    Entry 39 narrows this to the device modes. `KEX=pq TRUST=webpki`
    offers both groups, for the reason that mode already offers several
    signature schemes and several application protocols. `KEX=x25519
    TRUST=webpki` still offers x25519 alone and carries no ML-KEM.
    Entry 53 later changed the webpki half: every `TRUST=webpki` build
    carries ML-KEM and offers both groups, and `make` refuses a `KEX`
    value beside that trust mode. Entry 54 gives every server role both
    groups and a preference for the hybrid; this entry describes clients.

    Offering both groups and taking whichever the server picks was
    considered and rejected. It fails where it would matter most: the
    threat is harvest-now-decrypt-later, so a client that offers both
    and meets a server without ML-KEM completes a classically
    protected session, the recording stays decryptable later, and no
    part of the API reports which exchange ran. Fail-closed answers
    instead that a completed handshake was post-quantum. This is not
    a downgrade attack — the transcript hash and the server's
    signature or binder authenticate the group choice — it is the
    honest server that has no ML-KEM. The cost is also paid whether
    or not the hybrid is used: measured with gcc -Os on x86-64, the
    library sources are 25.0 kB of .text plus .rodata classically and
    32.3 kB in the hybrid build, and the session struct 1,056 bytes
    against 2,328, so a negotiating build carries ML-KEM on every
    connection including the ones that never run it.

    Two fields close, in every build, the one gap the argument above
    names — that no part of the API reports which exchange ran.
    `ch_tls.group` reports the NamedGroup the ServerHello's key_share
    selected, `CH_GROUP_X25519` or `CH_GROUP_X25519MLKEM768`, and
    `ch_cfg.require_pq` fails the handshake when that group is not
    `CH_GROUP_X25519MLKEM768`. Under `KEX=pq` the flag asserts a
    build-time property at run time: the build offers the hybrid alone,
    so the check reads the field the parser wrote and never the constant
    the build offered. A classic build refuses the flag at `ch_connect`
    with `CH_EINVAL`. The decision itself does not move for the raw and
    ca builds: each offers one group.

## Trust model

13. **Raw-pin builds hash certificates into the transcript, never
    parse them.** No X.509, no chains, no names, no expiry, no
    revocation, no trusted clock. Cost: no PKI; the operator
    provisions a key. Gain: the DER-parser vulnerability class does
    not exist in those builds. CA pinning was first declined on three
    objections: it readmits the parser class, needs a trusted clock
    for validity, and a pinned CA without name checking turns every
    certificate that CA ever issued into a skeleton key. The
    CA-mode build (entry 16) later answered each objection on its
    own terms. The profile removes the clock objection by design: the
    device reads no validity values, and freshness moves to
    reissuance policy. It contains the parser objection by proof: a
    fixed-grammar canonical-DER parser with CBMC memory-safety
    proofs, a Lean differential oracle, and a fuzz harness. And it
    accepts the skeleton-key objection and scopes it: the pinned key
    must belong to a CA dedicated to the fleet, every server
    certificate carries
    `extendedKeyUsage` exactly serverAuth, and docs/ca.md makes
    exclusivity of the pinned key the operator's contract.
14. **Key rotation is a second pin slot.** Cost: 16 bytes of config
    and an out-of-band recovery path for devices that miss both
    pushes. Gain: rotation without a fleet flag day, inside the trust
    model we already have. CA builds layer CA indirection on top of
    the same two slots: the slots hold CA keys, routine server-key
    rotation becomes reissuance and never touches devices, and the
    slot pair rotates the CA key itself. See docs/rotation.md.
15. **Tickets make both auth modes cheap.** Reconnects resume over PSK,
    so pinned mode pays its signature verification once per ticket
    lifetime; the recurring cost of any handshake is the key exchange
    alone — two x25519 operations, plus the ML-KEM keygen and decaps
    in a `KEX=pq` build (entry 12).
16. **CA trust is a build, not a negotiation.** `make TRUST=ca-rsa` pins a
    CA public key in the pin slots and verifies the server's chain — a
    server certificate alone, or that plus one intermediate — against
    it with a
    profiled parser: canonical DER, the build's one signature
    algorithm throughout, a fixed extension profile, signatures and
    shape only. Cost: the parser's flash and stack, one or two extra
    signature verifies on each full handshake, a receive-buffer floor
    derived from the certificate cap, and no device-side revocation —
    a stolen server key keeps authenticating until the CA key rotates,
    because the device reads no dates. Gain: server keys rotate by
    reissuance with zero device touches, and one pin covers a fleet
    of servers. Freshness is issuance policy, not device state: short
    certificate lifetimes and a monitored reissuance pipeline do the work
    that expiry checking would. docs/ca.md is the operational
    contract that makes the small device-side check sufficient.
17. **Public CAs stay a non-goal for the device modes.** Cost: an
    operator of a device fleet runs a dedicated CA or contracts a
    dedicated intermediate. Gain: a raw or ca device keeps needing no
    clock and no name matching — a public CA's trust model requires
    both, and a public CA's signature algorithms sit outside the device
    profile besides. A public-CA-fronted server still works from a
    device through raw-pin mode with a stable server key. docs/ca.md
    records the argument and the workable arrangements with external
    CAs.

    A host-side client has the clock, the memory and the hostname a
    public chain needs, and it may have no other way to reach the
    endpoint it was written for. That is what `TRUST=webpki` is, and
    entry 36 records it as a separate mode rather than as a change to
    this one: raw and ca do not move.

## Memory and runtime

18. **Zero heap.** One caller-allocated session struct plus one
    caller-provided receive buffer. Cost: the caller sizes memory up
    front. Gain: no allocator, no out-of-memory paths, and bounds the
    proofs can state exactly.
19. **`record_size_limit` is the receive buffer's size.** Cost:
    strictness toward peers that ignore RFC 8449 — an oversized record
    is a protocol error, not a resize. Gain: a peer can never send what
    the buffer cannot hold.
20. **Single task, single connection.** The reference random generator
    has global state, so every session in an image draws from one
    stream. Cost: no multi-session generator isolation. Gain:
    `ch_rand_bytes` stays a clean import that firmware replaces; see
    docs/entropy.md.

    **Which generator an image uses is declared, never defaulted**
    ([#41](https://github.com/c4milo/chapulin/issues/41)). `RAND=extern`
    leaves `ch_rand_bytes` undefined, so an image that never wired a
    generator fails to link; `RAND=drbg` packages `drbg.c` and exports
    `ch_drbg_seed`, which also puts the generator's `CH_ASSERT(g_seeded)`
    into a shipped object for the first time. Naming neither reaches an `#error` in `cfg.h` rather
    than one in the Makefile, because a firmware tree compiles these
    sources with its own build system and a Makefile-only check would
    miss exactly the integrator this targets. Cost: every consumer
    build writes one more line, and the break reaches every existing
    consumer at once. Gain: "I supply my own generator" is a statement
    somebody made rather than a step nobody took. Rejected: a weak
    `ch_rand_bytes` default, which would convert the link error into a
    build that succeeds — wolfSSL's `USE_TEST_GENSEED` shape, where a
    skipped decision looks like a made one.

    The hook returns `void`, and giving it a `ch_err` return was considered
    and deferred ([#41](https://github.com/c4milo/chapulin/issues/41)). A
    return code is the honest answer for a transient hardware fault, but it
    breaks the one function every consumer firmware tree implements, for a
    case `rand.h` already covers by contract: a generator that cannot
    produce bytes blocks or faults rather than returning short. What the
    `void` return does not catch is a hook that returns without writing, and
    that is why every draw in `handshake.c` is followed by an all-zero check
    against `rand.h`'s contract. Neither the check nor any signature can
    tell a weak generator from a strong one; nothing in a library can.
21. **Every operational error fails closed**: alert, wipe keys, dead
    session, caller reconnects. Cost: no graceful recovery. Gain: the
    entire resumable-error state space is removed from the code and the
    proofs. Corollary: `CH_EINVAL` (invalid configuration, nothing
    sent) is distinct from `CH_ECAP` (runtime capacity), so
    provisioning corruption never reads as an attack on the wire.

22. **One TX staging array, sized per build.** The ClientHello
    builder and the sealed-record path share the session's TX array; their
    lifetimes never overlap. `CH_TX_STAGE` is whichever is larger, per
    build, and the hello wins in both: 617 bytes classic, 1801 with a hybrid
    key share, against the 529 a sealed record needs. The classic figure
    used to be the sealed record's, which left a maximum ticket identity
    plus a maximum retry cookie failing closed with `CH_ECAP` mid-handshake
    ([#46](https://github.com/c4milo/chapulin/issues/46)); covering the
    hello costs that build 88 bytes and lets the same compile-time assert
    run everywhere. A second array would cost every build the hello's bytes,
    and the handshake proof keeps one array to model. Streaming the hello
    stays rejected: the PSK binder is an HMAC over the contiguous truncated
    hello, so a streaming builder would buffer the message anyway.
23. **The receive-buffer floor is a build constant.** `ch_connect`
    checks `buf_len` against `CH_MIN_RXBUF` before anything is sent.
    A feature that needs more room raises the constant, so a
    too-small buffer fails at setup with `CH_EINVAL`, not
    mid-handshake with `CH_ECAP`, where it would read like an attack.
    The floor covers only what the build can know: a raw-pin server's
    chain is the server's choice, so raw-pin deployments size above
    the floor. A CA build does know its worst case — the certificate
    cap bounds the chain — so it derives the floor from the cap
    instead of picking a number: `2*(CH_X509_MAX+5)+16`.
24. **The ML-KEM key pair lives as a 64-byte seed.** The handshake
    keeps the (d, z) seed in `handshake_state`, which lives on
    `ch_handshake`'s frame for the length of the handshake, instead of
    the expanded key pair.
    `mlkem_keygen_dk` re-expands it into a stack buffer at ClientHello
    build and again at decapsulation: two keygen runs per handshake,
    three when a HelloRetryRequest makes the client rebuild its hello.
    `mlkem_keygen_dk` writes the encapsulation key in place at
    dk + 1152, FIPS 203's own dk layout, so one dk-sized buffer serves
    both sites. The expansion is deterministic, so that
    retry sends the identical share without storing it. Cost: one
    keygen run more than a stored key pair would need, two more on a
    retry. Gain: 64 bytes of session state instead of the 2,400 a
    stored dk costs, and the dk lives only for the length of one call
    rather than for the length of the session.

## Assurance

25. **Bounded model checking, layered, with a published ledger.** Leaf
    modules prove concrete; upper layers prove against
    contract-checking stubs of the proven layer below. Where a formula
    will not converge, the harness pins a representative bound and
    documents it. Cost: this is not functional verification. Gain:
    proofs that finish, and claims nobody has to take on faith — the
    README states what is proved, at what bound, and what is only
    tested.
26. **The Lean spec is written from the RFCs, never from the C**, is
    partial exactly where the RFCs are partial, and carries theorems
    about itself. Cost: everything is implemented twice. Gain: a shared
    misreading of an RFC cannot make both sides agree, and each
    C-versus-spec agreement transfers a proven property, not just a
    matching answer.
27. **The RFC 8448 replay stops at secrets and MACs.** The traces
    protect records with AES-128-GCM, which this stack excludes, and
    sign with an RSA-1024 key, below the verifier's floor — so the
    tests check the floor holds, then verify the trace's
    CertificateVerify one layer down through the raw modexp. Cost: the
    replay never opens a record. Gain: third-party byte-exact checks of
    the transcript and key schedule without weakening the profile.

## Engineering

28. **Four exported symbols.** The library packages as one relocatable
    object; partial linking plus symbol localization does the
    namespacing, so sources keep natural names and applications cannot
    collide with internals.
29. **CI compiles with gcc on purpose** while development machines run
    clang: consumers are firmware trees whose vendor SDKs ship gcc
    cross-compilers, so gcc-only diagnostics belong in CI. Between the
    two, both major compiler families stay covered without a second CI
    leg.
30. **Tool versions pin to the development machine's.** When the local
    toolchain upgrades, the CI pins bump in the same commit. Code never
    adapts to an older checker.
31. **Two proof solvers, each where its memory profile fits.** kissat
    runs the fast tier (measured: verdicts in seconds to minutes where
    the built-in solver ran for hours); CI's slow tier keeps the
    built-in solver, because the external-solver path materializes the
    whole formula and exhausts a 16 GB runner. Verdicts are
    solver-independent. A content-keyed cache re-proves only what
    changed.
32. **Third-party audit is the optimization target.** Every
    review-facing trade — spelled-out names, the complexity-15 gate,
    pure predicates with state changes on their own lines, pinned
    byte constants instead of decode-and-judge — pays a little
    compactness for a lot of reviewability. Cost: more lines and
    more named helpers than the terse form. Gain: a security library
    earns trust through reviewers who did not write it, and every
    clever compression taxes each of them.
33. **Assertions live at proof time; runtime keeps contract-point
    guards.** TigerStyle asserts the negative space at runtime, two
    per function, on in production. chapulin moves that space into
    the CBMC layer — 193 proof assertions checked over every input
    at the bound — because on an unattended device an abort on
    hostile input is the denial of service. Runtime keeps only
    contract-point guards that no input can trigger (state-enum
    validity at the API entries), which also cover corrupted memory.
    Cost: hardware faults mid-connection surface as failed
    handshakes, not named aborts. Gain: exhaustive checking where
    inputs are hostile, and no abort path an attacker can reach.

34. **Revocation travels in the server certificate's notBefore, on a
    restricted set of dates.** A clockless device cannot check expiry
    or fetch a
    CRL, so reissuance alone never revokes a stolen server key. The
    epoch turns notBefore into a counter the CA already signs: dates
    restricted to UTCTime, YY 00..49, DD 01..28, midnight, compared
    as the exact index `YY*336 + (MM-1)*28 + (DD-1)`. Alternatives
    declined: a new certificate extension (every CA would have to
    learn it, and the device would parse more), a serial-number
    counter (issuance tools own serials), and GeneralizedTime dates
    from 2000 on (RFC 5280 §4.1.2.5 mandates UTCTime through 2049,
    so those certificates are unissuable). Cost: the CA must write
    an absolute notBefore, which Vault, step-ca, and AD CS will not
    do; advancing the epoch requires reissuing every server before
    any device
    sees it; and a device isolated from the fleet never learns of a
    it. Gain: a device-side revocation check with no clock, no CRL,
    no OCSP, and four bytes of device state. The epoch revokes
    certificates; revoking a stolen key means reissuing that server
    on a fresh key pair and advancing the epoch, so the old
    certificate falls
    below the stored epoch. Advancing is what makes key rotation stick.

35. **The stored epoch moves only after the server authenticates.** A
    CA-signed certificate is public, so presenting one proves
    nothing about the presenter: an attacker can replay a genuine
    higher-epoch certificate harvested from any real server. Rejecting on
    the chain verdict alone is safe — it only fails the handshake
    closed — but raising the stored epoch outlives the session, so
    it waits until
    CertificateVerify and Finished have proven a real server is
    there. Cost: the rule splits across two call sites instead of
    one. Gain: an unauthenticated peer cannot move device state that
    outlives the session.

36. **`TRUST=webpki` is a third trust mode, not a change to the other
    two.** It verifies a public chain against caller-supplied anchors,
    with hostnames and validity dates, so a host-side client can reach
    a public endpoint. Cost: a clock the caller supplies, a receive
    buffer measured in kilobytes, every signature family a public chain
    uses in one object, and a mode that refused PSK and resumption
    because nothing bound a ticket to a hostname, until entry 47 bound
    one. Gain: the raw and ca
    objects do not change — their sources, their defines and their
    SRAM rows stay where they are, and `make lint-trust-separation`
    holds the partition. docs/webpki.md states the profile, the
    measured bounds, and what the mode does not check.

    Extending the CA modes with optional dates and names was considered and
    rejected: it would put clock and name logic inside the object a
    device links. Verifying the chain in the caller instead of here was
    considered and rejected: it duplicates a certificate parser in a
    second language, outside this tree's proofs.

37. **A `TRUST=webpki` caller offers a list of application protocols and
    the server picks one.** ALPN (RFC 7301) is the mode's second
    exception to the rule that the client offers exactly one of
    everything, after the signature schemes. Cost: a negotiation
    surface. The ClientHello carries up to `CH_ALPN_MAX` names, the
    server chooses among them, and the outcome differs per connection,
    so the caller reads `ch_tls.alpn_selected` and branches on it —
    including on `CH_ALPN_NONE`, which says the server selected no
    protocol. Gain: one handshake instead of a failed one and a
    reconnect. An HTTP client that could offer one name would have to
    guess `h2`, and a server that speaks `http/1.1` would cost it a
    second full handshake.

    Offering one protocol per build, the way `PIN` and `KEX` fix one
    algorithm, was considered and rejected: a build cannot know what a
    given endpoint speaks, and the fallback costs a whole connection.
    Failing the handshake when the server sends no ALPN extension was
    considered and rejected too: RFC 7301 §3.2 lets a server that does
    not implement ALPN leave it out, so refusing there would refuse every
    server that speaks `http/1.1` by convention. docs/webpki.md states
    what the caller branches on and what the client refuses.

38. **QUIC is a transport axis, and chapulin owns packet protection on
    it, AES included.** RFC 9001 §4.1.3 removes the record layer: QUIC
    carries bare handshake messages in CRYPTO frames and protects
    packets itself. A `TRANSPORT=quic` build takes handshake bytes in,
    hands handshake bytes out, and seals and opens every packet at every
    level, so no traffic secret leaves the object. colibri, the HTTP/3
    caller, owns everything that is not cryptography: packet numbers,
    ACKs, loss recovery, congestion control, flow control, streams,
    connection IDs, Retry and version negotiation logic, and path
    validation. Cost, and most of it lands here: a fifth value in
    `LIB_VARIANT` beside PIN, TRUST, KEX and RAND; fifteen exported
    transport symbols against entry 28's four, on a `PUBLIC` whose
    first term the axis selects —
    `$(PUBLIC_TRANSPORT) $(PUBLIC_RAND) $(PUBLIC_CA)`, where
    `PUBLIC_TRANSPORT` drops the four TLS names rather than adding to
    them and the other two terms keep their meaning, so a CA-mode or
    RAND=drbg QUIC object exports sixteen and one with both exports
    seventeen; five library files replaced — `record.c`, `io.c`, `session.c`, `handshake.c` and
    `tls.c`, 990 lines — and five more given a second arm under
    `#ifdef`; entry 19's `record_size_limit` dropped, which leaves
    `cfg.buf_len` as the only cap on what a peer can send; the KeyUpdate
    entry 3 keeps turned into a connection error (RFC 9001 §6); two
    exceptions to entry 21 inside this tree, because RFC 9001 §5.5
    discards a packet it cannot authenticate instead of closing and
    because a caller-order mistake leaves the session live; entry 37's
    ALPN lifted out of `TRUST=webpki` into every trust mode, because RFC
    9001 §8.1 requires it; and AES-128-GCM and AES-128-ECB entering the
    codebase against entry 6. The largest piece is none of those. The
    driver blocks on the wire at five `hsr_next_msg` call sites, two of
    them in `handshake_auth.c`, so the caller-driven interface runs one
    step per whole handshake message, moves the handshake frame — 448
    bytes raw, 856 under TRUST=ca-rsa, 976 under TRUST=webpki, 512
    under KEX=pq — into the session, moves 233 of `handshake.c`'s 395
    lines into a `handshake_flight.c` both transports compile, and
    changes `handshake.o` in every TLS build. `handshake_psk` and
    `handshake_pin`, two of `proof/run.sh`'s 83 launch lines, are
    re-measured because that file moves under them. Gain: no second
    crypto stack. Every traffic secret a QUIC connection uses is
    derived, held, used and wiped inside one object this tree proves,
    and RFC 9001 §9.5's requirement that header protection removal,
    packet number recovery and packet protection removal happen together
    without timing side channels is met inside this tree's constant-time
    rules, measured by lint-wide-multiply on the 1-RTT path and argued
    from public keys on the Initial one, instead of re-argued in a second
    repository. Measured at `3432a5d`: the driver touches the record
    layer at 15 call sites in three files and the key schedule at none,
    and unchanged lines are 1,335 of 3,460 in a raw-mode object and
    4,392 of 6,517 in a TRUST=webpki one.

    Entry 6 does not fall; it gains one exception with a checkable
    boundary. The AES ban exists to keep a secret key out of
    table-driven code, and every key AES touches in QUIC is public: the
    Initial keys come from the client's Destination Connection ID and a
    salt RFC 9001 §5.2 prints, the Retry key and nonce are printed in
    §5.8, and §5 states that neither packet type is considered to have
    confidentiality or integrity protection. So AES may exist only
    where the key is public — Initial packet protection (§5.2), Initial
    header protection (§5.4.3) and the Retry integrity tag (§5.8) — and
    never under a key from the TLS key schedule. A key type,
    `aes_public_key`, that only `quic_aes.c`, `quic_initial.c` and
    `quic_retry.c` can build is the first guard, and the compiler runs
    it: `quic.h` stores no key, only the Destination Connection ID the
    keys come from, so the type is incomplete everywhere but the three
    sources that include `quic_aes_key.h`, and a fourth file that
    declares one gets an error. The calls are the part a rule reads, so
    the new invariant is Semgrep-tripwire there, the grade this tree
    gives an identifier ban: it permits exactly two callers and exactly
    three key sources, and no other source may call a symbol whose name
    begins `aes_` or `gcm_`. A reintroduction under another name is what
    a tripwire does not catch, and the reviewer reading the diff is what
    does. A Semgrep rule beside the
    thirteen in `.semgrep/invariants.yml` fails the build on a third
    caller,
    `lint-codegen-partition` holds both files in `WIDEMUL_PUBLIC` where
    a maintainer has to move them in plain view to admit a secret,
    `lib-check` keeps their symbols out of `PUBLIC`, and a `.violation`
    file proves the first gate works. The `CLAUDE.md` sentence and this
    file's entry 6 change in the commit that lands the first AES
    source; docs/quic.md carries both replacement texts. Be suspicious
    of this: the safety sits in the call graph, not in the code, and a
    constrained primitive tends to grow callers.

    Handing per-level secrets out and letting the caller protect
    packets was considered and rejected. A 32-byte secret is not a
    packet protection layer: the caller would still write
    HKDF-Expand-Label, HMAC-SHA-256, ChaCha20-Poly1305 and the §5.4.4
    mask before it needed the AES, so that split moves seven primitives
    outside this tree's proofs to keep two out, and five of the seven
    touch real traffic secrets — the cost entry 36 refused to pay for
    the certificate parser. One secret leaves the object today, the
    resumption PSK in `ch_ticket.psk`, through `on_ticket`
    (`handshake_post.c:53-54`); it is a key for a future connection,
    not a live traffic secret, and a per-level traffic secret would be
    the first live key to leave. A second TLS stack for
    HTTP/3 was considered and rejected too: it gives one product two
    trust models and two failure disciplines, and entry 12's
    fail-closed post-quantum property would hold over TCP and not over
    QUIC. Entry 12 stands in a QUIC build: one key-exchange group per
    build, on the same PIN, TRUST, KEX and RAND axes.

    The driver landed in `33978f6`, which moved the client's flight
    handlers into `handshake_flight.c` and put `quic_step.c` on top of
    them. docs/quic.md states the interface, the suspendable driver
    step by step with the state each step leaves behind, the measured
    reuse per build, the bounds that still need measuring, and the
    verification owed.

39. **A `TRUST=webpki` caller offers both key exchange groups and the
    server picks one.** This is the mode's third exception to the rule
    that the client offers exactly one of everything, after the signature
    schemes (entry 36) and the application protocols (entry 37), and it
    has the same cause: a host-side client cannot know what the endpoint
    it dialled supports. Entry 12's one-group-per-build rule stands
    unchanged for the raw and CA modes, where the device already
    pins the key of the endpoint it will talk to and therefore knows what
    that endpoint speaks.

    The ClientHello lists X25519MLKEM768 and x25519 in `supported_groups`
    and carries the X25519MLKEM768 `key_share`. A server that wants
    x25519 answers with a HelloRetryRequest naming it, and the second
    hello carries an x25519 share over the x25519 half of the key pair
    the hybrid share already held. This entry first said the client
    already handled that retry; it did not. The retry path it had took a
    cookie and refused every retry that named a group, and the change
    that built this offer built that path with it (`CH_KEX_TWO_GROUPS`,
    `hsf_read_server_hello`). This applies under `KEX=pq`: `KEX=x25519
    TRUST=webpki` has no hybrid to offer and lists x25519 alone. Cost:
    one extra round trip against a classic-only server. Gain: no round trip on the post-quantum path, which is the
    path worth making fast, and one ML-KEM key generation per handshake
    rather than one for every hello whether or not it is used.

    Carrying both shares was considered and rejected. It never costs a
    round trip, but it puts an ML-KEM-768 share — 1216 octets — in every
    hello a webpki client sends, generates a key pair that most
    handshakes discard, and grows `CH_HELLO_MAX` for a build that already
    carries the largest hello in the tree. HelloRetryRequest is an RFC
    9846 MUST this client implements and proves, so the fallback costs a
    round trip on a path that is becoming rare rather than bytes on every
    path.

    The consequence worth stating plainly: entry 12's fail-closed
    property does not survive negotiation. A webpki client that offers
    both groups will complete a handshake with a classic-only server
    rather than refusing one, which is the point of offering both. A
    caller that wants the old guarantee sets `ch_cfg.require_pq`, which
    already refuses a handshake whose selected group is not the hybrid,
    so the property becomes the caller's to ask for rather than the
    build's to enforce. The flag also drops x25519 from the hello, so
    that caller sends the one-group hello a raw `KEX=pq` build sends: a
    server without the hybrid finds no common group and fails the
    handshake, rather than asking for x25519 and being refused one round
    trip later.

    Entry 53 replaces the key shares this entry describes, and the
    paragraph above that rejected carrying both. Every webpki build now
    sends a share for each group, so a server without the hybrid selects
    x25519 in one round trip, and the HelloRetryRequest path described
    here is gone. The rest stands: the mode offers two groups, and
    `ch_cfg.require_pq` gives the fail-closed property back.

40. **The pinned algorithm is half of a `TRUST` value, not an axis.**
    `PIN` chose RSA-PSS or P-256 for the key a raw or ca build pins. It
    selected nothing in the other two builds: a `TRUST=webpki` object
    carries every verifier because a public chain's links are signed by
    different algorithm families, and a `ROLE=server` object carries both
    because `ch_srv_check` verifies both provisioned identities at boot.
    An axis that names nothing in two of the builds that read it is a
    suffix. `TRUST` now spells it: `raw-rsa` (the default), `raw-ecdsa`,
    `ca-rsa`, `ca-ecdsa` and `webpki`.

    What this buys is not one fewer flag. It is that `make TRUST=webpki
    PIN=ecdsa` asked for one verifier and got every one, and the Makefile
    answered by quietly emptying `PIN_FILTER` behind the caller's back;
    that build can no longer be written. The `ROLE=server` block carried
    two refusals for the same reason and now carries one, and
    `TRUST=ca-ecdsa` gained a `lint-trust-separation` row, which it never
    had while it was a combination rather than a value.

    A server names `TRUST=none`, a sixth value, and is refused without
    it. Letting it take the client default described the object with a
    value naming one algorithm where it holds both, and left the trust
    value unwritten at every server call site: `make check
    TRUST=raw-ecdsa` died because one recursion had not named one and
    inherited it. `TRUST=none` is refused for a client, whose whole job
    is to judge a peer certificate, so neither role can build under the
    other's value. The object it produces is the same 34 sources as
    before.

    The C stays as it was: `CH_PIN_ECDSA` and `CH_TRUST_CA` are
    unchanged, so firmware that compiles the sources directly sees
    nothing move. A stale `PIN=` on a build line is refused by name
    rather than ignored, because ignoring it would hand back an object
    built around the other verifier. `TRUST=raw` and `TRUST=ca` are
    refused the same way, each naming the two values that replaced it.

41. **`ROLE=both` is a host-side value, and one-role-per-object stays for
    devices.** `ROLE=client` and `ROLE=server` each carry one role
    because a device carries one for the life of the deployment, so the
    flash the other costs buys it nothing. That is a firmware argument,
    and it does not reach a host library: colibri serves HTTP/2 and
    HTTP/3 and also fetches over them, and stompy will do both in one
    process.

    Two objects are not a substitute, which is the fact that decided
    this. Each carries the shared half, so linking a client object and a
    server object into one program makes `ld` report `ch_read`,
    `ch_write`, `ch_close` and `ch_drbg_seed` defined twice — measured,
    four duplicate symbols. colibri avoids it today only by attaching one
    object per module, so the two never meet in one binary.

    The combined object needs no dispatch and no second name. `srv.h`
    already states why: `ch_read`, `ch_write` and `ch_close` are the same
    functions over the same `ch_tls`, "because record.[ch] names no
    side". So the roles differ in one call each way, and `ROLE=both`
    exports seven where the halves export five and six. It is also
    smaller than what it replaces: 132,960 bytes against 183,980 for the
    two TLS objects, and 148,520 against 213,804 for the two QUIC ones.
    `TRUST=none` is refused here, because the client half judges a peer.

42. **A record-mode server pushes its flight; only the client pulls.**
    `TRANSPORT=record` exists because a blocking callback cannot sit
    under a completion-based event loop: colibri drives rotor, whose loop
    is single-threaded with no fibers, so a `cfg.recv` that waits stalls
    every connection the loop holds. `ch_srv_accept` blocks by contract
    (`cfg.h:371`), which is why `ROLE=server TRANSPORT=record` was
    refused until the driver existed.

    The client's shape does not carry over. `ch_record_out` hands a
    staged record to the caller, and that works because a client's
    messages fit `ch_tls.tx`. A server's do not: one Certificate message
    is larger than `CH_TX_STAGE`, and `srv_flight.c` stages a protected
    message on the handler's own stack frame and streams the chain
    through `srv_frag`. There is nothing to pull from. A pull would need
    a resume point inside `srv_out_sealed`'s record loop, and `rec_step.h`
    rules that out: a step runs on a whole message and waits nowhere
    inside it. `srv_quic.h` reached the same place for the same reason,
    so `ch_srv_cfg.on_record_out` is `on_crypto_out` without the level.

    That still solves the problem: the callback copies each record into a
    buffer the caller owns and returns, so nothing waits on a socket.
    INV-28 states the claim and `bin/srv_rec_test` measures it with a
    `send` and a `recv` that fail the run if the driver calls them.

43. **The exporter is a build axis, and it widens one cap rather than adding
    a second serializer.** `EXPORTER=on` compiles `ch_export` (RFC 9846 §7.5)
    and adds `exp_master` to `ch_tls`; `EXPORTER=off`, the default, compiles
    neither. `ch_tls` measures 1144 bytes off and 1176 on, so a device that
    exports nothing pays nothing and the README's SRAM figures are the
    default build's, unchanged. colibri asked for the call for h2
    (`docs/chapulin.md` in that tree), and a host is the only caller.

    The label is the caller's, and RFC 9266's is 24 bytes against the 12
    TLS 1.3 itself writes, so the axis sets `HKDF_LABEL_MAX` to 32.
    `hkdf.h` makes that cap a build parameter with a floor of 12 instead of
    growing a second `hkdf_expand_label` for long labels: the only thing
    the cap sizes is one stack buffer, and two serializers of one `HkdfLabel`
    would be two places for its layout to drift. `HKDF_INFO_MAX` is derived
    from the cap for the same reason; it was a literal 64 while the cap was
    fixed, and the default build's buffer shrinks by ten bytes as a result.
    `tls.c` asserts that the public `CH_EXPORT_LABEL_MAX` and hkdf's cap are
    one number.

    `ch_export` refuses rather than asserts. A label is data a caller may
    compute, so an over-long one is an operational error and returns
    `CH_EINVAL`, and `hkdf_expand_label`'s `CH_ASSERT` on the length, which
    `ks_exporter` reaches, is then unreachable from the public call. It refuses every state but
    `CH_ST_CONNECTED`, because the secret does not exist until the peer's
    Finished verifies and a closed session has wiped it with the rest.

    `EXPORTER=on` with `TRANSPORT=quic` is refused by name, in the Makefile
    and again in `keysched.h` for a tree with its own build system. The
    call sits in `tls.c`, which `QUIC_REPLACED` drops, so that object would
    list `ch_export` and never define it — which is what `lib-check` caught
    when the pair was first tried. RFC 9001 keys QUIC from the handshake
    secrets and uses no TLS exporter, and the h2 caller runs over records,
    so a QUIC exporter is a separate change with an entry of its own in
    `quic.h` if anyone asks for one.

    No published vector exists: RFC 9846 prints none and RFC 8448's trace
    stops short of it. `bin/exporter_test`'s four vectors were produced by
    this code and confirmed byte for byte against an implementation written
    from §7.5's text in Python, which catches a misreading of the spec and
    not a shared one. The README says cross-checked, not published.

44. **The key log is an axis, a link-time hook, and refused for a device
    client.** colibri's interop endpoint must write an NSS key log in both
    roles and over QUIC (its design §9), and colibri holds no secret to
    write, so chapulin hands each traffic secret out as it derives it.
    `KEYLOG=on` compiles four `ch_keylog` calls at the two places
    `ks_handshake` and `ks_master` run in each role; `KEYLOG=off`, the
    default, compiles none.

    It is a hook the image defines, the way `ch_rand_bytes` and
    `ch_aes_block` are, rather than a `ch_cfg` field. A `KEYLOG=on` object
    imports `ch_keylog`, so an image that turned the axis on and wired
    nothing fails to link rather than logging into nowhere; a `ch_cfg`
    field would have needed a function pointer in every session and two
    lines `cfg.h`, at its 500-line cap, does not have. The hook gets
    `cfg.io`, so one hook tells connections apart.

    The refusal covers a client in a raw or ca trust mode, which is what
    a pinned firmware image is, and admits `TRUST=webpki`, the server's
    `TRUST=none` and `ROLE=both`. The first draft admitted only webpki
    and `ROLE=both`; that would have refused colibri's own server, which
    builds `ROLE=server TRUST=none`. A firmware server can therefore carry
    the axis. The refusal is a guard against building it by accident, not
    a security boundary: anyone compiling these sources can pass the
    define.

    Four labels and no more: the two handshake and the two `_0`
    application secrets. The format has no label for a KeyUpdate's next
    generation, which a reader derives itself, and none of this build's
    handshakes has early data. `EXPORTER_SECRET` is left out because no
    reader in colibri's matrix asks for it.

    The first build logged 32 zero bytes as the client's random. The
    client wipes `h->random` when the key exchange finishes, before the
    handshake secrets it logs, and the secrets still matched across the
    two ends, so a test comparing secrets alone would have passed.
    `bin/rec_loop_test` compares the random too, and INV-29 records the
    rule with a mutant that restores the bug.

45. **A `SUITE=aesgcm TRUST=webpki` client offers both cipher suites and
    the server picks one.** This is the mode's fourth exception to the
    rule that the client offers exactly one of everything, after the
    signature schemes (entry 36), the application protocols (37) and the
    key exchange groups (39), and it has their cause: a host-side client
    cannot know which suites the endpoint it dialled accepts, and RFC 9846
    §9.1 makes `TLS_AES_128_GCM_SHA256` the one a conformant server must
    implement. The ClientHello lists `TLS_CHACHA20_POLY1305_SHA256` first
    and `TLS_AES_128_GCM_SHA256` after it, the order `srv_select` prefers
    for the reason it states: ChaCha20 is constant time by construction,
    and AES is constant time because the build asserted it
    (`CH_NATIVE_AES`). The client keys every record direction with the
    suite the ServerHello selected, a ServerHello after a retry must repeat
    the retry's suite, and `ch_tls.suite` reports the one that ran.

    Cost: a negotiation surface, the AES sources in the object, and the
    build's statement about its hardware. `ct.h` refuses the suite without
    `AES=hw` and `CH_NATIVE_AES`, so the offer exists only on a host whose
    AES instructions the builder vouches for, and `quic_packet.c` refuses
    it over QUIC, where packet protection runs ChaCha20 alone. Gain: the
    client completes a handshake with a server that accepts AES-128-GCM
    alone, which the e2e suite checks against OpenSSL.

    A raw or ca client refuses `SUITE=aesgcm`, the way it refuses
    `KEYLOG=on` (entry 44). It pins the endpoint it talks to, so it knows
    that endpoint's suite, and it offers ChaCha20 alone; the Makefile and
    `handshake_message.c` stop the define there. A build with a server
    role takes it whatever its trust mode, because its server selects AES
    from a client that offers nothing else, and the client beside it in a
    raw or ca `ROLE=both` build still offers ChaCha20 alone.

    Offering AES-128-GCM alone under `SUITE=aesgcm` was considered and
    rejected: the build would then fail against every server that accepts
    ChaCha20 and not AES, and the reason to offer AES is to reach more
    servers, not different ones.

46. **A record-mode `ch_read` returns `CH_RECORD_AGAIN` when no record has
    arrived, and the session stays connected.** Entry 21 makes every
    operational error fatal, and an empty `recv` in `TRANSPORT=record` is
    not an error. The caller owns the socket and hands over whole records
    as they arrive, so between records it has nothing to hand over. Before
    this result existed, `ch_read` turned that empty `recv` into `CH_EIO`.
    A caller that received a record with no application data, such as a
    NewSessionTicket, had to hold it back until a data record arrived, or
    lose the session. `TRANSPORT=tls` does not change: its `recv` blocks,
    and a 0 there is the end of the stream.

    Cost: a second live result from `ch_read`, and one field that lives
    across calls, `ch_tls.post_fill`, which counts the bytes of a
    post-handshake message split across records. INV-13 states the terms.
    Gain: the caller passes each record to `ch_read` as it arrives and
    keeps no queue of its own.

    `CH_QUIET_CAP` still bounds the records one `ch_read` call handles
    without application data. A peer that sends such records without end
    now costs the caller one call per record, so the loop that repeats is
    the caller's, and `ch_read` does not spin.

    Treating a 0 inside a record as `CH_RECORD_AGAIN` too was considered
    and rejected. The partial header would have to be kept across calls,
    and `rec.h` already asks the caller for whole records.

47. **A `TRUST=webpki` client resumes a ticket bound to the hostname and
    anchors that received it.** A resumed handshake checks no certificate,
    so entry 36 refused resumption in this mode. RFC 8310 §9 makes
    resumption a MUST for a DNS-over-TLS client, and RFC 9846 §4.7.1 lets a
    client resume only under a `server_name` valid for the original
    certificate. Each ticket now carries a binding: HMAC-SHA256 keyed by
    its PSK over a hash of the lowercased hostname and the anchor array.
    `ch_connect` recomputes it and refuses a mismatch with `CH_EINVAL`
    before it sends a byte. docs/webpki.md, "Resumption", states the rules.

    Cost: 32 bytes in `ch_ticket`, 40 in `ch_tls` as `bench/sram.sh`
    measures it (a 32-byte field and its alignment), one field in `ch_cfg`,
    and a second path through the handshake for this mode, the one the raw
    and ca modes already take after a ticket. Gain: a reconnect to a public
    endpoint skips the chain walk and its signature checks, and a ticket
    stored under the wrong name fails at configuration, not after a
    session with a server the caller did not name.

    Keying the binding by the PSK, not hashing the configuration alone,
    ties it to one ticket: a caller cannot pair one ticket's PSK with
    another's binding by mistake. Storing the hostname in the ticket and
    comparing it was considered and rejected: the caller supplies both
    sides of that comparison, so it checks nothing a storage mistake would
    break.

    Offering the certificate path beside the ticket, so a server that
    declines the ticket can still authenticate by chain, was considered and
    rejected for now. It would put `signature_algorithms` in the resumed
    hello and give the client two ways through one handshake, where every
    mode here has one per hello. The cost of failing closed is one
    reconnect after a declined ticket.

48. **A QUIC server's Retry token is an HMAC chapulin computes under a key
    the caller holds, bound to the client's address, with the caller's
    clock.** colibri runs the QUIC Interop Runner's `retry` case as a server
    over one `ROLE=both` object and holds no key, so `quic_token.[ch]` mints
    and checks the token. `docs/quic_server.md`, "The Retry token", states
    the format and what the caller still owns. Cost: two exported calls, so
    a `ROLE=server TRANSPORT=quic` object exports eighteen, and one
    HMAC-SHA-256 per mint and per check. Gain: a stateless server gets both
    connection IDs back for its transport parameters, and a key stays on
    chapulin's side of the line `docs/quic_server.md` draws.

    The token is authenticated and not encrypted. RFC 9000 §8.1.4 asks
    integrity of a Retry token and nothing more, and its fields are ones
    the path saw in the clear. Sealing it with the ChaCha20-Poly1305 the
    object already carries would need a fresh nonce per token, and a nonce
    needs randomness or a stored counter: the first breaks the seeded
    replay colibri needs, and the second breaks the statelessness a Retry
    exists for. The §8.1.4 alternative of a random value the server
    remembers breaks the same two things.

    The instant is the caller's, in seconds, because chapulin reads no
    clock and `ch_cfg.now_seconds` already counts seconds. The check tells
    the caller which RFC answer applies: `CH_EPROTO` for a token that is
    not a Retry token, which §8.1.3 treats as no token, and `CH_EAUTH` for
    a Retry token that fails, which §8.1.2 answers with INVALID_TOKEN. The
    first byte decides, because §8.1.1 requires the two kinds to be told
    apart. A check that accepted each token once was considered and left
    to the caller: it needs state, and the window and the address binding
    already limit replay as §8.1.4 requires.

49. **A `TRUST=webpki` client takes SPKI pins, and with them RFC 7250 raw
    public keys.** RFC 8310 §9 makes RFC 7250 a MUST for a DNS-over-TLS
    client and lets it offer raw keys only with an SPKI pin set, so the
    host-side mode that caller builds takes pins. Pins alone are a whole
    configuration, the "SPKI + IP" profile for a server with no public
    certificate. With anchors too, a chain must pass the walk, the clock
    and the hostname, and a pin must name a key on the path the walk
    verified, as RFC 8310 §6.4 and RFC 7858 §4.2 ask. docs/webpki.md, "Raw
    public keys and SPKI pins", states the rules.

    Cost: a fifth thing the mode offers more than one of, the certificate
    types, and a second way for a Certificate message to authenticate a
    server, which is why the device modes stay without it. Gain: the
    caller reaches a pinned server whether it presents a raw key or a
    chain, and a pin change is a configuration change, not a CA.

    A new trust mode for pins alone was considered and rejected: a
    configuration with both a name and pins needs the chain code anyway,
    and a second host-side mode would split the tickets, the ALPN offer
    and the tests between two objects. Matching a pin on the leaf alone
    was considered and rejected: RFC 7858 pins the validated chain, and an
    operator who pins an intermediate would be locked out on the next leaf
    rotation.

50. **`CH_NATIVE_AES` covers the carry-less multiply as well as the AES
    instructions.** Under `AES=hw`, GHASH multiplies on PMULL or
    PCLMULQDQ in `quic_ghash_hw.c`, because `quic_gcm.c`'s portable
    multiply was 98% of an `AES=hw` seal and the instruction runs GHASH 60
    to 65 times faster from 1200 bytes up (docs/quic.md, "What the AES
    axis costs in time, measured"). AES-GCM needs both instructions under one key: the AES
    rounds produce the keystream and the hash subkey, and the carry-less
    multiply multiplies by that subkey. So `CH_NATIVE_AES`, the build's
    statement that this part's AES instructions run in constant time, now
    also states that its carry-less multiply does. `ct.h` writes the
    terms, and a `SUITE=aesgcm` build still names one define. A build
    whose keys are the public QUIC Initial and Retry keys needs no
    statement, as before (INV-26).

    Cost: one define now asserts two things, so the vendor statement
    behind it has to cover both instructions. A part whose AES rounds are
    constant time and whose carry-less multiply is not cannot carry
    `SUITE=aesgcm` honestly, and nothing here detects that part. Gain:
    one statement per AEAD, written once in the build files by someone
    who can answer for the part. On Arm the two are one feature already:
    the Arm C Language Extensions put the 64-bit PMULL in the AES
    extension, and `__ARM_FEATURE_AES` names both.

    A second macro, `CH_NATIVE_CLMUL`, was considered and rejected. No
    build here runs one instruction without the other: `AES=hw` compiles
    `quic_aes_hw.c` and `quic_ghash_hw.c` together and every other `AES`
    value compiles neither. The second define would be required exactly
    when the first is, so it would add a line to every suite build and a
    refusal to `ct.h` without separating any build that exists.
    `CH_NATIVE_WIDEMUL` stays apart because it covers a different
    instruction in different files, and a build asserts it without any
    AES at all.

51. **A server issues one self-sealed ticket per connection and resumes
    it under `psk_dhe_ke`, on the caller's clock.** colibri needs the QUIC
    Interop Runner's `resumption` case in both roles, and Camilo answered
    `docs/server.md`'s open question five yes. After the client Finished
    verifies, the server seals the ticket's PSK, the suite, the ALPN
    protocol and an issue instant under a ChaCha20-Poly1305 key the caller
    supplies (`srv_ticket.[ch]`), and sends it in one NewSessionTicket with
    no `early_data`. A later ClientHello that carries it resumes with a
    fresh key exchange and no Certificate (`srv_resume.[ch]`).
    `docs/server.md`, "Resumption", states the rules.

    Cost: one caller-held key as valuable as the signing keys, one more
    `ch_rand_bytes` site (INV-4), one more AEAD caller (INV-1), a caller
    clock the server did not read before, and 104 bytes of ticket per
    connection. Gain: a reconnect skips the signature and the certificate
    on both ends, and two chapulin endpoints resume each other, which is
    the deployment the client was written for.

    One ticket, because a client that resumes one connection after another
    gets a fresh ticket on each; a client racing parallel connections
    wants more, and none asks. The instant is the last full handshake's,
    carried forward through every resumed one, so a chain of resumptions
    ends one lifetime after the certificate last signed. A server with no
    clock issues no ticket and accepts none. A ticket binds its ALPN
    protocol, because application state may follow a ticket across
    connections (RFC 9001 §4.5), and it does not bind the server name or
    the signing identity: RFC 9846 §4.3.11 tells a server it need not bind
    the name, and a deployment that retires an identity rotates the ticket
    key.

    A database of tickets was considered and rejected: it needs storage
    that outlives a connection, which the zero-heap rule forbids. An HMAC
    over a readable ticket, the cookie's shape, was rejected because the
    ticket carries the PSK, which must stay secret. Deriving a key per
    ticket from a random salt, so no nonce can repeat, was considered and
    left aside: a random 96-bit nonce is safe for 2^32 tickets under one
    key, and `srv_ticket.h` tells the operator to rotate before then.

52. **The X25519 field is a build axis, `X25519=portable` or
    `X25519=wide`, and the wide field asserts its own multiply.**
    `X25519=portable`, the default, is `x25519.c`'s 16 limbs of 16 bits:
    256 products of 32 by 32 bits per field multiply, which `ct.h` can
    build from 16x16 pieces on any core. `X25519=wide` adds
    `x25519_wide.c`, five limbs of 51 bits: 25 products of 64 by 64 bits
    into 128, which a 64-bit core computes as MUL and UMULH on arm64 and
    as one MUL or MULX on x86-64. On an
    Apple M1 Pro the wide field takes about 34 µs per scalar
    multiplication, against 428 µs for the 16-limb field on the native
    multiply and 953 µs on the 16x16 decomposition the packaged object
    ships. The x25519 pair was 74% of an RSA-3072 client handshake there,
    and the wide field takes that client side from 2.57 ms to 0.77 ms
    (bench/notes-primitives.md).

    It is an axis rather than a replacement because a device cannot run
    the wide field. A 32-bit core has no 64x64->128 multiply, so its
    compiler would build each product from a runtime routine that
    branches on its operands; `ct.h` refuses the build instead, when the
    compiler has no `unsigned __int128`. The 16-limb field stays the
    default and the device path, unchanged, with its ten proofs, INV-24
    and the 32-bit codegen specs. The axis follows the AES one: the
    Makefile variable picks, one field per object, and the compiler's
    predefined macros are the whole detection. Nothing probes a CPU at
    run time, for the reasons `quic_aes_hw.c` gives.

    The values name what each field needs from the target, because that
    is what the person choosing has to know. `portable` runs on every
    core this tree builds for; `wide` needs the wide multiply and a
    statement about its timing. "fast" would name a property of one
    machine, and "radix51" names the representation, which says nothing
    about which targets can build it.

    The wide field has its own timing assertion, `CH_NATIVE_MUL128`,
    rather than reading `CH_NATIVE_WIDEMUL`, for two reasons. The two
    macros name different instructions: `CH_NATIVE_WIDEMUL` is about the
    32x32->64 multiply, and a part can promise one and not the other.
    And the Makefile sets `CH_NATIVE_WIDEMUL` for every host test binary,
    so a field keyed on it would move every host test off the 16-limb
    field, which would lose its native-multiply unit, Wycheproof and
    differential runs. `ct.h` writes the terms: Arm's FEAT_DIT list and
    Intel's DOIT list both name the instructions, and each holds only in
    the mode its vendor names.

    Cost: two fields to keep correct instead of one. The wide field has
    seven harnesses of its own (INV-34), an equivalence binary that
    compares it with the 16-limb field on every `make check`, a
    Wycheproof leg, a unit leg, a timing leg and a differential leg.
    Its constant-time claim rests on a vendor statement this tree cannot
    check, and on the code the pinned clang emits for arm64 and x86-64,
    which `lint-wide-multiply` holds; no gcc spec measures it, because no
    CI lane runs a 64-bit gcc through that gate. Gain: host builds, which
    open many connections, stop paying for a representation chosen for a
    core with no wide multiply. The Lean model needs no second copy:
    `spec/lean/Spec/X25519.lean` computes over natural numbers with a
    reduction mod p after every operation, so it states no limb layout,
    and `bin/diff_x25519_wide` runs the x25519 rows against it with the
    wide field.

53. **A `TRUST=webpki` client sends a key share for both groups, and `KEX`
    selects nothing for it.** Every webpki build carries ML-KEM-768 and
    lists X25519MLKEM768 and then x25519, the offer entry 39 made under
    `KEX=pq`. Its ClientHello now carries a key share for each: the
    hybrid share, then an x25519 share. The x25519 share repeats the
    x25519 half of the hybrid share. RFC 9846 §4.3.8 asks for the
    key_exchange of each KeyShareEntry to be generated independently
    (rfc9846.txt:2182-2184), and RFC 9954 §3.2 relaxes that rule for a
    value of the same algorithm reused across the entries of one
    ClientHello. So the second share needs no second key generation. A
    server selects either group in one round trip. When it selects
    x25519, the client wipes the ML-KEM seed, `handshake_state.dz`,
    before it runs the exchange.

    Cost: 36 bytes in every webpki hello, the second KeyShareEntry's
    group, length and 32-byte value, so `CH_HELLO_MAX` goes from 2,335
    to 2,371 against the `KEX=pq TRUST=webpki` build. Against the
    classic webpki build, which this entry removes, the hello grows by
    1,222 bytes, `ch_tls` from 1,800 to 3,016 bytes on arm64, and the
    `ch_connect` stack peak from 7,152 to 16,416 bytes, because every
    webpki object now carries ML-KEM (`bench/results-sram.csv`). A host
    pays those bytes easily, and the device modes do not pay them.

    Gain: no round trip to a server without the hybrid, and no key
    exchange choice for a host client to get wrong. `make TRUST=webpki
    KEX=x25519` built a client that could never run the hybrid, and
    `make TRUST=webpki KEX=pq` one that paid a HelloRetryRequest round
    trip to every classic server. Neither build exists now; the one
    webpki build completes with either server in one round trip.

    The change also deletes code. Both groups carry a share, so a
    HelloRetryRequest that names either one names a group the hello
    already shared, and RFC 9846 §4.3.8 makes that an illegal_parameter
    abort (rfc9846.txt:2205-2212). A retry can ask this client for a
    cookie and nothing else. `server_hello_info.retry_group`,
    `handshake_state.share_group`, `take_retry` and the x25519-only retry
    hello are gone, with the mutants that guarded them, and the retry
    hello's record version depends on the cookie alone again. A cookie
    retry still works: the retry hello resends both shares and echoes
    the cookie.

    `ch_cfg.require_pq` keeps its meaning. It drops x25519 from
    `supported_groups` and from `key_share`, so the hello is the
    one-group hybrid hello a raw or ca `KEX=pq` build sends, and a
    ServerHello that selects x25519 fails with illegal_parameter.

    `KEX` now chooses the group of a raw or ca device client and nothing
    else, and the Makefile refuses both values everywhere else, for
    entry 40's reason: a variable must not let a build ask for something
    it will not get. Beside `TRUST=webpki`, `KEX=x25519` asks for an
    x25519-only hello, and `KEX=pq` asks for the one-group hybrid hello,
    which `require_pq` gives at run time. A server role's key exchange is
    not a build choice either: the server offers x25519 until its hybrid
    half lands, and then carries ML-KEM in every build, so `ROLE=server`
    and `ROLE=both` refuse `KEX` too. `$(origin KEX)` tells the default
    from a value on the command line or in the environment. The object
    directory names a webpki build's key exchange `both`. `cfg.h`
    refuses `-DCH_KEX_PQ` beside `-DCH_TRUST_WEBPKI` for a client-only
    tree with its own build system.

    A `ROLE=both` webpki object, the one colibri links, carries the
    two-group client beside a server that still offers x25519 alone. The
    client's defines, `CH_KEX_TWO_GROUPS` and `CH_KEX_HYBRID`, come from
    `CH_TRUST_WEBPKI` and not from `CH_KEX_PQ`, so the server half keeps
    `CH_KEX_GROUP` at x25519 and never meets `srv_flight.h`'s refusal of
    `CH_KEX_PQ`. The server's hybrid half, when it lands, replaces that
    refusal and those x25519 constants. Entry 54 landed it: the refusal
    and the server's use of `CH_KEX_GROUP` are gone, and that object's
    server selects the hybrid its client offers.

    Entry 39 rejected carrying both shares for three costs: 1,216
    octets of ML-KEM share in every hello, a key pair most handshakes
    discard, and a larger `CH_HELLO_MAX`. The build that entry made
    already paid the first two: its hello carries the hybrid share, and
    so draws the ML-KEM key pair, whether or not the server takes it.
    What both shares add is the 36-byte x25519 entry, and that entry's
    key pair is the x25519 half the hybrid share already carries.

    A second, independent x25519 key pair for the x25519 share was
    considered and rejected. RFC 9954 permits the reuse, the server
    selects one group so only one share enters a key exchange, and the
    second pair would cost one more scalar multiplication per handshake.

54. **A server holds both groups and prefers X25519MLKEM768, and asks for
    it with a HelloRetryRequest when the client did not share it.** Camilo
    answered `docs/server.md`'s open question ten on 2026-09-24: every
    server build, `ROLE=server` and `ROLE=both` over all three transports,
    carries ML-KEM-768 and selects the hybrid for any client that lists
    it. `srv_kex.[ch]` holds the choice, the server's key share and the
    shared secret, and `ch_tls.group` reports the group on the server as
    it does on the client.

    The order is the server's, and it reads `supported_groups`:
    X25519MLKEM768 when the client lists it, and x25519 otherwise. A hello
    that carries the hybrid share gets the hybrid in one round trip, even
    when an x25519 share comes beside it. A hello that lists the hybrid
    and shares x25519 alone gets a HelloRetryRequest that names the
    hybrid, through the cookie the retry path already had, and its second
    hello must carry that share. A hello that lists x25519 alone gets
    x25519. RFC 9846 §4.3.8 describes this shape for a server that
    respects preferences: select from `supported_groups` first, then send
    a ServerHello or a HelloRetryRequest from what `key_share` carries
    (rfc9846.txt:2172-2177). Here the preference is the server's own.

    The trade is one round trip, paid only by a client that lists the
    hybrid and shares x25519 alone. Taking that x25519 share would save
    the round trip and complete a classic key exchange with a client that
    offered post-quantum protection, which is the recording entry 12
    names: harvested now and decrypted later. OpenSSL with x25519 first in
    its group list pays the round trip. A `TRUST=webpki` client, a
    `KEX=pq` client and OpenSSL's default list share the hybrid and pay
    nothing.

    The hybrid follows RFC 10024. The server encapsulates to the ML-KEM
    encapsulation key at the front of the client's share and answers with
    the ciphertext and then its x25519 value, and the shared secret is
    the ML-KEM secret and then the x25519 one, the order
    `handshake_flight.c`'s `hybrid_secret` already reads. An encapsulation
    key that fails FIPS 203 §7.2's modulus check, and a share of any
    length but 1,216 bytes, end the handshake with illegal_parameter, as
    RFC 10024 asks; the x25519 half keeps the all-zero check (INV-3). The
    32 bytes of encapsulation randomness are a new `ch_rand_bytes` site,
    drawn only when the server selects the hybrid (INV-4), and the ML-KEM
    secret lives in `handshake_state.mlkem_ss` from the ServerHello to the
    key schedule and no longer (INV-17).

    Cost: every server object carries ML-KEM-768 and SHA-3. The server's
    `ch_tls` grows from 1,368 to 1,968 bytes on arm64, because the
    ServerHello it stages in the TX array carries a 1,120-byte share, and
    `ch_srv_accept`'s stack peak goes from 5,248 to 10,304 bytes through
    the encapsulation (`bench/results-sram.csv`), which puts every server
    build on the hybrid's 6,656-byte frame budget (INV-19). There is no
    classic-only server: a device that cannot spare the stack cannot
    build one. Gain: every client that can run the hybrid gets it from a
    chapulin server, colibri's QUIC server included, with no build choice
    to get wrong.

    Three alternatives were considered and rejected. Selecting whichever
    group the client shared saves the round trip and gives a classic key
    exchange to exactly the clients that shared x25519 first. A `KEX`
    axis for servers would be a build choice a server does not need, and
    entry 53 already refuses `KEX` beside a server role. Drawing the
    encapsulation randomness in `srv_begin` beside the x25519 scalar would
    draw 32 bytes a classic handshake never uses and keep them in the
    handshake state until the ServerHello.
