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
7. **x25519 in 16-bit limbs (the TweetNaCl scheme).** Cost: a scalar
   multiplication takes about 78 ms on the mips32r2 reference target, or
   57 ms in a build that asserts `CH_NATIVE_WIDEMUL`
   (`bench/results-insn.csv`), and wider limbs would be faster. Gain: a
   machine-checked overflow lemma and citable prior formal work on the
   same scheme. Provability over speed; revisit if the workload becomes
   many short connections. Entry 52 adds wider limbs for 64-bit hosts as
   `X25519=wide`, and the 16-bit field stays the default.
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
    Entry 63 adds secp256r1 to the webpki offer, listed last with no
    share, and to every server, taken last.

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
    collide with internals. The four are the calls of the first build.
    Each axis now sets its own list of calls (entries 38, 41 and 43),
    and entry 56 adds one data symbol, `ch_build`, to every object.
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
    packets itself. A `TRANSPORT=quic-nonblocking` build takes handshake bytes in,
    hands handshake bytes out, and seals and opens every packet at every
    level, so no traffic secret leaves the object. colibri, the HTTP/3
    caller, owns everything that is not cryptography: packet numbers,
    ACKs, loss recovery, congestion control, flow control, streams,
    connection IDs, Retry and version negotiation logic, and path
    validation. Cost, and most of it lands here: a fifth value in
    `LIB_VARIANT` beside PIN, TRUST, KEX and RAND; fifteen exported
    transport calls against entry 28's four, on a `PUBLIC` whose
    first term the axis selects —
    `$(PUBLIC_TRANSPORT) $(PUBLIC_RAND) $(PUBLIC_CA)`, where
    `PUBLIC_TRANSPORT` drops the four TLS names rather than adding to
    them and the other two terms keep their meaning, so a CA-mode or
    RAND=drbg QUIC object exports sixteen calls and one with both exports
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
    changes `handshake.o` in every tcp-blocking build. `handshake_psk` and
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
    exports seven calls where the halves export five and six. It is also
    smaller than what it replaces: 132,960 bytes against 183,980 for the
    two tcp-blocking objects, and 148,520 against 213,804 for the two QUIC ones.
    `TRUST=none` is refused here, because the client half judges a peer.

42. **A tcp-nonblocking server pushes its flight; only the client pulls.**
    `TRANSPORT=tcp-nonblocking` exists because a blocking callback cannot sit
    under a completion-based event loop: colibri drives rotor, whose loop
    is single-threaded with no fibers, so a `cfg.recv` that waits stalls
    every connection the loop holds. `ch_srv_accept` blocks by contract
    (`cfg.h:371`), which is why `ROLE=server TRANSPORT=tcp-nonblocking` was
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

    `EXPORTER=on` with `TRANSPORT=quic-nonblocking` is refused by name, in the Makefile
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
    AES instructions the builder vouches for, and `quic_packet.c` refused
    it over QUIC, where packet protection ran ChaCha20 alone, until entry
    58. Gain: the client completes a handshake with a server that accepts
    AES-128-GCM alone, which the e2e suite checks against OpenSSL.

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

46. **A tcp-nonblocking `ch_read` returns `CH_RECORD_AGAIN` when no record has
    arrived, and the session stays connected.** Entry 21 makes every
    operational error fatal, and an empty `recv` in `TRANSPORT=tcp-nonblocking` is
    not an error. The caller owns the socket and hands over whole records
    as they arrive, so between records it has nothing to hand over. Before
    this result existed, `ch_read` turned that empty `recv` into `CH_EIO`.
    A caller that received a record with no application data, such as a
    NewSessionTicket, had to hold it back until a data record arrived, or
    lose the session. `TRANSPORT=tcp-blocking` does not change: its `recv` blocks,
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
    reconnect after a declined ticket. Entry 55 reversed this: dns.google
    resumes no hello that lacks `signature_algorithms`, and declines about
    one ticket in three.

48. **A QUIC server's Retry token is an HMAC chapulin computes under a key
    the caller holds, bound to the client's address, with the caller's
    clock.** colibri runs the QUIC Interop Runner's `retry` case as a server
    over one `ROLE=both` object and holds no key, so `quic_token.[ch]` mints
    and checks the token. `docs/quic_server.md`, "The Retry token", states
    the format and what the caller still owns. Cost: two exported calls, so
    a `ROLE=server TRANSPORT=quic-nonblocking` object exports eighteen calls, and one
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
    public keys and SPKI pins", states the rules. Entry 65 widens pins
    alone to a certificate chain whose leaf key a pin names.

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
    the cookie. Entry 63 lists secp256r1 after the two shared groups with
    no share, so a retry may name that group again, and the retry hello's
    record version depends on its position rather than on the cookie.

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

    Entry 63 adds secp256r1 as a third group, taken after x25519, only
    from a client that lists neither of the other two; the order above
    stands for them.

55. **A `TRUST=webpki` client offers the certificate path beside a ticket,
    and a declined ticket becomes a full handshake in the same
    connection.** cocuyo, a DNS-over-TLS client that links the webpki
    tcp-nonblocking object, measured dns.google (8.8.8.8:853) on 2026-09-24. With
    the hello entry 47 wrote, which offered the ticket and no signature
    scheme, it resumed 0 of 10 connections: dns.google answered every
    resuming hello with a handshake_failure alert, a good ticket included.
    It appears to choose its certificate and signature scheme before it
    decides whether to resume, so a hello with no scheme fails there. RFC
    9846 §4.3.3 names missing_extension for that case
    (rfc9846.txt:1813-1816). With signature_algorithms added beside the
    ticket and no fallback, cocuyo resumed 5 of 6; the sixth was an
    ordinary decline, and the client failed it closed with `CH_EAUTH`.
    OpenSSL 3.6.4's s_client resumed 6 of 9 and completed the other 3 as
    full handshakes in the same connection. cloudflare-dns.com and
    dns.quad9.net resumed with either hello.

    So the change has two halves, and each one is in the RFC. RFC 9846
    §4.3.3 requires signature_algorithms of a client that wants a server
    to authenticate with a certificate (rfc9846.txt:1811-1813), and §9.2
    lets a hello leave it out only when the hello offers a PSK
    (rfc9846.txt:4595-4597). §2.2 asks a client that offers a PSK to send
    a key share "to allow the server to decline resumption and fall back
    to a full handshake" (rfc9846.txt:699-702), and this client always
    sends one.

    - **The hello.** Every webpki ClientHello carries signature_algorithms
      with the five schemes, and server_certificate_type when SPKI pins
      are set, whether or not it presents a ticket. pre_shared_key stays
      the last extension, because the binder covers every byte before the
      binders list (rfc9846.txt:2564-2565). A retry hello after a
      HelloRetryRequest carries the same extensions and a binder computed
      again over the transcript the retry replaced.
    - **A selected ticket.** The handshake resumes as before: no
      Certificate, and `ch_tls.psk_selected` is 1.
    - **A declined ticket.** A ServerHello with no pre_shared_key makes
      `hsf_accept_server_hello` wipe the PSK's early secret and binder key
      and derive the early secret of no PSK, HKDF-Extract over 32 zero
      bytes (rfc9846.txt:4182-4185). The handshake then reads
      EncryptedExtensions, Certificate, CertificateVerify and Finished, and
      checks the chain, the clock, the hostname, the anchors and any SPKI
      pins exactly as a handshake with no ticket does. `ch_tls.psk_selected`
      is 0. A pre_shared_key that names any identity but 0 is no decline,
      and fails with illegal_parameter (rfc9846.txt:2551-2557).

    The three drivers decide whether a Certificate comes next from
    `ch_tls.psk_selected`, which `hsf_accept_server_hello` writes, and no
    longer from `cfg.psk`. In the raw and ca modes the two agree on every
    path, because those modes still fail a decline.

    Cost: 16 bytes in every resuming webpki hello, 23 with SPKI pins
    beside anchors. `CH_HELLO_MAX` and `CH_TX_STAGE` grow by 23 bytes in
    the webpki builds, from 2,371 to 2,394 over TCP and from 2,625 to 2,648
    over QUIC, and `ch_tls` grows from 3,016 to 3,040 bytes on arm64
    (`bench/results-sram.csv`). A webpki hello now offers two ways for a
    server to authenticate, the sixth thing the mode offers more than one
    of, and one handshake has two paths through it. The device modes pay
    nothing.

    Gain: cocuyo resumes with dns.google, and a server that declines a
    ticket costs one handshake instead of a failed connection and a
    reconnect. That matches what OpenSSL does and what §2.2 describes.

    The raw and ca modes stay as they were: their resuming hello offers
    the ticket alone, and a decline fails with handshake_failure
    (`CH_EAUTH`). Their server is the one endpoint a device pins, usually a
    chapulin server that holds its own ticket key, so a decline is rare
    and costs one reconnect. Offering the pinned scheme beside the ticket
    would put a second path through the device driver for a case nothing
    measured asks for, and in the ca modes a declined ticket would also
    have to run the epoch check that a resumed handshake skips (INV-21).

    Two alternatives were considered and rejected. Adding the schemes and
    failing a decline closed, the build cocuyo measured, resumes with
    dns.google and still turns about one connection in three into a
    reconnect. Reconnecting inside `ch_connect` without the ticket needs a
    second connection, and the caller owns the socket.

56. **Every packaged object exports a build record, `ch_build`, and a
    consumer compares it with its own headers.** A consumer links
    `bin/chapulin.o` and compiles against the headers under defines it
    writes itself. cocuyo reads them through Zig's `@cImport` under
    `CH_TRUST_WEBPKI`, `CH_TRANSPORT_TCP_NONBLOCKING` and `CH_RAND_EXTERN`, and
    colibri and stompy write their own lists. Nothing checked that those
    defines were the object's, and a mismatch links and runs. A consumer
    that forgets `CH_TRUST_WEBPKI` beside a webpki tcp-nonblocking object
    passes a 152-byte `ch_cfg` to a call that reads 232 bytes, and
    declares a 1,624-byte `ch_record` that the object writes 4,120 bytes
    of (arm64). So `build.c` defines one const `ch_build_info` in every
    object: the record format, one bit per define that changes a public
    layout or bound, the sizes of `ch_cfg`, `ch_tls`, `ch_ticket`,
    `ch_record`, `ch_quic` and `ch_rsa_priv`, and four bounds:
    `CH_TX_STAGE`, `CH_MIN_RXBUF`, `CH_X509_MAX` in a CA mode and
    `CH_TRANSPORT_PARAMS_MAX` in a QUIC build. `build.h` computes the same
    values from the consumer's defines as `CH_BUILD_` macros, and
    `ch_build_matches(&ch_build)` compares them all.

    The axes are the ten defines that change a size or a bound the
    record holds, or, for `CH_PIN_ECDSA` in a raw mode, the length a
    pinned key has: `CH_TRUST_CA`, `CH_TRUST_WEBPKI`, `CH_PIN_ECDSA`,
    `CH_KEX_PQ`, `CH_TRANSPORT_QUIC_NONBLOCKING`, `CH_TRANSPORT_TCP_NONBLOCKING`,
    `CH_SUITE_AES_GCM`, `CH_ROLE_SERVER`, `CH_EXPORTER` and `CH_KEYLOG`.
    `build.h` says what each one changes. Left out, each measured with and
    without the define under all three transports:

    - The RAND pattern. `rand.h` and `drbg.h` declare the same calls in
      every build, so no header changes. A mismatch still reports itself.
      An extern-pattern program that links a drbg object never has its
      `ch_rand_bytes` called, and the object's generator stops at
      `CH_ASSERT` on its first draw, unseeded, before a handshake sends a
      byte. A drbg-pattern program that links an extern object fails to
      link.
    - `CH_ROLE_BOTH`. A `ROLE=both` object has the layouts and bounds of
      the `ROLE=server` object with the same trust defines. The define
      declares `ch_connect`, and a program that calls it against a server
      object fails to link.
    - The AES implementation, `X25519=wide` and `WIDEMUL`. They change
      code and no size or bound. `AES=extern` imports `ch_aes_block`, and
      a program that does not define it fails to link.
    - `CH_NATIVE_AES` and `CH_NATIVE_MUL128`, statements about the part
      that `ct.h` reads to refuse a build.
    - `CH_KEX_TWO_GROUPS` and `CH_KEX_HYBRID`. `cfg.h` computes both from
      `CH_TRUST_WEBPKI` and `CH_KEX_PQ`, so their bits would repeat
      those two.

    The record is data, and not a check inside `ch_connect` and the init
    calls, for three reasons:

    - No exported name changes and no call gains a parameter or a result
      code, so every consumer links as it did.
    - A consumer in another language reads it. The struct is twelve
      `uint32_t` fields with no padding, and the expected values are
      object-like macros, which Zig's translate-c turns into constants.
      A Zig 0.16 program that `@cImport`s `build.h` under cocuyo's three
      defines reads `c.ch_build`, calls `c.ch_build_matches`, and gets 1
      against the webpki tcp-nonblocking object and 0 with `CH_TRANSPORT_TCP_NONBLOCKING`
      left out.
    - A consumer is asked, not forced. No library source reads
      `ch_build`, so a firmware tree that compiles the sources into its
      own build, and so cannot disagree with itself, carries 48 bytes of
      read-only data and runs nothing.

    Cost: one more exported symbol in every object, and the first that is
    data rather than a call, so every export list names it and every
    count of exported symbols grows by one, while the counts of calls
    stay as they were. 48 bytes of read-only data per object. A consumer
    that never compares gets nothing from it. `lib-check` builds a
    consumer twice for every object it checks, about 0.2 s a leg, and
    `make check` gained one leg, `TRUST=raw-ecdsa KEX=pq`, 2.6 s cold and
    1.0 s warm, so the record is read in a `KEX=pq` object.

    Gain: a disagreement between an object and a consumer's defines is
    one comparison at startup instead of a struct written past its end.

    Two alternatives were considered and rejected. A check inside each
    init call, against a size the caller passes, changes every call's
    signature or wraps each one in a macro that a Zig consumer cannot
    use, and a size alone misses a bound such as `CH_X509_MAX`. A symbol
    name per build, so a mismatch fails to link, would encode every axis
    and every overridable bound in the name and change every consumer's
    link line with each axis. The record compares layouts and bounds,
    not behavior, and defines, not revisions: headers from another
    commit are caught only where a size, a bound or a bit moved (INV-35).

    Entry 61 changed one thing here: the record's symbol name now
    carries the object's transport, and `build.h` maps `ch_build` to it,
    because two objects that both defined `ch_build` did not link into
    one image.

57. **A failed QUIC session keeps its write keys for one CONNECTION_CLOSE
    per level, and a call of its own seals it.** RFC 9001 §4.8 turns a TLS
    alert into a CONNECTION_CLOSE frame whose error code is 0x0100 plus the
    alert (rfc9001.txt:883-887). Until this entry a failure wiped every key
    at once, as entry 21 has every error do, so colibri could seal no close
    and the peer waited out its idle timeout. h3spec's TLS cases, a
    KeyUpdate at the Handshake level, no_application_protocol and
    missing_extension, check for that close
    ([colibri#59](https://github.com/c4milo/colibri/issues/59)).

    - **What a failure keeps.** `quic_fail` wipes every read key, `hs` and
      the traffic secrets, and clears every read bit of
      `ch_quic.levels_ready`, as before. It keeps the write keys of each
      level whose write bit is set: `initial_dcid` at the Initial level,
      which the seal derives the Initial send key from, `handshake_tx` and
      `handshake_hp_tx`, and `app_tx` and `app_hp_tx`. Both drivers fail
      through it, so the rule is the same for the client and the server.
    - **What the caller does.** It reads `ch_quic_error_code` and calls
      `ch_quic_seal_close` once at each level it can send, with one
      CONNECTION_CLOSE frame as the plaintext. The call seals the packet as
      `ch_quic_seal` does, then wipes that level's write keys and clears its
      write bit, so a second call there returns `CH_EINVAL`. `ch_quic_close`
      wipes whatever keys remain. docs/quic.md, "When a session fails",
      lists the steps.
    - **Its own call, not `ch_quic_seal`.** `ch_quic_seal` keeps its rule
      that a dead session seals nothing. So the caller's ordinary send path
      cannot seal a queued ACK or STREAM frame in place of a level's one
      close, and a reader of a call site knows which of the two it is.
    - **A bound on the packet.** `CH_QUIC_CLOSE_MAX` is 1200 bytes, header
      and tag included: RFC 9000 §14's smallest maximum datagram size
      (rfc9000.txt:4598-4599). A close needs a few dozen bytes, so the
      bound refuses nothing a close needs. chapulin checks no frame
      content, because that means parsing QUIC frames, which colibri owns;
      the bound caps what a caller that passes other bytes can send under
      a kept key at one such packet per level.

    Initial keys are public: RFC 9001 §5.2 derives them from a printed salt
    and a connection ID that travels in the clear. Handshake and 1-RTT keys
    are secret, and this entry lets a secret write key outlive the failure,
    until its one seal or until `ch_quic_close`. Three facts make that
    acceptable. RFC 9000 §10.2.3 asks for the close at the Handshake level,
    and at the Initial level from a server, before the handshake is
    confirmed, because the peer may not yet read a higher level
    (rfc9000.txt:3306-3308, rfc9000.txt:3316-3320); the kept key is what
    that packet needs. The key protects only the one packet the caller
    builds, and the read keys, which would open the peer's packets, die
    with the failure. And the key is wiped right after that packet, so it
    lives as long as the caller takes to build one packet. When the failure
    is the peer's authentication, the Handshake key is shared with a peer
    this endpoint did not authenticate, and the close tells that peer the
    error code and nothing else.

    Cost: one exported call, so a `TRANSPORT=quic-nonblocking` client object exports
    sixteen calls and a `ROLE=server TRANSPORT=quic-nonblocking` object nineteen. INV-17
    gains an exception, stated there. A caller that neither seals nor
    closes keeps a failed session's secret write keys for the life of the
    session struct. Gain: the peer learns why the connection ended, at each
    level it can read, and stops waiting on its idle timeout.

    Three alternatives were considered and rejected. Letting `ch_quic_seal`
    run once per level on a failed session changes the meaning of every
    existing call site, and a queued packet could take the close's place. Keeping
    every key and letting the caller seal any number of packets leaves
    nothing bounding what a failed session encrypts under a secret key.
    Building the frame inside chapulin would put a QUIC frame encoder on
    chapulin's side of the line entry 38 draws.

58. **A `SUITE=aesgcm` build holds `TLS_AES_128_GCM_SHA256` and
    `TLS_AES_256_GCM_SHA384` beside ChaCha20, over every transport, on the
    AES instructions alone.** Entry 45 gave the build one AES suite, and
    refused it over QUIC. colibri serves QUIC clients it does not control,
    and such a client may offer AES-GCM alone: h3spec's ClientHello lists
    `TLS_AES_256_GCM_SHA384`, `TLS_AES_128_GCM_SHA256` and
    `TLS_AES_128_CCM_SHA256`, and no ChaCha20. RFC 9846 §9.1 makes the
    AES-128 suite a MUST and the AES-256 one a SHOULD
    (`rfc9846.txt:4540-4543`).

    - **AES-256 runs on the instructions, never on the S-box.**
      `aes_traffic_key_init` expands a 16-byte or a 32-byte key, and
      `aes_encrypt_schedule` runs ten or fourteen rounds by the round count
      the schedule records. A traffic key is secret, so `ct.h`'s refusal
      of `-DCH_SUITE_AES_GCM` without `AES=hw` and `CH_NATIVE_AES` covers
      both key sizes. `quic_aes_soft.c` holds a software AES-256 that only
      `-DCH_AES_256_TEST` compiles: it is the reference
      `bin/aes_equiv_test` and the `quic_aes256` proof hold the
      instructions to, and `lint-trust-separation` refuses that define in
      every packaged object.
    - **The key schedule takes the hash length first.** `hmac`,
      `hkdf_extract`, `hkdf_expand`, `hkdf_expand_label`,
      `hkdf_derive_secret` and every `ks_` call take a leading
      `size_t hash_len`: `SHA256_LEN`, or `SHA384_LEN` in a
      `-DCH_SUITE_AES_GCM` build. HMAC-SHA-384 is a body of its own behind
      a two-arm dispatcher, the shape `docs/server.md` measured, because
      one body over both hashes exceeds the complexity limit. Every secret
      array is `HKDF_HASH_MAX` wide, which is `SHA256_LEN` in every build
      without the suite, so those builds keep their sizes.
    - **The transcript runs both hashes in a suite build.** A client hashes
      its ClientHello before the ServerHello names a suite, so
      `ch_transcript` feeds SHA-256 and SHA-384 the same bytes, and each
      read names its hash by length. A HelloRetryRequest writes the
      synthetic message at the retry suite's hash. The client derives the
      early secret of no PSK when the ServerHello arrives, at the suite's
      hash.
    - **A PSK carries its hash in its length.** A ticket's PSK is as long
      as its suite's hash (`rfc9846.txt:3298-3301`), so `ch_ticket` gains
      `psk_len`, a client presents it as `ch_cfg.psk_len`, and the binder
      and the early secret take the hash that length names. A client
      aborts with illegal_parameter when the server selects the PSK under
      a suite of another hash (`rfc9846.txt:2551-2556`). A server passes a
      ticket over unless its suite has the selected suite's hash
      (`rfc9846.txt:3219-3220`), and the handshake goes on with a
      certificate.
    - **The record layer gains AES-256.** `rec_dir` records its suite, the
      key and IV derive at the suite's hash, and a KeyUpdate runs "traffic
      upd" at that hash and keeps the suite.
    - **QUIC protects Handshake and 1-RTT packets with the suite.** Each
      `quic_keys` and `quic_hp_key` records its suite, packet protection
      runs AES-GCM or ChaCha20-Poly1305 by it (RFC 9001 §5.3), and header
      protection runs AES-ECB or ChaCha20 by it, at the suite's key length
      (§5.4.3, §5.4.4). The Initial level keeps AES-128-GCM under its
      public keys, unchanged. `quic_packet.c` builds an `aes_traffic_key`
      on its frame for each packet and each mask and wipes it there. Each
      AES-GCM key set counts what it seals and refuses the packet that
      would reach §6.6's confidentiality limit of 2^23
      (`rfc9001.txt:1812-1813`). The count lives in the key set, so a key
      update starts it again and `ch_quic` gains no field; initiating that
      update before the limit is colibri's (`rfc9001.txt:1803-1805`). The
      integrity limit stays ChaCha20's 2^36, which is stricter than
      AES-GCM's 2^52 (`rfc9001.txt:1829-1831`).
    - **The order.** The server selects ChaCha20, then AES-128-GCM, then
      AES-256-GCM, the first of them the client listed, and the webpki
      client offers them in that order. ChaCha20 comes first for entry
      45's reason. AES-128-GCM comes before AES-256-GCM because its
      schedule is SHA-256, the hash every handshake proof covers; the
      SHA-384 schedule is proved in its own harnesses alone. So h3spec's
      offer selects AES-128-GCM, which `bin/webpki_loop_aes` feeds the
      server through the real parser. `ch_srv_cfg.cipher_suites` replaces
      the order: a host whose AES instructions outrun its ChaCha20, or one
      that wants AES-256's margin, names the order it wants, and a list
      may leave a suite out. Every server init refuses a code point the
      build does not hold.
    - **The key log takes the secret's length.** `ch_keylog` gains
      `secret_len`, because a SHA-384 secret is 48 bytes and the NSS
      format writes all of them.

    Cost, measured by `bench/sram.sh` on arm64: `ch_tls` grows from
    1,984 to 2,256 bytes in a `ROLE=server SUITE=aesgcm` build and from 3,064
    to 3,336 in a `TRUST=webpki SUITE=aesgcm` one, against the same probes
    run on the tree before this change. `ch_quic` in the `ROLE=both
    TRUST=webpki` QUIC object colibri links is 5,432 bytes with the suite and
    4,944 without it. The suite build's `ch_srv_accept` peaks at 10,448 bytes
    of stack where it peaked at 10,304, and its webpki `ch_connect` at 16,544
    where it peaked at 16,432. `ch_read` peaks at 1,728 bytes where it peaked
    at 1,696, in every build, on the KeyUpdate path through the hash-agile
    HKDF. Every other build keeps its session size. A suite build
    hashes every handshake byte twice. `ch_ticket` gains 8 bytes, for
    `psk_len`, in every build, and the key log hook changes signature in
    every `KEYLOG=on` build, colibri's included. A server ticket in a suite
    build is 120 bytes where it was 104, because its body holds a 48-byte
    PSK. Gain: the server meets §9.1 for AES-only clients over every
    transport, and a webpki client reaches an AES-only endpoint.

    No publication prints a QUIC packet protected under an AES-256-GCM
    key or a SHA-384 schedule: RFC 9001 Appendix A protects its Initial
    packets with AES-128-GCM and its 1-RTT packet with ChaCha20.
    `test/quic_suite_test.c` holds both AES suites to an independent
    Python computation instead, one that reproduces Appendix A.5 from its
    printed secret first.

    `TLS_AES_128_CCM_SHA256` stays out: no client this tree serves needs
    it, and it would add a second AES mode with its own tag construction.

    Adding the AES-256 rows to the webpki loop found a defect entry 45
    shipped. The server read `cipher_suites` once per suite it held, and
    each read walked the whole list, so a `SUITE=aesgcm` server read the
    compression bytes as suites and refused every real ClientHello. The
    parser now reads the list once.

59. **A server compares the extensions of a retried ClientHello as a set:
    the frozen digest takes them in ascending type order.** colibri found
    the need through the QUIC Interop Runner on 2026-09-24. Since entry 54
    (4d897ed) a server asks for X25519MLKEM768 with a HelloRetryRequest
    when a client lists it and shares x25519 alone, and ngtcp2's interop
    client does exactly that. Its second ClientHello carries the same
    extensions in another order: supported_versions moves from after
    key_share to the front. The server keeps no state across the retry. It
    compares a SHA-256 digest, carried in the cookie, over every field and
    extension §4.2.2 does not let the client change, and it computed that
    digest in the order the extensions sat on the wire. The reorder changed
    the digest, `srv_check_retry_hello` answered illegal_parameter, and
    every ngtcp2 handshake that needed a retry failed.
    `test/srv_quic_retry_vectors.h` holds the two hellos colibri recorded.

    §4.2.2 has the client send "the same ClientHello without modification"
    apart from five listed changes (rfc9846.txt:1191-1213), and §4.3 lets
    extensions "appear in any order" (rfc9846.txt:1669-1670). Camilo
    decided on 2026-09-24 that a reorder is not a modification the server
    refuses. A second hello that carries exactly the covered extensions of
    the first, each with the same type and bytes, is accepted in any order.
    One that
    adds, drops or changes a covered extension, or changes a head field
    from legacy_version through legacy_compression_methods, is refused
    with illegal_parameter as before. The five extensions §4.2.2 lets
    change, key_share, early_data, cookie, pre_shared_key and padding, stay
    out of the digest.

    **The construction.** The digest is SHA-256 over the head, then each
    covered extension whole, its type, length and body, in ascending type
    order (`add_frozen_extensions`, `srv_parser.c`). The parser already
    refuses a second extension of any type, unknown types included, with
    illegal_parameter (`srv_ext_duplicate`, rfc9846.txt:1673-1674), before
    it computes the digest, so the types in a block it hashes are distinct.
    With distinct types, one set of covered extensions gives one byte
    string: the sort order is fixed, and each extension carries its own
    type and length, so the string reads back into exactly one set. Two
    different sets therefore give two different strings, and a digest that
    matches across them is a SHA-256 collision. That is the argument the
    wire-order digest rested on, with a list replaced by a set. The cookie
    format does not change: 32 bytes of digest, opened and compared with
    `ct_memeq` as before. A cookie minted before this change carries a
    wire-order digest and fails the comparison for any hello whose
    extensions were not already in ascending order, and a cookie lives for
    one retry, so nothing supports the old form.

    **The cost.** The walk keeps no list: each pass reads the whole block
    for the covered extension with the smallest type above the last one it
    added, and the pass after the last one finds none. A block of n
    extensions costs at most (n + 1) * n extension headers read, beside
    the n * (n - 1) / 2 that `srv_ext_duplicate` already read. The
    construction does not bound n. The block is at most 65,535 bytes and
    never longer than `cfg.buf_len`, and an extension is at least 4 bytes,
    so n is at most 16,383, and a device's buffer holds far fewer. A
    ClientHello of n empty extensions of distinct unknown types, parsed on
    an arm64 M1 Pro (clang -O2) by the parser before this entry and after
    its construction, took:

    | Extensions | Message | Duplicate check | Whole parse, before | Whole parse, after |
    |---:|---:|---:|---:|---:|
    | 100 | 443 B | under 1 ms | under 1 ms | under 1 ms |
    | 1,000 | 4,043 B | 5 ms | 5 ms | 15 ms |
    | 4,086 | 16,387 B | 75 ms | 74 ms | 252 ms |
    | 16,383 | 65,575 B | 1.2 s | 1.2 s | 4.1 s |

    A browser or ngtcp2 hello carries 10 to 20 extensions, a few hundred
    header reads. The last row is a host that accepts a 64 KiB ClientHello:
    one hello costs it 4.1 s of processor time where it cost 1.2 s
    before, all of it before any key exists.

    **The bound on the extension count.** Camilo decided on 2026-09-24 to
    bound n. The parser refuses a ClientHello whose extension block holds
    more than `SRV_CLIENT_HELLO_EXT_MAX` extensions, 128, with
    illegal_parameter (`srv_parser.h`). `srv_ext_over_max` counts them in
    one walk that stops at the 129th, so it reads at most 129 headers
    however long the block is. `srv_parse_client_hello` calls it after the
    block's length check and before `srv_ext_duplicate`, so neither walk
    whose cost is n squared ever runs over more than 128 extensions. The
    count is not taken in `parse_extension`'s walk, because
    `srv_ext_duplicate` runs before that walk: a count there would bound
    the frozen digest's walk and leave the duplicate check unbounded. An
    unknown type counts the same as a recognized one. Every server path
    reads its hellos through `srv_parse_client_hello`: the blocking server
    (`srv_handshake.c`), the tcp-nonblocking server (`srv_rec.c`) and the QUIC
    server (`srv_quic.c`), for a first hello and a retried one alike, so
    the refusal is the same on each.

    Why 128. Each count below was published, or read from the library's
    source, as of 2026-09-24.

    - Browsers. JA4 fingerprints count a hello's extensions and leave
      GREASE out (https://github.com/FoxIO-LLC/ja4). Chrome's carry 16 to
      18, to which it adds two GREASE extensions, and one more,
      pre_shared_key, when it resumes; a capture of Chrome 146 to 153 is
      https://github.com/bogdanfinn/tls-client/issues/281. Firefox's
      carry 17, Safari's 11 to 14, and Chromium's over QUIC 12.
    - Libraries. A client sends at most the extensions its source can
      write: OpenSSL defines 32, BoringSSL 31 plus padding,
      pre_shared_key and two GREASE extensions, rustls 23 and Go's
      crypto/tls 20. curl over OpenSSL sends 12.
    - QUIC. ngtcp2's two recorded hellos carry 10 and 11.
    - The registry. IANA's TLS ExtensionType Values registry
      (https://www.iana.org/assignments/tls-extensiontype-values) assigns
      64 values, 43 of them allowed in a TLS 1.3 ClientHello, and RFC
      8701 reserves 16 GREASE values for extensions. A client that sent
      every assigned type and every GREASE value once would send 80, and
      the parser refuses a type sent twice.

    So 128 is six times what Chrome sends and 48 more than a client can
    send without inventing types. The bound departs from one RFC 9846
    rule, and this record says so: a server must ignore an unrecognized
    extension (`rfc9846.txt:1299`), and §9.3 restates that as an
    invariant (`rfc9846.txt:4636-4637`). A hello of 129 extensions, most
    of them unknown, is refused here where those lines would have it
    negotiate. No client above sends one. tlsfuzzer's
    `test-tls13-large-number-of-extensions.py`
    (https://github.com/tlsfuzzer/tlsfuzzer) does: it sends thousands of
    empty unknown extensions and expects a handshake, so those
    conversations fail against this server by design. None of the
    libraries above bounds the count. Each refuses only duplicates, and
    BoringSSL, Go and rustls find them by sorting the types or with a map
    or a set, each held in memory that grows with n; a parser with no
    heap has no such memory.

    Why illegal_parameter. RFC 9846 bounds the block's bytes,
    `Extension extensions<7..2^16-1>` (`rfc9846.txt:1237`), and not its
    count, so a block of 129 extensions parses under the syntax. §6 sends
    decode_error for a message that "cannot be parsed according to the
    syntax" and illegal_parameter for one that is "syntactically correct
    but semantically invalid" (`rfc9846.txt:3784-3791`). The alert
    definitions draw the same line (`rfc9846.txt:3947-3950`,
    `rfc9846.txt:3961-3966`), and add that decode_error "should never be
    observed in communication between proper implementations", which
    would point an operator at a corrupted message that is not there. So
    the refusal is illegal_parameter, this design's choice under §6, the
    rule the refusal of a second extension of one type follows too. It is
    checked before every rule on the extensions themselves, so a hello
    past the bound is illegal_parameter whatever else its extensions
    break.

    The cost with the bound, measured the same way on the same machine,
    best of 2,000 runs where a run takes under a millisecond. The clock
    counts whole microseconds, so a refusal shows as its smallest step:

    | Extensions | Message | Whole parse, without the bound | Whole parse, with it |
    |---:|---:|---:|---:|
    | 128 | 555 B | 0.25 ms | 0.25 ms |
    | 128, with 507-byte bodies | 65,451 B | 0.58 ms | 0.57 ms |
    | 129 | 559 B | 0.25 ms | 1 µs or less, refused |
    | 4,086 | 16,387 B | 262 ms | 1 µs or less, refused |
    | 16,383 | 65,575 B | 4.2 s | 1 µs or less, refused |

    The most a hello can now cost the parser is the second row: the 128
    extensions the bound admits, with bodies that fill a 64 KiB block.
    What it adds to the row above is SHA-256 over those bodies, the only
    work the parser does per byte of an unknown extension. Before this
    entry, 16,383 empty extensions in the same 64 KiB cost 1.2 s.

    Three alternatives were considered and rejected. An XOR of one digest
    per extension is order-independent, but two copies of one extension
    cancel and a client could add a pair unseen. A sum of per-extension
    digests modulo 2^256 does not cancel, but its collision resistance is
    a generalized birthday bound this record cannot state plainly. Sorting
    into a buffer costs n log n and needs memory in proportion to n. With
    the bound, the buffer would fit in 256 bytes of stack, but the walks
    it would replace cost a quarter of a millisecond at the bound, so it
    would add a buffer and a sort to audit and save nothing a caller
    could measure.

    `bin/srv_quic_test` replays the recorded hellos: the first draws a
    HelloRetryRequest that matches colibri's server's byte for byte up to
    the digest, and the second completes the handshake through the client
    Finished, with this server's cookie and the test's own key share written
    over the recorded ones. The same binary holds the boundary pairs: the
    first hello's order and ngtcp2's accepted; one covered byte changed,
    one covered extension dropped, one added, one head byte changed and one
    extension sent twice refused. `bin/srv_test` holds the digest to a
    vector over the covered extensions in ascending order. Two CBMC
    harnesses in the slow tier cover the parser. `srv_parser_frozen`
    proves the construction above over every extension block up to 24
    bytes: the duplicate check answers exactly when two types match, and
    the walk hands SHA-256 each covered extension once, whole, in strictly
    ascending type order. `srv_parser_walk` proves the whole ClientHello
    walk memory safe up to 64 bytes with the readers stubbed; it had no
    launch line before this entry, because harness.h's SHA-256 stub made
    the formula too large, and it now keeps a stub of its own.
    OpenSSL's `s_client` offers no option that reorders a retried hello,
    so `test/e2e.sh` keeps its TCP retry leg, which sends the same order
    twice and still passes.

    The bound has tests of its own. `bin/srv_test` fills the golden hello
    out with unknown extensions: at exactly 128 it parses, and its frozen
    digest matches a vector over every covered extension, the filler
    included; at 129 it is illegal_parameter. A supported_versions with a
    trailing byte is decode_error at 128 and illegal_parameter at 129, and
    so is a block that ends in half a header, so the bound is checked
    first. `bin/srv_rec_test` sends this tree's own hello, filled out to
    128 and to 129, through the tcp-nonblocking server: the first draws the flight
    and the second illegal_parameter. `bin/srv_quic_test` fills ngtcp2's
    two recorded hellos out with the same unknown extensions, so the
    frozen digest matches and only the count can refuse. A first hello of
    127 and its retried hello of 128 draw the flight; a first hello of 128
    draws a HelloRetryRequest and its retried hello of 129 is
    illegal_parameter; a first hello of 129 is refused before any
    HelloRetryRequest. The ngtcp2 replay above still passes.

    Two CBMC harnesses hold the bound at smaller values, which
    `srv_parser.h` admits for a harness. `srv_parser_count` proves, over
    every block up to 24 bytes with the bound at 3, that
    `srv_ext_over_max` answers 1 exactly when the block begins with more
    than the bound's whole extensions, and that it never reads a header
    past the one that passes the bound. It runs in the fast tier, in 1 s.
    `srv_parser_walk` takes the bound at 4 and holds the loops of both
    walks to four extensions, one fewer than its 64-byte message holds, so
    an unwinding assertion fails if either walk ever runs over a fifth.
    The bound let that formula grow from 60 bytes to 64: before it, 64
    bytes returned no verdict in 18 minutes, and with it the formula
    takes 489 s and 1.34 GB, still the slow tier. Five violations guard
    the bound. srv-parser-ext-max-off-by-one,
    srv-parser-ext-max-refuses-bound and srv-parser-ext-max-after-walk
    require `bin/srv_test` to fail, srv-parser-ext-max-removed requires
    `bin/srv_quic_test` to fail, and srv-parser-ext-max-after-duplicate,
    which moves the count below the duplicate check, requires the
    `srv_parser_walk` proof to fail. Both checks answer illegal_parameter,
    so no test can see that order, and the proof's loop bound is what
    catches it.

60. **The peer's close_notify closes the peer's direction alone, and
    `ch_close` closes this side's.** RFC 9846 §6 says a close_notify
    closes one direction of the connection (rfc9846.txt:3767-3768), and
    §6.1 says sending one has no effect on the sender's read side and
    drops TLS 1.2's rule of answering one at once with a close_notify of
    one's own (rfc9846.txt:3857-3864). Until this entry `ch_read` kept
    the TLS 1.2 rule: on the peer's close_notify it called `ch_close`,
    which sent this side's close_notify and wiped both directions. The
    caller could not send what it still owed, because `ch_write` refused
    the closed session. Under `TRANSPORT=tcp-nonblocking` the reply went through
    `cfg.send` from inside `ch_read`, which colibri's adapter does not
    expect, so the alert was lost, and the caller's own `ch_close` sent
    nothing because the keys were gone.

    - **What the read does.** The `ch_read` that reads the peer's
      close_notify returns 0 and sends nothing. It wipes `rd`,
      `rd_secret` and `res_master`, the secrets only a read uses
      (INV-17), and sets `ch_tls.read_closed`. Every later `ch_read`
      returns 0 before it calls `cfg.recv`. §6.1 says data after a
      closure alert MUST be ignored (rfc9846.txt:3837-3839), and a
      record that is never read is never decrypted or acted on.
    - **What stays.** `wr`, `wr_secret` and `exp_master` stay, and
      `ch_tls.state` stays `CH_ST_CONNECTED`. `ch_write` sends as
      before, and `ch_close` sends this side's close_notify under the
      write key and wipes the rest, as it always did.
    - **How a caller learns of it.** From `ch_read`'s 0, which already
      meant the peer closed, and from `read_closed`. A new state value
      was considered and rejected. Callers test `CH_ST_CONNECTED` before
      they write, and writing is still allowed, so every such test would
      be wrong until the caller learned the new value; `CH_ASSERT(t->state
      <= CH_ST_FAILED)` and `rec_session_dead` would each need to judge a
      fifth value too. `CH_ST_CLOSED` keeps its one meaning: this side
      called `ch_close` or `ch_record_close`, and no key is left. The
      field sits in the padding before `send_epochs`, so `sizeof(ch_tls)`
      did not change in any build, host or rv32, and `ch_build` records
      the same sizes.
    - **Every driver at once.** The blocking client and server and the
      tcp-nonblocking client and server all read through the one `ch_read`
      in `tls.c`. A QUIC object compiles no `tls.c`: QUIC carries no
      close_notify, and RFC 9001 §4.8 treats every TLS alert as fatal
      (rfc9001.txt:888-893), so nothing there changes.

    Cost: one public field. A caller whose `ch_read` returned 0 must
    still call `ch_close`, or the peer never receives this side's
    close_notify, and the write key lives until it does. The examples
    already called it on that path, and `test/tls_client.c` now does.
    Gain: this side can finish
    sending after the peer is done, as RFC 9846 intends, and `ch_read`
    sends nothing when the peer closes.

    A call that sends this side's close_notify and keeps reading, the
    other half of a half close, was not added. No caller has asked for
    it, and `ch_close` stays the one call that ends a session. §6.1 lets
    a party close its read side without waiting for the peer's
    close_notify (rfc9846.txt:3864-3867), which `ch_close` does.

61. **An image links one packaged object of each of two transports: the
    three exports every transport carries take the transport into their
    symbol names, and the two pairs that share calls are refused at the
    link.** cocuyo wants DNS over TLS, DNS over QUIC and DNS over HTTP/3 in
    one binary, so it links a `TRUST=webpki TRANSPORT=tcp-nonblocking` object for
    the first and colibri's `TRUST=webpki TRANSPORT=quic-nonblocking ROLE=both` object
    for the other two. The link failed on `ch_build`, which both objects
    defined (entry 56). The two objects' headers disagree about `ch_cfg`
    and `ch_tls`, so a program calls each object from a translation unit
    compiled under that object's defines. A name both objects define
    fails the link, and a linker that kept one definition would hand one
    of those units the other object's.

    - **The build record.** Its symbol is `ch_build_info_tcp_blocking`,
      `ch_build_info_tcp_nonblocking` or `ch_build_info_quic_nonblocking`, and `build.h` defines
      `ch_build` as an object-like macro for the one the defines in force
      select. `ch_build_matches(&ch_build)` compiles unchanged in C and
      through `chapulin.hpp`, reads the record of the object whose
      headers the unit compiles against, and a unit compiled for another
      transport than its object's fails to link.
    - **Zig.** translate-c turns the macro into `pub const ch_build =
      ch_build_info_tcp_nonblocking;`, and Zig 0.16 refuses to evaluate that constant,
      because its initializer is an extern variable (checked 2026-09-25).
      An asm label on the declaration is dropped by translate-c, and a
      macro that dereferences the record's address meets the same
      refusal. So a Zig program writes the record's own name,
      `c.ch_build_matches(&c.ch_build_info_tcp_nonblocking)`, and an `@cImport` missing
      `CH_TRANSPORT_TCP_NONBLOCKING` declares no such name, so that mistake stops
      the compile. A function name maps without this: Zig evaluates
      `pub const ch_srv_check = ch_srv_check_quic_nonblocking;`, because a function
      is known at compile time.

    The audit. Twenty-two objects were built on 2026-09-25 and each pair
    of different transports was compared by the names `nm` lists as
    defined: the four `TRUST` client modes and `RAND=drbg` over each
    transport, `ROLE=server` and `ROLE=both` over each, `EXPORTER=on`, and
    `SUITE=aesgcm AES=hw` over tcp-nonblocking and QUIC. No object defines a
    common or weak symbol. Six names were shared:

    | Name | Objects that export it | Resolution |
    |---|---|---|
    | `ch_build` | every object | named per transport, mapped in `build.h` |
    | `ch_srv_check` | every `ROLE=server` and `ROLE=both` object | named per transport, mapped in `srv.h` |
    | `ch_pubkey_from_pem` | every `TRUST=ca-rsa` and `TRUST=ca-ecdsa` object | named per transport, mapped in `x509_ca.h` |
    | `ch_drbg_seed` | every `RAND=drbg` object | refused: two `RAND=drbg` objects do not link |
    | `ch_read`, `ch_write`, `ch_close` | every `TRANSPORT=tcp-blocking` and `TRANSPORT=tcp-nonblocking` object | refused: a tcp-blocking object and a tcp-nonblocking object do not link |
    | `ch_export` | `EXPORTER=on` objects, the two TCP transports only | refused with the pair above |

    `ch_srv_check` and `ch_pubkey_from_pem` follow the record for two
    reasons. A server pair is the plain case, an HTTP/2 server beside an
    HTTP/3 one, and two definitions of `ch_srv_check` are not
    interchangeable, since each reads its own transport's `ch_cfg`. A CA
    pair is rarer, but the rule is then one sentence: every export that
    objects of more than one transport carry takes the transport into its
    name. The Makefile applies it in one list, `TRANSPORT_NAMED`, so
    `PUBLIC` and `lib-check` read symbol names.

    The two refusals, and why neither is renamed:

    - **`ch_drbg_seed`.** Each `RAND=drbg` object carries its own
      generator, with its own state, local to the object. Two objects
      are two generators and two seeds, and an image that hands one seed
      to both draws the same bytes in each: the same key share in a
      record session and a QUIC session. Renaming the call would make
      that image link. A `RAND=drbg` object beside a `RAND=extern` one
      links, because the generator's `ch_rand_bytes` is local, and it
      still keeps a second generator the image's hook does not feed, so
      `docs/porting.md` refuses that pair in words.
    - **`ch_read`, `ch_write` and `ch_close`.** The tcp-nonblocking
      transport keeps the connected session's calls under the blocking transport's
      names (`rec.h`), and a tcp-nonblocking object does everything a
      blocking one does with the caller driving the socket. Renaming
      them would move the three calls every TLS program links against,
      for an image that gains nothing by carrying both transports.

    Camilo decided on 2026-09-24 that an image defines `ch_rand_bytes`
    and `ch_assert_fail` once, for every chapulin object and every user of
    chapulin it links, and that no session takes a randomness callback of
    its own. One entropy source per image is simpler to audit, INV-4
    keeps a single hook, and two users already share one object per
    transport: cocuyo, and a consumer that reaches chapulin through
    colibri. So `ch_rand_bytes` must be safe to call from several threads
    at once, because a thread-per-core image runs sessions on every core.
    `docs/porting.md` states that and lists the calls that draw from it.

    What holds it:

    - `test/lib-pair-check.sh`, in `make check`, links four pairs and
      runs each half: webpki tcp-nonblocking client beside the webpki QUIC
      `ROLE=both` object (cocuyo's), tcp-nonblocking server beside QUIC
      server, raw-rsa tcp-blocking beside raw-rsa QUIC, and ca-rsa
      tcp-blocking beside ca-rsa QUIC.
      Each half reads its own record, runs `ch_srv_check` or
      `ch_pubkey_from_pem` where its object has one, and starts a
      session. The drbg pair and the tcp-blocking and tcp-nonblocking pair must fail to
      link, and the linker must name each shared name. It reuses the
      objects the `lib-check` legs build and builds two more: 5.2 s with
      every object built, 8 s with the two to build.
    - `lib-check`'s consumer compiled with the transport moved now must
      fail to link, naming the other transport's record. It used to read
      a record that differed, which can no longer happen, so a consumer
      with `CH_PIN_ECDSA` moved reads the difference instead. Every header
      admits that define, and it changes no symbol name and no hook.
    - `inv35-build-record-shared-name` gives the QUIC transport's build
      record the tcp-nonblocking transport's name, and `test/lib-pair-check.sh` catches
      it.

    One more change came with it. `test/violations.py` edits `PUBLIC`,
    links, restores it and links again within one second, and make 3.81
    compares mtimes to the second, so the second link was skipped and the
    object kept the edited export list: `inv35-build-record-not-exported`
    followed by `inv35-build-record-omits-axis` failed the second one's
    baseline on a correct tree. The link stamp now forces the link when
    its line differs from the build's, whatever the clocks say.

    Cost: three symbol names change. A C or C++ consumer changes
    nothing; a Zig consumer writes `ch_build_info_tcp_nonblocking` or `ch_build_info_quic_nonblocking`
    where it wrote `ch_build`, which cocuyo does on three lines and
    colibri's tests on four. `lint-quic-partition` lists `x509_ca.h` and
    `x509_ca.c` beside `build.h` and `build.c`, because a QUIC build
    compiles the provisioning call under its own name.
    `bench/stack.py` reports `ch_pubkey_from_pem_tcp_blocking`. `make check`
    gains the pair test and one more consumer build per `lib-check` leg.

    Gain: one image links the objects of two transports, and each unit
    of it reads the record of its own object.

    Rejected: a weak `ch_build` in every object, because the linker keeps
    one, and the other transport's unit reads it; renaming at the link
    with `objcopy --redefine-sym`, because Apple's toolchain has no
    `objcopy` and the consumer's header must name the symbol anyway; and
    one object carrying two transports, because `TRANSPORT` is one per
    object and the two layouts of `ch_tls` cannot share one name. Entry
    56 rejected a symbol name per build because it would encode every
    axis in the name. The transport is one axis, and it already changes
    the link line, since each transport exports its own calls.

62. **Each `TRANSPORT` value names what TLS runs over and who does the
    I/O: `tcp-blocking`, `tcp-nonblocking` and `quic-nonblocking`.** The
    axis took `tls`, `record` and `quic`. TLS is not a transport: it runs
    over TCP or inside QUIC. `record` named the unit the caller passes, a
    TLS record, and not what sets the mode apart, which is that the
    caller's code does the I/O. It also gave "record" two meanings, the
    build record and a transport, so `ch_build_record` (entry 61) read as
    the struct itself. The values now say both halves:
    - `tcp-blocking`, the default: TLS records over a byte stream, and
      chapulin calls the blocking `cfg.send` and `cfg.recv`.
    - `tcp-nonblocking`: the same records, and the caller passes bytes in
      and takes bytes out (`rec.h`).
    - `quic-nonblocking`: TLS handshake messages inside QUIC, always
      driven by the caller (`quic.h`).

    Every value names its I/O style, the QUIC one included, which has no
    blocking twin, so no reader takes an unmarked name to block. The
    defines follow the values (`CH_TRANSPORT_TCP_NONBLOCKING`,
    `CH_TRANSPORT_QUIC_NONBLOCKING`), and so do the symbol names entry 61
    gave the transport: `ch_build_info_tcp_blocking`, named for the type
    `ch_build_info`, and `ch_srv_check_tcp_blocking`. The old values stop
    the build with a message naming the new ones, so no consumer gets a
    different transport without noticing.

    Gain: a reader learns from the name alone what the object runs over
    and whether a call can wait on the network.

    Rejected: marking only one I/O style (`tls` beside `tls-async`, or
    `tls-blocking` beside `tls`), because the unmarked names then read as
    the other style; `https`, because chapulin carries any protocol over
    TLS, and HTTP is one; and renaming the API, because `ch_record_in`
    still takes TLS records. "TCP" names the byte stream every consumer
    uses; any reliable byte stream works under either TCP value.

63. **A `TRUST=webpki` client lists secp256r1 after the two groups it
    shares and answers a HelloRetryRequest for it, and every server takes
    secp256r1 last.** colibri's webpki client could not connect to
    nghttpd 1.52.0 on OpenSSL 3.0, which accepts secp256r1 and no other
    group: the hello listed X25519MLKEM768 and x25519, and the server
    answered handshake_failure. RFC 9846 §9.1 makes key exchange with
    secp256r1 a MUST and X25519 a SHOULD (rfc9846.txt:4548-4550).
    `p256_ecdh.[ch]` already held a constant-time P-256 key exchange that
    no library object called.

    - **The client's offer.** `supported_groups` lists X25519MLKEM768,
      x25519 and secp256r1, in that order, and `key_share` carries the
      hybrid and x25519 shares entry 53 set and no secp256r1 share. §4.3.8
      lets the shares be a subset of the list (rfc9846.txt:2161-2165). A
      server that wants secp256r1 answers with a HelloRetryRequest naming
      it, which is legal because the hello listed secp256r1 and sent no
      share for it (rfc9846.txt:2205-2215). The retry hello replaces
      `key_share` with one secp256r1 entry, the 65-byte uncompressed point
      of §4.3.8.2 (rfc9846.txt:1194-1196, 2261-2275), and keeps the rest
      of the first hello, a cookie beside it when the retry sent one. The
      ServerHello must then select secp256r1 (rfc9846.txt:2233-2238). A
      retry naming the hybrid or x25519 is still illegal_parameter, as
      entry 53 made it, and so is a ServerHello that selects secp256r1
      when no retry named it. `ch_cfg.require_pq` keeps its meaning: the
      hello lists and shares the hybrid alone, so a retry naming
      secp256r1 names a group the hello never listed and is refused.
    - **The client's key.** `handshake_groups.c` draws the P-256 scalar
      through `ch_rand_bytes` when a retry names secp256r1 and at no other
      time, a new INV-4 site. A draw outside [1, n-1] happens with
      probability below 2^-32 and is drawn again, up to four draws
      (`P256_ECDH_DRAWS`); four refusals in a row from a working
      generator happen with probability below 2^-128, so CH_ASSERT treats
      them as a hook that wrote nothing, as every draw site treats an
      all-zero draw. The retry wipes the first hello's x25519 and ML-KEM
      key pairs, which no later message uses. The scalar and the point
      live in `handshake_state` until the ServerHello; the call that
      computes the secret wipes the scalar on both exits (INV-17).
    - **The checks and the secret.** `p256_ecdh` refuses a server point
      whose form byte is not 0x04, whose coordinates are not below p, or
      which is not on the curve, the three steps §4.3.8.2 lists
      (rfc9846.txt:2277-2286); the point at infinity has no 65-byte
      encoding and fails the curve equation. The parser refuses any length
      but 65. Each refusal is illegal_parameter. The shared secret is the
      32-byte X coordinate with no leading zero dropped (§7.4.2,
      rfc9846.txt:4266-4276), and the key schedule extracts from it as it
      extracts from an x25519 secret. `ch_tls.group` reports
      `CH_GROUP_SECP256R1`.
    - **The server.** Every server role, `ROLE=server` and `ROLE=both`
      over all three transports, holds secp256r1 as its third group and
      takes it last: X25519MLKEM768 when the client lists it, then x25519,
      then secp256r1. A client that lists secp256r1 alone gets it, in one
      round trip when it shared it and after a HelloRetryRequest when it
      did not. A client that lists x25519 or the hybrid never gets P-256.
      `srv_kex_share` checks the client's point before it draws the
      server's P-256 key, a new INV-4 site in `srv_kex.c`, and a refused
      point is illegal_parameter before any ServerHello goes out.
      `srv_kex_secret` wipes the scalar on both exits. The PQ-first rule
      of entry 54 stands unchanged.

    Cost: the webpki hello grows by the 2 bytes of the third NamedGroup, so
    `CH_HELLO_MAX` and the webpki `CH_TX_STAGE` go from 2,394 to 2,396, and
    the QUIC one from 2,648 to 2,650. The retry hello to secp256r1 needs no
    term: its one 69-byte `KeyShareEntry` replaces the 1,256 bytes of the
    first hello's two, so it is 1,187 bytes shorter than a cookie retry.
    `bench/sram.sh` measures the webpki `ch_tls` at 3,048 bytes on arm64,
    against 3,040, and `ch_connect`'s stack peak at 16,528 bytes, against
    16,416, because the handshake state holds the retry group, the 65-byte
    point and the 32-byte scalar; `ch_srv_accept` peaks at 10,336 bytes,
    against 10,304, because it holds the scalar. Every webpki object now
    packages `p256_ecdh.c`, `p256_point.c`, `p256_scalar.c` and
    `p256_field.c`, and every server object adds `p256_ecdh.c` to the
    three it already carried for its ECDSA signer. A server that holds
    secp256r1 alone costs this client one round trip, and one P-256
    scalar multiplication takes 1,228 microseconds against x25519's 953,
    measured on an M1 Pro (`bench/notes-primitives.md`). Gain: the client
    reaches a server that holds only the group §9.1 requires, and the
    server serves a client that offers only that group.

    Two alternatives were considered and rejected. Sending a secp256r1
    share in the first hello saves that round trip, and puts 69 bytes and
    a P-256 key generation in every hello, a key pair nearly every
    handshake discards, which is the trade entry 39 declined for the
    hybrid. Preferring secp256r1 to x25519 on the server gives the slower
    group to every client that lists both, OpenSSL's default list and
    every webpki client among them.

    The earlier text overclaimed. `docs/server.md`'s list of §9.1
    residuals, written on 2026-09-18, said the server held both secp256r1
    and X25519, while its profile table and `srv_parser.h` said it held
    X25519MLKEM768 and x25519 alone, and the code agreed with the table.
    The server held no secp256r1 until this entry, and that sentence is
    true from this entry on.

64. **A `TRUST=webpki` QUIC client takes SPKI pins with the meaning they
    have over TCP.** cocuyo, a DNS resolver, runs DNS over QUIC (RFC 9250)
    through colibri with chapulin's QUIC object as its TLS. RFC 9250 §5.1
    gives a DNS-over-QUIC client the authentication requirements RFC 7858
    and RFC 8310 give a DNS-over-TLS one. RFC 8310 §6.3 lists an SPKI pin
    set and an address as one way to authenticate a server, and §6.4 has a
    client configured with a name and pins require both
    (`rfc8310.txt:805-814`). cocuyo's DNS-over-TLS path already uses all
    three configurations entry 49 allows: a hostname alone, pins alone, and
    both. `ch_quic_init` refused pins and required a hostname, so its QUIC
    path could use the first alone.

    - **The rules.** `quic_config.c` calls `webpki_cfg_ok`, the function
      `ch_connect` and `ch_record_init` call, where it kept its own copy
      of the anchor, hostname and clock rules. So a configuration is valid
      over QUIC exactly when it is valid over TCP, and RFC 9001's three
      rules stay on top: transport parameters, `on_level_ready`, and an
      ALPN offer that names a protocol. `CH_SPKI_PIN_MAX` bounds the pins
      on both transports.
    - **The handshake.** Nothing else changes. The ClientHello builder,
      the EncryptedExtensions parser and `webpki_server_key` were already
      shared with TCP, and the configuration rule alone kept pins out. The
      hello offers `server_certificate_type` as over TCP, and the
      Certificate is judged as over TCP: a raw key by the pins alone, a
      chain beside anchors by the walk, the name and a pin on the path the
      walk verified, and a chain answering pins alone refused with
      unsupported_certificate.
    - **The ticket binding.** `webpki_ticket_config_hash` hashes the pins
      beside the hostname and the anchors, and `ch_quic_init` takes that
      hash when the session starts, as `ch_connect` does. So every ticket a
      pinned QUIC session receives is bound to its pins, and `ch_quic_init`
      refuses the ticket under another pin set or none. A resumed
      handshake sends no certificate, so no pin is checked in it; the
      binding is what holds it to the pins that judged the first session's
      key.
    - **What is tested, and what is not.** `bin/quic_loop_webpki` runs the
      three configurations against this tree's QUIC server, which sends a
      chain and never a raw public key. A hostname alone and a hostname
      with pins pass end to end. Pins alone are tested for their offer and
      for the refusal of that server's chain. A raw public key accepted
      over QUIC is not tested: no QUIC server this tree runs sends one,
      and OpenSSL 3.6.4's `s_server` has `-enable_server_rpk` and no QUIC.
      The raw-key rule is the TCP one, tested end to end over TCP.

    Cost: the 7-byte `server_certificate_type` offer now goes out over
    QUIC. `CH_HELLO_MAX` already counted it there, because the builder is
    shared, so the QUIC webpki `CH_TX_STAGE` stays 2,650 bytes, and
    `ch_tls` and `ch_quic` keep their sizes, read from the build record
    of each object on arm64 macOS: 3,200 and 4,808 bytes in the client
    object, 3,408 and 5,056 under `ROLE=both`. `quic_config.c` drops its
    second copy of the ALPN name rules in this build, because
    `webpki_cfg_ok` runs them, and its text falls from 452 to 144 bytes.
    Gain: a DNS-over-QUIC client uses the configurations its DNS-over-TLS
    path uses, and a pin means one thing on every transport.

    A QUIC copy of the pin rules was considered and rejected: two copies
    of one rule can drift apart, and a copy has no reason to exist when
    the handshake code that reads the configuration is shared.

65. **SPKI pins alone accept a certificate chain whose leaf key a pin
    names.** Entry 49 made pins alone RFC 8310's "SPKI + IP" profile
    (`rfc8310.txt:683-685`) and read it as a raw public key alone: an
    X.509 answer was refused with unsupported_certificate. cocuyo's
    DNS-over-QUIC targets, AdGuard and NextDNS, send ordinary ECDSA chains
    that end at USERTrust ECC, and cocuyo reaches them by address and pin.
    RFC 7858 §4.2 has the client hash the keys of the validated server
    chain, or the raw key the server sent, and match a pin
    (`rfc7858.txt:434-440`). With no anchor, no clock and no hostname
    there is no validated chain, so this entry fixes what pins alone check.
    Pins alone now mean that the server proves it holds a pinned leaf key,
    sent raw or inside a certificate.

    - **The offer.** Pins alone offer RawPublicKey, then X509. With
      anchors the offer already listed both.
    - **The rule.** A chain under pins alone passes when one pin is the
      SHA-256 of its leaf's SubjectPublicKeyInfo, and CertificateVerify
      then verifies under the leaf's key. The certificate is public; the
      signature is what proves the server holds the key.
    - **What is not read.** The chain above the leaf, the dates and the
      names, because there is no anchor, clock or hostname to check them
      against. The list is framed by the walk's own framing, and the leaf
      is read only as far as its key, by `webpki_cert.c`'s own field
      readers. The fields after the key are skipped as whole TLVs, so
      each container still ends where its fields end (INV-25), and their
      content is not read. INV-20's containment holds: the reader has one
      caller, that caller has one caller in `handshake_auth.c`, and
      neither reads a clock.
    - **Other keys do not count.** A pin that names only an intermediate
      or a root key is refused with bad_certificate, the alert a pin miss
      gets. With no name to check, a pin on a CA key would accept every
      certificate that CA issued, to anyone.
    - **Unchanged.** A raw public key, pins beside anchors, and the ticket
      binding, which holds a resumed session to the pins that judged the
      first one.

    Cost: a pinned leaf key breaks when the operator rotates it, and a leaf
    rotates more often than a CA key, so a caller pins a backup key too, as
    RFC 7858 §4.2 asks. Under pins alone, `webpki_cert.c`'s readers now
    parse peer input, where only `webpki_spki.c` parsed it before. The
    pins-alone hello grows by 1 byte, the X509 entry, inside
    the `CH_HELLO_MAX` every webpki build already counted, so
    `CH_TX_STAGE`, `ch_tls` and `ch_quic` keep their sizes. Gain: pins
    alone reach a server whose leaf key the caller knows, whether it sends
    the key raw or in a certificate, over both TCP transports and QUIC.

    What changes in entry 49: its "SPKI + IP" profile no longer means a
    server with no public certificate alone. Its rejection of matching a
    pin on the leaf alone stands where anchors are set, because there a
    pin on any key of the validated path counts. Under pins alone the leaf
    is the one key the signature proves, so it is the one key a pin may
    name.

    Two alternatives were considered and rejected. Accepting a pin on any
    key of the chain and checking the signatures from the leaf up to it,
    with the pinned certificate as an anchor, accepts every leaf that CA
    issued, to anyone, when no name is checked; a caller who pins a CA
    sets anchors and a hostname instead. Refusing X.509 under pins alone,
    as entry 49 did, leaves a DNS client unable to reach a public resolver
    by address and pin.
