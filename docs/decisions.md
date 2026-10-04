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
   Entries 45, 50, 58 and 68 later admit AES under traffic keys, in a
   `SUITE=aesgcm` build that takes AES instructions or an AES peripheral
   whose timing the build vouches for; the default build is still
   ChaCha20 alone.
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
    hello, so a streaming builder would buffer the message anyway. Entry 71
    lets a TCP build raise the sealed record's plaintext with `TX_RECORD`,
    and where the record then outgrows the hello, the record wins.
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
    proofs that finish, and claims nobody has to take on faith —
    docs/verification.md states what is proved, at what bound, and what is only
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
    `aes_public_key`, that only `aes.c`, `quic_initial.c` and
    `quic_retry.c` can build is the first guard, and the compiler runs
    it: `quic.h` stores no key, only the Destination Connection ID the
    keys come from, so the type is incomplete everywhere but the three
    sources that include `aes_public_key.h`, and a fourth file that
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
    a resume point inside `srv_out_sealed`'s record loop, and
    `tcp_nonblocking_step.h` rules that out: a step runs on a whole
    message and waits nowhere inside it. `srv_quic.h` reached the same
    place for the same reason, so `ch_srv_cfg.on_record_out` is
    `on_crypto_out` without the level.

    That still solves the problem: the callback copies each record into a
    buffer the caller owns and returns, so nothing waits on a socket.
    INV-28 states the claim and `bin/srv_tcp_nonblocking_test` measures it
    with a `send` and a `recv` that fail the run if the driver calls them.

43. **The exporter is a build axis, and it widens one cap rather than adding
    a second serializer.** `EXPORTER=on` compiles `ch_export` (RFC 9846 §7.5)
    and adds `exp_master` to `ch_tls`; `EXPORTER=off`, the default, compiles
    neither. `ch_tls` measures 1144 bytes off and 1176 on, so a device that
    exports nothing pays nothing and docs/performance.md's SRAM figures
    are the default build's, unchanged. colibri asked for the call for h2
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
    not a shared one. docs/verification.md says cross-checked, not
    published.

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
    `bin/tcp_nonblocking_loop_test` compares the random too, and INV-29
    records the rule with a mutant that restores the bug.

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
    the retry's suite, and `ch_tls.suite` reports the one that ran. Entry
    80 puts the AES-GCM suites first in a build on `AES=hw` with
    `CH_NATIVE_AES`, and lets a caller name the client's order.

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
    and `tcp_nonblocking.h` already asks the caller for whole records.

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
    PCLMULQDQ in `ghash_hw.c`, because `gcm.c`'s portable
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
    `aes_hw.c` and `ghash_hw.c` together, `AES=runtime` compiles both and
    runs both on one answer about the part (entry 81), and every other
    `AES` value compiles neither. The second define would be required exactly
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
    run time, for the reasons `aes_hw.c` gives.

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

    - The RAND pattern. It changes no size or bound: `rand.h` declares
      the same call in every build, and `drbg.h` adds only the
      declaration of `ch_drbg_seed`, under `CH_RAND_DRBG`. A mismatch
      still reports itself.
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

    Entry 77 changed one thing here: `CH_RAND_SESSION` takes bit `0x400`
    of `axes`, because it adds two fields to `ch_cfg`. `RAND=extern` and
    `RAND=drbg` still take no bit.

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
      `bin/aes_equiv_test` and the `aes256` proof hold the
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
      build does not hold. Entry 80 orders both roles AES-256-GCM, then
      AES-128-GCM, then ChaCha20 in a build on `AES=hw` with
      `CH_NATIVE_AES`, where h3spec's offer then selects AES-256-GCM.
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
    (`srv_handshake.c`), the tcp-nonblocking server
    (`srv_tcp_nonblocking.c`) and the QUIC server (`srv_quic.c`), for a
    first hello and a retried one alike, so the refusal is the same on
    each.

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
    first. `bin/srv_tcp_nonblocking_test` sends this tree's own hello, filled out
    to 128 and to 129, through the tcp-nonblocking server: the first draws the
    flight and the second illegal_parameter. `bin/srv_quic_test` fills ngtcp2's
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
      <= CH_ST_FAILED)` and `tcp_nonblocking_session_dead` would each need
      to judge a fifth value too. `CH_ST_CLOSED` keeps its one meaning:
      this side called `ch_close` or `ch_record_close`, and no key is
      left. The field sits in the padding before `send_epochs`, so
      `sizeof(ch_tls)` did not change in any build, host or rv32, and
      `ch_build` records the same sizes.
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
    | `ch_drbg_seed`, and `ch_rand_bytes` from entry 67 on | every `RAND=drbg` object | refused: two `RAND=drbg` objects do not link |
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
      `docs/porting.md` refuses that pair in words. Entry 67 exports
      `ch_rand_bytes` from a `RAND=drbg` object, and that pair now has
      one generator.
    - **`ch_read`, `ch_write` and `ch_close`.** The tcp-nonblocking
      transport keeps the connected session's calls under the blocking transport's
      names (`tcp_nonblocking.h`), and a tcp-nonblocking object does everything a
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

    Entry 77 changed one thing here: a `RAND=session` object takes a
    randomness callback per session in its `ch_cfg` and imports no
    `ch_rand_bytes`, so an image whose objects are all `RAND=session`
    defines none. The hook stays one per image for `RAND=extern` and
    `RAND=drbg`.

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
      and takes bytes out (`tcp_nonblocking.h`).
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
      against. Every entry is framed by the walk's own framing, but only
      the leaf is kept, so pins alone take any number of entries the
      message holds, where the walk takes `CH_WEBPKI_FLIGHT_ENTRIES`. For
      the same reason every entry, the leaf included, may take
      `CH_WEBPKI_LEAF_PIN_CERT_MAX` bytes, 16375, the largest certificate
      one entry carries in the 0x4000-byte message body every handshake
      reader admits, where the walk holds each certificate to
      `CH_WEBPKI_CERT_MAX`, 3072 bytes.
      The walk parses up to three certificates and verifies their
      signatures; pins alone parse only the leaf, and only as far as its
      key. This entry first kept both of the walk's caps, which refused
      the QUIC Interop Runner's amplificationlimit chain, a leaf of 5,514
      bytes under eight intermediates, though no entry past the leaf is
      read and the twenty 250-byte subjectAltName entries that make the
      leaf that large are not read either. The webpki_cert_key proof
      covers the reader to one byte past the new cap. The receive buffer
      bounds the message as well, so a caller whose server sends a
      Certificate message larger than `CH_TRUST_MIN_RXBUF` sizes
      `cfg.buf_len` to hold all of it. The leaf
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

66. **`ch_drbg_seed` takes a seed of any length from 32 bytes up and
    hashes it into the generator key**
    ([#164](https://github.com/c4milo/chapulin/issues/164)). docs/entropy.md
    told a `RAND=drbg` integrator to concatenate several entropy sources
    and hash them with `sha256_of` into the 32 bytes `ch_drbg_seed` took.
    The packaged object exports `ch_drbg_seed` and keeps `sha256_of`
    local, so that recipe did not link, and nothing compiled it.

    - **The call.** `ch_drbg_seed(const uint8_t *seed, size_t seed_len)`.
      The generator key is the SHA-256 of all `seed_len` bytes. The
      caller concatenates its sources into one buffer and passes the
      whole buffer, and needs no hash of its own.
    - **The floor.** A seed shorter than `CH_DRBG_SEED_MIN`, 32 bytes, is
      a programmer error, and `CH_ASSERT` fires. 32 is the key length. A
      seed shorter than the key cannot carry a full key of entropy. The
      floor does not measure entropy: a 32-byte counter passes it.
    - **Reseeding.** A second call replaces the state, as before. The
      reseed recipe concatenates fresh bytes with output the generator
      just drew.
    - **Wipes.** The digest goes straight into the generator key, so no
      stack copy of it exists, and the SHA-256 context is wiped before
      the call returns. The caller wipes its own buffer.
    - **The check.** `test/entropy_recipe.c` is docs/entropy.md's
      boot-seed recipe in C. `make lib-check RAND=drbg` links it against
      the packaged object and runs it, so a recipe that calls a function
      the object keeps local fails there.

    Cost: an API break. Every caller changes its call, colibri's test
    endpoints among them, and the known answers in `bin/drbg_test`
    changed with the key. `sha256.c` was already in every object, so the
    object gains no module; `drbg.c`'s text grows from 240 to 313 bytes
    and `ch_drbg_seed`'s frame from 8 to 128 bytes on Cortex-M3 (Arm GNU
    gcc 15.3, `-Os`), measured with `-fstack-usage`. The call runs at
    boot, beside no handshake, so no stack peak bench/sram.sh reports
    moves. Under the two riscv32 gcc specs, `drbg.c`'s branch ceiling
    rises from 9 to 10: the test of `seed_len` and a stack-protector
    canary replace the copy loop's back edge, and neither reads a seed
    byte. Gain: the documented recipe links and runs, and a part with no
    hash of its own seeds from several sources in one call.

    What this entry does not change: rewriting the seed file and both
    reseed recipes read generator output, which takes a `ch_rand_bytes`
    call. The packaged object kept `ch_rand_bytes` local, so an image that
    linked the object could not follow those three steps. Entry 67
    exports it.

    Two alternatives were considered and rejected. Exporting a
    `ch_sha256` under `RAND=drbg` adds a sixth public call, and adds it
    because one recipe needed it, not because the API calls for a hash.
    Fixing only the documentation leaves a part with no SHA-256 of its
    own with nothing to hash with.

67. **A `RAND=drbg` object exports `ch_rand_bytes`.** docs/entropy.md has
    the image read generator output three times: it rewrites the seed file
    at boot, it reseeds when entropy arrives later, and a part with a TRNG
    reseeds on a schedule. The packaged object kept `ch_rand_bytes` local,
    so an image that linked it had no call that returned generator output,
    and entry 66 left those steps as a known gap. Camilo chose on
    2026-09-26 to export the call.

    - **The export.** `PUBLIC_RAND` is `ch_drbg_seed ch_rand_bytes`, so a
      `RAND=drbg` object exports six calls, and seven under a ca mode.
    - **An image that also defines `ch_rand_bytes`.** Before, the object
      used its own generator and the image's definition was never called.
      Now the link fails with a duplicate symbol, which names the mistake
      at build time.
    - **Pairs of objects (entry 61).** Two `RAND=drbg` objects still do not
      link, and the linker now names `ch_rand_bytes` beside
      `ch_drbg_seed`. A `RAND=drbg` object beside a `RAND=extern` one links
      when the image defines no `ch_rand_bytes`, and the `RAND=extern`
      object then draws from the other's generator. The image has one
      generator, as entry 61's rule of one entropy source per image asks.
      That generator is single-task (`drbg.h`), so an image that runs
      sessions on several threads keeps `RAND=extern` everywhere.
    - **The check.** `test/entropy_recipe.c` now rewrites its seed file
      and reseeds with `ch_rand_bytes` before its handshake, and
      `lib-check RAND=drbg` links it against the object, so a
      `ch_rand_bytes` made local again fails there.

    Cost: one more public call, and a `RAND=drbg` image's hook has a name it
    must not also define. Gain: every step docs/entropy.md gives can be
    followed with the packaged object alone.

    The alternative, rewriting the three steps to need no generator
    output, was rejected: it drops the seed-file rewrite, the step that
    keeps two devices imaged from one flash from replaying one stream.

68. **A `SUITE=aesgcm` build runs both AES-GCM suites on `AES=extern`, and
    the build states the peripheral's timing with
    `CH_AES_EXTERN_CONSTANT_TIME`**
    ([#177](https://github.com/c4milo/chapulin/issues/177)). Entry 58 held
    the suites to `AES=hw`, so a part with an AES peripheral and no AES
    instructions could not offer them. `AES=extern` already left QUIC's
    public keys to the image's `ch_aes_block`. Camilo decided on
    2026-09-26 to let that hook take traffic keys too, over both TCP
    transports and QUIC.

    - **The hook takes a key length.** It is
      `ch_aes_block(key, key_len, in, out)`, with `key_len` `AES_128_KEY`
      or `AES_256_KEY`. `aes_extern.c` gains `aes_expand_round_keys_256`
      and `aes_cipher_block_256`: the first stores the 32 key bytes where
      the round keys go and zeros the rest, and the second passes them to
      the hook with length 32, as the AES-128 pair does with 16. So
      `SUITE=aesgcm` holds `TLS_AES_128_GCM_SHA256` and
      `TLS_AES_256_GCM_SHA384` under every `AES` value it takes.
    - **A separate timing flag.** `ct.h` admits `-DCH_SUITE_AES_GCM` on
      `AES=hw` with `CH_NATIVE_AES`, on `AES=runtime` with the same
      statement since entry 81, or on `AES=extern` with
      `CH_AES_EXTERN_CONSTANT_TIME`, and refuses every other pairing,
      `AES=soft` included. `CH_AES_EXTERN_CONSTANT_TIME` is the firmware
      author's statement, from the vendor, that the peripheral behind
      `ch_aes_block` runs in constant time for 16-byte and 32-byte keys.
      The Makefile never writes it, as it never writes `CH_NATIVE_AES`,
      and `lint-trust-separation` bans both from every suite object's
      defines. The test binaries state it on their own lines. The build
      record leaves it out for entry 56's reason: no public layout or
      bound reads it.
    - **What the flag covers.** The AES blocks, and nothing else. Under
      `AES=extern`, GHASH runs on `gcm.c`'s portable multiply: 128 masked
      steps per block, with no table, no multiply instruction and no
      branch on a subkey bit, and `lint-wide-multiply` holds its branch
      count. So the flag claims nothing about GHASH. It claims nothing
      about what the hook or the peripheral keeps after a call either,
      such as a key register or a cached expansion; `aes_block.h` leaves
      that to the image, and this tree wipes its own copies, the stored
      key among them, where it wiped the round keys before. And no
      mechanism in this tree can observe a peripheral's timing. The
      statement is the whole of the claim, as `CH_NATIVE_AES` is for the
      instructions.
    - **The rename.** `quic_aes_extern.c` is now `aes_extern.c`, because a
      suite build compiles it over TCP, so it is no longer QUIC-only
      (INV-27). `quic_aes_soft.c` keeps its prefix: its S-box is indexed
      with the key, so a suite build refuses it, and the one suite build
      that holds it, an `AES=runtime` QUIC object, runs QUIC's public keys
      alone on it (entry 81).
    - **The tests.** Every `AES=extern` test binary links
      `test/aes_extern_hook.c` as the hook: `quic_aes_soft.c`'s cipher
      under other names, for both key lengths, which aborts on any other
      length. Over it run FIPS 197, SP 800-38D and RFC 9001 Appendix A,
      RFC 8448's record, the QUIC suite computation, both loop tests, the
      Wycheproof AES-GCM suite, the AES rows of the Lean differential,
      and e2e's client and server against OpenSSL under each suite. None
      needs an AES instruction, so every host runs them. The
      `aes_extern` proof holds the four entries to the hook's contract
      over a stub of it.

    Cost:

    - The hook's signature changes. An image that defined the old
      three-argument hook still links, because C checks no signature at
      link time, and that hook then takes the key length for its input
      pointer. No known image defines the hook; colibri and cocuyo do
      not.
    - A part whose peripheral has no AES-256 cannot build the suite with
      `AES=extern`, and keeps ChaCha20.
    - A second timing statement a firmware author must make and answer
      for. It is as weak as `CH_NATIVE_AES`: this tree cannot check it.
    - A traffic key now leaves code this tree compiles. Before this entry,
      every suite build ran its traffic keys on instructions the compiler
      emitted from this tree's sources. Now a suite build can hand them
      to a function the image supplies, whose code nobody here reads.
    - `make check` builds and runs five more binaries, a third Wycheproof
      leg and one more `lib-check` object; `make diff` runs one more
      binary, and `test/e2e.sh` ten more legs.

    Gain: a part with an AES peripheral offers the suite RFC 9846 §9.1
    makes mandatory, and the SHOULD one beside it, over every transport,
    and the suite build is no longer host-only.

    Three alternatives were considered and rejected.

    - **AES-128 alone under `AES=extern`.** It keeps the hook's signature
      and serves the mandatory suite. It was rejected because
      `SUITE=aesgcm` would then name two suites under `AES=hw` and one
      under `AES=extern`, so which suites a build holds would depend on a
      second axis, and a `ch_srv_cfg.cipher_suites` order that names
      `TLS_AES_256_GCM_SHA384` would be valid in one build and refused in
      the other.
    - **A second hook for AES-256.** `ch_aes_block_256` beside the 16-byte
      hook would keep an old definition linking. It was rejected because
      it doubles what the image implements and what the INV-26 rule
      matches, while a part with AES-256 serves both lengths from one
      peripheral driver; and no known image defines the old hook, so its
      signature protects nobody.
    - **Reusing `CH_NATIVE_AES`.** One define for both values. It was
      rejected because `CH_NATIVE_AES` states the timing of the AES
      instructions and of the carry-less multiply, and an `AES=extern`
      object runs neither: its blocks are the peripheral's and its GHASH
      is the portable multiply. One define would let a statement about
      one piece of silicon be read as a statement about another.
      `test/quic-builds.sh` refuses each flag on the other's value.

69. **A Zig project depends on chapulin as a package: `build.zig` builds the
    object `make lib` builds, and `make lint-zig-build` holds the two builds
    to each other.** colibri linked a `bin/*.o` from a checkout its caller
    had built with make. Camilo decided on 2026-09-26 that the Makefile
    stays the source of truth, that a Zig build beside it must produce the
    same object, and that a check in `make check` compares the two. The
    Zig version is colibri's, 0.16.0.

    - **The options.** `b.dependency("chapulin", .{ ... })` takes the
      Makefile's variables under their own names and values: `TRANSPORT`,
      `ROLE`, `TRUST`, `SUITE`, `AES`, `RAND`, `EXPORTER`, `KEYLOG`, `KEX`,
      `X25519` and `WIDEMUL`. The three hardware statements a builder adds
      to make's `CFLAGS`, `CH_NATIVE_AES`, `CH_AES_EXTERN_CONSTANT_TIME` and
      `CH_NATIVE_MUL128`, are options of their own that default off, so a
      build that needs one and lacks it stops at `ct.h`, as make's does.
      `build.zig` repeats each axis block of the Makefile as one function,
      and refuses the same combinations with the same words. `AES=hw` adds
      the target's AES and carry-less multiply features, as
      `AES_HW_CFLAGS` adds flags for cc.
    - **What a dependent gets.** The named lazy path `chapulin.o`, the
      localized object, and `include`, the directory of the headers. The
      dependent compiles the headers under the object's defines, as a C
      program does, and calls `ch_build_matches` once (entry 56). There is
      no static library: the object links with one `addObjectFile` call,
      and Zig 0.16's archiver leaves an odd-sized last member unpadded,
      which Apple's nm and llvm-ar refuse to read. Entry 70 adds the
      module `chapulin`, so a Zig dependent no longer writes the defines.
    - **One object.** `addObject` over every source partially links them
      with Zig's own linker, for ELF and Mach-O, as `ld -r` does for make.
    - **The localizer.** `tools/localize_symbols.zig` does to that object
      what `objcopy -G` and `nmedit -s` do to make's: every defined symbol
      but the public names becomes local. In ELF32 and ELF64 of either byte
      order it sets STB_LOCAL, moves the locals before the globals, rewrites
      the symbol table's sh_info, and renumbers the symbol index in every
      relocation, section group and SHT_SYMTAB_SHNDX entry. It clears the
      sh_link of SHT_LLVM_ADDRSIG, which marks that table stale the way
      `ld -r` does, and lld then ignores it. In 64-bit Mach-O it clears
      N_EXT and N_PEXT, reorders the table into LC_DYSYMTAB's three ranges,
      rewrites the ranges, renumbers every external relocation and indirect
      symbol entry, and rewrites a localized variable's N_GSYM debugging
      entry as nmedit does. No section moves and no size changes.
    - **What it refuses.** Anything it cannot rewrite in full, rather than
      a guess: another format, a section or load command that may hold
      symbol indices it does not know, a common symbol, a name to keep that
      the object does not define, and a MIPS GOT16 or CALL16 relocation
      against a symbol it would make local. The MIPS ABI reads those two
      differently against a local symbol, so localizing position
      independent MIPS code changes what it computes; objcopy does that
      without a word, and lld only warns. A MIPS object compiled without
      PIC has neither relocation.
    - **Flags.** The defines, `-std=c11` and `-O2` are make's, and so are
      the warnings. Zig adds `-DNDEBUG`, which nothing here reads, `-fPIC`
      and a kept frame pointer. It turns on no stack protector, which
      Apple's clang and Ubuntu's gcc turn on by default, and on Linux no
      `_FORTIFY_SOURCE`, which Ubuntu's gcc defines by default. The comment
      above `cflags` in `build.zig` lists each and why it does not change
      what the object computes or exports.
    - **The check (INV-36).** `test/zig-build-check.sh` copies exactly the
      files `build.zig.zon`'s `.paths` names, which is what a dependent
      receives, after requiring that list to name every root source and
      header git tracks. It builds the default object and colibri's four
      both ways, requires the same sources, defines and exports, links
      `test/build_test.c` against each Zig object under make's defines, and
      links the tcp-nonblocking `ROLE=both` and QUIC objects into one image
      and runs it. check-slow repeats the comparison over every `lib-check`
      leg's configuration. `test/localize-check.sh` compares the localizer
      with `llvm-objcopy -G` on nine ELF targets, big-endian mips32r2 among
      them, and with `nmedit -s` as well on two Mach-O targets, and links
      every result. Five mutants break `build.zig` or the localizer.
    - **The pin.** `tools/toolchain.env` pins `ZIG_VERSION` and the hash of
      the x86_64 Linux tarball, `.github/actions/install-zig` checks the
      download against it, the check workflow's `check`, `slow` and
      `mutants` jobs and the nightly's violation job install it, and
      `lint-toolchain` checks the version on every machine.

    Cost:

    - The Makefile's axis logic exists twice, and a change to an axis is
      made in both files. The check catches a change made in one of them
      in each configuration it builds; a combination it does not build is
      caught when a dependent builds it.
    - `make check` needs zig. `lint-zig-build` takes 8 s with every object
      built and 90 s with none, and check-slow adds 37 s.
    - About 1,300 lines of Zig, `build.zig` and the localizer, that this
      tree reads and tests as it does its C.

    Gain: a Zig project builds chapulin with `zig build`, for any target
    Zig compiles C for, with no make, no binutils and no Xcode tools, and
    links an object that exports what `lib-check` holds make's to.

    Two alternatives were considered and rejected.

    - **Host `ld -r` and `objcopy` or `nmedit`, run from `build.zig`.** It
      would repeat the Makefile's recipe, and it would tie a Zig build to
      the host's tools: macOS ships no objcopy, `nmedit` reads no ELF, and a
      host linker partially links only its own target's objects, so a
      cross build would need a binutils per target. `zig objcopy` in 0.16
      has no option that keeps some globals and localizes the rest.
    - **A plain static library whose internal symbols stay global.** It
      is what Zig builds with no tool of ours. But every internal name is
      then global, so two objects of different transports define the same
      names and one image cannot link both (entry 61), an application's own
      name can collide with one, and the export list `lib-check` holds
      means nothing for that object.
70. **The Zig package exports a module of the object's API, which
    translate-c makes from the public headers under the defines
    `build.zig` compiled that object with.** The public headers change
    shape with the object's defines: fields of `ch_cfg` and `ch_tls`
    appear and disappear, and array sizes change. A Zig program used to
    write the define list for its own `@cImport` by hand. A wrong list
    compiles, links and corrupts memory at run time, and only
    `ch_build_matches` at startup catches it. colibri's list was already
    wrong: it left out `HKDF_LABEL_MAX=32`, which `EXPORTER=on` adds.
    colibri also links objects of two transports into one image, and
    one `@cImport` cannot include `tls.h` twice under two sets of defines.
    Camilo decided on 2026-09-26 that the package exports the module, and
    that `ch_build_matches` stays as the run-time check.

    - **The module.** `build.zig` writes `chapulin.h`, which includes the
      headers that declare what the object exports and imports.
      translate-c translates it for the object's target under every `-D`
      in the flag list the sources compile with. Both take their defines
      from that one list, so the object and the module cannot differ. Each
      dependency gives a module of its own, so colibri's image of two
      transports imports two modules and links two objects:

      ```zig
      const h2 = b.dependency("chapulin", .{
          .target = target,
          .RAND = .@"extern",
          .TRANSPORT = .@"tcp-nonblocking",
          .ROLE = .both,
          .TRUST = .webpki,
          .EXPORTER = .on,
      });
      const quic = b.dependency("chapulin", .{
          .target = target,
          .RAND = .@"extern",
          .TRANSPORT = .@"quic-nonblocking",
          .ROLE = .both,
          .TRUST = .webpki,
          .SUITE = .aesgcm,
          .AES = .hw,
          .KEYLOG = .on,
          .CH_NATIVE_AES = true,
      });
      module.addImport("chapulin_h2", h2.module("chapulin"));
      module.addImport("chapulin_quic", quic.module("chapulin"));
      module.addObjectFile(h2.namedLazyPath("chapulin.o"));
      module.addObjectFile(quic.namedLazyPath("chapulin.o"));
      ```

    - **The name.** The module is `chapulin`, the package's name. A Zig
      package names its main module after itself, and this module is the
      object's API for Zig, as `chapulin.hpp` is its API for C++.
    - **The headers.** The `declarations` table in `build.zig` names the
      header that declares each name an object can export and each hook it
      can import (`docs/porting.md`). `chapulin.h` includes the headers of
      the names one object exports and imports, and a name the table
      lacks stops the build. So a QUIC client's module declares no
      `ch_connect`, which that object does not define, and a CA mode's
      module declares `ch_pubkey_from_pem`.
    - **What translate-c handles.** Zig 0.16.0's translate-c translates
      every public struct, union, enum constant, function pointer field
      and call. It turns `_Static_assert` into a comptime check. It turns
      the static inline `ch_build_matches` into a Zig function whose
      `sizeof` terms become `@sizeOf` of the translated types, so the
      comparison checks the layout the Zig program itself uses. It makes
      the incomplete AES key types (`aes_public_key`, `aes_traffic_key`
      and `aes_key_schedule`) opaque, so a Zig program cannot build one,
      as a C file cannot (INV-26). No public header has a bit field or a
      flexible array member. The macros that give a call its transport's
      symbol name, `ch_srv_check` and `ch_pubkey_from_pem`, become
      constants that name an extern function, and a Zig program calls
      `c.ch_srv_check` as a C program does. Two of chapulin's macros do
      not work. `CH_ASSERT` uses `__FILE__`, which translate-c does not
      translate, and no caller needs it. `ch_build` becomes a constant
      whose value is an extern variable, and Zig refuses to evaluate it,
      so a program names the transport's record,
      `&c.ch_build_info_quic_nonblocking`. The module declares only its
      own transport's record, so a wrong name stops the compile.
    - **The check (INV-36).** `test/zig-build-check.sh` copies
      `test/zig-consumer`, a Zig project that depends on the staged
      package as colibri does. For each configuration it builds
      `matches.zig`, which imports the module and links the object. The
      program compiles only when the module declares every name the
      object exports, and it requires `ch_build_matches` to return 1. For
      colibri's two objects it builds `pair.zig`, which imports both
      modules, links both objects and starts a client on each.
      `inv36-zig-module-drops-define` translates the module without
      `-DCH_EXPORTER`, and `inv36-zig-module-misses-header` names the
      wrong header for the tcp-nonblocking server's calls. The check
      catches both.
    - **The lengths the headers name.** A module that declares every
      export can still lack a constant a public header sizes a field by.
      colibri's QUIC server could not name the ticket key's length,
      which `srv_cfg.h` cited and only `srv_ticket.h` defined, until
      `64e2f25` moved it into `srv_cfg.h`. `tools/public-constants.py` now preprocesses
      each object's headers under its defines, comments kept, and lists
      every name shaped like a length or a cap in a comment of a public
      header. It fails when the consumer cannot see one, and
      `matches.zig` declares and evaluates each. Across the 21
      configurations it found five more comments naming four internal
      constants, and those comments now give the number instead.

    Cost:

    - It serves Zig alone. A C program, firmware among them, still writes
      its own defines, and only `ch_build_matches` catches a mistake.
    - The module is translate-c's output, and translate-c changes between
      Zig releases: 0.16.0's is built on Aro. Zig is pinned at 0.16.0, so
      translate-c changes only when the pin moves, and the pull request
      that moves it runs the check against the new output.
    - From nothing built, `lint-zig-build` takes about 25 s longer: 66 s
      against 39 s before, and 103 s against 81 s, in two pairs of runs on
      an M-series Mac with a load average above 18. With everything
      built, `test/zig-build-check.sh` takes 3.5 s where it took 3.0 s.

    Gain: a Zig program names no define. Its types come from the defines
    the object compiled with, so no program keeps a list that can go out
    of date as colibri's did, and each object in an image of two
    transports has its own module.

    Two alternatives were considered and set aside.

    - **A generated configuration header every consumer includes.** `make
      lib` and `build.zig` would write a header that defines the object's
      defines, and every public header would include it first. It would
      serve C firmware as well as Zig. But it changes the public headers
      and the Makefile, so it waits until a C consumer asks for it.
    - **The define list as a file the package exports.** A Zig program
      would read it and pass each define to its own `@cImport` or
      translate-c step. The program still does that work, and every
      consumer writes it again.
71. **A TCP build sets how much plaintext one outgoing record carries,
    `TX_RECORD`, from 512 to 16384 bytes, and the default stays 512.**
    stompy uploads 5 MiB log segments to S3 over a `TRUST=webpki
    TRANSPORT=tcp-nonblocking ROLE=both` object. At 512 bytes a record, one
    segment takes 10,240 records and 10,240 send callbacks, and the 22
    bytes each record adds come to 4.3% of the data. At 16384 bytes it
    takes 320 records, and the overhead is 0.13%. Camilo approved the
    option on 2026-09-26 at stompy's request. This entry amends entry 22.

    - **The value.** `CH_TX_PT` (`cfg.h`) is the most plaintext one
      outgoing record carries. It sits under `#ifndef`, and the Makefile's
      `TX_RECORD=N` writes `-DCH_TX_PT=N` into the object, and `build.zig`'s
      `TX_RECORD` option does the same. `ch_write` and a server's sealed
      flight still put the smaller of `CH_TX_PT` and the peer's
      `record_size_limit` (RFC 8449) into each record, so a peer that asks
      for smaller records gets them.
    - **The range.** 512 is the floor: nothing needs smaller records, and
      every test and proof in this tree runs at 512 or above. 16384 is
      the ceiling, the most plaintext RFC 9846 §5.1 lets one record carry
      (`rfc9846.txt:3514-3516`). The Makefile and `build.zig` take a
      decimal integer with no leading zero, because C reads a leading zero
      as octal. `cfg.h` refuses a value outside the range for a firmware
      tree that builds these sources its own way.
    - **The staging array.** `session.h` names each build's hello literal
      `CH_TX_HELLO`, and `CH_TX_STAGE` is the larger of it and one sealed
      record, `CH_TX_PT + 1 + AEAD_TAG`. At the default the hello still
      wins in every build, so every default `ch_tls` keeps its size byte
      for byte. `handshake.c` and `quic.c` check `CH_HELLO_MAX` against
      `CH_TX_HELLO`, not `CH_TX_STAGE`, because a raised `CH_TX_PT` can make
      the array larger than any hello, and a stale literal would then pass.
      The 2^14 assertion moves to `CH_TX_HELLO` too: the hello ships as one
      plaintext record, while a sealed record's body is ciphertext, which
      §5.2 caps at 2^14 + 256 bytes (`rfc9846.txt:3595-3596`).
    - **The Certificate.** A server streams its Certificate through
      `srv_frag`, which lives on `srv_send_certificate`'s stack frame. Its
      buffer stays `SRV_FRAG_MAX`, 512 bytes, whatever `CH_TX_PT` is, so a
      Certificate still goes out in records of at most 512 bytes. A buffer
      of 16,384 bytes would be four times the 4,096-byte frame budget of a
      `TRUST=webpki` object and more than six times the 2,560 bytes of
      every other (INV-19). A Certificate goes out once per full
      handshake, so larger fragments would save a few records per
      connection.
    - **The receive side.** The option changes what this endpoint sends
      and nothing else. What it receives is bounded by its own
      `cfg.buf_len`, which it advertises as `record_size_limit`, as before.
      A peer of a `TX_RECORD=16384` object receives records of 16,384 bytes
      only when its own buffer holds 16,406 bytes: the record header, the
      plaintext, the inner content type and the tag.
    - **The check.** `bin/webpki_loop_tx_record` is `test/webpki_loop_test.c`
      at `TX_RECORD=16384`: a write of `CH_TX_PT` bytes goes out as one
      record and `CH_TX_PT + 1` bytes as two, a client whose buffer
      advertises a smaller limit gets records of that limit, and 32,868
      bytes move each way between the object's two drivers. The
      handshakes it shares with the default loop count the Certificate's
      three records, which holds `srv_frag` at `SRV_FRAG_MAX`.
      `test/tx-record-builds.sh` compiles each edge of the range in the
      headers, runs it through make and `build.zig`, and checks where
      `CH_TX_STAGE` turns from the hello to the sealed record. `make check`
      runs both, with `lib-check` and `lint-stack`, on the `TX_RECORD=16384`
      object, and check-slow's Zig roster builds that object both ways.
      Five mutants in `test/violations/` break the rules:
      `inv19-srv-frag-sized-by-tx-record`, which the loop catches, and
      `inv38-tx-record-past-2-14`, `inv38-tx-record-quic-accepted`,
      `inv38-tx-record-makefile-quic-accepted` and
      `inv36-zig-build-tx-record-past-2-14`, which the script catches.

    Cost:

    - `ch_tls` grows by `CH_TX_PT + 17` bytes less the build's hello
      literal, rounded to the struct's alignment. Measured with a `sizeof`
      probe under Apple clang 21 on arm64, stompy's object, `TRUST=webpki
      TRANSPORT=tcp-nonblocking ROLE=both`, goes from 3,264 bytes to 17,264
      at `TX_RECORD=16384`, and its `ch_record` from 4,480 to 18,480. The
      formula gives 16,401 - 2,396 = 14,005 bytes and the struct grew by
      14,000, because `tx` is its last field and 5 of those bytes fill the
      padding the old struct already carried at its end. The default
      classic client would go from 1,144 bytes to 16,928.
    - A device cannot spare that, which is why the default stays 512 and
      the figures in docs/performance.md stay the default build's.
    - The build record holds `CH_TX_STAGE` and not `CH_TX_PT`, so
      `ch_build_matches` tells an object and a consumer apart only where
      the two values give different arrays. A value whose sealed record
      stays under the hello, such as 1,024 in a `KEX=pq` build, changes no
      layout, and the record cannot see it.

    A `TRANSPORT=quic-nonblocking` object refuses the option, in the
    Makefile, in `build.zig` and in `session.h`. RFC 9001 §4.1.3 removes
    the record layer (`rfc9001.txt:462-464`), so a QUIC build seals no
    record and stages its hello alone, and the one place it reads
    `CH_TX_PT` is `srv_out_limit`, which only `srv_frag` reads there and
    `SRV_FRAG_MAX` caps anyway. A value there would change nothing, so the
    build refuses it rather than accept a setting it ignores.

    Two alternatives were considered and set aside.

    - **A transmit buffer the caller supplies in `ch_cfg`,** the way
      `cfg.buf` holds received records. One object could then send at
      either size. But every build's `ch_cfg` would carry a pointer and a
      length, every init call a second buffer rule, and no consumer needs
      one object at two sizes.
    - **Sealing straight from the caller's bytes,** a scatter-gather
      `rec_seal` that writes no staged copy. It would cost `ch_tls` nothing
      at any size, and it is a second sealing entry point, which INV-1
      exists to prevent.
72. **Where a record ends, how much plaintext a send buffer holds, and a
    ticket's age are computed in C, not by the caller.** Camilo approved a
    Zig API that forwards to C and holds no TLS logic, and on 2026-09-26
    he decided that three computations colibri makes in Zig move into C
    first: `whole_record_len`, `sealable_len` and `owed_len_max` in its
    record adapter, and the obfuscated ticket age in its resumption code.
    Each one is a TLS rule, so a caller that computes it keeps a copy of
    the rule that no proof and no test here checks.

    - **`ch_record_whole_len(p, n)`** (`tcp_nonblocking.h`,
      `tcp_nonblocking_frame.c`, every `TRANSPORT=tcp-nonblocking` object in
      either role). It answers the length of the record at the front of
      `p`, header included, or 0 while `p` holds less than that record.
      A caller passes that many bytes to `ch_read`, whose `recv` must hand
      over whole records. A length field above 2^14 + 256, which RFC 9846
      §5.2 forbids a peer (`rfc9846.txt:3595-3596`), answers `REC_HDR`, the
      header alone: `ch_read` reads those five bytes and refuses the
      record, where an answer of 0 would leave the caller waiting for a
      body that must not come.
    - **`ch_writable_len(t, cap)`** (`tls.h`, `tls.c`, both TCP
      transports). It answers the most plaintext one `ch_write` seals into
      `cap` bytes of records. `ch_write` and this call read the record
      limit, the smaller of `peer_limit` and `CH_TX_PT` (INV-38), through
      one helper, `record_plaintext_max`, so the two cannot disagree about
      it.
    - **`CH_ALERT_RECORD_LEN` and `CH_KEY_UPDATE_RECORD_LEN`** (`tls.h`),
      `REC_OVERHEAD + 2` and `REC_OVERHEAD + 5`, which `tls.c` asserts are
      24 and 27 bytes. `ch_close` sends one alert record. `ch_read` sends
      one KeyUpdate record for each KeyUpdate that asks for an answer,
      and an alert record when it fails. A record carries at most one
      KeyUpdate, as its last message, because RFC 9846 §5.1 lets no
      handshake message span the key change it makes (INV-39), so a
      record gets at most one answer; `bin/unit` checks that. This entry
      first said one record could carry two KeyUpdates and get two
      answers, which is the record INV-39 refuses.
    - **`ch_ticket_obfuscated_age(ticket, age_ms)`** (`ticket.h`,
      `handshake_post.c`, every object with a client). It answers
      `age_ms + ticket->age_add` modulo 2^32 (RFC 9846 §4.3.11.1,
      `rfc9846.txt:2574-2578`) and reads no other field, so a copy of the
      ticket kept after `on_ticket` returned serves. `age_ms` is 64 bits
      wide, like the configuration field below, so a caller passes one
      value to both and the reduction happens here.
    - **`ch_cfg.ticket_age_ms` and `ch_cfg.ticket_lifetime_s`.** RFC 9846
      §4.3.11.1 says a client MUST NOT use a ticket older than its
      `ticket_lifetime` (`rfc9846.txt:2572-2574`), and §4.6.1 that it MUST
      NOT use one more than 7 days after issuance whatever the lifetime
      (`rfc9846.txt:3259-3261`). With `resumption` set, `ch_connect`,
      `ch_record_init` and `ch_quic_init` return `CH_EINVAL` before a byte
      is sent when the age is above the lifetime or above
      `CH_TICKET_LIFETIME_MAX`, 604,800 seconds. An age equal to either is
      still offered. The rule is one predicate, `hspost_ticket_age_ok`
      (`handshake_post.h`), which `tls.c`'s two `tlsi_config_ok`
      definitions and `quic_config_ok` each call.
    - **What 0 means.** An age of 0 is a ticket that arrived this
      millisecond. A lifetime of 0 is one the caller did not give, and the
      age is then held to seven days alone. That reading is sound because
      `handle_ticket` now drops a NewSessionTicket whose `ticket_lifetime`
      is 0, which §4.6.1 says to discard at once
      (`rfc9846.txt:3258-3259`), so no ticket with that lifetime is handed
      to `on_ticket`. A configuration that sets neither field, as every one
      written before them does, is refused nothing. A lifetime above seven
      days, which a server must not send, keeps the seven days.
    - **Symbol names.** An image links one object of each of two
      transports (entry 61), and every client object exports
      `ch_ticket_obfuscated_age`, so it joins `TRANSPORT_NAMED`: its symbol
      is `ch_ticket_obfuscated_age_tcp_blocking`, `_tcp_nonblocking` or
      `_quic_nonblocking`, and `ticket.h` maps the name a caller writes,
      as `srv.h` maps `ch_srv_check`. `build.zig` names the same symbols.
      `ch_writable_len` keeps its name: the two TCP transports export it
      beside `ch_write`, and entry 61 refuses an image of those two
      objects for `ch_read`, `ch_write` and `ch_close` already.
      `test/lib-pair-check.sh`'s refused pair now names it. Each client
      half that script links, and each half of
      `test/zig-consumer/pair.zig`, calls its own object's ticket call.
    - **The header.** `ch_ticket` and `CH_TICKET_ID_MAX` moved from
      `cfg.h` to `ticket.h`, which `cfg.h` includes. `cfg.h` was at the
      500-line limit, and the ticket, the call that reads it and the
      seven-day cap are one concern.
    - **The build record.** The two fields grow `ch_cfg`, and with it
      `ch_tls`, `ch_record` and `ch_quic`: 16 bytes on arm64, 1,144 to
      1,160 for the default `ch_tls`, and 8 on rv32, 1,072 to 1,080
      (`bench/results-sram.csv`). `ch_build_matches` compares
      `sizeof(ch_cfg)`, which grew in every build measured: 152 to 168
      bytes on arm64, and by 8 or 12 on rv32 and Cortex-M3. A consumer
      compiled under these headers and linked against an object built at
      `02515f2` read `sizeof_ch_cfg` 152 against its own 168 and exited 1,
      in the default, the webpki tcp-nonblocking `ROLE=both`, the webpki
      QUIC `ROLE=both` and the tcp-nonblocking server configurations.
    - **The proofs.** `record_whole_len` proves the whole contract over
      every `n` up to 2^20, in a heap object exactly `n` bytes long.
      `writable_len` proves the call safe over any `peer_limit` and `cap`,
      and runs its answer through the real `ch_write` for every `cap` up
      to 1,603 bytes and every `peer_limit` from 63: what `ch_write` sends
      fits `cap`, and one byte more does not. The second claim is an
      equality over a division, and at 16 bits of `cap` it returned no
      verdict in 600 seconds, so `bin/unit` checks the answer at
      `SIZE_MAX`. `quic_config_webpki` proves the age rule over any age
      and lifetime, and `handshake_post` that no ticket with a lifetime of
      0 is handed over. Thirteen mutants in `test/violations/` break the
      rules, and each is caught.
    - **The spec.** Unchanged. `spec/lean/Spec/Record.lean` models one
      record's protection, and its `seal_size` theorem states the
      22 bytes a record adds, which is the size `writable_len`'s
      `rec_seal` stub asserts. It models no byte stream cut into
      records, no write loop and no configuration refusal, and
      `Spec/Handshake.lean` models a NewSessionTicket as a message in the
      handshake's order and reads none of its fields. The three
      additions are length arithmetic and one configuration rule, which
      CBMC proves on the C itself, so a spec model would add a second
      statement of the same arithmetic and a differential that compares
      two copies of one formula.

    Cost:

    - `ch_cfg` grows by 16 bytes on arm64 and by 8 or 12 on rv32, and
      every session struct with it: the default `ch_tls` by 16 and 8.
    - Every client object exports one more call and every TCP object one
      more; every tcp-nonblocking object exports `ch_record_whole_len`.
    - `ch_writable_len` divides once, so `tls.c` takes a ceiling of 1 in
      `lint-wide-multiply` beside `sha3.c`'s, and `RV_ALLOWED` records its
      `__mulsi3` and `__udivsi3` on rv32ic. Both operands are public: the
      caller's buffer length and a record's length. It counts the overhead
      per record rather than taking the remainder of the division, because
      gcc turned that remainder into a second division on riscv32.
    - `ch_cfg` carries both the age and `obfuscated_age`, which the
      caller computes from it. C cannot check that the two agree, because
      `ch_cfg` carries no `age_add`.

    Gain: the Zig API and colibri keep no TLS rule of their own, and the
    ticket lifetime that RFC 9846 puts on a client is checked where every
    client entry checks its configuration.

    Rejected:

    - **`ch_record_read` and `ch_record_write`, bytes in and bytes out,**
      the design's option (b). A tcp-nonblocking session would then need
      no `send` or `recv` after the handshake, but a connected session
      would have two ways to read and two to write, each with a contract
      and tests of its own, where the two calls above read a header and
      a limit and change nothing.
    - **Leaving the three in the caller,** the design's option (c). It
      keeps a record rule outside C, which is what the API was approved
      to avoid.
    - **A 32-bit age.** RFC 9846 says 32 bits hold any plausible age, and
      an age kept in 32 bits wraps after about 49.7 days, where a
      ticket reads as young again. The field is 64 bits wide and the call
      reduces its sum itself.
    - **Refusing a lifetime of 0 with `resumption` set.** Every
      configuration written before the field existed sets 0, so every
      resumption in them would be refused.
73. **The Zig package's module `chapulin` is a Zig API that forwards to the
    C calls and carries the object, and the translated headers are its
    `chapulin.c`.** colibri and cocuyo each wrote an adapter over the
    translated headers: callbacks, `ch_cfg` building, record framing and
    error codes. Camilo approved an API that replaces them on 2026-09-26,
    colibri and cocuyo reviewed its design, and entry 72 moved the three
    computations it would otherwise have held into C. This entry amends
    entry 69, whose dependents added the object themselves, and entry 70,
    whose module becomes `chapulin.c`. docs/zig.md is the API's reference.

    - **What it adds.** Values a session is configured from and the
      `ch_cfg` each builds (`toCfg`), one Zig error per result code,
      the callbacks C calls, which copy bytes between the caller's
      slices and the session, and storage: the receive buffer, the
      latest ticket and the peer's transport parameters. It is
      chapulin.hpp's kind of wrapper. A record's length, a write's size
      and a ticket's age come from `ch_record_whole_len`,
      `ch_writable_len` and `ch_ticket_obfuscated_age`, so the API keeps
      no TLS rule.
    - **The module.** `build.zig` makes the translated headers a private
      module, imported by the API as `chapulin_c` and declared as
      `chapulin.c`, and roots the module `chapulin` at `chapulin.zig`.
      Zig 0.16.0 refuses one file in two modules of one program, and
      colibri imports the modules of two objects, so `build.zig` copies
      the three files into a directory of each configuration's own, with
      `defines.txt`, the object's define list, beside them.
    - **The object.** The module carries it with `addObjectFile`. A
      program links it once however many of its modules import the
      module, and a program that also adds `chapulin.o` defines every
      public name twice and fails to link. So `test/zig-consumer` adds no
      object, and neither does the example in docs/building.md.
    - **Per configuration.** Each file declares every call, and a call
      whose C name the object lacks is a `@compileError` naming the
      option that adds it. The headers declared the client's
      `ch_record_init` and `ch_quic_init` in a `ROLE=server` object too,
      which defines neither, so the client sessions first required the
      client's ticket call as well. Each header now declares a call only
      in the objects that define it, which matches.zig holds (INV-36),
      and the sessions ask for the call itself. A TCP object's `Error`
      lacks `Discard` and `AeadLimit`, whose codes only a QUIC object's
      headers declare.
    - **Error sets.** Each call's set is the part of `chapulin.Error` its
      C call returns, which a reading of every return path confirmed for
      the 22 calls that return a code. `fromCode` maps a code, and panics
      on one the call's header says it never returns. It is public, for a
      program that calls a function the API leaves out.
    - **Reading and writing.** `read` passes at most one whole record to
      `ch_read`, and its `consumed` is 0, a record, or the 5-byte header
      of a record no peer may send, which `ch_read` then refuses.
      `ch_read` answers a KeyUpdate that asks for one, and a record
      carries at most one KeyUpdate (INV-39), so `reply` takes at most
      one record of `key_update_record_len` bytes, and one of
      `alert_record_len` when the read fails. `write` is all or
      nothing: it seals nothing when `pt` is longer than
      `ch_writable_len` allows. `close` is `ch_close`, which sends the
      close_notify and wipes the keys.
    - **Tickets.** A Ticket holds the `ch_ticket` by value and the
      identity bytes, so `ch_ticket_obfuscated_age` takes it as it is and
      `sizeof_ch_ticket` in the build record covers it. `takeTicket`,
      `recordClose` and the QUIC `close` zero the slot.
      `Ticket.fromFields` rebuilds one from stored fields, and
      `Ticket.fromOnTicket` copies what `on_ticket` hands over.
    - **The reserved `keyUpdate`.** No C call starts a record-mode
      KeyUpdate, so a record session's `keyUpdate` is a `@compileError`.
      When C gains the call, RFC 9846 §4.7.3's cap on updates sent gets a
      result of its own.
    - **The design's open questions.** Entry 72 settled the first two: the
      age is 64 bits wide in `ch_cfg` and in `ch_ticket_obfuscated_age`,
      so the Zig passes it whole and truncates nothing, and the call
      reads `age_add` alone, so a ticket whose identity pointer is null
      serves. Camilo decided the third: stompy's object, `TX_RECORD=16384`,
      runs in `check`.
    - **The check (INV-36).** `test/zig-build-check.sh` now builds six
      configurations, stompy's among them, and for each runs `unit.zig`,
      the API's unit tests, and for each `ROLE=both` object `loop.zig`, a
      client and a server of that object against each other through the
      API alone, in record mode and over QUIC. The loops take the r2
      chain, its anchor, its clock and its leaf key from
      `test/webpki_corpus.h`, the fixture the C loop tests use, through a
      translate-c step. Seven mutants break the API or the module, and
      the script catches each.

    Cost:

    - About 1,150 lines of Zig in the three files, each under 500, and
      about 1,170 in `test/zig-consumer`. A change to a public C call
      changes its Zig call in the same commit, as `chapulin.hpp` is kept.
    - `lint-zig-build` builds one more configuration and runs more
      programs. With every object built, `test/zig-build-check.sh` took
      4.2 and 5.1 s where it took 3.65 s; with no Zig build, 41.1 and
      41.7 s where it took 35.2 s, on an M-series Mac with a load
      average between 7 and 14.
    - A program's two objects give two sets of types, so a program that
      serves both converts its own values once per object.

    Gain: colibri, cocuyo and stompy run chapulin through Zig values and
    errors, with no callback and no `ch_cfg` of their own, and the code
    that did that work in three programs is tested here against both
    roles of the objects they link.

    Rejected:

    - **Keeping `chapulin` as the translated module and exporting the API
      as a second module.** colibri's two imports would stay as they are,
      but the package's own name would keep naming the headers rather
      than the API, and a program would still add the object.
    - **The API's unit tests as `test` blocks in its own files.** Zig runs
      a module's tests only when that module is the test's root, and the
      API's files cannot define the hooks the object imports, so the
      tests would need a second copy of the module. They sit in
      `test/zig-consumer/unit.zig`, over the public calls, and run
      against each configuration's module.

    Entry 78 changed one thing here: `ch_write` sends a KeyUpdate by
    itself as the last record an AES-GCM write key seals, no call that a
    caller starts one through is planned, and `keyUpdate` stays reserved.

74. **A server checks every provisioned identity against what its flight
    needs before a session starts, and a refusal inside the flight is
    `CH_EAUTH`.** The Zig API's error table (entry 73) found a server
    flight that returned `CH_EINVAL` after its ServerHello went out:
    `srv_auth.c` returned it when a slot's key lengths did not match its
    scheme or its signer refused the key, and `srv_flight.c` when a
    certificate did not fit its cert_data field. `CH_EINVAL` says nothing
    was sent (cfg.h), and a caller that read it that way would retry a
    dead session. Each of those conditions is a fact about the
    configuration, so a check at entry can find it.

    - **The rules.** `srv_identities_usable` (srv_auth.h) asks of every
      provisioned slot: key lengths srv_cfg.h states, with an RSA
      `pub_len` of at most `SRV_SIG_MAX`, the bytes the flight signs
      into; a private key the scheme's signer takes; and a chain a
      Certificate message can carry (`srv_certificate_fits`,
      srv_message.h). `srv_config_ok`, which `ch_srv_accept`,
      `ch_srv_record_init` and `ch_srv_quic_init` run, and `ch_srv_check`
      ask it. Each rule reads lengths, pointers, two bytes of a public
      modulus and one private scalar, and signs nothing.
    - **The signers own their key tests.** `p256_sign_key_ok` and
      `rsa_pss_sign_key_ok` are the tests `p256_sign` and `rsa_pss_sign`
      already ran, now calls of their own that each signer runs first.
      They read the private key, and `srv_auth.c` reads no byte behind
      `ch_identity.priv`, so each sits in its signer's module.
      `rsa_pss_sign_key_ok` is inline in rsa_sign.h, so rsa_sign.c
      compiles one copy of the test, as it did before, and
      `lint-wide-multiply`, which counts the branches in rsa_sign.c, reads
      the same count. Measured before and after: identical assembly under
      the three clang specs and under mips gcc at -Os, and the same branch
      and multiply counts under mips gcc at -O2 and under Ubuntu's arm and
      riscv gcc at the m3 and rv32 specs' flags.
    - **The chain rule closes a second gap.** A chain whose Certificate
      message runs past the handshake header's 3-byte length field was
      never refused: `srv_build_certificate_header` wrote the length cut
      to its low 24 bits. The same rule refuses it, and a certificate of
      no bytes, which cert_data<1..2^24-1> forbids.
    - **The code inside the flight.** Once the check has passed, a
      refusal inside the flight comes from ECDSA's own signing, no nonce
      candidate in range or an r or s of zero, each below 2^-127
      (p256_sign.h), from key or chain bytes the caller changed after
      init, or from a fault. The ServerHello has gone out by then. The
      code is `CH_EAUTH`, because this side's authentication failed, and
      the alert stays internal_error, which tells the peer the fault is
      local.

    Rejected:

    - **`CH_ASSERT` inside the flight.** CLAUDE.md keeps it for
      programmer error. The nonce refusal is not one, and a fault or a
      caller's later write can cause the others; an assertion would stop
      the whole device for one connection's failure.
    - **A new result code for a local failure.** Every wrapper would map
      it, chapulin.hpp and the Zig API among them, for events the check
      now excludes, where `CH_EAUTH` already says what failed.
    - **`CH_ECAP`.** The flight answers a message that does not fit with
      it, and a signer's refusal is not that.

    Cost: each server init runs the rules, one pass over each chain's
    lengths and one scalar range test per ECDSA slot. And a
    configuration with one broken slot beside a sound one, which served
    every client that selected the sound one, now serves none: init
    refuses it whole, as `ch_srv_check` already did.

    Gain: `CH_EINVAL` from a server means nothing was sent, on every
    path, and a broken identity is found at init rather than at the
    first handshake that selects it.

75. **Every object reports what ended a session through two calls, and a
    session that reads the peer's fatal alert answers it with nothing.**
    colibri could not tell its own failure from its peer's: the alert a
    tcp-nonblocking session chose after the handshake was sent by
    `ch_read` and reported nowhere, because `ch_record_alert` names only
    the handshake's, and a peer's alert was answered with
    unexpected_message, which RFC 9846 §6.2 forbids: on a fatal alert both
    sides close the connection at once (rfc9846.txt:3890-3893).

    - **The calls.** `ch_alert_sent` reads `ch_tls.alert_sent`, which
      each failure funnel writes: `tlsi_fail`, `tcp_nonblocking_fail`
      beside `ch_record_alert`'s field, and `quic_fail` beside
      `ch_quic_alert`'s. `ch_alert_received` reads
      `ch_tls.alert_received`, which `hsr_refuse_alert` writes for every
      TCP reader, and answers 0 in a QUIC object, which carries no alert
      record and declares no such field. alert.h declares both, and
      tls.h and quic.h include it: tls.h is the TCP transports' header
      alone (INV-27), and a QUIC object exports the two calls as well.
      Every object of every transport exports them, so their symbol
      names carry the transport, as `ch_ticket_obfuscated_age`'s do
      (entries 61 and 72). Both fields sit in padding, so `ch_tls`,
      `ch_record` and `ch_quic` keep their sizes in every build
      bench/sram.sh measures.
    - **The peer's fatal alert.** Any 2-byte alert record whose
      description is not close_notify or user_canceled is one, whatever
      its level byte (§6, rfc9846.txt:3779-3782). The call that reads it
      returns `CH_EPROTO`, the code a peer's alert already gave, wipes,
      fails the session and sends nothing, and the funnels write no
      `alert_sent` once `alert_received` is set. A record of the alert
      type of any other length is not an alert (§5.1,
      rfc9846.txt:3475-3478), and every reader now answers it with
      decode_error, where the tcp-nonblocking handshake and the record
      layer answered unexpected_message. close_notify and user_canceled
      keep what they did: after the handshake the first closes the
      peer's direction and the second is read past, and in the
      handshake either ends it with the alert that reader gives any
      record it cannot use.
    - **An alert in the clear during the handshake.** Both handshake
      readers take one whether or not this side has installed its read
      key. A peer protects an alert under its own write key (§6,
      rfc9846.txt:3759-3760), and a client that could not use the
      ServerHello has none, so it answers in the clear to a server that
      already reads protected records. The tcp-nonblocking reader used to
      decrypt such a record and answer bad_record_mac.
    - **Where the post-handshake reader fails.** `hspost_read` now calls
      `tlsi_fail` itself, with bad_record_mac, decode_error or
      unexpected_message, instead of returning a code for `tls.c` to map.
      A wrapper in `tls.c` holding the alert as a local grew `ch_read`'s
      peak stack by 48 bytes; with the call in `hspost_read` it is 16
      bytes lower than before.

    Rejected:

    - **Both declarations in tls.h, with a second pair in quic.h.** Two
      contracts to keep in step, a quic.h already at the 500-line cap,
      and build.zig's header table names one header per call.
    - **A new result code for the peer's alert.** Every wrapper would map
      it, chapulin.hpp and the Zig API among them, and `CH_EPROTO` with
      `ch_alert_received` already says what happened.
    - **Reading an alert in the clear only before the read key.** The
      server would decrypt the alert of a client that failed on the
      ServerHello, fail it with bad_record_mac and answer an alert that
      closed the connection.

    Cost: two more exported calls in every object, and a peer's alert in
    the clear is read during the whole handshake, where nothing
    authenticates its description; it ends a handshake an on-path
    attacker could end anyway by dropping bytes. `ch_read`'s peak stack is
    1,712 bytes, from 1,728, and no struct grew.

    Gain: a caller logs what ended each session through one pair of
    calls on every transport, and neither side answers an alert that
    closed the connection.

    Entry 76 changed one thing here: a tcp-nonblocking driver sends the
    alert of its own handshake failure, and `ch_record_alert` and its
    field are gone.

76. **A tcp-nonblocking driver sends the alert of its own handshake
    failure, sealed once it has a write key, and `ch_record_alert` is
    gone.** A failure in `ch_record_in` or `ch_srv_record_in` wiped every
    key and named its alert in `ch_record_alert` for the caller to send.
    The caller holds no key, so it could send the alert only in the clear.
    RFC 9846 §6 encrypts an alert under the current connection state
    (rfc9846.txt:3758-3760), and a strict peer that already reads
    protected records takes a record in the clear for a bad one. The
    blocking drivers did this right: `tlsi_fail` seals under `ch_tls.wr`
    when `ch_tls.keys` is set.

    - **The seal.** `tcp_nonblocking_fail` writes the alert as one record
      before it wipes: sealed under `ch_tls.wr` when `ch_tls.keys` is set,
      and in the clear before. A client sets `keys` right after the
      ServerHello, and a server right after it has sent its own. The wipe
      then clears every key, so none outlives the failure. The record is
      `CH_ALERT_RECORD_LEN` bytes sealed and `REC_HDR + 2` in the clear.
    - **The client stages it.** The record goes into `ch_tls.tx`, where
      the client stages every record it writes. `ch_record_out` hands it
      over on the failed session, in as many calls as the caller's buffer
      needs, and answers `CH_EINVAL` after the last byte, the answer a
      failed session gave before.
    - **The server pushes it.** The record leaves through
      `cfg.srv.on_record_out` inside the failing `ch_srv_record_in`, after
      the records of the flight that went out first. The push is best
      effort, as `tlsi_fail`'s send is. A failed `recordIn` in the Zig API
      returns no `Progress`, so a server's `outputLen()` returns what the
      last `recordIn` wrote into `output`, a failed one included. The QUIC
      server's `cryptoIn` needs no such call: the caller's `Outgoing`
      keeps its own counts, and a QUIC failure pushes no bytes, because
      the caller seals the CONNECTION_CLOSE (entry 57).
    - **Nothing after the peer's alert.** A failure on the peer's fatal
      alert stages and pushes nothing (§6.2, entry 75).
    - **`ch_record_alert` and its field go.** The call would read 0 after
      every failure now, and `ch_alert_sent` names the alert in every
      case. The field sat in padding, so `ch_record` keeps its size in
      every build.

    Rejected:

    - **Keeping the write key for the caller,** as `quic_fail` keeps a
      level's write keys for `ch_quic_seal_close` (entry 57). The caller
      would need a call to seal with, and the key would outlive the
      failure until the caller made that call. A QUIC caller builds the
      CONNECTION_CLOSE packet around its seal; a record-mode alert is one
      fixed record the driver can finish itself.
    - **A pull for the server's alert.** A server pushes every record it
      writes and has no `ch_srv_record_out` (docs/server.md). One record
      to pull would give the server a second output path.
    - **Keeping `ch_record_alert` for the callers that read it.** It would
      read 0 after every failure, and a caller that sent what it named
      would send nothing.

    Cost: `ch_record_out` returns bytes on a failed session once, a caller
    of `ch_record_alert` no longer links, and a server whose sink refused
    a record pushes the alert into the same sink. A record sealed after a
    refused one is one sequence number ahead of what the peer read, so the
    peer cannot open it unless the refused bytes reached it; the blocking
    drivers have the same limit, and the last item below says why it
    stays.

    Gain: a caller sends the bytes the API hands it and nothing else, and
    a strict peer reads every handshake alert: in the clear before the
    failing side's write key, and protected after. No key survives a
    failure.

    Three cases the change left open are closed the same way in every
    driver:

    - **A refused record names internal_error.** A record the caller's
      transport refused, through `cfg.send`, `cfg.srv.on_record_out` or
      `cfg.srv.on_crypto_out`, kept the handler's default alert,
      decode_error, which says the peer sent a malformed message. RFC 9846
      §6.2 names internal_error for an error unrelated to the peer
      (rfc9846.txt:3979-3981), and `ch_write` already named it for a
      failed send. Only the send call knows that the failure is this
      side's, so each send names it there: `srv_out.c` for the server,
      `send_staged` in `handshake.c` for the blocking client's ClientHello
      and Finished, and `take_key_update` in `handshake_post.c` for the
      KeyUpdate reply `ch_read` sends. A failed receive keeps its reader's
      alert, because a peer that closes the connection fails a receive
      the same way. A tcp-nonblocking or QUIC client sends nothing during
      its handshake: its caller collects the bytes.
    - **The ticket push.** A NewSessionTicket that the sink refused after
      the client Finished failed the tcp-nonblocking and the QUIC server
      with no alert recorded: each wiped its handshake state, `hs.alert`
      among it, before `tcp_nonblocking_fail` or `quic_fail` read the
      alert. Each now returns first. `tcp_nonblocking_fail` then records
      internal_error and seals the alert that `fail` pushes, and
      `quic_fail` records it and keeps the close keys, and each wipes the
      state after. The QUIC server reported 0x0100, which names
      close_notify. The blocking server's `srv_handshake` reads the alert
      before its wipe, so it always recorded one.
    - **The sequence number after a refused record.** The refused record
      used its sequence number, and the driver does not take it back. The
      sink may have written the record whole or in part before it
      reported the failure, so the peer may hold those bytes. Sealing the
      alert under the same number would put two plaintexts under one
      nonce, which breaks ChaCha20-Poly1305 and AES-GCM alike. So the
      alert goes out one number ahead, and it opens only for a peer that
      took the refused bytes, as `test/tcp_nonblocking_failure_alert_tests.h`
      shows. A QUIC server has no such limit: its caller seals the
      CONNECTION_CLOSE under a packet number of its own.

77. **A `RAND=session` object draws every random byte from a source each
    session's `ch_cfg` names, and packages no generator.** colibri's owner
    ruled in its decision 94 that cocuyo, its sibling project, replays a
    connection from a seeded stream. With one `ch_rand_bytes` per image, a
    replay had to know which chapulin calls draw and in what order, and it
    broke with no error when a draw moved from one call to another.
    Sessions on different threads also shared that one hook, which then
    needed a lock or state held per thread. Camilo chose on 2026-09-27 a
    third value of the `RAND` axis, and firmware keeps `RAND=extern`.

    - **The fields.** Under `-DCH_RAND_SESSION`, `ch_cfg` gains
      `rand_bytes`, which the library calls as `rand_bytes(rand_io, p,
      n)`, and `rand_io`, which it hands over unread and which may be
      NULL. The contract is `ch_rand_bytes`'s (rand.h): the source writes
      n bytes and returns nothing, so a source that cannot fill must not
      return. It is a CSPRNG in production, because a deterministic
      stream gives predictable keys to anyone who knows its seed. A
      seeded stream that replays a connection is for tests.
    - **One draw path.** Every library draw calls `rand_draw`
      (`rand_draw.h`), which calls the session's `rand_bytes` under
      `RAND=session` and `ch_rand_bytes` under the other two patterns,
      so those builds draw as they did. The ten sites stay ten. One
      moved: `rsa_pss_sign` takes its salt as an argument, and
      `srv_auth.c`'s `sign_rsa_pss` draws it from the configuration the
      signature serves, as `mlkem_encaps_derand` and `p256_ecdh_keygen`
      take their random bytes from their callers. `rsa_pss_sign` keeps
      the assertion against an all-zero salt. `inv-4-one-draw-path`
      refuses a `ch_rand_bytes` call outside `rand_draw`'s body, and the
      files and calls rules now count `rand_draw` calls.
    - **The refusal.** `ch_connect`, `ch_record_init`, `ch_quic_init`,
      `ch_srv_accept`, `ch_srv_record_init`, `ch_srv_quic_init` and
      `ch_srv_check` return `CH_EINVAL` for a NULL `rand_bytes`, before
      they draw or send anything. `ch_srv_check` signs with the RSA
      identity, and that signature draws a salt, so it refuses whichever
      identities the configuration holds, as the init calls do.
    - **No fallback.** The object neither defines nor imports
      `ch_rand_bytes` and packages no `drbg.c`, so an image that links
      only such objects defines no entropy hook. `rand.h` declares the
      hook only for the other two patterns. `lib-check` holds the object
      to name neither `ch_rand_bytes` nor `ch_drbg_seed`, the counterpart
      of the `RAND=extern` import check, and links `test/build_test.c`,
      which defines no hook under the define.
    - **The build record.** `CH_BUILD_RAND_SESSION` is bit `0x400` of
      `axes`: the define changes `ch_cfg`, and with it `ch_tls`,
      `ch_record` and `ch_quic`. `RAND=extern` and `RAND=drbg` still take
      no bit, because neither changes a layout (entry 56).
    - **Threads.** A session draws from its own source alone, so the
      library holds no entropy state that sessions share, and sessions on
      different threads need no lock around the library's draws. A lock
      is the source's business, and only where two sessions share one.
    - **The Zig API.** `Client.random` and `Server.random` are
      `?std.Random`, null by default. A session's init stores the value
      in the session and points `rand_io` at that copy, and an adapter
      fills each draw from it. A null value leaves `rand_bytes` NULL, and
      C refuses it with `CH_EINVAL`, which init returns as
      `error.Invalid`. `Server.check` holds the value for the one call.

    Rejected:

    - **A per-session callback beside the hook, which falls back to
      `ch_rand_bytes` when NULL.** A forgotten field would draw from the
      image's generator with no error, which is the silent break this
      entry exists to remove, and every object would still import the
      hook.
    - **`rsa_pss_sign` taking a fill function and its context.** The
      signer would call through a pointer into the session's source. With
      the salt as an argument it draws nothing, and a signature is a
      function of the key, the digest and the salt.
    - **A required Zig field.** A Zig field's default cannot depend on
      the build, so a field that is absent from the other builds and
      required in this one needs a second copy of each value struct. A
      null value that C refuses keeps the rule in C, where every other
      configuration rule is.

    Cost: in a `RAND=session` build `ch_cfg`, `ch_tls`, `ch_record` and
    `ch_quic` each grow by two pointers, 16 bytes on arm64 and 8 on
    rv32ic, measured. No other build's layout moves, and bench/sram.sh
    reads the same numbers as before. `rsa_pss_sign` takes one more
    argument. `make check` gains one packaged-object leg and three loop
    binaries, and check-slow's Zig roster one configuration.

    Gain: a replay needs only each session's seed, whichever calls draw
    and in whatever order, and two sessions never draw from each other's
    stream, on one thread or several.

78. **An AES-GCM write key seals at most 2^24 records, and `ch_write` sends
    the KeyUpdate that retires it by itself.** RFC 9846 §5.5 has a sender
    close the connection or send a KeyUpdate while a key is still below
    its AEAD's usage limit (`rfc9846.txt:3743-3744`), and gives AES-GCM's
    as up to 2^24.5 full-size records under one set of keys
    (`rfc9846.txt:3750-3753`). A `SUITE=aesgcm` build's record layer held
    only the 64-bit sequence wrap, so a long connection sealed past that
    limit under one key. docs/server.md said `rec_seal` had a per-suite
    ceiling and that the session rekeyed with `rec_dir_update` before it.
    Neither existed, and a rekey with no KeyUpdate would have left the
    peer reading under the old key. colibri needed the rekey and asked for
    a call that starts a KeyUpdate. Camilo decided on 2026-09-27 that
    chapulin rekeys by itself and adds no public call.

    - **The ceiling.** `REC_AES_GCM_RECORDS_MAX` (`record.h`) is 2^24, the
      largest power of two at or below 2^24.5. It counts every record under
      the key, whatever its size, the reading that can never let a key
      pass the RFC's figure. An AES-GCM write key seals at sequence numbers
      0 to 2^24 - 1 and at none above: `rec_seal` refuses a record at or
      past the ceiling, beside its wrap guard, so no path seals past it.
      `rec_open` keeps no count, because §5.5 says a receiver SHOULD NOT
      enforce the limit (`rfc9846.txt:3747-3748`).
    - **The KeyUpdate.** Before each record it seals, `ch_write` reads the
      write key's suite and sequence number. When an AES-GCM key's next
      record would take its last sequence number, `ch_write` sends a
      KeyUpdate there, under the old key, then moves the write direction
      to the next key and seals the record at sequence number 0 of it. So
      the KeyUpdate is the last record under the old key. Its
      request_update is 0: the key at its limit is this side's write key,
      and the peer's write key keeps a count of its own.
      `hspost_send_key_update` (`handshake_post.c`) seals, sends and
      rekeys, for this and for the answer to a peer that asked for one.
      `ch_write` serves both roles and both TCP transports.
    - **The sender cap.** §4.7.3 lets a sender send 2^48 - 1 KeyUpdates
      (`rfc9846.txt:3400-3402`), `HSPOST_SEND_EPOCHS_MAX`, and says the
      limits of §5.5 may then end the connection
      (`rfc9846.txt:3408-3410`). A key at its ceiling after that many
      fails the write: `tlsi_fail` seals internal_error at the key's last
      sequence number and wipes the keys, and `ch_write` returns
      `CH_ECAP`. That is `ch_write`'s code for a record it cannot seal,
      which it already returned at the sequence wrap, and it leaves the
      session dead, as INV-13 and tls.h say of every `ch_write` error but
      `CH_EPROTO`. internal_error, because the cause is this side's count
      and not the peer's input.
    - **Other sends.** A server's NewSessionTicket goes out at sequence
      number 0 of the key its handshake installed, the answer to a peer's
      KeyUpdate rekeys right after its one record, and an alert is the
      last record before the keys are wiped. `ch_write` leaves every
      AES-GCM key with its last sequence number free, so each of the three
      takes at most that one, and none checks.
    - **`ch_writable_len`.** It counts the KeyUpdate record when the write
      it sizes would cross the ceiling, so the Zig API's all-or-nothing
      `write` (entry 73) never hands `ch_write` an output too short for
      what it sends. It counts one KeyUpdate and no second: it answers at
      most the plaintext of the records the key has left and 2^24 - 1
      records under the next key, over a gigabyte at the smallest record a
      peer may ask for. Counting any number of KeyUpdates would divide cap
      by the length of 2^24 - 1 records and a KeyUpdate, which passes 2^32
      at records of 235 bytes, where a 32-bit `size_t` cannot hold it. The
      crossing path divides by the record length a second time, in a
      `SUITE=aesgcm` build alone, over public lengths.
    - **The file.** `ch_write` and `ch_writable_len` moved from `tls.c` to
      `tls_write.c`, which `tls.h` declares, because the change took
      `tls.c` past 500 lines. `lint-wide-multiply`'s division ceiling and
      `RV_ALLOWED`'s runtime calls moved with them, and `tls.c` joined
      `tools/proof-cover.py`'s `AUDITED`, because `writable_len` now
      includes `tls_write.c`.
    - **QUIC.** Unchanged. RFC 9001 §6 forbids the TLS KeyUpdate message
      there (`rfc9001.txt:1566-1568`), and each AES-GCM key set counts its
      packets against §6.6's confidentiality limit (docs/quic.md).
    - **The Zig API.** `write` is unchanged, because `writableLen` is
      `ch_writable_len`. The reserved `keyUpdate` stays a `@compileError`,
      and entry 73's result for a caller-started update at the cap goes
      with the call.
    - **The check.** `test/key_limit_cases.h` runs in
      `bin/webpki_loop_aes` and `bin/webpki_loop_aes_extern` over
      tcp-nonblocking, and in `bin/tcp_blocking_key_limit` over
      tcp-blocking: a client and a server of one object each write across
      the ceiling under both AES-GCM suites, with both ends' sequence
      numbers moved near it rather than 2^24 records sealed.
      `bin/aes_suite_test` holds `rec_seal`'s refusal to its exact
      boundary. `writable_len_suite` proves `ch_writable_len`'s answer
      against the real `ch_write` in the suite build, for every cap up to
      three records of the session's limit, a KeyUpdate record and a
      byte, and that no data record takes an AES-GCM key's last sequence
      number; `writable_len_suite_any` proves the call safe over any
      input; `record_suite` proves that `rec_seal` refuses the wrap and
      the ceiling and nothing else. Seven mutants in `test/violations/`
      break the rules, and each is caught.
    - **Two repairs the checks needed.** `bin/webpki_loop_aes_extern`'s
      rule sat above `WEBPKI_LOOP_SRCS`, and make expands a rule's
      prerequisites where it reads the rule, so the list held none of the
      library sources and an edit to one never rebuilt the binary. Two of
      the mutants here passed on that stale binary until the rule moved
      below the list. And a `lint-tidy` pass now reads `tls_write.c` and
      `record.c` under the suite define, which reads `ct.h`'s suite guard
      for the first time; its `#if defined(CH_AES_HW)` is `#ifdef` now,
      as readability-use-concise-preprocessor-directives asks.
    - **The spec.** Unchanged. `spec/lean/Spec/Record.lean` models one
      record's protection under ChaCha20-Poly1305, and its `seal` says it
      does not model `rec_seal`'s refusal; `Spec/Handshake.lean` models a
      KeyUpdate as a message a connected session accepts. Neither models
      the records a session sends or when it moves to a new key.

    Rejected:

    - **A KeyUpdate call the caller starts,** entry 73's reserved
      `keyUpdate`. colibri needed it for this limit alone, and a caller
      that forgot to call it would seal past the limit.
    - **Closing the connection at the ceiling,** which §5.5 also allows.
      A host moving large uploads would lose its connection every 2^24
      records, 8 GiB at 512 bytes a record.
    - **Rekeying without a KeyUpdate,** what docs/server.md described. The
      peer's read direction would stay on the old key, and the next record
      would fail its tag.
    - **Counting full-size records alone,** the unit the RFC's figure is
      in. `ch_write` would have to judge each record's size, and the key
      could seal more records than the count here allows.
    - **request_update 1.** The peer's write key keeps its own count, so
      its answer would rekey a direction that is at no limit.

    Cost: one comparison before each record a `SUITE=aesgcm` build seals
    through `ch_write`, and one 27-byte KeyUpdate record per 2^24 records
    under an AES-GCM key. No struct grew, and bench/sram.sh reads the same
    numbers. A caller that sizes its output for one message adds
    `CH_KEY_UPDATE_RECORD_LEN` bytes under `SUITE=aesgcm`, or the write
    that crosses the ceiling returns `error.Cap` through the Zig API with
    nothing sealed. `make check` runs one more binary and one more tidy
    pass, and the fast proof tier two more harnesses, 49 seconds and
    under one.

    Gain: a `SUITE=aesgcm` session keeps RFC 9846 §5.5's AES-GCM limit for
    as long as it runs, with nothing for the caller to call, and every
    write sized with `ch_writable_len` still fits.

79. **A QUIC object derives packet keys for QUIC version 1 and version 2,
    and the caller names the version of each packet.** RFC 9369's QUIC
    version 2 is version 1 with a new Version field, new long header type
    codes, a new Initial salt, new HKDF labels and a new Retry integrity
    key and nonce (`rfc9369.txt:130-188`). colibri reads and writes the
    wire, so the header codes, Version Negotiation and RFC 9368's
    version_information transport parameter are its half, tracked in
    https://github.com/c4milo/colibri/issues/54. The keys are chapulin's,
    and a QUIC object derived version 1's alone. Camilo decided on
    2026-09-29 how the version enters the calls.

    - **The caller names the version.** Each packet call takes the version
      beside the encryption level, and chapulin reads no header byte to
      learn either. An Initial packet may carry either version, because a
      server keeps its original version's Initial receive keys until it
      processes a Handshake packet in the negotiated version
      (`rfc9369.txt:250-254`). A Handshake or 1-RTT packet in any version
      but the negotiated one is refused, the drop §4.1 requires
      (`rfc9369.txt:256-259`). A Retry uses the original version
      (`rfc9369.txt:221-227`).
    - **The client.** Its configuration names its original version, and a
      configuration that names none is refused. It learns the negotiated
      version from the first long header whose Version field differs from
      the original (`rfc9369.txt:240-244`), and switches once, deriving the
      new version's Initial keys from the same Destination Connection ID.
      The switch is refused once the first CRYPTO byte from the server has
      been delivered, because the server sends every CRYPTO frame in the
      negotiated version, and a CRYPTO frame in the original version makes
      the original the negotiated one (`rfc9369.txt:236-244`).
    - **The server.** A callback from the server's caller chooses the
      negotiated version once, after the client's transport parameters
      and before ticket selection, the HelloRetryRequest and the
      ServerHello, because a server sends no CRYPTO frame before it has
      processed those parameters (`rfc9369.txt:236-237`). `srv_select`
      ran before the parameters were handed to the caller, and the
      HelloRetryRequest path never handed them out, so the parameters
      moved ahead of it. The caller answers from RFC 9368's
      version_information, which chapulin does not parse. The callback is
      `ch_srv_cfg.choose_version`: NULL keeps the original version, and an
      answer the build does not derive fails the session with `CH_EIO`
      and internal_error, the code a refused `on_crypto_out` returns,
      because the failure is the caller's and not the peer's.
    - **Tickets and tokens.** A ticket belongs to the version of the
      connection that issued it, the negotiated one after a switch
      (`rfc9369.txt:268-284`). A server ticket records that version, and
      the server passes over a ticket of another version for a full
      handshake. A TCP server's tickets record no version, so no ticket
      crosses transports. A client offers no ticket issued under a version
      other than its original one: `ch_ticket.quic_version` carries the
      version and `ch_cfg.ticket_quic_version` presents it, and
      `ch_quic_init` refuses a mismatch. A raw or ca client refuses a
      declined ticket, so its resumption fails closed when the server
      switches. The Retry token binds the version, which §4.1 permits
      (`rfc9369.txt:224-227`): its tag covers the version the way it covers
      the client's address, so the layout and `CH_QUIC_TOKEN_MAX` stay as
      they were, and a token checked under the other version fails its tag.
    - **INV-7 and INV-26.** INV-7's one version per build is the TLS
      version, 1.3, and it stays one; its claim will say that the QUIC
      version is the caller's value, like the level, and that chapulin
      chooses neither. Version 2's Initial keys come from a salt the RFC
      prints and a connection ID sent in the clear, and its Retry key and
      nonce are printed (`rfc9369.txt:158-188`), so INV-26's public-key
      argument covers them as it covers version 1's.

    Rejected:

    - **A `QUIC_VERSION` build axis.** No field would grow and no signature
      would change, but a build could not negotiate: the interop runner's
      v2 case starts in version 1 and has the server answer in version 2.
    - **The version as a pseudo-level.** The packet calls would keep their
      signatures, but a level would then name a version, and chapulin
      could not drop a Handshake packet in the wrong version.
    - **A switch allowed until the Handshake keys.** It would admit a
      switch after server CRYPTO bytes arrived in the original version,
      which §4.1 makes the negotiated version.
    - **An unset original version meaning version 1.** Every caller names
      the version on every packet call anyway, and a default would hide a
      configuration that forgot it.
    - **Dropping a mismatched ticket at init.** colibri asked on
      2026-09-29 whether `ch_quic_init` should drop a ticket issued under
      another version and run a full handshake instead of refusing the
      configuration. RFC 9369 §5 forbids offering the ticket
      (`rfc9369.txt:268-271`) but does not say which to do. Camilo kept
      the refusal the same day: a silent drop would change what the caller
      asked for without telling it, and hide the mistake that passed the
      ticket.

    Cost: a version argument on each packet call, fields for the original
    and the negotiated version, and a version in each ticket. The two
    version fields grow `ch_quic` in colibri's object, `ROLE=both
    TRUST=webpki TRANSPORT=quic-nonblocking`, from 5,072 to 5,080 bytes on
    arm64, and from 5,544 to 5,560 under `SUITE=aesgcm`, measured by
    bench/sram.sh; the TCP sessions docs/performance.md measures do not
    change. The server's `choose_version` pointer grows it to 5,088
    bytes, and to 5,584 under `SUITE=aesgcm`, measured the same way. The
    two ticket version fields sit in padding, so neither `ch_ticket` nor
    `ch_cfg` grows. A server ticket grows by four bytes, to 108, and to
    124 under `SUITE=aesgcm`, and its format version moves to 2, so a
    ticket sealed before the change fails to open and costs its client one
    full handshake.

    Gain: colibri can negotiate version 2 in both roles, as the interop
    runner's v2 case asks, and chapulin enforces every rule that §4.1 and
    §5 state for the keys, tickets and tokens it holds.

    Status: this entry and the two RFCs landed first, then the interface:
    `ch_cfg.quic_original_version`, the version argument on the packet
    calls and on the two Retry calls, `ch_quic_switch_version` and
    `ch_quic_negotiated_version`. Version 2's keys and the client's switch
    have landed since. `quic_version.h`'s `quic_version_derived`, the one
    rule that says which versions a build derives, admits version 1 and
    version 2. `aes.c` holds version 2's Initial salt and Retry key beside
    version 1's, `quic_retry.c` its Retry nonce, and `quic_version.h` its
    four labels, each copied from `rfc9369.txt:158-188`, and RFC 9369
    Appendix A checks every one of them against the vendored text. A client
    that starts in either version may switch to the other once, before the
    server's first CRYPTO byte, and a whole handshake runs in version 2. A
    server's caller chooses the negotiated version through
    `ch_srv_cfg.choose_version` at the first ClientHello, after the
    client's transport parameters and before the ticket selection, a
    HelloRetryRequest and the ServerHello. A ticket records the negotiated
    version of the connection that issued it in both roles, the server
    passes over a ticket of another version, the client offers none in
    another, and the Retry token binds the original version through its
    tag. QUIC version 2 is complete in both roles.

80. **A build on `AES=hw` with `CH_NATIVE_AES` offers and prefers
    AES-256-GCM, then AES-128-GCM, then ChaCha20, and a caller may set a
    client's order.** Entries 45 and 58 put ChaCha20 first in both roles:
    a `SUITE=aesgcm TRUST=webpki` client offered
    `TLS_CHACHA20_POLY1305_SHA256`, then `TLS_AES_128_GCM_SHA256`, then
    `TLS_AES_256_GCM_SHA384`, and a server with no
    `ch_srv_cfg.cipher_suites` preferred the same order. A server that
    follows the client's order then selects ChaCha20 when both ends have
    the AES instructions, and so does Go's, which reads the client's order
    only to choose between AES-GCM and ChaCha20 and then takes its own
    list, AES-128-GCM first (`crypto/tls`,
    `handshake_server_tls13.go`). stompy measured the cost through colibri's h11
    client, over the TCP object built `SUITE=aesgcm AES=hw` at 0adcf33, on
    one Apple M1 core in OrbStack with 5 MiB PUTs to MinIO: 1 ms of CPU
    per MB and 935 MB/s over 8 connections in cleartext, and 5 ms of CPU
    per MB and 150 MB/s, the same from 1 to 8 connections, over TLS.
    MinIO's Go server selected ChaCha20, 0x1303, because the client listed
    it before AES-GCM.
    The server role showed the same effect: against Go's client, on an AMD
    EPYC 7763 runner with the AES instructions, colibri's server over the
    object at 0adcf33 selected 0x1303. Camilo decided on 2026-09-29
    ([#180](https://github.com/c4milo/chapulin/issues/180)). This entry
    amends entry 45's offer and the order bullet of entry 58.

    - **The default order, chosen at build time, the same in both
      roles.** A `SUITE=aesgcm` build on `AES=hw` that defines
      `CH_NATIVE_AES` offers, as a client, and prefers, as a server,
      `TLS_AES_256_GCM_SHA384`, then `TLS_AES_128_GCM_SHA256`, then
      `TLS_CHACHA20_POLY1305_SHA256`. The build asserted that its AES
      instructions and its carry-less multiply run in constant time
      (entry 50), and AES-128-GCM on them outran ChaCha20-Poly1305 at
      every size docs/quic.md measured, on arm64 and on x86-64. Every
      other build keeps entry 58's order, ChaCha20 first, `AES=extern`
      included: GHASH runs there on `gcm.c`'s portable multiply, and
      nothing in this tree measures a peripheral. `suite.h` states the
      order once, as `suite_default_order`, and `SUITE_AES_FIRST` marks
      the build that takes the AES-first one; the ClientHello and
      `srv_select` read that one definition. `ch_srv_cfg.cipher_suites`
      still overrides the server's default.
    - **AES-256-GCM first.** Camilo chose AES-256-GCM ahead of
      AES-128-GCM to align chapulin with NSA's CNSA 2.0 suite, which
      requires AES-256 and SHA-384. Entry 58 put AES-128-GCM first
      because every handshake proof covers the SHA-256 schedule, and that
      stays true: the SHA-384 schedule has only its own harnesses
      (`transcript384`, `keysched384` and the `hkdf384` ones). The
      AES-256 rows of `bin/webpki_loop_aes`, `bin/quic_loop_aes` and
      `test/e2e.sh` run it through whole handshakes. On `AES=hw`, a
      default handshake with this tree's server, or with any server that
      follows the client's order and holds AES-256-GCM, now runs the
      SHA-384 schedule, and its tickets carry 48-byte PSKs. Go's server
      still selects AES-128-GCM, from its own list; a caller who wants
      AES-256-GCM from it leaves AES-128-GCM out of
      `ch_cfg.cipher_suites`.
    - **The caller's order.** A client that offers more than one suite
      (`CH_CLIENT_AES_SUITES`) takes `ch_cfg.cipher_suites` and
      `ch_cfg.cipher_suite_count`, with the element type and the count
      convention of `ch_srv_cfg.cipher_suites`. NULL with a count of 0
      offers the build's default. `ch_connect`, `ch_record_init` and
      `ch_quic_init` return `CH_EINVAL` for a list that names a suite the
      build does not hold, repeats a suite, or is longer than the
      `SUITE_HELD_COUNT` suites the build holds (`webpki_cfg.h`). The
      ClientHello offers exactly the caller's list, in its order. The
      parser still takes any suite the build holds, so
      `hsf_read_server_hello` refuses a ServerHello or a HelloRetryRequest
      that names a suite the list left out, with illegal_parameter
      (`rfc9846.txt:1373-1376`, `rfc9846.txt:1484-1485`). The Zig API
      gains `values.Client.cipher_suites`, which forwards to the C field
      and is gated with `@hasField`, as the server's is. `chapulin.hpp`
      exposes no suite order for either role and gains none.
    - **No CPU probe.** Nothing in this tree asks a CPU what it has
      (CLAUDE.md), and neither does colibri: its decision 97 picks the
      chapulin object from the build target's features, so an `AES=hw`
      object exists only for a target with the AES instructions. colibri's
      callers probe the CPU when they want a choice at run time, and pass
      an order that colibri forwards through `values.Client.cipher_suites`
      and `values.Server.cipher_suites`. Without one, the build-time
      default holds.
    - **The check.** `bin/webpki_session_test`, `bin/webpki_session_aes`
      and `bin/webpki_session_aes_extern` hold the ClientHello's
      cipher_suites bytes to each build's default, and the last two hold
      the caller's list to each rule's edge and to the suites the client
      takes back. `test/webpki_loop_order.h` feeds this tree's server a
      hello that lists the three suites in each of their six orders, in
      the three webpki loop builds, and requires the first suite of the
      server's default order; `bin/webpki_loop_aes`,
      `bin/webpki_loop_aes_extern` and `bin/quic_loop_aes` run the
      caller's list end to end. `test/e2e.sh` has OpenSSL's `s_server`,
      which follows the client's order, select AES-256-GCM from the
      `AES=hw` client, ChaCha20 from the `AES=extern` one and
      AES-128-GCM from either under `WEBPKI_SUITES=1301,1303`, and has
      `s_client` offer AES-128-GCM first to this tree's server, which
      selects its own first suite. The `hello_build_suite` proof holds the
      builder to `CH_HELLO_MAX` over every list shape, and
      `quic_config_webpki_suite` proves the list rule. Eight mutants in
      `test/violations/` break the new rules, and each is caught.

    Rejected, both on 2026-09-29:

    - **A CPU probe in chapulin.** An arm64 core cannot read its ID
      registers from EL0 without the operating system's help, so a probe
      needs per-OS code, and the bare-metal lanes have no OS to ask.
      Whether a build has the AES instructions stays the compiler's
      answer at build time, or under `AES=runtime` the caller's
      (entry 81).
    - **A probe function the caller supplies.** It would move no rule into
      chapulin that a caller's order does not already carry, and it would
      add a callback to every configuration. A caller runs its own probe
      and passes the order it chose.

    Cost: `ch_cfg` gains a pointer and a count in a `SUITE=aesgcm
    TRUST=webpki` build, 16 bytes on arm64, and every struct that holds a
    copy grows with it. Measured by `bench/sram.sh` and the same `sizeof`
    probes run on the tree before this change: `ch_tls` from 3,352 to
    3,368 bytes, the `ROLE=both TRUST=webpki` tcp-nonblocking `ch_record`
    from 4,896 to 4,912 and its QUIC `ch_quic` from 5,544 to 5,560. No
    stack peak moved. On `AES=hw` a default handshake runs AES-256-GCM,
    fourteen rounds a block where AES-128-GCM runs ten, and the SHA-384
    key schedule; this tree has not measured what that costs. The fast
    proof tier gains two formulas, `hello_build_suite` (659
    properties, 131 s, 0.17 GB) and `quic_config_webpki_suite` (705
    properties, 6 s, 0.14 GB), and `make check` one binary,
    `bin/webpki_session_aes_extern`.

    Gain: on a host whose build asserts the AES instructions, a chapulin
    client gets AES-GCM from a server that follows the client's order or,
    as Go's does, reads it to choose between AES-GCM and ChaCha20, and a
    chapulin server gives it to a client that offers it, with no call to
    make. A caller that learns at run time what its CPU has sets
    either order through the Zig API.

81. **An `AES=runtime` object holds the AES instructions and a fallback,
    and the caller's CPU probe picks between them for each session**
    ([#183](https://github.com/c4milo/chapulin/issues/183)). Every other
    `AES` value fixes the choice when the object is built. An `AES=hw`
    object runs the AES instructions for every QUIC Initial packet and for
    AES-GCM traffic, so it stops with SIGILL on a CPU without them, and
    every other object holds ChaCha20 alone for traffic, so a caller whose
    probe finds the instructions cannot use them. colibri picks its
    chapulin object from the build target's features (its decision 97),
    and its callers probe the CPU when they want the choice at run time
    (entry 80). Camilo decided on 2026-09-29. This entry amends entries 50
    and 68 where they state the `AES` axis.

    - **The build value.** `AES=runtime` compiles `aes_hw.c` and
      `ghash_hw.c` with no instruction flag. A target pragma at the top of
      each file puts the target attribute on each function in it, `+aes`
      on arm64, whose AES extension holds the 64-bit PMULL, and `aes` and
      `pclmul` on x86-64, so the instructions appear in those two files
      alone and the rest of the object runs on any CPU of its
      architecture. A QUIC object also holds `quic_aes_soft.c`, whose two
      entries take the names `aes_soft_expand_round_keys` and
      `aes_soft_cipher_block` there, for QUIC's public keys. A TCP object
      has no public key and holds no table. Both files refuse a target
      other than arm64 or x86-64 with an `#error`.
    - **The answer.** `ch_cfg.aes_instructions`, declared only in an
      `AES=runtime` object, takes `CH_AES_INSTRUCTIONS_PRESENT` or
      `CH_AES_INSTRUCTIONS_ABSENT`: whether the CPU has the AES and
      carry-less multiply instructions, as the caller's probe found.
      `ch_connect`, `ch_record_init`, `ch_quic_init`, `ch_srv_accept`,
      `ch_srv_record_init` and `ch_srv_quic_init` return `CH_EINVAL` for
      any other value, 0 included, before anything is sent, as they do
      for an unset QUIC version, so every caller states what its probe
      found. chapulin probes nothing.
    - **Present** behaves as `AES=hw`. QUIC Initial packets and their
      header protection run on the instructions, and a `SUITE=aesgcm`
      build offers and prefers entry 80's order.
    - **Absent** runs neither instruction. QUIC Initial packets and their
      header protection run on the table, and their GHASH on `gcm.c`'s
      portable multiply; both keys are public (INV-26). The session holds
      ChaCha20 alone: a client offers it alone and a server's default
      order is it alone. Init refuses a `ch_cfg.cipher_suites` or a
      `ch_srv_cfg.cipher_suites` that names an AES-GCM suite rather than
      dropping the suite, and a server refuses a retry cookie that names
      one with illegal_parameter, because a server with the instructions
      may have minted it under the same cookie key.
    - **Each schedule records its cipher.** `aes_key_schedule` gains
      `instructions` in a QUIC object, and `aes_encrypt_schedule`,
      `aes_encrypt_block_hp` and `gcm.c` run a schedule on the cipher it
      records. The Initial constructor records the caller's answer, the
      Retry constructor the table, and `aes_traffic_key_init` the
      instructions under either answer, so the table runs no traffic
      key. Each branch reads the caller's answer or a constant, not a
      key.
    - **The Retry key runs on the table under either answer.**
      `ch_srv_quic_retry_tag` takes no configuration to read an answer
      from, and RFC 9001 and RFC 9369 print the key, so the table leaks
      nothing. Under the present answer this departs from `AES=hw` in
      which cipher computes the tag, and not in the tag.
    - **`CH_NATIVE_AES` keeps its meaning.** It is the builder's statement
      that the part's AES instructions and carry-less multiply run in
      constant time where the part has them, and `ct.h` refuses
      `SUITE=aesgcm` on `AES=runtime` without it. The caller's answer says
      whether the instructions exist; the build states their timing.
    - **What the build refuses.** The Makefile and `build.zig` refuse
      `AES=runtime` in a TCP object without `SUITE=aesgcm`, which carries
      no AES to choose, and `cfg.h` refuses the same build for a tree with
      its own build system. `aes_block.h` refuses `CH_AES_RUNTIME` beside
      `CH_AES_HW` or `CH_AES_EXTERN`.
    - **The build record** carries `CH_BUILD_AES_RUNTIME`, because the
      field changes `ch_cfg`'s layout, which is entry 77's reason for
      `RAND=session`.
    - **The wrappers.** `chapulin.hpp` gains `AesInstructions` and
      `Config::aes_instructions()`. The Zig API gains `AesInstructions`
      and `aes_instructions` in `Client` and `Server` values, declared
      where `@hasField` finds the field; null leaves 0, which init
      refuses.
    - **The checks.** `bin/aes_runtime_test` runs RFC 9001 and RFC 9369
      Appendix A under both answers and the SP 800-38D and FIPS 197
      vectors under traffic keys, and counts every call into the table,
      the instructions and the carry-less multiply: under the absent
      answer no call goes to the instructions, under the present one the
      table runs no Initial key, and the table runs no traffic key.
      `test/aes-runtime-qemu.sh` builds that binary and both loop
      binaries for x86-64 and runs them under `qemu-x86_64 -cpu
      max,-aes,-pclmulqdq`: the absent answer passes the vectors and whole
      QUIC and TCP handshakes, and the present answer and an `AES=hw`
      build die of SIGILL. CI's mips job runs it on every push, with the
      qemu-user package that job installs, and
      `test/docker-aes-runtime-qemu.sh` runs it in a container elsewhere.
      QEMU's arm64 models all implement the AES extension, so on arm64
      the claim rests on the counts and on `test/aes-runtime-disasm.sh`,
      which CI's arm64 job runs: it disassembles the three `AES=runtime`
      objects `make check` links and finds the AES and PMULL instructions
      in `aes_hw.c`'s and `ghash_hw.c`'s functions alone.
      `bin/webpki_session_aes_runtime`, `bin/webpki_loop_aes_runtime`,
      `bin/quic_loop_aes_runtime`, `bin/tcp_blocking_loop_aes_runtime`
      and `bin/srv_flight_test_aes_runtime` hold the field to 0, 1, 2 and
      3 at every init call, each pair of
      answers to the suite both ends run, and each refused list and
      cookie. The `aes_runtime`, `srv_select_runtime` and
      `quic_config_webpki_runtime` proofs hold the cipher each key takes,
      the default order and the answer rule over every byte an answer can
      be. `lint-trust-separation` admits `aes_hw.c`, `ghash_hw.c` and
      `quic_aes_soft.c` together in `AES=runtime`'s QUIC rows alone, and
      `aes-two-implementations-in-one-object.violation` stays caught.
      Thirteen mutants in `test/violations/` break the new rules, and each
      is caught. `inv26-runtime-initial-seal-ignores-answer` seals every
      QUIC Initial packet under the present answer, which no test on a
      CPU with the instructions can see: both ciphers compute the same
      packet, and `bin/aes_runtime_test` links no `quic.c`. The qemu run
      catches it.

    Cost:

    - One object holds two AES implementations, which CLAUDE.md forbade.
      `lint-trust-separation` holds the exception to one value and one
      pair.
    - Every block in a QUIC object reads which cipher its schedule
      records, and every schedule carries one more byte.
    - `ch_cfg` grows 8 bytes on arm64 in an `AES=runtime` build: one byte,
      and the alignment of the pointer after it (docs/performance.md).
    - A present answer on a CPU without the instructions dies of SIGILL,
      and an absent one on a CPU with them runs ChaCha20. The answer is
      the caller's, and chapulin cannot check it.
    - `make check` builds and runs eight more binaries and three more
      `lib-check` objects, and `lint-zig-build` one more configuration.
      CI's mips job builds four x86-64 binaries and runs them under qemu,
      and its arm64 job builds the three objects and disassembles them.

    Gain: one object per architecture serves CPUs with and without the
    AES instructions, and colibri's callers pass the answer their probe
    found instead of choosing an object at build time.

    Rejected:

    - **An attribute macro on each function.** The first draft put
      `AES_HW_TARGET` before every function in the two files. Semgrep
      could not parse a function whose definition starts with an unknown
      macro, so `lint-invariants` read those files only in part. The
      pragma gives each function the same target attribute and leaves
      each definition as `AES=hw` writes it.
    - **Cutting a caller's list down to ChaCha20 under the absent
      answer.** A caller who named AES-GCM asked for an offer the session
      cannot make, and a silent drop would hide that.

82. **`CHACHA=vector` computes ChaCha20 four blocks at a time in 128-bit
    vectors, NEON on arm64 and SSE2 on x86-64, and `CHACHA=portable`
    stays the default and the reference.** At fc02391, `chacha20.c`
    computed one 64-byte block at a time and XORed one byte at a time.
    On an Apple M1 Pro under clang those two stages took 33 of the 66 µs
    that `rec_seal` spent on a 16 KiB record, and every build carries
    ChaCha20-Poly1305 (docs/performance.md, "Where a record's time
    goes"). Camilo decided on 2026-09-29
    ([#181](https://github.com/c4milo/chapulin/issues/181)) to make the
    AEAD cheaper with a vector path. The path keeps entry 45's reason for
    ChaCha20, constant time by construction, gives the portable C's
    output, and leaves the portable C as the reference.

    - **Four blocks per call, one per lane.** `chacha20_vector.c` holds
      each of the 16 state words of four consecutive blocks in one vector
      of four 32-bit lanes. It runs `chacha20.c`'s rounds on the 16
      vectors with adds, exclusive-ors and fixed rotations, transposes
      the result into block order, and XORs it into the output 16 bytes
      at a time. `chacha20_xor` calls it under `-DCH_CHACHA_VECTOR`.
      `chacha20_block`, which derives the Poly1305 key, stays the
      portable function in both builds.
    - **`chacha20.h`'s contract, unchanged.** The lanes hold the
      counters counter to counter + 3, and the adds wrap modulo 2^32, as
      `state[12]++` does. A last group of 1 to 255 bytes computes four
      blocks into a buffer and XORs its bytes one at a time, as
      `chacha20.c` XORs its last block. Each 16 bytes are read before the
      16 at the same offset are written, in ascending order, so the
      output may sit on the input or below it, where `rec_open` puts it.
    - **NEON and SSE2, from the compiler's macros.** Every AArch64 core
      has NEON and every x86-64 core has SSE2, so a compiler for either
      target defines `__ARM_NEON` or `__SSE2__`. Nothing probes a CPU,
      and no caller passes a probe's answer: unlike the AES instructions,
      these come with the architecture. `chacha20_vector.h` stops a build
      for any other target, and for a big-endian one, whose lanes would
      store their bytes in the wrong order. So `CHACHA=vector` never falls
      back to the portable loop. `test/chacha-builds.sh` checks both
      refusals, and that a vector object calls the path.
    - **An axis, as `X25519` is (entry 52).** A device core has neither
      instruction set, so the portable loop stays the default and the
      device path, with its proof. The values name what each path needs
      from the target. The vector path asks for no timing statement of
      its own, where `X25519=wide` asks for `CH_NATIVE_MUL128`: it
      multiplies nothing, reads no table, and runs the operations the
      portable loop runs. The build record leaves the axis out, as entry
      56 leaves `X25519=wide` out, because no public layout or bound
      reads it.
    - **128-bit vectors only.** They are the widest that every core of
      both architectures has. No machine here runs x86-64, so nothing
      could show that AVX2 pays, and the ruling admits AVX2 only on a
      measurement. An eight-block NEON variant, two groups of four in one
      round loop, ran faster in a scratch timing loop under clang, which
      is no measurement this tree records. It is a second tradeoff, with
      more register pressure on SSE2's 16 registers, so it waits for a
      change of its own, measured alone.
    - **Poly1305 stays as it is.** Its cost in the packaged object is the
      widening multiply: `ct.h` builds each 32x32->64 product from 16x16
      pieces. `WIDEMUL=native`, the builder's statement that the multiply
      runs in constant time, already runs the same Poly1305 in about a
      third of the time. A vector Poly1305 needs a widening multiply too,
      so it would need the same statement. Entry 83 adds one under that
      statement.

    Cost: a second ChaCha20 to keep equal to the first. The pair is 313
    lines. On arm64 under clang at `-O2` it adds 1,192 bytes of text to a
    host object, and takes the stack below `chacha20_xor` from 320 to 768
    bytes, which `lint-stack` holds to the device budget in the
    `CHACHA=vector` leg. Nothing proves the path, because CBMC cannot
    read an intrinsic. `make check` holds it with
    `bin/chacha20_equiv_test`, 30,771 cases against the portable loop;
    `bin/unit_chacha_vector`, which runs RFC 8439's vectors and every
    record the unit suite seals; a Wycheproof leg; a packaged-object leg;
    and the codegen gate's two 64-bit specs, which hold its branches at
    12. Seven violations break the path, and each is caught
    (docs/verification.md, "The vector ChaCha20").

    Gain: the record bench's second run, a filter's figures, took a 16
    KiB `rec_seal` from 67.3 to 47.6 µs on macOS clang, from 61.6 to 41.6
    µs on the Linux VM's clang and from 83.7 to 65.6 µs on gcc 13. With
    `WIDEMUL=native` as well, it takes 26.1 to 34.2 µs, 39% to 42% of the
    packaged portable record (docs/performance.md).

83. **`CHACHA=vector` with `WIDEMUL=native` runs Poly1305's block loop
    four blocks at a time in two vector lanes, NEON on arm64 and SSE2 on
    x86-64, and `CH_NATIVE_WIDEMUL` states the timing of every widening
    multiply the object runs, scalar or vector.** Entry 82 left Poly1305
    as it was. In that entry's record runs, with the vector ChaCha20 in
    place and `WIDEMUL=native`, Poly1305 took 11.2 to 12.8 µs of the 26.1
    to 34.2 µs a 16 KiB `rec_seal` took, most of what the vector ChaCha20
    left. A vector Poly1305 multiplies, so it needs a statement about the
    multiply's timing. Camilo ruled on 2026-09-30
    ([#181](https://github.com/c4milo/chapulin/issues/181)) that
    `CH_NATIVE_WIDEMUL` is that statement for every widening multiply the
    object runs, scalar or vector, NEON's UMULL and UMLAL and SSE2's
    PMULUDQ among them, with no new flag, and that the vector Poly1305
    builds only under `CHACHA=vector` with `WIDEMUL=native`.

    - **Two lanes, four blocks a group.** `poly1305_vector.c` holds two
      accumulators of five 26-bit limbs, one per lane, as `poly1305.c`
      holds one. Lane 0 takes the first and third block of each group of
      four, and lane 1 the second and fourth. For each group both lanes
      compute (h + the lane's first block) * r^4 + (the lane's second
      block) * r^2, two steps of Horner's rule over every other block, as
      five sums of 32x32->64 products, and carry the sums back into limbs.
      The last group multiplies lane 1 by r^3 and r instead, the powers
      its blocks are owed, and the two lanes' sums add up to the
      accumulator. Each call computes r^2, r^3 and r^4 from `p->r` with
      three scalar multiplies, so the `poly1305` context gains no field.
    - **`poly1305.c` stays the reference and chooses in one place.**
      `whole_blocks` in `poly1305.c` is the one call site that picks
      between the loops, so a choice the caller makes at run time
      ([#186](https://github.com/c4milo/chapulin/issues/186)) can go there
      alone. It hands the path every whole group of an update that holds
      at least 128 bytes of whole blocks, and its own loop takes the
      blocks after the last group. The buffered partial block and the
      final reduction stay in `poly1305.c` in every build. The path hands
      back the accumulator's value modulo 2^130 - 5 with every limb at
      most 2^26, inside the bounds `poly1305.c`'s loop keeps, so the loop
      and `poly1305_final` read it as they read their own.
    - **A threshold of two groups.** Below it, the powers of r cost more
      than the lanes save. In a scratch timing loop on the M1 Pro the path
      was slower than the portable loop over one group and faster over
      two, under Apple clang 21, clang 18 and gcc 13. That is no
      measurement this tree records, and no x86-64 machine has timed the
      SSE2 arm, so `POLY1305_VECTOR_MIN` is 128 bytes until one does.
    - **Two carry rounds where the portable loop has one chain.** In that
      timing loop, clang moved each carry of a chain into the next sum's
      chain of multiply-adds, which the adds allow, and so each sum waited
      on the one below it. A round adds a shifted value to a masked one,
      which leaves no chain to move a carry into, and two rounds leave
      limbs below 2^26 + 2^10. gcc kept every array that a loop indexes in
      memory, so the file indexes limbs by constants alone.
    - **One statement for both multiplies.** A builder who defines
      `CH_NATIVE_WIDEMUL` for an object that is also `CHACHA=vector`
      states the timing of the part's vector widening multiplies, not only
      its scalar one; `ct.h` says so. Without the define a `CHACHA=vector`
      object runs `poly1305.c`'s loop and its 16x16 decomposition.
      `poly1305_vector.h` turns the path on only where `CH_CHACHA_VECTOR`
      and `ct.h`'s `CH_WIDEMUL_NATIVE` meet, so `CH_CT_WIDEMUL` turns it
      off with the scalar multiply, and the Makefile and `build.zig`
      package `poly1305_vector.c` only in an object that is both.
    - **Each call wipes the powers of r.** r and a tag seen on the wire
      give the pad s, and r and s forge any message under that one-time
      key, such as a lost QUIC packet with its bits flipped. Each power
      gives r back, by a root modulo 2^130 - 5. So the call keeps r^2,
      r^3, r^4 and the two multipliers built from them in one struct, and
      wipes it through `ct_wipe` once when it ends: 208 bytes on NEON and
      352 on SSE2. Registers and the spill slots the compiler picks stay
      out of reach, as they do for every wipe written in C.
      `bin/poly1305_equiv_test` copies the stack below a call and requires
      none of the three powers there, in any layout the call holds them
      in. On x86-64 that check failed under Apple clang 21, a compiler no
      CI job builds x86-64 with. A group's two multipliers are 18 vectors
      and x86-64 has 16 vector registers, so that compiler loaded them
      before the loop and kept key powers in spill slots: 70 spills in a
      1,104-byte frame. Since 2026-10-04 `multiply_add` reads each limb of
      a multiplier through a volatile pointer on x86-64, which loads it
      from the struct where a product uses it. The frame is 536 bytes with
      one spill, and the check passes under Apple clang 21, gcc 13 and
      clang 23. arm64 keeps the plain reads: its 32 vector registers hold
      both multipliers, and the volatile reads there cost 30 percent more
      instructions and 3 percent more cycles on an M1 Pro and remove
      nothing. The wipe came after the scratch timing that set the threshold,
      which does not measure it, and after the paired record runs below.
      The record runs docs/performance.md holds now measure the code with
      it.
    - **Entry 82's limits hold.** 128-bit vectors only, no probe of the
      CPU, and nothing new in the build record: no public layout or bound
      reads the path.

    Cost: a second Poly1305 block loop to keep equal to the first. The
    pair is 443 lines. On arm64 under Apple clang 21 at `-O2` it adds
    1,872 bytes of text to a host object, 1,824 in `poly1305_vector.c` and
    48 in `poly1305.c`. It takes the stack below `poly1305_update` from 80
    to 400 bytes in a `CHACHA=vector WIDEMUL=native` build, 336 of them
    the path's frame with its struct of powers, and the deepest path from
    `aead_seal` through `mac` from 400 to 720. The peak below `aead_seal`
    stays where the vector ChaCha20 put it, 848 bytes: `aead_seal`'s 80
    over `chacha20_vector_xor`'s 768, as `bench/stack.py` reports.
    `lint-stack` holds the path's frames to the device budget in the
    `check-lib-chacha-vector-widemul` leg. Nothing
    proves the path, because CBMC cannot read an intrinsic. `make check`
    holds it with `bin/poly1305_equiv_test`, 43,282 cases against the
    portable loop and the check of the stack a call leaves;
    `bin/unit_chacha_vector`, which runs RFC 8439's A.3 and A.5 vectors on
    it; a Wycheproof leg; a packaged-object leg on each CI architecture;
    and the codegen gate's two 64-bit specs, which hold its branches at 4.
    Nine violations break the path, and each is caught
    (docs/verification.md, "The CHACHA=vector Poly1305").

    Gain: in paired runs of the record bench, a filter's figures, a
    `CHACHA=vector WIDEMUL=native` build took a 16 KiB `rec_seal` from
    26.2 to 17.4 µs on macOS clang, from 25.5 to 16.8 µs on the Linux VM's
    clang and from 33.3 to 23.1 µs on gcc 13, and Poly1305 over its
    ciphertext from 11.6, 11.2 and 12.8 µs to 2.7, 2.6 and 2.7 µs. That
    record takes 26% to 28% of the packaged portable one's time
    (docs/performance.md, "Where a record's time goes"). These runs came
    before the wipe of the powers, one `ct_wipe` of 208 or 352 bytes per
    call. The runs that performance.md held at d10b6e2, taken with the AES-GCM
    changes of [#184](https://github.com/c4milo/chapulin/issues/184),
    measure the code with the wipe: that build's Poly1305 takes 2.8 µs on
    macOS clang and gcc 13, and its 16 KiB `rec_seal` 17.2 and 18.4 µs.
    On the VM's clang the Poly1305 takes 4.7 µs in that bench build, where
    the linker's placement of the function, not its code, causes the
    difference (docs/performance.md, the pitfalls).

84. **Every client entry takes a PSK identity of 1 to `CH_TICKET_ID_MAX`
    bytes, refuses a ClientHello it cannot stage before a byte goes out,
    and keeps the session's epoch report when it refuses.** Two answers
    differed between `ch_connect` and the two non-blocking client entries,
    `ch_record_init` and `ch_quic_init`, and one of them was reachable
    because the raw and ca modes put no bound on a PSK identity.

    - **The hello.** `ch_connect` built its first ClientHello inside the
      handshake, so a hello too long for `ch_tls.tx` failed there: an
      internal_error alert went out in the clear, and `ch_connect`
      returned `CH_ECAP`. The two non-blocking entries build that hello
      before they return, and they refused it with `CH_EINVAL` and
      nothing staged. `ch_handshake` now builds the first hello before
      its first send and refuses it the same way, so all three return
      `CH_EINVAL`, send nothing and record no alert (INV-13). The retry
      hello a HelloRetryRequest asks for still fails the handshake with
      `CH_ECAP` and internal_error in every driver, because the first
      hello has gone out by then.
    - **The identity bound.** `hello_build` proves that `CH_HELLO_MAX`
      holds every hello whose PSK identity is at most `CH_TICKET_ID_MAX`
      bytes. `webpki_cfg_ok` held a ticket's identity to 1 to
      `CH_TICKET_ID_MAX` bytes, and the raw and ca configuration checks
      held an external identity to no length at all. A longer identity
      reached the first hello's refusal, and one the first hello still
      held could make the retry hello, which echoes a cookie, too long
      in the middle of the handshake. Camilo ruled on 2026-09-30 that
      every raw and ca client entry refuses an identity that is not 1 to
      `CH_TICKET_ID_MAX` bytes with `CH_EINVAL`, through `psk_id_len_ok`
      in `tls.c` and `quic_config.c`. That check is what makes both
      branches unreachable for every configuration a client entry
      accepts, and each branch still fails closed as it did, with no
      test that reaches it. The empty identity those checks took goes
      too: RFC 9846 §4.3.11 gives an identity at least one byte
      (rfc9846.txt:2468-2471).
    - **The epoch report.** `ch_record_init` and `ch_quic_init` zeroed
      the session on every refusal. After refusing a ticket that the
      stored epoch retired, they left `CH_EPOCH_NONE` in
      `ch_tls.epoch_status`, where `ch_connect` leaves
      `CH_EPOCH_REVOKED` (docs/ca.md). Each now zeroes the session but
      for `ch_tls.epoch`, `epoch_seen` and `epoch_status`, through
      `tcp_nonblocking_refuse_init` and `quic_refuse_init`. The two
      server entries call the same functions, and a server's three
      fields are zero.

    Rejected:

    - **Zeroing `ch_connect`'s epoch report instead.** No rule asks for
      a zeroed session. The non-blocking entries zero theirs so that
      nothing stays staged and no key share outlives the call, and three
      fields that hold no secret change neither. Zeroing them would
      remove the one field that tells a retired ticket from every other
      refusal.
    - **`CH_ECAP` from the two non-blocking entries.** A non-blocking
      call that returns `CH_ECAP` leaves its session live (INV-13), and
      a peer that has read no byte is owed no alert.
    - **Holding a longer identity.** A larger `ch_tls.tx` would carry
      more than `CH_TICKET_ID_MAX` bytes of identity, at an SRAM cost in
      every build, for an identity no ticket this tree takes can have.

    Cost: two functions of ten lines, one per non-blocking transport,
    and `ch_handshake` carries the first hello's length into the
    handshake. An external PSK identity longer than 320 bytes, which RFC
    9846 allows, no longer connects in the raw and ca modes.

    Gain: whichever client entry a caller uses, a refusal returns one
    code and leaves one epoch report, and no configuration a client entry
    accepts makes a ClientHello its staging array cannot hold.

85. **An AES-GCM open decrypts while it hashes, and wipes the plaintext it
    wrote when the tag does not match.** `gcm_open` computed the tag over
    the ciphertext, compared it and only then decrypted, so it read the
    ciphertext twice. On the AES instructions the seal runs counter mode
    and GHASH in one loop (`gcm_hw.c`), and the open could not, because it
    wrote no plaintext before the comparison. OpenSSL's open runs both in
    one loop and wipes its output on a mismatch. Camilo ruled on
    2026-09-30 ([#184](https://github.com/c4milo/chapulin/issues/184))
    that chapulin's open does the same, and that `gcm.h` promises this
    instead: no plaintext is returned on a bad tag, and the open wipes its
    output before it returns.

    - **The order.** `open_schedule` in `gcm.c` starts GHASH over the
      associated data, hands the whole passes of eight blocks under a
      schedule the AES instructions run to `gcm_open_passes_hw`, runs
      GHASH and then counter mode over the rest, and compares the tag
      through `ct_memeq`. `gcm_open_passes_hw` runs one pass ahead:
      iteration p hashes pass p and decrypts pass p - 1, so the GHASH of
      one pass runs beside the AES rounds of the one before. Every AES
      value takes this order, the table's included, because one body
      serves them all.
    - **Aliasing.** `gcm.h` still admits `pt == ct` and `pt` below `ct`,
      and `quic_packet.c`, `quic_initial.c` and `record.c` open in place.
      A plaintext write can then overwrite ciphertext, so both loops hash
      each ciphertext byte before they write to its address.
    - **The wipe.** On a mismatch the open wipes the n bytes it wrote
      through `ct_wipe` and returns 0, and it writes no byte outside
      them. The branch on the comparison's verdict tells an observer
      nothing the return value does not tell the caller. The plaintext of
      a forged ciphertext is that ciphertext exclusive-ored with the
      keystream of the nonce, so leaving it would hand the sender that
      keystream.
    - **What a caller finds after a discard.** `ch_quic_open` works in
      place. A packet whose tag does not match leaves its header with the
      protection removed, which the call does before the AEAD runs, as it
      did before, zeros where the payload was, and the tag and every byte
      past `pkt_len` as they arrived. colibri compares a datagram's last
      16 bytes with its Stateless Reset tokens (RFC 9000 §10.3.1,
      `rfc9000.txt:3486-3497`), and those bytes are the last packet's
      tag, which no open writes. `quic.h` and `quic_initial.h` now state
      this where they called those bytes unspecified. A failed `rec_open`
      ends its session (INV-13), and its record holds zeros where the
      payload was.
    - **ChaCha20-Poly1305 keeps its order.** `aead_open` still verifies
      first and writes nothing on a mismatch. The promise above admits
      both orders, so moving it later changes no caller.

    Rejected:

    - **Comparing first on the instructions.** It reads the ciphertext
      twice, which is the time the gain below measures.
    - **Decrypting into a scratch buffer and copying on a match.** That
      takes a second buffer as large as a record, 16 KiB of SRAM, and a
      second pass over the data.
    - **Leaving the plaintext for the caller to drop.** The caller would
      hold unauthenticated plaintext and the keystream it gives away.

    Cost: a forged record now costs counter mode and a wipe on top of
    GHASH. `ct_wipe` writes one byte at a time. In a scratch timing loop
    on the M1 Pro under Apple clang, a failed open of 1 KiB took 845 ns
    where the comparison first took 375 ns, and of 16 KiB 8.0 µs where
    it took 1.3 µs; a genuine open of 16 KiB went from 3.0 to 2.5 µs in
    the same loop. A failed TLS record ends its session, so it happens
    once per connection. A QUIC endpoint discards a forged packet and
    goes on, and a packet that fits a 1,500-byte path costs about the
    1 KiB figure.

    Gain: in paired runs of the record bench, a 16 KiB `aead_open` went
    from 2.99 to 2.57 µs under AES-128-GCM and from 3.39 to 2.99 µs under
    AES-256-GCM on macOS clang, from 3.00 to 2.86 and 3.44 to 3.27 µs on
    the Linux VM's clang 18, and from 3.23 to 2.84 and 3.65 to 3.28 µs on
    gcc 13. The seal did not move.

    Guards. `test/gcm_tests.h` forges one tag bit in every SP 800-38D
    case and requires zeros after the call and the byte after them
    untouched, in `bin/quic_test` and the legs that run those vectors.
    `bin/ghash_equiv_test`, the Wycheproof AES-GCM suite and
    `bin/diff_quic_test` require zeros from every refused open, and
    `bin/ghash_equiv_test` opens in place and five bytes below the
    ciphertext on both paths. `bin/quic_suite_test` forges the tag of the
    first of two packets in one datagram and checks every byte of the
    datagram after the failed open. `gcm-open-keeps-plaintext` drops the
    wipe, and `bin/quic_test` fails; `gcm-hw-open-hashes-after-decrypt`
    hashes each pass after decrypting it, and `bin/ghash_equiv_test`
    fails; `gcm-open-tail-hashed-after-decrypt` runs counter mode over the
    rest before GHASH, and `bin/quic_test` fails. `gcm_refusal` proves the
    zeros below n and nothing written past n for any tag, on the portable
    path; no harness reads `gcm_hw.c`.

86. **A `CHACHA=vector` pass computes eight blocks on NEON, two groups of
    four side by side, and four on SSE2, and XORs its keystream into the
    data from the registers that computed it.** Entry 82 computed one
    group of four blocks a call, stored it to memory and XORed it into the
    data in a second loop, and it left an eight-block NEON variant for a
    change of its own, measured alone. In the record bench at 9b72b67,
    ChaCha20 took 14.0 of the 17.3 µs a 16 KiB `rec_seal` took on macOS
    in a `CHACHA=vector WIDEMUL=native` build, where OpenSSL sealed the
    same record in 9.4 (docs/performance.md).

    - **Where the time went.** In a scratch timing loop on the M1 Pro
      under Apple clang 21, over 16 KiB in place, entry 82's path took
      13.9 µs. The same group with its XOR from registers took 13.4; that
      group without its four transposes, 13.0; with the rotation by 8 as
      one table lookup (TBL) in place of a shift and an insert, 12.5. Two
      groups a pass took 8.3. The rounds of one group kept every word in
      a register, with no load or store, so they took most of the time,
      and they waited on themselves: each quarter round is a chain of 15
      operations on NEON, each waiting on the one before, and one group
      runs four such chains at once.
    - **Two groups on NEON.** A pass holds two groups' 32 words, which
      fill arm64's 32 vector registers. The compilers keep a few of them
      on the stack: per double round the loop loads or stores a vector 11
      times under Apple clang 21, 23 times under clang 18 and 42 under
      gcc 13, beside 240 vector operations. The pass's three loops over
      its groups carry `#pragma GCC unroll 2`, for the reason `gcm_hw.c`'s
      loops carry theirs (docs/performance.md, the pitfalls): gcc keeps
      an array that a rolled loop indexes in memory.
    - **One group on SSE2.** SSE2 has 16 vector registers, which one
      group's 16 words fill. No x86-64 machine here can time a second
      group, and an emulated one says nothing about time, so SSE2 keeps
      one group a pass. It takes the XOR from registers and the last
      bytes below as NEON does.
    - **The XOR from registers.** A pass XORs each row of 16 bytes from
      the vector that holds its keystream, in ascending order, reading
      each row before it writes it, as entry 82 did from memory, so the
      output may still sit on the input or below it. The last pass tests
      each row against the bytes left, and the last 1 to 15 bytes pass
      through a buffer of 16 bytes that `ct_wipe` clears. Entry 82 left
      its last 256 bytes of keystream on the stack. No wipe written in C
      clears a register or a spill slot the compiler picks, here as
      elsewhere.
    - **Rejected: the rotation by 8 as a table lookup.** It took 6% off
      Apple clang's two-group pass. Under gcc 13 it took from 5% off to
      27% more, depending on the order of the rounds in the source: the
      lookup's index takes a register, and gcc then kept more of the
      state on the stack. gcc is the compiler CI runs, so the rotation
      stays a shift and an insert.
    - **Unchanged.** Entry 82's constant-time argument and its limits:
      128-bit vectors, no probe of the CPU, nothing in the build record.
      `chacha20_block` stays the portable function.

    Cost: on arm64 under Apple clang 21 at `-O2`, `chacha20_vector.c`'s
    text grows from 1,744 to 3,108 bytes. Its conditional branches in
    `make lint-wide-multiply` rise from 12 to 40 on arm64 and 23 on
    x86-64: most test whether the last pass's limit covers a row, and
    each tests the byte count. `bench/stack.py` puts the stack below `chacha20_xor` in a
    `CHACHA=vector` build at 544 bytes, from 768, because no call stores
    a group to memory; with `WIDEMUL=native`, the peak below `aead_seal`
    falls from 848 to 720, and its deepest path now runs through `mac`
    and the vector Poly1305. `bin/chacha20_equiv_test` runs every length
    to 2,048 bytes, which crosses a NEON pass's edge four times, and the
    counter's last 17 values at every length to 20 blocks: 49,211 cases.
    The four violations that break the path's rows, counters and last
    bytes moved to the new code, and the equivalence test catches each,
    on NEON and, under emulation, on SSE2.

    Gain: in paired runs of the record bench, a filter's figures, a
    `CHACHA=vector WIDEMUL=native` build took a 16 KiB `rec_seal` from
    17.8 to 12.1 µs on macOS clang, from 17.5 to 12.2 µs on the Linux
    VM's clang and from 18.4 to 12.7 µs on gcc 13, and ChaCha20 in place
    from 14.5, 14.0 and 15.0 µs to 8.8, 8.4 and 9.2 µs. The first pair
    agreed: 0.67, 0.64 and 0.67 of the time before, where the second gave
    0.68, 0.70 and 0.69. OpenSSL seals the same record in 9.4, 10.2 and
    10.2 µs on the same machine.

87. **A `WIDEMUL=runtime` object holds both widening multiplies, and the
    caller's answer picks one for each session**
    ([#186](https://github.com/c4milo/chapulin/issues/186)).
    `WIDEMUL=decomposed`, the default, builds every widening product from
    `ct.h`'s 16x16 pieces, and `WIDEMUL=native` takes the CPU's multiply on
    the builder's statement that it runs in constant time
    ([#53](https://github.com/c4milo/chapulin/issues/53), entry 83). Both
    fix the multiply when the object is built. On arm64 the multiply runs
    in constant time only on a core with FEAT_DIT and only while the
    thread has set PSTATE.DIT, and on x86-64 only on a part in Intel's
    DOIT list while the operating system has set DOITM. So a host program
    whose threads differ, or which runs on CPUs that differ, had no object
    that fit. Camilo decided on 2026-09-30.

    - **The build value.** `WIDEMUL=runtime` defines `CH_WIDEMUL_RUNTIME`
      and compiles twice each file built on the multiply that the object
      carries: `poly1305.c`, `x25519.c`, `mlkem_poly.c`, `p256_field.c`,
      `p256_scalar.c` and `rsa_sign.c` (`WIDEMUL_COPIED` in the Makefile,
      `widemul_copied` in `build.zig`). Under `CHACHA=vector` it adds
      `poly1305_vector_native.c`, the vector Poly1305, as a native copy
      alone, because that path runs on the native multiply only.
    - **How a file compiles twice.** The file under its own names compiles
      as a `WIDEMUL=decomposed` object compiles it: `test/widemul-builds.sh`
      requires the same assembly with the runtime define as without it, so
      the proofs and the recorded ceilings of that file hold for this copy
      unchanged. The native copy is `<file>_native.c`, two lines:
      `#include "widemul_native.h"`, then `#include "<file>.c"`.
      `widemul_native.h` defines `CH_WIDEMUL_NATIVE_COPY`, which makes
      `ct.h` take the native multiply in that translation unit alone, and
      gives each of the 52 names the seven files define outside their unit
      a second name ending in `_native`. A name missing from that list is
      defined by both copies, and the link of the object refuses it. An
      auditor reads one source per file, one two-line wrapper and one
      list of renames.
    - **The answer.** `ch_cfg.widemul`, declared only in a
      `WIDEMUL=runtime` object, takes `CH_WIDEMUL_CONSTANT_TIME`, which
      says the multiply runs in constant time on this CPU in the mode the
      session's thread runs in, or `CH_WIDEMUL_NOT_STATED`. `ch_connect`,
      `ch_record_init`, `ch_quic_init`, `ch_srv_accept`,
      `ch_srv_record_init`, `ch_srv_quic_init` and `ch_srv_check` return
      `CH_EINVAL` for any other value, 0 included, before they send
      anything, so every caller states its answer.
    - **The mode is the caller's.** Setting PSTATE.DIT on arm64, and the
      DOITM policy on x86-64, belong to the caller and its operating
      system. chapulin writes no CPU state and probes nothing (`cpu_cfg.h`),
      for the reason entry 81 gives for the AES instructions: arm64 code
      that reads PSTATE.DIT on a core without FEAT_DIT takes SIGILL, and
      code in user mode cannot read DOITM.
    - **One branch per operation.** `widemul.h` holds one dispatcher per
      entry built on the multiply that code outside the seven files calls:
      `poly1305_update`, `poly1305_final`, `x25519`, `x25519_base`,
      `mlk_polyvec_compress`, `mlk_poly_compress`, `mlk_poly_tomsg`,
      `p256_fe_mul`, `p256_fe_sqr`, `p256_fe_to_mont`, `p256_fe_from_mont`,
      `p256_fe_inv`, `p256_scalar_mul`, `p256_scalar_inverse`,
      `rsa_pss_sign` and `rsa_sp1`. Each branches once on the answer, which
      the caller chose and which is not secret: once per Poly1305 update
      and final, once per X25519 scalar multiplication, once per ML-KEM
      compression, once per P-256 field or scalar multiply, once per RSA
      signature, and never once per product. No function pointer is
      involved. `CH_WIDEMUL_CONSTANT_TIME` runs the native copy, and every
      other byte runs the file under its own names, so a direction whose
      answer was never written takes the decomposition.
    - **Where the answer travels.** Every operation built on the multiply
      takes the answer as its first argument in every build, and an object
      that holds one multiply passes `WIDEMUL_BUILD_ANSWER`, which its
      dispatchers ignore. A session passes its configuration's
      answer. Each TCP init call writes it into both record directions
      once it accepts the configuration (`rec_dir.widemul`, in bytes the
      alignment of the sequence number left unused), and each QUIC packet
      call reads it from its session.
    - **The vector Poly1305.** Under `CHACHA=vector` the constant-time
      answer also runs the vector Poly1305: `poly1305_native.c`'s block
      loop calls `poly1305_vector_blocks_native`, and `poly1305.c` under
      its own names calls no vector path (entry 83).
    - **What the build refuses.** `ct.h` refuses `CH_NATIVE_WIDEMUL` beside
      `CH_WIDEMUL_RUNTIME`, which would give the files under their own
      names the native multiply, and a native copy outside a
      `WIDEMUL=runtime` object. The Makefile, `build.zig` and `ct.h` each
      refuse `X25519=wide` beside it: that field's `CH_NATIVE_MUL128`
      states the 64x64->128 multiply's timing when the object is built
      (entry 52), which is the statement this value moves to each session.
      A copy of the wide field per answer is left for a later decision.
    - **The build record** carries `CH_BUILD_WIDEMUL_RUNTIME`, because the
      field changes the layout of `ch_cfg`, and with it of `ch_tls`,
      `ch_record` and `ch_quic`, which is entry 77's reason for
      `RAND=session`.
    - **The wrappers.** `chapulin.hpp` gains `Widemul` and
      `Config::widemul()`. The Zig API gains `Widemul` and `widemul` in
      `Client` and `Server` values, declared where `@hasField` finds the
      field; null leaves 0, which init refuses.
    - **The checks.** `bin/widemul_runtime_test` compiles the seven files
      again under counted names and runs the AEAD, X25519, ML-KEM, P-256,
      RSA signing and record operations under each answer: the native
      copies alone under the constant-time answer, the files under their
      own names alone and as many times under the other, the decomposition
      under 0, 3, 0x80 and 0xff, the same bytes under all of them, and the
      vector Poly1305 under the constant-time answer alone. The unit,
      ML-KEM, P-256 and RSA signing vectors and both Wycheproof legs run
      once per answer. `bin/tcp_blocking_loop_widemul`,
      `bin/tcp_nonblocking_loop_widemul`, `bin/quic_loop_widemul` and
      `bin/webpki_session_widemul` hold the field to 0, 1, 2 and 3 at every
      init call and `ch_srv_check`, and run a whole handshake for each pair
      of answers with the same counts. Where both ends are this tree's
      sessions they count each end's calls around its own calls, so each
      end runs the copy its own answer names, the QUIC one through a
      Handshake and a 1-RTT packet each way. `test/widemul-builds.sh` holds
      `ct.h`'s three refusals, the assembly of each file under its own
      names, the vector calls, and the Makefile's and `build.zig`'s lists
      and refusal. `lint-trust-separation` admits the native copies in
      `WIDEMUL=runtime`'s rows alone and requires each beside its file.
      `lint-wide-multiply` records each native copy's own ceilings under
      every spec: the products it asks of the native multiply, which is
      what the copy is for, and its branches, read against the file under
      its own names, which keeps its ceilings. `lint-runtime-symbols`
      admits rv32ic's `__muldi3` in the native copies, which `softmul.c`
      supplies in constant time. Fifty-three mutants in `test/violations/`
      break the new rules, and each is caught.
    - **The proofs.** No harness compiles `CH_WIDEMUL_RUNTIME`, and no copy
      needs a run of its own. `proof/run.sh` compiles each file on the
      native multiply, which is the native copy's text under other names,
      and `ctwidemul` carries those verdicts to the decomposition, which is
      the file under its own names (docs/verification.md). Under twelve
      build configurations every harness preprocesses to the text it had
      before this change, one assertion's line number aside. The
      dispatchers have no harness; the counting test holds them.
    - **CI.** The check workflow runs all of it on x86-64. The arm64 and macOS
      jobs run the `WIDEMUL=runtime` binaries under both answers in
      `suite-check` and package a `CHACHA=vector WIDEMUL=runtime` object.

    Cost:

    - Flash. The default build on `WIDEMUL=runtime` takes 35.9 kB on
      mips32r2 at `-Os`, 5.7 kB more than the default
      (docs/performance.md). On arm64 at `-O2`, counted as
      `bench/device-ram.sh` counts host flash, the packaged object grows
      from 35,754 to 44,647 bytes for the raw client, from 97,264 to
      139,882 for the server, and from 158,145 to 203,023 for the
      `CHACHA=vector` QUIC object colibri links on `AES=runtime`. A native
      copy keeps the entries no dispatcher calls, such as
      `p256_fe_add_native`, and a link that drops unreferenced functions
      can remove them.
    - `ch_cfg` grows 8 bytes on arm64, one byte and its alignment, so the
      default session struct is 1,168 bytes against 1,160. In colibri's
      QUIC object the byte sits beside `aes_instructions`, and `ch_quic`
      does not grow.
    - One compare and branch per dispatched call. No bench measures a
      `WIDEMUL=runtime` object.
    - A constant-time answer on a thread without DIT, or on a part outside
      the DOIT list, runs the native multiply where it is not constant
      time. The answer is the caller's, and chapulin cannot check it.
    - `make check` builds and runs fifteen more binaries, two more
      Wycheproof legs, three more `lib-check` objects and one more script,
      and `lint-zig-build` one more configuration.

    Gain: one object serves threads and CPUs whose multiply runs in
    constant time and those whose multiply does not, and its caller states
    which at each init, as it states the AES instructions (entry 81).

    Rejected:

    - **The renames in the build.** The Makefile could compile each file a
      second time with `-D` renames. The renames would then live in the
      Makefile, in `build.zig` and in every build a firmware tree writes,
      where a reader of the sources does not see them.
    - **A template expanded twice.** Each file could define its functions
      through a naming macro and be included twice with two suffixes. Every
      function of the seven files would change shape, and the proofs and
      lints would read macro-built names.
    - **A function pointer per operation, or a branch per product.** A
      table of pointers would make every call an indirect call an auditor
      has to trace to its table, and a branch in each product loop would
      put the answer in every inner loop. One branch per operation keeps
      the files as they were.

88. **A recipe or script that builds outside `make check` takes its
    sources from a list a rule check builds links, and check builds what a
    script still lists itself.** Recipes outside `make check` named their
    sources by hand, so a change that adds a call from one file into
    another broke only them. It happened twice on 2026-09-30: the AES=hw
    build in `bench/aead.sh` lacked `gcm_hw.c`, and bench.yml's aead job
    failed to link (9b72b67); `san-check`'s build of
    `bin/san/chacha20_equiv_test` lacked `ct.c` once `chacha20_vector.c`
    called `ct_wipe`, and CI's san job failed to link (c798fb8). `make
    check` built neither, so both landed on main.

    - **The lanes.** A test that check builds keeps the sources it links
      in a variable its rule reads, such as `RSA_TEST_SRCS` or
      `CHACHA20_EQUIV_TEST_SRCS`, and `san-check`, `cross-check`,
      `m3-check`, `coverage`, the `CH_CT_WIDEMUL` builds and the
      `WIDEMUL=runtime` builds read the same variable. The Wycheproof builds read `WYCHEPROOF_SRCS`, and the
      three differential arms and `test/spec_coverage.py` read
      `DIFF_SRCS`, which `bin/diff` reads.
    - **The scripts.** A script asks make where a variable names what it
      links: `bench/aead.sh` and `bench/record.sh` read `AES_HW_SRCS`
      (`print-aes-hw-srcs`), and `test/aes-runtime-qemu.sh` reads the
      lists its four binaries' rules link (`print-aes-runtime-qemu-srcs`).
      The three instruction-count scripts read one list of sources and
      defines, `INSN_SRCS` and `INSN_DEF` (`print-insn-lists`), where
      each kept a copy before.
    - **What check builds.** The rest of what a script lists is the
      script's own choice: the AEAD sources a bench times, or the
      modules the Cortex-M3 known answers need. `check-script-builds`
      runs `test/script-builds.sh`, which builds every such program with
      the host's compiler and runs none: `bench/aead.sh --build`,
      `bench/record.sh --build`, `bench/primitives.sh --build`,
      `test/qemu-m3.sh --build`, and `bench/insn_driver.c` over
      `INSN_SRCS` and `INSN_DEF`. The step skips when it passed before on
      the same inputs (INV-37).
    - **Found on the way.** The three instruction-count scripts had not
      compiled since b309c92, when `record.c` began to read `cfg.h`
      through `suite.h` and their builds declared no entropy pattern.
      `INSN_DEF` declares `CH_RAND_EXTERN`, which the driver never draws
      from. `bench/record.sh` had not compiled since 9cf2028, which gave
      `aead.c`'s `mac` the multiply's answer while
      `bench/record_aead.c`, which includes `aead.c`, still called it
      with seven arguments.
    - **Left as they are.** `proof/run.sh` names each harness's sources
      itself, because a harness chooses which callees are stubs, and it
      rejects a result whose log names a callee with no body.
      `bench/audit-mips.sh` compiles one file at a time and links
      nothing, and `test/quic-builds.sh` and `test/chacha-builds.sh`
      compile single files on purpose.

    Cost: one more step in check, which builds 23 programs in about 45 s
    of CPU and 9 s of wall time on an M1 Pro whenever a `.c` or `.h` file
    changes; INV-40 states the rule, and `inv40-aead-calls-hkdf` shows the
    step catches a call a script's list misses. Gain: a source list
    outside check can no longer miss a source its code calls without
    check failing first. The differential arms are the exception, because
    `bin/diff`, whose list they share, builds in `make check-slow`.

89. **A host object holds every fast path beside the portable code and
    picks among them at init from `ch_cfg.cpu`, the caller's description
    of its CPU, and a device object stays portable**
    ([#181](https://github.com/c4milo/chapulin/issues/181),
    [#183](https://github.com/c4milo/chapulin/issues/183),
    [#186](https://github.com/c4milo/chapulin/issues/186)). Four build
    variables choose the speed paths today: `AES`, `CHACHA`, `WIDEMUL` and
    `X25519`. Entries 81 and 87 moved two of those choices to each session,
    one field at a time, and colibri builds `AES=runtime` with
    `CHACHA=vector`. Camilo ruled on 2026-09-30:

    - **Direction.** A host object, for arm64 or x86-64, compiles each fast
      path for its own instructions, as `AES=runtime` compiles `aes_hw.c`,
      beside the portable code, and picks at init. A device object stays
      portable. `AES=extern` and `WIDEMUL=native` stay as device options.
      The product variables stay: `TRANSPORT`, `ROLE`, `TRUST`, `KEX`,
      `RAND` and `SUITE`. `AES`, `CHACHA`, `WIDEMUL` and `X25519` leave the
      host build, and AVX2 and VAES never become variables.
    - **Discovery.** The caller probes the CPU and passes the result in.
      chapulin still probes nothing.
    - **Shape.** `ch_cfg.cpu` is a `uint32_t` of bits. Every init refuses a
      value without `CH_CPU_PROBED`. `CH_CPU_CONSTANT_TIME_AES` says the
      CPU has the AES and carry-less multiply instructions and states that
      they run in constant time, `CH_CPU_AVX2` says it has AVX2, and
      `CH_CPU_VAES` that it has VAES and VPCLMULQDQ on 256-bit registers.
      `CH_CPU_CONSTANT_TIME_MULTIPLY` is the caller's statement about the
      multiply, and PSTATE.DIT and DOITM are the caller's to set. A caller
      written before a release that adds a bit leaves that bit clear and
      runs the slower path. A bit for another architecture is refused, not
      ignored. The field replaces `ch_cfg.aes_instructions` and
      `ch_cfg.widemul`.

    Camilo then ruled on four points the direction left open: the host
    test, the field in a device object, the AES timing statement and the
    bit that picks the wide X25519 field. He named the AES bit
    `CH_CPU_CONSTANT_TIME_AES` so that its name states the claim it
    carries. The sections below state each ruling and its reason. Once the
    code lands, this entry amends entries 50, 52, 68, 80, 81, 82, 83, 86
    and 87 where they state a speed variable.

    **The host test.** A target is a host target when its compiler passes
    the three probes the Makefile runs today for `AES=runtime`,
    `CHACHA=vector` and `X25519=wide`: it defines `__aarch64__` or
    `__x86_64__`, it defines `__ARM_NEON` or `__SSE2__` for a little-endian
    core, and it defines `__SIZEOF_INT128__`. Every
    LP64 compiler for the two architectures passes all three. The Makefile
    and `build.zig` run the test, and a host build passes one define,
    `-DCH_CPU_RUNTIME`, named after `CH_AES_RUNTIME` and
    `CH_WIDEMUL_RUNTIME`, which it replaces. A source chooses between a
    host path and the portable code on that define alone, never on an
    architecture macro. Inside a host path an architecture macro picks the
    instruction set, as `aes_hw.c` picks the Arm or the x86 AES
    instructions. `cpu_cfg.h` stops a build that passes the define for a
    target that fails the test. Reason: a firmware tree with its own
    build, the proof harnesses of the portable code, the device rows of
    `bench/sram.sh` and the test binaries of the portable code compile the
    sources without the define, so each gets the code it compiles today.
    cbmc defines the
    architecture macros of the machine it runs on, `__aarch64__` and
    `__ARM_NEON` on an arm64 Mac, so sources that chose on those macros
    would hand CBMC intrinsics, which it cannot read.

    **The product picks the object on a host target.** A
    device client, `ROLE=client` with a raw or ca `TRUST`, builds the
    portable object on every target. Entry 44 calls that client a pinned
    firmware image, and the Makefile calls it a device client when it
    refuses `SUITE=aesgcm` for it (entry 45). `TRUST=webpki`, `ROLE=server`
    and `ROLE=both` build the host object on a host target. So an arm64
    device that runs Linux and pins its server gets the small object
    through `TRUST`, and no seventh variable exists. Reasons: the default
    build, a `TRUST=raw-rsa` client, stays the portable object on every
    development machine, so `make lib`, the examples, `lint-stack`'s
    default budget and every firmware caller see what they see today; and
    a webpki or server program already needs the clock, the hostname and
    the buffers of a host. Cost: a raw or ca client on a 64-bit host never
    runs a fast path, and a webpki or server program on an arm64 device
    always takes the host object. A check that packages the device object
    of a server on a host target sets the result of the host test empty on
    its own command line: `HOST_TARGET=` for make and `-DHOST_TARGET=` for
    `zig build`. The `AES=extern` server's `lib-check` leg does, and so do
    its configuration in `lint-zig-build`'s roster and the device rows of
    `lint-trust-separation`. `HOST_TARGET=yes` names the host object the
    same way, so the rows that read a host object's sources and defines
    read the same on every compiler, and `cpu_cfg.h` still stops a compile
    for a target that fails the test. `test/host-builds.sh` holds both
    builds to both values.

    **No field in a device object.** `ch_cfg.cpu` exists only
    in a host object, as `aes_instructions` exists only under
    `AES=runtime`. A device object holds one path per primitive, so the
    field would choose nothing, and it would add 32 bits to every session's
    copy of `ch_cfg`. Required there, it would make every firmware caller's
    init return `CH_EINVAL` until the caller set it, a failure no compiler
    reports. Accepted as 0 there, its rule would differ between objects
    anyway. Cost: a program built for both kinds of object writes the
    field under `#ifdef CH_CPU_RUNTIME`. The build record's bit tells a
    consumer which layout it has, and `ch_build_matches` refuses a
    mismatch.

    **`CH_CPU_CONSTANT_TIME_AES` states the timing of the AES
    instructions.** In a host object the bit says that the CPU has the AES
    and carry-less multiply instructions, and that the caller states they
    run in constant time on it, in the mode the session's thread runs in.
    Its name states that claim, as the multiply bit's name states its own.
    A host object needs no `CH_NATIVE_AES`, and a host build drops the
    define. The security argument:

    - **What leaks.** AES-GCM leaks its key through timing only if the AES
      rounds or the carry-less multiply take a time that depends on their
      operands. Neither architecture promises fixed timing outside a mode
      its vendor names. Arm's A64 reference lists AESE, AESD, AESMC,
      AESIMC, PMULL and PMULL2 as data-independent-time instructions while
      PSTATE.DIT is 1. Intel's DOIT list names AESENC, AESDEC, AESIMC,
      AESKEYGENASSIST, PCLMULQDQ, VAESENC and VPCLMULQDQ, which hold on Ice
      Lake, Gracemont and later parts while the operating system has set
      DOITM (`cpu_cfg.h`). The same two lists name MADD, UMULH, MUL and
      MULX, which the multiply bit states.
    - **Who can state it.** The statement is about one CPU in one mode. A
      host object runs on CPUs its builder never sees: under `AES=runtime`,
      `CH_NATIVE_AES` already states the timing of instructions on CPUs
      nobody named. The caller probes the CPU and sets the mode, so the
      caller is the one party that can make the statement. Entry 87 moved
      the multiply's statement to the caller for the same reason.
    - **What stays.** chapulin infers nothing. A session whose caller
      leaves the bit clear runs ChaCha20 for every traffic key and runs the
      table on QUIC's public keys alone (INV-26), as entry 81's absent
      answer does. The table never takes a traffic key. A device object
      keeps its build statements, `CH_AES_EXTERN_CONSTANT_TIME` and
      `CH_NATIVE_WIDEMUL`, because it runs on one part its builder knows.
    - **What is lost.** Today a builder who will not state the timing
      builds an object in which no session runs AES-GCM. Afterwards only
      `SUITE=chacha` does that. A caller can also copy a probe's answer
      into the bit without meaning the claim. The bit's name and its
      comment in `cpu_cfg.h` state the claim, and `CH_CPU_PROBED` makes each
      caller write the field on purpose.
    - **Rejected.** Keeping the define would leave a host object with a
      build line about CPUs nobody has seen, beside a multiply statement it
      takes at run time from the same vendor lists. Making the multiply bit
      state the AES timing too would make AES-GCM depend on a statement
      about the multiply, which colibri does not make today.

    **The multiply bit picks the wide field.**
    `CH_CPU_CONSTANT_TIME_MULTIPLY` states the 64x64->128 multiply as well.
    Entry 52 kept `CH_NATIVE_MUL128` apart from `CH_NATIVE_WIDEMUL` for two
    reasons, and neither holds for a caller's bit. Each test binary runs
    both fields under both values of the bit, so the test flags'
    `CH_NATIVE_WIDEMUL` no longer picks a field. And the lists a caller can
    cite, DIT's and DOIT's, name both widths. Under the bit, X25519 runs
    `x25519_wide.c`, which took 34 µs a scalar multiplication on an M1 Pro
    against 428 µs for the 16-limb field on the native multiply (entry 52).
    So `x25519_native.c` goes, and a host object runs the 16-limb field on
    the decomposition alone. Cost: a caller who can state the 32-bit
    multiply and not the 64-bit one cannot say so. No part known here
    separates the two.

    **The mapping.** Each removed value becomes a bit in a host object:

    | Today | In a host object |
    |---|---|
    | `AES=hw` with `CH_NATIVE_AES`; `AES=runtime` with `CH_AES_INSTRUCTIONS_PRESENT` | `CH_CPU_CONSTANT_TIME_AES` set |
    | `AES=soft`; `AES=runtime` with `CH_AES_INSTRUCTIONS_ABSENT` | `CH_CPU_CONSTANT_TIME_AES` clear |
    | `CHACHA=vector` | no bit: NEON or SSE2 in every session |
    | `WIDEMUL=native`; `WIDEMUL=runtime` with `CH_WIDEMUL_CONSTANT_TIME` | `CH_CPU_CONSTANT_TIME_MULTIPLY` set |
    | `WIDEMUL=decomposed`; `WIDEMUL=runtime` with `CH_WIDEMUL_NOT_STATED` | `CH_CPU_CONSTANT_TIME_MULTIPLY` clear |
    | `X25519=wide` with `CH_NATIVE_MUL128` | `CH_CPU_CONSTANT_TIME_MULTIPLY` set |
    | `CHACHA=vector WIDEMUL=native`, the vector Poly1305 | `CH_CPU_CONSTANT_TIME_MULTIPLY` set |

    A host build refuses every value of `AES` and of `WIDEMUL`, a default
    value written on its command line included: it holds the AES
    instructions and both multiplies, so neither variable chooses anything
    there. `AES=soft`, `AES=extern`, `WIDEMUL=decomposed` and
    `WIDEMUL=native` stay for device objects. Every build refuses `X25519`
    and `CHACHA`, which choose nothing in either object: a device object
    holds the 16-limb field and `chacha20.c`'s loop alone. A host session
    never runs that loop: every
    arm64 core has NEON and every x86-64 core SSE2 (entry 82), so no bit
    turns the vector path off, and `chacha20_block`, which derives the
    Poly1305 key, stays the portable function. Entry 90 added the AVX2
    ChaCha20 and the VAES GCM with a predicate each, and this entry adds
    none of its own. `chacha20.c`'s `use_avx2` reads `CH_CPU_AVX2`.
    `gcm_vaes.h`'s `gcm_use_vaes` reads `CH_CPU_VAES` beside
    `CH_CPU_CONSTANT_TIME_AES`, whose statement covers the AES instructions
    at every width, from the byte each AES key schedule records of its
    session's `ch_cfg.cpu`.

    **What init refuses.** `ch_connect`, `ch_record_init`, `ch_quic_init`,
    `ch_srv_accept`, `ch_srv_record_init`, `ch_srv_quic_init` and
    `ch_srv_check` return `CH_EINVAL`, before they send anything, for a
    value without `CH_CPU_PROBED` and for a value with a bit this object
    does not define for its architecture: `CH_CPU_AVX2` or `CH_CPU_VAES` on
    arm64, or a bit a later release adds. A defined bit for instructions
    the object never runs, such as `CH_CPU_CONSTANT_TIME_AES` in a TCP
    object without `SUITE=aesgcm`, still describes the CPU, and init
    accepts it. In a `SUITE=aesgcm` object with `CH_CPU_CONSTANT_TIME_AES`
    clear, init refuses a `cipher_suites` list that names an AES-GCM suite,
    as it does for entry 81's absent answer.

    **How the object chooses.** Entries 81 and 87 already built the parts.
    A target pragma compiles each instruction set's functions for those
    instructions alone, so the rest of the object runs on any CPU of its
    architecture. Each file built on the multiply compiles twice, the
    second time as `<file>_native.c`. One branch per operation reads the
    session's bits, and no function pointer is involved. A host object is
    compiled for its architecture's base instruction set: a builder who
    passes `-march` for a newer CPU makes the whole object require that
    CPU, whatever the bits say.

    **What goes and what merges**, counted at 178f791:

    | What | Today | After |
    |---|---|---|
    | Speed variables, and their values | 4, and 11 | 2, and 4, for device objects |
    | Compiler probes for them | 4 | 1, the host test |
    | `lib-check` legs in `make check` | 29, 12 for a speed value | 20 |
    | `lint-zig-build` configurations | 32, 15 for a speed value | 22 |
    | Wycheproof binaries | 7 | 3 |
    | Test binaries the four variables add | 37 | about 20 |
    | `lint-trust-separation` rows that name a speed value | 23 | about 12 |
    | Native-copy ceilings in `lint-wide-multiply` | 110 | 12 |
    | Scripts that test the variables' refusals | 3 | 1 |
    | Speed steps in each of CI's arm64 and macOS jobs | 4 | 2 |
    | Build-record bits | 2 | 1, `CH_BUILD_CPU_RUNTIME` |
    | `build.zig` options | 16 | 13, `HOST_TARGET` among them |
    | `ch_cfg` fields | 2 | 1 |
    | `chapulin.hpp` types and setters | 4 | 2 |
    | Zig API types and fields | 6 | 3 |
    | Timing defines | 4 | 2, for device objects |

    The two rows that say "about" were estimates. At the fifth commit
    the tree holds 24 host test binaries on arm64 and 25 on x86-64
    (`HOST_BINS`, `HOST_VECTOR_BINS` and `bin/x86_kernels_test`), and 26
    `lint-trust-separation` rows name a speed variable, 19 of them a build
    the Makefile must refuse.

    - Nine `lib-check` legs go: the five that name a fast path on a raw
      client, and the four that repeat a webpki, server or QUIC object the
      host test now builds. Three stay: a server and colibri's QUIC object,
      both on `SUITE=aesgcm`, and the device server on `AES=extern`. The
      eight legs of webpki and server products build the host object with no
      change to their command lines. Ten Zig configurations go the same way.
    - The three Wycheproof binaries are the default one, the `AES=extern`
      one and the host one, which runs once per set of bits that changes a
      path: four times on arm64, and on x86-64 twice more, with
      `CH_CPU_AVX2` added and then `CH_CPU_VAES`, where the CPU has the
      instructions.
    - The five equivalence tests stay. Each loop, session and vector test
      becomes one host binary that runs under every set of bits.
    - The eight 32-bit specs of `lint-wide-multiply` never compile a native
      copy, and `x25519_native.c` goes.
    - Each of CI's arm64 and macOS jobs keeps one host `lib-check` and one
      disassembly, which then covers every file a target pragma compiles.
      The mips job's qemu run stays, and runs the host binaries with the
      bits clear on a CPU without the instructions. It also runs them on a
      CPU model for each x86-64 bit, where a session that names
      instructions the model lacks dies of SIGILL.
    - `CH_BUILD_CPU_RUNTIME` takes a new bit, so no record from 0.1.0
      matches a host object.
    - `CH_NATIVE_AES` and `CH_NATIVE_MUL128` go. `CH_NATIVE_WIDEMUL` and
      `CH_AES_EXTERN_CONSTANT_TIME` stay for device objects.
    - 132 of the 599 mutants in `test/violations/` name a speed variable,
      its define or one of its files. Most hold code that stays. Each
      commit re-points or retires the ones that name what it removes.

    **Migration.** Six commits, each through `make check`. Each code commit
    marks its break with `!` in its header and updates the docs that state
    what it changes.

    1. The interface: `ch_cfg.cpu` and its bits in `cpu_cfg.h`, the host
       test in the Makefile and `build.zig`, `CH_CPU_RUNTIME`,
       `CH_BUILD_CPU_RUNTIME`, the refusals, `Config::cpu()`, the Zig `cpu`
       fields and the tests of the refusals. No path reads the bits yet:
       the four variables still choose, and no output byte changes.
    2. AES. A host object holds the instructions, and in a QUIC object the
       table for public keys, as `AES=runtime` does, and
       `CH_CPU_CONSTANT_TIME_AES` picks. `AES=hw`, `AES=runtime`,
       `aes_instructions` and `CH_NATIVE_AES` go.
    3. The multiply. A host object holds the native copies, and the
       multiply bit picks. `WIDEMUL=runtime` and `ch_cfg.widemul` go.
    4. X25519. The wide field joins every host object under the multiply
       bit, and `x25519_native.c`, `X25519` and `CH_NATIVE_MUL128` go.
    5. ChaCha20. The vector path joins every host object, the vector
       Poly1305 runs under the multiply bit, and `CHACHA` goes.
    6. CLAUDE.md, with the text Camilo approves.

    Each code commit measures the objects it changes with `bench/sram.sh`
    and `bench/device-ram.sh`. The AVX2 and VAES predicates landed before
    commit 1 (entry 90), and commit 5 makes them read their bits, with the
    rest of the x86-64 vector paths.

    - **colibri** links `TRANSPORT=quic-nonblocking ROLE=both TRUST=webpki
      SUITE=aesgcm AES=runtime CHACHA=vector` with `CH_NATIVE_AES` through
      `build.zig`, and sets `aes_instructions` from stdx's platform probe
      (https://github.com/c4milo/stdx/issues/15). From commit 1, every init
      returns `CH_EINVAL` until colibri sets `cpu`. From commit 2,
      `build.zig` no longer declares `AES=runtime` or `CH_NATIVE_AES`,
      which `zig build` then refuses. The probe's answer and the timing
      claim colibri's build stated with `CH_NATIVE_AES` move into
      `CH_CPU_CONSTANT_TIME_AES`. From commit 5 the same holds for
      `CHACHA`, and the vector path runs anyway. Its sessions keep their
      paths: AES-GCM on the instructions under `CH_CPU_CONSTANT_TIME_AES`,
      and the decomposition unless colibri sets the multiply bit. stdx's
      probe must learn AVX2 and VAES before colibri can set those bits.
    - **stompy**'s object is `TRUST=webpki TRANSPORT=tcp-nonblocking
      ROLE=both` at `TX_RECORD=16384` (entry 71). It is a host object, so
      from commit 1 every init refuses its configuration until stompy sets
      `cpu`. If it builds `SUITE=aesgcm AES=hw` with `CH_NATIVE_AES`, as the
      TCP object entry 80 measured through colibri's h11 client did, commit
      2 refuses those values, and without `CH_CPU_CONSTANT_TIME_AES` its
      sessions offer ChaCha20 alone. From commit 5 its ChaCha20 runs the
      vector path.
    - **Semver.** Item 4 of SemVer 2.0.0 lets anything change in a 0.y.z
      release. The series ships as 0.2.0 in `build.zig.zon`, tagged once
      the nightly passes on its last commit, as 0.1.0 was. colibri and
      stompy pin chapulin by hash, so each moves from 0.1.0 to 0.2.0 in one
      step, when it chooses.

    **CLAUDE.md.** Three bullets change, with the text Camilo approves.
    The protocol bullet states the webpki client's suite order on `AES=hw`
    with `CH_NATIVE_AES`. The dependency bullet names a variable beside
    `chacha20_vector.[ch]`, `poly1305_vector.[ch]`, the three
    implementations behind `aes_block.h`, `ghash_hw.[ch]`, `gcm_hw.[ch]`
    and `x25519_wide.[ch]`. The constant-time bullet states the widening
    multiply, the `X25519` and `CHACHA` variables, the `AES` variable and
    the suite's timing defines. Its paragraphs on the two purposes of AES
    and on the two key types stay.

    Cost:

    - Every host object holds every path. Entry 87 measured the multiply
      alone: on arm64 at `-O2`, the server object grows from 97,264 to
      139,882 bytes when it holds both multiplies, and the AES and vector
      paths add more. `bench/device-ram.sh` measures each commit. At the
      fifth commit, under Apple clang 21 at `-O2`, the vector ChaCha20 and
      Poly1305 add 4,860 bytes of text to an arm64 host object that held
      neither, and 12,185 on x86-64, where the AVX2 kernel comes with them:
      the server object holds 144,506 and 182,307 bytes. colibri's QUIC
      object, which built `CHACHA=vector` before, holds 203,131 and
      263,631, 396 and 704 more than that build. No session struct grows:
      a record direction keeps its copy of `cpu` in 4 bytes its alignment
      left unused.
    - A host session always runs the vector ChaCha20, which no proof
      covers. The proved loop runs in device objects alone.
    - Every host caller writes `ch_cfg.cpu`, and colibri and stompy change
      their builds and their configurations.
    - A host object's timing statements move from build lines, which a
      reviewer reads once, into each caller's code.
    - A 32-bit target loses two choices: `CHACHA=vector` on 32-bit NEON or
      SSE2, which no CI leg builds, and `WIDEMUL=runtime`, which entry 87
      measured on mips32r2 and no consumer links.
    - A 64-bit target that is neither arm64 nor x86-64, such as riscv64,
      loses `X25519=wide`, which it could build: the wide field is in a
      host object alone, and the host test names two architectures. No CI
      leg built it there.

    Gain: one object per product and architecture runs on every CPU of
    that architecture, at the speed its caller describes. Four variables
    leave the host build, `make check` packages nine fewer objects and
    `lint-zig-build` builds ten fewer configurations, and an instruction
    set a later release adds becomes a bit, not a variable.

    Rejected:

    - **The host target alone, for every product.** The default object, a
      raw client, would become the host object on every development
      machine. The examples and `lint-stack`'s default budget would then
      measure the host object, and a firmware's raw client built on a
      64-bit machine would have a field it lacks on its device.
    - **A seventh variable that asks for the device object.** It would
      bring back a speed choice in the build, which the ruling removes, for
      a case `TRUST` already names.
    - **Choosing on the architecture macros in the sources.** The proofs
      would compile intrinsics, and a firmware tree with its own build
      could not get the portable object for a 64-bit target.

90. **Every x86-64 host object carries an AVX2 ChaCha20 kernel beside its
    SSE2 path, and VAES and VPCLMULQDQ AES-GCM kernels beside its 128-bit
    loops, and the caller's CPU bits pick them.** When this entry landed
    no call ran them, because `ch_cfg.cpu` did not exist yet; the last
    bullet of the list below says what entry 89's code changed. On
    GitHub's x86-64 runners a 16 KiB
    `rec_seal` took about 6 µs on AES-128-GCM where OpenSSL took 4, and
    about 20 µs on ChaCha20-Poly1305 in a `CHACHA=vector WIDEMUL=native`
    build where OpenSSL took 7.5. chapulin ran SSE2 and the 128-bit AES-NI
    and PCLMULQDQ there, on CPUs that have AVX2, VAES and VPCLMULQDQ.
    Under entry 89 a host object picks its paths at init from
    `ch_cfg.cpu`, which the caller fills from its own probe, and entry 89
    names the bits these kernels need: `CH_CPU_AVX2`, `CH_CPU_VAES` and
    `CH_CPU_CONSTANT_TIME_AES`. chapulin probes nothing.

    - **The ChaCha20 kernel.** `chacha20_avx2.c` holds each of the 16
      state words of eight consecutive blocks in one 256-bit vector, one
      block per lane, and runs `chacha20.c`'s rounds on the 16 vectors:
      one group a pass, because AVX2's 16 registers hold one group's 16
      words. The rotations by 16 and by 8 move whole bytes, so each is one
      byte shuffle (VPSHUFB) under a constant order, and the rotations by
      12 and 7 shift and OR. A 4x4 transpose within each 128-bit half and
      VPERM2I128, which joins two halves, turn the 16 vectors into 16 rows
      of 32 bytes in block order. The pass XORs them into the data from
      the registers in ascending order, so the output may sit on the input
      or below it, as entry 86's path allows. The last 1 to 31 bytes pass
      through a buffer of 32 bytes that `ct_wipe` clears.
    - **The AES-GCM kernels.** `gcm_vaes.c` runs `gcm_hw.c`'s three loops
      two blocks to a 256-bit register. VAESENC runs one AES round on each
      half of a register, so each round key is loaded into both halves.
      The counters keep their bytes reversed, so one 32-bit add per pair
      of blocks is inc32, and one byte shuffle puts each block back in
      order. GHASH multiplies a pair of blocks by a pair of powers with one
      VPCLMULQDQ per product, 12 per pass of eight blocks where
      `ghash_vector.h` takes 24, adds each sum's two halves, and runs
      `ghash_vector.h`'s reduction unchanged. The powers are
      `ghash_vector.h`'s, paired, and read through a volatile lvalue from
      the state each call wipes, for the reason `ghash_power_at` gives.
    - **A step of two passes.** The AES rounds run a step at a time, two
      of `gcm_hw.h`'s passes in eight registers. VAESENC's next round on a
      register waits on its last, and a step of one pass, four registers,
      left the AES units idle between rounds. In one run on an EPYC 7763
      runner that built both in each job, a 16 KiB AES-128-GCM seal took
      4.66 µs under gcc and 3.36 under clang with steps of one pass, and
      4.07 and 3.20 with steps of two; the open moved from 3.43 to 3.38
      and from 3.10 to 3.03. GHASH keeps its
      pass of eight blocks, so the powers and the reduction stay
      `ghash_vector.h`'s, and `gcm.c`'s split of a message into passes
      stays as it was. A call with an odd number of passes ends on a step
      of one pass, whose rounds still run on eight registers; the four it
      does not use hold keystream no output takes, and the call's wipe
      clears them.
    - **Target attributes, not flags.** Every function in
      `chacha20_avx2.c` carries `target("avx2")`, and every function in
      `gcm_vaes.c` `target("aes,pclmul,avx2,vaes,vpclmulqdq")`, applied by
      one clang attribute push or one gcc target pragma, as entry 81
      applies AES=runtime's. So an object needs no instruction flag for
      them, and the rest of it runs on any x86-64 CPU, with AES-NI and
      PCLMULQDQ under `AES=hw`. `chacha20_avx2.c` joins every x86-64
      `CHACHA=vector` object and `gcm_vaes.c` every x86-64 `AES=hw` and
      `AES=runtime` object, and on arm64 both compile to nothing.
    - **One predicate per path.** `chacha20.c`'s `use_avx2` decides
      whether `chacha20_xor` runs the kernel in place of
      `chacha20_vector.c`'s SSE2 path, and `gcm_hw.c`'s `use_vaes` whether
      its three entries hand their blocks to the kernel of the same shape,
      so `gcm.c` is unchanged. Both answer 0 until `ch_cfg.cpu` exists.
      Then `use_avx2` reads `CH_CPU_AVX2`, and `use_vaes` reads
      `CH_CPU_VAES` and `CH_CPU_CONSTANT_TIME_AES` and answers 1 only where
      both are set. Under AES=runtime, `ch_cfg.aes_instructions` says only
      that AES-NI and PCLMULQDQ exist, so it cannot pick the kernels.
    - **Timing.** The ChaCha20 kernel is constant time by entry 82's
      construction: adds, exclusive-ors, shifts and byte shuffles under
      constant orders, with no table, no multiply, and no branch or
      address on the key, the nonce, the counter or the data. The GCM
      kernels run VAESENC and VPCLMULQDQ under a traffic key in a
      SUITE=aesgcm build. Entry 89's `CH_CPU_CONSTANT_TIME_AES` states
      that the AES instructions and the carry-less multiply run in
      constant time at every width, and the DOIT list it cites names
      VAESENC and VPCLMULQDQ; `use_vaes` is to require that bit.
      `CH_NATIVE_AES` states nothing about the 256-bit forms, and no
      define makes a kernel run (`ct.h`).
    - **What tests may ask.** Test code asks its CPU through
      `__builtin_cpu_supports` and CPUID (`test/x86_kernels_cpu.h`); the
      library asks nothing. The equivalence tests call the kernels
      directly, and three binaries and a Wycheproof leg send the library's
      calls to them through a force-included header that renames the
      128-bit entry, while the library's own predicates still answer 0.
      Each skips a CPU without the instructions, and CI's `x86-64-kernels`
      job, under `CH_REQUIRE_X86_KERNELS=1`, fails on one instead
      (docs/verification.md, "The x86-64 kernels").
    - **Left out.** An AVX2 Poly1305, which follows
      [#186](https://github.com/c4milo/chapulin/issues/186)'s rework of
      the multiply files. A 512-bit path: on a Xeon Platinum 8370C runner,
      which has AVX-512, OpenSSL sealed 16 KiB of AES-128-GCM in 1.42 µs
      where these kernels took 3.29 under clang and 3.64 under gcc. A GHASH
      pass of sixteen blocks, which would need sixteen powers of H and a
      pass size `gcm.c` does not know.
    - **Since entry 89's code.** Its fifth commit made both predicates
      read the bits, and four statements above changed with it. Both
      kernels join every x86-64 host object, which is the one object that
      holds either. `use_avx2` answers for `chacha20_xor_cpu`, which takes
      a session's `ch_cfg.cpu` from a record, a packet or an AEAD call;
      `chacha20_xor` takes no value and runs the SSE2 path. The GCM
      predicate is `gcm_vaes.h`'s `gcm_use_vaes`, beside three inline
      entries that `gcm.c` calls, so `gcm_hw.c` is the 128-bit path alone
      and calls no kernel, and each key's schedule records the low byte of
      its session's `ch_cfg.cpu` for the predicate to read. The three
      binaries and the Wycheproof leg that renamed the 128-bit entries are
      gone: `bin/unit_host`, `bin/ghash_equiv_test`, `bin/quic_test_hw`
      and the Wycheproof host binary run those cases on the kernels under
      the `ch_cfg.cpu` values that name them, and `bin/x86_kernels_test`
      counts which calls run a kernel under each value.

    Cost:

    - 339 lines in `chacha20_avx2.[ch]` and 535 in `gcm_vaes.[ch]`, with
      no harness, because CBMC cannot read an intrinsic.
    - At `-O2` on x86-64, `chacha20_avx2.o` holds 2,821 bytes of text
      under gcc 13 and 3,015 under clang 18, and `gcm_vaes.o` 4,542 and
      7,542, beside `gcm_hw.o`'s 4,996 and 6,723. Every x86-64
      `CHACHA=vector` object carries the first, and every x86-64 `AES=hw`
      and `AES=runtime` object the second.
    - Stack frames: the ChaCha20 kernel's pass takes 904 bytes under gcc
      and 616 under clang; the GCM seal 1,024 and 1,016, the open 1,024
      and 984, and counter mode 384 and 376, where `gcm_hw.c`'s seal takes
      576 and 600.
    - Three binaries and one Wycheproof leg in `make check` on an x86-64
      host, and CI's `x86-64-kernels` job.

    Gain, 16 KiB records in µs: the medians bench/record.sh writes, from
    bench.yml's `record-x86_64` job at 6763ce8 on an AMD EPYC 7763 runner,
    whose one-minute load average ran from 0.44 to 0.97. "Before" is the
    128-bit path and "after" the kernels, built in the same job.
    OpenSSL 3.6.4's figures are the gcc job's; the clang job's differ by
    0.02 at most.

    | | gcc before | gcc after | clang before | clang after | OpenSSL |
    |---|---|---|---|---|---|
    | AES-128-GCM seal | 6.29 | 3.69 | 5.85 | 3.19 | 4.05 |
    | AES-128-GCM open | 6.10 | 3.39 | 5.34 | 3.03 | 4.12 |
    | AES-256-GCM seal | 7.06 | 4.14 | 6.50 | 3.61 | 4.36 |
    | AES-256-GCM open | 6.92 | 3.83 | 5.98 | 3.44 | 4.43 |
    | ChaCha20-Poly1305 seal | 20.19 | 13.64 | 21.29 | 13.65 | 7.47 |
    | ChaCha20-Poly1305 open | 19.98 | 13.39 | 21.04 | 13.55 | 7.47 |
    | ChaCha20 alone | 13.11 | 6.51 | 13.94 | 6.57 | |

    Of the kernels' AES-128-GCM seal, the AEAD took 2.98 µs under gcc and
    2.63 under clang, and the record layer 0.71 and 0.57. Poly1305 takes
    6.6 to 6.8 µs of the ChaCha20-Poly1305 rows either way, which
    [#186](https://github.com/c4milo/chapulin/issues/186) addresses. A
    run 40 minutes earlier on the same CPU model, at the same kernels,
    gave gcc's AES-128-GCM seal 4.07 and clang's 3.20, so the gcc figure
    moved by 10% from one runner to the next.
91. **`ct_wipe` calls the libc's `memset` through a volatile function
    pointer, and the proofs read a byte-loop stub with the same
    contract.** `ct_wipe` stored one byte per iteration through a
    volatile pointer, and a compiler may not merge volatile stores into
    wider ones. Since entry 85 a forged AES-GCM open wipes the plaintext
    it wrote, so refusing a forged 16 KiB record took 8.3 µs on the M1 Pro
    where a genuine open took 2.6, and every seal and open also wipes its
    expanded key and the state of its passes once a call. `ct_wipe` now
    sits in `ct_wipe.c`, which holds

    ```c
    static void *(*const volatile ct_memset)(void *, int, size_t) = memset;
    ```

    and calls `memset` through it when n is not 0. `ct.c` keeps
    `ct_memeq`, and `ct.h` declares both.

    - **Why the compiler keeps the call.** A volatile object is read each
      time the abstract machine reads it (C11 5.1.2.3p6), so the compiler
      loads the pointer at every call and cannot tell which function the
      load returns. It cannot delete a call to a function it does not
      know, and it cannot treat the call as a `memset` whose stores no
      later read needs. That holds where it inlines `ct_wipe` into a
      caller whose buffer ends right after the call, as a consumer's
      link-time optimization does. `memset` is the libc's, compiled apart
      from every caller, so it writes each byte.
    - **What a compiler may still do.** It may compare the loaded pointer
      with `memset` and drop the call on the branch where the two are
      equal. gcc and clang make that comparison for an indirect call only
      from a profile: gcc's value-profile transformations and LLVM's
      indirect-call promotion read `-fprofile-use` data. A
      profile-guided build of chapulin needs its output read again.
    - **n of 0.** C11 7.24.1p2 asks `memset` for a valid pointer even
      when n is 0, so `ct_wipe` makes no call then, and a caller with
      nothing to wipe may pass a null pointer. The branch reads the
      length, which is public.
    - **The output read.** A scratch unit compiled this `ct_wipe` beside
      two functions that each pass a stack buffer of 64 bytes or 16 KiB to a
      function in another unit, wipe it and return, at `-O2` and `-Os`,
      under Apple clang 21 for arm64 and x86-64 macOS; clang 23.1.2 for
      arm64 and x86-64 Linux, `thumbv7m-none-eabi -mcpu=cortex-m3`,
      `mips-linux-musl -march=mips32r2` and `riscv32-unknown-elf
      -march=rv32imac`; gcc 13.3 for x86-64 and arm64 Linux; the Arm GNU
      gcc 15.3.1 the m3 lane pins; the mips lane's gcc 12.4; and the
      riscv32 lane's Bootlin gcc 14.3 at rv32imac and rv32ic. Every clang
      at both levels, and every gcc at `-O2`, inlines `ct_wipe`, and the
      caller loads `ct_memset` and calls through it. gcc at `-Os` calls
      `ct_wipe.part.0`, the out-of-line part of `ct_wipe` after the test
      of n, which does the same. With `ct_wipe` calling `memset` by name
      instead, every clang deletes the call at both levels and every gcc
      at `-O2`; gcc at `-Os` keeps it only because it does not inline
      `ct_wipe` there.
    - **The proofs.** 84 launch lines in `proof/run.sh` link `ct.c`, and
      20 of them bound the loop `ct_wipe.0`. Each now links
      `proof/ct_wipe_stub.c` beside it, a contract stub that is the loop
      `ct_wipe` was, so no other harness's formula changed: `ct_memeq` in
      `ct.c` and `ct_wipe` in the stub are the same tokens as the two
      bodies `ct.c` held at a104a3e. `proof/ct_harness.c` proves the stub
      writes zero to p[0..n), as it proved of the loop before, and now
      also that it writes no byte past them. `proof/ct_wipe_harness.c`
      proves `ct_wipe.c` memory-safe and UB-free, zero over p[0..n) and
      no other byte written, over a heap buffer of every size CBMC's
      pointer encoding holds, in 0.5 s and 22 MB. Of `memset` it proves
      CBMC's model only. Run one at a time under a 30-minute limit,
      beside other jobs on the M1 Pro, `ct` proved 63 properties in 12 s,
      `ct_wipe` 66 in under a second, `aead` 254 in 6 s, `gcm_safety` 457
      in 254 s, `handshake_post` 765 in 119 s and `record` 412 in 603 s.
      At a104a3e the last four prove the same counts, and `ct` proves 59,
      without the check of the bytes past n.
    - **Tests.** `bin/unit` wipes n bytes for each n from 0 to 32 between
      guard bytes, and a null pointer with n of 0.
      `test/poly1305_equiv_vector.c` compiles `ct_wipe.c` into the unit
      that holds the vector Poly1305, renamed as that unit renames its
      other calls, so the compiler can inline `ct_wipe` where the call's
      powers of r end. `ct-wipe-plain-memset` calls `memset` by name, and
      `bin/poly1305_equiv_test` then finds the powers on the stack, under
      Apple clang 21 and under gcc 13.3 on arm64 and x86-64 Linux. Every
      other binary compiles `ct_wipe.c` as a unit of its own, where no
      compiler can delete either body's call, so no other test notices
      the mutant.
    - **Zig.** Zig 0.16's compiler_rt exports a weak `memset` that stores
      one byte per iteration: built for aarch64 Linux at `ReleaseFast`, it
      is a loop of `strb`. A Zig program on Linux that links no libc gets
      that one, so its `ct_wipe` still writes every byte through the same
      volatile pointer, at about the old loop's speed. colibri and stompy
      get the speed below when they link a libc or export a faster
      `memset` of their own, which takes the place of the weak one.

    Rejected:

    - **`memset` and a fence.** C11 names no barrier that keeps stores
      nothing reads afterwards. `atomic_signal_fence` orders memory
      against a signal handler, and whether it keeps a `memset` of a
      buffer whose lifetime then ends is the compiler's choice, not the
      standard's. An `asm` statement with a memory clobber keeps it, and
      is GNU C, not C11.
    - **Wider volatile stores.** A `uint32_t` or `uint64_t` lvalue stored
      into a byte array breaks the effective-type rule (C11 6.5p7).
    - **`memset_s`, `explicit_bzero` or `memset_explicit`.** Annex K is
      optional, and glibc and musl do not ship `memset_s`;
      `explicit_bzero` is not in C. C23's `memset_explicit` is the
      standard form of this call, and chapulin builds as C11.
    - **Keeping the loop.** It costs what the gain below measures.
    - **A second body in `ct.c` under `__CPROVER__`.** cbmc defines that
      macro, so `ct.c` could have compiled the loop for the proofs and the
      `memset` call for every build. Camilo ruled on 2026-10-01 that
      shipped C carries no verification token (docs/proofs.md, "Prior
      art"), and the stub on the launch line keeps every formula without
      one.

    Cost: one indirect call per wipe, one pointer in read-only data, and a
    branch on n. On mips32r2 `ct.o` and `ct_wipe.o` take 120 bytes where
    `ct.o` took 100, and `ct_wipe`'s frame grew from 0 to 24
    (`bench/device-ram.sh`). Where `memset`
    is itself a byte loop the call adds a little: `bench/insn-mips.sh`
    links such a `memset`, and there a 1 KiB AEAD seal went from 81,976
    to 82,006 instructions and its stack from 748 to 756 bytes. On the
    Cortex-M3, whose newlib `memset` stores words, the same seal went from
    67,684 to 67,367 instructions.

    Gain, in paired runs on the M1 Pro under macOS's Apple clang 21, then
    in the OrbStack VM under clang 18 and gcc 13:

    - A forged 16 KiB AES-128-GCM open, timed directly: 8.3, 8.8 and
      8.6 µs before, 2.5, 3.0 and 2.8 µs after; at 1 KiB, 877, 909 and
      921 ns before, 248, 264 and 275 ns after.
    - The record bench's 16 KiB AES-128-GCM seal, `gcm_traffic_seal`:
      2.59, 2.95 and 2.95 µs before, 2.28, 2.63 and 2.62 µs after; at
      1 KiB, 556, 586 and 613 ns before, 248, 283 and 278 ns after. The
      wipe of the expanded key took 93, 95 and 95 ns, and takes 5.5, 4.7
      and 4.7.
    - ChaCha20-Poly1305's 16 KiB seal did not move past the runs' spread
      in the packaged build, and fell by 1% under `CHACHA=vector
      WIDEMUL=native`, whose vector Poly1305 wipes its powers of r on
      each call; at 1 KiB that build's seal fell by 9%.

    The CSVs that docs/performance.md renders were measured again for this
    entry, and two of their changes predate it. `bench/results-device.csv`
    was older than `handshake_auth.c`, whose object is 736 bytes at
    a104a3e where the file held 648. And at a104a3e, before this change as
    after it, the packaged ChaCha20-Poly1305 record takes 2% to 3% longer
    than in the runs the tables held at 97826ba, and the VM's clang runs
    the vector Poly1305 in 4.8 µs where those runs took 3.0.
