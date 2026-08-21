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

6. **ChaCha20-Poly1305 only; AES never enters the codebase.** Cost: the
   IoT profile's mandatory AES-CCM suite and AES-only servers. Gain:
   constant time by construction on any core — no lookup tables, no
   timing story to defend. An AES-CCM build flag is the most likely
   future concession.
7. **x25519 in 16-bit limbs (the TweetNaCl scheme).** Cost: about 57 ms
   per scalar multiplication on the mips32r2 reference target, where
   wider limbs would be faster. Gain: a machine-checked overflow lemma
   and citable prior formal work on the same scheme. Provability over
   speed; revisit if the workload becomes many short connections.
8. **One pinned signature algorithm per build**: RSA-PSS by default,
   P-256 behind `make PIN=ecdsa`, never both. Cost: switching means
   rebuilding. Gain: no signature-algorithm negotiation surface and a
   smaller binary. RSA won the default on measurement — its verify is
   4x faster and 3.8 kB smaller in flash than P-256's — and RSA is what
   stock endpoints hold.
9. **RSA is verify-only**: exponent fixed at 65537, moduli of 256 to
   384 bytes, the pin is the raw modulus, no PKCS#1 v1.5, deliberately
   variable time. Cost: exotic keys are unsupported. Gain: a tiny
   fixed-shape verifier with no ASN.1 anywhere. Variable time is safe
   because every input to verification is public.
10. **No Ed25519.** Cost: none today — no real server-certificate
   population uses it, and PSK already covers endpoints we control.
   Gain: no second hash function (Ed25519 needs SHA-512) and no third
   pin mode.

## Trust model

11. **Certificates are hashed into the transcript, never parsed.** No
    X.509, no chains, no names, no expiry, no revocation, no trusted
    clock. Cost: no PKI; the operator provisions a key. Gain: the
    DER-parser vulnerability class does not exist here. CA pinning has
    been evaluated and declined: the measurable costs (6 to 15 kB of
    flash, one extra verify per chain link) are affordable, but it
    readmits the parser class, needs a trusted clock for validity, and
    a pinned public CA without name checking turns every certificate
    that CA ever issued into a skeleton key.
12. **Key rotation is a second pin slot, not CA indirection.** Cost: 16
    bytes of config and an out-of-band recovery path for devices that
    miss both pushes. Gain: rotation without a fleet flag day, inside
    the trust model we already have. See docs/rotation.md.
13. **Tickets make both auth modes cheap.** Reconnects resume over PSK,
    so pinned mode pays its signature verification once per ticket
    lifetime; the recurring cost of any handshake is the two x25519
    operations.

## Memory and runtime

14. **Zero heap.** One caller-allocated session struct plus one
    caller-provided receive buffer. Cost: the caller sizes memory up
    front. Gain: no allocator, no out-of-memory paths, and bounds the
    proofs can state exactly.
15. **`record_size_limit` is the receive buffer's size.** Cost:
    strictness toward peers that ignore RFC 8449 — an oversized record
    is a protocol error, not a resize. Gain: a peer can never send what
    the buffer cannot hold.
16. **Single task, single connection.** The reference random generator
    is opt-in source with global state, excluded from the packaged
    object. Cost: no multi-session generator isolation. Gain:
    `ch_rand_bytes` stays a clean import that firmware replaces; see
    docs/entropy.md.
17. **Every operational error fails closed**: alert, wipe keys, dead
    session, caller reconnects. Cost: no graceful recovery. Gain: the
    entire resumable-error state space is removed from the code and the
    proofs. Corollary: `CH_EINVAL` (invalid configuration, nothing
    sent) is distinct from `CH_ECAP` (runtime capacity), so
    provisioning corruption never reads as an attack on the wire.

18. **One TX staging array, sized per build.** The ClientHello
    builder and the sealed-record path share the session's TX array;
    their lifetimes never overlap. A build whose hello outgrows one
    sealed record (a PQ key share) raises `CH_TX_STAGE` for that build
    alone. A second array would cost every build the hello's bytes,
    and the handshake proof keeps one array to model. Streaming the
    hello stays rejected: the PSK binder is an HMAC over the
    contiguous truncated hello, so a streaming builder would buffer
    the message anyway.
19. **The receive-buffer floor is a build constant.** `ch_connect`
    checks `buf_len` against `CH_MIN_RXBUF` before anything is sent.
    A feature that needs more room raises the constant, so a
    too-small buffer fails at setup with `CH_EINVAL`, not
    mid-handshake with `CH_ECAP`, where it would read like an attack.
    The floor covers only what the build can know: a pinned server's
    chain is the server's choice, so pinned deployments size above
    the floor.

## Assurance

20. **Bounded model checking, layered, with a published ledger.** Leaf
    modules prove concrete; upper layers prove against
    contract-checking stubs of the proven layer below. Where a formula
    will not converge, the harness pins a representative bound and
    documents it. Cost: this is not functional verification. Gain:
    proofs that finish, and claims nobody has to take on faith — the
    README states what is proved, at what bound, and what is only
    tested.
21. **The Lean spec is written from the RFCs, never from the C**, is
    partial exactly where the RFCs are partial, and carries theorems
    about itself. Cost: everything is implemented twice. Gain: a shared
    misreading of an RFC cannot make both sides agree, and each
    C-versus-spec agreement transfers a proven property, not just a
    matching answer.
22. **The RFC 8448 replay stops at secrets and MACs.** The traces
    protect records with AES-128-GCM, which this stack excludes, and
    sign with an RSA-1024 key, below the verifier's floor — so the
    tests check the floor holds, then verify the trace's
    CertificateVerify one layer down through the raw modexp. Cost: the
    replay never opens a record. Gain: third-party byte-exact checks of
    the transcript and key schedule without weakening the profile.

## Engineering

23. **Four exported symbols.** The library packages as one relocatable
    object; partial linking plus symbol localization does the
    namespacing, so sources keep natural names and applications cannot
    collide with internals.
24. **CI compiles with gcc on purpose** while development machines run
    clang: consumers are firmware trees whose vendor SDKs ship gcc
    cross-compilers, so gcc-only diagnostics belong in CI. Between the
    two, both major compiler families stay covered without a second CI
    leg.
25. **Tool versions pin to the development machine's.** When the local
    toolchain upgrades, the CI pins bump in the same commit. Code never
    adapts to an older checker.
26. **Two proof solvers, each where its memory profile fits.** kissat
    runs the fast tier (measured: verdicts in seconds to minutes where
    the built-in solver ran for hours); CI's slow tier keeps the
    built-in solver, because the external-solver path materializes the
    whole formula and exhausts a 16 GB runner. Verdicts are
    solver-independent. A content-keyed cache re-proves only what
    changed.
27. **Third-party audit is the optimization target.** Every
    review-facing trade — spelled-out names, the complexity-15 gate,
    pure predicates with state changes on their own lines, pinned
    byte constants instead of decode-and-judge — pays a little
    compactness for a lot of reviewability. Cost: more lines and
    more named helpers than the terse form. Gain: a security library
    earns trust through reviewers who did not write it, and every
    clever compression taxes each of them.
