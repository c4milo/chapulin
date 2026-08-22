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
   fixed-shape verifier with no ASN.1 in it. DER handling lives in
   `x509_der.c` alone, and only `TRUST=ca` builds package that file;
   `rsa.c` stays ASN.1-free in every build. Variable time is safe
   because every input to verification is public.
10. **No Ed25519.** Cost: none today — no real server-certificate
   population uses it, and PSK already covers endpoints we control.
   Gain: no second hash function (Ed25519 needs SHA-512) and no third
   pin mode.

## Trust model

11. **Raw-pin builds hash certificates into the transcript, never
    parse them.** No X.509, no chains, no names, no expiry, no
    revocation, no trusted clock. Cost: no PKI; the operator
    provisions a key. Gain: the DER-parser vulnerability class does
    not exist in those builds. CA pinning was first declined on three
    objections: it readmits the parser class, needs a trusted clock
    for validity, and a pinned CA without name checking turns every
    certificate that CA ever issued into a skeleton key. The
    `TRUST=ca` build (entry 14) later answered each objection on its
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
12. **Key rotation is a second pin slot.** Cost: 16 bytes of config
    and an out-of-band recovery path for devices that miss both
    pushes. Gain: rotation without a fleet flag day, inside the trust
    model we already have. CA builds layer CA indirection on top of
    the same two slots: the slots hold CA keys, routine server-key
    rotation becomes reissuance and never touches devices, and the
    slot pair rotates the CA key itself. See docs/rotation.md.
13. **Tickets make both auth modes cheap.** Reconnects resume over PSK,
    so pinned mode pays its signature verification once per ticket
    lifetime; the recurring cost of any handshake is the two x25519
    operations.
14. **CA trust is a build, not a negotiation.** `make TRUST=ca` pins a
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
15. **Public CAs stay a non-goal.** Cost: operators run a dedicated CA
    or contract a dedicated intermediate. Gain: the device keeps
    needing no clock and no name matching — a public CA's trust model
    requires both, and Let's Encrypt's signature algorithms sit
    outside the profile besides. A public-CA-fronted server still
    works through raw-pin mode with a stable server key. docs/ca.md
    records the argument and the workable arrangements with external
    CAs.

## Memory and runtime

16. **Zero heap.** One caller-allocated session struct plus one
    caller-provided receive buffer. Cost: the caller sizes memory up
    front. Gain: no allocator, no out-of-memory paths, and bounds the
    proofs can state exactly.
17. **`record_size_limit` is the receive buffer's size.** Cost:
    strictness toward peers that ignore RFC 8449 — an oversized record
    is a protocol error, not a resize. Gain: a peer can never send what
    the buffer cannot hold.
18. **Single task, single connection.** The reference random generator
    is opt-in source with global state, excluded from the packaged
    object. Cost: no multi-session generator isolation. Gain:
    `ch_rand_bytes` stays a clean import that firmware replaces; see
    docs/entropy.md.
19. **Every operational error fails closed**: alert, wipe keys, dead
    session, caller reconnects. Cost: no graceful recovery. Gain: the
    entire resumable-error state space is removed from the code and the
    proofs. Corollary: `CH_EINVAL` (invalid configuration, nothing
    sent) is distinct from `CH_ECAP` (runtime capacity), so
    provisioning corruption never reads as an attack on the wire.

20. **One TX staging array, sized per build.** The ClientHello
    builder and the sealed-record path share the session's TX array;
    their lifetimes never overlap. A build whose hello outgrows one
    sealed record (a PQ key share) raises `CH_TX_STAGE` for that build
    alone. A second array would cost every build the hello's bytes,
    and the handshake proof keeps one array to model. Streaming the
    hello stays rejected: the PSK binder is an HMAC over the
    contiguous truncated hello, so a streaming builder would buffer
    the message anyway.
21. **The receive-buffer floor is a build constant.** `ch_connect`
    checks `buf_len` against `CH_MIN_RXBUF` before anything is sent.
    A feature that needs more room raises the constant, so a
    too-small buffer fails at setup with `CH_EINVAL`, not
    mid-handshake with `CH_ECAP`, where it would read like an attack.
    The floor covers only what the build can know: a raw-pin server's
    chain is the server's choice, so raw-pin deployments size above
    the floor. A CA build does know its worst case — the certificate
    cap bounds the chain — so it derives the floor from the cap
    instead of picking a number: `2*(CH_X509_MAX+5)+16`.

## Assurance

22. **Bounded model checking, layered, with a published ledger.** Leaf
    modules prove concrete; upper layers prove against
    contract-checking stubs of the proven layer below. Where a formula
    will not converge, the harness pins a representative bound and
    documents it. Cost: this is not functional verification. Gain:
    proofs that finish, and claims nobody has to take on faith — the
    README states what is proved, at what bound, and what is only
    tested.
23. **The Lean spec is written from the RFCs, never from the C**, is
    partial exactly where the RFCs are partial, and carries theorems
    about itself. Cost: everything is implemented twice. Gain: a shared
    misreading of an RFC cannot make both sides agree, and each
    C-versus-spec agreement transfers a proven property, not just a
    matching answer.
24. **The RFC 8448 replay stops at secrets and MACs.** The traces
    protect records with AES-128-GCM, which this stack excludes, and
    sign with an RSA-1024 key, below the verifier's floor — so the
    tests check the floor holds, then verify the trace's
    CertificateVerify one layer down through the raw modexp. Cost: the
    replay never opens a record. Gain: third-party byte-exact checks of
    the transcript and key schedule without weakening the profile.

## Engineering

25. **Four exported symbols.** The library packages as one relocatable
    object; partial linking plus symbol localization does the
    namespacing, so sources keep natural names and applications cannot
    collide with internals.
26. **CI compiles with gcc on purpose** while development machines run
    clang: consumers are firmware trees whose vendor SDKs ship gcc
    cross-compilers, so gcc-only diagnostics belong in CI. Between the
    two, both major compiler families stay covered without a second CI
    leg.
27. **Tool versions pin to the development machine's.** When the local
    toolchain upgrades, the CI pins bump in the same commit. Code never
    adapts to an older checker.
28. **Two proof solvers, each where its memory profile fits.** kissat
    runs the fast tier (measured: verdicts in seconds to minutes where
    the built-in solver ran for hours); CI's slow tier keeps the
    built-in solver, because the external-solver path materializes the
    whole formula and exhausts a 16 GB runner. Verdicts are
    solver-independent. A content-keyed cache re-proves only what
    changed.
29. **Third-party audit is the optimization target.** Every
    review-facing trade — spelled-out names, the complexity-15 gate,
    pure predicates with state changes on their own lines, pinned
    byte constants instead of decode-and-judge — pays a little
    compactness for a lot of reviewability. Cost: more lines and
    more named helpers than the terse form. Gain: a security library
    earns trust through reviewers who did not write it, and every
    clever compression taxes each of them.
30. **Assertions live at proof time; runtime keeps contract-point
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

31. **Revocation travels in the server certificate's notBefore, on a
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

32. **The stored epoch moves only after the server authenticates.** A
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
