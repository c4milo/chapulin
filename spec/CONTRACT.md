# Spec module contract

The Lean spec is a differential oracle for the C stack. Rules:

1. **Independence**: write every function from the RFC text (cite the
   section in a doc comment). Never look at the C sources; if you need a
   detail, it is in the RFC. Definitional style: arithmetic over `Nat`
   with explicit `mod`, no performance tricks unless a vector demands it.
2. **Signatures are fixed** (namespaces and types exactly as below).
3. Every module ends with a `selftest : Bool`, `true` iff all checks
   pass. Most check the RFC's published vectors; Record, Drbg, and X509
   have no third-party vectors and their selftests are structural
   (framing, nonce construction, rekeying, mint/parse round trips) —
   the differential and, for Record, the planned RFC 8448 trace replay
   carry the known-answer weight there.

```
Spec.Sha256.sha256    : ByteArray → ByteArray                          -- FIPS 180-4, 32 bytes out
Spec.Hkdf.hmac        : (key msg : ByteArray) → ByteArray              -- RFC 2104 w/ SHA-256
Spec.Hkdf.extract     : (salt ikm : ByteArray) → ByteArray             -- RFC 5869
Spec.Hkdf.expand      : (prk info : ByteArray) → (len : Nat) → ByteArray
Spec.Hkdf.expandLabel : (secret : ByteArray) → (label : String) →
                        (ctx : ByteArray) → (len : Nat) → ByteArray    -- RFC 9846 §7.1
Spec.Hkdf.schedule    : (psk ecdhe helloHash finHash : ByteArray) →
                        (ByteArray × ByteArray × ByteArray × ByteArray)
                        -- (cHs, sHs, cAp, sAp) per RFC 9846 §7.1 with a PSK and
                        -- no early data: early = extract 0 psk;
                        -- hs = extract (deriveSecret early "derived" empty) ecdhe;
                        -- cHs/sHs from helloHash; master from hs;
                        -- cAp/sAp from finHash.
Spec.ChaCha.xor       : (key nonce : ByteArray) → (counter : UInt32) →
                        (data : ByteArray) → ByteArray                 -- RFC 8439 §2.4
Spec.Poly.mac         : (key msg : ByteArray) → ByteArray              -- RFC 8439 §2.5, Nat mod 2^130-5
Spec.Aead.seal        : (key nonce aad pt : ByteArray) → ByteArray     -- RFC 8439 §2.8, ct ++ tag
Spec.Aead.open?       : (key nonce aad ct tag : ByteArray) → Option ByteArray
Spec.Record.seal      : (trafficSecret : ByteArray) → (seq : Nat) →
                        (ctype : UInt8) → (pt : ByteArray) → ByteArray
                        -- RFC 9846 §5.2-5.3: key/iv = expandLabel secret "key"/"iv",
                        -- nonce = iv XOR seq (BE, low 8 bytes), inner = pt ++ [ctype],
                        -- header 17 03 03 len, out = header ++ seal(...)
Spec.Drbg.next        : (key : ByteArray) → (n : Nat) →
                        (ByteArray × ByteArray)                        -- fast key erasure over ChaCha20:
                        -- (next key, n output bytes) from one request
Spec.Record.nextSecret : (secret : ByteArray) → ByteArray             -- RFC 9846 §7.2 "traffic upd"
Spec.X25519.scalarMult : (scalar point : ByteArray) → ByteArray        -- RFC 7748 §5, Nat mod 2^255-19
Spec.X25519.base       : (scalar : ByteArray) → ByteArray              -- point = 9
Spec.P256.pubKey?     : (d : Nat) → Option ByteArray                   -- FIPS 186-4 §D.1.2.3, X‖Y 64 bytes
Spec.P256.ecdsaSign   : (d k z : Nat) → Option (Nat × Nat)             -- FIPS 186-4 §6.4, (r, s);
                        -- none for d/k outside [1, n-1] or r/s = 0. The spec
                        -- signs so the oracle can mint valid signatures; the C
                        -- side only ever verifies.
Spec.P256.ecdsaVerify : (pub hash : ByteArray) → (r s : Nat) → Bool    -- SEC 1 v2 §4.1.4
Spec.Rsa.pssVerify    : (n e : Nat) → (mHash sig : ByteArray) → Bool    -- RFC 8017 §8.1.2,
                        -- rsa_pss_rsae_sha256: SHA-256, MGF1-SHA256, saltLen 32.
Spec.Rsa.pssSign      : (n d : Nat) → (mHash salt : ByteArray) →
                        Option ByteArray                                -- RFC 8017 §8.1.1;
                        -- rsaSign is an alias. The spec signs so the oracle can mint
                        -- signatures the C verifier must accept; the C side only verifies.
                        -- salt is explicit so a fixed value gives a reproducible signature.
Spec.X509.parse       : Alg → (caKey list : ByteArray) →
                        Option (ByteArray × Option Nat)
                        -- profiled chain acceptance over the RFC 8446 §4.4.2
                        -- CertificateEntry list (empty per-entry extensions):
                        -- one entry, the leaf verified directly under caKey;
                        -- or two, the leaf then the intermediate — the
                        -- intermediate verified under caKey and the leaf under
                        -- the intermediate's SPKI. Each certificate: at most
                        -- `certMax alg` bytes — 768 (p256) or 1536 (rsa),
                        -- mirroring x509.h's per-build CH_X509_MAX defaults
                        -- (the C cap is overridable per build; the spec models
                        -- the defaults) — in canonical DER (X.690 §10, with
                        -- §8.19-minimal extnID subidentifiers), the RFC 5280
                        -- v3 profile with its
                        -- arm's extensions — leaf: keyUsage(digitalSignature)
                        -- + extendedKeyUsage(serverAuth); intermediate:
                        -- keyUsage(keyCertSign) + basicConstraints(CA=TRUE,
                        -- pathLen 0), extendedKeyUsage forbidden. `some`
                        -- carries the leaf's SPKI key bytes (RSA modulus
                        -- value, or P-256 X‖Y) paired with its notBefore's
                        -- revocation-epoch number: `some (yy*336 +
                        -- (mm-1)*28 + (dd-1))` (0..16799) when the notBefore
                        -- is epoch-shaped — UTCTime, all twelve leading
                        -- characters ASCII digits, YY 00..49, MM 01..12,
                        -- DD 01..28, HHMMSS zero — and `none` in the pair for
                        -- every other valid Time shape (extraction stays
                        -- permissive; the C driver enforces the epoch rule).
                        -- The intermediate's validity digits go unread. Alg
                        -- is rsa (e = 65537, caKey = modulus bytes) or p256
                        -- (caKey = X‖Y). Line op:
                        -- `x509parse <alg> <cakey> <list>` →
                        -- `ok <key> <epoch>` (`-` when the notBefore is not
                        -- epoch-shaped) / `ERR x509 reject`.
Spec.X509.mint        : CaKey → (serial issuer validity subject leafKey exts :
                        ByteArray) → Option ByteArray
                        -- canonical CA-signed leaf as a one-entry
                        -- CertificateEntry list; the driver supplies every
                        -- field and the CA private key (rsa n/d and a 32-byte
                        -- PSS salt, or p256 d/k), so the C parser must accept
                        -- every minted certificate. `ecdsaSigDer` is the
                        -- spec-side ECDSA-Sig-Value encoder the p256 arm signs
                        -- through. Line ops: `x509mint rsa <n> <d> <salt>
                        -- <serial> <issuer> <validity> <subject> <leafkey>
                        -- <exts>` and `x509mint p256 <d> <k> <serial> ...same
                        -- fields` → `<list>` / `FAIL`.
Spec.X509.mintChain   : (ca int : CaKey) → (serial issuer validity subject
                        leafKey leafExts intExts : ByteArray) →
                        Option ByteArray
                        -- canonical chained pair as a two-entry
                        -- CertificateEntry list: the leaf (leafExts) signed by
                        -- the intermediate key, then the intermediate — its
                        -- SPKI is int's own public key, its extensions
                        -- intExts — signed by the CA. Both certificates share
                        -- the driver-supplied serial, issuer, validity, and
                        -- subject. The C parser must accept every minted
                        -- chain whose extensions are on-profile; off-profile
                        -- intExts mint chains the profile check alone must
                        -- reject. Line ops: `x509mintchain rsa <ca_n> <ca_d>
                        -- <int_n> <int_d> <salt> <serial> <issuer> <validity>
                        -- <subject> <leafkey> <leafexts> <intexts>` and
                        -- `x509mintchain p256 <ca_d> <ca_k> <int_d> <int_k>
                        -- <serial> ...same fields` → `<list>` / `FAIL`.
Spec.Handshake.step   : (mode : Mode) → State → Msg → Option State      -- RFC 9846 §4 order of
                        -- server-to-client messages after the ClientHello; none = fatal
                        -- (unexpected_message). Msg has one constructor per line-protocol
                        -- letter (S H E C R V F N K A L); Mode is psk or pinned. `pinned`
                        -- models the raw-pin build (TRUST=raw); CA builds share the
                        -- message order but no sequence oracle covers them — the e2e
                        -- run does.
Spec.Handshake.accepts : (mode : Mode) → (msgs : List Msg) → Bool       -- fold step from start;
                        -- accept iff every message is legal and the handshake completes
                        -- (connected, optionally then close_notify). Line op:
                        -- `hsseq <mode> <letters>` → 1/0, `-` for the empty sequence.
```

Shared helpers live in `Spec/Bytes.lean` (hex, BE/LE Nat coding, xor).
Build with `~/.elan/bin/lake build` inside `spec/`; keep the build
dependency-free (no mathlib).

## Proven properties

The spec also carries theorems, proved in the same module as the
definition they are about and checked by `lake build`. Where the
differential run shows C-and-spec agreement on the compared domain,
these theorems say what that agreement buys: a property known of the
model, not just a matching answer. All of them quantify over every
input; none assume the RFC vectors.

```
Spec.ChaCha.xor_xor          xor k n c (xor k n c d) = d               -- keystream determinism:
                             -- decryption is encryption (RFC 8439 §2.4)
Spec.Aead.open?_seal         open? of seal's ct (first |pt| bytes) and tag (last 16)
                             -- returns `some pt` for all key/nonce/aad/pt
Spec.Aead.open?_ne_tag       tag ≠ recomputed Poly1305 tag → open? = none
                             -- (needs Spec.Bytes.bytesToHex_inj: open? compares hex)
Spec.Record.aeadOpen_seal    splitting Record.seal's output at 5 and 5+|pt|+1 and
                             -- AEAD-opening with the §7.3 key/iv and §5.3 nonce returns
                             -- `some (pt ++ [ctype])`. The spec has no Record.open —
                             -- deprotection lives in the C read path — so the theorem
                             -- states that path's check at the AEAD layer.
Spec.Hkdf.expand_size        (expand prk info len).size = len          -- RFC 5869 §2.3 "first
Spec.Hkdf.expandLabel_size   (expandLabel s l c len).size = len        -- L octets of T"
Spec.Sha256.sha256_size      (sha256 msg).size = 32
Spec.Drbg.next_key_eq_block  the next key is the counter-0 ChaCha20 block under the
                             -- current key, so key advance does not depend on how many
                             -- output bytes the request asked for (next_key_indep)
Spec.Drbg.next_key_out_disjoint
                             -- the next key comes from keystream bytes 0..31 and the
                             -- output from 32 onward: no output byte is a key byte,
                             -- which is what fast key erasure rests on
Spec.Drbg.next_out_prefix    a shorter request is a prefix of a longer one under the
                             -- same key: every request is cut from one stream
Spec.Record.nonce_inj        distinct sequence numbers below 2^64 give distinct record
                             -- nonces (RFC 9846 §5.3): within one traffic key the
                             -- nonce never repeats
Spec.Bytes.natToBytesBE_inj  big-endian encoding is injective below 2^(8*len)
                             -- (Record.nonce_inj rests on it)
Spec.Handshake, over every accepting trace (both modes unless noted):
  count_finished_of_accepts       exactly one Finished (§4.5.3)
  finished_mem_of_accepts         no accepting trace omits Finished
  psk_no_certificate              PSK: no Certificate anywhere (§2.2)
  pinned_one_certificate          pinned: exactly one Certificate (§4.5.1)
  pinned_one_certificateVerify    pinned: exactly one CertificateVerify (§4.5.2)
  pinned_cert_order               pinned: every prefix with CertificateVerify has
                                  Certificate, every prefix with Finished has
                                  CertificateVerify — with the unit counts this is
                                  C before CV before F (§4.5)
  count_serverHello_of_accepts    exactly one ServerHello, HRR path included (§4.2.3)
  count_encryptedExtensions_of_accepts
                                  exactly one EncryptedExtensions (§4.4.1)
  no_certificateRequest_of_accepts
                                  none: the client offers no certificate and fails
                                  closed rather than answer §4.4.2 with an empty one
  psk_no_certificateVerify        PSK: no CertificateVerify either (§2.2)
  no_post_handshake_before_finished
                                  every prefix holding a NewSessionTicket, KeyUpdate or
                                  application data already holds the Finished — the
                                  handshake gates traffic (§4.7.1, §4.7.3, §5.1)
  closeNotify_at_most_one         at most one close_notify (§6.1)
  closeNotify_last                nothing follows a close_notify (§6.1)
  connected_stable                a run of post-handshake messages from `connected` stays
                                  connected, so acceptance does not depend on how many
                                  arrive (§4.7.1, §4.7.3, §5.1)
  accepts_decompose               every accepting trace is a flight of at most
                                  `flightBound mode` messages (4 under PSK, 6 under
                                  pinned) reaching `connected`, then post-handshake
                                  messages, then an optional single close_notify —
                                  so the flight decides acceptance and everything
                                  after it is covered by `connected_stable`
  accepts_of_flight               the converse: a flight that reaches `connected` accepts
  hrr_at_most_one                 at most one HelloRetryRequest (§4.2.4)
```

Size lemmas (`Poly.mac_size`, `ChaCha.block_size`, `Aead.seal_size`,
`Record.seal_size`, `Hkdf.hmac_size`) and the `Spec/Bytes.lean` proof
toolkit (fold characterizations, `xorBytes` involution,
`bytesToHex_inj`) support the above and are exported for future proofs.

Not proved, deliberately: functional correctness of the C (CBMC plus
the differential carry that), cryptographic security notions, and
x25519/P-256 group laws (mathlib-scale; out of scope for a
dependency-free build).

## Proof status by module

The machine-versus-convention line for the spec, kept honest by `make
lint-spec` (hygiene: no escape hatches in the model; the load-bearing
theorems rest on Lean's three standard axioms only). "Vector-checked"
means the module's selftest plus the differential oracle carry it;
"proven" means theorems beyond that.

| module | theorems | what is proven vs only vector-checked |
| --- | --- | --- |
| Bytes | 24 | proof toolkit: fold characterizations, xor involution and left cancellation, hex injectivity, big-endian round trip and injectivity |
| Drbg | 13 | key advance (the next key is the counter-0 block, independent of the request size), key/output disjointness within one keystream, request-prefix consistency, session key chain |
| Handshake | 17 | state-machine safety invariants: exactly one ServerHello, EncryptedExtensions and Finished; no certificate flight under PSK; pinned flight shape and order; HRR bound; no CertificateRequest; no post-handshake message before Finished; close_notify at most once and last |
| Record | 6 | seal/open round trip, record size, nonce size, nonce injectivity (distinct sequence numbers never share a nonce) |
| ChaCha | 5 | block size, structural lemmas, keystream prefix stability; keystream itself vector-checked |
| Hkdf | 5 | output lengths, schedule wiring and secret sizes; derivations vector-checked |
| Aead | 4 | seal/open round trip, tag rejection, output size, pad16 alignment |
| Rsa | 4 | PSS signature and hash size contracts on both sign and verify; the arithmetic stays vector-checked |
| Sha256 | 4 | structural lemmas, padding block alignment and message prefix; compression function vector-checked |
| Poly | 1 | MAC size; arithmetic vector-checked |
| P256 | 0 | executable oracle only: RFC 6979 vectors and the differential |
| X25519 | 0 | executable oracle only: RFC 7748 vectors and the differential |
| X509Der | 19 | DER canonicality: a length, a TLV, and an INTEGER are accepted only in the one encoding X.690 §10.1 and §8.3.2 admit, so the reader is DER-strict rather than BER-lenient; plus the encode/decode round trips and the §8.19.2 subidentifier rule |
| X509 | 4 | parse soundness: an accepted list reports a key only after a signature over the complete DER of the TBSCertificate that carried it verified under the pinned key, or under an intermediate the pinned key itself signed; the entry is a byte range of the list and no third entry can follow. Acceptance policy beyond that is executable oracle only: mint/parse round trips for the single leaf and the chained pair (self-checked signatures; OpenSSL material is exercised by the C strictness suite) and the differential |

The two remaining zero-theorem modules are the hardest and the most
security-critical; they are executable and vector-checked but carry no
proven properties. The missing theorems, in value order: X25519 ladder
invariants, then the P-256 and RSA arithmetic lemmas — all three need
number theory this dependency-free build does not carry. The
mint-then-parse round trip is deliberately not on the list: it is
completeness, not soundness, a parser that accepted everything would
satisfy it, and the differential already mints and parses on every row
against the real C. The RSA arithmetic is statable today without
an interface change — the factorization enters as a hypothesis, not an
argument — but its proof needs number theory the dependency-free build
does not carry.

None of these theorems say anything about the C. They constrain the
model the differential compares against, so a spec regression fails
`lake build` instead of silently weakening the oracle, and they state
relations across runs — key independence, nonce injectivity, request
prefixes — that a differential row, being one input and one output,
cannot express.

## Writing proofs here

A theorem is read far more often than it is written, and it is read by
someone deciding whether to trust the C. Optimize for that reader.

**The statement is the audit unit.** Its proof is checked by Lean's
kernel; nobody has to follow the tactic script. So a long proof of a
short statement costs an auditor nothing, while a short proof of a
sprawling statement costs everything. Keep a statement to a few lines
and carry no hypothesis it does not need.

**Never restate a definition's internals in a hypothesis — derive
them.** A theorem that assumes how `mint` builds its TBSCertificate,
rather than unfolding the `mint` call it was handed, keeps compiling
after that layout changes: the hypotheses become unsatisfiable and the
theorem turns vacuously true, with nothing failing. Derive what you
need from the call, so a layout change breaks the proof instead of
hollowing the statement.

**Prove the direction that carries weight.** `parse (mint x) = some x`
is completeness, and a parser that accepted everything would satisfy
it. `parse list = some k → a signature over that list verified` is
soundness. Prefer soundness; say which one a theorem gives when it is
not obvious.

Style, in rough order of how much it buys:

- **Name hypotheses for what they say**, never `h1`, `h2`, `hx`. Use
  `h_fits`, `h_minimal`, `h_verified`. The rule the C follows —
  names spell words out — does not stop at the language boundary.
- **Break a goal with `have`**, one named intermediate claim at a time,
  instead of one tactic block that lands the whole thing.
- **Chain equalities with `calc`** rather than a dense `rw` sequence.
  The chain reads like the mathematics; the sequence reads like a
  diff.
- **Go forward, not backward.** `obtain` and `rcases` on what you have
  beat `apply` on what you want, because the reader can follow along
  without running Lean.
- **`refine` with `?_` holes** instead of a bare `apply`, so each
  remaining goal is written down rather than conjured.
- **One deduction per line.** Wrap at 100 columns like everything else.
- **Factor repeated case analysis into a private lemma.** Three
  branches doing the same four steps with different constants is one
  lemma taking those constants.
- **Cite the standard** in the doc comment — RFC section, X.690 clause,
  FIPS paragraph — the same as the definitions do.
- **Delete the debris** once it is green: redundant `have`s, commented
  `rw` chains, single rewrites that collapse into one `rw [a, b, c]`.

Naming follows mathlib's scheme even though mathlib is not a
dependency: `snake_case`, `foo_of_bar` for an implication, suffixes
`_size`, `_inj`, `_canonical`, `_sound`. A Lean reader should
recognize the shape without being told.

**Tactics that do not exist here.** This build carries no mathlib, and
several tactics people reach for first are mathlib-only. Reaching for
them wastes an afternoon:

| want | absent | use instead |
| --- | --- | --- |
| contradiction | `by_contra` | `cases Decidable.em p with` |
| arithmetic goals | `linarith`, `nlinarith`, `positivity` | `omega` |
| casts | `qify` | `norm_cast`, `push_cast` (both present) |
| field arithmetic | `field_simp` | rewrite by hand |
| monotonicity | `gcongr` | the explicit lemma |

`omega`, `decide`, `norm_cast`, and `push_cast` are present and carry
most of the arithmetic here. `DecidableEq` is derived for the model's
inductive types, so `Decidable.em` is constructive on them.
