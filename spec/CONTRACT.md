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
Spec.Sha3.sha3_256    : ByteArray → ByteArray                          -- FIPS 202, 32 bytes out
Spec.Sha3.sha3_512    : ByteArray → ByteArray                          -- FIPS 202, 64 bytes out
Spec.Sha3.shake128    : ByteArray → (outLen : Nat) → ByteArray         -- FIPS 202 XOF
Spec.Sha3.shake256    : ByteArray → (outLen : Nat) → ByteArray         -- FIPS 202 XOF
Spec.MlKem.keygen     : (d z : ByteArray) → ByteArray × ByteArray      -- FIPS 203 §7.1,
                        -- ML-KEM-768: (ek, dk) = (1184, 2400) bytes from the
                        -- two 32-byte seeds, via §6.1's derandomized
                        -- ML-KEM.KeyGen_internal. Line op:
                        -- `mlkem_keygen <d> <z>` → `<ek> <dk>`.
Spec.MlKem.encaps     : (ek m : ByteArray) → Option (ByteArray × ByteArray)
                        -- FIPS 203 §7.2 with §6.2's derandomized
                        -- ML-KEM.Encaps_internal: some (ct, ss) =
                        -- (1088, 32) bytes; none when ek fails §7.2's
                        -- checks: not 1184 bytes, or a coefficient not
                        -- reduced mod q.
                        -- Line op: `mlkem_encaps <ek> <m>` →
                        -- `<ct> <ss>` / `FAIL`.
Spec.MlKem.decaps     : (dk ct : ByteArray) → ByteArray                -- FIPS 203 §7.3
                        -- via §6.3's ML-KEM.Decaps_internal: the 32-byte
                        -- shared secret; a tampered ciphertext yields the
                        -- implicit-reject secret J(z ‖ ct), never an error.
                        -- Line op: `mlkem_decaps <dk> <ct>` → `<ss>`.
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
                        -- cAp/sAp from finHash. ecdhe is the key-exchange
                        -- IKM at any length — HKDF sets no size — and the
                        -- builds feed two: 32 octets (x25519) or 64 (the
                        -- hybrid's mlkem_ss then x25519_ss, RFC 10024's order).
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
Spec.Record.open?     : (trafficSecret : ByteArray) → (seq : Nat) →
                        (rec : ByteArray) → Option (ByteArray × UInt8)
                        -- RFC 9846 §5.2-5.4 deprotection, the inverse of seal:
                        -- outer type 17, the length field against the record,
                        -- the §5.2 record_overflow and §5.4 inner ceilings, the
                        -- AEAD tag under the §5.3 nonce, then §5.4's scan from
                        -- the end for the content type. The type is handed back
                        -- as found — which types are legal where belongs to the
                        -- reader above this layer, as it does in the C, so the
                        -- two model the same function. Line op:
                        -- `rec_open <secret> <seq> <record>` →
                        -- `ok <ctype> <content>` / `ERR rec_open reject`.
Spec.Record.nextSecret : (secret : ByteArray) → ByteArray             -- RFC 9846 §7.2 "traffic upd"
Spec.X25519.scalarMult : (scalar point : ByteArray) → ByteArray        -- RFC 7748 §5, Nat mod 2^255-19
Spec.X25519.base       : (scalar : ByteArray) → ByteArray              -- point = 9
Spec.P256.pubKey?     : (d : Nat) → Option ByteArray                   -- FIPS 186-4 §D.1.2.3, X‖Y 64 bytes
Spec.P256.ecdsaSign   : (d k z : Nat) → Option (Nat × Nat)             -- FIPS 186-4 §6.4, (r, s);
                        -- none for d/k outside [1, n-1] or r/s = 0. The spec
                        -- signs so the oracle can mint valid signatures; the C
                        -- side only ever verifies.
Spec.P256.ecdsaVerify : (pub hash : ByteArray) → (r s : Nat) → Bool    -- SEC 1 v2 §4.1.4
Spec.HandshakeParser.parseServerHello : (kex : Kex) → (pskOffered : Bool) → (msg : ByteArray) →
                        Except Alert ServerHelloKind                    -- RFC 9846 §4.1.3, §4.1.4.
                        -- Takes the whole Handshake structure of §4 (msg_type,
                        -- uint24 length, body); handshake_parser.c's entry points take the
                        -- body, so the driver frames it. kex is the Makefile's
                        -- KEX variable, as Scheme is its PIN: the build's one
                        -- offered group, which fixes the key_share group code
                        -- point (x25519 0x001D, or RFC 10024's X25519MLKEM768
                        -- 0x11EC) and the server share size (32, or 1120 —
                        -- the ML-KEM-768 ciphertext then the x25519 value).
                        -- pskOffered is handshake_parser.h's
                        -- psk_mode: §4.2 makes a pre_shared_key response
                        -- admissible only if the ClientHello offered one, and
                        -- that is the one thing the message alone cannot settle.
                        -- Everything else the profile fixes is a byte compare
                        -- against a constant: legacy_version 0x0303, the empty
                        -- legacy_session_id_echo handshake_message.c offers, the one cipher
                        -- suite, the build's group. Line op:
                        -- `hs_server_hello <psk|nopsk> <x25519|pq> <msg>` →
                        -- `sh <key_exchange> <selected_identity|->`
                        -- / `hrr <cookie>` / `ERR hs_server_hello reject`.
Spec.HandshakeParser.parseEncryptedExtensions : (msg : ByteArray) →
                        Except Alert EncryptedExtensions               -- RFC 9846 §4.3.1.
                        -- Line op: `hs_encrypted_extensions <msg>` →
                        -- `ok <record_size_limit|->` (RFC 8449 §4, decimal, the
                        -- extension's own value; handshake_parser.c stores it less the
                        -- inner content-type octet) / `ERR ... reject`.
Spec.HandshakeParser.parseCertificate : (msg : ByteArray) → Except Alert Certificate
                        -- RFC 9846 §4.4.2: the empty certificate_request_context
                        -- then the exact-fill CertificateEntry list, whose
                        -- per-entry extensions must be ones the client offered —
                        -- none. Line op: `hs_certificate <msg>` →
                        -- `ok <entry_count> <leaf_cert_data>` / `ERR ... reject`.
Spec.HandshakeParser.parseCertificateVerify : (scheme : Scheme) → (msg : ByteArray) →
                        Except Alert CertificateVerify                 -- RFC 9846 §4.4.3:
                        -- the one offered SignatureScheme, then an exact-fill
                        -- `opaque signature<0..2^16-1>`. The signature's length
                        -- is the verifier's business, not the parser's. Line op:
                        -- `hs_certificate_verify <rsa|p256> <msg>` →
                        -- `ok <algorithm> <signature>` / `ERR ... reject`.
Spec.HandshakeParser.verifyContent : (transcriptHash : ByteArray) → ByteArray  -- RFC 9846 §4.4.3's
                        -- 130 signed octets: 64 spaces, the context string, a
                        -- zero, the hash. Line op: `hs_verify_content <hash>`.
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
                        -- `handshake_sequence <mode> <letters>` → 1/0, `-` for the empty sequence.
Spec.Epoch.check      : (bound stored : Nat) → (cert : Option Nat) → Bool
                        -- docs/ca.md, INV-21: handshake.c's epoch_check over one
                        -- leaf. cert is the certificate reader's epoch number —
                        -- `some e` when the notBefore is epoch-shaped
                        -- (leaf.epoch_ok set, value leaf.epoch), `none` for any
                        -- other valid date. Accepts iff
                        -- `stored ≤ e ≤ stored + bound`; the C's two refusals
                        -- differ only by alert. No line op: see "Epoch is not an
                        -- oracle" below.
Spec.Epoch.commit     : (stored : Nat) → (cert : Option Nat) → Nat
                        -- hsa_epoch_commit: raise the stored epoch to e when e is
                        -- strictly higher, else leave it. Takes no bound, because
                        -- the C function reads none.
Spec.Epoch.step       : (bound stored : Nat) → (cert : Option Nat) → Nat
                        -- one CA-mode handshake: commit only where check
                        -- accepted. That is the C's call order — epoch_check in
                        -- hsa_server_auth, hsa_epoch_commit in run after
                        -- expect_finished — and it is what bounds the result.
Spec.Epoch.storedAfter : (bound stored : Nat) → (certs : List (Option Nat)) → Nat
                        -- ch_tls.epoch after one handshake per certificate, in
                        -- order: `certs.foldl (step bound) stored`.
Spec.Epoch.acceptedCount : (bound : Nat) → Nat → List (Option Nat) → Nat
                        -- how many of those handshakes the check accepted, each
                        -- judged against the stored epoch as it stood then.
```

Shared helpers live in `Spec/Bytes.lean` (hex, BE/LE Nat coding, xor).
Build with `~/.elan/bin/lake build` inside `spec/`; keep the build
dependency-free (no mathlib).

## Epoch is not an oracle

`Spec/Epoch.lean` breaks two rules this file states elsewhere, and
both breaks are deliberate.

It has no line op and no `selftest`. Both functions live in
`handshake_auth.c`: `epoch_check` is `static` there, so nothing
outside that translation unit can call it at all, and while
`hsa_epoch_commit` has external linkage — the state machine in
`handshake.c` calls it after the server Finished — driving it from
`test/diff_test.c` would mean building a whole `handshake_state` with
the epoch callbacks configured, not passing two numbers. So the
differential still has nothing to compare against, and a selftest
would have nothing to check. Rule 3 asks every module for a selftest
because every other module is an oracle; here an unreached one would
be dead code.

That makes the module weaker than the rest of `spec/`, and the weaker
claim is the honest one. On docs/invariants.md's check scale a Lean
theorem "reaches the C only through the differential's agreement" —
and this module has no differential. Its theorems constrain the model
and nothing else. They say what the ordering and bound rule
guarantees for a device that applies it as the model does; no run
compares that model against the C. A C change that breaks the rule —
inverting the comparison in `hsa_epoch_commit`, dropping the bound term
from `epoch_check`, or moving the commit to where a rejected
certificate reaches it — leaves `lake build` green. INV-21 lists what
does guard those on the C side: the `CH_ASSERT` on
`server_finished_ok`, `test_epoch_cfg`, and the e2e `ca-epoch-*` legs.
Reading these definitions against those two C functions is a manual
step, and the module is written for it: both functions are short, and
`check` and `commit` sit next to the C names they model.

The model also drops three things the C does, each named in the
module's own doc comment: the `cfg.epoch_load == NULL` gate that turns
the feature off, the `epoch_status`/`epoch_seen` reporting, and the
rule that a commit may run only after the server Finished — that last
one is message order, which `CH_ASSERT(h->server_finished_ok)` enforces
in the C and `Spec.Handshake` models as a trace property.

## Where the C and the model split a check

Both sides must refuse the same messages, but they need not refuse them
in the same function. `handshake_parser.c` is a framing parser: it hands what it
read to `handshake.c`, which decides whether the handshake can go on.
The model has no layer above it, so it makes those decisions where it
reads the field. Five checks fall on opposite sides of that line, and
`test/diff_handshake_parser.h` projects the C answer down to the model's
boundary rather than weakening the model to match the split:

| check | C decides | model decides |
| --- | --- | --- |
| ServerHello with no key_share | `hello_exchange`, on `have_share` | `parseServerHello` |
| selected_identity outside the one offered index | `hello_exchange`, on `psk_ok` | `parseServerHello` |
| HelloRetryRequest with no cookie | `handshake.c`, on an absent cookie | `parseServerHello` |
| CertificateEntry carrying an unoffered extension | the trust mode's certificate parser | `parseCertificate` |
| ServerHello that ignores the offered PSK | `hello_exchange`, on `psk_ok` | nothing — both parsers accept it; whether resumption was required sits above them |

Each ends the handshake on both sides, except the last: the unoffered
CertificateEntry extension is refused only in the `TRUST=ca` build,
where `x509_verify_leaf` requires empty per-entry extensions. A pinned
build never reads the entries — it hashes the certificate into the
transcript and authenticates by the signature — so §4.4.2's MUST-abort
for that extension is unenforced there. The unread extension changes
nothing the signature does not already cover, so the gap is by design;
the model refuses the extension in both builds, and the driver projects
the CA-build verdict.

One more went the other way — the model bounded the CertificateVerify
signature by the pinned key's size, which §4.4.3 does not do and
`handshake_parser.c` leaves to the verifier — and the model gave the check up
rather than the driver paper over it.

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
                             -- `some (pt ++ [ctype])`. `open?_seal` states the same
                             -- round trip at the record layer, where deprotection
                             -- now lives; this one remains as its AEAD-layer step.
Spec.Hkdf.expand_size        (expand prk info len).size = len          -- RFC 5869 §2.3 "first
Spec.Hkdf.expandLabel_size   (expandLabel s l c len).size = len        -- L octets of T"
Spec.Sha256.sha256_size      (sha256 msg).size = 32
Spec.Sha3.sha3_256_size      (sha3_256 msg).size = 32                  -- FIPS 202 §6.1-6.2
Spec.Sha3.sha3_512_size      (sha3_512 msg).size = 64
Spec.Sha3.shake128_size      (shake128 msg outLen).size = outLen
Spec.Sha3.shake256_size      (shake256 msg outLen).size = outLen
Spec.Sha3.absorb_size        (absorb rate padded).size = 200           -- the state string
Spec.Sha3.squeeze_size       (squeeze rate state outLen).size = outLen -- at a real rate
Spec.Sha3.pad_blocks         (pad rate domain msg).size % rate = 0     -- §B.2 pad10*1
Spec.Sha3.pad_prefix         padding keeps the message as a prefix
Spec.MlKem.keygen_ek_size    (keygen d z).1.size = 1184                -- FIPS 203 §6.1 key sizes
Spec.MlKem.keygen_dk_size    z.size = 32 → (keygen d z).2.size = 2400
Spec.MlKem.encaps_ct_size    encaps ek m = some (ct, ss) → ct.size = 1088   -- §6.2
Spec.MlKem.decaps_size       (decaps dk ct).size = 32                  -- §6.3, both the normal
                             -- and the implicit-reject branch
Spec.MlKem.byteEncode_size   (byteEncode F d).size = 32 * d            -- §4.2.1 ByteEncode_d,
Spec.MlKem.encode3_size      (encode3 v d).size = 96 * d               -- and over a rank-3 vector
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

Spec.Epoch, over the monotonic revocation epoch (docs/ca.md, INV-21). `bound` is
quantified, so every statement covers every build's CH_EPOCH_BOUND:
  commit_ge                     a commit never lowers the stored epoch
  commit_le_of_check            a commit the check admitted raises it by at most
                                bound; with commit_ge, an admitted commit that
                                moves at all lands in (stored, stored + bound]
  commit_takes_any_epoch        the bound belongs to the call order, not to
                                hsa_epoch_commit: for every bound and stored epoch a
                                certificate bound+1 steps ahead is one the check
                                refuses and the commit would take
  step_idem                     replaying an accepted certificate changes nothing
  storedAfter_ge                over a list of certificates the stored epoch
                                never decreases
  storedAfter_le                and rises by at most bound per accepted
                                certificate: n completed handshakes end no higher
                                than stored + bound * n — the jump bound rule,
                                which no single-step statement expresses
  storedAfter_eq_of_none_accepted
                                a run that accepted nothing ends where it started
  storedAfter_le_maxEpoch       a device at or below CH_EPOCH_MAX that sees only
                                in-range numbers keeps one, so the stored side of
                                `stored + bound` also stays inside uint32

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
| HandshakeParser | 7 | message-grammar soundness, quantified over both `Kex` builds: an accepted ServerHello echoes the empty legacy_session_id the profile offers and a key_exchange of exactly `kex.serverShareSize` octets (32 x25519, 1120 hybrid), and any selected_identity it reports is the single index one offered identity puts in range; a result is a HelloRetryRequest exactly when the Random is §4.1.4's fixed value; an accepted CertificateVerify reports the build's own pinned SignatureScheme and no other |
| Handshake | 17 | state-machine safety invariants: exactly one ServerHello, EncryptedExtensions and Finished; no certificate flight under PSK; pinned flight shape and order; HRR bound; no CertificateRequest; no post-handshake message before Finished; close_notify at most once and last |
| Record | 8 | seal/open round trip at both the AEAD and record layers, record size, nonce size, nonce injectivity (distinct sequence numbers never share a nonce), and that an accepted record never carries content type invalid(0) |
| ChaCha | 5 | block size, structural lemmas, keystream prefix stability; keystream itself vector-checked |
| Hkdf | 5 | output lengths, schedule wiring and secret sizes; derivations vector-checked |
| Aead | 4 | seal/open round trip, tag rejection, output size, pad16 alignment |
| Rsa | 4 | PSS signature and hash size contracts on both sign and verify; the arithmetic stays vector-checked |
| Sha256 | 4 | structural lemmas, padding block alignment and message prefix; compression function vector-checked |
| Sha3 | 8 | output lengths for the two hashes and two XOFs, sponge state size, padding block alignment and message prefix; the permutation itself vector-checked |
| MlKem | 6 | FIPS 203 §6.1-6.3 output-length contracts (ek 1184, dk 2400, ct 1088, shared secret 32 on both decapsulation branches) and the ByteEncode length law they rest on; the NTT, sampling, and compression arithmetic stay vector-checked |
| Poly | 1 | MAC size; arithmetic vector-checked |
| P256 | 0 | executable oracle only: RFC 6979 vectors and the differential |
| X25519 | 2 | RFC 7748 §5 clamping: every decoded scalar is a multiple of the cofactor 8, and has bit 254 set with bit 255 clear. The first keeps `k * P` in the prime-order subgroup, the second fixes the ladder's iteration count. The ladder arithmetic itself stays vector-checked |
| X509Der | 19 | DER canonicality: a length, a TLV, and an INTEGER are accepted only in the one encoding X.690 §10.1 and §8.3.2 admit, so the reader is DER-strict rather than BER-lenient; plus the encode/decode round trips and the §8.19.2 subidentifier rule |
| X509 | 4 | parse soundness: an accepted list reports a key only after a signature over the complete DER of the TBSCertificate that carried it verified under the pinned key, or under an intermediate the pinned key itself signed; the entry is a byte range of the list and no third entry can follow. Acceptance policy beyond that is executable oracle only: mint/parse round trips for the single leaf and the chained pair (self-checked signatures; OpenSSL material is exercised by the C strictness suite) and the differential |
| Epoch | 8 | the ordering and bound rule over the epoch value: commit monotonicity, the per-certificate bound, the run-level `stored + bound * accepted` ceiling, replay idempotence, and range preservation. Model only — no differential covers this module (below) |

The one remaining zero-theorem module, P-256, is among the hardest and the most
security-critical; it is executable and vector-checked but carries no
proven properties. The missing theorems, in value order: X25519 ladder
invariants, then the P-256 and RSA arithmetic lemmas — all three need
number theory this dependency-free build does not carry. What is
provable without it has now been taken: the clamping guarantees are
properties of the scalar, not of the group, and no differential row
could have caught a clamping bug, since the C and the spec would agree
while both were wrong. The
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
  FIPS paragraph — the same as the definitions do. `missingDocs` is on,
  so a public declaration without one fails `make check`; the linter
  cannot read a trailing `--` comment, only a `/-- ... -/` block.
- **Delete the debris** once it is green: redundant `have`s, commented
  `rw` chains, single rewrites that collapse into one `rw [a, b, c]`.
  Four of Lean's own linters check this — `unreachableTactic`,
  `unnecessarySimpa`, `unusedRCasesPattern`, `tactic.unusedName`, on in
  `lakefile.toml` — and `make lint-spec` turns their warnings into
  errors, so `make check` fails on debris.

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

Everything in this section is machine-checked except one rule: naming
hypotheses. No linter reads intent, so that one rests on review.

`omega`, `decide`, `norm_cast`, and `push_cast` are present and carry
most of the arithmetic here. `DecidableEq` is derived for the model's
inductive types, so `Decidable.em` is constructive on them.
