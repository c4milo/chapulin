# Spec module contract

The Lean spec is a differential oracle for the C stack. Rules:

1. **Independence**: write every function from the RFC text (cite the
   section in a doc comment). Never look at the C sources; if you need a
   detail, it is in the RFC. Definitional style: arithmetic over `Nat`
   with explicit `mod`, no performance tricks unless a vector demands it.
2. **Signatures are fixed** (namespaces and types exactly as below).
3. Every module ends with a `selftest : Bool`, `true` iff all checks
   pass. Most check the RFC's published vectors; Record and Drbg have no
   third-party vectors and their selftests are structural (framing,
   nonce construction, rekeying) — the differential and, for Record, the
   planned RFC 8448 trace replay carry the known-answer weight there.

```
Spec.Sha256.sha256    : ByteArray → ByteArray                          -- FIPS 180-4, 32 bytes out
Spec.Hkdf.hmac        : (key msg : ByteArray) → ByteArray              -- RFC 2104 w/ SHA-256
Spec.Hkdf.extract     : (salt ikm : ByteArray) → ByteArray             -- RFC 5869
Spec.Hkdf.expand      : (prk info : ByteArray) → (len : Nat) → ByteArray
Spec.Hkdf.expandLabel : (secret : ByteArray) → (label : String) →
                        (ctx : ByteArray) → (len : Nat) → ByteArray    -- RFC 8446 §7.1
Spec.Hkdf.schedule    : (psk ecdhe helloHash finHash : ByteArray) →
                        (ByteArray × ByteArray × ByteArray × ByteArray)
                        -- (cHs, sHs, cAp, sAp) per RFC 8446 §7.1 with a PSK and
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
                        -- RFC 8446 §5.2-5.3: key/iv = expandLabel secret "key"/"iv",
                        -- nonce = iv XOR seq (BE, low 8 bytes), inner = pt ++ [ctype],
                        -- header 17 03 03 len, out = header ++ seal(...)
Spec.Drbg.next        : (key : ByteArray) → (n : Nat) →
                        (ByteArray × ByteArray)                        -- fast key erasure over ChaCha20:
                        -- (next key, n output bytes) from one request
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
Spec.Handshake.step   : (mode : Mode) → State → Msg → Option State      -- RFC 8446 §4 order of
                        -- server-to-client messages after the ClientHello; none = fatal
                        -- (unexpected_message). Msg has one constructor per line-protocol
                        -- letter (S H E C R V F N K A L); Mode is psk or pinned.
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
Spec.Handshake, over every accepting trace (both modes unless noted):
  count_finished_of_accepts       exactly one Finished (§4.4.4)
  finished_mem_of_accepts         no accepting trace omits Finished
  psk_no_certificate              PSK: no Certificate anywhere (§2.2)
  pinned_one_certificate          pinned: exactly one Certificate (§4.4.2)
  pinned_one_certificateVerify    pinned: exactly one CertificateVerify (§4.4.3)
  pinned_cert_order               pinned: every prefix with CertificateVerify has
                                  Certificate, every prefix with Finished has
                                  CertificateVerify — with the unit counts this is
                                  C before CV before F (§4.4)
  hrr_at_most_one                 at most one HelloRetryRequest (§4.1.4)
```

Size lemmas (`Poly.mac_size`, `ChaCha.block_size`, `Aead.seal_size`,
`Record.seal_size`, `Hkdf.hmac_size`) and the `Spec/Bytes.lean` proof
toolkit (fold characterizations, `xorBytes` involution,
`bytesToHex_inj`) support the above and are exported for future proofs.

Not proved, deliberately: functional correctness of the C (CBMC plus
the differential carry that), cryptographic security notions, and
x25519/P-256 group laws (mathlib-scale; out of scope for a
dependency-free build).
