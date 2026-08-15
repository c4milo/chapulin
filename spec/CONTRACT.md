# Spec module contract

The Lean spec is a differential oracle for the C stack. Rules:

1. **Independence**: write every function from the RFC text (cite the
   section in a doc comment). Never look at the C sources; if you need a
   detail, it is in the RFC. Definitional style: arithmetic over `Nat`
   with explicit `mod`, no performance tricks unless a vector demands it.
2. **Signatures are fixed** (namespaces and types exactly as below).
3. Every module ends with a `selftest : Bool` that checks the RFC test
   vectors for that module and is `true` iff all pass.

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
Spec.X25519.scalarMult : (scalar point : ByteArray) → ByteArray        -- RFC 7748 §5, Nat mod 2^255-19
Spec.X25519.base       : (scalar : ByteArray) → ByteArray              -- point = 9
Spec.P256.pubKey?     : (d : Nat) → Option ByteArray                   -- FIPS 186-4 §D.1.2.3, X‖Y 64 bytes
Spec.P256.ecdsaSign   : (d k z : Nat) → Option (Nat × Nat)             -- FIPS 186-4 §6.4, (r, s);
                        -- none for d/k outside [1, n-1] or r/s = 0. The spec
                        -- signs so the oracle can mint valid signatures; the C
                        -- side only ever verifies.
Spec.P256.ecdsaVerify : (pub hash : ByteArray) → (r s : Nat) → Bool    -- SEC 1 v2 §4.1.4
```

Shared helpers live in `Spec/Bytes.lean` (hex, BE/LE Nat coding, xor).
Build with `~/.elan/bin/lake build` inside `spec/`; keep the build
dependency-free (no mathlib).
