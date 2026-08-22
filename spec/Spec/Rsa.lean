import Spec.Bytes
import Spec.Sha256

/-!
RSASSA-PSS with SHA-256, written from PKCS #1 v2.2 (RFC 8017) only.

The RSA primitive is modular exponentiation over `Nat` (§5.1-5.2): a
square-and-multiply `powMod` that reduces mod `n` after every
multiplication, so intermediates never exceed `n^2` — the same shape as
the `powMod` in `Spec/P256.lean` and `Spec/X25519.lean`. I2OSP/OS2IP are
the big-endian byte codings in `Spec/Bytes.lean`.

The hash is SHA-256 (`hLen = 32`), the mask generator is MGF1 with
SHA-256 (§B.2.1), and the salt length is fixed at 32. EMSA-PSS-ENCODE
(§9.1.1) and EMSA-PSS-VERIFY (§9.1.2) run over `ByteArray`.

Signing lives here so the oracle can mint signatures the C verifier must
accept; the C side only ever verifies. `pssSign` (aliased `rsaSign`)
takes the private exponent and an explicit salt, so a fixed salt gives a
reproducible signature.
-/

namespace Spec.Rsa

open Spec.Bytes

/-- Output length of SHA-256 in octets (RFC 8017 §B.1). -/
def hLen : Nat := 32

/-- Salt length, fixed at the hash length (RFC 8017 §8.1 recommendation). -/
def sLen : Nat := 32

/-- Square-and-multiply `b^e mod m`, reducing after every multiplication
so intermediates never exceed `m^2`. -/
def powMod (b e m : Nat) : Nat :=
  go (b % m) e (1 % m)
where
  go (b e acc : Nat) : Nat :=
    if _h : e = 0 then acc
    else go (b * b % m) (e / 2) (if e % 2 = 1 then acc * b % m else acc)
  termination_by e
  decreasing_by omega

/-- Bit length of `n` (number of significant bits); `modBits` in §8.1. -/
def bitLen (n : Nat) : Nat := if n == 0 then 0 else Nat.log2 n + 1

/-- `len` zero octets. -/
def zeros (len : Nat) : ByteArray := Id.run do
  let mut out := ByteArray.emptyWithCapacity len
  for _ in [0:len] do
    out := out.push 0
  return out

/-- RSAVP1 (§5.2.2): verification primitive `s^e mod n`. -/
def rsavp1 (n e s : Nat) : Nat := powMod s e n

/-- RSASP1 (§5.2.1): signature primitive `m^d mod n`. -/
def rsasp1 (n d m : Nat) : Nat := powMod m d n

/-- MGF1 (§B.2.1) with SHA-256: concatenate `Hash(mgfSeed ‖ I2OSP(c,4))`
for `c = 0,1,…` until at least `maskLen` octets, then truncate. -/
def mgf1 (mgfSeed : ByteArray) (maskLen : Nat) : ByteArray := Id.run do
  let iters := (maskLen + hLen - 1) / hLen
  let mut t := ByteArray.empty
  for c in [0:iters] do
    t := t ++ Spec.Sha256.sha256 (mgfSeed ++ natToBytesBE c 4)
  return t.extract 0 maskLen

/-- EMSA-PSS-ENCODE (§9.1.1). `mHash` is the already-computed message
digest (`hLen` octets), `salt` the salt (`sLen` octets), and `emBits`
the intended integer bit length (`modBits - 1`). `none` when the modulus
is too small or the digest has the wrong length. -/
def emsaPssEncode (mHash salt : ByteArray) (emBits : Nat) : Option ByteArray :=
  let emLen := (emBits + 7) / 8
  if mHash.size != hLen then none
  -- §9.1.1 step 3: emLen must hold the hash, salt, 0x01 and 0xbc.
  else if emLen < hLen + salt.size + 2 then none
  else
    -- M' = (0x00)^8 ‖ mHash ‖ salt, then H = Hash(M') (steps 5-6).
    let m' := zeros 8 ++ mHash ++ salt
    let h := Spec.Sha256.sha256 m'
    -- DB = PS ‖ 0x01 ‖ salt (steps 7-8).
    let psLen := emLen - salt.size - hLen - 2
    let db := zeros psLen ++ ByteArray.mk #[0x01] ++ salt
    -- maskedDB = DB XOR MGF(H, emLen - hLen - 1) (steps 9-10).
    let maskedDB := xorBytes db (mgf1 h (emLen - hLen - 1))
    -- Clear the leftmost 8*emLen - emBits bits of maskedDB (step 11).
    let clear := UInt8.ofNat (8 * emLen - emBits)
    let maskedDB := maskedDB.set! 0 (maskedDB[0]! &&& (0xff >>> clear))
    -- EM = maskedDB ‖ H ‖ 0xbc (step 12).
    some (maskedDB ++ h ++ ByteArray.mk #[0xbc])

/-- EMSA-PSS-VERIFY (§9.1.2). `mHash` is the message digest, `em` the
encoded message (`emLen` octets), `emBits = modBits - 1`. -/
def emsaPssVerify (mHash em : ByteArray) (emBits : Nat) : Bool :=
  let emLen := (emBits + 7) / 8
  if mHash.size != hLen then false
  else if em.size != emLen then false
  else if emLen < hLen + sLen + 2 then false
  -- Step 4: trailer octet.
  else if em[emLen - 1]! != 0xbc then false
  else
    -- Step 5: split maskedDB ‖ H.
    let maskedDB := em.extract 0 (emLen - hLen - 1)
    let h := em.extract (emLen - hLen - 1) (emLen - 1)
    let clear := UInt8.ofNat (8 * emLen - emBits)
    -- Step 6: the leftmost 8*emLen - emBits bits of maskedDB are zero.
    if maskedDB[0]! &&& (~~~(0xff >>> clear)) != 0 then false
    else
      -- Steps 7-9: recover DB and clear the same leading bits.
      let db := xorBytes maskedDB (mgf1 h (emLen - hLen - 1))
      let db := db.set! 0 (db[0]! &&& (0xff >>> clear))
      let psLen := emLen - hLen - sLen - 2
      -- Step 10: PS is all zero and the separator octet is 0x01.
      if !(List.range psLen).all (fun i => db[i]! == 0) then false
      else if db[psLen]! != 0x01 then false
      else
        -- Steps 11-14: recompute H' over the recovered salt.
        let salt := db.extract (psLen + 1) db.size
        let m' := zeros 8 ++ mHash ++ salt
        bytesToHex (Spec.Sha256.sha256 m') == bytesToHex h

/-- RSASSA-PSS-VERIFY (§8.1.2) with modulus `n`, public exponent `e`,
message digest `mHash`, and signature octets `sig`. Accepts iff the
length, range, and PSS checks all hold. -/
def pssVerify (n e : Nat) (mHash sig : ByteArray) : Bool :=
  let modBits := bitLen n
  let k := (modBits + 7) / 8
  -- §8.1.2 step 1: the signature is exactly k octets.
  if sig.size != k then false
  else
    let s := bytesToNatBE sig
    -- RSAVP1 rejects s outside [0, n-1] (§5.2.2 step 1).
    if s ≥ n then false
    else
      let emBits := modBits - 1
      let emLen := (emBits + 7) / 8
      let m := rsavp1 n e s
      -- I2OSP (§4.1) errors when the integer exceeds the target width;
      -- in verification that error is a reject (§8.1.2 step 3). Reachable
      -- when modBits is not a multiple of 8; truncating instead would
      -- hand the decoder bytes of a number that never came out of RSAVP1.
      if m >= 256 ^ emLen then false
      else emsaPssVerify mHash (natToBytesBE m emLen) emBits

/-- RSASSA-PSS-SIGN (§8.1.1) with modulus `n`, private exponent `d`,
message digest `mHash`, and an explicit `salt` (`sLen` octets). Returns
the `k`-octet signature, or `none` when the modulus is too small. -/
def pssSign (n d : Nat) (mHash salt : ByteArray) : Option ByteArray :=
  let modBits := bitLen n
  let emBits := modBits - 1
  match emsaPssEncode mHash salt emBits with
  | none => none
  | some em =>
    let k := (modBits + 7) / 8
    some (natToBytesBE (rsasp1 n d (bytesToNatBE em)) k)

/-- Alias for `pssSign`: the full RSASSA-PSS signing operation. -/
def rsaSign (n d : Nat) (mHash salt : ByteArray) : Option ByteArray :=
  pssSign n d mHash salt

/-- Test vectors: an OpenSSL-minted 2048-bit RSASSA-PSS/SHA-256
signature (salt length 32) verifies; a sign-then-verify round trip over
the same key with a fixed salt succeeds; and a one-byte flip of the
digest is rejected on both paths. -/
def selftest : Bool :=
  -- A malformed literal falls back to a 1-byte sentinel and breaks the
  -- length-sensitive checks instead of testing the empty string.
  let hx := fun s => (hexToBytes? s).getD (ByteArray.mk #[0])
  let n := 0xa59931eebcc909b93406f4c6999c3b86e086bea972203cb921e806c42c0d73b87b9db6647e15753e232c1f8b8fdfac6210e9866b5eec09ffd62eacfc16b67bcd736d90dae48435130a247e054a4bf821b1c0ccd673ec3240f8686b46e22689c0ab86fd2329a8e10a0fcea94df123459a3ae4d2de6aad52b850c2955e38155be708e9f6dafdc9934e661503bc69463f962aa1f0dabb8427ce065a0f2e6e2bf7650ba0e9c4532d03fb50e5c45447090f00b1e99dd44ba351fb3c78dc2cbf7860e3285789f39a758eb8c314c493d5baf351ba82c3381e4c940574b37f891e63ed5daae377df24ab67d717d5621aa7dc87046359d5b61910ad63d01e56d9bec95a7b
  let e := 65537
  let d := 0x2bd7f91bebd8d05dbc1421679990ff43b11b8bcc621e7de548405dd63f919a335c6b3fb8b0972ed0f25002d419160fd67102db277f5cc032ffbaa0eb277a4e21f1af2f1c7d4731a42659ce11c97f7ea531224a39773cb07b7a296f49b7a39b722b17d4daa3f3860d7b6cec6f69ea3c49ded0e9b1a08dde2a559b871f887ac337653e73889f8e67b4792ef87e7d53270abcb193e68d576ed631b3756b5f9468c27b006fe67380f3078143774a0567cf1160581bb562768f1e1e1c5371d62ee56d6df2e444f8f516acc5b3330a49d66b6081fc1f1d77ffa212223123208e5a773ece826038c46a425d04787317ff2cb895b4b6710234434263f83f9aa2764c3071
  let mHash := hx "1d2f3c6dcd92e89664c5cdca3eed74c5bc6da8d9d38a80bb4d1e4a6adb7f9822"
  let sig := hx ("0090188641c0a6ac5ecbf2156cc6d8fac2bfe21aa8484aa33eff1cefc49470de" ++
                 "cd712d50f3aff6cfadd5e5c0cd5e3dc9ede07e270efd3b8e7594c4140a2238f1" ++
                 "1ba460d817a9b838a8734032470d4426863592e42e3455226890d9c8d1d125f3" ++
                 "611b584125e9586821ddb8487b09245e4d10b42a771d134d0c6c8687848f6f94" ++
                 "403f4c5c502e915c9bf34915f0078c20b1259cbd040800b553855b3b213c6b4bb" ++
                 "726f1c7ffa58cbd6c4db88f22288de7a864c1ab1634166c37f304414e1110855a" ++
                 "87b8ec538d9301bfc85a995ba78edac361a14d08f13615c30e56934460e89894a" ++
                 "3aaba345c8c02dd8263aace4899805107eb217efa98c00023ff2021da8f47")
  -- A fixed 32-byte salt drives a deterministic sign-then-verify round trip.
  let salt := hx "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
  let mHash2 := hx "af96472d3b9a625e8ede207d21da78af279fb5ffc7692c73c20813e2d71a15cd"
  let flip := fun (b : ByteArray) => b.set! 0 (b[0]! ^^^ 1)
  -- OpenSSL-minted vector: accept the real signature, reject a flipped digest.
  pssVerify n e mHash sig &&
  !pssVerify n e (flip mHash) sig &&
  -- Round trip with the spec's own signer under the fixed salt.
  (match pssSign n d mHash2 salt with
   | some s => pssVerify n e mHash2 s && !pssVerify n e (flip mHash2) s
   | none => false)


theorem pssSign_size (n d : Nat) (mHash salt sig : ByteArray)
    (h : pssSign n d mHash salt = some sig) :
    sig.size = (bitLen n + 7) / 8 := by
  simp only [pssSign] at h
  cases he : emsaPssEncode mHash salt (bitLen n - 1) with
  | none => rw [he] at h; simp at h
  | some em => rw [he] at h; simp at h; subst h; exact natToBytesBE_size _ _

theorem pssVerify_size (n e : Nat) (mHash sig : ByteArray)
    (h : sig.size ≠ (bitLen n + 7) / 8) : pssVerify n e mHash sig = false := by
  unfold pssVerify; simp [h]

theorem pssVerify_hash_size (n e : Nat) (mHash sig : ByteArray)
    (h : mHash.size ≠ hLen) : pssVerify n e mHash sig = false := by
  unfold pssVerify emsaPssVerify; simp [h]

theorem pssSign_hash_size (n d : Nat) (mHash salt : ByteArray)
    (h : mHash.size ≠ hLen) : pssSign n d mHash salt = none := by
  simp only [pssSign, emsaPssEncode]; simp [h]

end Spec.Rsa
