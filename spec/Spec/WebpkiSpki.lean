import Spec.X509Der
import Spec.Rsa

/-!
SubjectPublicKeyInfo for the `TRUST=webpki` chain verifier, written from
RFC 5280 §4.1.2.7 (the SPKI SEQUENCE), RFC 3279 §2.3.1 (rsaEncryption
and RSAPublicKey) and RFC 5480 §2.1.1 and §2.2 (id-ecPublicKey, the
named curve, the ECPoint).

The model decodes and then judges, where the C byte-compares: it reads
the AlgorithmIdentifier's OBJECT IDENTIFIER and parameters as TLVs, and
the RSA modulus and exponent as DER INTEGERs, then states the profile
over the decoded values. Canonical DER (`Spec.X509Der`) gives each value
one encoding, which is what lets the two agree.

The profile, from docs/webpki.md's "Algorithms":

* rsaEncryption with NULL parameters, exponent 65537, and a modulus
  whose bit length is a multiple of 64 from 2048 to `8 * modulusMax`,
  odd. A bit length that is a multiple of 8 means the top bit of the
  top byte is set, so the returned key is exactly the modulus's
  big-endian bytes and no pad.
* id-ecPublicKey with prime256v1 or secp384r1, the point in the
  uncompressed form `0x04 ‖ X ‖ Y`. The point's place on the curve is
  the verifier's check (`Spec.P256.ecdsaVerify`, `Spec.P384.ecdsaVerify`),
  not this reader's.

`readSpki?` takes the whole SPKI TLV and nothing after it; the C reader
takes a stream, and the differential projects its answer onto the whole
input.
-/

namespace Spec.WebpkiSpki

open Spec.Bytes Spec.X509

/-- The three public-key algorithms the mode admits. -/
inductive KeyAlg
  /-- rsaEncryption (RFC 3279 §2.3.1). -/
  | rsa
  /-- id-ecPublicKey over prime256v1 (RFC 5480 §2.1.1). -/
  | p256
  /-- id-ecPublicKey over secp384r1 (RFC 5480 §2.1.1). -/
  | p384
  deriving DecidableEq, Repr

/-- The line-protocol name of an algorithm. -/
def KeyAlg.name : KeyAlg → String
  | .rsa => "rsa"
  | .p256 => "p256"
  | .p384 => "p384"

/-- The largest modulus in bytes: 512, RSA-4096, the `CH_RSA_MODULUS_MAX`
of a `CH_TRUST_WEBPKI` build (docs/webpki.md, "Bounds"). -/
def modulusMax : Nat := 512

/-- rsaEncryption, 1.2.840.113549.1.1.1 (RFC 3279 §2.3.1), content octets. -/
def oidRsaEncryption : ByteArray :=
  ByteArray.mk #[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01]

/-- id-ecPublicKey, 1.2.840.10045.2.1 (RFC 5480 §2.1.1), content octets. -/
def oidEcPublicKey : ByteArray := ByteArray.mk #[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01]

/-- prime256v1 (secp256r1), 1.2.840.10045.3.1.7 (RFC 5480 §2.1.1.1). -/
def oidPrime256v1 : ByteArray := ByteArray.mk #[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07]

/-- secp384r1, 1.3.132.0.34 (RFC 5480 §2.1.1.1). -/
def oidSecp384r1 : ByteArray := ByteArray.mk #[0x2b, 0x81, 0x04, 0x00, 0x22]

/-- The parameters an AlgorithmIdentifier carries for each algorithm:
NULL for rsaEncryption (RFC 3279 §2.3.1 "the parameters component ...
MUST be present and MUST be of type NULL"), the namedCurve OBJECT
IDENTIFIER for id-ecPublicKey (RFC 5480 §2.1.1). -/
def params : KeyAlg → ByteArray
  | .rsa => tlv 0x05 ByteArray.empty
  | .p256 => tlv 0x06 oidPrime256v1
  | .p384 => tlv 0x06 oidSecp384r1

/-- The algorithm OBJECT IDENTIFIER for each algorithm. -/
def algOid : KeyAlg → ByteArray
  | .rsa => oidRsaEncryption
  | .p256 | .p384 => oidEcPublicKey

/-- The AlgorithmIdentifier SEQUENCE for each algorithm. -/
def algId (alg : KeyAlg) : ByteArray := tlv 0x30 (tlv 0x06 (algOid alg) ++ params alg)

/-- The algorithm a decoded OBJECT IDENTIFIER and parameter bytes name,
or `none`. -/
def keyAlgOf? (oid rest : ByteArray) : Option KeyAlg :=
  [KeyAlg.rsa, .p256, .p384].find? (fun alg => oid == algOid alg && rest == params alg)

/-- RSAPublicKey ::= SEQUENCE { modulus INTEGER, publicExponent INTEGER }
(RFC 3279 §2.3.1), filling the BIT STRING's bytes, judged by the
profile: exponent 65537, a bit length that is a multiple of 64 from 2048
to `8 * modulusMax`, and an odd modulus. Returns the modulus's
big-endian bytes, one byte per eight bits. -/
def rsaKey? (key : ByteArray) : Option ByteArray := do
  let (seq, seqEnd) ← readTlv key 0 0x30
  guard (seqEnd == key.size)
  let (n, o1) ← readDerInt seq 0
  let (e, o2) ← readDerInt seq o1
  guard (o2 == seq.size ∧ e == 65537)
  let bits := Spec.Rsa.bitLen n
  guard (2048 ≤ bits ∧ bits ≤ 8 * modulusMax ∧ bits % 64 = 0 ∧ n % 2 = 1)
  some (natToBytesBE n (bits / 8))

/-- ECPoint in the uncompressed form (RFC 5480 §2.2, SEC 1 v2 §2.3.3):
`0x04` then two coordinates of `coordLen` bytes, filling the BIT
STRING's bytes. Returns X ‖ Y. -/
def ecPoint? (coordLen : Nat) (key : ByteArray) : Option ByteArray := do
  guard (key.size = 1 + 2 * coordLen ∧ key[0]! = 0x04)
  some (key.extract 1 key.size)

/-- The key an algorithm's own reader takes from the BIT STRING's bytes,
paired with the algorithm. -/
def keyOf? (alg : KeyAlg) (key : ByteArray) : Option (KeyAlg × ByteArray) :=
  match alg with
  | .rsa => (rsaKey? key).map fun k => (.rsa, k)
  | .p256 => (ecPoint? 32 key).map fun k => (.p256, k)
  | .p384 => (ecPoint? 48 key).map fun k => (.p384, k)

/-- SubjectPublicKeyInfo ::= SEQUENCE { algorithm AlgorithmIdentifier,
subjectPublicKey BIT STRING } (RFC 5280 §4.1.2.7), exact-fill at every
level, the BIT STRING's unused-bits octet zero. Returns the algorithm
and the key bytes: the RSA modulus, or the EC point's X ‖ Y. -/
def readSpki? (spki : ByteArray) : Option (KeyAlg × ByteArray) := do
  let (body, spkiEnd) ← readTlv spki 0 0x30
  guard (spkiEnd == spki.size)
  let (alg, o1) ← readTlv body 0 0x30
  let (oid, o2) ← readTlv alg 0 0x06
  let keyAlg ← keyAlgOf? oid (alg.extract o2 alg.size)
  let (bitString, o3) ← readTlv body o1 0x03
  guard (o3 == body.size)
  guard (bitString.size ≠ 0 ∧ bitString[0]! = 0)
  keyOf? keyAlg (bitString.extract 1 bitString.size)

/-- The SPKI encoding of a key, the inverse the oracle mints with: the
modulus as a DER INTEGER beside the exponent 65537, or `0x04 ‖ X ‖ Y`. -/
def encodeSpki (alg : KeyAlg) (key : ByteArray) : ByteArray :=
  let subjectKey :=
    match alg with
    | .rsa => tlv 0x30 (derIntNat (bytesToNatBE key) ++ derIntNat 65537)
    | .p256 | .p384 => ByteArray.mk #[0x04] ++ key
  tlv 0x30 (algId alg ++ tlv 0x03 (ByteArray.mk #[0x00] ++ subjectKey))

/-- Round trips over each algorithm and one refusal per profile rule:
the exponent, the parity and each end of the modulus size range, the
point form, and each curve's point under the other's identifier. -/
def selftest : Bool :=
  let modulus := fun (bytes : Nat) => natToBytesBE (2 ^ (8 * bytes - 1) + 0x5a5a01) bytes
  let point := fun (len : Nat) =>
    ByteArray.mk ((List.range len).map (fun i => UInt8.ofNat (i + 1))).toArray
  let rsaWith := fun (n : ByteArray) (e : Nat) =>
    tlv 0x30 (algId .rsa ++
      tlv 0x03 (ByteArray.mk #[0x00] ++ tlv 0x30 (derIntNat (bytesToNatBE n) ++ derIntNat e)))
  let accepts := fun (alg : KeyAlg) (key : ByteArray) =>
    match readSpki? (encodeSpki alg key) with
    | some (alg', key') => alg' == alg && key' == key
    | none => false
  accepts .rsa (modulus 256) && accepts .rsa (modulus 264) && accepts .rsa (modulus 512) &&
    accepts .p256 (point 64) && accepts .p384 (point 96) &&
    readSpki? (rsaWith (modulus 256) 3) == none &&
    readSpki? (encodeSpki .rsa (natToBytesBE (2 ^ 2047 + 2) 256)) == none &&
    readSpki? (encodeSpki .rsa (modulus 248)) == none &&
    readSpki? (encodeSpki .rsa (modulus 255)) == none &&
    readSpki? (encodeSpki .rsa (modulus 513)) == none &&
    readSpki? (encodeSpki .rsa (modulus 520)) == none &&
    readSpki? (tlv 0x30 (algId .p256 ++ tlv 0x03 (ByteArray.mk #[0x00, 0x02] ++ point 32)))
      == none &&
    readSpki? (encodeSpki .p384 (point 64)) == none &&
    readSpki? (encodeSpki .p256 (point 96)) == none

/-!
## Proofs

`rsaKey?` states its profile over the decoded modulus. The theorem below
restates it over the returned bytes, the form the C check reads: a size
from 256 to `modulusMax` in multiples of 8, the top bit of the top byte
set, and the value odd.
-/

private theorem bind_some_elim {α β : Type} {x : Option α} {f : α → Option β} {b : β}
    (h : (x >>= f) = some b) : ∃ a, x = some a ∧ f a = some b := by
  cases hx : x with
  | none => rw [hx] at h; cases h
  | some a => rw [hx] at h; exact ⟨a, rfl, h⟩

private theorem guard_some {p : Prop} [Decidable p] {u : Unit}
    (h : (guard p : Option Unit) = some u) : p := by
  by_cases hp : p
  · exact hp
  · unfold guard at h
    rw [if_neg hp] at h
    cases h

/-- Every key `readSpki?` returns came out of `keyOf?`. -/
private theorem readSpki?_keyOf (spki : ByteArray) (result : KeyAlg × ByteArray)
    (h : readSpki? spki = some result) : ∃ alg bits, keyOf? alg bits = some result := by
  unfold readSpki? at h
  obtain ⟨⟨body, spkiEnd⟩, -, h⟩ := bind_some_elim h
  obtain ⟨-, -, h⟩ := bind_some_elim h
  obtain ⟨⟨algTlv, o1⟩, -, h⟩ := bind_some_elim h
  obtain ⟨⟨oid, o2⟩, -, h⟩ := bind_some_elim h
  obtain ⟨keyAlg, -, h⟩ := bind_some_elim h
  obtain ⟨⟨bitString, o3⟩, -, h⟩ := bind_some_elim h
  obtain ⟨-, -, h⟩ := bind_some_elim h
  obtain ⟨-, -, h⟩ := bind_some_elim h
  exact ⟨keyAlg, _, h⟩

private theorem keyOf?_rsa (alg : KeyAlg) (bits key : ByteArray)
    (h : keyOf? alg bits = some (.rsa, key)) : rsaKey? bits = some key := by
  cases alg <;> simp only [keyOf?, Option.map_eq_some_iff, Prod.mk.injEq] at h
  · obtain ⟨k, hk, -, rfl⟩ := h
    exact hk
  · obtain ⟨k, -, h_alg, -⟩ := h
    cases h_alg
  · obtain ⟨k, -, h_alg, -⟩ := h
    cases h_alg

private theorem keyOf?_p256 (alg : KeyAlg) (bits key : ByteArray)
    (h : keyOf? alg bits = some (.p256, key)) : ecPoint? 32 bits = some key := by
  cases alg <;> simp only [keyOf?, Option.map_eq_some_iff, Prod.mk.injEq] at h
  · obtain ⟨k, -, h_alg, -⟩ := h
    cases h_alg
  · obtain ⟨k, hk, -, rfl⟩ := h
    exact hk
  · obtain ⟨k, -, h_alg, -⟩ := h
    cases h_alg

private theorem keyOf?_p384 (alg : KeyAlg) (bits key : ByteArray)
    (h : keyOf? alg bits = some (.p384, key)) : ecPoint? 48 bits = some key := by
  cases alg <;> simp only [keyOf?, Option.map_eq_some_iff, Prod.mk.injEq] at h
  · obtain ⟨k, -, h_alg, -⟩ := h
    cases h_alg
  · obtain ⟨k, -, h_alg, -⟩ := h
    cases h_alg
  · obtain ⟨k, hk, -, rfl⟩ := h
    exact hk

/-- A bit length that is a multiple of 8 fits the byte count it names:
the value is below `2 ^ bits` and at or above `2 ^ (bits - 1)`. -/
private theorem bitLen_bounds (n : Nat) (h_pos : 0 < Spec.Rsa.bitLen n) :
    n < 2 ^ Spec.Rsa.bitLen n ∧ 2 ^ (Spec.Rsa.bitLen n - 1) ≤ n := by
  unfold Spec.Rsa.bitLen at h_pos ⊢
  by_cases hz : n = 0
  · subst hz; simp at h_pos
  · have hne : (n == 0) = false := by simpa using hz
    rw [hne] at h_pos ⊢
    simp only [Bool.false_eq_true, if_false, Nat.add_sub_cancel]
    exact ⟨Nat.lt_log2_self, Nat.log2_self_le hz⟩

/-- An RSA key `readSpki?` accepts is 256 to `modulusMax` bytes in
multiples of 8, its value has the top bit of its top byte set, so its
bit length is exactly eight times its size, and it is odd. -/
theorem readSpki?_rsa_key (spki key : ByteArray) (h : readSpki? spki = some (.rsa, key)) :
    256 ≤ key.size ∧ key.size ≤ modulusMax ∧ key.size % 8 = 0 ∧
      2 ^ (8 * key.size - 1) ≤ bytesToNatBE key ∧ bytesToNatBE key % 2 = 1 := by
  obtain ⟨alg, bits, h_keyOf⟩ := readSpki?_keyOf spki _ h
  have h_rsa := keyOf?_rsa alg bits key h_keyOf
  unfold rsaKey? at h_rsa
  obtain ⟨⟨seq, seqEnd⟩, -, h_rsa⟩ := bind_some_elim h_rsa
  obtain ⟨-, -, h_rsa⟩ := bind_some_elim h_rsa
  obtain ⟨⟨n, o1⟩, -, h_rsa⟩ := bind_some_elim h_rsa
  obtain ⟨⟨e, o2⟩, -, h_rsa⟩ := bind_some_elim h_rsa
  obtain ⟨-, -, h_rsa⟩ := bind_some_elim h_rsa
  obtain ⟨u, h_profile, h_rsa⟩ := bind_some_elim h_rsa
  obtain ⟨h_min, h_max, h_step, h_odd⟩ := guard_some h_profile
  simp only [Option.some.injEq] at h_rsa
  subst h_rsa
  have h_size : (natToBytesBE n (Spec.Rsa.bitLen n / 8)).size = Spec.Rsa.bitLen n / 8 :=
    natToBytesBE_size _ _
  have h_whole : 8 * (Spec.Rsa.bitLen n / 8) = Spec.Rsa.bitLen n := by omega
  obtain ⟨h_lt, h_ge⟩ := bitLen_bounds n (by omega)
  have h_value : bytesToNatBE (natToBytesBE n (Spec.Rsa.bitLen n / 8)) = n := by
    rw [bytesToNatBE_natToBytesBE, h_whole, Nat.mod_eq_of_lt h_lt]
  rw [h_size, h_value, h_whole]
  simp only [modulusMax] at h_max ⊢
  exact ⟨by omega, by omega, by omega, h_ge, h_odd⟩

/-- A P-256 key `readSpki?` accepts is the 64-byte X ‖ Y. -/
theorem readSpki?_p256_size (spki key : ByteArray) (h : readSpki? spki = some (.p256, key)) :
    key.size = 64 := by
  obtain ⟨alg, bits, h_keyOf⟩ := readSpki?_keyOf spki _ h
  have h_point := keyOf?_p256 alg bits key h_keyOf
  unfold ecPoint? at h_point
  obtain ⟨u, h_form, h_point⟩ := bind_some_elim h_point
  have h_len := (guard_some h_form).1
  simp only [Option.some.injEq] at h_point
  rw [← h_point, ByteArray.size_extract, h_len]
  omega

/-- A P-384 key `readSpki?` accepts is the 96-byte X ‖ Y. -/
theorem readSpki?_p384_size (spki key : ByteArray) (h : readSpki? spki = some (.p384, key)) :
    key.size = 96 := by
  obtain ⟨alg, bits, h_keyOf⟩ := readSpki?_keyOf spki _ h
  have h_point := keyOf?_p384 alg bits key h_keyOf
  unfold ecPoint? at h_point
  obtain ⟨u, h_form, h_point⟩ := bind_some_elim h_point
  have h_len := (guard_some h_form).1
  simp only [Option.some.injEq] at h_point
  rw [← h_point, ByteArray.size_extract, h_len]
  omega

end Spec.WebpkiSpki
