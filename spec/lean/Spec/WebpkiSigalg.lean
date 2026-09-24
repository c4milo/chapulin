import Spec.Sha256
import Spec.Sha512
import Spec.P256
import Spec.P384
import Spec.RsaPkcs1
import Spec.X509
import Spec.WebpkiSpki

/-!
Certificate signature algorithms and signature verification for the
`TRUST=webpki` chain verifier, written from RFC 5280 §4.1.1.2 (the
signatureAlgorithm field), RFC 4055 §5 (sha256WithRSAEncryption and
sha384WithRSAEncryption, NULL parameters), RFC 5758 §3.2
(ecdsa-with-SHA256 and ecdsa-with-SHA384, parameters absent), RFC 8017
§8.2.2 (RSASSA-PKCS1-v1_5) and FIPS 186-4 §6.4 (ECDSA).

`readSigalg?` decodes the AlgorithmIdentifier and judges the decoded
OBJECT IDENTIFIER and parameters, where the C byte-compares whole
encodings; `readSigalg?_iff` proves the two views accept the same four
byte strings.

`verify` hashes the signed bytes — the TBSCertificate TLV, whose
content is `tbs` — with the hash the algorithm names, then checks the
signature with `Spec.RsaPkcs1`, `Spec.P256` or `Spec.P384`. A
certificate signature carries no binding between the digest length and
the curve (RFC 9846 §4.3.3 binds them for CertificateVerify only), so
the message hash an ECDSA check takes is FIPS 186-4 §6.4's leftmost
`min(N, outlen)` bits of the digest, `N` the bit length of the curve's
order, written here as an integer (`leftmostBits`). The C writes the
same rule as bytes: it passes a SHA-384 digest whole to a P-256 verify
that reads its first 32 bytes, and puts 16 zero bytes on the left of a
SHA-256 digest for P-384. `curveHash_p256_sha384` and
`curveHash_p384_sha256` prove the byte forms equal the integer rule.
-/

namespace Spec.WebpkiSigalg

open Spec.Bytes Spec.X509 Spec.WebpkiSpki

/-- The four certificate signature algorithms the mode admits. -/
inductive SigAlg
  /-- sha256WithRSAEncryption, PKCS#1 v1.5 (RFC 4055 §5). -/
  | rsaSha256
  /-- sha384WithRSAEncryption, PKCS#1 v1.5 (RFC 4055 §5). -/
  | rsaSha384
  /-- ecdsa-with-SHA256 (RFC 5758 §3.2). -/
  | ecdsaSha256
  /-- ecdsa-with-SHA384 (RFC 5758 §3.2). -/
  | ecdsaSha384
  deriving DecidableEq, Repr

/-- The line-protocol name of an algorithm. -/
def SigAlg.name : SigAlg → String
  | .rsaSha256 => "rsa_sha256"
  | .rsaSha384 => "rsa_sha384"
  | .ecdsaSha256 => "ecdsa_sha256"
  | .ecdsaSha384 => "ecdsa_sha384"

/-- Every admitted algorithm, in the order `readSigalg?` tries them. -/
def all : List SigAlg := [.rsaSha256, .rsaSha384, .ecdsaSha256, .ecdsaSha384]

/-- The algorithm a line-protocol name names. -/
def SigAlg.ofName? (s : String) : Option SigAlg := all.find? (·.name == s)

/-- Whether the algorithm is an RSASSA-PKCS1-v1_5 one. -/
def SigAlg.isRsa : SigAlg → Bool
  | .rsaSha256 | .rsaSha384 => true
  | .ecdsaSha256 | .ecdsaSha384 => false

/-- The OBJECT IDENTIFIER content octets: 1.2.840.113549.1.1.11 and
.12 (RFC 4055 §5), 1.2.840.10045.4.3.2 and .3 (RFC 5758 §3.2). -/
def oid : SigAlg → ByteArray
  | .rsaSha256 => ByteArray.mk #[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b]
  | .rsaSha384 => ByteArray.mk #[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0c]
  | .ecdsaSha256 => ByteArray.mk #[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02]
  | .ecdsaSha384 => ByteArray.mk #[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03]

/-- The parameters: NULL for the RSA algorithms (RFC 4055 §5: "the
parameters MUST be NULL"), absent for the ECDSA ones (RFC 5758 §3.2:
"the encoding MUST omit the parameters field"). -/
def params (a : SigAlg) : ByteArray :=
  if a.isRsa then tlv 0x05 ByteArray.empty else ByteArray.empty

/-- The AlgorithmIdentifier's one DER encoding. -/
def encode (a : SigAlg) : ByteArray := tlv 0x30 (tlv 0x06 (oid a) ++ params a)

/-- AlgorithmIdentifier ::= SEQUENCE { algorithm OBJECT IDENTIFIER,
parameters ANY OPTIONAL } (RFC 5280 §4.1.1.2), exact-fill: the
algorithm the decoded identifier names when the parameters are the ones
that algorithm requires, or `none`. -/
def readSigalg? (b : ByteArray) : Option SigAlg := do
  let (body, bodyEnd) ← readTlv b 0 0x30
  guard (bodyEnd == b.size)
  let (algorithm, o1) ← readTlv body 0 0x06
  all.find? fun a => algorithm == oid a && body.extract o1 body.size == params a

/-- The certificate cap: no TBS content over `CH_WEBPKI_CERT_MAX`, 3072
bytes, is hashed (docs/webpki.md, "Bounds"). -/
def certMax : Nat := 3072

/-- FIPS 180-4: the hash the algorithm names over `m`. -/
def digestOf (a : SigAlg) (m : ByteArray) : ByteArray :=
  match a with
  | .rsaSha256 | .ecdsaSha256 => Spec.Sha256.sha256 m
  | .rsaSha384 | .ecdsaSha384 => Spec.Sha512.sha384 m

/-- FIPS 186-4 §6.4, step 5 of generation and step 3 of verification:
the leftmost `min(N, outlen)` bits of the hash as an integer, where `N`
is `orderBits` and `outlen` the hash's bit length. -/
def leftmostBits (orderBits : Nat) (hash : ByteArray) : Nat :=
  if 8 * hash.size ≤ orderBits then bytesToNatBE hash
  else bytesToNatBE hash / 2 ^ (8 * hash.size - orderBits)

/-- The fixed-length message hash an ECDSA check takes: `leftmostBits`
as `coordLen` big-endian bytes. -/
def curveHash (orderBits coordLen : Nat) (digest : ByteArray) : ByteArray :=
  natToBytesBE (leftmostBits orderBits digest) coordLen

/-- `m` zero bytes. -/
def zeroPad (m : Nat) : ByteArray := ByteArray.mk (Array.replicate m 0)

/-- An ECDSA-Sig-Value checked by `check` over its two integers; a
signature that does not parse fails. -/
def ecdsaCheck (check : Nat → Nat → Bool) (sig : ByteArray) : Bool :=
  match checkSignature.ecdsaSigParse sig with
  | none => false
  | some (r, s) => check r s

/-- Verifies `sig` over the TBSCertificate whose content is `tbs`, under
the key `readSpki?` returned: RSASSA-PKCS1-v1_5 with e = 65537 for an
RSA algorithm and an RSA key, ECDSA over the curve's message hash for an
ECDSA algorithm and an EC key, and `false` for a family mismatch or a
`tbs` over `certMax`. -/
def verify (a : SigAlg) (keyAlg : KeyAlg) (key tbs sig : ByteArray) : Bool :=
  if certMax < tbs.size then false
  else
    let digest := digestOf a (tlv 0x30 tbs)
    match a.isRsa, keyAlg with
    | true, .rsa => Spec.RsaPkcs1.pkcs1Verify (bytesToNatBE key) 65537 digest sig
    | false, .p256 => ecdsaCheck (Spec.P256.ecdsaVerify key (curveHash 256 32 digest)) sig
    | false, .p384 => ecdsaCheck (Spec.P384.ecdsaVerify key (curveHash 384 48 digest)) sig
    | _, _ => false

/-- A private key the oracle signs with: an RSA modulus and private
exponent, or an ECDSA private key and nonce. -/
inductive Signer
  /-- RSA modulus `n` and private exponent `d`. -/
  | rsa (n d : Nat)
  /-- P-256 private key `d` and nonce `k`. -/
  | p256 (d k : Nat)
  /-- P-384 private key `d` and nonce `k`. -/
  | p384 (d k : Nat)

/-- Signs the TBSCertificate whose content is `tbs`, so the oracle can
mint signatures the C must accept. Returns the signer's SPKI and the
signature, or `none` for a family mismatch or a signer the curve or the
modulus refuses. -/
def sign (a : SigAlg) (signer : Signer) (tbs : ByteArray) : Option (ByteArray × ByteArray) :=
  let digest := digestOf a (tlv 0x30 tbs)
  match a.isRsa, signer with
  | true, .rsa n d => do
    let sig ← Spec.RsaPkcs1.pkcs1Sign n d digest
    some (encodeSpki .rsa (natToBytesBE n ((Spec.Rsa.bitLen n + 7) / 8)), sig)
  | false, .p256 d k => do
    let pub ← Spec.P256.pubKey? d
    let (r, s) ← Spec.P256.ecdsaSign d k (bytesToNatBE (curveHash 256 32 digest))
    some (encodeSpki .p256 pub, ecdsaSigDer r s)
  | false, .p384 d k => do
    let pub ← Spec.P384.pubKey? d
    let (r, s) ← Spec.P384.ecdsaSign d k (bytesToNatBE (curveHash 384 48 digest))
    some (encodeSpki .p384 pub, ecdsaSigDer r s)
  | _, _ => none

set_option compiler.extract_closed false in
/-- The reader over the four encodings and the refusals docs/webpki.md
names — SHA-1 under both families, RSA-PSS, and each family with the
other's parameter form — then sign-then-verify under both curves with
both hashes (the cut and the pad included) and under RSA, and the
refusals of a changed TBS, a family mismatch and the TBS cap. -/
def selftest (_ : Unit) : Bool :=
  let hx := fun s => (hexToBytes? s).getD (ByteArray.mk #[0])
  let reads := all.all fun a => readSigalg? (encode a) == some a
  let refuses := [
    "300d06092a864886f70d0101050500",        -- sha1WithRSAEncryption
    "300906072a8648ce3d0401",                -- ecdsa-with-SHA1
    "300d06092a864886f70d01010a0500",        -- id-RSASSA-PSS with a NULL
    "300c06082a8648ce3d0403020500",          -- ecdsa-with-SHA256 with a NULL
    "300b06092a864886f70d01010b",            -- sha256WithRSAEncryption, NULL absent
    "300d06092a864886f70d01010b050000"].all  -- a trailing byte
    fun s => readSigalg? (hx s) == none
  let tbs := ascii "chapulin webpki selftest tbs"
  let changed := ascii "chapulin webpki selftest tbz"
  let roundTrip := fun (a : SigAlg) (signer : Signer) =>
    match sign a signer tbs with
    | none => false
    | some (spki, sig) =>
      match readSpki? spki with
      | none => false
      | some (keyAlg, key) =>
        verify a keyAlg key tbs sig && !verify a keyAlg key changed sig
  let p256 := Signer.p256 0x1234567 0x7654321
  let p384 := Signer.p384 0x2345678 0x8765432
  -- The 2048-bit key `Spec/RsaPkcs1.lean`'s selftest signs with.
  let rsa := Signer.rsa
    0xa59931eebcc909b93406f4c6999c3b86e086bea972203cb921e806c42c0d73b87b9db6647e15753e232c1f8b8fdfac6210e9866b5eec09ffd62eacfc16b67bcd736d90dae48435130a247e054a4bf821b1c0ccd673ec3240f8686b46e22689c0ab86fd2329a8e10a0fcea94df123459a3ae4d2de6aad52b850c2955e38155be708e9f6dafdc9934e661503bc69463f962aa1f0dabb8427ce065a0f2e6e2bf7650ba0e9c4532d03fb50e5c45447090f00b1e99dd44ba351fb3c78dc2cbf7860e3285789f39a758eb8c314c493d5baf351ba82c3381e4c940574b37f891e63ed5daae377df24ab67d717d5621aa7dc87046359d5b61910ad63d01e56d9bec95a7b
    0x2bd7f91bebd8d05dbc1421679990ff43b11b8bcc621e7de548405dd63f919a335c6b3fb8b0972ed0f25002d419160fd67102db277f5cc032ffbaa0eb277a4e21f1af2f1c7d4731a42659ce11c97f7ea531224a39773cb07b7a296f49b7a39b722b17d4daa3f3860d7b6cec6f69ea3c49ded0e9b1a08dde2a559b871f887ac337653e73889f8e67b4792ef87e7d53270abcb193e68d576ed631b3756b5f9468c27b006fe67380f3078143774a0567cf1160581bb562768f1e1e1c5371d62ee56d6df2e444f8f516acc5b3330a49d66b6081fc1f1d77ffa212223123208e5a773ece826038c46a425d04787317ff2cb895b4b6710234434263f83f9aa2764c3071
  let mismatch :=
    match sign .ecdsaSha256 p256 tbs with
    | none => false
    | some (spki, sig) =>
      match readSpki? spki with
      | none => false
      | some (_, key) =>
        !verify .rsaSha256 .p256 key tbs sig && !verify .ecdsaSha256 .rsa key tbs sig
  let capped :=
    let long := ByteArray.mk (Array.replicate (certMax + 1) 0x41)
    match sign .ecdsaSha256 p256 long with
    | none => false
    | some (spki, sig) =>
      match readSpki? spki with
      | none => false
      | some (keyAlg, key) => !verify .ecdsaSha256 keyAlg key long sig
  reads && refuses &&
    roundTrip .ecdsaSha256 p256 && roundTrip .ecdsaSha384 p256 &&
    roundTrip .ecdsaSha256 p384 && roundTrip .ecdsaSha384 p384 &&
    roundTrip .rsaSha256 rsa && roundTrip .rsaSha384 rsa &&
    mismatch && capped && sign .rsaSha256 p256 tbs == none

/-!
## Proofs

Three kinds of fact. `readSigalg?` accepts exactly the four encodings,
one algorithm each. The C's byte-level cut and pad are the integer rule
FIPS 186-4 §6.4 states. And `verify` refuses a family mismatch and a
TBS over the cap before any arithmetic.
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

private theorem byteArray_eq_of_beq {a b : ByteArray} (h : (a == b) = true) : a = b :=
  ByteArray.ext (eq_of_beq h)

/-- An accepted AlgorithmIdentifier is the encoding of the algorithm it
names: the decoded OBJECT IDENTIFIER and parameters, re-encoded, are the
input bytes. -/
private theorem encode_of_readSigalg? (b : ByteArray) (a : SigAlg)
    (h : readSigalg? b = some a) : b = encode a := by
  unfold readSigalg? at h
  obtain ⟨⟨body, bodyEnd⟩, h_body, h⟩ := bind_some_elim h
  obtain ⟨u, h_fill, h⟩ := bind_some_elim h
  obtain ⟨⟨algorithm, o1⟩, h_oid, h_find⟩ := bind_some_elim h
  have h_end : bodyEnd = b.size := eq_of_beq (guard_some h_fill)
  dsimp only at h_find
  have h_matches := List.find?_some h_find
  simp only [Bool.and_eq_true] at h_matches
  obtain ⟨h_match_oid, h_match_params⟩ := h_matches
  obtain ⟨h_b_end, -, h_b_slice⟩ := readTlv_canonical b 0 0x30 body bodyEnd h_body
  obtain ⟨h_o1, h_o1_le, h_oid_slice⟩ := readTlv_canonical body 0 0x06 algorithm o1 h_oid
  have h_b : b = tlv 0x30 body := by
    rw [slice, Nat.zero_add, show (tlv 0x30 body).size = b.size by omega,
      ByteArray.extract_zero_size] at h_b_slice
    exact h_b_slice
  have h_split : body = tlv 0x06 algorithm ++ body.extract o1 body.size := by
    have h_whole : body.extract 0 body.size = body := ByteArray.extract_zero_size
    rw [ByteArray.extract_eq_extract_append_extract o1 (by omega) (by omega)] at h_whole
    rw [slice, Nat.zero_add, show (tlv 0x06 algorithm).size = o1 by omega] at h_oid_slice
    rw [h_oid_slice] at h_whole
    exact h_whole.symm
  rw [h_b, h_split, byteArray_eq_of_beq h_match_oid, byteArray_eq_of_beq h_match_params]
  rfl

/-- `readSigalg?` accepts exactly the four canonical encodings, and each
names the one algorithm it encodes: so no second byte string reads as
an admitted algorithm, and no encoding reads as two. -/
theorem readSigalg?_iff (b : ByteArray) (a : SigAlg) : readSigalg? b = some a ↔ b = encode a := by
  refine ⟨encode_of_readSigalg? b a, ?_⟩
  rintro rfl
  cases a <;> decide

/-- A big-endian string's value is its high part shifted past its low
part. -/
private theorem foldl_shift (l : List UInt8) (acc : Nat) :
    l.foldl (fun x v => x * 256 + v.toNat) acc
      = acc * 256 ^ l.length + l.foldl (fun x v => x * 256 + v.toNat) 0 := by
  induction l generalizing acc with
  | nil => simp
  | cons x t ih =>
    simp only [List.foldl_cons, List.length_cons]
    rw [ih (acc * 256 + x.toNat), ih (0 * 256 + x.toNat), Nat.pow_succ, Nat.zero_mul,
      Nat.zero_add, Nat.add_mul, Nat.mul_assoc acc 256, Nat.mul_comm 256 (256 ^ t.length),
      Nat.add_assoc]

/-- Big-endian decoding of a concatenation. -/
theorem bytesToNatBE_append (hi lo : ByteArray) :
    bytesToNatBE (hi ++ lo) = bytesToNatBE hi * 256 ^ lo.size + bytesToNatBE lo := by
  simp only [bytesToNatBE, byteArray_foldl_eq]
  have h_list : (hi ++ lo).data.toList = hi.data.toList ++ lo.data.toList := by simp
  have h_len : lo.data.toList.length = lo.size := Array.length_toList
  rw [h_list, List.foldl_append, foldl_shift lo.data.toList, h_len]

/-- Zero bytes on the left leave a big-endian value unchanged: the pad
the C writes for P-384 keeps the integer FIPS 186-4 §6.4 names. -/
theorem bytesToNatBE_zeroPad_append (m : Nat) (d : ByteArray) :
    bytesToNatBE (zeroPad m ++ d) = bytesToNatBE d := by
  have h_zero : bytesToNatBE (zeroPad m) = 0 := by
    simp only [bytesToNatBE, byteArray_foldl_eq, zeroPad, Array.toList_replicate]
    induction m with
    | zero => rfl
    | succ k ih => simpa [List.replicate_succ] using ih
  rw [bytesToNatBE_append, h_zero, Nat.zero_mul, Nat.zero_add]

/-- A digest no longer than the order is used whole: SHA-256 for P-256,
SHA-384 for P-384. -/
theorem curveHash_whole (orderBits : Nat) (d : ByteArray) (h_fits : 8 * d.size = orderBits) :
    curveHash orderBits d.size d = d := by
  rw [curveHash, leftmostBits, if_pos (by omega)]
  exact natToBytesBE_bytesToNatBE d

/-- P-256 with SHA-384: the message hash is the first 32 bytes of the
digest, the bytes the C's `p256_ecdsa_verify` reads when handed the
digest whole. -/
theorem curveHash_p256_sha384 (d : ByteArray) (h_size : d.size = 48) :
    curveHash 256 32 d = d.extract 0 32 := by
  have h_split : d = d.extract 0 32 ++ d.extract 32 48 := by
    have h_whole : d.extract 0 d.size = d := ByteArray.extract_zero_size
    rw [ByteArray.extract_eq_extract_append_extract 32 (by omega) (by omega), h_size] at h_whole
    exact h_whole.symm
  have h_hi_size : (d.extract 0 32).size = 32 := by rw [ByteArray.size_extract]; omega
  have h_lo_size : (d.extract 32 48).size = 16 := by rw [ByteArray.size_extract]; omega
  have h_lo_lt : bytesToNatBE (d.extract 32 48) < 256 ^ 16 := by
    have h_lt := bytesToNatBE_lt (d.extract 32 48)
    rwa [h_lo_size] at h_lt
  have h_join := bytesToNatBE_append (d.extract 0 32) (d.extract 32 48)
  rw [← h_split, h_lo_size] at h_join
  have h_shift : (2 : Nat) ^ (8 * 48 - 256) = 256 ^ 16 := by decide
  have h_value : leftmostBits 256 d = bytesToNatBE (d.extract 0 32) := by
    rw [leftmostBits, if_neg (by omega), h_size, h_shift, h_join, Nat.add_comm,
      Nat.add_mul_div_right _ _ (by decide), Nat.div_eq_of_lt h_lo_lt, Nat.zero_add]
  have h_round := natToBytesBE_bytesToNatBE (d.extract 0 32)
  rw [h_hi_size] at h_round
  rw [curveHash, h_value, h_round]

/-- P-384 with SHA-256: the message hash is 16 zero bytes then the
digest, the bytes the C builds for `p384_ecdsa_verify`. -/
theorem curveHash_p384_sha256 (d : ByteArray) (h_size : d.size = 32) :
    curveHash 384 48 d = zeroPad 16 ++ d := by
  have h_padded_size : (zeroPad 16 ++ d).size = 48 := by
    rw [ByteArray.size_append, zeroPad, zeros_size, h_size]
  calc curveHash 384 48 d
      = natToBytesBE (bytesToNatBE (zeroPad 16 ++ d)) 48 := by
        rw [curveHash, leftmostBits, if_pos (by omega), bytesToNatBE_zeroPad_append]
    _ = natToBytesBE (bytesToNatBE (zeroPad 16 ++ d)) (zeroPad 16 ++ d).size := by
        rw [h_padded_size]
    _ = zeroPad 16 ++ d := natToBytesBE_bytesToNatBE _

/-- A TBS over the certificate cap is refused, whatever the key and
signature. -/
theorem verify_tbs_cap (a : SigAlg) (keyAlg : KeyAlg) (key tbs sig : ByteArray)
    (h_over : certMax < tbs.size) : verify a keyAlg key tbs sig = false := by
  simp [verify, h_over]

/-- An RSA algorithm under an EC key is refused. -/
theorem verify_rsa_sigalg_ec_key (a : SigAlg) (keyAlg : KeyAlg) (key tbs sig : ByteArray)
    (h_rsa : a.isRsa = true) (h_ec : keyAlg ≠ .rsa) : verify a keyAlg key tbs sig = false := by
  cases keyAlg <;> simp_all [verify]

/-- An ECDSA algorithm under an RSA key is refused. -/
theorem verify_ecdsa_sigalg_rsa_key (a : SigAlg) (key tbs sig : ByteArray)
    (h_ecdsa : a.isRsa = false) : verify a .rsa key tbs sig = false := by
  simp [verify, h_ecdsa]

end Spec.WebpkiSigalg
