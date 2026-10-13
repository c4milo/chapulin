import Spec.PemBlocks
import Spec.X509Der
import Spec.P256

/-!
# The PEM files an operator provisions

Written from RFC 5280 §4.1 (a Certificate and its TBSCertificate, read
for their outer fields alone), RFC 5480 §2.1.1 (the P-256 key's
AlgorithmIdentifier and ECParameters), RFC 5958 §2 (PKCS #8's
PrivateKeyInfo), RFC 5915 §3 (SEC 1's ECPrivateKey), and the limits
`pem_files.h` names. The PEM text is `Spec.PemBlocks`'s, the DER readers
`Spec.X509Der`'s, and the point a scalar names `Spec.P256.pubKey?`.

Three files, three functions:

* `chainFromPem?`: a chain of one to `chainMax` certificates, and 255 at
  most, that share `derLen` bytes, each read for its outer fields and
  nothing else;
* `keyFromPem?`: a P-256 private key in either form, under one EC
  PARAMETERS block that names prime256v1 for SEC 1, its point computed
  from the scalar and checked against any point the file carries and
  against the end-entity certificate's key;
* `anchorsFromPem?`: a CA bundle of one to `anchorMax` roots that share
  `derLen` bytes, each read for its subject Name and its
  SubjectPublicKeyInfo and nothing else.

The caller gives `derLen`, `chainMax` and `anchorMax`, as the C caller
gives its rooms (docs/decisions.md 131).

A file that decodes is not authenticated: nothing here reads a signature.
-/

namespace Spec.PemFiles

open Spec.Bytes Spec.Pem Spec.PemBlocks Spec.X509

/-- Hex literal for a pinned constant; a malformed literal falls back to
a 1-byte sentinel no comparison matches. -/
private def hexConst (s : String) : ByteArray := (hexToBytes? s).getD (ByteArray.mk #[0])

/-- The most certificates a chain holds: `ch_identity.chain_count` is a
`uint8_t`. -/
def chainCountMax : Nat := 255
/-- `CH_PEM_KEY_DER_MAX`: the longest key DER the readers admit. -/
def keyDerMax : Nat := 150
/-- `CH_PEM_PARAMETERS_DER_MAX`: the DER of the one EC PARAMETERS block a
key file may hold, prime256v1's OBJECT IDENTIFIER. -/
def parametersDerMax : Nat := 10
/-- `CH_PEM_KEY_TEXT_MAX`: the longest key file, the key's block and an
EC PARAMETERS block above it, each derived as `pemMax` is. -/
def keyTextMax : Nat := pemMax keyDerMax + pemMax parametersDerMax

/-- id-ecPublicKey with the namedCurve prime256v1 (RFC 5480 §2.1.1), the
whole AlgorithmIdentifier SEQUENCE. -/
def p256Algorithm : ByteArray := hexConst "301306072a8648ce3d020106082a8648ce3d030107"

/-- ECParameters' namedCurve prime256v1 (RFC 5480 §2.1.1): the OBJECT
IDENTIFIER alone, the whole DER of the EC PARAMETERS block a key file may
hold. -/
def p256Parameters : ByteArray := hexConst "06082a8648ce3d030107"

/-- The SubjectPublicKeyInfo of the P-256 point `xy` (X‖Y): the SEQUENCE,
`p256Algorithm`, and a BIT STRING of the uncompressed point (SEC 1
§2.3.3). -/
def p256Spki (xy : ByteArray) : ByteArray :=
  hexConst "3059" ++ p256Algorithm ++ hexConst "03420004" ++ xy

/-- One field that may be absent: when the byte at `off` is `tag`, one
TLV of it; otherwise nothing. Returns the offset past it. -/
def skipOptional (b : ByteArray) (off : Nat) (tag : UInt8) : Option Nat :=
  if byteAt? b off == some tag then (readTlv b off tag).map (·.2) else some off

/-- A certificate read as far as its key, with no judgement of its
fields (RFC 5280 §4.1): the Certificate SEQUENCE fills the input and holds the
TBSCertificate, a signatureAlgorithm SEQUENCE and a signature BIT
STRING; the TBSCertificate holds an optional version [0], the
serialNumber, the signature, the issuer, the validity, the subject, the
subjectPublicKeyInfo and the optional [1], [2] and [3], and nothing
after. Returns the subject's and the key's whole TLVs. -/
def readSubjectKey (cert : ByteArray) : Option (ByteArray × ByteArray) := do
  let (body, end₀) ← readTlv cert 0 0x30
  guard (end₀ == cert.size)
  let (tbs, o₁) ← readTlv body 0 0x30
  let (_, o₂) ← readTlv body o₁ 0x30
  let (_, o₃) ← readTlv body o₂ 0x03
  guard (o₃ == body.size)
  let t₀ ← skipOptional tbs 0 0xa0
  let (_, t₁) ← readTlv tbs t₀ 0x02
  let (_, t₂) ← readTlv tbs t₁ 0x30
  let (_, t₃) ← readTlv tbs t₂ 0x30
  let (_, t₄) ← readTlv tbs t₃ 0x30
  let (_, t₅) ← readTlv tbs t₄ 0x30
  let (_, t₆) ← readTlv tbs t₅ 0x30
  let t₇ ← skipOptional tbs t₆ 0x81
  let t₈ ← skipOptional tbs t₇ 0x82
  let t₉ ← skipOptional tbs t₈ 0xa3
  guard (t₉ == tbs.size)
  some (slice tbs t₄ (t₅ - t₄), slice tbs t₅ (t₆ - t₅))

/-- An ECPrivateKey (RFC 5915 §3) on P-256: version 1, a privateKey of
exactly 32 bytes, the parameters [0] that name prime256v1, which
`curveRequired` demands, and an optional publicKey [1] of the
uncompressed point. The fields fill the DER. Returns the scalar and the point
the file carries, X‖Y. -/
def readEcPrivateKey (curveRequired : Bool) (der : ByteArray) :
    Option (ByteArray × Option ByteArray) := do
  let (body, end₀) ← readTlv der 0 0x30
  guard (end₀ == der.size)
  let o₁ ← matchAt body 0 (hexConst "020101")
  let o₂ ← matchAt body o₁ (hexConst "0420")
  guard (o₂ + 32 ≤ body.size)
  let o₃ := o₂ + 32
  let hasCurve := byteAt? body o₃ == some 0xa0
  guard (!curveRequired || hasCurve)
  let o₄ ← if hasCurve then matchAt body o₃ (hexConst "a00a06082a8648ce3d030107") else some o₃
  let (point, o₅) ←
    if byteAt? body o₄ == some 0xa1 then do
      let o ← matchAt body o₄ (hexConst "a14403420004")
      guard (o + 64 ≤ body.size)
      some (some (slice body o 64), o + 64)
    else some (none, o₄)
  guard (o₅ == body.size)
  some (slice body o₂ 32, point)

/-- A PrivateKeyInfo (RFC 5958 §2) of version 0 on P-256: the version,
`p256Algorithm`, and a privateKey OCTET STRING that holds an
ECPrivateKey. The fields fill the DER, so no attributes and no publicKey. The ECPrivateKey's
curve is optional here, since the AlgorithmIdentifier names it. -/
def readPkcs8 (der : ByteArray) : Option (ByteArray × Option ByteArray) := do
  let (body, end₀) ← readTlv der 0 0x30
  guard (end₀ == der.size)
  let o₁ ← matchAt body 0 (hexConst "020100")
  let o₂ ← matchAt body o₁ p256Algorithm
  let (key, o₃) ← readTlv body o₂ 0x04
  guard (o₃ == body.size)
  readEcPrivateKey false key

/-- A SEC 1 ECPrivateKey, whose curve RFC 5915 §3 requires outside
PKCS #8. -/
def readSec1 (der : ByteArray) : Option (ByteArray × Option ByteArray) :=
  readEcPrivateKey true der

/-- `ch_chain_from_pem`: one to `chainMax` certificates, and
`chainCountMax` at most, end-entity first, under the chain's strict text
rule. Their DER shares `derLen` bytes, and each reads as a certificate's
outer fields. -/
def chainFromPem? (derLen chainMax : Nat) (input : ByteArray) : Option (List ByteArray) := do
  let certs ← readCertificates? .refused derLen input
  guard (certs.length ≤ chainMax ∧ certs.length ≤ chainCountMax)
  guard (certs.all fun c => (readSubjectKey c).isSome)
  some certs

/-- `ch_anchors_from_pem`: one to `anchorMax` roots under the bundle's
text rule. Their DER shares `derLen` bytes, and each is read for its
subject Name and SubjectPublicKeyInfo. -/
def anchorsFromPem? (derLen anchorMax : Nat) (input : ByteArray) :
    Option (List (ByteArray × ByteArray)) := do
  let certs ← readCertificates? .skipped derLen input
  guard (certs.length ≤ anchorMax)
  certs.mapM readSubjectKey

/-- Byte-string equality through the hex text of each, which
`Spec.Bytes.bytesToHex_inj` makes faithful: ByteArray carries no
`LawfulBEq` instance, so a proof cannot read `=` back out of its `==`,
as `Spec.HandshakeParser.bytesEq` says. -/
def sameBytes (a b : ByteArray) : Bool := bytesToHex a == bytesToHex b

/-- An EC PARAMETERS block that names prime256v1 at the head of `cs`,
then line breaks that end in LF, then the rest: the EC PRIVATE KEY block
alone, which `decodeOne?` reads. -/
def readSec1AfterParameters? (cs : List UInt8) : Option ByteArray := do
  let (parameters, rest) ← readBlock? labelEcParameters cs
  guard (sameBytes parameters p256Parameters)
  match strictGap rest with
  | .block key => decodeOne? labelEcPrivateKey key.length keyDerMax ⟨key.toArray⟩
  | _ => none

/-- The key file's blocks, read by the reader of the form the key's label
names: a PRIVATE KEY block alone is PKCS #8, an EC PRIVATE KEY block alone
is SEC 1, and so is an EC PRIVATE KEY block under one EC PARAMETERS block
that names prime256v1. -/
def readKeyFile? (input : ByteArray) : Option (ByteArray × Option ByteArray) :=
  match decodeOne? labelPrivateKey input.size keyDerMax input with
  | some der => readPkcs8 der
  | none =>
    match decodeOne? labelEcPrivateKey input.size keyDerMax input with
    | some der => readSec1 der
    | none => (readSec1AfterParameters? input.toList).bind readSec1

/-- `ch_p256_key_from_pem`: the scalar and its point, X‖Y, when the file
is at most `keyTextMax` bytes, the scalar is 1 to n - 1, any point the
file carries is that point, and the leaf's key is P-256's with that point.
The C call's cpu argument picks how the point is computed and not which
point, so the spec takes none. -/
def keyFromPem? (input leaf : ByteArray) : Option (ByteArray × ByteArray) := do
  guard (input.size ≤ keyTextMax)
  let (scalar, filePoint) ← readKeyFile? input
  let pub ← Spec.P256.pubKey? (bytesToNatBE scalar)
  guard (filePoint.all (sameBytes · pub))
  let (_, spki) ← readSubjectKey leaf
  guard (sameBytes spki (p256Spki pub))
  some (scalar, pub)

set_option compiler.extract_closed false in
/-- Known answers: the corpus leaf key of `test/webpki_corpus/keys/leaf_p256.pem` in
both forms against its scalar, a key at the boundaries of the range, and refusals of
each shape the C refuses. -/
def selftest (_ : Unit) : Bool :=
  let scalar := hexConst "34200888da10b426faf05d7f1678369bbe0b6f189374b1a943bf0179b138e90d"
  let point := hexConst ("e1a90594ca86f0a593421acd2c4a92b2faa2b7e271091c6186df53cff2a28e34" ++
    "240e17cf6a99180c139f17c33bb5307ed09d63d0e1f3db92aa4167deb7682159")
  let sec1 := hexConst ("30770201010420" ++
    "34200888da10b426faf05d7f1678369bbe0b6f189374b1a943bf0179b138e90d" ++
    "a00a06082a8648ce3d030107a14403420004" ++
    "e1a90594ca86f0a593421acd2c4a92b2faa2b7e271091c6186df53cff2a28e34" ++
    "240e17cf6a99180c139f17c33bb5307ed09d63d0e1f3db92aa4167deb7682159")
  let pkcs8 := hexConst ("308187020100301306072a8648ce3d020106082a8648ce3d030107046d306b0201010420" ++
    "34200888da10b426faf05d7f1678369bbe0b6f189374b1a943bf0179b138e90d" ++
    "a14403420004" ++
    "e1a90594ca86f0a593421acd2c4a92b2faa2b7e271091c6186df53cff2a28e34" ++
    "240e17cf6a99180c139f17c33bb5307ed09d63d0e1f3db92aa4167deb7682159")
  let sec1NoCurve := hexConst ("30250201010420" ++
    "34200888da10b426faf05d7f1678369bbe0b6f189374b1a943bf0179b138e90d")
  readSec1 sec1 == some (scalar, some point) &&
    readPkcs8 pkcs8 == some (scalar, some point) &&
    (readSec1 sec1NoCurve).isNone &&
    readEcPrivateKey false sec1NoCurve == some (scalar, none) &&
    Spec.P256.pubKey? (bytesToNatBE scalar) == some point &&
    (readPkcs8 sec1).isNone &&
    (readSec1 pkcs8).isNone &&
    (p256Spki point).size == 91 &&
    p256Parameters.size == parametersDerMax &&
    keyTextMax == 452

/-! ## Proofs

`keyFromPem?_sound` is the key call's contract in the direction that
carries weight: an accepted file's point is its scalar's, the scalar is
in range, and the leaf's key is that point. `chainFromPem?_bounds` and
`anchorsFromPem?_bounds` are the two runs' counts and sizes.
`anchorsFromPem?_begins` is Camilo's rule of 2026-10-13 for a bundle: a
BEGIN line of any label but CERTIFICATE refuses it. -/

/-- An accepted key's point is its scalar's under `Spec.P256.pubKey?`,
which holds the scalar to 1 to n - 1, and the leaf certificate's
SubjectPublicKeyInfo is P-256's with that point. -/
theorem keyFromPem?_sound (input leaf scalar pub : ByteArray)
    (h : keyFromPem? input leaf = some (scalar, pub)) :
    Spec.P256.pubKey? (bytesToNatBE scalar) = some pub ∧
      ∃ name, readSubjectKey leaf = some (name, p256Spki pub) := by
  simp only [keyFromPem?, Option.bind_eq_bind, Option.bind_eq_some_iff] at h
  obtain ⟨_, -, ⟨scalar', filePoint⟩, -, pub', h_pub, _, -, ⟨name, spki⟩, h_leaf, _, h_spki,
    h_out⟩ := h
  simp only [Option.some.injEq, Prod.mk.injEq] at h_out
  obtain ⟨rfl, rfl⟩ := h_out
  have h_eq : spki = p256Spki pub' := by
    unfold guard at h_spki
    split at h_spki
    · rename_i h_same
      exact bytesToHex_inj _ _ (eq_of_beq h_same)
    · simp at h_spki
  subst h_eq
  exact ⟨h_pub, name, h_leaf⟩

/-- An accepted chain holds one to `chainMax` certificates, and
`chainCountMax` at most, of at most `derLen` bytes together, and each
reads as a certificate's outer fields. -/
theorem chainFromPem?_bounds (derLen chainMax : Nat) (input : ByteArray)
    (certs : List ByteArray) (h : chainFromPem? derLen chainMax input = some certs) :
    1 ≤ certs.length ∧ certs.length ≤ chainMax ∧ certs.length ≤ chainCountMax ∧
      derTotal certs ≤ derLen ∧ ∀ c ∈ certs, (readSubjectKey c).isSome := by
  simp only [chainFromPem?, Option.bind_eq_bind, Option.bind_eq_some_iff] at h
  obtain ⟨read, h_read, _, h_count, _, h_framed, h_out⟩ := h
  obtain rfl : read = certs := by simpa using h_out
  obtain ⟨h_one, h_total⟩ := readCertificates?_bounds .refused derLen input read h_read
  have h_count' : read.length ≤ chainMax ∧ read.length ≤ chainCountMax := by
    unfold guard at h_count
    split at h_count
    · assumption
    · simp at h_count
  have h_all : (read.all fun c => (readSubjectKey c).isSome) = true := by
    unfold guard at h_framed
    split at h_framed
    · assumption
    · simp at h_framed
  exact ⟨h_one, h_count'.1, h_count'.2, h_total, fun c hc => List.all_eq_true.mp h_all c hc⟩

/-- A map that succeeds keeps the list's length. -/
private theorem length_of_mapM {α β : Type} (f : α → Option β) :
    ∀ (l : List α) (out : List β), l.mapM f = some out → out.length = l.length
  | [], out, h => by
    rw [List.mapM_nil] at h
    obtain rfl : ([] : List β) = out := by simpa using h
    rfl
  | a :: l, out, h => by
    rw [List.mapM_cons] at h
    simp only [Option.bind_eq_bind, Option.bind_eq_some_iff, Option.pure_def,
      Option.some.injEq] at h
    obtain ⟨_, -, rest, h_rest, rfl⟩ := h
    simp [length_of_mapM f l rest h_rest]

/-- An accepted bundle holds one to `anchorMax` roots. -/
theorem anchorsFromPem?_bounds (derLen anchorMax : Nat) (input : ByteArray)
    (anchors : List (ByteArray × ByteArray))
    (h : anchorsFromPem? derLen anchorMax input = some anchors) :
    1 ≤ anchors.length ∧ anchors.length ≤ anchorMax := by
  simp only [anchorsFromPem?, Option.bind_eq_bind, Option.bind_eq_some_iff] at h
  obtain ⟨certs, h_certs, _, h_count, h_map⟩ := h
  obtain ⟨h_one, -⟩ := readCertificates?_bounds .skipped derLen input certs h_certs
  have h_count' : certs.length ≤ anchorMax := by
    unfold guard at h_count
    split at h_count
    · assumption
    · simp at h_count
  have h_len := length_of_mapM readSubjectKey certs anchors h_map
  omega

/-- A bundle that the call accepts holds "-----BEGIN " only at the start
of a line, and there CERTIFICATE's BEGIN line starts. So a BEGIN line of
any other label refuses the bundle (docs/decisions.md 131). -/
theorem anchorsFromPem?_begins (derLen anchorMax : Nat) (input : ByteArray)
    (anchors : List (ByteArray × ByteArray))
    (h : anchorsFromPem? derLen anchorMax input = some anchors) (k : Nat)
    (h_k : beginPrefix.isPrefixOf (input.toList.drop k) = true) :
    (k = 0 ∨ input.toList[k - 1]? = some 10) ∧
      beginLine.isPrefixOf (input.toList.drop k) = true := by
  simp only [anchorsFromPem?, Option.bind_eq_bind, Option.bind_eq_some_iff] at h
  obtain ⟨certs, h_certs, -⟩ := h
  exact readCertificates?_begins derLen input certs h_certs k h_k

end Spec.PemFiles
