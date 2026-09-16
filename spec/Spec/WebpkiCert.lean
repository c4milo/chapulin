import Spec.X509Der
import Spec.WebpkiTime
import Spec.WebpkiSpki
import Spec.WebpkiSigalg

/-!
One certificate for the `TRUST=webpki` chain verifier, written from
RFC 5280 §4.1 (Certificate and TBSCertificate), §4.1.2.1 (version),
§4.1.2.2 (serialNumber), §4.1.1.2 (the two signature fields must match),
§4.1.2.8 (the unique identifiers), §4.2 (extensions and criticality),
§4.2.1.3 (keyUsage), §4.2.1.6 (subjectAltName), §4.2.1.9
(basicConstraints) and §4.2.1.12 (extendedKeyUsage), over the canonical
DER readers of `Spec.X509Der`.

`parseCertificate?` takes the arm, `false` for a leaf and `true` for an
issuer, and one whole certificate:

* version 3, a serial of at most 20 value bytes, one of the four
  signature algorithms of `Spec.WebpkiSigalg`, the issuer and subject
  Names as whole TLVs read no further, a validity of two Times from
  `Spec.WebpkiTime` in order, a SubjectPublicKeyInfo `Spec.WebpkiSpki`
  accepts, the extensions field, and nothing after it: so no unique
  identifier;
* the outer signatureAlgorithm byte for byte the TBS signature field,
  and a signature BIT STRING with zero unused bits and at least one byte;
* at most `certificateMax` bytes.

`readExtensions?` reads the extensions field: one to `extensionCountMax`
Extensions of at most `extensionTlvMax` bytes each. It decodes keyUsage,
extendedKeyUsage and basicConstraints and judges them by the arm, records
where subjectAltName's value lies, refuses a second copy of any of the
four, skips every other extension when it is not critical and refuses it
when it is. The leaf needs keyUsage with digitalSignature,
extendedKeyUsage with id-kp-serverAuth among its purposes, and
subjectAltName, and a basicConstraints it carries asserts no CA. An
issuer needs keyUsage with keyCertSign and a critical basicConstraints
asserting CA, and its extendedKeyUsage is not read. A pathLenConstraint
without cA is refused on either arm, and one above `pathLenMax` is
refused.

The model decodes and then judges, where the C byte-compares some
fields; `Spec.X509Der`'s canonical readers give each value one encoding,
which is what lets the two agree. Byte ranges of the input are offsets,
so the differential compares them with the C's pointers into the same
buffer. What the model leaves out: the alert a refusal names, which the
unit tests pin, and every verdict about the chain, the clock or the
hostname, which belong to the walk.
-/

namespace Spec.WebpkiCert

open Spec.Bytes Spec.X509 Spec.WebpkiSpki Spec.WebpkiSigalg

/-- `CH_WEBPKI_CERT_MAX`: the largest certificate the mode reads
(docs/webpki.md, "Bounds"). -/
def certificateMax : Nat := 3072

/-- `CH_WEBPKI_EXT_COUNT_MAX`: the most extensions one certificate
carries. -/
def extensionCountMax : Nat := 16

/-- `CH_WEBPKI_EXT_TLV_MAX`: the largest Extension TLV, header included. -/
def extensionTlvMax : Nat := 1024

/-- The largest pathLenConstraint: a DER INTEGER of two content octets. -/
def pathLenMax : Nat := 32767

/-- A byte range of the input: the offset of its first byte and its
length. -/
structure Range where
  /-- The offset of the first byte. -/
  off : Nat
  /-- The number of bytes. -/
  len : Nat
  deriving DecidableEq, Repr

/-- What the extension walk records: which of the four read extensions it
saw, basicConstraints' cA and pathLenConstraint, and the subjectAltName
extnValue's range, whose presence is what seeing subjectAltName means. -/
structure Extensions where
  /-- keyUsage was seen. -/
  keyUsage : Bool
  /-- extendedKeyUsage was seen. -/
  extKeyUsage : Bool
  /-- basicConstraints was seen. -/
  basicConstraints : Bool
  /-- The subjectAltName extnValue, the GeneralNames TLV, when seen. -/
  subjectAltName : Option Range
  /-- basicConstraints' cA, false when basicConstraints is absent. -/
  isCa : Bool
  /-- basicConstraints' pathLenConstraint, when present. -/
  pathLen : Option Nat
  deriving DecidableEq, Repr

/-- The record before the first extension. -/
def Extensions.empty : Extensions := ⟨false, false, false, none, false, none⟩

/-- The `webpki_cert.seen` byte: 1 keyUsage, 2 extendedKeyUsage,
4 basicConstraints, 8 subjectAltName (webpki.h's `WEBPKI_EXT_*`). -/
def Extensions.seen (e : Extensions) : Nat :=
  (if e.keyUsage then 1 else 0) + (if e.extKeyUsage then 2 else 0) +
    (if e.basicConstraints then 4 else 0) + (if e.subjectAltName.isSome then 8 else 0)

/-- The four extensions the walk reads. -/
inductive Known
  /-- keyUsage, 2.5.29.15 (§4.2.1.3). -/
  | keyUsage
  /-- extendedKeyUsage, 2.5.29.37 (§4.2.1.12). -/
  | extKeyUsage
  /-- basicConstraints, 2.5.29.19 (§4.2.1.9). -/
  | basicConstraints
  /-- subjectAltName, 2.5.29.17 (§4.2.1.6). -/
  | subjectAltName

/-- subjectAltName, arc 2.5.29.17, content octets. -/
def oidSubjectAltName : ByteArray := ByteArray.mk #[0x55, 0x1d, 0x11]

/-- id-kp-serverAuth, 1.3.6.1.5.5.7.3.1 (§4.2.1.12), content octets. -/
def oidServerAuth : ByteArray := ByteArray.mk #[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01]

/-- A BOOLEAN TRUE in its one DER encoding (X.690 §11.1). -/
def booleanTrue : ByteArray := ByteArray.mk #[0x01, 0x01, 0xff]

/-- The extension an extnID names, among the four the walk reads. -/
def known? (oid : ByteArray) : Option Known :=
  if oid == oidKeyUsage then some .keyUsage
  else if oid == oidExtKeyUsage then some .extKeyUsage
  else if oid == oidBasicConstraints then some .basicConstraints
  else if oid == oidSubjectAltName then some .subjectAltName
  else none

/-- One TLV with the given tag at `off`: the offset of its content, the
content, and the offset just past it. -/
def readTlvAt (b : ByteArray) (off : Nat) (tag : UInt8) : Option (Nat × ByteArray × Nat) :=
  (readTlv b off tag).map fun (content, contentEnd) => (contentEnd - content.size, content, contentEnd)

/-- The KeyPurposeId entries of an ExtKeyUsageSyntax from `off` to the
end of `list`, at most `fuel` of them: `some` of whether one is
id-kp-serverAuth, when every entry is an OBJECT IDENTIFIER with content. -/
def purposesWalk (list : ByteArray) : Nat → Nat → Bool → Option Bool
  | 0, off, found => if off == list.size then some found else none
  | fuel + 1, off, found =>
    if off == list.size then some found
    else do
      let (oid, off') ← readTlv list off 0x06
      guard (oid.size ≠ 0)
      purposesWalk list fuel off' (found || oid == oidServerAuth)

/-- ExtKeyUsageSyntax ::= SEQUENCE SIZE (1..MAX) OF KeyPurposeId
(§4.2.1.12), filling the extnValue: whether id-kp-serverAuth is among the
purposes. Every entry takes three bytes or more, so `list.size` entries
of fuel reach the end of any list that can be read. -/
def readServerAuth? (value : ByteArray) : Option Bool := do
  let (list, listEnd) ← readTlv value 0 0x30
  guard (listEnd == value.size ∧ list.size ≠ 0)
  purposesWalk list list.size 0 false

/-- BasicConstraints ::= SEQUENCE { cA BOOLEAN DEFAULT FALSE,
pathLenConstraint INTEGER (0..MAX) OPTIONAL } (§4.2.1.9), filling the
extnValue, in canonical DER: a FALSE cA is absent, and the constraint is
a minimal non-negative INTEGER of at most `pathLenMax`. -/
def readBasicConstraints? (value : ByteArray) : Option (Bool × Option Nat) := do
  let (seq, seqEnd) ← readTlv value 0 0x30
  guard (seqEnd == value.size)
  let (ca, o1) ←
    if byteAt? seq 0 == some 0x01 then (matchAt seq 0 booleanTrue).map fun o => (true, o)
    else some (false, 0)
  if o1 == seq.size then some (ca, none)
  else do
    let (pathLen, o2) ← readDerInt seq o1
    guard (o2 == seq.size ∧ pathLen ≤ pathLenMax)
    some (ca, some pathLen)

/-- Judges one read extension by the arm and records it: a second copy
of any of the four is refused. `range` is where the extnValue lies. -/
def record (isCa critical : Bool) (k : Known) (value : ByteArray) (range : Range)
    (acc : Extensions) : Option Extensions :=
  match k with
  | .keyUsage => do
    -- The leaf signs handshakes, an issuer signs certificates; other bits may be set too.
    guard (!acc.keyUsage ∧ readKeyUsage value (if isCa then 0x04 else 0x80))
    some { acc with keyUsage := true }
  | .extKeyUsage => do
    guard (!acc.extKeyUsage)
    if isCa then some { acc with extKeyUsage := true }
    else do
      let serverAuth ← readServerAuth? value
      guard serverAuth
      some { acc with extKeyUsage := true }
  | .basicConstraints => do
    guard (!acc.basicConstraints)
    let (ca, pathLen) ← readBasicConstraints? value
    guard (ca == isCa ∧ (critical || !isCa) ∧ (ca || pathLen.isNone))
    some { acc with basicConstraints := true, isCa := ca, pathLen := pathLen }
  | .subjectAltName => do
    guard acc.subjectAltName.isNone
    some { acc with subjectAltName := some range }

/-- An Extension's critical field at `off`: TRUE exactly as `01 01 ff`,
FALSE absent, since it is the DEFAULT (X.690 §11.5). Returns the flag and
the offset past it. -/
def readCritical? (ext : ByteArray) (off : Nat) : Option (Bool × Nat) := do
  let t ← byteAt? ext off
  if t == 0x01 then
    if off + 3 ≤ ext.size ∧ ext[off + 1]! == 0x01 ∧ ext[off + 2]! == 0xff then some (true, off + 3)
    else none
  else some (false, off)

/-- One Extension (§4.1) at `off` in the extension list: SEQUENCE {
extnID OBJECT IDENTIFIER, critical BOOLEAN DEFAULT FALSE, extnValue OCTET
STRING } in canonical DER, the whole TLV at most `extensionTlvMax` bytes,
the extnID §8.19-minimal. An extension the walk does not read is skipped
when not critical and refused when critical (§4.2). Returns the record,
the subjectAltName range relative to `list`, and the offset past the
Extension. -/
def readOneExtension (isCa : Bool) (list : ByteArray) (off : Nat) (acc : Extensions) :
    Option (Extensions × Nat) := do
  let (extOff, ext, extEnd) ← readTlvAt list off 0x30
  guard (extEnd - off ≤ extensionTlvMax)
  let (oid, o1) ← readTlv ext 0 0x06
  guard (oid.size ≠ 0 ∧ oid.size ≤ 16 ∧ oidMinimal oid)
  let (critical, o2) ← readCritical? ext o1
  let (valueOff, value, o3) ← readTlvAt ext o2 0x04
  guard (o3 == ext.size)
  match known? oid with
  | none => if critical then none else some (acc, extEnd)
  | some k => do
    let recorded ← record isCa critical k value ⟨extOff + valueOff, value.size⟩ acc
    some (recorded, extEnd)

/-- The Extensions from `off` to the end of `list`, at most `fuel` of
them. -/
def extensionsWalk (isCa : Bool) (list : ByteArray) : Nat → Nat → Extensions → Option Extensions
  | 0, off, acc => if off == list.size then some acc else none
  | fuel + 1, off, acc =>
    if off == list.size then some acc
    else do
      let (acc', off') ← readOneExtension isCa list off acc
      extensionsWalk isCa list fuel off' acc'

/-- What each arm must have seen: keyUsage, extendedKeyUsage and
subjectAltName on the leaf; keyUsage and basicConstraints on an issuer. -/
def Extensions.complete (isCa : Bool) (e : Extensions) : Bool :=
  if isCa then e.keyUsage && e.basicConstraints
  else e.keyUsage && e.extKeyUsage && e.subjectAltName.isSome

/-- A range `base` bytes further into the input. -/
def Range.shift (r : Range) (base : Nat) : Range := ⟨base + r.off, r.len⟩

/-- The record with its subjectAltName range `base` bytes further into the
input: how a range relative to an inner buffer becomes one relative to
the buffer holding it. -/
def Extensions.shift (e : Extensions) (base : Nat) : Extensions :=
  { e with subjectAltName := e.subjectAltName.map (Range.shift · base) }

/-- extensions [3] EXPLICIT Extensions at `off` (§4.1), required, with
Extensions ::= SEQUENCE SIZE (1..MAX) OF Extension filling the [3]
wrapper, walked and judged by the arm. Returns the record, the
subjectAltName range relative to `b`, and the offset past the field. -/
def readExtensions? (isCa : Bool) (b : ByteArray) (off : Nat) : Option (Extensions × Nat) := do
  let (wrapOff, wrap, wrapEnd) ← readTlvAt b off 0xa3
  let (listOff, list, listEnd) ← readTlvAt wrap 0 0x30
  guard (listEnd == wrap.size ∧ list.size ≠ 0)
  let walked ← extensionsWalk isCa list extensionCountMax 0 Extensions.empty
  guard (walked.complete isCa)
  some (walked.shift (wrapOff + listOff), wrapEnd)

/-- The TBSCertificate fields, ranges relative to the TBS content. -/
structure Tbs where
  /-- The issuer Name TLV. -/
  issuer : Range
  /-- The subject Name TLV. -/
  subject : Range
  /-- notBefore, packed as `Spec.WebpkiTime.readTime` packs it. -/
  notBefore : Nat
  /-- notAfter, packed the same way. -/
  notAfter : Nat
  /-- The public key's algorithm. -/
  keyAlg : KeyAlg
  /-- The public key: the RSA modulus, or the EC point's X ‖ Y. -/
  key : ByteArray
  /-- The signature AlgorithmIdentifier TLV's bytes. -/
  sigAlgTlv : ByteArray
  /-- The algorithm it names. -/
  sigAlg : SigAlg
  /-- The extension record. -/
  extensions : Extensions

/-- Validity ::= SEQUENCE { notBefore Time, notAfter Time } (§4.1.2.5),
filling its length, with notBefore no later than notAfter: the two
packed dates and the offset past the field. -/
def readValidity? (b : ByteArray) (off : Nat) : Option (Nat × Nat × Nat) := do
  let (validity, validityEnd) ← readTlv b off 0x30
  let (notBefore, o1) ← Spec.WebpkiTime.readTime validity 0
  let (notAfter, o2) ← Spec.WebpkiTime.readTime validity o1
  guard (o2 == validity.size ∧ notBefore ≤ notAfter)
  some (notBefore, notAfter, validityEnd)

/-- TBSCertificate (§4.1), first byte to last, exact-fill: version [0]
EXPLICIT INTEGER 2, serialNumber, signature, issuer, validity, subject,
subjectPublicKeyInfo, extensions [3], and nothing else, so neither unique
identifier. -/
def readTbs? (isCa : Bool) (tbs : ByteArray) : Option Tbs := do
  let o1 ← matchAt tbs 0 versionV3
  let o2 ← readSerial tbs o1
  let (_, o3) ← readTlv tbs o2 0x30
  let sigAlgTlv := slice tbs o2 (o3 - o2)
  let sigAlg ← readSigalg? sigAlgTlv
  let (_, o4) ← readTlv tbs o3 0x30
  let (notBefore, notAfter, o5) ← readValidity? tbs o4
  let (_, o6) ← readTlv tbs o5 0x30
  let (_, o7) ← readTlv tbs o6 0x30
  let (keyAlg, key) ← readSpki? (slice tbs o6 (o7 - o6))
  let (extensions, o8) ← readExtensions? isCa tbs o7
  guard (o8 == tbs.size)
  some ⟨⟨o3, o4 - o3⟩, ⟨o5, o6 - o5⟩, notBefore, notAfter, keyAlg, key, sigAlgTlv, sigAlg,
    extensions⟩

/-- One parsed certificate; every range is an offset into the
certificate's bytes. -/
structure Certificate where
  /-- The TBSCertificate content, without its header. -/
  tbs : Range
  /-- The issuer Name TLV. -/
  issuer : Range
  /-- The subject Name TLV. -/
  subject : Range
  /-- notBefore, packed. -/
  notBefore : Nat
  /-- notAfter, packed. -/
  notAfter : Nat
  /-- The public key's algorithm. -/
  keyAlg : KeyAlg
  /-- The public key's bytes. -/
  key : ByteArray
  /-- The signature algorithm, the same in both fields. -/
  sigAlg : SigAlg
  /-- The signature BIT STRING's bytes after its unused-bits octet. -/
  signature : Range
  /-- The extension record, its subjectAltName range into the certificate. -/
  extensions : Extensions

/-- Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm,
signatureValue } (§4.1), at most `certificateMax` bytes, exact-fill at
every level, the arm's TBSCertificate, the outer signatureAlgorithm byte
for byte the TBS signature field (§4.1.1.2), and a signature BIT STRING
with zero unused bits and at least one byte. -/
def parseCertificate? (isCa : Bool) (cert : ByteArray) : Option Certificate := do
  guard (cert.size ≤ certificateMax)
  let (bodyOff, body, bodyEnd) ← readTlvAt cert 0 0x30
  guard (bodyEnd == cert.size)
  let (tbsOff, tbs, tbsEnd) ← readTlvAt body 0 0x30
  let fields ← readTbs? isCa tbs
  let o1 ← matchAt body tbsEnd fields.sigAlgTlv
  let (sigOff, sig, sigEnd) ← readTlvAt body o1 0x03
  guard (sigEnd == body.size ∧ 2 ≤ sig.size ∧ sig[0]! == 0)
  let base := bodyOff + tbsOff
  some {
    tbs := ⟨base, tbs.size⟩
    issuer := fields.issuer.shift base
    subject := fields.subject.shift base
    notBefore := fields.notBefore
    notAfter := fields.notAfter
    keyAlg := fields.keyAlg
    key := fields.key
    sigAlg := fields.sigAlg
    signature := ⟨bodyOff + sigOff + 1, sig.size - 1⟩
    extensions := fields.extensions.shift base }

/-- Hex for a selftest constant; a malformed literal becomes one byte no
reader accepts as a certificate. -/
private def hex (s : String) : ByteArray := (hexToBytes? s).getD (ByteArray.mk #[0])

/-- The corpus r2 leaf (test/webpki_corpus.h, `webpki_corpus_message_r2`
entry 0): P-256, ecdsa-with-SHA256, six extensions. -/
def r2Leaf : ByteArray := hex
  ("308201e53082018ba003020102020115300a06082a8648ce3d040302303f310b300906035504061302555331" ++
   "0f300d060355040a0c06436f72707573311f301d06035504030c16436f7270757320523220496e7465726d65" ++
   "6469617465301e170d3236303130313030303030305a170d3236313233313233353935395a301a3118301606" ++
   "035504030c0f73332e6578616d706c652e746573743059301306072a8648ce3d020106082a8648ce3d030107" ++
   "03420004e1a90594ca86f0a593421acd2c4a92b2faa2b7e271091c6186df53cff2a28e34240e17cf6a99180c" ++
   "139f17c33bb5307ed09d63d0e1f3db92aa4167deb7682159a3819c308199300c0603551d130101ff04023000" ++
   "300e0603551d0f0101ff040403020780301d0603551d250416301406082b0601050507030106082b06010505" ++
   "070302301a0603551d1104133011820f73332e6578616d706c652e74657374301d0603551d0e0416041408ee" ++
   "7cfbcd51fcd6ceebe6120ef1657ba018a03e301f0603551d23041830168014e7ab73f72604d2cb3329676f58" ++
   "06ce7be8baef17300a06082a8648ce3d0403020348003045022069214df5546bd569e4782a4a99dbacdc4a29" ++
   "07b4b789d654d379259f0231b516022100a0b8056f940a4067d93263c04773d110ea862daf302d45277c2258" ++
   "926e295aba")

/-- The corpus r2 intermediate, entry 1 of the same message: P-256 under
ecdsa-with-SHA384, basicConstraints critical with cA and pathLen 0. -/
def r2Issuer : ByteArray := hex
  ("3082020e30820195a003020102020109300a06082a8648ce3d040303303a310b300906035504061302555331" ++
   "0f300d060355040a0c06436f72707573311a301806035504030c11436f7270757320502d33383420526f6f74" ++
   "301e170d3235303130313030303030305a170d3430313233313233353935395a303f310b3009060355040613" ++
   "025553310f300d060355040a0c06436f72707573311f301d06035504030c16436f7270757320523220496e74" ++
   "65726d6564696174653059301306072a8648ce3d020106082a8648ce3d030107034200046ca205b58d0d3b6d" ++
   "47d02be2afbbfbb5297dced41b43c6d6773ed3117cde18d4a5399a6995b98f8578db250aeb4a34fd3f95c06e" ++
   "7a52c5b2579edd99f12b8c1aa3818630818330120603551d130101ff040830060101ff020100300e0603551d" ++
   "0f0101ff040403020106301d0603551d250416301406082b0601050507030106082b06010505070302301d06" ++
   "03551d0e04160414e7ab73f72604d2cb3329676f5806ce7be8baef17301f0603551d23041830168014d9c3e3" ++
   "e650ed33e56381d80031e486e9426654d3300a06082a8648ce3d040303036700306402300b14478c504ff0f0" ++
   "4c9c2766511d9bcfac5f8cd9660fdb0b92fd50e1ff19a29852c6d13ed0b401a852095464399a2c9902300454" ++
   "315c907f5ebbe6c49f757ae398010363c7ed744f4a789bfc987197792f820e2187b7cd143275c08a5278621f" ++
   "074b")

/-- The r2 leaf rebuilt around a given extension list: its TBS fields
through the SubjectPublicKeyInfo, then `[3] { SEQUENCE exts }`, then its
signature algorithm and signature. The selftest checks that its own six
extensions rebuild the corpus bytes. -/
def r2LeafWith (exts : ByteArray) : ByteArray :=
  let prefixHex :=
    "a003020102020115300a06082a8648ce3d040302303f310b3009060355040613025553310f300d060355040a" ++
    "0c06436f72707573311f301d06035504030c16436f7270757320523220496e7465726d656469617465301e17" ++
    "0d3236303130313030303030305a170d3236313233313233353935395a301a3118301606035504030c0f7333" ++
    "2e6578616d706c652e746573743059301306072a8648ce3d020106082a8648ce3d03010703420004e1a90594" ++
    "ca86f0a593421acd2c4a92b2faa2b7e271091c6186df53cff2a28e34240e17cf6a99180c139f17c33bb5307e" ++
    "d09d63d0e1f3db92aa4167deb7682159"
  let signatureHex :=
    "003045022069214df5546bd569e4782a4a99dbacdc4a2907b4b789d654d379259f0231b516022100a0b8056f" ++
    "940a4067d93263c04773d110ea862daf302d45277c2258926e295aba"
  tlv 0x30 (tlv 0x30 (hex prefixHex ++ tlv 0xa3 (tlv 0x30 exts)) ++ hex "300a06082a8648ce3d040302" ++
    tlv 0x03 (hex signatureHex))

/-- The r2 leaf's six extensions, in order. -/
def r2LeafExtensions : List ByteArray :=
  ["300c0603551d130101ff04023000", "300e0603551d0f0101ff040403020780",
   "301d0603551d250416301406082b0601050507030106082b06010505070302",
   "301a0603551d1104133011820f73332e6578616d706c652e74657374",
   "301d0603551d0e0416041408ee7cfbcd51fcd6ceebe6120ef1657ba018a03e",
   "301f0603551d23041830168014e7ab73f72604d2cb3329676f5806ce7be8baef17"].map hex

/-- The corpus leaf and issuer under both arms, the leaf's fields and
ranges, and one refusal or acceptance per rule over the rebuilt leaf:
each required extension removed, keyUsage without digitalSignature,
extendedKeyUsage without serverAuth, a leaf asserting CA, a duplicate,
an unknown extension critical and not, and the count and size caps on
both sides. -/
def selftest : Bool :=
  let joined := fun (l : List ByteArray) => l.foldl (· ++ ·) ByteArray.empty
  let without := fun (i : Nat) => joined (r2LeafExtensions.eraseIdx i)
  let unknown := fun (arc : UInt8) => hex "3009060355" ++ ByteArray.mk #[0x1d, arc] ++ hex "04023000"
  let sized := fun (total : Nat) =>
    tlv 0x30 (hex "0603551d09" ++ tlv 0x04 (ByteArray.mk (Array.replicate (total - 13) 0x5a)))
  let accepts := fun (isCa : Bool) (b : ByteArray) => (parseCertificate? isCa b).isSome
  let leaf := parseCertificate? false r2Leaf
  let fieldsOk :=
    match leaf with
    | none => false
    | some c =>
      c.tbs == ⟨8, 395⟩ && c.sigAlg == .ecdsaSha256 && c.keyAlg == .p256 && c.key.size == 64 &&
        c.notBefore == 20260101000000 && c.notAfter == 20261231235959 &&
        c.signature == ⟨418, 71⟩ && c.extensions.seen == 15 && !c.extensions.isCa &&
        c.extensions.pathLen == none &&
        (match c.extensions.subjectAltName with
         | some r => slice r2Leaf r.off r.len == hex "3011820f73332e6578616d706c652e74657374"
         | none => false) &&
        slice r2Leaf c.issuer.off 2 == hex "303f" && slice r2Leaf c.subject.off 2 == hex "301a"
  let issuerOk :=
    match parseCertificate? true r2Issuer with
    | some c => c.extensions.isCa && c.extensions.pathLen == some 0 &&
        c.extensions.subjectAltName == none && c.sigAlg == .ecdsaSha384
    | none => false
  let ku := hex "300e0603551d0f0101ff040403020520"
  let ekuClient := hex "30150603551d25040e300c06082b06010505070302"
  let bcCa := hex "300f0603551d130101ff040530030101ff"
  let critical := hex "300c0603551d1e0101ff04023000"
  let plain := hex "30090603551d1e04023000"
  let tenUnknown := joined ((List.range 10).map fun i => unknown (UInt8.ofNat (0x40 + i)))
  fieldsOk && issuerOk && r2LeafWith (joined r2LeafExtensions) == r2Leaf &&
    !accepts true r2Leaf && !accepts false r2Issuer &&
    !accepts false (r2LeafWith (without 1)) && !accepts false (r2LeafWith (without 2)) &&
    !accepts false (r2LeafWith (without 3)) && accepts false (r2LeafWith (without 0)) &&
    !accepts false (r2LeafWith (without 1 ++ ku)) &&
    !accepts false (r2LeafWith (without 2 ++ ekuClient)) &&
    !accepts false (r2LeafWith (without 0 ++ bcCa)) &&
    !accepts false (r2LeafWith (joined r2LeafExtensions ++ r2LeafExtensions[3]!)) &&
    !accepts false (r2LeafWith (joined r2LeafExtensions ++ critical)) &&
    accepts false (r2LeafWith (joined r2LeafExtensions ++ plain)) &&
    accepts false (r2LeafWith (joined r2LeafExtensions ++ tenUnknown)) &&
    !accepts false (r2LeafWith (joined r2LeafExtensions ++ tenUnknown ++ unknown 0x60)) &&
    accepts false (r2LeafWith (joined r2LeafExtensions ++ sized extensionTlvMax)) &&
    !accepts false (r2LeafWith (joined r2LeafExtensions ++ sized (extensionTlvMax + 1))) &&
    !accepts false (r2Leaf ++ ByteArray.mk #[0])

/-!
## Proofs

Soundness facts about what an accepted certificate is, each over every
input: its bytes are exactly one Certificate SEQUENCE whose TBS content is
the recorded range and whose outer signatureAlgorithm encodes the
recorded algorithm; the subjectAltName range lies inside the extensions
field; and each arm saw the extensions it needs.
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

private theorem tlv_size (tag : UInt8) (c : ByteArray) :
    (tlv tag c).size = 1 + (encodeLen c.size).size + c.size := by
  rw [tlv, ByteArray.size_append, ByteArray.size_append]
  rfl

/-- `readTlvAt` is `readTlv` with the content's offset beside it. -/
private theorem readTlv_of_readTlvAt {b : ByteArray} {off : Nat} {tag : UInt8} {co : Nat}
    {c : ByteArray} {e : Nat} (h : readTlvAt b off tag = some (co, c, e)) :
    readTlv b off tag = some (c, e) ∧ co = e - c.size := by
  unfold readTlvAt at h
  obtain ⟨⟨c', e'⟩, h_read, h_eq⟩ := Option.map_eq_some_iff.mp h
  simp only [Prod.mk.injEq] at h_eq
  obtain ⟨h_co, h_c, h_e⟩ := h_eq
  subst h_c h_e
  exact ⟨h_read, h_co.symm⟩

/-- The content `readTlv` returns is the input's bytes just before the end
offset, which is inside the input, and the header before them is at
least one byte. -/
private theorem readTlv_content {b : ByteArray} {off : Nat} {tag : UInt8} {c : ByteArray}
    {e : Nat} (h : readTlv b off tag = some (c, e)) :
    off < e - c.size ∧ c.size ≤ e ∧ e ≤ b.size ∧ slice b (e - c.size) c.size = c := by
  obtain ⟨h_end, h_fits, -⟩ := readTlv_canonical b off tag c e h
  have h_size := tlv_size tag c
  unfold readTlv at h
  obtain ⟨t, -, h⟩ := bind_some_elim h
  obtain ⟨-, -, h⟩ := bind_some_elim h
  obtain ⟨⟨len, co⟩, -, h⟩ := bind_some_elim h
  simp only [Option.some.injEq, Prod.mk.injEq] at h
  obtain ⟨h_c, h_e⟩ := h
  have h_len : c.size = len := by
    rw [← h_c, slice, ByteArray.size_extract]
    omega
  have h_co : e - c.size = co := by omega
  refine ⟨by omega, by omega, h_fits, ?_⟩
  rw [h_co, h_len, h_c]

/-- What `readTlvAt` returns is a range of the input: the content starts
after `off`, ends at the returned offset inside the input, and is the
input's bytes there. -/
private theorem readTlvAt_range {b : ByteArray} {off : Nat} {tag : UInt8} {co : Nat}
    {c : ByteArray} {e : Nat} (h : readTlvAt b off tag = some (co, c, e)) :
    off < co ∧ co + c.size = e ∧ e ≤ b.size ∧ slice b co c.size = c := by
  obtain ⟨h_read, h_co⟩ := readTlv_of_readTlvAt h
  obtain ⟨h_after, h_le, h_fits, h_slice⟩ := readTlv_content h_read
  subst h_co
  exact ⟨h_after, by omega, h_fits, h_slice⟩

/-- A range of a range is a range of the whole. -/
private theorem slice_slice (b : ByteArray) (i n j m : Nat) (h_inner : j + m ≤ n) :
    slice (slice b i n) j m = slice b (i + j) m := by
  simp only [slice, ByteArray.extract_extract]
  congr 1
  omega

/-- An accepted `matchAt` found `want` at `off`. -/
private theorem matchAt_some {b want : ByteArray} {off off' : Nat}
    (h : matchAt b off want = some off') :
    off' = off + want.size ∧ off' ≤ b.size ∧ slice b off want.size = want := by
  unfold matchAt at h
  split at h
  · split at h
    · next h_eq =>
      simp only [Option.some.injEq] at h
      exact ⟨h.symm, by omega, ByteArray.ext (eq_of_beq h_eq)⟩
    · cases h
  · cases h

/-- The signature field `readTbs?` records is the encoding of the
algorithm it records. -/
private theorem readTbs?_sigAlgTlv {isCa : Bool} {tbs : ByteArray} {f : Tbs}
    (h : readTbs? isCa tbs = some f) : f.sigAlgTlv = encode f.sigAlg := by
  unfold readTbs? at h
  obtain ⟨o1, -, h⟩ := bind_some_elim h
  obtain ⟨o2, -, h⟩ := bind_some_elim h
  obtain ⟨⟨_, o3⟩, -, h⟩ := bind_some_elim h
  obtain ⟨sigAlg, h_sigalg, h⟩ := bind_some_elim h
  obtain ⟨⟨_, o4⟩, -, h⟩ := bind_some_elim h
  obtain ⟨⟨notBefore, notAfter, o5⟩, -, h⟩ := bind_some_elim h
  obtain ⟨⟨_, o6⟩, -, h⟩ := bind_some_elim h
  obtain ⟨⟨_, o7⟩, -, h⟩ := bind_some_elim h
  obtain ⟨⟨keyAlg, key⟩, -, h⟩ := bind_some_elim h
  obtain ⟨⟨extensions, o8⟩, -, h⟩ := bind_some_elim h
  obtain ⟨-, -, h⟩ := bind_some_elim h
  simp only [Option.some.injEq] at h
  subst h
  exact (readSigalg?_iff _ _).mp h_sigalg

/-- An accepted certificate is exactly one Certificate SEQUENCE of three
fields: a TBSCertificate whose content is the bytes the recorded `tbs`
range names, inside the input; the outer signatureAlgorithm, which is the
DER encoding of the recorded algorithm, so the TBS signature field it
equals names the same one; and a BIT STRING with a zero unused-bits octet
and at least one signature byte. Nothing precedes, separates or follows
the three. -/
theorem parseCertificate?_frames (isCa : Bool) (cert : ByteArray) (c : Certificate)
    (h : parseCertificate? isCa cert = some c) :
    c.tbs.off + c.tbs.len ≤ cert.size ∧
      ∃ sig, cert = tlv 0x30 (tlv 0x30 (slice cert c.tbs.off c.tbs.len) ++ encode c.sigAlg ++
          tlv 0x03 sig) ∧ 2 ≤ sig.size ∧ sig[0]! = 0 := by
  unfold parseCertificate? at h
  obtain ⟨-, -, h⟩ := bind_some_elim h
  obtain ⟨⟨bodyOff, body, bodyEnd⟩, h_body, h⟩ := bind_some_elim h
  obtain ⟨_, h_whole, h⟩ := bind_some_elim h
  obtain ⟨⟨tbsOff, tbs, tbsEnd⟩, h_tbs, h⟩ := bind_some_elim h
  obtain ⟨fields, h_fields, h⟩ := bind_some_elim h
  obtain ⟨o1, h_match, h⟩ := bind_some_elim h
  obtain ⟨⟨sigOff, sig, sigEnd⟩, h_sig, h⟩ := bind_some_elim h
  obtain ⟨_, h_tail, h⟩ := bind_some_elim h
  simp only [Option.some.injEq] at h
  subst h
  obtain ⟨h_sig_end, h_sig_size, h_sig_zero⟩ := guard_some h_tail
  have h_body_end : bodyEnd = cert.size := eq_of_beq (guard_some h_whole)
  have h_sigalg := readTbs?_sigAlgTlv h_fields
  obtain ⟨h_body_read, -⟩ := readTlv_of_readTlvAt h_body
  obtain ⟨h_tbs_read, -⟩ := readTlv_of_readTlvAt h_tbs
  obtain ⟨h_sig_read, -⟩ := readTlv_of_readTlvAt h_sig
  obtain ⟨-, h_body_co, -, h_body_slice⟩ := readTlvAt_range h_body
  obtain ⟨-, h_tbs_co, h_tbs_fits, h_tbs_slice⟩ := readTlvAt_range h_tbs
  obtain ⟨hc_end, -, hc_slice⟩ := readTlv_canonical cert 0 0x30 body bodyEnd h_body_read
  obtain ⟨h1_end, -, h1_slice⟩ := readTlv_canonical body 0 0x30 tbs tbsEnd h_tbs_read
  obtain ⟨h2_end, -, h2_slice⟩ := matchAt_some h_match
  obtain ⟨h3_end, -, h3_slice⟩ := readTlv_canonical body o1 0x03 sig sigEnd h_sig_read
  have h_sig_body : sigEnd = body.size := eq_of_beq h_sig_end
  have h_tbs_range : slice cert (bodyOff + tbsOff) tbs.size = tbs := by
    rw [← slice_slice cert bodyOff body.size tbsOff tbs.size (by omega), h_body_slice,
      h_tbs_slice]
  refine ⟨by simp only; omega, sig, ?_, by omega, eq_of_beq h_sig_zero⟩
  simp only [h_tbs_range]
  have h_cert : cert = tlv 0x30 body := by
    rw [slice, Nat.zero_add, show (tlv 0x30 body).size = cert.size by omega,
      ByteArray.extract_zero_size] at hc_slice
    exact hc_slice
  have h_split : body = tlv 0x30 tbs ++ encode fields.sigAlg ++ tlv 0x03 sig := by
    rw [h_sigalg] at h2_end
    have h_all : body.extract 0 body.size = body := ByteArray.extract_zero_size
    rw [ByteArray.extract_eq_extract_append_extract o1 (by omega) (by omega),
      ByteArray.extract_eq_extract_append_extract tbsEnd (by omega) (by omega)] at h_all
    rw [slice, Nat.zero_add, show (tlv 0x30 tbs).size = tbsEnd by omega] at h1_slice
    rw [slice, h_sigalg, show tbsEnd + (encode fields.sigAlg).size = o1 by omega] at h2_slice
    rw [slice, show o1 + (tlv 0x03 sig).size = body.size by omega] at h3_slice
    rw [h1_slice, h2_slice, h3_slice] at h_all
    exact h_all.symm
  rw [h_cert, h_split]

/-- An accepted extension either leaves the record as it was, or is one of
the four the walk reads, recorded with an extnValue range inside the
list. -/
private theorem readOneExtension_cases {isCa : Bool} {list : ByteArray} {off off' : Nat}
    {acc acc' : Extensions} (h : readOneExtension isCa list off acc = some (acc', off')) :
    acc' = acc ∨ ∃ critical k value range, range.off + range.len ≤ list.size ∧
      record isCa critical k value range acc = some acc' := by
  unfold readOneExtension at h
  obtain ⟨⟨extOff, ext, extEnd⟩, h_ext, h⟩ := bind_some_elim h
  obtain ⟨_, -, h⟩ := bind_some_elim h
  obtain ⟨⟨oid, o1⟩, -, h⟩ := bind_some_elim h
  obtain ⟨_, -, h⟩ := bind_some_elim h
  obtain ⟨⟨critical, o2⟩, -, h⟩ := bind_some_elim h
  obtain ⟨⟨valueOff, value, o3⟩, h_value, h⟩ := bind_some_elim h
  obtain ⟨_, h_fill, h⟩ := bind_some_elim h
  obtain ⟨-, h_ext_size, h_ext_fits, -⟩ := readTlvAt_range h_ext
  obtain ⟨-, h_value_size, h_value_fits, -⟩ := readTlvAt_range h_value
  split at h
  · split at h
    · cases h
    · simp only [Option.some.injEq, Prod.mk.injEq] at h
      exact Or.inl h.1.symm
  · next k _ =>
    obtain ⟨recorded, h_record, h⟩ := bind_some_elim h
    simp only [Option.some.injEq, Prod.mk.injEq] at h
    obtain ⟨rfl, -⟩ := h
    exact Or.inr ⟨critical, k, value, ⟨extOff + valueOff, value.size⟩, by simp only; omega,
      h_record⟩

/-- Recording keeps cA equal to the arm whenever basicConstraints has been
seen, and false before. -/
private theorem record_isCa {isCa critical : Bool} {k : Known} {value : ByteArray} {range : Range}
    {acc acc' : Extensions} (h : record isCa critical k value range acc = some acc')
    (h_acc : acc.isCa = (isCa && acc.basicConstraints)) :
    acc'.isCa = (isCa && acc'.basicConstraints) := by
  cases k <;> simp only [record] at h
  · obtain ⟨_, -, h⟩ := bind_some_elim h
    simp only [Option.some.injEq] at h
    subst h
    exact h_acc
  · obtain ⟨_, -, h⟩ := bind_some_elim h
    split at h
    · simp only [Option.some.injEq] at h
      subst h
      exact h_acc
    · obtain ⟨_, -, h⟩ := bind_some_elim h
      obtain ⟨_, -, h⟩ := bind_some_elim h
      simp only [Option.some.injEq] at h
      subst h
      exact h_acc
  · obtain ⟨_, -, h⟩ := bind_some_elim h
    obtain ⟨⟨ca, pathLen⟩, -, h⟩ := bind_some_elim h
    obtain ⟨_, h_judged, h⟩ := bind_some_elim h
    simp only [Option.some.injEq] at h
    subst h
    have h_ca : ca = isCa := eq_of_beq (guard_some h_judged).1
    simp only [Bool.and_true]
    exact h_ca
  · obtain ⟨_, -, h⟩ := bind_some_elim h
    simp only [Option.some.injEq] at h
    subst h
    exact h_acc

/-- Recording changes the subjectAltName range only to the range it was
handed. -/
private theorem record_subjectAltName {isCa critical : Bool} {k : Known} {value : ByteArray}
    {range : Range} {acc acc' : Extensions} (h : record isCa critical k value range acc = some acc') :
    acc'.subjectAltName = acc.subjectAltName ∨ acc'.subjectAltName = some range := by
  cases k <;> simp only [record] at h
  · obtain ⟨_, -, h⟩ := bind_some_elim h
    simp only [Option.some.injEq] at h
    subst h
    exact Or.inl rfl
  · obtain ⟨_, -, h⟩ := bind_some_elim h
    split at h
    · simp only [Option.some.injEq] at h
      subst h
      exact Or.inl rfl
    · obtain ⟨_, -, h⟩ := bind_some_elim h
      obtain ⟨_, -, h⟩ := bind_some_elim h
      simp only [Option.some.injEq] at h
      subst h
      exact Or.inl rfl
  · obtain ⟨_, -, h⟩ := bind_some_elim h
    obtain ⟨⟨ca, pathLen⟩, -, h⟩ := bind_some_elim h
    obtain ⟨_, -, h⟩ := bind_some_elim h
    simp only [Option.some.injEq] at h
    subst h
    exact Or.inl rfl
  · obtain ⟨_, -, h⟩ := bind_some_elim h
    simp only [Option.some.injEq] at h
    subst h
    exact Or.inr rfl

/-- A property every accepted extension keeps holds of the walk's result. -/
private theorem extensionsWalk_inv (isCa : Bool) (list : ByteArray) (P : Extensions → Prop)
    (h_step : ∀ off off' acc acc', P acc →
      readOneExtension isCa list off acc = some (acc', off') → P acc') :
    ∀ fuel off acc result, P acc → extensionsWalk isCa list fuel off acc = some result →
      P result := by
  intro fuel
  induction fuel with
  | zero =>
    intro off acc result h_acc h
    simp only [extensionsWalk] at h
    split at h
    · simp only [Option.some.injEq] at h
      exact h ▸ h_acc
    · cases h
  | succ fuel ih =>
    intro off acc result h_acc h
    simp only [extensionsWalk] at h
    split at h
    · simp only [Option.some.injEq] at h
      exact h ▸ h_acc
    · obtain ⟨⟨acc', off'⟩, h_one, h⟩ := bind_some_elim h
      exact ih off' acc' result (h_step off off' acc acc' h_acc h_one) h

/-- The pieces of an accepted extensions field: the [3] wrapper and the
list inside it, the walk's record, and the record `readExtensions?`
returns, which moves the subjectAltName range from the list to `b`. -/
private theorem readExtensions?_parts {isCa : Bool} {b : ByteArray} {off off' : Nat}
    {e : Extensions} (h : readExtensions? isCa b off = some (e, off')) :
    ∃ wrapOff wrap listOff list walked,
      readTlvAt b off 0xa3 = some (wrapOff, wrap, off') ∧
      (∃ listEnd, readTlvAt wrap 0 0x30 = some (listOff, list, listEnd)) ∧
      extensionsWalk isCa list extensionCountMax 0 Extensions.empty = some walked ∧
      walked.complete isCa = true ∧ e = walked.shift (wrapOff + listOff) := by
  unfold readExtensions? at h
  obtain ⟨⟨wrapOff, wrap, wrapEnd⟩, h_wrap, h⟩ := bind_some_elim h
  obtain ⟨⟨listOff, list, listEnd⟩, h_list, h⟩ := bind_some_elim h
  obtain ⟨_, -, h⟩ := bind_some_elim h
  obtain ⟨walked, h_walk, h⟩ := bind_some_elim h
  obtain ⟨_, h_complete, h⟩ := bind_some_elim h
  simp only [Option.some.injEq, Prod.mk.injEq] at h
  obtain ⟨h_e, h_end⟩ := h
  subst h_end
  exact ⟨wrapOff, wrap, listOff, list, walked, h_wrap, ⟨listEnd, h_list⟩, h_walk,
    guard_some h_complete, h_e.symm⟩

/-- The subjectAltName range an accepted extensions field records lies
inside that field: after its first byte, and ending no later than the
offset `readExtensions?` returns. So `webpki_match_san` reads bytes of
the extensions and nothing else. -/
theorem readExtensions?_subjectAltName (isCa : Bool) (b : ByteArray) (off off' : Nat)
    (e : Extensions) (r : Range) (h : readExtensions? isCa b off = some (e, off'))
    (h_san : e.subjectAltName = some r) : off < r.off ∧ r.off + r.len ≤ off' := by
  obtain ⟨wrapOff, wrap, listOff, list, walked, h_wrap, ⟨listEnd, h_list⟩, h_walk, -, rfl⟩ :=
    readExtensions?_parts h
  obtain ⟨h_after, h_wrap_size, -, -⟩ := readTlvAt_range h_wrap
  obtain ⟨-, h_list_size, h_list_fits, -⟩ := readTlvAt_range h_list
  have h_inside := extensionsWalk_inv isCa list
    (fun acc => ∀ r, acc.subjectAltName = some r → r.off + r.len ≤ list.size)
    (by
      intro o o' acc acc' h_acc h_one r h_r
      rcases readOneExtension_cases h_one with h_same | ⟨critical, k, value, range, h_fits, h_rec⟩
      · exact h_acc r (h_same ▸ h_r)
      · rcases record_subjectAltName h_rec with h_kept | h_new
        · exact h_acc r (h_kept ▸ h_r)
        · rw [h_new] at h_r
          cases h_r
          exact h_fits)
    extensionCountMax 0 Extensions.empty walked (by intro r h_r; cases h_r) h_walk
  simp only [Extensions.shift, Option.map_eq_some_iff] at h_san
  obtain ⟨r0, h_r0, rfl⟩ := h_san
  have h_r0_fits := h_inside r0 h_r0
  simp only [Range.shift]
  omega

/-- What each arm saw, over every accepted extensions field: the leaf's
keyUsage, extendedKeyUsage and subjectAltName, with cA false; an issuer's
keyUsage and basicConstraints, with cA true. -/
theorem readExtensions?_complete (isCa : Bool) (b : ByteArray) (off off' : Nat) (e : Extensions)
    (h : readExtensions? isCa b off = some (e, off')) :
    e.keyUsage = true ∧ e.isCa = isCa ∧
      (if isCa then e.basicConstraints = true
       else e.extKeyUsage = true ∧ e.subjectAltName.isSome = true) := by
  obtain ⟨wrapOff, wrap, listOff, list, walked, -, -, h_walk, h_complete, rfl⟩ :=
    readExtensions?_parts h
  have h_isCa := extensionsWalk_inv isCa list
    (fun acc => acc.isCa = (isCa && acc.basicConstraints))
    (by
      intro o o' acc acc' h_acc h_one
      rcases readOneExtension_cases h_one with h_same | ⟨critical, k, value, range, -, h_rec⟩
      · exact h_same ▸ h_acc
      · exact record_isCa h_rec h_acc)
    extensionCountMax 0 Extensions.empty walked (by simp [Extensions.empty]) h_walk
  cases isCa <;> simp only [Extensions.complete, Extensions.shift, Bool.and_eq_true, if_true,
    if_false, Bool.false_eq_true, Option.isSome_map] at h_complete ⊢
  · simp only [Bool.false_and] at h_isCa
    exact ⟨h_complete.1.1, h_isCa, h_complete.1.2, h_complete.2⟩
  · simp only [Bool.true_and] at h_isCa
    exact ⟨h_complete.1, h_isCa.trans h_complete.2, h_complete.2⟩

/-- The extensions record `readTbs?` returns is one `readExtensions?`
accepted inside the TBS content, ending at the content's end. -/
private theorem readTbs?_extensions {isCa : Bool} {tbs : ByteArray} {f : Tbs}
    (h : readTbs? isCa tbs = some f) :
    ∃ off, readExtensions? isCa tbs off = some (f.extensions, tbs.size) := by
  unfold readTbs? at h
  obtain ⟨o1, -, h⟩ := bind_some_elim h
  obtain ⟨o2, -, h⟩ := bind_some_elim h
  obtain ⟨⟨_, o3⟩, -, h⟩ := bind_some_elim h
  obtain ⟨sigAlg, -, h⟩ := bind_some_elim h
  obtain ⟨⟨_, o4⟩, -, h⟩ := bind_some_elim h
  obtain ⟨⟨notBefore, notAfter, o5⟩, -, h⟩ := bind_some_elim h
  obtain ⟨⟨_, o6⟩, -, h⟩ := bind_some_elim h
  obtain ⟨⟨_, o7⟩, -, h⟩ := bind_some_elim h
  obtain ⟨⟨keyAlg, key⟩, -, h⟩ := bind_some_elim h
  obtain ⟨⟨extensions, o8⟩, h_extensions, h⟩ := bind_some_elim h
  obtain ⟨_, h_end, h⟩ := bind_some_elim h
  simp only [Option.some.injEq] at h
  subst h
  have h_o8 : o8 = tbs.size := eq_of_beq (guard_some h_end)
  exact ⟨o7, h_o8 ▸ h_extensions⟩

/-- The pieces of an accepted certificate the extension facts need: the
TBS content, its range, and the record `readTbs?` returned for it. -/
private theorem parseCertificate?_extensions {isCa : Bool} {cert : ByteArray} {c : Certificate}
    (h : parseCertificate? isCa cert = some c) :
    ∃ tbs f, c.tbs.len = tbs.size ∧ readTbs? isCa tbs = some f ∧
      c.extensions = f.extensions.shift c.tbs.off := by
  unfold parseCertificate? at h
  obtain ⟨_, -, h⟩ := bind_some_elim h
  obtain ⟨⟨bodyOff, body, bodyEnd⟩, -, h⟩ := bind_some_elim h
  obtain ⟨_, -, h⟩ := bind_some_elim h
  obtain ⟨⟨tbsOff, tbs, tbsEnd⟩, -, h⟩ := bind_some_elim h
  obtain ⟨fields, h_fields, h⟩ := bind_some_elim h
  obtain ⟨o1, -, h⟩ := bind_some_elim h
  obtain ⟨⟨sigOff, sig, sigEnd⟩, -, h⟩ := bind_some_elim h
  obtain ⟨_, -, h⟩ := bind_some_elim h
  simp only [Option.some.injEq] at h
  subst h
  exact ⟨tbs, fields, rfl, h_fields, rfl⟩

/-- The subjectAltName range an accepted certificate records lies inside
its TBS content, so inside the bytes the issuer's signature covers. -/
theorem parseCertificate?_subjectAltName (isCa : Bool) (cert : ByteArray) (c : Certificate)
    (r : Range) (h : parseCertificate? isCa cert = some c)
    (h_san : c.extensions.subjectAltName = some r) :
    c.tbs.off < r.off ∧ r.off + r.len ≤ c.tbs.off + c.tbs.len := by
  obtain ⟨tbs, f, h_len, h_tbs, h_ext⟩ := parseCertificate?_extensions h
  obtain ⟨off, h_read⟩ := readTbs?_extensions h_tbs
  rw [h_ext] at h_san
  simp only [Extensions.shift, Option.map_eq_some_iff] at h_san
  obtain ⟨r0, h_r0, rfl⟩ := h_san
  have h_inside := readExtensions?_subjectAltName isCa tbs off tbs.size f.extensions r0 h_read h_r0
  simp only [Range.shift]
  omega

/-- What each arm saw, over every accepted certificate: the leaf's
keyUsage, extendedKeyUsage and subjectAltName, with cA false; an issuer's
keyUsage and basicConstraints, with cA true. -/
theorem parseCertificate?_complete (isCa : Bool) (cert : ByteArray) (c : Certificate)
    (h : parseCertificate? isCa cert = some c) :
    c.extensions.keyUsage = true ∧ c.extensions.isCa = isCa ∧
      (if isCa then c.extensions.basicConstraints = true
       else c.extensions.extKeyUsage = true ∧ c.extensions.subjectAltName.isSome = true) := by
  obtain ⟨tbs, f, -, h_tbs, h_ext⟩ := parseCertificate?_extensions h
  obtain ⟨off, h_read⟩ := readTbs?_extensions h_tbs
  have h_arm := readExtensions?_complete isCa tbs off tbs.size f.extensions h_read
  rw [h_ext]
  simpa only [Extensions.shift, Option.isSome_map] using h_arm

end Spec.WebpkiCert
