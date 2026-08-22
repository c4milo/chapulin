import Spec.Bytes
import Spec.Sha256
import Spec.Rsa
import Spec.P256
import Spec.X509Der

/-!
Profiled X.509 for the own-CA trust mode, written from X.690 (DER),
RFC 5280, and RFC 8446 §4.4.2 — never from the C sources; the
canonical-DER readers and encoders live in `Spec.X509Der`.

`parse` models the profile over the Certificate message's
CertificateEntry list: one entry (the leaf, signed directly by the
CA) or two (the leaf, then the intermediate that signed it; the
intermediate signed by the CA), each with empty per-entry extensions.
Every certificate is v3 in canonical DER under the build's one
algorithm, at most `certMax alg` bytes — that def's docstring states
the C-cap caveat. The leaf and the intermediate differ only in their
extension arm: the leaf requires keyUsage(digitalSignature) and
extendedKeyUsage(serverAuth); the intermediate requires
keyUsage(keyCertSign) and basicConstraints(CA=TRUE, pathLen 0) and
forbids extendedKeyUsage. Acceptance returns the leaf's SPKI key
bytes together with the revocation-epoch number its notBefore
carries when epoch-shaped (`readTimeEpoch` in `Spec.X509Der`); every
deviation is `none`.

`mint` and `mintChain` are the differential oracle's accept-side
builders: the driver supplies every field and the private keys, and
the C parser must accept every minted certificate.
-/

namespace Spec.X509

open Spec.Bytes

/-- Extension count bound; a walk past it is off-profile. -/
def extCountMax : Nat := 8

/-- Largest single Extension TLV (tag and length octets included). -/
def extTlvMax : Nat := 256

/-- The build's one signature algorithm; RSA fixes `e = 65537`. -/
inductive Alg
  | rsa
  | p256
deriving BEq

/-- Input cap: the largest certificate the profile admits, per
algorithm — x509.h's per-build defaults for CH_X509_MAX. The C cap is
overridable per build; the spec models the defaults. -/
def certMax : Alg → Nat
  | .p256 => 768
  | .rsa => 1536

/-- The line protocol's algorithm token. -/
def algOf? : String → Option Alg
  | "rsa" => some .rsa
  | "p256" => some .p256
  | _ => none

/-- The CA signing key the oracle mints with: RSA modulus, private
exponent and PSS salt, or a P-256 private scalar and nonce. -/
inductive CaKey
  | rsa (n d : Nat) (salt : ByteArray)
  | p256 (d k : Nat)

def CaKey.alg : CaKey → Alg
  | .rsa .. => .rsa
  | .p256 .. => .p256

/-- Hex literal for a pinned constant; a malformed literal falls back
to a 1-byte sentinel no comparison matches. -/
private def hexConst (s : String) : ByteArray :=
  (hexToBytes? s).getD (ByteArray.mk #[0])

/-- ECDSA-Sig-Value (RFC 5480 appendix A): SEQUENCE of the two
signature INTEGERs, in canonical DER. -/
def ecdsaSigDer (r s : Nat) : ByteArray :=
  tlv 0x30 (derIntNat r ++ derIntNat s)

/-! ## Pinned profile constants, assembled from their RFC structure -/

/-- version [0] EXPLICIT INTEGER 2: the one admitted v3 encoding
(RFC 5280 §4.1.2.1). -/
def versionV3 : ByteArray := tlv 0xa0 (tlv 0x02 (hexConst "02"))

/-- AlgorithmIdentifier for SHA-256 with an explicit NULL parameter,
the OpenSSL issuance encoding the profile pins (RFC 4055 §2.1 allows
absent or NULL; the profile admits exactly one). -/
def sha256AlgNull : ByteArray :=
  tlv 0x30 (tlv 0x06 (hexConst "608648016503040201") ++ hexConst "0500")

/-- The build's one signature AlgorithmIdentifier. P-256:
ecdsa-with-SHA256, parameters absent (RFC 5758 §3.2). RSA: RSASSA-PSS
with SHA-256 in both hash slots, MGF1, saltLength 32, trailerField
absent (RFC 4055 §3.1). -/
def sigAlg : Alg → ByteArray
  | .p256 => tlv 0x30 (tlv 0x06 (hexConst "2a8648ce3d040302"))
  | .rsa =>
    tlv 0x30 (tlv 0x06 (hexConst "2a864886f70d01010a") ++
      tlv 0x30 (tlv 0xa0 sha256AlgNull ++
        tlv 0xa1 (tlv 0x30 (tlv 0x06 (hexConst "2a864886f70d010108") ++ sha256AlgNull)) ++
        tlv 0xa2 (tlv 0x02 (hexConst "20"))))

/-- SubjectPublicKeyInfo AlgorithmIdentifier: rsaEncryption with its
mandatory NULL parameters (RFC 3279 §2.3.1), or id-ecPublicKey with
prime256v1 (RFC 5480 §2.1.1). -/
def spkiAlgId : Alg → ByteArray
  | .rsa => tlv 0x30 (tlv 0x06 (hexConst "2a864886f70d010101") ++ hexConst "0500")
  | .p256 => tlv 0x30 (tlv 0x06 (hexConst "2a8648ce3d0201") ++ tlv 0x06 (hexConst "2a8648ce3d030107"))

/-- publicExponent: 65537 and nothing else (the profile's fixed `e`). -/
def rsaExponent : ByteArray := hexConst "0203010001"

/-- Extension OID contents, arc 2.5.29 (RFC 5280 §4.2.1). -/
def oidKeyUsage : ByteArray := hexConst "551d0f"
def oidExtKeyUsage : ByteArray := hexConst "551d25"
def oidBasicConstraints : ByteArray := hexConst "551d13"

/-- ExtKeyUsageSyntax holding exactly id-kp-serverAuth
(RFC 5280 §4.2.1.12). -/
def ekuServerAuth : ByteArray := tlv 0x30 (tlv 0x06 (hexConst "2b06010505070301"))

/-- BasicConstraints with CA=FALSE: the DEFAULT is absent in DER, so
the content is the empty SEQUENCE (RFC 5280 §4.2.1.9, X.690 §11.5). -/
def bcNotCa : ByteArray := hexConst "3000"

/-- BasicConstraints for the intermediate: CA=TRUE with
pathLenConstraint 0 (RFC 5280 §4.2.1.9), the one admitted encoding —
the hierarchy's depth is pinned at issuance. -/
def bcCaPathlen0 : ByteArray := hexConst "30060101ff020100"

/-- keyUsage with digitalSignature only: the canonical named-bit
encoding (X.690 §11.2.2). -/
def kuDigitalSignature : ByteArray := hexConst "03020780"

/-- keyUsage with keyCertSign (bit 5) only: the canonical named-bit
encoding (X.690 §11.2.2) the chain selftest mints with. -/
def kuKeyCertSign : ByteArray := hexConst "03020204"

/-- One Extension TLV: extnID, critical when TRUE (FALSE is DEFAULT and
stays absent), extnValue OCTET STRING (RFC 5280 §4.1 Extension). -/
def extension (oid : ByteArray) (critical : Bool) (value : ByteArray) : ByteArray :=
  tlv 0x30 (tlv 0x06 oid ++ (if critical then hexConst "0101ff" else ByteArray.empty) ++
    tlv 0x04 value)

/-- The leaf profile's required extension pair:
keyUsage(digitalSignature) critical, extendedKeyUsage(serverAuth)
non-critical. -/
def profileExtensions : ByteArray :=
  extension oidKeyUsage true kuDigitalSignature ++
    extension oidExtKeyUsage false ekuServerAuth

/-- The intermediate profile's required extension pair:
keyUsage(keyCertSign) critical, basicConstraints(CA=TRUE, pathLen 0)
critical. -/
def caExtensions : ByteArray :=
  extension oidKeyUsage true kuKeyCertSign ++
    extension oidBasicConstraints true bcCaPathlen0

/-- keyUsage alone: off-profile input for the reject checks. -/
def keyUsageOnlyExtensions : ByteArray :=
  extension oidKeyUsage true kuDigitalSignature

/-- extendedKeyUsage alone: off-profile input for the reject checks. -/
def ekuOnlyExtensions : ByteArray :=
  extension oidExtKeyUsage false ekuServerAuth

/-- The leaf pair plus an extension whose extnID encodes
subidentifier 37 non-minimally (`55 1d 80 25`): off-profile input for
the X.690 §8.19.2 reject check. -/
def padOidExtensions : ByteArray :=
  profileExtensions ++ extension (hexConst "551d8025") false ekuServerAuth

/-! ## Certificate reader -/

/-- subjectPublicKeyInfo for the build's algorithm; returns the key
bytes. RSA (RFC 3279 §2.3.1): modulus content is the required 0x00 pad
plus a value of 256..384 bytes, a multiple of 8, top byte's bit set,
odd; exponent exactly 65537. P-256 (RFC 5480 §2.2): BIT STRING with 0
unused bits holding uncompressed 0x04‖X‖Y. -/
def readSpki (alg : Alg) (b : ByteArray) (off : Nat) : Option (ByteArray × Nat) := do
  let (body, off') ← readTlv b off 0x30
  let o1 ← matchAt body 0 (spkiAlgId alg)
  let (bits, o2) ← readTlv body o1 0x03
  guard (o2 == body.size)
  match alg with
  | .p256 => do
    guard (bits.size == 66)
    guard (bits[0]! == 0 ∧ bits[1]! == 0x04)
    some (bits.extract 2 66, off')
  | .rsa => do
    guard (bits.size ≠ 0 ∧ bits[0]! == 0) -- 0 unused bits
    let inner := bits.extract 1 bits.size
    let (seq, ko) ← readTlv inner 0 0x30
    guard (ko == inner.size)
    let (m, mo) ← readTlv seq 0 0x02
    guard (m.size ≥ 2 ∧ m[0]! == 0 ∧ m[1]! &&& 0x80 == 0x80)
    let value := m.extract 1 m.size
    guard (256 ≤ value.size ∧ value.size ≤ 384 ∧ value.size % 8 == 0)
    guard (value[value.size - 1]! &&& 1 == 1) -- the verifier needs an odd modulus
    let eo ← matchAt seq mo rsaExponent
    guard (eo == seq.size)
    some (value, off')

/-- One Extension (RFC 5280 §4.1): SEQUENCE { extnID, critical BOOLEAN
DEFAULT FALSE, extnValue OCTET STRING }. TRUE is exactly `01 01 ff`;
FALSE must be absent. Decoded extensions are checked exactly against
the certificate's arm — `isCa` false for the leaf, true for the
intermediate — and tracked in `seen` (1 = keyUsage,
2 = extendedKeyUsage, 4 = basicConstraints); unknown ones pass only
when non-critical. -/
def readExtension (isCa : Bool) (b : ByteArray) (off seen : Nat) : Option (Nat × Nat) := do
  let (ext, endOff) ← readTlv b off 0x30
  guard (endOff - off ≤ extTlvMax)
  let (oid, o1) ← readTlv ext 0 0x06
  guard (oid.size ≠ 0 ∧ oid.size ≤ 16)
  -- Without minimality, one extnID would have many encodings and a
  -- duplicate could pose as an unknown extension.
  guard (oidMinimal oid)
  let t ← byteAt? ext o1
  let (critical, o2) ←
    if t == 0x01 then
      if o1 + 3 ≤ ext.size ∧ ext[o1 + 1]! == 0x01 ∧ ext[o1 + 2]! == 0xff then
        some (true, o1 + 3)
      else none
    else some (false, o1)
  let (val, o3) ← readTlv ext o2 0x04
  guard (o3 == ext.size)
  if oid == oidKeyUsage then do
    -- The leaf signs handshakes; the intermediate signs certificates.
    guard (readKeyUsage val (if isCa then 0x04 else 0x80) ∧ seen &&& 1 == 0)
    some (seen ||| 1, endOff)
  else if oid == oidExtKeyUsage then do
    -- Purpose fields belong to end entities: forbidden on the
    -- intermediate, exactly serverAuth on the leaf.
    guard (!isCa ∧ val == ekuServerAuth ∧ seen &&& 2 == 0)
    some (seen ||| 2, endOff)
  else if oid == oidBasicConstraints then do
    guard (val == (if isCa then bcCaPathlen0 else bcNotCa) ∧ seen &&& 4 == 0)
    some (seen ||| 4, endOff)
  else if critical then
    none -- RFC 5280 §4.2: an unrecognized critical extension is rejected
  else
    some (seen, endOff) -- unknown non-critical: skipped, contents unread

/-- The extension walk: at most `fuel` extensions consuming `b`
exactly; returns the seen mask. -/
def extensionWalk (isCa : Bool) (b : ByteArray) : Nat → Nat → Nat → Option Nat
  | 0, off, seen => if off == b.size then some seen else none
  | fuel + 1, off, seen =>
    if off == b.size then some seen
    else do
      let (seen', off') ← readExtension isCa b off seen
      extensionWalk isCa b fuel off' seen'

/-- TBSCertificate body, first byte to last, exact-consume
(RFC 5280 §4.1). issuer and subject are opaque bounded TLVs — no name
matching by design — and validity holds exactly two Times. `isCa`
picks the extension arm. Returns the SPKI key bytes; for the leaf the
notBefore doubles as the revocation epoch, so its number
travels out too — the intermediate's digits go unread. -/
def readTbs (alg : Alg) (isCa : Bool) (tbs : ByteArray) : Option (ByteArray × Option Nat) := do
  let o1 ← matchAt tbs 0 versionV3
  let o2 ← readSerial tbs o1
  let o3 ← matchAt tbs o2 (sigAlg alg)
  let (_, o4) ← readTlv tbs o3 0x30 -- issuer, bound by the CA signature
  let (validity, o5) ← readTlv tbs o4 0x30
  let (v1, epoch) ←
    if isCa then do
      let v1 ← readTime validity 0
      some (v1, (none : Option Nat))
    else readTimeEpoch validity 0
  let v2 ← readTime validity v1
  guard (v2 == validity.size)
  let (_, o6) ← readTlv tbs o5 0x30 -- subject
  let (key, o7) ← readSpki alg tbs o6
  let (wrap, o8) ← readTlv tbs o7 0xa3 -- extensions [3], required
  guard (o8 == tbs.size) -- trailing TBS fields are off-profile
  let (exts, eo) ← readTlv wrap 0 0x30
  guard (eo == wrap.size ∧ exts.size ≠ 0) -- Extensions is SIZE (1..MAX)
  let seen ← extensionWalk isCa exts extCountMax 0 0
  -- The purpose binding is mandatory: keyUsage + extendedKeyUsage on
  -- the leaf, keyUsage + basicConstraints on the intermediate.
  guard (if isCa then seen &&& 1 == 1 ∧ seen &&& 4 == 4 else seen &&& 1 == 1 ∧ seen &&& 2 == 2)
  some (key, epoch)

/-- The CA signature over the exact TBSCertificate bytes: RSASSA-PSS
(RFC 8017 §8.1.2, e = 65537) against the modulus bytes, or ECDSA
(SEC 1 v2 §4.1.4) against the X‖Y point after canonical
ECDSA-Sig-Value decoding. -/
def checkSignature (alg : Alg) (caKey hash sig : ByteArray) : Bool :=
  match alg with
  | .rsa => Spec.Rsa.pssVerify (bytesToNatBE caKey) 65537 hash sig
  | .p256 =>
    if caKey.size ≠ 64 then false
    else
      match ecdsaSigParse sig with
      | none => false
      | some (r, s) => Spec.P256.ecdsaVerify caKey hash r s
where
  /-- ECDSA-Sig-Value: SEQUENCE of two `readDerInt` INTEGERs, exact-fill. -/
  ecdsaSigParse (sig : ByteArray) : Option (Nat × Nat) := do
    let (body, endOff) ← readTlv sig 0 0x30
    guard (endOff == sig.size)
    let (r, o1) ← readDerInt body 0
    let (s, o2) ← readDerInt body o1
    guard (o2 == body.size)
    some (r, s)

/-- Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm,
signatureValue } (RFC 5280 §4.1), exact-fill at every level. The outer
algorithm must byte-equal the pinned constant and the signature BIT
STRING carries 0 unused bits. Returns `readTbs`'s key-and-epoch pair,
the SHA-256 of the TBS bytes with their own header, and the
signature — the chain step picks whose key must verify them. -/
def readCertificate (alg : Alg) (isCa : Bool) (cert : ByteArray) :
    Option ((ByteArray × Option Nat) × ByteArray × ByteArray) := do
  let (body, o0) ← readTlv cert 0 0x30
  guard (o0 == cert.size)
  let (tbs, tbsEnd) ← readTlv body 0 0x30
  let keyEpoch ← readTbs alg isCa tbs
  let o1 ← matchAt body tbsEnd (sigAlg alg)
  let (sig, o2) ← readTlv body o1 0x03
  guard (o2 == body.size)
  guard (sig.size ≥ 2 ∧ sig[0]! == 0) -- signature bits fill whole bytes
  some (keyEpoch, Spec.Sha256.sha256 (slice body 0 tbsEnd), sig.extract 1 sig.size)

/-- One CertificateEntry at `off` (RFC 8446 §4.4.2): u24 length,
cert_data — at most the algorithm's `certMax` — empty (u16 0)
per-entry extensions. Returns the certificate bytes and the offset
just past the entry. -/
def entryAt? (alg : Alg) (list : ByteArray) (off : Nat) : Option (ByteArray × Nat) := do
  let b0 ← byteAt? list off
  let b1 ← byteAt? list (off + 1)
  let b2 ← byteAt? list (off + 2)
  let certLen := b0.toNat * 65536 + b1.toNat * 256 + b2.toNat
  guard (certLen ≠ 0 ∧ certLen ≤ certMax alg)
  guard (off + 3 + certLen + 2 ≤ list.size)
  guard (list[off + 3 + certLen]! == 0 ∧ list[off + 3 + certLen + 1]! == 0)
  some (slice list (off + 3) certLen, off + 3 + certLen + 2)

/-- The Certificate message's CertificateEntry list (RFC 8446 §4.4.2):
one entry (the leaf, verified directly under the CA key) or two (the
leaf, then the intermediate — the intermediate verified under the CA
key and the leaf under the intermediate's SPKI), and nothing after
them: the root never travels. `some` carries the leaf's SPKI key
bytes paired with its notBefore's revocation-epoch number —
`none` in the pair when the notBefore is a valid Time off the
range; every off-profile or non-canonical input is `none`. -/
def parse (alg : Alg) (caKey list : ByteArray) : Option (ByteArray × Option Nat) := do
  let (leafCert, o1) ← entryAt? alg list 0
  let (leafKeyEpoch, leafHash, leafSig) ← readCertificate alg false leafCert
  if o1 == list.size then do
    guard (checkSignature alg caKey leafHash leafSig)
    some leafKeyEpoch
  else do
    let (intCert, o2) ← entryAt? alg list o1
    guard (o2 == list.size) -- a third entry is off-profile
    let ((intKey, _), intHash, intSig) ← readCertificate alg true intCert
    guard (checkSignature alg caKey intHash intSig)
    guard (checkSignature alg intKey leafHash leafSig)
    some leafKeyEpoch

/-! ## Minting -/

/-- SubjectPublicKeyInfo for the minted leaf: `leafKey` is the RSA
modulus value (top bit set) or the P-256 X‖Y point. -/
def mintSpki : Alg → ByteArray → Option ByteArray
  | .p256, key =>
    if key.size == 64 then
      some (tlv 0x30 (spkiAlgId .p256 ++ tlv 0x03 (hexConst "0004" ++ key)))
    else none
  | .rsa, m =>
    if m.size ≠ 0 ∧ m[0]! &&& 0x80 == 0x80 then
      some (tlv 0x30 (spkiAlgId .rsa ++
        tlv 0x03 (ByteArray.mk #[0] ++ tlv 0x30 (tlv 0x02 (ByteArray.mk #[0] ++ m) ++ rsaExponent))))
    else none

/-- The CA signature over the TBS digest, as the signature BIT
STRING's whole-byte content. -/
def mintSignature : CaKey → ByteArray → Option ByteArray
  | .rsa n d salt, hash => Spec.Rsa.pssSign n d hash salt
  | .p256 d k, hash => do
    let (r, s) ← Spec.P256.ecdsaSign d k (bytesToNatBE hash)
    some (ecdsaSigDer r s)

/-- One signed certificate around a caller-encoded serial TLV:
`subjectKey` becomes the SPKI and `signer` signs the TBS bytes. -/
def mintCert (signer : CaKey) (serialTlv issuer validity subject subjectKey exts : ByteArray) :
    Option ByteArray := do
  let alg := signer.alg
  let spki ← mintSpki alg subjectKey
  let tbs := tlv 0x30 (versionV3 ++ serialTlv ++ sigAlg alg ++ tlv 0x30 issuer ++
    tlv 0x30 validity ++ tlv 0x30 subject ++ spki ++ tlv 0xa3 (tlv 0x30 exts))
  let sig ← mintSignature signer (Spec.Sha256.sha256 tbs)
  let cert := tlv 0x30 (tbs ++ sigAlg alg ++ tlv 0x03 (ByteArray.mk #[0] ++ sig))
  guard (cert.size ≤ 0xffff) -- encodeLen's domain
  some cert

/-- One CertificateEntry: u24 length, the certificate, empty (u16 0)
per-entry extensions (RFC 8446 §4.4.2). -/
def entryBytes (cert : ByteArray) : ByteArray :=
  natToBytesBE cert.size 3 ++ cert ++ natToBytesBE 0 2

/-- Builds a CA-signed leaf around a caller-encoded serial TLV; the
selftest uses this to mint a genuinely signed certificate whose only
flaw is a non-minimal length. `mint` is the public entry. -/
def mintCore (ca : CaKey) (serialTlv issuer validity subject leafKey exts : ByteArray) :
    Option ByteArray := do
  let cert ← mintCert ca serialTlv issuer validity subject leafKey exts
  some (entryBytes cert)

/-- Canonical CA-signed leaf as a one-entry CertificateEntry list. The
driver supplies every field: serial value bytes, issuer/validity/
subject SEQUENCE contents, the leaf key, and the Extensions content. -/
def mint (ca : CaKey) (serial issuer validity subject leafKey exts : ByteArray) :
    Option ByteArray :=
  mintCore ca (tlv 0x02 serial) issuer validity subject leafKey exts

/-- The signer's own public key: the RSA modulus value bytes, or the
P-256 X‖Y point. -/
def CaKey.pub? : CaKey → Option ByteArray
  | .rsa n _ _ => some (natBytesMin n)
  | .p256 d _ => Spec.P256.pubKey? d

/-- Canonical chained pair as a two-entry CertificateEntry list: the
leaf signed by `int` under the leaf extension arm's fields, then the
intermediate — its SPKI is `int`'s own public key — signed by `ca`
around `intExts`. Both certificates share the driver-supplied serial,
issuer, validity, and subject fields. The C parser must accept every
minted chain whose extensions are on-profile. -/
def mintChain (ca int : CaKey) (serial issuer validity subject leafKey leafExts intExts :
    ByteArray) : Option ByteArray := do
  guard (ca.alg == int.alg)
  let intPub ← int.pub?
  let leafCert ← mintCert int (tlv 0x02 serial) issuer validity subject leafKey leafExts
  let intCert ← mintCert ca (tlv 0x02 serial) issuer validity subject intPub intExts
  some (entryBytes leafCert ++ entryBytes intCert)

/-- Structural checks: a minted certificate parses back to the minted
key — and the epoch number of its epoch-shaped notBefore
(`250101000000Z` is number 8400) — under both algorithms; the last
allowed date (`491228000000Z`, 16799) extracts and the first day past
the end (`491229000000Z`) parses with no epoch; a genuinely
signed variant whose serial
length is long-form fails on canonicality alone; the keyUsage-only
variant fails on the missing EKU and the EKU-only variant on the
missing keyUsage; the non-minimal-extnID variant fails on X.690
§8.19.2 alone; a wrong CA key and a trailing byte fail. A minted chain parses back to the leaf key; the same chain
fails under a wrong CA key, and a chain whose intermediate carries
the leaf's extension arm fails on the profile. -/
def selftest : Bool :=
  let serial := hexConst "2a"
  let name := hexConst "310c300a06035504030c03636861"
  let validity := tlv 0x17 (ascii "250101000000Z") ++ tlv 0x18 (ascii "20350101000000Z")
  -- P-256 arm: the RFC 6979 §A.2.5 key as the CA, a second scalar's
  -- point as the leaf key, a third scalar as the chain's intermediate.
  let caD := 0xc9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721
  let caK := 0xa6e3c57dd01abe90086538398355dd4c3b17aa873382b0f24d6129493d8aad60
  let leafD := 0x1b8e05f5ee0f8b25101f13b6dc3d514cbbbf6bc7e2b1c9f2f6a2e15c7a3d4e51
  let intD := 0x2e9f0c2b1d4a68355c7e01f2a9b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5
  let intK := 0x619b8f0a7c2d3e4f5061728394a5b6c7d8e9fa0b1c2d3e4f506172839405161b
  (match Spec.P256.pubKey? caD, Spec.P256.pubKey? leafD with
   | some caPub, some leafPub =>
     let ca := CaKey.p256 caD caK
     let int := CaKey.p256 intD intK
     (match mint ca serial name validity name leafPub profileExtensions with
      | some l =>
        parse .p256 caPub l == some (leafPub, some 8400) &&
          (parse .p256 leafPub l).isNone && -- wrong CA
          (parse .p256 caPub (l ++ ByteArray.mk #[0])).isNone -- trailing byte
      | none => false) &&
       -- Epoch boundary: the last allowed date extracts; the first
       -- day past the end is shape-valid but carries no epoch.
       (let vLast := tlv 0x17 (ascii "491228000000Z") ++ tlv 0x18 (ascii "20350101000000Z")
        match mint ca serial name vLast name leafPub profileExtensions with
        | some l => parse .p256 caPub l == some (leafPub, some 16799)
        | none => false) &&
       (let vOff := tlv 0x17 (ascii "491229000000Z") ++ tlv 0x18 (ascii "20350101000000Z")
        match mint ca serial name vOff name leafPub profileExtensions with
        | some l => parse .p256 caPub l == some (leafPub, none)
        | none => false) &&
       -- long-form serial length `02 81 01`: signature genuine, DER not
       (match mintCore ca (hexConst "02810101") name validity name leafPub profileExtensions with
        | some l => (parse .p256 caPub l).isNone
        | none => false) &&
       (match mint ca serial name validity name leafPub keyUsageOnlyExtensions with
        | some l => (parse .p256 caPub l).isNone
        | none => false) &&
       (match mint ca serial name validity name leafPub ekuOnlyExtensions with
        | some l => (parse .p256 caPub l).isNone
        | none => false) &&
       (match mint ca serial name validity name leafPub padOidExtensions with
        | some l => (parse .p256 caPub l).isNone
        | none => false) &&
       -- The chained pair: leaf under the intermediate, intermediate under
       -- the CA; a wrong CA key and a leaf-profile intermediate both fail.
       (match mintChain ca int serial name validity name leafPub profileExtensions
           caExtensions with
        | some l =>
          parse .p256 caPub l == some (leafPub, some 8400) &&
            (parse .p256 leafPub l).isNone && -- wrong CA on the chain head
            (parse .p256 caPub (l ++ ByteArray.mk #[0])).isNone -- trailing byte
        | none => false) &&
       (match mintChain ca int serial name validity name leafPub profileExtensions
           profileExtensions with
        | some l => (parse .p256 caPub l).isNone -- intermediate off its arm
        | none => false)
   | _, _ => false) &&
  -- RSA arm: the module's 2048-bit test key as the CA; the leaf
  -- modulus only has to satisfy the profile's shape checks.
  (let n := 0xa59931eebcc909b93406f4c6999c3b86e086bea972203cb921e806c42c0d73b87b9db6647e15753e232c1f8b8fdfac6210e9866b5eec09ffd62eacfc16b67bcd736d90dae48435130a247e054a4bf821b1c0ccd673ec3240f8686b46e22689c0ab86fd2329a8e10a0fcea94df123459a3ae4d2de6aad52b850c2955e38155be708e9f6dafdc9934e661503bc69463f962aa1f0dabb8427ce065a0f2e6e2bf7650ba0e9c4532d03fb50e5c45447090f00b1e99dd44ba351fb3c78dc2cbf7860e3285789f39a758eb8c314c493d5baf351ba82c3381e4c940574b37f891e63ed5daae377df24ab67d717d5621aa7dc87046359d5b61910ad63d01e56d9bec95a7b
   let d := 0x2bd7f91bebd8d05dbc1421679990ff43b11b8bcc621e7de548405dd63f919a335c6b3fb8b0972ed0f25002d419160fd67102db277f5cc032ffbaa0eb277a4e21f1af2f1c7d4731a42659ce11c97f7ea531224a39773cb07b7a296f49b7a39b722b17d4daa3f3860d7b6cec6f69ea3c49ded0e9b1a08dde2a559b871f887ac337653e73889f8e67b4792ef87e7d53270abcb193e68d576ed631b3756b5f9468c27b006fe67380f3078143774a0567cf1160581bb562768f1e1e1c5371d62ee56d6df2e444f8f516acc5b3330a49d66b6081fc1f1d77ffa212223123208e5a773ece826038c46a425d04787317ff2cb895b4b6710234434263f83f9aa2764c3071
   let salt := hexConst "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
   let leafMod := natToBytesBE (2 ^ 2047 + 987654321) 256
   match mint (.rsa n d salt) serial name validity name leafMod profileExtensions with
   | some l =>
     parse .rsa (natBytesMin n) l == some (leafMod, some 8400) &&
       (parse .rsa (natBytesMin n) (l.extract 0 (l.size - 1))).isNone -- truncation
   | none => false)

end Spec.X509
