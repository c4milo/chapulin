import Spec.WebpkiCert
import Spec.WebpkiName

/-!
The chain walk of the `TRUST=webpki` trust mode (`webpki.c`), written
from docs/webpki.md's "The chain walk", "Validity", "Hostnames" and
"Trust anchors" over the certificate model of `Spec.WebpkiCert`, the
hostname matcher of `Spec.WebpkiName` and the signature verifier of
`Spec.WebpkiSigalg`.

`verifyChain` takes a configuration — the anchors, the reference
hostname and the clock as a packed date — and one RFC 9846 §4.5.1
CertificateEntry list, and answers one of five verdicts. An accepted
chain reports the leaf's key and the path it verified: how many entries
it read, leaf first, and the index of the anchor that verified the last
of them, which is where the SPKI pins of `Spec.WebpkiPin` may match. The
four refusals are exactly the four the C's return code and alert tell
apart, so the differential compares them:

* `rejected` is the C's `CH_EPROTO`: the list framing, a certificate the
  profile refuses, an issuer whose subject is not this certificate's
  issuer, and a pathLenConstraint the CA certificates under it exceed,
  where a self-issued certificate does not count (RFC 5280 §6.1.4 (l));
* `expired` is `CH_EAUTH` with `certificate_expired`;
* `unauthenticated` is `CH_EAUTH` with `bad_certificate`: no dNSName
  matches the hostname, or a signature fails under its issuer;
* `unknownCa` is `CH_EAUTH` with `unknown_ca`: the entries ran out, or
  `chainMax` certificates were read, before an anchor verified.

The order is the C's, and it is what the verdicts mean: the leaf's
profile, then its validity, then the hostname, then the walk, which
consults the anchors before it reads each next entry and stops at the
first anchor that both names the issuer and verifies the signature.

What the model leaves out: the alert itself, which
test/webpki_chain_test.c pins, and the entry bytes after the
terminating certificate, which the walk never reads and this model never
parses either.
-/

namespace Spec.Webpki

open Spec.Bytes Spec.X509 Spec.WebpkiSpki Spec.WebpkiSigalg Spec.WebpkiCert

/-- `CH_WEBPKI_CHAIN_MAX`: the certificates the walk reads and verifies. -/
def chainMax : Nat := 3

/-- `CH_WEBPKI_FLIGHT_ENTRIES`: the entries one Certificate message may
carry. -/
def flightEntries : Nat := 4

/-- One trust anchor: a root's subject Name as its whole DER `Name` TLV
and its public key as its whole DER `SubjectPublicKeyInfo`. Nothing else
of the root is read, not even its dates. -/
structure Anchor where
  /-- The subject Name TLV, compared byte for byte against an issuer Name. -/
  name : ByteArray
  /-- The SubjectPublicKeyInfo, read by `Spec.WebpkiSpki.readSpki?`. -/
  spki : ByteArray

/-- What the caller configures: the anchors, the reference hostname, and
the clock as the packed date `Spec.WebpkiTime` produces. -/
structure Config where
  /-- The anchors, tried in order at every depth. -/
  anchors : List Anchor
  /-- The hostname a leaf's subjectAltName must name. -/
  hostname : List UInt8
  /-- The clock, packed as `YYYYMMDDHHMMSS`. -/
  now : Nat

/-- The walk's answer. -/
inductive Verdict where
  /-- The chain verified: the leaf's key algorithm and key, the count of
  entries on the path, and the index of the anchor that ended it. -/
  | ok (alg : KeyAlg) (key : ByteArray) (path anchor : Nat)
  /-- `CH_EPROTO`: the framing or the profile. -/
  | rejected
  /-- The clock lies outside a validity. -/
  | expired
  /-- The hostname does not match, or a signature fails under its issuer. -/
  | unauthenticated
  /-- No anchor verified before the entries or `chainMax` ran out. -/
  | unknownCa

/-- The name the differential compares. -/
def Verdict.name : Verdict → String
  | .ok _ _ _ _ => "ok"
  | .rejected => "rejected"
  | .expired => "expired"
  | .unauthenticated => "unauthenticated"
  | .unknownCa => "unknown_ca"

/-- What the walk from one certificate reaches. `reached` is an anchor
that verified; the other four are `Verdict`'s refusals. -/
inductive Step where
  /-- An anchor named the issuer and verified the signature: the count of
  certificates read, and that anchor's index. -/
  | reached (path anchor : Nat)
  /-- `CH_EPROTO`. -/
  | rejected
  /-- The clock lies outside an issuer's validity. -/
  | expired
  /-- A signature fails under its issuer. -/
  | unauthenticated
  /-- The entries or `chainMax` ran out. -/
  | unknownCa
  deriving DecidableEq, Repr

/-- One `CertificateEntry`: a u24 certificate length, the certificate,
and a u16 extensions vector this mode requires to be empty. Reads at
most `fuel - 1` entries, so a list with more refuses. -/
def entriesFrom : Nat → ByteArray → Nat → List ByteArray → Option (List ByteArray)
  | 0, _, _, _ => none
  | fuel + 1, b, off, acc =>
    if off == b.size then (if acc.isEmpty then none else some acc.reverse)
    else if b.size < off + 3 then none
    else
      let len := 65536 * b[off]!.toNat + 256 * b[off + 1]!.toNat + b[off + 2]!.toNat
      if len == 0 || certificateMax < len || b.size < off + 5 + len then none
      else if b[off + 3 + len]! != 0 || b[off + 4 + len]! != 0 then none
      else entriesFrom fuel b (off + 5 + len) (slice b (off + 3) len :: acc)

/-- The CertificateEntry list: 1 to `flightEntries` entries of at most
`certificateMax` bytes each, filling the list exactly. -/
def readEntries? (list : ByteArray) : Option (List ByteArray) :=
  entriesFrom (flightEntries + 1) list 0 []

/-- `notBefore ≤ now ≤ notAfter`, both ends inclusive (RFC 5280
§4.1.2.5). -/
def validityCovers (c : Certificate) (now : Nat) : Bool :=
  decide (c.notBefore ≤ now) && decide (now ≤ c.notAfter)

/-- RFC 5280 §4.2.1.9 and §6.1.4 (l): `below` is the number of CA
certificates between an issuer and the leaf that are not self-issued,
which its pathLenConstraint bounds; an absent constraint admits any
number. -/
def pathLenAdmits (issuer : Certificate) (below : Nat) : Bool :=
  match issuer.extensions.pathLen with
  | none => true
  | some p => below ≤ p

/-- The issuer Name TLV of a parsed certificate. -/
def issuerName (cert : ByteArray) (c : Certificate) : ByteArray :=
  slice cert c.issuer.off c.issuer.len

/-- The subject Name TLV of a parsed certificate. -/
def subjectName (cert : ByteArray) (c : Certificate) : ByteArray :=
  slice cert c.subject.off c.subject.len

/-- RFC 5280 §6.1: a certificate is self-issued when its subject Name
equals its issuer Name, which is what a CA re-keying under its own Name
issues for the new key. -/
def selfIssued (cert : ByteArray) (c : Certificate) : Bool :=
  subjectName cert c == issuerName cert c

/-- `cert`'s signature under a key: the TBSCertificate content the
verifier re-emits the header for, and the signature BIT STRING's bytes. -/
def verifyUnder (cert : ByteArray) (c : Certificate) (alg : KeyAlg) (key : ByteArray) : Bool :=
  Spec.WebpkiSigalg.verify c.sigAlg alg key (slice cert c.tbs.off c.tbs.len)
    (slice cert c.signature.off c.signature.len)

/-- Step 6a for one anchor: its subject Name equals `cert`'s issuer Name
and its key verifies `cert`'s signature. An anchor whose
SubjectPublicKeyInfo the reader refuses verifies nothing. -/
def anchorVerifies (cert : ByteArray) (c : Certificate) (a : Anchor) : Bool :=
  a.name == issuerName cert c &&
    (match readSpki? a.spki with
     | none => false
     | some (alg, key) => verifyUnder cert c alg key)

/-- Step 6a: the index of the first anchor that verifies `cert`, trying
every anchor in order, so a root re-keyed under one Name works. -/
def anchorIndex? (cfg : Config) (cert : ByteArray) (c : Certificate) : Option Nat :=
  cfg.anchors.findIdx? (anchorVerifies cert c)

/-- Steps 6a to 6g from the certificate in hand, which `read`
certificates into the chain with `below` of the issuers among them not
self-issued. The anchors come first at every depth, so a chain that
reaches one leaves the entries after it unread. -/
def walkFrom (cfg : Config) (cert : ByteArray) (c : Certificate) (rest : List ByteArray)
    (read below : Nat) : Step :=
  match anchorIndex? cfg cert c with
  | some anchor => .reached read anchor
  | none =>
    if read == chainMax then .unknownCa
    else
      match rest with
      | [] => .unknownCa
      | next :: more =>
        match parseCertificate? true next with
        | none => .rejected
        | some issuer =>
          if !validityCovers issuer cfg.now then .expired
          else if subjectName next issuer != issuerName cert c then .rejected
          else if !pathLenAdmits issuer below then .rejected
          else if !verifyUnder cert c issuer.keyAlg issuer.key then .unauthenticated
          else walkFrom cfg next issuer more (read + 1)
            (if selfIssued next issuer then below else below + 1)

/-- Step 5: a dNSName of the leaf's subjectAltName matches the reference
hostname. A leaf with no subjectAltName matches nothing, and the leaf arm
of `parseCertificate?` already refuses one. -/
def hostMatches (leafBytes : ByteArray) (leaf : Certificate) (host : List UInt8) : Bool :=
  match leaf.extensions.subjectAltName with
  | none => false
  | some r => Spec.WebpkiName.matchSan (slice leafBytes r.off r.len) host

/-- The whole walk over one CertificateEntry list. -/
def verifyChain (cfg : Config) (list : ByteArray) : Verdict :=
  match readEntries? list with
  | none => .rejected
  | some [] => .rejected
  | some (leafBytes :: rest) =>
    match parseCertificate? false leafBytes with
    | none => .rejected
    | some leaf =>
      if !validityCovers leaf cfg.now then .expired
      else if !hostMatches leafBytes leaf cfg.hostname then .unauthenticated
      else
        match walkFrom cfg leafBytes leaf rest 1 0 with
        | .reached path anchor => .ok leaf.keyAlg leaf.key path anchor
        | .rejected => .rejected
        | .expired => .expired
        | .unauthenticated => .unauthenticated
        | .unknownCa => .unknownCa

/-- Hex for a selftest constant; a malformed literal becomes one byte no
reader accepts. -/
private def hex (s : String) : ByteArray := (hexToBytes? s).getD (ByteArray.mk #[0])

/-- The corpus P-384 root's subject Name TLV
(test/webpki_corpus.h, `webpki_corpus_name_root_p384`). -/
def rootP384Name : ByteArray := hex
  ("303a310b3009060355040613025553310f300d060355040a0c06436f72707573311a301806035504030c11436f" ++
   "7270757320502d33383420526f6f74")

/-- The same root's SubjectPublicKeyInfo. -/
def rootP384Spki : ByteArray := hex
  ("3076301006072a8648ce3d020106052b8104002203620004f46519a97e1933bb9895601ab933026b2da86345c9" ++
   "ab9d4ceb1799154c3cd9f6d388d5939f4115ea57a498b4197916df6c8d12308b76b046d963b5b7d717153e6de0" ++
   "29f1ab15a119d1ffede111bf0cb4f74810f4e54830ffa72bc999e14f69db")

/-- The corpus `anchor_key_mismatch` anchor: the root's Name over another
P-384 key. -/
def impostorP384Spki : ByteArray := hex
  ("3076301006072a8648ce3d020106052b81040022036200045c8984a17b7c704e3f953bcb5d6c826dee8f5712b1" ++
   "87d98fe406fc13bb73cbe8b2ce7fb98033c5d3de5b067143cfcc494ff00e12e6bfb9f6960e6837e89bfb624b2e" ++
   "a757026c5293201ec34d498febd8d0eb2dd187e1d932f8c5db16355590ff")

/-- One CertificateEntry around a certificate. -/
def entry (cert : ByteArray) : ByteArray :=
  natToBytesBE cert.size 3 ++ cert ++ ByteArray.mk #[0, 0]

/-- The corpus `r2` message's CertificateEntry list: the P-256 leaf and
its P-256 intermediate, under the P-384 root. -/
def r2List : ByteArray := entry r2Leaf ++ entry r2Issuer

/-- `s3.example.test`, the hostname every minted corpus leaf names. -/
def corpusHost : List UInt8 := "s3.example.test".toUTF8.toList

/-- The corpus `r2` configuration at a clock inside both validities. -/
def r2Config : Config :=
  { anchors := [⟨rootP384Name, rootP384Spki⟩], hostname := corpusHost, now := 20260701000000 }

/-- The corpus r2 chain accepted over a path of two entries ending at
anchor 0, and at anchor 1 behind the impostor anchor, which names the
issuer and verifies nothing; and one refusal per rule: the clock one
second past the leaf's notAfter and one before its notBefore, a hostname
no dNSName names, an anchor whose Name matches over another key, no
anchor at all, a fifth entry, and an empty list. -/
def selftest : Bool :=
  let ok := verifyChain r2Config r2List
  let leafKey := match parseCertificate? false r2Leaf with
    | some c => c.key
    | none => ByteArray.empty
  let clock := fun (n : Nat) => verifyChain { r2Config with now := n } r2List
  let host := fun (h : String) =>
    verifyChain { r2Config with hostname := h.toUTF8.toList } r2List
  let anchors := fun (a : List Anchor) => verifyChain { r2Config with anchors := a } r2List
  let five := r2List ++ entry r2Leaf ++ entry r2Leaf ++ entry r2Leaf
  let rekeyed := anchors [⟨rootP384Name, impostorP384Spki⟩, ⟨rootP384Name, rootP384Spki⟩]
  (match ok with
   | .ok alg key path anchor => alg == .p256 && key == leafKey && key.size == 64 && path == 2 &&
       anchor == 0
   | _ => false) &&
    (match rekeyed with
     | .ok _ _ path anchor => path == 2 && anchor == 1
     | _ => false) &&
    ok.name == "ok" &&
    (clock 20261231235959).name == "ok" &&
    (clock 20270101000000).name == "expired" &&
    (clock 20260101000000).name == "ok" &&
    (clock 20251231235959).name == "expired" &&
    (host "other.example.test").name == "unauthenticated" &&
    (anchors [⟨rootP384Name, impostorP384Spki⟩]).name == "unknown_ca" &&
    (anchors []).name == "unknown_ca" &&
    (verifyChain r2Config five).name == "rejected" &&
    (verifyChain r2Config ByteArray.empty).name == "rejected" &&
    (verifyChain r2Config (entry r2Issuer)).name == "rejected"

/-- A verified signature path from the certificate in hand to an anchor,
of `path` certificates counted from the one `read` numbers, ending at the
anchor with index `anchor`: either that anchor is the first to name this
certificate's issuer and verify its signature, or the next entry is an
issuer this mode admits, valid at the clock, named by this certificate,
whose pathLenConstraint admits the `below` CA certificates under it, whose
key verifies this certificate, and which itself heads such a path,
counted below it unless it is self-issued. -/
inductive HasPath (cfg : Config) :
    ByteArray → Certificate → List ByteArray → Nat → Nat → Nat → Nat → Prop where
  /-- Step 6a: an anchor ends the path. -/
  | anchor {cert : ByteArray} {c : Certificate} {rest : List ByteArray} {read below anchor : Nat}
      (h : anchorIndex? cfg cert c = some anchor) : HasPath cfg cert c rest read below read anchor
  /-- Steps 6c to 6g: the next entry is the issuer, and the path goes on. -/
  | issuer {cert : ByteArray} {c : Certificate} {read below path anchor : Nat} (next : ByteArray)
      (more : List ByteArray) (ic : Certificate)
      (h_parse : parseCertificate? true next = some ic)
      (h_valid : validityCovers ic cfg.now = true)
      (h_name : (subjectName next ic == issuerName cert c) = true)
      (h_path : pathLenAdmits ic below = true)
      (h_sig : verifyUnder cert c ic.keyAlg ic.key = true)
      (h_more : HasPath cfg next ic more (read + 1)
        (if selfIssued next ic then below else below + 1) path anchor) :
      HasPath cfg cert c (next :: more) read below path anchor

/-- The index an anchor search returns names an anchor that verifies
`cert`, and no anchor before it does. -/
theorem anchorIndex?_verifies (cfg : Config) (cert : ByteArray) (c : Certificate) (anchor : Nat)
    (h : anchorIndex? cfg cert c = some anchor) :
    ∃ h_lt : anchor < cfg.anchors.length, anchorVerifies cert c cfg.anchors[anchor] = true ∧
      ∀ j (h_before : j < anchor), anchorVerifies cert c cfg.anchors[j] = false := by
  obtain ⟨h_lt, h_fits, h_first⟩ := List.findIdx?_eq_some_iff_getElem.mp h
  exact ⟨h_lt, h_fits, fun j h_before => by simpa using h_first j h_before⟩

/-- A walk that reaches an anchor has a verified signature path to it, of
the length and at the anchor the walk reports. -/
theorem walkFrom_reached (cfg : Config) (rest : List ByteArray) :
    ∀ (cert : ByteArray) (c : Certificate) (read below path anchor : Nat),
      walkFrom cfg cert c rest read below = .reached path anchor →
        HasPath cfg cert c rest read below path anchor := by
  induction rest with
  | nil =>
    intro cert c read below path anchor h
    rw [walkFrom] at h
    split at h
    · rename_i found h_anchor
      simp only [Step.reached.injEq] at h
      obtain ⟨rfl, rfl⟩ := h
      exact .anchor h_anchor
    · split at h <;> simp at h
  | cons next more ih =>
    intro cert c read below path anchor h
    rw [walkFrom] at h
    split at h
    · rename_i found h_anchor
      simp only [Step.reached.injEq] at h
      obtain ⟨rfl, rfl⟩ := h
      exact .anchor h_anchor
    split at h
    · simp at h
    split at h
    · simp at h
    rename_i ic h_parse
    split at h
    · simp at h
    rename_i h_valid
    split at h
    · simp at h
    rename_i h_name
    split at h
    · simp at h
    rename_i h_path
    split at h
    · simp at h
    rename_i h_sig
    refine .issuer next more ic h_parse ?_ ?_ ?_ ?_ (ih next ic (read + 1) _ path anchor h)
    · simpa using h_valid
    · simpa [bne] using h_name
    · simpa using h_path
    · simpa using h_sig

/-- Soundness: an accepted chain is the leaf of a CertificateEntry list
the framing admits, parsed under the leaf arm, valid at the clock,
matched by its own subjectAltName against `cfg.hostname`, and the head of
a verified signature path of `path` certificates to the anchor at index
`anchor`; and the key the verdict carries is that leaf's own. -/
theorem verifyChain_ok (cfg : Config) (list : ByteArray) (alg : KeyAlg) (key : ByteArray)
    (path anchor : Nat) (h : verifyChain cfg list = .ok alg key path anchor) :
    ∃ leafBytes rest leaf,
      readEntries? list = some (leafBytes :: rest) ∧
        parseCertificate? false leafBytes = some leaf ∧
        leaf.keyAlg = alg ∧ leaf.key = key ∧
        validityCovers leaf cfg.now = true ∧
        hostMatches leafBytes leaf cfg.hostname = true ∧
        HasPath cfg leafBytes leaf rest 1 0 path anchor := by
  unfold verifyChain at h
  split at h
  · simp at h
  · simp at h
  rename_i leafBytes rest h_entries
  split at h
  · simp at h
  rename_i leaf h_leaf
  split at h
  · simp at h
  rename_i h_valid
  split at h
  · simp at h
  rename_i h_matched
  split at h
  · rename_i found_path found_anchor h_walk
    simp only [Verdict.ok.injEq] at h
    obtain ⟨h_alg, h_key, rfl, rfl⟩ := h
    exact ⟨leafBytes, rest, leaf, h_entries, h_leaf, h_alg, h_key, by simpa using h_valid,
      by simpa using h_matched, walkFrom_reached cfg rest leafBytes leaf 1 0 _ _ h_walk⟩
  all_goals simp at h

end Spec.Webpki
