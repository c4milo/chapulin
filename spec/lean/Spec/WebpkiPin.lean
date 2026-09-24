import Spec.Sha256
import Spec.Webpki

/-!
SPKI pins and RFC 7250 raw public keys for the `TRUST=webpki` client
(`webpki_pin.c`), written from RFC 7858 §4.2 (an SPKI pin is the SHA-256
of a DER SubjectPublicKeyInfo, and the pins name keys on the validated
chain), RFC 7250 §3 (a RawPublicKey Certificate message carries one
SubjectPublicKeyInfo in place of a chain) and RFC 9846 §4.5.1 (the
CertificateEntry framing it shares with a chain).

`verifyRawKey` judges a RawPublicKey CertificateEntry list by the pins
alone and answers one of five verdicts. The four refusals are the four
pairs of return code and alert the C tells apart:

* `rejected` is `CH_EPROTO` with `bad_certificate`: the framing, a count
  of entries other than one, or an entry over `spkiMax` bytes;
* `unsupportedExtension` is `CH_EPROTO` with `unsupported_extension`: a
  non-empty per-entry extensions vector;
* `unsupportedCertificate` is `CH_EPROTO` with `unsupported_certificate`:
  an entry `Spec.WebpkiSpki.readSpki?` refuses, which includes one it
  does not fill exactly;
* `unpinned` is `CH_EAUTH` with `bad_certificate`: no pin names the key.

`pathPinned` is the other rule: after `Spec.Webpki.verifyChain` accepted
a chain, a pin must name the key of one of the entries on the path it
reported, or of the anchor that ended it.
-/

namespace Spec.WebpkiPin

open Spec.Bytes Spec.X509 Spec.WebpkiSpki Spec.WebpkiCert Spec.Webpki

/-- `CH_WEBPKI_SPKI_MAX`: the largest SubjectPublicKeyInfo `readSpki?`
accepts, an RSA key of `modulusMax` bytes, and so the largest raw
public key entry. -/
def spkiMax : Nat := 550

/-- RFC 7858 §4.2: a pin names `spki` when it equals the SHA-256 of those
bytes, the whole DER SubjectPublicKeyInfo. -/
def pinned (pins : List ByteArray) (spki : ByteArray) : Bool :=
  pins.contains (Spec.Sha256.sha256 spki)

/-- The answer for a RawPublicKey Certificate message. -/
inductive RawVerdict where
  /-- A pin names the key: its algorithm and bytes. -/
  | ok (alg : KeyAlg) (key : ByteArray)
  /-- The framing, or a count of entries other than one. -/
  | rejected
  /-- A non-empty per-entry extensions vector. -/
  | unsupportedExtension
  /-- A malformed SubjectPublicKeyInfo, or one the mode refuses. -/
  | unsupportedCertificate
  /-- No pin names the key. -/
  | unpinned

/-- The name the differential compares. -/
def RawVerdict.name : RawVerdict → String
  | .ok _ _ => "ok"
  | .rejected => "rejected"
  | .unsupportedExtension => "unsupported_extension"
  | .unsupportedCertificate => "unsupported_certificate"
  | .unpinned => "unpinned"

/-- The key a raw entry carries: `readSpki?` over the whole entry, which
must fill it, and a pin that names the entry's bytes. -/
def judgeRawKey (pins : List ByteArray) (spki : ByteArray) : RawVerdict :=
  match readSpki? spki with
  | none => .unsupportedCertificate
  | some (alg, key) => if pinned pins spki then .ok alg key else .unpinned

/-- A RawPublicKey CertificateEntry list (RFC 7250 §3, RFC 9846 §4.5.1):
exactly one entry, a u24 length from 1 to `spkiMax`, that many bytes, and
an empty u16 extensions vector, with nothing after it. -/
def verifyRawKey (pins : List ByteArray) (list : ByteArray) : RawVerdict :=
  if list.size < 3 then .rejected
  else
    let len := 65536 * list[0]!.toNat + 256 * list[1]!.toNat + list[2]!.toNat
    if len == 0 || spkiMax < len || list.size < 5 + len then .rejected
    else if list[3 + len]! != 0 || list[4 + len]! != 0 then .unsupportedExtension
    else if list.size != 5 + len then .rejected
    else judgeRawKey pins (slice list 3 len)

/-- The SubjectPublicKeyInfo TLV of a certificate the walk read, parsed
under the arm it read it under: the leaf's for entry 0, an issuer's after
it. -/
def certificateSpki? (index : Nat) (cert : ByteArray) : Option ByteArray :=
  (parseCertificate? (index != 0) cert).map fun c => slice cert c.spki.off c.spki.len

/-- RFC 7858 §4.2 pins the validated chain: a pin names the key of one of
the first `path` entries of the list, or of the anchor at index `anchor`.
An entry beyond the path does not count. A path over `chainMax` entries or
an anchor index past the anchors is none the walk reports, and names
nothing. -/
def pathPinned (pins : List ByteArray) (anchors : List Anchor) (list : ByteArray)
    (path anchor : Nat) : Bool :=
  match readEntries? list, anchors[anchor]? with
  | some entries, some a =>
    decide (path ≤ chainMax) &&
      (((entries.take path).zipIdx.any fun (cert, index) =>
          match certificateSpki? index cert with
          | some spki => pinned pins spki
          | none => false) ||
        pinned pins a.spki)
  | _, _ => false

set_option compiler.extract_closed false in
/-- The corpus r2 leaf's SubjectPublicKeyInfo framed as one raw entry:
accepted with its pin first or second of two, and refused without it;
and one refusal per framing rule. -/
def selftest (_ : Unit) : Bool :=
  let spki := match certificateSpki? 0 r2Leaf with
    | some b => b
    | none => ByteArray.empty
  let frame := fun (data : ByteArray) (ext : ByteArray) =>
    natToBytesBE data.size 3 ++ data ++ ext
  let pin := Spec.Sha256.sha256 spki
  let other := ByteArray.mk (Array.replicate 32 0x5a)
  let one := frame spki (ByteArray.mk #[0, 0])
  (verifyRawKey [pin, other] one).name == "ok" &&
    (verifyRawKey [other, pin] one).name == "ok" &&
    (verifyRawKey [other] one).name == "unpinned" &&
    (verifyRawKey [pin] (one ++ one)).name == "rejected" &&
    (verifyRawKey [pin] (one ++ ByteArray.mk #[0])).name == "rejected" &&
    (verifyRawKey [pin] (frame spki (ByteArray.mk #[0, 1, 0]))).name == "unsupported_extension" &&
    (verifyRawKey [pin] (frame (spki ++ ByteArray.mk #[0]) (ByteArray.mk #[0, 0]))).name ==
      "unsupported_certificate" &&
    (verifyRawKey [pin] ByteArray.empty).name == "rejected" &&
    spki.size == 91

/-!
## Proofs
-/

/-- Soundness of the raw key rule: an accepted list is one CertificateEntry
of 1 to `spkiMax` bytes and nothing after it, whose bytes `readSpki?` reads
whole as the returned key, and whose SHA-256 is one of the pins. -/
theorem verifyRawKey_ok (pins : List ByteArray) (list : ByteArray) (alg : KeyAlg)
    (key : ByteArray) (h : verifyRawKey pins list = .ok alg key) :
    ∃ len, 1 ≤ len ∧ len ≤ spkiMax ∧ list.size = 5 + len ∧
      readSpki? (slice list 3 len) = some (alg, key) ∧
      pins.contains (Spec.Sha256.sha256 (slice list 3 len)) = true := by
  unfold verifyRawKey at h
  split at h
  · simp at h
  dsimp only at h
  generalize 65536 * list[0]!.toNat + 256 * list[1]!.toNat + list[2]!.toNat = len at h
  split at h
  · simp at h
  rename_i h_frame
  split at h
  · simp at h
  split at h
  · simp at h
  rename_i h_fill
  unfold judgeRawKey at h
  split at h
  · simp at h
  rename_i read_alg read_key h_read
  split at h
  · rename_i h_pinned
    simp only [RawVerdict.ok.injEq] at h
    obtain ⟨rfl, rfl⟩ := h
    simp only [spkiMax, Bool.or_eq_true, beq_iff_eq, decide_eq_true_eq, not_or, not_lt] at h_frame
    obtain ⟨⟨h_nonempty, h_cap⟩, -⟩ := h_frame
    have h_within : len ≤ spkiMax := Nat.not_lt.mp fun h_over => h_cap (decide_eq_true h_over)
    refine ⟨len, by omega, h_within, by simpa using h_fill, h_read, ?_⟩
    simpa only [pinned] using h_pinned
  · simp at h

end Spec.WebpkiPin
