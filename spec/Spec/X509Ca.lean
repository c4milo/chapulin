import Spec.Pem
import Spec.X509

/-!
# Provisioning: one PEM certificate to the public key it carries

Written from RFC 5280 section 4.1 (Certificate and TBSCertificate),
section 4.2.1.9 (basicConstraints) and section 4.2.1.3 (keyUsage). The
armour is RFC 7468, which `Spec.Pem` models.

This is NOT the verifier `Spec.X509.parse` models, and the differences
are the point rather than an omission:

* the signature is never checked, only its framing read, because a
  trust anchor's self-signature proves nothing;
* validity, issuer and subject go unread, because the device has no
  clock and matches no names;
* `basicConstraints` must say `cA TRUE` and accepts any
  `pathLenConstraint`, where the verifier admits only `pathLen 0` --
  a self-signed root carries none;
* `keyUsage` is optional, and when present must permit `keyCertSign`;
* `extendedKeyUsage` is not required and is rejected when critical,
  like any other unrecognized critical extension.

Decoding is not authenticating. This yields bytes, never a verdict.
-/

namespace Spec.X509Ca

open Spec.Bytes Spec.X509

/-- Hex literal for a pinned constant; a malformed literal falls back
to a 1-byte sentinel no comparison matches. Spec.X509 keeps its own
private copy of this. -/
private def hexConst (s : String) : ByteArray := (hexToBytes? s).getD (ByteArray.mk #[0])

/-- BOOLEAN TRUE, the `cA` field. DER admits one encoding of true. -/
def caTrue : ByteArray := hexConst "0101ff"

/-- `basicConstraints` on a trust anchor: `cA TRUE`, then either
nothing or a `pathLenConstraint` INTEGER. A root emits `30 03 01 01
ff`, an intermediate `30 06 01 01 ff 02 01 00`, and both are anchors
an operator may legitimately pin. -/
def isCaTrue (v : ByteArray) : Bool :=
  match readTlv v 0 0x30 with
  | none => false
  | some (body, endOff) =>
    if endOff != v.size then false
    else match matchAt body 0 caTrue with
      | none => false
      | some o =>
        if o == body.size then true
        else match readTlv body o 0x02 with
          | none => false
          | some (_, o') => o' == body.size

/-- One extension. Returns the offset past it and whether it was the
`basicConstraints` that said CA. -/
def readExtension (b : ByteArray) (off : Nat) (sawCa : Bool) : Option (Nat × Bool) := do
  let (ext, endOff) ← readTlv b off 0x30
  guard (endOff - off ≤ extTlvMax)
  let (oid, o1) ← readTlv ext 0 0x06
  guard (oid.size ≠ 0 ∧ oid.size ≤ 16 ∧ oidMinimal oid)
  let t ← byteAt? ext o1
  let (critical, o2) ←
    if t == 0x01 then
      if o1 + 3 ≤ ext.size ∧ ext[o1 + 1]! == 0x01 ∧ ext[o1 + 2]! == 0xff then
        some (true, o1 + 3)
      else none
    else some (false, o1)
  let (val, o3) ← readTlv ext o2 0x04
  guard (o3 == ext.size)
  if oid == oidBasicConstraints then do
    guard (!sawCa ∧ isCaTrue val)
    some (endOff, true)
  else if oid == oidKeyUsage then do
    -- Optional in RFC 5280, and conforming CAs SHOULD mark it
    -- critical, so it needs a case here or every real intermediate
    -- would fail the unknown-critical rule below. An anchor whose own
    -- keyUsage forbids signing certificates cannot anchor a chain.
    guard (readKeyUsage val 0x04)
    some (endOff, sawCa)
  else if critical then
    none -- RFC 5280 section 4.2: an unrecognized critical extension is rejected
  else
    some (endOff, sawCa) -- unknown non-critical: skipped, contents unread

/-- At most `fuel` extensions consuming `b` exactly. True only when
`basicConstraints` said CA. -/
def extensionWalk (b : ByteArray) : Nat → Nat → Bool → Option Bool
  | 0, off, sawCa => if off == b.size then some sawCa else none
  | fuel + 1, off, sawCa =>
    if off == b.size then some sawCa
    else do
      let (off', sawCa') ← readExtension b off sawCa
      extensionWalk b fuel off' sawCa'

/-- TBSCertificate, exact-consume. Four fields are skipped whole:
signatureAlgorithm is the anchor's own and is never checked, issuer
and subject are names this profile does not read, and validity needs
a clock the device does not have. -/
def readTbs (alg : Alg) (tbs : ByteArray) : Option ByteArray := do
  let o1 ← matchAt tbs 0 versionV3
  let o2 ← readSerial tbs o1
  let (_, o3) ← readTlv tbs o2 0x30 -- signatureAlgorithm
  let (_, o4) ← readTlv tbs o3 0x30 -- issuer
  let (_, o5) ← readTlv tbs o4 0x30 -- validity
  let (_, o6) ← readTlv tbs o5 0x30 -- subject
  let (key, o7) ← readSpki alg tbs o6
  let (wrap, o8) ← readTlv tbs o7 0xa3
  guard (o8 == tbs.size)
  let (exts, eo) ← readTlv wrap 0 0x30
  guard (eo == wrap.size ∧ exts.size ≠ 0)
  let sawCa ← extensionWalk exts extCountMax 0 false
  guard sawCa
  some key

/-- The whole certificate. The signature's framing is read and its
bytes are not: verifying a self-signature would only tell an
integrator that a check happened, while reading the framing rejects a
certificate truncated after the TBS. -/
def readCertificate (alg : Alg) (cert : ByteArray) : Option ByteArray := do
  let (body, endOff) ← readTlv cert 0 0x30
  guard (endOff == cert.size)
  let (tbs, o1) ← readTlv body 0 0x30
  let key ← readTbs alg tbs
  let (_, o2) ← readTlv body o1 0x30 -- signatureAlgorithm
  let (sig, o3) ← readTlv body o2 0x03
  -- The BIT STRING's framing, exactly as the C reads it: at least the
  -- unused-bits octet plus one content byte, and the unused-bits octet
  -- zero because signature bits fill whole bytes (x509_der.c's
  -- x509_read_bitstring, the same guard Spec.X509 line 334 applies on
  -- the verifier path). A review found this walk laxer than the C
  -- here -- accepting 03 01 00 and a nonzero unused-bits octet -- which
  -- made the differential's byte-flip rows able to split the two sides.
  guard (sig.size ≥ 2 ∧ sig[0]! == 0 ∧ o3 == body.size)
  some key

/-- The exported entry: PEM text to the key bytes
`ch_cfg.server_pubkey` takes. -/
def caKey? (alg : Alg) (derMax : Nat) (pem : ByteArray) : Option ByteArray := do
  let der ← Spec.Pem.decode? derMax pem
  guard (der.size ≤ derMax)
  readCertificate alg der

/-- Structural, like `Spec.X509`'s: no third party publishes vectors
for a provisioning walk. The differential in test/diff_pem.h carries
the known-answer weight, minting certificates with `Spec.X509.mint`
and comparing against the C. -/
def selftest : Bool :=
  isCaTrue (hexConst "30030101ff")            -- a root: no pathLenConstraint
    ∧ isCaTrue (hexConst "30060101ff020100")  -- an intermediate: pathLen 0
    ∧ isCaTrue (hexConst "30060101ff020103")  -- any pathLen is an anchor
    ∧ !isCaTrue (hexConst "3000")             -- a leaf: cA absent
    ∧ !isCaTrue (hexConst "30030101fe")       -- not DER's TRUE
    ∧ !isCaTrue (hexConst "30040101ff00")     -- trailing junk after cA

/-!
## Proofs

Two facts are pinned here. First, the key `caKey?` returns is sized
for `ch_cfg.server_pubkey`: the walk ends in `Spec.X509.readSpki`,
whose guards fix the P-256 point at 64 bytes and the RSA modulus
value at 256 to 384 bytes in multiples of 8, and no step between
`readSpki` and `caKey?` changes the key bytes. Second, `isCaTrue`
accepts exactly the two shapes its docstring names: `cA TRUE` alone,
or `cA TRUE` followed by one pathLenConstraint TLV that fills the
SEQUENCE.
-/

/-- Splits one `Option` bind that produced `some` into the step's own
`some` and the continuation's. The walks below apply it once per
do-chain step. -/
private theorem bind_some_elim {α β : Type} {x : Option α} {f : α → Option β} {b : β}
    (h : (x >>= f) = some b) : ∃ a, x = some a ∧ f a = some b := by
  cases hx : x with
  | none => rw [hx] at h; cases h
  | some a => rw [hx] at h; exact ⟨a, rfl, h⟩

private theorem guard_neg {p : Prop} [Decidable p] (h : ¬p) :
    (guard p : Option Unit) = none := by
  unfold guard
  rw [if_neg h]
  rfl

private theorem guard_some {p : Prop} [Decidable p] {u : Unit}
    (h : (guard p : Option Unit) = some u) : p := by
  by_cases hp : p
  · exact hp
  · rw [guard_neg hp] at h
    cases h

private theorem byteArray_beq_self (a : ByteArray) : (a == a) = true :=
  beq_self_eq_true (a := a.data)

private theorem byteArray_eq_of_beq {a b : ByteArray} (h : (a == b) = true) : a = b :=
  ByteArray.ext (eq_of_beq h)

/-- Reading before the join reads the left array. -/
private theorem byteAt?_append_left (a b : ByteArray) (i : Nat) (h : i < a.size) :
    byteAt? (a ++ b) i = byteAt? a i := by
  unfold byteAt?
  rw [dif_pos (show i < (a ++ b).size by rw [ByteArray.size_append]; omega), dif_pos h,
    ByteArray.getElem_append_left h]

/-- Reading past the join reads the right array. -/
private theorem byteAt?_append_right (a b : ByteArray) (i : Nat) :
    byteAt? (a ++ b) (a.size + i) = byteAt? b i := by
  unfold byteAt?
  by_cases h : i < b.size
  · rw [dif_pos (show a.size + i < (a ++ b).size by rw [ByteArray.size_append]; omega),
      dif_pos h]
    congr 1
    rw [ByteArray.getElem_append_right (by omega)]
    congr 1
    omega
  · rw [dif_neg (by rw [ByteArray.size_append]; omega), dif_neg h]

private theorem encodeLen_size_pos (n : Nat) : 0 < (encodeLen n).size := by
  rw [encodeLen]
  split
  · show 0 < 1
    decide
  · split
    · show 0 < 2
      decide
    · show 0 < 3
      decide

private theorem tlv_size (tag : UInt8) (c : ByteArray) :
    (tlv tag c).size = 1 + (encodeLen c.size).size + c.size := by
  rw [tlv, ByteArray.size_append, ByteArray.size_append]
  rfl

/-- A TLV with bytes after it, split at its three parts. -/
private theorem tlv_append (tag : UInt8) (content rest : ByteArray) :
    tlv tag content ++ rest
      = ByteArray.mk #[tag] ++ (encodeLen content.size ++ (content ++ rest)) := by
  rw [tlv, ByteArray.append_assoc, ByteArray.append_assoc]

/-- `Spec.X509.readTlv_tlv` at an arbitrary start offset: reading at
the end of `pre` reads back what `tlv` wrote there. -/
private theorem readTlv_tlv_at (pre : ByteArray) (tag : UInt8) (content rest : ByteArray)
    (h : content.size ≤ 0xffff) :
    readTlv (pre ++ (tlv tag content ++ rest)) pre.size tag
      = some (content, pre.size + (tlv tag content).size) := by
  have h_tag_size : (ByteArray.mk #[tag]).size = 1 := rfl
  have hA : pre ++ (tlv tag content ++ rest)
      = (pre ++ ByteArray.mk #[tag]) ++ (encodeLen content.size ++ (content ++ rest)) := by
    rw [tlv_append, ← ByteArray.append_assoc]
  have hpre1 : (pre ++ ByteArray.mk #[tag]).size = pre.size + 1 := by
    rw [ByteArray.size_append, h_tag_size]
  have h_byte0 : byteAt? ((pre ++ ByteArray.mk #[tag]) ++
      (encodeLen content.size ++ (content ++ rest))) pre.size = some tag := by
    rw [byteAt?_append_left _ _ pre.size (by omega)]
    have h0 := byteAt?_append_right pre (ByteArray.mk #[tag]) 0
    rw [Nat.add_zero] at h0
    rw [h0]
    rfl
  have hlen := readLen_encodeLen (pre ++ ByteArray.mk #[tag]) content.size (content ++ rest)
    h (by rw [ByteArray.size_append]; omega)
  rw [hpre1] at hlen
  have hs : slice ((pre ++ ByteArray.mk #[tag]) ++ (encodeLen content.size ++ (content ++ rest)))
      (pre.size + 1 + (encodeLen content.size).size) content.size = content := by
    rw [slice, ← ByteArray.append_assoc,
      show pre.size + 1 + (encodeLen content.size).size
        = ((pre ++ ByteArray.mk #[tag]) ++ encodeLen content.size).size + 0 by
          rw [ByteArray.size_append, hpre1]; omega,
      show ((pre ++ ByteArray.mk #[tag]) ++ encodeLen content.size).size + 0 + content.size
        = ((pre ++ ByteArray.mk #[tag]) ++ encodeLen content.size).size + content.size by omega,
      ByteArray.extract_append_size_add' rfl, ByteArray.extract_append_eq_left rfl]
  rw [readTlv, hA, h_byte0,
    show pre.size + (tlv tag content).size
      = pre.size + 1 + (encodeLen content.size).size + content.size by rw [tlv_size]; omega]
  simp only [Option.bind_eq_bind, Option.bind_some, beq_self_eq_true]
  rw [hlen]
  simp only [Option.bind_some, hs]
  rfl

/-- `matchAt` accepts `a` at offset 0 of `a ++ b`. -/
private theorem matchAt_prefix (a b : ByteArray) : matchAt (a ++ b) 0 a = some a.size := by
  unfold matchAt
  rw [slice, Nat.zero_add, ByteArray.extract_append_eq_left rfl,
    if_pos (show a.size ≤ (a ++ b).size by rw [ByteArray.size_append]; omega),
    if_pos (byteArray_beq_self a)]

/-- Every length `readLen` accepts fits `encodeLen`'s two-octet
domain: each of the three accepted forms states at most 0xffff. -/
private theorem readLen_le (b : ByteArray) (off len co : Nat)
    (h : readLen b off = some (len, co)) : len ≤ 0xffff := by
  unfold readLen at h
  cases hb : byteAt? b off with
  | none => rw [hb] at h; simp at h
  | some first =>
    rw [hb] at h
    simp only [Option.bind_eq_bind, Option.bind_some] at h
    have hf := first.toNat_lt
    split at h
    · split at h
      · simp only [Option.some.injEq, Prod.mk.injEq] at h
        omega
      · cases h
    · split at h
      · cases hb1 : byteAt? b (off + 1) with
        | none => rw [hb1] at h; simp at h
        | some l =>
          rw [hb1] at h
          simp only [Option.bind_some] at h
          have hl := l.toNat_lt
          split at h
          · simp only [Option.some.injEq, Prod.mk.injEq] at h
            omega
          · cases h
      · split at h
        · cases hb1 : byteAt? b (off + 1) with
          | none => rw [hb1] at h; simp at h
          | some hi =>
            rw [hb1] at h
            simp only [Option.bind_some] at h
            cases hb2 : byteAt? b (off + 2) with
            | none => rw [hb2] at h; simp at h
            | some lo =>
              rw [hb2] at h
              simp only [Option.bind_some] at h
              have hhi := hi.toNat_lt
              have hlo := lo.toNat_lt
              split at h
              · simp only [Option.some.injEq, Prod.mk.injEq] at h
                omega
              · cases h
        · cases h

/-- Content `readTlv` returns is at most 0xffff bytes, because its
length came through `readLen`. -/
private theorem readTlv_size_le (b : ByteArray) (off : Nat) (tag : UInt8)
    (c : ByteArray) (endOff : Nat) (h : readTlv b off tag = some (c, endOff)) :
    c.size ≤ 0xffff := by
  unfold readTlv at h
  obtain ⟨t, -, h⟩ := bind_some_elim h
  obtain ⟨-, -, h⟩ := bind_some_elim h
  obtain ⟨⟨len, co⟩, hlen, h⟩ := bind_some_elim h
  simp only [Option.some.injEq, Prod.mk.injEq] at h
  obtain ⟨hc, -⟩ := h
  have hle := readLen_le b (off + 1) len co hlen
  rw [← hc, slice, ByteArray.size_extract]
  omega

/-- What a `matchAt` success says: the returned offset is just past
the pinned bytes, they fit, and the input carries them at `off`. -/
private theorem matchAt_some (b : ByteArray) (off : Nat) (want : ByteArray) (o : Nat)
    (h : matchAt b off want = some o) :
    o = off + want.size ∧ off + want.size ≤ b.size ∧ slice b off want.size = want := by
  unfold matchAt at h
  split at h
  · next hle =>
    split at h
    · next hbeq =>
      simp only [Option.some.injEq] at h
      exact ⟨h.symm, hle, byteArray_eq_of_beq hbeq⟩
    · cases h
  · cases h

/-- The accept side of `isCaTrue`'s pathLenConstraint arm, for any
INTEGER-tagged TLV the length codec can write. -/
private theorem isCaTrue_pathlen (p : ByteArray)
    (hp : (caTrue ++ tlv 0x02 p).size ≤ 0xffff) :
    isCaTrue (tlv 0x30 (caTrue ++ tlv 0x02 p)) = true := by
  have hpsize : p.size ≤ 0xffff := by
    have hs := ByteArray.size_append (a := caTrue) (b := tlv 0x02 p)
    have htp := tlv_size 0x02 p
    omega
  have hread : readTlv (tlv 0x30 (caTrue ++ tlv 0x02 p)) 0 0x30
      = some (caTrue ++ tlv 0x02 p, (tlv 0x30 (caTrue ++ tlv 0x02 p)).size) := by
    have h0 := readTlv_tlv 0x30 (caTrue ++ tlv 0x02 p) ByteArray.empty hp
    rwa [ByteArray.append_empty] at h0
  have hmatch : matchAt (caTrue ++ tlv 0x02 p) 0 caTrue = some caTrue.size :=
    matchAt_prefix caTrue (tlv 0x02 p)
  have hread2 : readTlv (caTrue ++ tlv 0x02 p) caTrue.size 0x02
      = some (p, caTrue.size + (tlv 0x02 p).size) := by
    have h0 := readTlv_tlv_at caTrue 0x02 p ByteArray.empty hpsize
    rwa [ByteArray.append_empty] at h0
  have hne : (caTrue.size == (caTrue ++ tlv 0x02 p).size) = false := by
    have hs := ByteArray.size_append (a := caTrue) (b := tlv 0x02 p)
    have hpos := encodeLen_size_pos p.size
    have htp := tlv_size 0x02 p
    refine beq_eq_false_iff_ne.mpr ?_
    omega
  have hfin : (caTrue.size + (tlv 0x02 p).size == (caTrue ++ tlv 0x02 p).size) = true := by
    refine beq_iff_eq.mpr ?_
    rw [ByteArray.size_append]
  unfold isCaTrue
  simp only [hread, bne_self_eq_false, Bool.false_eq_true, if_false, hmatch, hne, hread2, hfin]

/-- `isCaTrue` accepts exactly the two anchor encodings: the SEQUENCE
holding `cA TRUE` alone, or `cA TRUE` and then one INTEGER-tagged
TLV — the pathLenConstraint — that fills the SEQUENCE. The size bound
is `encodeLen`'s two-octet domain, which `tlv` needs to write the
SEQUENCE the reader reads back. The INTEGER's content is any byte
string: `isCaTrue` accepts the pathLenConstraint's value unread. -/
theorem isCaTrue_iff (v : ByteArray) :
    isCaTrue v = true ↔
      v = tlv 0x30 caTrue ∨
        ∃ p, (caTrue ++ tlv 0x02 p).size ≤ 0xffff ∧ v = tlv 0x30 (caTrue ++ tlv 0x02 p) := by
  constructor
  · intro h
    unfold isCaTrue at h
    split at h
    · cases h
    · next body endOff hread =>
      split at h
      · cases h
      · next hoff =>
        have hoff' : endOff = v.size := by simpa using hoff
        obtain ⟨hcan, -, hslice⟩ := readTlv_canonical v 0 0x30 body endOff hread
        have hv : v = tlv 0x30 body := by
          rw [show (tlv 0x30 body).size = v.size by omega] at hslice
          rw [slice, Nat.zero_add, ByteArray.extract_zero_size] at hslice
          exact hslice
        have hbody_le : body.size ≤ 0xffff := readTlv_size_le v 0 0x30 body endOff hread
        split at h
        · cases h
        · next o hmatch =>
          obtain ⟨ho, hfit, hpre⟩ := matchAt_some body 0 caTrue o hmatch
          rw [slice, Nat.zero_add] at hpre
          split at h
          · next hend =>
            have hbs : body.size = caTrue.size := by
              have he := eq_of_beq hend
              omega
            left
            rw [← hbs, ByteArray.extract_zero_size] at hpre
            rw [hv, hpre]
          · next hend =>
            split at h
            · cases h
            · next pl o' hread2 =>
              have ho' : o' = body.size := eq_of_beq h
              obtain ⟨hcan2, -, hslice2⟩ := readTlv_canonical body o 0x02 pl o' hread2
              have hbody : body = caTrue ++ tlv 0x02 pl := by
                have hwhole : body.extract 0 body.size = body := ByteArray.extract_zero_size
                rw [ByteArray.extract_eq_extract_append_extract caTrue.size (by omega)
                  (by omega)] at hwhole
                rw [slice, show o = caTrue.size by omega,
                  show caTrue.size + (tlv 0x02 pl).size = body.size by omega] at hslice2
                rw [hpre, hslice2] at hwhole
                exact hwhole.symm
              right
              exact ⟨pl, by rw [← hbody]; exact hbody_le, by rw [hv, hbody]⟩
  · intro h
    rcases h with hroot | ⟨p, hp, hshape⟩
    · rw [hroot]
      decide
    · rw [hshape]
      exact isCaTrue_pathlen p hp

/-- The p256 arm of `readSpki` returns only the 64-byte X‖Y point:
its guard fixes the BIT STRING at 66 bytes, and the arm returns the
64 bytes after the unused-bits octet and the 0x04 point prefix. -/
private theorem readSpki_p256_size (b : ByteArray) (off : Nat) (k : ByteArray) (kOff : Nat)
    (h : readSpki .p256 b off = some (k, kOff)) : k.size = 64 := by
  unfold readSpki at h
  obtain ⟨⟨body, spkiEnd⟩, -, h⟩ := bind_some_elim h
  obtain ⟨o1, -, h⟩ := bind_some_elim h
  obtain ⟨⟨bits, o2⟩, -, h⟩ := bind_some_elim h
  obtain ⟨-, -, h⟩ := bind_some_elim h
  obtain ⟨u66, hbits66, h⟩ := bind_some_elim h
  obtain ⟨-, -, h⟩ := bind_some_elim h
  have hbits : bits.size = 66 := by simpa using guard_some hbits66
  simp only [Option.some.injEq, Prod.mk.injEq] at h
  obtain ⟨hk, -⟩ := h
  rw [← hk, ByteArray.size_extract, hbits]
  decide

/-- The rsa arm of `readSpki` returns only a modulus value its own
size guard admits: 256 to 384 bytes, a multiple of 8. -/
private theorem readSpki_rsa_size (b : ByteArray) (off : Nat) (k : ByteArray) (kOff : Nat)
    (h : readSpki .rsa b off = some (k, kOff)) :
    256 ≤ k.size ∧ k.size ≤ 384 ∧ k.size % 8 = 0 := by
  unfold readSpki at h
  obtain ⟨⟨body, spkiEnd⟩, -, h⟩ := bind_some_elim h
  obtain ⟨o1, -, h⟩ := bind_some_elim h
  obtain ⟨⟨bits, o2⟩, -, h⟩ := bind_some_elim h
  obtain ⟨-, -, h⟩ := bind_some_elim h
  obtain ⟨-, -, h⟩ := bind_some_elim h
  obtain ⟨⟨seq, ko⟩, -, h⟩ := bind_some_elim h
  obtain ⟨-, -, h⟩ := bind_some_elim h
  obtain ⟨⟨m, mo⟩, -, h⟩ := bind_some_elim h
  obtain ⟨-, -, h⟩ := bind_some_elim h
  obtain ⟨usz, hsize, h⟩ := bind_some_elim h
  obtain ⟨-, -, h⟩ := bind_some_elim h
  obtain ⟨eo, -, h⟩ := bind_some_elim h
  obtain ⟨-, -, h⟩ := bind_some_elim h
  simp only [Option.some.injEq, Prod.mk.injEq] at h
  obtain ⟨hk, -⟩ := h
  have hsz := guard_some hsize
  rw [← hk]
  exact ⟨hsz.1, hsz.2.1, by simpa using hsz.2.2⟩

/-- The key `readTbs` returns is the one `readSpki` returned,
unchanged. -/
private theorem readTbs_spki (alg : Alg) (tbs k : ByteArray)
    (h : readTbs alg tbs = some k) :
    ∃ off endOff, readSpki alg tbs off = some (k, endOff) := by
  unfold readTbs at h
  obtain ⟨o1, -, h⟩ := bind_some_elim h
  obtain ⟨o2, -, h⟩ := bind_some_elim h
  obtain ⟨⟨_, o3⟩, -, h⟩ := bind_some_elim h
  obtain ⟨⟨_, o4⟩, -, h⟩ := bind_some_elim h
  obtain ⟨⟨_, o5⟩, -, h⟩ := bind_some_elim h
  obtain ⟨⟨_, o6⟩, -, h⟩ := bind_some_elim h
  obtain ⟨⟨key, o7⟩, hspki, h⟩ := bind_some_elim h
  obtain ⟨⟨wrap, o8⟩, -, h⟩ := bind_some_elim h
  obtain ⟨-, -, h⟩ := bind_some_elim h
  obtain ⟨⟨exts, eo⟩, -, h⟩ := bind_some_elim h
  obtain ⟨-, -, h⟩ := bind_some_elim h
  obtain ⟨sawCa, -, h⟩ := bind_some_elim h
  obtain ⟨-, -, h⟩ := bind_some_elim h
  simp only [Option.some.injEq] at h
  rw [h] at hspki
  exact ⟨o6, o7, hspki⟩

/-- The key `readCertificate` returns is the one `readTbs` returned,
unchanged. -/
private theorem readCertificate_tbs (alg : Alg) (cert k : ByteArray)
    (h : readCertificate alg cert = some k) :
    ∃ tbs, readTbs alg tbs = some k := by
  unfold readCertificate at h
  obtain ⟨⟨body, endOff⟩, -, h⟩ := bind_some_elim h
  obtain ⟨-, -, h⟩ := bind_some_elim h
  obtain ⟨⟨tbs, o1⟩, -, h⟩ := bind_some_elim h
  obtain ⟨key, htbs, h⟩ := bind_some_elim h
  obtain ⟨⟨_, o2⟩, -, h⟩ := bind_some_elim h
  obtain ⟨⟨sig, o3⟩, -, h⟩ := bind_some_elim h
  obtain ⟨-, -, h⟩ := bind_some_elim h
  simp only [Option.some.injEq] at h
  rw [h] at htbs
  exact ⟨tbs, htbs⟩

/-- The key `caKey?` returns is the one `readCertificate` returned,
unchanged. -/
private theorem caKey?_certificate (alg : Alg) (derMax : Nat) (pem k : ByteArray)
    (h : caKey? alg derMax pem = some k) :
    ∃ der, readCertificate alg der = some k := by
  unfold caKey? at h
  obtain ⟨der, -, h⟩ := bind_some_elim h
  obtain ⟨-, -, h⟩ := bind_some_elim h
  exact ⟨der, h⟩

/-- A key `readCertificate` accepts under `.p256` is exactly the
64-byte X‖Y point `ch_cfg.server_pubkey` takes in the ECDSA build. -/
theorem readCertificate_p256_size (cert k : ByteArray)
    (h : readCertificate .p256 cert = some k) : k.size = 64 := by
  obtain ⟨tbs, htbs⟩ := readCertificate_tbs .p256 cert k h
  obtain ⟨off, endOff, hspki⟩ := readTbs_spki .p256 tbs k htbs
  exact readSpki_p256_size tbs off k endOff hspki

/-- A key `readCertificate` accepts under `.rsa` is a modulus value
of 256 to 384 bytes, a multiple of 8: RSA-2048 up to RSA-3072. -/
theorem readCertificate_rsa_size (cert k : ByteArray)
    (h : readCertificate .rsa cert = some k) :
    256 ≤ k.size ∧ k.size ≤ 384 ∧ k.size % 8 = 0 := by
  obtain ⟨tbs, htbs⟩ := readCertificate_tbs .rsa cert k h
  obtain ⟨off, endOff, hspki⟩ := readTbs_spki .rsa tbs k htbs
  exact readSpki_rsa_size tbs off k endOff hspki

/-- Every key `caKey?` yields under `.p256` is exactly 64 bytes: the
X‖Y point `ch_cfg.server_pubkey` takes, and the ECDSA build's
CH_X509_KEY_MAX. -/
theorem caKey?_p256_size (derMax : Nat) (pem k : ByteArray)
    (h : caKey? .p256 derMax pem = some k) : k.size = 64 := by
  obtain ⟨der, hcert⟩ := caKey?_certificate .p256 derMax pem k h
  exact readCertificate_p256_size der k hcert

/-- Every key `caKey?` yields under `.rsa` is a modulus value of 256
to 384 bytes, a multiple of 8: it fits the RSA build's
CH_X509_KEY_MAX of 384. -/
theorem caKey?_rsa_size (derMax : Nat) (pem k : ByteArray)
    (h : caKey? .rsa derMax pem = some k) :
    256 ≤ k.size ∧ k.size ≤ 384 ∧ k.size % 8 = 0 := by
  obtain ⟨der, hcert⟩ := caKey?_certificate .rsa derMax pem k h
  exact readCertificate_rsa_size der k hcert

end Spec.X509Ca
