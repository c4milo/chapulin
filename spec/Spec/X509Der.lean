import Spec.Bytes

/-!
Canonical-DER primitives for the profiled X.509 model, written from
X.690 — never from the C sources. Canonical DER admits one encoding
per value: definite minimal lengths, exact-fill containers, DEFAULT
values absent, minimal INTEGERs, named-bit BIT STRING minimality,
§8.19-minimal OID subidentifiers. Every reader rejects a non-minimal
or malformed encoding before it interprets any field, and the
encoders emit the same minimal forms. `Spec.X509` layers the RFC 5280
certificate grammar on top; the field readers that profile shapes
(`readSerial`, `readTime`, `readTimeEpoch`) cite its sections
inline. `readTimeEpoch` also extracts the revocation-epoch number
index a leaf's notBefore may carry.
-/

namespace Spec.X509

open Spec.Bytes

/-- `len` content bytes starting at `off` (clamped by `extract`; callers
bound `off + len` first). -/
def slice (b : ByteArray) (off len : Nat) : ByteArray :=
  b.extract off (off + len)

/-! ## Encoder -/

/-- Minimal definite DER length (X.690 §10.1); contents up to 0xffff. -/
def encodeLen (n : Nat) : ByteArray :=
  if n < 0x80 then ByteArray.mk #[UInt8.ofNat n]
  else if n < 0x100 then ByteArray.mk #[0x81, UInt8.ofNat n]
  else ByteArray.mk #[0x82, UInt8.ofNat (n / 256), UInt8.ofNat (n % 256)]

/-- One TLV: tag, minimal length, content (X.690 §8.1). -/
def tlv (tag : UInt8) (content : ByteArray) : ByteArray :=
  ByteArray.mk #[tag] ++ encodeLen content.size ++ content

/-- Minimal big-endian bytes of `v` (one zero byte for `v = 0`). -/
def natBytesMin (v : Nat) : ByteArray :=
  natToBytesBE v (if v == 0 then 1 else Nat.log2 v / 8 + 1)

/-- DER INTEGER of a non-negative value: minimal content, one 0x00 pad
exactly when the top bit is set (X.690 §8.3). -/
def derIntNat (v : Nat) : ByteArray :=
  let c := natBytesMin v
  tlv 0x02 (if c[0]! &&& 0x80 == 0x80 then ByteArray.mk #[0] ++ c else c)

/-! ## Reader -/

def byteAt? (b : ByteArray) (off : Nat) : Option UInt8 :=
  if h : off < b.size then some b[off] else none

/-- One DER length at `off`: definite form in its shortest encoding
(X.690 §10.1), and it must fit the bytes that remain. Three or more
length octets cannot occur under `certMax`. Returns the length and the
offset of the content. -/
def readLen (b : ByteArray) (off : Nat) : Option (Nat × Nat) := do
  let first ← byteAt? b off
  let f := first.toNat
  if f < 0x80 then
    if off + 1 + f ≤ b.size then some (f, off + 1) else none
  else if f == 0x81 then do
    let l ← byteAt? b (off + 1)
    if 0x80 ≤ l.toNat ∧ off + 2 + l.toNat ≤ b.size then some (l.toNat, off + 2) else none
  else if f == 0x82 then do
    let hi ← byteAt? b (off + 1)
    let lo ← byteAt? b (off + 2)
    let l := hi.toNat * 256 + lo.toNat
    if 0x100 ≤ l ∧ off + 3 + l ≤ b.size then some (l, off + 3) else none
  else none

/-- One TLV with the given tag: the content bytes and the offset just
past them. -/
def readTlv (b : ByteArray) (off : Nat) (tag : UInt8) : Option (ByteArray × Nat) := do
  let t ← byteAt? b off
  guard (t == tag)
  let (len, contentOff) ← readLen b (off + 1)
  some (slice b contentOff len, contentOff + len)

/-- Literal compare against a pinned encoding; the offset past it. -/
def matchAt (b : ByteArray) (off : Nat) (want : ByteArray) : Option Nat :=
  if off + want.size ≤ b.size then
    if slice b off want.size == want then some (off + want.size) else none
  else none

/-- One DER INTEGER: non-negative, minimal content (X.690 §8.3).
Returns the value and the offset past it. -/
def readDerInt (b : ByteArray) (off : Nat) : Option (Nat × Nat) := do
  let (c, off') ← readTlv b off 0x02
  guard (c.size ≠ 0)
  guard (c[0]! &&& 0x80 == 0)
  if c[0]! == 0 ∧ c.size ≥ 2 then guard (c[1]! &&& 0x80 == 0x80) else pure ()
  some (bytesToNatBE c, off')

/-- serialNumber: INTEGER, positive, nonzero, minimal; value at most 20
bytes (RFC 5280 §4.1.2.2 bounds the value), so content reaches 21
exactly when a top-bit-set value needs the 0x00 pad. -/
def readSerial (b : ByteArray) (off : Nat) : Option Nat := do
  let (c, off') ← readTlv b off 0x02
  guard (c.size ≠ 0 ∧ c.size ≤ 21)
  guard (c[0]! &&& 0x80 == 0) -- negative is off-profile
  if c[0]! == 0 then do
    guard (c.size ≠ 1) -- zero
    guard (c[1]! &&& 0x80 == 0x80) -- a pad the value does not need
  else
    guard (c.size ≠ 21) -- 21-byte value: over the RFC cap
  some off'

/-- One Time: UTCTime `YYMMDDHHMMSSZ` or GeneralizedTime
`YYYYMMDDHHMMSSZ` (RFC 5280 §4.1.2.5 admits exactly these shapes).
The digits go unread: the profile has no clock. -/
def readTime (b : ByteArray) (off : Nat) : Option Nat := do
  let t ← byteAt? b off
  let want ← if t == 0x17 then some 13 else if t == 0x18 then some 15 else none
  let l ← byteAt? b (off + 1)
  guard (l.toNat == want ∧ off + 2 + want ≤ b.size)
  guard (b[off + 1 + want]! == 0x5a) -- 'Z' is the only admitted zone
  some (off + 2 + want)

/-- `readTime` plus extraction, over exactly `readTime`'s shape rules:
returns the offset past the Time and `some` of its epoch number `yy*336 + (mm-1)*28 + (dd-1)` (0..16799) when the Time is
epoch-shaped — UTCTime, all twelve leading characters ASCII digits,
YY 00..49, MM 01..12, DD 01..28, HHMMSS zero. Every other valid Time
shape passes with `none`: extraction stays permissive, and the
driver enforces only when the epoch callbacks are configured. -/
def readTimeEpoch (b : ByteArray) (off : Nat) : Option (Nat × Option Nat) := do
  let off' ← readTime b off
  let t ← byteAt? b off
  if t ≠ 0x17 then
    return (off', none) -- GeneralizedTime is shape-valid, never epoch-shaped
  let c := slice b (off + 2) 12 -- the digits, past the tag and length octets
  if !(c.toList.all fun d => 0x30 ≤ d && d ≤ 0x39) then
    return (off', none) -- shape-valid Time, not all digits
  let digit (i : Nat) : Nat := c[i]!.toNat - 0x30
  let yy := digit 0 * 10 + digit 1
  let mm := digit 2 * 10 + digit 3
  let dd := digit 4 * 10 + digit 5
  let hms := digit 6 + digit 7 + digit 8 + digit 9 + digit 10 + digit 11
  if yy > 49 || mm < 1 || mm > 12 || dd < 1 || dd > 28 || hms ≠ 0 then
    return (off', none) -- a valid date, but not an allowed epoch
  return (off', some (yy * 336 + (mm - 1) * 28 + (dd - 1)))

/-- keyUsage extnValue: a named-bit BIT STRING in canonical DER
(X.690 §11.2.2): trailing zero bits absent, unused-bit count matching
the lowest set bit, zero padding, and `required` — the caller's mask
over the first defined octet: 0x80 digitalSignature for the leaf,
0x04 keyCertSign for the intermediate — set. -/
def readKeyUsage (v : ByteArray) (required : UInt8) : Bool :=
  match readTlv v 0 0x03 with
  | none => false
  | some (c, endOff) =>
    endOff == v.size && (c.size == 2 || c.size == 3) &&
      (let unused := c[0]!.toNat
       let last := c[c.size - 1]!
       unused ≤ 7 && last ≠ 0 &&
         last &&& UInt8.ofNat ((1 <<< unused) - 1) == 0 &&
         (last >>> UInt8.ofNat unused) &&& 1 == 1 &&
         c[1]! &&& required ≠ 0)

/-- X.690 §8.19 subidentifier discipline over an OID's content bytes:
no subidentifier starts with 0x80 (§8.19.2, minimal base-128), and
the final octet completes its subidentifier (top bit clear). The
accumulator carries (ok so far, at a subidentifier start). -/
def oidMinimal (oid : ByteArray) : Bool :=
  let final := oid.foldl
    (fun (st : Bool × Bool) b => (st.1 && !(st.2 && b == 0x80), b &&& 0x80 == 0))
    (true, true)
  final.1 && final.2


/-!
## Proofs

Two codecs are pinned here. `encodeLen`/`readLen` and `tlv`/`readTlv`
round-trip, and `readLen`/`readTlv` accept nothing but the encoder's
own bytes: X.690 §10.1 admits one length encoding per length, so a
reader that takes a second one would take two encodings of one
certificate. The DER INTEGER codec gets the same treatment against
X.690 §8.3.2 — minimal content, one 0x00 pad exactly when the top bit
is set — via `natBytesMin`, whose big-endian bytes are the minimal
ones for their value.
-/

private theorem guard_pos {p : Prop} [Decidable p] (h : p) :
    (guard p : Option Unit) = some () := by
  unfold guard
  rw [if_pos h]
  rfl

private theorem guard_neg {p : Prop} [Decidable p] (h : ¬p) :
    (guard p : Option Unit) = none := by
  unfold guard
  rw [if_neg h]
  rfl

private theorem ofNat_toNat (u : UInt8) : UInt8.ofNat u.toNat = u := by simp

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

private theorem lt_of_byteAt? (b : ByteArray) (off : Nat) (x : UInt8)
    (h : byteAt? b off = some x) : off < b.size := by
  unfold byteAt? at h
  split at h
  · assumption
  · simp at h

private theorem getElem_of_byteAt? (b : ByteArray) (off : Nat) (x : UInt8)
    (h : byteAt? b off = some x) (hlt : off < b.size) : b[off] = x := by
  unfold byteAt? at h
  rw [dif_pos hlt] at h
  simpa using h

private theorem byteAt?_eq_some (b : ByteArray) (i : Nat) (h : i < b.size) :
    byteAt? b i = some b[i]! := by
  unfold byteAt?
  rw [dif_pos h, getElem!_pos b i h]

private theorem getElem!_of_byteAt? (b : ByteArray) (i : Nat) (x : UInt8)
    (h : byteAt? b i = some x) : b[i]! = x := by
  unfold byteAt? at h
  split at h
  · next hi => rw [getElem!_pos b i hi]; simpa using h
  · simp at h

/-! ### The length codec (X.690 §10.1) -/

private theorem readLen_encodeLen_short (pre : ByteArray) (n : Nat) (tail : ByteArray)
    (hn : n < 0x80) (ht : n ≤ tail.size) :
    readLen (pre ++ (encodeLen n ++ tail)) pre.size
      = some (n, pre.size + (encodeLen n).size) := by
  have henc : encodeLen n = ByteArray.mk #[UInt8.ofNat n] := by
    simp [encodeLen, hn]
  have hsz : (encodeLen n).size = 1 := by rw [henc]; rfl
  have h0 : byteAt? (pre ++ (encodeLen n ++ tail)) pre.size = some (UInt8.ofNat n) := by
    have h := byteAt?_append_right pre (encodeLen n ++ tail) 0
    rw [Nat.add_zero] at h
    rw [h, byteAt?_append_left _ _ 0 (by omega), henc]
    rfl
  have hval : (UInt8.ofNat n).toNat = n := by
    simp [Nat.mod_eq_of_lt (show n < 256 by omega)]
  rw [readLen, h0]
  simp only [Option.bind_eq_bind, Option.bind_some, hval, hsz]
  rw [if_pos hn, if_pos (by rw [ByteArray.size_append, ByteArray.size_append, hsz]; omega)]

private theorem readLen_encodeLen_one (pre : ByteArray) (n : Nat) (tail : ByteArray)
    (hlo : 0x80 ≤ n) (hn : n < 0x100) (ht : n ≤ tail.size) :
    readLen (pre ++ (encodeLen n ++ tail)) pre.size
      = some (n, pre.size + (encodeLen n).size) := by
  have henc : encodeLen n = ByteArray.mk #[0x81, UInt8.ofNat n] := by
    simp [encodeLen, Nat.not_lt.mpr hlo, hn]
  have hsz : (encodeLen n).size = 2 := by rw [henc]; rfl
  have h0 : byteAt? (pre ++ (encodeLen n ++ tail)) pre.size = some 0x81 := by
    have h := byteAt?_append_right pre (encodeLen n ++ tail) 0
    rw [Nat.add_zero] at h
    rw [h, byteAt?_append_left _ _ 0 (by omega), henc]
    rfl
  have h1 : byteAt? (pre ++ (encodeLen n ++ tail)) (pre.size + 1) = some (UInt8.ofNat n) := by
    rw [byteAt?_append_right pre (encodeLen n ++ tail) 1,
      byteAt?_append_left _ _ 1 (by omega), henc]
    rfl
  have hval : (UInt8.ofNat n).toNat = n := by
    simp [Nat.mod_eq_of_lt (show n < 256 by omega)]
  have h129 : (0x81 : UInt8).toNat = 129 := rfl
  rw [readLen, h0]
  simp only [Option.bind_eq_bind, Option.bind_some, h1, hval, hsz, h129]
  rw [if_neg (by omega), if_pos (by decide),
    if_pos (And.intro (by omega)
      (by rw [ByteArray.size_append, ByteArray.size_append, hsz]; omega))]

private theorem readLen_encodeLen_two (pre : ByteArray) (n : Nat) (tail : ByteArray)
    (hlo : 0x100 ≤ n) (hn : n ≤ 0xffff) (ht : n ≤ tail.size) :
    readLen (pre ++ (encodeLen n ++ tail)) pre.size
      = some (n, pre.size + (encodeLen n).size) := by
  have henc : encodeLen n
      = ByteArray.mk #[0x82, UInt8.ofNat (n / 256), UInt8.ofNat (n % 256)] := by
    simp [encodeLen, Nat.not_lt.mpr (show 0x80 ≤ n by omega), Nat.not_lt.mpr hlo]
  have hsz : (encodeLen n).size = 3 := by rw [henc]; rfl
  have h0 : byteAt? (pre ++ (encodeLen n ++ tail)) pre.size = some 0x82 := by
    have h := byteAt?_append_right pre (encodeLen n ++ tail) 0
    rw [Nat.add_zero] at h
    rw [h, byteAt?_append_left _ _ 0 (by omega), henc]
    rfl
  have h1 : byteAt? (pre ++ (encodeLen n ++ tail)) (pre.size + 1)
      = some (UInt8.ofNat (n / 256)) := by
    rw [byteAt?_append_right pre (encodeLen n ++ tail) 1,
      byteAt?_append_left _ _ 1 (by omega), henc]
    rfl
  have h2 : byteAt? (pre ++ (encodeLen n ++ tail)) (pre.size + 2)
      = some (UInt8.ofNat (n % 256)) := by
    rw [byteAt?_append_right pre (encodeLen n ++ tail) 2,
      byteAt?_append_left _ _ 2 (by omega), henc]
    rfl
  have hhi : (UInt8.ofNat (n / 256)).toNat = n / 256 := by
    simp [Nat.mod_eq_of_lt (show n / 256 < 256 by omega)]
  have hlo2 : (UInt8.ofNat (n % 256)).toNat = n % 256 := by
    simp [Nat.mod_eq_of_lt (show n % 256 < 256 by omega)]
  have hsum : (UInt8.ofNat (n / 256)).toNat * 256 + (UInt8.ofNat (n % 256)).toNat = n := by
    rw [hhi, hlo2]; omega
  have h130 : (0x82 : UInt8).toNat = 130 := rfl
  rw [readLen, h0]
  simp only [Option.bind_eq_bind, Option.bind_some, h1, h2, hsum, hsz, h130]
  rw [if_neg (by omega), if_neg (by decide), if_pos (by decide),
    if_pos (And.intro (by omega)
      (by rw [ByteArray.size_append, ByteArray.size_append, hsz]; omega))]

/-- `readLen` reads back the length `encodeLen` wrote, and reports the
offset just past the length octets. The encoder's domain is the
two-octet form (X.690 §10.1), and the length must fit the bytes that
follow, which is what the reader checks. -/
theorem readLen_encodeLen (pre : ByteArray) (n : Nat) (tail : ByteArray)
    (hn : n ≤ 0xffff) (ht : n ≤ tail.size) :
    readLen (pre ++ (encodeLen n ++ tail)) pre.size
      = some (n, pre.size + (encodeLen n).size) := by
  rcases Nat.lt_or_ge n 0x80 with h | h
  · exact readLen_encodeLen_short pre n tail h ht
  · rcases Nat.lt_or_ge n 0x100 with h2 | h2
    · exact readLen_encodeLen_one pre n tail h h2 ht
    · exact readLen_encodeLen_two pre n tail h2 hn ht

/-- Length canonicality (X.690 §10.1): every length `readLen` accepts
is written exactly as `encodeLen` writes it — the octets consumed are
`encodeLen`'s own — and the content it announces fits the array. A
non-minimal length octet string therefore has no accepting reader. -/
theorem readLen_canonical (b : ByteArray) (off len co : Nat)
    (h : readLen b off = some (len, co)) :
    co = off + (encodeLen len).size ∧ co + len ≤ b.size ∧
      slice b off (encodeLen len).size = encodeLen len := by
  unfold readLen at h
  cases hb : byteAt? b off with
  | none => rw [hb] at h; simp at h
  | some first =>
    rw [hb] at h
    simp only [Option.bind_eq_bind, Option.bind_some] at h
    have hlt : off < b.size := lt_of_byteAt? b off first hb
    have hbe : b[off] = first := getElem_of_byteAt? b off first hb hlt
    by_cases hf : first.toNat < 0x80
    · rw [if_pos hf] at h
      by_cases hle : off + 1 + first.toNat ≤ b.size
      · rw [if_pos hle] at h
        simp only [Option.some.injEq, Prod.mk.injEq] at h
        obtain ⟨rfl, rfl⟩ := h
        have henc : encodeLen first.toNat = ByteArray.mk #[UInt8.ofNat first.toNat] := by
          simp [encodeLen, hf]
        have hsz : (encodeLen first.toNat).size = 1 := by rw [henc]; rfl
        refine ⟨by omega, by omega, ?_⟩
        rw [hsz, slice, ByteArray.extract_add_one (by omega), henc, hbe]
        simp only [ofNat_toNat]
        rfl
      · rw [if_neg hle] at h; simp at h
    · rw [if_neg hf] at h
      by_cases h81 : (first.toNat == 129) = true
      · rw [if_pos h81] at h
        cases hb1 : byteAt? b (off + 1) with
        | none => rw [hb1] at h; simp at h
        | some l =>
          rw [hb1] at h
          simp only [Option.bind_some] at h
          by_cases hc : 128 ≤ l.toNat ∧ off + 2 + l.toNat ≤ b.size
          · rw [if_pos hc] at h
            simp only [Option.some.injEq, Prod.mk.injEq] at h
            obtain ⟨rfl, rfl⟩ := h
            have hlt1 : off + 1 < b.size := lt_of_byteAt? b (off + 1) l hb1
            have hbe1 : b[off + 1] = l := getElem_of_byteAt? b (off + 1) l hb1 hlt1
            have hfirst : first = 0x81 := by
              apply UInt8.toNat_inj.mp
              have h129 : (0x81 : UInt8).toNat = 129 := rfl
              rw [h129]
              exact eq_of_beq h81
            have henc : encodeLen l.toNat = ByteArray.mk #[0x81, UInt8.ofNat l.toNat] := by
              have hlt256 : l.toNat < 256 := l.toNat_lt
              simp [encodeLen, Nat.not_lt.mpr hc.1, hlt256]
            have hsz : (encodeLen l.toNat).size = 2 := by rw [henc]; rfl
            refine ⟨by omega, by omega, ?_⟩
            rw [hsz, slice, ByteArray.extract_add_two (by omega), henc, hbe, hbe1, hfirst]
            simp only [ofNat_toNat]
            rfl
          · rw [if_neg hc] at h; simp at h
      · rw [if_neg h81] at h
        by_cases h82 : (first.toNat == 130) = true
        · rw [if_pos h82] at h
          cases hb1 : byteAt? b (off + 1) with
          | none => rw [hb1] at h; simp at h
          | some hi =>
            cases hb2 : byteAt? b (off + 2) with
            | none => rw [hb1, hb2] at h; simp at h
            | some lo =>
              rw [hb1, hb2] at h
              simp only [Option.bind_some] at h
              by_cases hc : 256 ≤ hi.toNat * 256 + lo.toNat ∧
                  off + 3 + (hi.toNat * 256 + lo.toNat) ≤ b.size
              · rw [if_pos hc] at h
                simp only [Option.some.injEq, Prod.mk.injEq] at h
                obtain ⟨rfl, rfl⟩ := h
                have hlt1 : off + 1 < b.size := lt_of_byteAt? b (off + 1) hi hb1
                have hlt2 : off + 2 < b.size := lt_of_byteAt? b (off + 2) lo hb2
                have hbe1 : b[off + 1] = hi := getElem_of_byteAt? b (off + 1) hi hb1 hlt1
                have hbe2 : b[off + 2] = lo := getElem_of_byteAt? b (off + 2) lo hb2 hlt2
                have hfirst : first = 0x82 := by
                  apply UInt8.toNat_inj.mp
                  have h130 : (0x82 : UInt8).toNat = 130 := rfl
                  rw [h130]
                  exact eq_of_beq h82
                have hhi : hi.toNat < 256 := hi.toNat_lt
                have hlo : lo.toNat < 256 := lo.toNat_lt
                have hdiv : (hi.toNat * 256 + lo.toNat) / 256 = hi.toNat := by omega
                have hmod : (hi.toNat * 256 + lo.toNat) % 256 = lo.toNat := by omega
                have henc : encodeLen (hi.toNat * 256 + lo.toNat)
                    = ByteArray.mk #[0x82, UInt8.ofNat hi.toNat, UInt8.ofNat lo.toNat] := by
                  rw [encodeLen, if_neg (by omega), if_neg (by omega), hdiv, hmod]
                have hsz : (encodeLen (hi.toNat * 256 + lo.toNat)).size = 3 := by
                  rw [henc]; rfl
                refine ⟨by omega, by omega, ?_⟩
                rw [hsz, slice, ByteArray.extract_add_three (by omega), henc, hbe, hbe1, hbe2,
                  hfirst]
                simp only [ofNat_toNat]
                rfl
              · rw [if_neg hc] at h; simp at h
        · rw [if_neg h82] at h; simp at h

/-! ### The TLV codec (X.690 §8.1) -/

/-- A TLV with bytes after it, split at its three parts. -/
private theorem tlv_append (tag : UInt8) (content rest : ByteArray) :
    tlv tag content ++ rest
      = ByteArray.mk #[tag] ++ (encodeLen content.size ++ (content ++ rest)) := by
  rw [tlv, ByteArray.append_assoc, ByteArray.append_assoc]

/-- `readTlv` reads back what `tlv` wrote: the same tag, the content
bytes unchanged, and the offset of the first byte after the TLV —
whatever follows it in the array. `tlv` truncates the length above
0xffff (X.690 §10.1 in `encodeLen`'s two-octet domain), so the
content is capped there. -/
theorem readTlv_tlv (tag : UInt8) (content rest : ByteArray)
    (h : content.size ≤ 0xffff) :
    readTlv (tlv tag content ++ rest) 0 tag = some (content, (tlv tag content).size) := by
  have hmid : ∀ (A B C : ByteArray) (i j : Nat),
      (A ++ (B ++ C)).extract (A.size + (B.size + i)) (A.size + (B.size + j))
        = C.extract i j := by
    intro A B C i j
    rw [ByteArray.extract_append_size_add' rfl, ByteArray.extract_append_size_add' rfl]
  have h1 : (ByteArray.mk #[tag]).size = 1 := rfl
  have hlen := readLen_encodeLen (ByteArray.mk #[tag]) content.size (content ++ rest) h
    (by rw [ByteArray.size_append]; omega)
  rw [h1] at hlen
  have h0 : byteAt? (ByteArray.mk #[tag] ++ (encodeLen content.size ++ (content ++ rest))) 0
      = some tag := by
    rw [byteAt?_append_left _ _ 0 (by omega)]
    rfl
  have hs : slice (ByteArray.mk #[tag] ++ (encodeLen content.size ++ (content ++ rest)))
      (1 + (encodeLen content.size).size) content.size = content := by
    rw [slice,
      show 1 + (encodeLen content.size).size
        = (ByteArray.mk #[tag]).size + ((encodeLen content.size).size + 0) by omega,
      show (ByteArray.mk #[tag]).size + ((encodeLen content.size).size + 0) + content.size
        = (ByteArray.mk #[tag]).size + ((encodeLen content.size).size + content.size) by omega,
      hmid, ByteArray.extract_append_eq_left rfl]
  have hsize : (tlv tag content).size
      = 1 + (encodeLen content.size).size + content.size := by
    rw [tlv, ByteArray.size_append, ByteArray.size_append, h1]
  rw [readTlv, tlv_append, h0]
  simp only [Option.bind_eq_bind, Option.bind_some, beq_self_eq_true, Nat.zero_add]
  rw [hlen]
  simp only [Option.bind_some, hs, hsize]
  rfl

/-- The tag is checked, not assumed: reading a TLV under any other tag
fails (X.690 §8.1.2). -/
theorem readTlv_tlv_ne (tag want : UInt8) (content rest : ByteArray) (h : want ≠ tag) :
    readTlv (tlv tag content ++ rest) 0 want = none := by
  have h1 : (ByteArray.mk #[tag]).size = 1 := rfl
  have h0 : byteAt? (ByteArray.mk #[tag] ++ (encodeLen content.size ++ (content ++ rest))) 0
      = some tag := by
    rw [byteAt?_append_left _ _ 0 (by omega)]
    rfl
  rw [readTlv, tlv_append, h0]
  simp only [Option.bind_eq_bind, Option.bind_some]
  rw [guard_neg (by simpa using fun hc => h (by rw [hc]))]
  rfl

/-- TLV canonicality (X.690 §8.1 with §10.1): the bytes `readTlv`
consumes are exactly `tlv` applied to the tag and the content it
returned, so the accepted encoding of a value is unique and the end
offset is the start plus that encoding's length. -/
theorem readTlv_canonical (b : ByteArray) (off : Nat) (tag : UInt8) (c : ByteArray)
    (off' : Nat) (h : readTlv b off tag = some (c, off')) :
    off' = off + (tlv tag c).size ∧ off' ≤ b.size ∧
      slice b off (tlv tag c).size = tlv tag c := by
  unfold readTlv at h
  cases hb : byteAt? b off with
  | none => rw [hb] at h; simp at h
  | some t =>
    rw [hb] at h
    simp only [Option.bind_eq_bind, Option.bind_some] at h
    by_cases ht : (t == tag) = true
    · rw [guard_pos ht] at h
      simp only [Option.bind_some] at h
      cases hl : readLen b (off + 1) with
      | none => rw [hl] at h; simp at h
      | some p =>
        obtain ⟨len, co⟩ := p
        rw [hl] at h
        simp only [Option.bind_some, Option.some.injEq, Prod.mk.injEq] at h
        obtain ⟨rfl, rfl⟩ := h
        obtain ⟨hco, hfit, hslice⟩ := readLen_canonical b (off + 1) len co hl
        have hlt : off < b.size := lt_of_byteAt? b off t hb
        have hbe : b[off] = tag := by
          rw [getElem_of_byteAt? b off t hb hlt]
          exact eq_of_beq ht
        have hcsz : (slice b co len).size = len := by
          rw [slice, ByteArray.size_extract]
          omega
        have htlv : (tlv tag (slice b co len)).size = 1 + (encodeLen len).size + len := by
          rw [tlv, ByteArray.size_append, ByteArray.size_append, hcsz]
          rfl
        refine ⟨by omega, by omega, ?_⟩
        rw [htlv, slice,
          ByteArray.extract_eq_extract_append_extract (off + 1 + (encodeLen len).size)
            (by omega) (by omega),
          ByteArray.extract_eq_extract_append_extract (off + 1) (by omega) (by omega),
          ByteArray.extract_add_one (by omega), hbe, tlv, hcsz]
        congr 1
        · have hsl : b.extract (off + 1) (off + 1 + (encodeLen len).size) = encodeLen len :=
            hslice
          rw [hsl]
          rfl
        · rw [slice, hco]
          congr 1
          omega
    · rw [guard_neg ht] at h; simp at h

/-! ### Big-endian values -/

private def beVal (l : List UInt8) : Nat := l.foldl (fun acc v => acc * 256 + v.toNat) 0

private theorem beVal_foldl (l : List UInt8) : ∀ a : Nat,
    l.foldl (fun acc v => acc * 256 + v.toNat) a = a * 256 ^ l.length + beVal l := by
  induction l with
  | nil => intro a; simp [beVal]
  | cons x xs ih =>
    intro a
    have hb : beVal (x :: xs) = x.toNat * 256 ^ xs.length + beVal xs := by
      have hu : beVal (x :: xs)
          = List.foldl (fun acc v => acc * 256 + v.toNat) (0 * 256 + x.toNat) xs := rfl
      rw [hu, Nat.zero_mul, Nat.zero_add, ih x.toNat]
    rw [List.foldl_cons, ih (a * 256 + x.toNat), hb, List.length_cons, Nat.pow_succ,
      Nat.add_mul, Nat.mul_assoc, Nat.mul_comm 256 (256 ^ xs.length), Nat.add_assoc]

private theorem beVal_cons (x : UInt8) (t : List UInt8) :
    beVal (x :: t) = x.toNat * 256 ^ t.length + beVal t := by
  have hu : beVal (x :: t)
      = List.foldl (fun acc v => acc * 256 + v.toNat) (0 * 256 + x.toNat) t := rfl
  rw [hu, Nat.zero_mul, Nat.zero_add, beVal_foldl t x.toNat]

private theorem beVal_lt (l : List UInt8) : beVal l < 256 ^ l.length := by
  induction l with
  | nil => simp [beVal]
  | cons x xs ih =>
    rw [beVal_cons, List.length_cons, Nat.pow_succ]
    have hx : x.toNat + 1 ≤ 256 := by have := x.toNat_lt; omega
    have h1 : (x.toNat + 1) * 256 ^ xs.length ≤ 256 * 256 ^ xs.length :=
      Nat.mul_le_mul_right _ hx
    have h2 : x.toNat * 256 ^ xs.length + 256 ^ xs.length = (x.toNat + 1) * 256 ^ xs.length := by
      rw [Nat.add_mul, Nat.one_mul]
    have h3 := Nat.mul_comm 256 (256 ^ xs.length)
    omega

private theorem beVal_inj : ∀ (l1 l2 : List UInt8), l1.length = l2.length →
    beVal l1 = beVal l2 → l1 = l2 := by
  intro l1
  induction l1 with
  | nil => intro l2 hl _; cases l2 <;> simp_all
  | cons x xs ih =>
    intro l2 hl hv
    cases l2 with
    | nil => simp at hl
    | cons y ys =>
      have hlen : xs.length = ys.length := by simpa using hl
      rw [beVal_cons, beVal_cons, hlen] at hv
      have hp : 0 < 256 ^ ys.length := Nat.pow_pos (by omega)
      have hb1 : beVal xs < 256 ^ ys.length := by rw [← hlen]; exact beVal_lt xs
      have hb2 : beVal ys < 256 ^ ys.length := beVal_lt ys
      have hx : x.toNat = y.toNat := by
        have e1 : (256 ^ ys.length * x.toNat + beVal xs) / 256 ^ ys.length = x.toNat := by
          rw [Nat.mul_add_div hp, Nat.div_eq_of_lt hb1, Nat.add_zero]
        have e2 : (256 ^ ys.length * y.toNat + beVal ys) / 256 ^ ys.length = y.toNat := by
          rw [Nat.mul_add_div hp, Nat.div_eq_of_lt hb2, Nat.add_zero]
        rw [Nat.mul_comm (256 ^ ys.length) x.toNat] at e1
        rw [Nat.mul_comm (256 ^ ys.length) y.toNat] at e2
        rw [← e1, ← e2, hv]
      have hrest : beVal xs = beVal ys := by rw [hx] at hv; omega
      rw [UInt8.toNat_inj.mp hx, ih ys hlen hrest]

private theorem bytesToNatBE_eq_beVal (b : ByteArray) : bytesToNatBE b = beVal b.data.toList := by
  rw [bytesToNatBE, byteArray_foldl_eq]
  rfl

private theorem length_toList (b : ByteArray) : b.data.toList.length = b.size := by
  rw [Array.length_toList]
  rfl

private theorem toList_eq_cons (b : ByteArray) (h : 0 < b.size) :
    b.data.toList = b[0]! :: b.data.toList.tail := by
  have hne : b.data.toList ≠ [] := by
    intro he
    have hl := length_toList b
    rw [he] at hl
    simp at hl
    omega
  have hhead : b.data.toList.head hne = b[0]! := by
    rw [List.head_eq_getElem, getElem!_pos b 0 h]
    simp [ByteArray.getElem_eq_getElem_data]
  rw [← hhead]
  exact (List.cons_head_tail hne).symm

private theorem pow256 (k : Nat) : (2 : Nat) ^ (8 * k) = 256 ^ k := by
  rw [Nat.pow_mul]

/-- A big-endian byte string denotes a value below `256 ^ size`. -/
theorem bytesToNatBE_lt (b : ByteArray) : bytesToNatBE b < 256 ^ b.size := by
  rw [bytesToNatBE_eq_beVal, ← length_toList]
  exact beVal_lt _

/-- Re-encoding a decoded value at the width it was read from returns
the original bytes: `bytesToNatBE` loses nothing at a fixed size. -/
theorem natToBytesBE_bytesToNatBE (b : ByteArray) :
    natToBytesBE (bytesToNatBE b) b.size = b := by
  have hsz := natToBytesBE_size (bytesToNatBE b) b.size
  have hval : bytesToNatBE (natToBytesBE (bytesToNatBE b) b.size) = bytesToNatBE b := by
    rw [bytesToNatBE_natToBytesBE, pow256, Nat.mod_eq_of_lt (bytesToNatBE_lt b)]
  apply ByteArray.ext
  apply Array.toList_inj.mp
  refine beVal_inj _ _ ?_ ?_
  · rw [length_toList, length_toList, hsz]
  · rw [← bytesToNatBE_eq_beVal, ← bytesToNatBE_eq_beVal, hval]

/-- A leading byte that is not zero puts the value at or above
`256 ^ (size - 1)`: the byte string carries no slack. -/
theorem bytesToNatBE_ge (b : ByteArray) (h : 0 < b.size) (h0 : b[0]! ≠ 0) :
    256 ^ (b.size - 1) ≤ bytesToNatBE b := by
  have hc := toList_eq_cons b h
  have hlen : b.data.toList.tail.length = b.size - 1 := by
    have h2 := length_toList b
    rw [hc, List.length_cons] at h2
    omega
  have hx : 1 ≤ b[0]!.toNat := by
    rcases Nat.eq_zero_or_pos b[0]!.toNat with hz | hp
    · exact absurd (UInt8.toNat_inj.mp (by rw [hz]; rfl)) h0
    · omega
  rw [bytesToNatBE_eq_beVal, hc, beVal_cons, hlen]
  have hm := Nat.mul_le_mul_right (256 ^ (b.size - 1)) hx
  omega

/-! ### Minimal INTEGER content (X.690 §8.3.2) -/

private theorem natBytesMin_lt (v : Nat) :
    v < 256 ^ (if v == 0 then 1 else Nat.log2 v / 8 + 1) := by
  rcases Nat.eq_zero_or_pos v with rfl | hv
  · simp
  · rw [if_neg (by simp; omega)]
    have h1 : v < 2 ^ (Nat.log2 v + 1) := Nat.lt_log2_self
    have h2 : Nat.log2 v + 1 ≤ 8 * (Nat.log2 v / 8 + 1) := by omega
    have h3 : (2 : Nat) ^ (Nat.log2 v + 1) ≤ 2 ^ (8 * (Nat.log2 v / 8 + 1)) :=
      Nat.pow_le_pow_right (by omega) h2
    rw [← pow256]
    omega

private theorem natBytesMin_ge (v : Nat) (hv : v ≠ 0) :
    256 ^ ((if v == 0 then 1 else Nat.log2 v / 8 + 1) - 1) ≤ v := by
  rw [if_neg (by simp; omega), Nat.add_sub_cancel, ← pow256]
  have h1 : (2 : Nat) ^ (8 * (Nat.log2 v / 8)) ≤ 2 ^ Nat.log2 v :=
    Nat.pow_le_pow_right (by omega) (by omega)
  have h2 : (2 : Nat) ^ Nat.log2 v ≤ v := Nat.log2_self_le hv
  omega

private theorem minLen_unique (v k : Nat) (hk : 0 < k) (h1 : 256 ^ (k - 1) ≤ v)
    (h2 : v < 256 ^ k) : (if v == 0 then 1 else Nat.log2 v / 8 + 1) = k := by
  have hp : 0 < 256 ^ (k - 1) := Nat.pow_pos (by omega)
  have hv : v ≠ 0 := by omega
  rw [if_neg (by simp; omega)]
  rw [← pow256] at h1
  rw [← pow256] at h2
  have e1 : 8 * (k - 1) ≤ Nat.log2 v := (Nat.le_log2 hv).mpr h1
  have e2 : Nat.log2 v < 8 * k := (Nat.log2_lt hv).mpr h2
  omega

/-- `natBytesMin` writes one byte for zero, else `⌊log2 v⌋ / 8 + 1`. -/
theorem natBytesMin_size (v : Nat) :
    (natBytesMin v).size = if v == 0 then 1 else Nat.log2 v / 8 + 1 :=
  natToBytesBE_size _ _

private theorem natBytesMin_size_pos (v : Nat) : 0 < (natBytesMin v).size := by
  rw [natBytesMin_size]
  split <;> omega

/-- `natBytesMin` encodes the value it is given. -/
theorem bytesToNatBE_natBytesMin (v : Nat) : bytesToNatBE (natBytesMin v) = v := by
  rw [natBytesMin, bytesToNatBE_natToBytesBE, pow256]
  exact Nat.mod_eq_of_lt (natBytesMin_lt v)

/-- Minimality is exactly the absence of a leading zero byte: any byte
string that starts with a nonzero byte is the one `natBytesMin` writes
for its value. -/
theorem natBytesMin_bytesToNatBE (b : ByteArray) (h : 0 < b.size) (h0 : b[0]! ≠ 0) :
    natBytesMin (bytesToNatBE b) = b := by
  rw [natBytesMin,
    minLen_unique (bytesToNatBE b) b.size h (bytesToNatBE_ge b h h0) (bytesToNatBE_lt b),
    natToBytesBE_bytesToNatBE]

/-- `natBytesMin` never writes a leading zero byte for a nonzero value
(X.690 §8.3.2); the single zero byte of `natBytesMin 0` is the one
exception. -/
theorem natBytesMin_head_ne_zero (v : Nat) (hv : v ≠ 0) : (natBytesMin v)[0]! ≠ 0 := by
  intro hz
  have hpos := natBytesMin_size_pos v
  have hc := toList_eq_cons (natBytesMin v) hpos
  have hlen : (natBytesMin v).data.toList.tail.length = (natBytesMin v).size - 1 := by
    have h2 := length_toList (natBytesMin v)
    rw [hc, List.length_cons] at h2
    omega
  have hval : bytesToNatBE (natBytesMin v) = v := bytesToNatBE_natBytesMin v
  rw [bytesToNatBE_eq_beVal, hc, beVal_cons, hlen, hz] at hval
  have hzero : (0 : UInt8).toNat = 0 := rfl
  rw [hzero, Nat.zero_mul, Nat.zero_add] at hval
  have hlt := beVal_lt (natBytesMin v).data.toList.tail
  rw [hlen] at hlt
  have hge := natBytesMin_ge v hv
  rw [← natBytesMin_size] at hge
  omega

private theorem and_0x80_cases (x : UInt8) : x &&& 0x80 = 0 ∨ x &&& 0x80 = 0x80 := by
  have h : ∀ n : Nat, n &&& 128 = 0 ∨ n &&& 128 = 128 := by
    intro n
    have hp : (128 : Nat) = 2 ^ 7 := rfl
    cases hb : n.testBit 7 with
    | false =>
      left
      apply Nat.eq_of_testBit_eq
      intro i
      rw [hp, Nat.testBit_and, Nat.testBit_two_pow, Nat.zero_testBit]
      cases hi : decide (7 = i) with
      | false => simp
      | true =>
        have h7 : 7 = i := of_decide_eq_true hi
        subst h7
        simp [hb]
    | true =>
      right
      apply Nat.eq_of_testBit_eq
      intro i
      rw [hp, Nat.testBit_and, Nat.testBit_two_pow]
      cases hi : decide (7 = i) with
      | false => simp
      | true =>
        have h7 : 7 = i := of_decide_eq_true hi
        subst h7
        simp [hb]
  have h80 : (0x80 : UInt8).toNat = 128 := rfl
  have h0 : (0 : UInt8).toNat = 0 := rfl
  rcases h x.toNat with h1 | h1
  · left
    apply UInt8.toNat_inj.mp
    rw [UInt8.toNat_and, h80, h0, h1]
  · right
    apply UInt8.toNat_inj.mp
    rw [UInt8.toNat_and, h80, h1]

private theorem bytesToNatBE_pad (c : ByteArray) :
    bytesToNatBE (ByteArray.mk #[0] ++ c) = bytesToNatBE c := by
  rw [bytesToNatBE, bytesToNatBE, byteArray_foldl_eq, byteArray_foldl_eq, ByteArray.data_append]
  simp

private theorem extract_head (c : ByteArray) (h : 1 < c.size) :
    (c.extract 1 c.size)[0]! = c[1]! := by
  have hs : (c.extract 1 c.size).size = c.size - 1 := by
    rw [ByteArray.size_extract]
    omega
  rw [getElem!_pos _ 0 (by omega), getElem!_pos c 1 (by omega), ByteArray.getElem_extract]

private theorem pad_split (c : ByteArray) (h : 0 < c.size) (h0 : c[0]! = 0) :
    ByteArray.mk #[0] ++ c.extract 1 c.size = c := by
  have hone : (ByteArray.mk #[0]).size = 1 := rfl
  have hs : (c.extract 1 c.size).size = c.size - 1 := by
    rw [ByteArray.size_extract]
    omega
  refine ByteArray.ext_getElem ?_ ?_
  · rw [ByteArray.size_append, hone, hs]
    omega
  · intro i hi hi'
    rcases Nat.eq_zero_or_pos i with rfl | hpos
    · rw [ByteArray.getElem_append_left (by omega)]
      rw [getElem!_pos c 0 h] at h0
      rw [← h0]
      rfl
    · rw [ByteArray.getElem_append_right (by omega), ByteArray.getElem_extract]
      congr 1
      omega

/-! ### The DER INTEGER codec (X.690 §8.3) -/

/-- `readDerInt` reads back the value `derIntNat` wrote, and reports
the offset just past the INTEGER, whatever follows it. The bound is
`encodeLen`'s two-octet domain. -/
theorem readDerInt_derIntNat (v : Nat) (rest : ByteArray)
    (h : (natBytesMin v).size < 0xffff) :
    readDerInt (derIntNat v ++ rest) 0 = some (v, (derIntNat v).size) := by
  have hpos := natBytesMin_size_pos v
  have hraw : derIntNat v = tlv 0x02
      (if (natBytesMin v)[0]! &&& 0x80 == 0x80 then ByteArray.mk #[0] ++ natBytesMin v
       else natBytesMin v) := rfl
  have hone : (ByteArray.mk #[0]).size = 1 := rfl
  by_cases hp : ((natBytesMin v)[0]! &&& 0x80 == 0x80) = true
  · have hd : derIntNat v = tlv 0x02 (ByteArray.mk #[0] ++ natBytesMin v) := by
      rw [hraw, if_pos hp]
    have hsz : (ByteArray.mk #[0] ++ natBytesMin v).size ≤ 0xffff := by
      rw [ByteArray.size_append, hone]; omega
    have h0 : (ByteArray.mk #[0] ++ natBytesMin v)[0]! = 0 := by
      refine getElem!_of_byteAt? _ 0 0 ?_
      rw [byteAt?_append_left _ _ 0 (by omega)]
      rfl
    have h1 : (ByteArray.mk #[0] ++ natBytesMin v)[1]! = (natBytesMin v)[0]! := by
      refine getElem!_of_byteAt? _ 1 _ ?_
      have hr := byteAt?_append_right (ByteArray.mk #[0]) (natBytesMin v) 0
      rw [hone] at hr
      rw [hr]
      exact byteAt?_eq_some _ 0 hpos
    have hsize2 : (ByteArray.mk #[0] ++ natBytesMin v).size ≥ 2 := by
      rw [ByteArray.size_append, hone]; omega
    rw [readDerInt, hd, readTlv_tlv 0x02 _ rest hsz]
    simp only [Option.bind_eq_bind, Option.bind_some, h0, h1, bytesToNatBE_pad,
      bytesToNatBE_natBytesMin]
    have hne : (ByteArray.mk #[0] ++ natBytesMin v).size ≠ 0 := by omega
    rw [guard_pos hne, guard_pos (show ((0 : UInt8) &&& 0x80 == 0) = true from rfl)]
    simp only [Option.bind_some]
    rw [if_pos (And.intro (show ((0 : UInt8) == 0) = true from rfl) hsize2), guard_pos hp]
    rfl
  · have hd : derIntNat v = tlv 0x02 (natBytesMin v) := by rw [hraw, if_neg hp]
    have hsz : (natBytesMin v).size ≤ 0xffff := by omega
    have hz : (natBytesMin v)[0]! &&& 0x80 = 0 := by
      rcases and_0x80_cases (natBytesMin v)[0]! with hc | hc
      · exact hc
      · exact absurd (by rw [hc]; rfl) hp
    have hcond : ¬(((natBytesMin v)[0]! == 0) = true ∧ (natBytesMin v).size ≥ 2) := by
      intro hcc
      rcases Nat.eq_zero_or_pos v with rfl | hv
      · have h1 : (natBytesMin 0).size = 1 := by rw [natBytesMin_size]; rfl
        omega
      · exact natBytesMin_head_ne_zero v (by omega) (eq_of_beq hcc.1)
    rw [readDerInt, hd, readTlv_tlv 0x02 _ rest hsz]
    simp only [Option.bind_eq_bind, Option.bind_some, bytesToNatBE_natBytesMin]
    rw [guard_pos (show (natBytesMin v).size ≠ 0 by omega),
      guard_pos (show ((natBytesMin v)[0]! &&& 0x80 == 0) = true by rw [hz]; rfl)]
    simp only [Option.bind_some]
    rw [if_neg hcond]

/-- The reader's three content checks characterise minimality
(X.690 §8.3.2): content that is nonempty, has its top bit clear, and
carries a 0x00 pad only when the next byte needs one is exactly the
content `derIntNat` writes for the value it denotes. -/
theorem derIntNat_bytesToNatBE (c : ByteArray) (hne : c.size ≠ 0)
    (hsign : c[0]! &&& 0x80 = 0)
    (hmin : c[0]! = 0 → 2 ≤ c.size → c[1]! &&& 0x80 = 0x80) :
    derIntNat (bytesToNatBE c) = tlv 0x02 c := by
  have hraw : derIntNat (bytesToNatBE c) = tlv 0x02
      (if (natBytesMin (bytesToNatBE c))[0]! &&& 0x80 == 0x80 then
        ByteArray.mk #[0] ++ natBytesMin (bytesToNatBE c)
       else natBytesMin (bytesToNatBE c)) := rfl
  rw [hraw]
  congr 1
  by_cases h0 : c[0]! = 0
  · by_cases h2 : 2 ≤ c.size
    · have hts : (c.extract 1 c.size).size = c.size - 1 := by
        rw [ByteArray.size_extract]; omega
      have ht0 : (c.extract 1 c.size)[0]! = c[1]! := extract_head c (by omega)
      have hb := hmin h0 h2
      have htne : (c.extract 1 c.size)[0]! ≠ 0 := by
        rw [ht0]
        intro hc
        rw [hc] at hb
        exact absurd hb (by decide)
      have hsplit := pad_split c (by omega) h0
      have hv : bytesToNatBE c = bytesToNatBE (c.extract 1 c.size) := by
        have hpad := bytesToNatBE_pad (c.extract 1 c.size)
        rw [hsplit] at hpad
        exact hpad
      have hnm : natBytesMin (bytesToNatBE c) = c.extract 1 c.size := by
        rw [hv]
        exact natBytesMin_bytesToNatBE _ (by omega) htne
      rw [hnm, ht0, if_pos (by rw [hb]; rfl)]
      exact hsplit
    · have hcl := toList_eq_cons c (by omega)
      have htail : c.data.toList.tail = [] := by
        have hl := length_toList c
        rw [hcl, List.length_cons] at hl
        exact List.length_eq_zero_iff.mp (by omega)
      have hv0 : bytesToNatBE c = 0 := by
        rw [bytesToNatBE_eq_beVal, hcl, beVal_cons, htail, h0]
        rfl
      have hnm : natBytesMin (bytesToNatBE c) = c := by
        rw [hv0, natBytesMin]
        have h1 : c.size = 1 := by omega
        rw [← h1]
        have hb := natToBytesBE_bytesToNatBE c
        rw [hv0] at hb
        simpa using hb
      rw [hnm, h0, if_neg (by decide)]
  · have hnm : natBytesMin (bytesToNatBE c) = c :=
      natBytesMin_bytesToNatBE c (by omega) h0
    rw [hnm, if_neg (by rw [hsign]; decide)]

/-- INTEGER canonicality (X.690 §8.3.2): the bytes `readDerInt`
consumes are exactly `derIntNat` applied to the value it returned. A
non-minimal INTEGER — a redundant 0x00 pad, or a non-minimal length —
has no accepting reader, so one value has one accepted encoding. -/
theorem readDerInt_canonical (b : ByteArray) (off v off' : Nat)
    (h : readDerInt b off = some (v, off')) :
    off' = off + (derIntNat v).size ∧ slice b off (derIntNat v).size = derIntNat v := by
  unfold readDerInt at h
  cases hr : readTlv b off 0x02 with
  | none => rw [hr] at h; simp at h
  | some p =>
    obtain ⟨c, o⟩ := p
    rw [hr] at h
    simp only [Option.bind_eq_bind, Option.bind_some] at h
    by_cases g1 : c.size ≠ 0
    · rw [guard_pos g1] at h
      simp only [Option.bind_some] at h
      by_cases g2 : (c[0]! &&& 0x80 == 0) = true
      · rw [guard_pos g2] at h
        simp only [Option.bind_some] at h
        have hfin : ∀ hmin : c[0]! = 0 → 2 ≤ c.size → c[1]! &&& 0x80 = 0x80,
            v = bytesToNatBE c → off' = o →
            off' = off + (derIntNat v).size ∧
              slice b off (derIntNat v).size = derIntNat v := by
          intro hmin hv ho
          obtain ⟨hoff, _, hs⟩ := readTlv_canonical b off 0x02 c o hr
          rw [hv, derIntNat_bytesToNatBE c g1 (eq_of_beq g2) hmin, ho]
          exact ⟨hoff, hs⟩
        by_cases g3 : ((c[0]! == 0) = true ∧ c.size ≥ 2)
        · rw [if_pos g3] at h
          by_cases g4 : (c[1]! &&& 0x80 == 0x80) = true
          · rw [guard_pos g4] at h
            simp only [Option.bind_some, Option.some.injEq, Prod.mk.injEq] at h
            exact hfin (fun _ _ => eq_of_beq g4) h.1.symm h.2.symm
          · rw [guard_neg g4] at h; simp at h
        · rw [if_neg g3] at h
          simp only [Option.some.injEq, Prod.mk.injEq] at h
          refine hfin (fun hc0 hc2 => absurd ⟨?_, hc2⟩ g3) h.1.symm h.2.symm
          simp [hc0]
      · rw [guard_neg g2] at h; simp at h
    · rw [guard_neg g1] at h; simp at h

/-! ### OID subidentifiers (X.690 §8.19.2) -/

private def oidStep (st : Bool × Bool) (b : UInt8) : Bool × Bool :=
  (st.1 && !(st.2 && b == 0x80), b &&& 0x80 == 0)

private theorem oidMinimal_eq (oid : ByteArray) :
    oidMinimal oid =
      ((oid.data.toList.foldl oidStep (true, true)).1 &&
        (oid.data.toList.foldl oidStep (true, true)).2) := by
  rw [oidMinimal, byteArray_foldl_eq]
  rfl

/-- A rejection is permanent: once the walk has seen a bad
subidentifier start, no later byte clears it. -/
private theorem oidStep_false (l : List UInt8) : ∀ st : Bool × Bool, st.1 = false →
    (l.foldl oidStep st).1 = false := by
  induction l with
  | nil => intro st h; exact h
  | cons x xs ih =>
    intro st h
    refine ih (oidStep st x) ?_
    simp [oidStep, h]

private theorem data_toList_append (a b : ByteArray) :
    (a ++ b).data.toList = a.data.toList ++ b.data.toList := by
  rw [ByteArray.data_append]
  simp

/-- Empty content passes: `oidMinimal` states the subidentifier
discipline and nothing about length, so `readExtension` guards
`oid.size ≠ 0` itself. -/
theorem oidMinimal_empty : oidMinimal ByteArray.empty = true := rfl

/-- The last octet completes its subidentifier: its top bit is clear,
so the content never ends mid-subidentifier (X.690 §8.19.2). -/
theorem oidMinimal_last (pre : ByteArray) (x : UInt8)
    (h : oidMinimal (pre ++ ByteArray.mk #[x]) = true) : x &&& 0x80 = 0 := by
  rw [oidMinimal_eq, data_toList_append] at h
  have hl : (ByteArray.mk #[x]).data.toList = [x] := rfl
  rw [hl, List.foldl_append] at h
  simp only [List.foldl_cons, List.foldl_nil, Bool.and_eq_true] at h
  exact eq_of_beq h.2

/-- The first subidentifier does not open with the pad octet 0x80
(X.690 §8.19.2: base-128 digits carry no leading zero). -/
theorem oidMinimal_head_ne_pad (post : ByteArray) (y : UInt8)
    (h : oidMinimal (ByteArray.mk #[y] ++ post) = true) : y ≠ 0x80 := by
  intro hy
  rw [oidMinimal_eq, data_toList_append] at h
  have hl : (ByteArray.mk #[y]).data.toList = [y] := rfl
  rw [hl, List.foldl_append] at h
  have hstep : (List.foldl oidStep (true, true) [y]).1 = false := by
    simp [oidStep, hy]
  rw [oidStep_false post.data.toList _ hstep] at h
  simp at h

/-- No later subidentifier opens with the pad octet either: `x` ends a
subidentifier (top bit clear), so the byte after it starts the next
one and is not 0x80 (X.690 §8.19.2). With `oidMinimal_head_ne_pad`
and `oidMinimal_last` this is the whole rule: every subidentifier
start is a byte other than 0x80, and the content ends on a complete
subidentifier. -/
theorem oidMinimal_no_pad (pre post : ByteArray) (x y : UInt8)
    (h : oidMinimal (pre ++ ByteArray.mk #[x] ++ (ByteArray.mk #[y] ++ post)) = true)
    (hx : x &&& 0x80 = 0) : y ≠ 0x80 := by
  intro hy
  rw [oidMinimal_eq, data_toList_append, data_toList_append, data_toList_append] at h
  have hlx : (ByteArray.mk #[x]).data.toList = [x] := rfl
  have hly : (ByteArray.mk #[y]).data.toList = [y] := rfl
  rw [hlx, hly, List.foldl_append, List.foldl_append, List.foldl_append] at h
  have hstep : ((List.foldl oidStep (List.foldl oidStep
      (List.foldl oidStep (true, true) pre.data.toList) [x]) [y])).1 = false := by
    simp [oidStep, hx, hy]
  rw [oidStep_false post.data.toList _ hstep] at h
  simp at h

end Spec.X509
