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

end Spec.X509
