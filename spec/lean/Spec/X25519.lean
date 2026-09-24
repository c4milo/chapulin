import Spec.Bytes

/-!
X25519 Diffie-Hellman scalar multiplication, RFC 7748 §5.

Everything is plain `Nat` arithmetic with an explicit `% p` after every
field operation, `p = 2^255 - 19` (§4.1). The ladder is the exact
pseudocode of §5: conditional swap driven by the running ladder bit,
working variables `x_2/z_2/x_3/z_3`, and `a24 = 121665`. Inversion is
Fermat's little theorem, `z^(p-2)`, via square-and-multiply that reduces
mod `p` at every step (no unreduced giant powers).
-/

namespace Spec.X25519

open Spec.Bytes

/-- Field prime `p = 2^255 - 19` (RFC 7748 §4.1). -/
def p : Nat := 2 ^ 255 - 19

/-- `a24 = (486662 - 2) / 4 = 121665` (RFC 7748 §5). -/
def a24 : Nat := 121665

/-- Square-and-multiply `b^e mod m`, reducing after every multiplication
so intermediates never exceed `m^2`. -/
def powMod (b e m : Nat) : Nat :=
  go (b % m) e (1 % m)
where
  go (b e acc : Nat) : Nat :=
    if _h : e = 0 then acc
    else go (b * b % m) (e / 2) (if e % 2 = 1 then acc * b % m else acc)
  termination_by e
  decreasing_by omega

/-- Field inversion by Fermat's little theorem: `z^(p-2) mod p`
(RFC 7748 §5 finishes the ladder with `x_2 * (z_2^(p - 2))`). -/
def finv (z : Nat) : Nat := powMod z (p - 2) p

/-- RFC 7748 §5 `decodeUCoordinate` for bits = 255: mask the most
significant bit of the final byte (`u_list[31] &= 0x7f`), then decode
little-endian. -/
def decodeUCoordinate (b : ByteArray) : Nat :=
  bytesToNatLE (b.set! 31 (b[31]! &&& 0x7f))

/-- RFC 7748 §5 `decodeScalar25519`: clamp with
`k[0] &= 248; k[31] &= 127; k[31] |= 64`, then decode little-endian. -/
def decodeScalar (b : ByteArray) : Nat :=
  let b := b.set! 0 (b[0]! &&& 248)
  let b := b.set! 31 ((b[31]! &&& 127) ||| 64)
  bytesToNatLE b

/-- RFC 7748 §5 `encodeUCoordinate`: reduce mod `p`, emit 32 bytes
little-endian. -/
def encodeUCoordinate (u : Nat) : ByteArray :=
  natToBytesLE (u % p) 32

/-- The Montgomery ladder of RFC 7748 §5 on decoded scalar `k` and
u-coordinate `u`: 255 iterations (`t = 254` down to `0`), conditional
swap on `swap ^= k_t`, then the §5 formulas
`A, AA, B, BB, E, C, D, DA, CB` and the updates
`x_3 = (DA + CB)^2`, `z_3 = x_1 * (DA - CB)^2`,
`x_2 = AA * BB`, `z_2 = E * (AA + a24 * E)`.
Returns the affine result `x_2 * z_2^(p-2) mod p`. Subtraction in GF(p)
is `(x + p - y) % p`; both operands are already reduced, so the `Nat`
difference never underflows. -/
def ladder (k u : Nat) : Nat := Id.run do
  let x1 := u % p
  let mut x2 : Nat := 1
  let mut z2 : Nat := 0
  let mut x3 := x1
  let mut z3 : Nat := 1
  let mut swap : Nat := 0
  for i in [0:255] do
    let t := 254 - i
    let kt := (k >>> t) &&& 1
    swap := swap ^^^ kt
    if swap = 1 then
      let tx := x2; x2 := x3; x3 := tx
      let tz := z2; z2 := z3; z3 := tz
    swap := kt
    let a  := (x2 + z2) % p
    let aa := a * a % p
    let bs := (x2 + p - z2) % p
    let bb := bs * bs % p
    let e  := (aa + p - bb) % p
    let c  := (x3 + z3) % p
    let d  := (x3 + p - z3) % p
    let da := d * a % p
    let cb := c * bs % p
    let s  := (da + cb) % p
    x3 := s * s % p
    let t2 := (da + p - cb) % p
    z3 := x1 * (t2 * t2 % p) % p
    x2 := aa * bb % p
    z2 := e * ((aa + a24 * e % p) % p) % p
  -- Final conditional swap (§5, after the loop body).
  if swap = 1 then
    let tx := x2; x2 := x3; x3 := tx
    let tz := z2; z2 := z3; z3 := tz
  return x2 * finv z2 % p

/-- X25519 (RFC 7748 §5): decode scalar and u-coordinate, run the
Montgomery ladder, encode the result. -/
def scalarMult (scalar point : ByteArray) : ByteArray :=
  encodeUCoordinate (ladder (decodeScalar scalar) (decodeUCoordinate point))

/-- X25519 with the base point `u = 9` (RFC 7748 §4.1, §6.1). -/
def base (scalar : ByteArray) : ByteArray :=
  scalarMult scalar (encodeUCoordinate 9)

/-- RFC 7748 test vectors: the two §5.2 single vectors, one iteration of
the §5.2 iteration test, and the §6.1 Diffie-Hellman public keys and
shared secret. -/
def selftest : Bool :=
  -- A malformed literal falls back to a 1-byte sentinel and breaks the
  -- length-sensitive checks instead of testing the empty string.
  let hx := fun s => (hexToBytes? s).getD (ByteArray.mk #[0])
  let sm := fun (k u r : String) => bytesToHex (scalarMult (hx k) (hx u)) == r
  -- §5.2 vector 1
  sm "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4"
     "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c"
     "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552" &&
  -- §5.2 vector 2 (u has the top bit set, exercising the mask)
  sm "4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d"
     "e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493"
     "95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957" &&
  -- §5.2 iteration test, one iteration (k = u = 9)
  sm "0900000000000000000000000000000000000000000000000000000000000000"
     "0900000000000000000000000000000000000000000000000000000000000000"
     "422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079" &&
  -- §6.1: public keys from the private keys, and the shared secret K
  let alicePriv := hx "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"
  let bobPriv := hx "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb"
  let alicePub := "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"
  let bobPub := "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"
  let shared := "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"
  bytesToHex (base alicePriv) == alicePub &&
  bytesToHex (base bobPriv) == bobPub &&
  bytesToHex (scalarMult alicePriv (hx bobPub)) == shared &&
  bytesToHex (scalarMult bobPriv (hx alicePub)) == shared


/-!
Clamping guarantees (RFC 7748 §5).

`decodeScalar` is the only place the secret scalar is shaped, and the
two facts it must establish are the ones the rest of X25519 silently
assumes. Neither is observable in a differential test against the C:
the C and this spec would agree byte for byte while both clamped
wrongly, so these are proved rather than compared.

* `decodeScalar_mul_eight` — the scalar is a multiple of the cofactor
  8, which is what places `k * P` in the prime-order subgroup and makes
  a small-subgroup attack on a hostile u-coordinate impossible.
* `decodeScalar_range` — the scalar has bit 254 set and bit 255 clear,
  which fixes the position of its leading bit, so the ladder's 255
  iterations are independent of the secret.

The argument is bit arithmetic over `bytesToNatLE`, no number theory
and no curve group. `bytesToNatLE` is re-read as `natLE` over the byte
list, dividing by `256 ^ i` is shown to be dropping `i` low bytes, and
then the low three bits of byte 0 and the top two bits of byte 31 are
read off that characterization.
-/

/-- Little-endian value of a byte list. `bytesToNatLE` folds over an
`Array`; this is the same fold over its `List`, where `cons` and `drop`
are available. -/
private def natLE (l : List UInt8) : Nat :=
  l.foldr (fun v acc => acc * 256 + v.toNat) 0

private theorem natLE_cons (v : UInt8) (vs : List UInt8) :
    natLE (v :: vs) = natLE vs * 256 + v.toNat := rfl

private theorem bytesToNatLE_eq_natLE (b : ByteArray) :
    bytesToNatLE b = natLE b.data.toList := by
  rw [bytesToNatLE, natLE, Array.foldr_toList]

/-- Dividing by 256 drops the low byte. -/
private theorem natLE_div_256 (l : List UInt8) : natLE l / 256 = natLE l.tail := by
  cases l with
  | nil => rfl
  | cons v vs =>
    have h_byte_lt : v.toNat < 256 := by have := v.toNat_lt; omega
    rw [natLE_cons, List.tail_cons]
    omega

/-- Dividing by `256 ^ i` drops the `i` low bytes. -/
private theorem natLE_div_pow (i : Nat) (l : List UInt8) :
    natLE l / 256 ^ i = natLE (l.drop i) := by
  induction i with
  | zero => simp
  | succ i ih =>
    calc natLE l / 256 ^ (i + 1)
        = natLE l / 256 ^ i / 256 := by rw [Nat.pow_succ, Nat.div_div_eq_div_mul]
      _ = natLE (l.drop i) / 256 := by rw [ih]
      _ = natLE (l.drop i).tail := natLE_div_256 _
      _ = natLE (l.drop (i + 1)) := by rw [List.tail_drop]

private theorem toList_length_eq_size (c : ByteArray) : c.data.toList.length = c.size :=
  Array.length_toList

private theorem getElem_toList_eq (c : ByteArray) (i : Nat) (h_lt : i < c.size) :
    c.data.toList[i]'(by rw [toList_length_eq_size]; exact h_lt) = c[i]! := by
  rw [getElem!_pos c i h_lt]
  simp [ByteArray.getElem_eq_getElem_data]

/-- Byte `i` is the low digit of what is left after dropping `i` bytes:
the base-256 digit extraction the two theorems below both need. -/
private theorem natLE_split (c : ByteArray) (i : Nat) (h_lt : i < c.size) :
    natLE (c.data.toList.drop i)
      = natLE (c.data.toList.drop (i + 1)) * 256 + (c[i]!).toNat := by
  have h_len : i < c.data.toList.length := by rw [toList_length_eq_size]; exact h_lt
  rw [List.drop_eq_getElem_cons h_len, natLE_cons, getElem_toList_eq c i h_lt]

/-- The clamped array `decodeScalar` decodes, named so the byte-level
lemmas can talk about it. `decodeScalar_eq_clamp` pins it to the
definition by `rfl`, so a change to the clamp breaks this proof rather
than leaving a stale copy behind. -/
private def clamp (b : ByteArray) : ByteArray :=
  let b := b.set! 0 (b[0]! &&& 248)
  b.set! 31 ((b[31]! &&& 127) ||| 64)

private theorem decodeScalar_eq_clamp (b : ByteArray) :
    decodeScalar b = bytesToNatLE (clamp b) := rfl

private theorem clamp_size (b : ByteArray) : (clamp b).size = b.size := by
  simp only [clamp, ByteArray.size_set!]

private theorem clamp_getElem_zero (b : ByteArray) (h_size : 0 < b.size) :
    (clamp b)[0]! = b[0]! &&& 248 := by
  simp only [clamp]
  rw [ByteArray.getElem!_set!_ne _ 31 0 _ (by omega)]
  exact ByteArray.getElem!_set!_self _ 0 _ h_size

private theorem clamp_getElem_31 (b : ByteArray) (h_size : 31 < b.size) :
    (clamp b)[31]! = ((b[31]! &&& 127) ||| 64) := by
  simp only [clamp]
  rw [ByteArray.getElem!_set!_self _ 31 _ (by rw [ByteArray.size_set!]; exact h_size)]
  rw [ByteArray.getElem!_set!_ne _ 0 31 _ (by omega)]

/-- `k[0] &= 248` clears bits 0, 1 and 2, leaving a multiple of 8. -/
private theorem and_248_mod_eight (v : UInt8) : (v &&& 248).toNat % 8 = 0 := by
  have h_mod_eq_and : ∀ x : Nat, x % 8 = x &&& 7 := by
    intro x
    simpa using (Nat.and_two_pow_sub_one_eq_mod x 3).symm
  have h_mask_meet : (248 : Nat) &&& 7 = 0 := by decide
  calc (v &&& 248).toNat % 8
      = (v.toNat &&& 248) &&& 7 := by rw [UInt8.toNat_and]; exact h_mod_eq_and _
    _ = v.toNat &&& (248 &&& 7) := Nat.and_assoc _ _ _
    _ = 0 := by rw [h_mask_meet, Nat.and_zero]

/-- `k[31] &= 127` clears bit 7 of the top byte and `k[31] |= 64` sets
bit 6, so the top byte lands in `[64, 128)`. -/
private theorem and_127_or_64_bounds (v : UInt8) :
    64 ≤ ((v &&& 127) ||| 64).toNat ∧ ((v &&& 127) ||| 64).toNat < 128 := by
  have h_toNat : ((v &&& 127) ||| 64).toNat = (v.toNat &&& 127) ||| 64 := by
    rw [UInt8.toNat_or, UInt8.toNat_and]
    rfl
  have h_low_lt : v.toNat &&& 127 < 2 ^ 7 := Nat.and_lt_two_pow v.toNat (by decide)
  have h_bit254_set : (64 : Nat) ≤ (v.toNat &&& 127) ||| 64 := Nat.right_le_or
  have h_bit255_clear : (v.toNat &&& 127) ||| 64 < 2 ^ 7 :=
    Nat.or_lt_two_pow h_low_lt (by decide)
  have h_pow : (2 : Nat) ^ 7 = 128 := by decide
  rw [h_toNat]
  omega

/-- A number whose base-`d` high digit lies in `[lo, hi]` lies in
`[d * lo, d * (hi + 1))`. -/
private theorem bounds_of_div (n d c lo hi : Nat) (h_pos : 0 < d)
    (h_div : n / d = c) (h_lo : lo ≤ c) (h_hi : c ≤ hi) :
    d * lo ≤ n ∧ n < d * (hi + 1) := by
  have h_div_mod : d * (n / d) + n % d = n := Nat.div_add_mod n d
  have h_rem_lt : n % d < d := Nat.mod_lt n h_pos
  rw [h_div] at h_div_mod
  have h_lo_le : d * lo ≤ d * c := Nat.mul_le_mul_left d h_lo
  have h_hi_le : d * c ≤ d * hi := Nat.mul_le_mul_left d h_hi
  have h_succ : d * (hi + 1) = d * hi + d := Nat.mul_succ d hi
  omega

/-- RFC 7748 §5 clamping (`k[0] &= 248`) clears the low three bits of
the first octet, so every decoded scalar is a multiple of the Curve25519
cofactor 8. This is what forces `k * P` into the prime-order subgroup
and makes a small-subgroup attack on an attacker-chosen u-coordinate
impossible: the order-8 component of any such point is annihilated.

No size hypothesis: byte 0 is the low digit, and `set!` out of range is
a no-op, so the property survives every array length, including the
empty one (which decodes to 0). -/
theorem decodeScalar_mul_eight (b : ByteArray) : decodeScalar b % 8 = 0 := by
  rw [decodeScalar_eq_clamp, bytesToNatLE_eq_natLE]
  cases Nat.eq_zero_or_pos (clamp b).size with
  | inl h_empty =>
    have h_nil : (clamp b).data.toList = [] := by
      apply List.eq_nil_of_length_eq_zero
      rw [toList_length_eq_size, h_empty]
    rw [h_nil]
    rfl
  | inr h_nonempty =>
    have h_split := natLE_split (clamp b) 0 h_nonempty
    have h_low_clear : ((clamp b)[0]!).toNat % 8 = 0 := by
      rw [clamp_getElem_zero b (by rw [← clamp_size b]; exact h_nonempty)]
      exact and_248_mod_eight _
    rw [List.drop_zero] at h_split
    omega

/-- RFC 7748 §5 clamping (`k[31] &= 127; k[31] |= 64`) clears bit 255
and sets bit 254, pinning the decoded scalar to `[2^254, 2^255)`. The
leading bit therefore sits at a fixed position whatever the secret is,
which is what lets the §5 ladder run its 255 iterations unconditionally
instead of starting at the scalar's own top bit — a data-independent
trip count, and so no timing channel on the secret's magnitude.

`b.size = 32` is exactly the right hypothesis, not a convenience.
`set!` is a no-op out of range, so a shorter array never gets bit 254
set and the lower bound fails; a longer array has its bytes past index
31 decoded as well and the upper bound fails. -/
theorem decodeScalar_range (b : ByteArray) (h_size : b.size = 32) :
    2 ^ 254 ≤ decodeScalar b ∧ decodeScalar b < 2 ^ 255 := by
  have h_clamp_size : (clamp b).size = 32 := by rw [clamp_size, h_size]
  have h_top_byte : (clamp b)[31]! = (b[31]! &&& 127) ||| 64 :=
    clamp_getElem_31 b (by omega)
  have h_drop_all : (clamp b).data.toList.drop 32 = [] := by
    apply List.drop_eq_nil_of_le
    rw [toList_length_eq_size, h_clamp_size]
    omega
  have h_high_digit :
      natLE (clamp b).data.toList / 256 ^ 31 = ((clamp b)[31]!).toNat := by
    rw [natLE_div_pow, natLE_split (clamp b) 31 (by omega), h_drop_all]
    simp [natLE]
  have h_top_byte_bounds := and_127_or_64_bounds b[31]!
  rw [← h_top_byte] at h_top_byte_bounds
  have h_pow_pos : 0 < (256 : Nat) ^ 31 := Nat.pow_pos (by decide)
  have h_bounds := bounds_of_div (natLE (clamp b).data.toList) (256 ^ 31)
    ((clamp b)[31]!).toNat 64 127 h_pow_pos h_high_digit h_top_byte_bounds.1 (by omega)
  have h_bit254 : (256 : Nat) ^ 31 * 64 = 2 ^ 254 := by decide
  have h_bit255 : (256 : Nat) ^ 31 * (127 + 1) = 2 ^ 255 := by decide
  rw [decodeScalar_eq_clamp, bytesToNatLE_eq_natLE]
  omega

end Spec.X25519
