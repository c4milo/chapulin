import Mathlib.Data.ZMod.Basic
import Mathlib.Tactic

/-!
# The DNSSEC Ed25519 check's point decoding

`decode_point` (`x25519_wide_ed25519.h`) reads the 32 bytes of an Ed25519
public key as a point of edwards25519 by RFC 8032 §5.1.3
(https://github.com/c4milo/chapulin/issues/189). This module models it
from the C over `ZMod p`, and proves that each point it returns is the one
RFC 8032 names.

* `powP58` is `pow_p58`'s chain of squarings and products, and `powP58_eq`
  proves that it computes `z ^ ((p - 5) / 8)`.
* `candidate` is the C's x before its check: `u v³ (u v⁷) ^ ((p - 5) / 8)`
  with `u = y² - 1` and `v = d y² + 1`, step 3 of the RFC.
* `root?` is the check of step 3: the candidate where `v x² = u`, the
  candidate times `sqrtM1` where `v x² = -u`, and nothing otherwise.
* `decode` is `decode_point`: a y at or above p refused, the root, a zero x
  with the sign bit set refused, and x negated where its low bit is not the
  sign bit, step 4.

The theorems give soundness, the direction that carries weight: a key
`decode` accepts names a point of the curve (`decode_onCurve`), its y is
the 255 low bits of the key, which are below p (`decode_y`), and the low
bit of its x is the key's bit 255 (`decode_sign`). The curve equation and
y fix x up to its sign, and the sign bit fixes the sign, so the point is
the one the key encodes. They do not prove the converse, that `decode`
accepts every key that encodes a point: that needs p to be prime, which no
module here proves. `bin/dnssec_test` and the Wycheproof suite hold that
side on valid keys, and `bin/diff_ed25519` holds the C to `decode`.

This module is written from the C, not from a standard, and CONTRACT.md
says why.
-/

namespace Spec.Ed25519Decode

/-- The field prime, `2 ^ 255 - 19` (RFC 8032 §5.1). -/
def p : ℕ := 2 ^ 255 - 19

instance : NeZero p := ⟨by norm_num [p]⟩

/-- d = -121665 / 121666 mod p (RFC 8032 §5.1), `ED25519_D`. -/
def d : ZMod p :=
  ((37095705934669439343138083508754565189542113879843219016388785533085940283555 : ℕ) : ZMod p)

/-- The square root of -1, `2 ^ ((p - 1) / 4) mod p`, `ED25519_SQRT_M1`. -/
def sqrtM1 : ZMod p :=
  ((19681161376707505956807079304988542015446066515923890162744021073123829784752 : ℕ) : ZMod p)

/-- `sqr_times`: `n` squarings of `t`. -/
def sqrTimes (t : ZMod p) : ℕ → ZMod p
  | 0 => t
  | n + 1 => sqrTimes (t ^ 2) n

/-- `pow_p58`, one `let` for each C statement. -/
def powP58 (z : ZMod p) : ZMod p :=
  let z2 := z ^ 2
  let z9 := sqrTimes z2 2 * z
  let z11 := z9 * z2
  let z2_5_0 := z11 ^ 2 * z9
  let z2_10_0 := sqrTimes z2_5_0 5 * z2_5_0
  let z2_20_0 := sqrTimes z2_10_0 10 * z2_10_0
  let t := sqrTimes z2_20_0 20 * z2_20_0
  let z2_50_0 := sqrTimes t 10 * z2_10_0
  let z2_100_0 := sqrTimes z2_50_0 50 * z2_50_0
  let t := sqrTimes z2_100_0 100 * z2_100_0
  let t := sqrTimes t 50 * z2_50_0
  sqrTimes t 2 * z

/-- The candidate x of RFC 8032 §5.1.3 step 3, as `decode_point` computes it. -/
def candidate (y : ZMod p) : ZMod p :=
  let u := y ^ 2 - 1
  let v := d * y ^ 2 + 1
  let v3 := v ^ 2 * v
  powP58 (v3 ^ 2 * v * u) * v3 * u

/-- The check of step 3: an x with `v x² = u`, or nothing. -/
def root? (y : ZMod p) : Option (ZMod p) :=
  let u := y ^ 2 - 1
  let v := d * y ^ 2 + 1
  let x := candidate y
  if v * x ^ 2 = u then some x
  else if v * x ^ 2 = -u then some (x * sqrtM1)
  else none

/-- Step 4 for a root `r` and the key's bit 255, `sign`: a zero x with the bit set refused, and
`r` negated where its low bit is not the bit. -/
def signed (sign : ℕ) (r : ZMod p) : Option (ZMod p) :=
  if r = 0 ∧ sign = 1 then none else some (if r.val % 2 = sign then r else -r)

/-- `decode_point`: the point the 32 little-endian bytes `s` encode, or nothing. -/
def decode (s : ℕ) : Option (ZMod p × ZMod p) :=
  if p ≤ s % 2 ^ 255 then none
  else
    let y : ZMod p := ((s % 2 ^ 255 : ℕ) : ZMod p)
    ((root? y).bind (signed (s / 2 ^ 255 % 2))).map (·, y)

/-- `sqr_times` is a power of a power of two. -/
theorem sqrTimes_eq (t : ZMod p) (n : ℕ) : sqrTimes t n = t ^ 2 ^ n := by
  induction n generalizing t with
  | zero => simp [sqrTimes]
  | succ n ih => rw [sqrTimes, ih, ← pow_mul, pow_succ']

/-- `pow_p58` computes `z ^ ((p - 5) / 8)`, which is `z ^ (2 ^ 252 - 3)`. -/
theorem powP58_eq (z : ZMod p) : powP58 z = z ^ ((p - 5) / 8) := by
  simp only [powP58, sqrTimes_eq, ← pow_mul, ← pow_add, ← pow_succ]
  norm_num [p]

/-- `sqrtM1` squares to -1. -/
theorem sqrtM1_sq : sqrtM1 ^ 2 = -1 := by
  have h_zero : ((19681161376707505956807079304988542015446066515923890162744021073123829784752 ^ 2
      + 1 : ℕ) : ZMod p) = 0 := by
    rw [ZMod.natCast_eq_zero_iff]
    norm_num [p]
  push_cast at h_zero
  simp only [sqrtM1]
  linear_combination h_zero

/-- A root `root?` returns solves `v x² = u`. -/
theorem root?_spec {y x : ZMod p} (h_root : root? y = some x) :
    (d * y ^ 2 + 1) * x ^ 2 = y ^ 2 - 1 := by
  simp only [root?] at h_root
  split_ifs at h_root with h_plus h_minus
  · rw [← Option.some_inj.mp h_root]
    exact h_plus
  · rw [← Option.some_inj.mp h_root]
    linear_combination ((d * y ^ 2 + 1) * candidate y ^ 2) * sqrtM1_sq - h_minus

/-- What `decode` accepts, unfolded: y below p, a root x, and the x it returns. -/
theorem decode_some {s : ℕ} {x y : ZMod p} (h_decode : decode s = some (x, y)) :
    s % 2 ^ 255 < p ∧ y = ((s % 2 ^ 255 : ℕ) : ZMod p) ∧ ∃ r, root? y = some r ∧
      ¬(r = 0 ∧ s / 2 ^ 255 % 2 = 1) ∧
      x = (if r.val % 2 = s / 2 ^ 255 % 2 then r else -r) := by
  unfold decode at h_decode
  by_cases h_range : p ≤ s % 2 ^ 255
  · rw [if_pos h_range] at h_decode
    cases h_decode
  rw [if_neg h_range] at h_decode
  obtain ⟨x', h_bind, h_pair⟩ := Option.map_eq_some_iff.mp h_decode
  obtain ⟨r, h_root, h_signed⟩ := Option.bind_eq_some_iff.mp h_bind
  obtain ⟨h_x, h_y⟩ := Prod.mk.inj h_pair
  unfold signed at h_signed
  by_cases h_refused : r = 0 ∧ s / 2 ^ 255 % 2 = 1
  · rw [if_pos h_refused] at h_signed
    cases h_signed
  rw [if_neg h_refused] at h_signed
  refine ⟨by omega, h_y.symm, r, h_y ▸ h_root, h_refused, ?_⟩
  rw [← h_x, ← Option.some_inj.mp h_signed]

/-- A point `decode` returns is on the curve: `-x² + y² = 1 + d x² y²`. -/
theorem decode_onCurve {s : ℕ} {x y : ZMod p} (h_decode : decode s = some (x, y)) :
    -x ^ 2 + y ^ 2 = 1 + d * x ^ 2 * y ^ 2 := by
  obtain ⟨-, h_y, r, h_root, -, h_x⟩ := decode_some h_decode
  have h_sq : x ^ 2 = r ^ 2 := by split_ifs at h_x <;> rw [h_x]; ring
  rw [h_sq]
  linear_combination -(root?_spec h_root)

/-- The y `decode` returns is the key's 255 low bits, which are below p. -/
theorem decode_y {s : ℕ} {x y : ZMod p} (h_decode : decode s = some (x, y)) :
    s % 2 ^ 255 < p ∧ y.val = s % 2 ^ 255 := by
  obtain ⟨h_range, h_y, -⟩ := decode_some h_decode
  rw [h_y, ZMod.val_natCast, Nat.mod_eq_of_lt h_range]
  exact ⟨h_range, rfl⟩

/-- The low bit of the x `decode` returns is the key's bit 255, RFC 8032's sign of x. -/
theorem decode_sign {s : ℕ} {x y : ZMod p} (h_decode : decode s = some (x, y)) :
    x.val % 2 = s / 2 ^ 255 % 2 := by
  obtain ⟨-, -, r, -, h_refused, h_x⟩ := decode_some h_decode
  split_ifs at h_x with h_parity
  · rw [h_x, h_parity]
  · have h_r : r ≠ 0 := by
      rintro rfl
      simp only [ZMod.val_zero, Nat.zero_mod, true_and] at h_parity h_refused
      omega
    have : NeZero r := ⟨h_r⟩
    have h_lt := ZMod.val_lt r
    have h_p : p =
        57896044618658097711785492504343953926634992332820282019728792003956564819949 := by
      norm_num [p]
    rw [h_x, ZMod.val_neg_of_ne_zero]
    omega

end Spec.Ed25519Decode
