import Mathlib.NumberTheory.LegendreSymbol.Basic
import Mathlib.Tactic
import Spec.Prime25519

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
the one the key encodes. `decode_complete` proves the converse: `decode`
accepts every key whose y is below p and names a point with x's low bit
as the key's bit 255. It rests on p being prime (`Spec.Prime25519`):
v^(p - 1) = 1, and x^((p - 1) / 2) is 1 or -1. `d_not_square` proves by
Euler's criterion that d is not a square, so v is never zero.
`bin/diff_ed25519` holds the C to `decode`.

This module is written from the C, not from a standard, and CONTRACT.md
says why.
-/

namespace Spec.Ed25519Decode

/-- The field prime, `2 ^ 255 - 19` (RFC 8032 §5.1). -/
def p : ℕ := 2 ^ 255 - 19

instance : Fact (Nat.Prime p) := ⟨Spec.Prime25519.prime_p⟩

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

/-- For an x not zero, the low bit of -x is not that of x: -x is p - x, and p is odd. -/
theorem neg_parity {x : ZMod p} (h_x : x ≠ 0) : (-x).val % 2 ≠ x.val % 2 := by
  have : NeZero x := ⟨h_x⟩
  have h_lt := ZMod.val_lt x
  have h_p : p =
      57896044618658097711785492504343953926634992332820282019728792003956564819949 := by
    norm_num [p]
  rw [ZMod.val_neg_of_ne_zero]
  omega

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
    have h_bit := Nat.mod_two_eq_zero_or_one (s / 2 ^ 255)
    have h_r_bit := Nat.mod_two_eq_zero_or_one r.val
    have h_neg_bit := Nat.mod_two_eq_zero_or_one (-r).val
    have := neg_parity h_r
    rw [h_x]
    omega

/-! ## The converse, over the field -/

/-- A natural number's power in `ZMod p`, by `Spec.Prime25519.powMod`, which the kernel
evaluates. -/
theorem natCast_pow (b k : ℕ) :
    ((b : ZMod p)) ^ k = ((Spec.Prime25519.powMod p b k : ℕ) : ZMod p) := by
  rw [Spec.Prime25519.powMod_eq, ZMod.natCast_mod, Nat.cast_pow]

/-- d is not a square: by Euler's criterion, since d^((p - 1) / 2) is -1. -/
theorem d_not_square : ¬IsSquare d := by
  have h_d : d ≠ 0 := by
    rw [d, Ne, ZMod.natCast_eq_zero_iff]
    intro h_dvd
    have := Nat.le_of_dvd (by norm_num) h_dvd
    norm_num [p] at this
  rw [ZMod.euler_criterion p h_d, d, natCast_pow]
  have h_power : Spec.Prime25519.powMod p
      37095705934669439343138083508754565189542113879843219016388785533085940283555 (p / 2) =
      p - 1 := by decide +kernel
  rw [h_power, Nat.cast_sub (by norm_num [p]), ZMod.natCast_self, Nat.cast_one, zero_sub]
  have : Fact (2 < p) := ⟨by norm_num [p]⟩
  exact ZMod.neg_one_ne_one

/-- v = d y² + 1 is never zero, or d would be the square of `sqrtM1 / y`. -/
theorem v_ne_zero (y : ZMod p) : d * y ^ 2 + 1 ≠ 0 := by
  intro h_zero
  have h_y : y ≠ 0 := by rintro rfl; simp at h_zero
  refine d_not_square ⟨sqrtM1 / y, ?_⟩
  rw [div_mul_div_comm, eq_div_iff (mul_ne_zero h_y h_y)]
  linear_combination h_zero - sqrtM1_sq

/-- 2 is not zero, since p is odd. -/
theorem two_ne_zero_mod_p : (2 : ZMod p) ≠ 0 := by
  intro h_zero
  have h_cast : ((2 : ℕ) : ZMod p) = 0 := by exact_mod_cast h_zero
  rw [ZMod.natCast_eq_zero_iff] at h_cast
  have := Nat.le_of_dvd (by norm_num) h_cast
  norm_num [p] at this

/-- Step 3 finds a root for every y with a point: an r with r² = x², so r is x or -x. -/
theorem root?_complete {x y : ZMod p} (h_curve : (d * y ^ 2 + 1) * x ^ 2 = y ^ 2 - 1) :
    ∃ r, root? y = some r ∧ r ^ 2 = x ^ 2 := by
  have h_v := v_ne_zero y
  have h_k : 8 * ((p - 5) / 8) + 4 = p - 1 := by norm_num [p]
  have h_candidate : candidate y = x ^ (2 * ((p - 5) / 8) + 2) := by
    simp only [candidate, powP58_eq]
    rw [← h_curve]
    calc (((d * y ^ 2 + 1) ^ 2 * (d * y ^ 2 + 1)) ^ 2 * (d * y ^ 2 + 1) *
          ((d * y ^ 2 + 1) * x ^ 2)) ^ ((p - 5) / 8) * ((d * y ^ 2 + 1) ^ 2 * (d * y ^ 2 + 1)) *
          ((d * y ^ 2 + 1) * x ^ 2)
        = (d * y ^ 2 + 1) ^ (8 * ((p - 5) / 8) + 4) * x ^ (2 * ((p - 5) / 8) + 2) := by
          generalize d * y ^ 2 + 1 = w
          generalize (p - 5) / 8 = k
          ring
      _ = x ^ (2 * ((p - 5) / 8) + 2) := by
        rw [h_k, ZMod.pow_card_sub_one_eq_one h_v, one_mul]
  have h_square : candidate y ^ 2 = x ^ 2 * x ^ (4 * ((p - 5) / 8) + 2) := by
    rw [h_candidate, ← pow_mul, ← pow_add]
    congr 1
  simp only [root?]
  by_cases h_x : x = 0
  · subst h_x
    have h_zero : candidate y = 0 := by rw [h_candidate]; exact zero_pow (by omega)
    rw [if_pos (by rw [h_zero, ← h_curve])]
    exact ⟨_, rfl, by rw [h_zero]⟩
  have h_euler : (x ^ (4 * ((p - 5) / 8) + 2)) ^ 2 = 1 := by
    rw [← pow_mul, show (4 * ((p - 5) / 8) + 2) * 2 = p - 1 by omega,
      ZMod.pow_card_sub_one_eq_one h_x]
  have h_cases : x ^ (4 * ((p - 5) / 8) + 2) = 1 ∨ x ^ (4 * ((p - 5) / 8) + 2) = -1 := by
    rw [sq] at h_euler
    exact mul_self_eq_one_iff.mp h_euler
  have h_u : y ^ 2 - 1 ≠ 0 := by
    rw [← h_curve]
    exact mul_ne_zero h_v (pow_ne_zero 2 h_x)
  rcases h_cases with h_e | h_e
  · rw [if_pos (by rw [h_square, h_e, ← h_curve]; ring)]
    exact ⟨_, rfl, by rw [h_square, h_e, mul_one]⟩
  · have h_minus : (d * y ^ 2 + 1) * candidate y ^ 2 = -(y ^ 2 - 1) := by
      rw [h_square, h_e, ← h_curve]
      ring
    have h_not_plus : ¬(d * y ^ 2 + 1) * candidate y ^ 2 = y ^ 2 - 1 := by
      intro h_plus
      have h_twice : (2 : ZMod p) * (y ^ 2 - 1) = 0 := by linear_combination h_minus - h_plus
      exact h_u ((mul_eq_zero.mp h_twice).resolve_left two_ne_zero_mod_p)
    rw [if_neg h_not_plus, if_pos h_minus]
    refine ⟨_, rfl, ?_⟩
    rw [mul_pow, sqrtM1_sq, h_square, h_e]
    ring

/-- `decode` accepts every key whose 255 low bits are a y below p of a point (x, y) of the
curve, with the low bit of x as the key's bit 255, and returns that point (RFC 8032 §5.1.3). -/
theorem decode_complete {s : ℕ} {x : ZMod p} (h_range : s % 2 ^ 255 < p)
    (h_curve : -x ^ 2 + ((s % 2 ^ 255 : ℕ) : ZMod p) ^ 2 =
      1 + d * x ^ 2 * ((s % 2 ^ 255 : ℕ) : ZMod p) ^ 2)
    (h_sign : x.val % 2 = s / 2 ^ 255 % 2) :
    decode s = some (x, ((s % 2 ^ 255 : ℕ) : ZMod p)) := by
  obtain ⟨r, h_root, h_sq⟩ := root?_complete (x := x) (y := ((s % 2 ^ 255 : ℕ) : ZMod p))
    (by linear_combination -h_curve)
  have h_zero_bit : x = 0 → s / 2 ^ 255 % 2 ≠ 1 := by
    rintro rfl
    rw [ZMod.val_zero] at h_sign
    omega
  unfold decode
  simp only [show ¬p ≤ s % 2 ^ 255 by omega, if_false, h_root, Option.bind_some]
  rcases sq_eq_sq_iff_eq_or_eq_neg.mp h_sq with rfl | rfl
  · have h_kept : ¬(r = 0 ∧ s / 2 ^ 255 % 2 = 1) := fun h => h_zero_bit h.1 h.2
    rw [signed, if_neg h_kept, if_pos h_sign]
    rfl
  · by_cases h_x : x = 0
    · subst h_x
      rw [neg_zero, signed, if_neg (fun h => h_zero_bit rfl h.2), if_pos h_sign]
      rfl
    · have h_kept : ¬(-x = 0 ∧ s / 2 ^ 255 % 2 = 1) := fun h => h_x (neg_eq_zero.mp h.1)
      have h_flip : ¬(-x).val % 2 = s / 2 ^ 255 % 2 := by
        rw [← h_sign]
        exact neg_parity h_x
      rw [signed, if_neg h_kept, if_neg h_flip, neg_neg]
      rfl

end Spec.Ed25519Decode
