import Spec.Ed25519Verify
import Spec.Prime25519

/-!
# X25519's key generation over curve25519's field

`Spec.X25519Edwards` proves `toU_baseMulExtended` for every field in which 2 is not zero, d is
not a square and -1 is, under the hypothesis that the point the loop ends at has an x that is
not zero. This module states it over `ZMod p`, with p = 2^255 - 19, for the base point B of
RFC 7748 section 4.1, and removes the hypothesis for every clamped scalar.

* `montU_toMont_base` proves that the image of B on the Montgomery curve has u 9, the u of
  curve25519's base point.
* `L_smul_base` proves that L times that image is the identity. The kernel computes L B with
  `Spec.Ed25519Verify.loopExtended`, and `verify_point` carries the result to the image.
* `addOrderOf_base` proves that the image has order L, since L is prime (`Spec.Prime25519`).
* `baseMul_x_ne_zero` proves that the loop's point has an x that is not zero for digits whose
  sum L does not divide: the identity and the point of order two are the two points with x zero.
* `not_dvd_of_clamped` proves that L divides no clamped scalar: a multiple of 8 from 2^254 up to
  2^255 - 1.

`toU_keygen` puts them together: for digits whose sum is a clamped scalar s, the u that
`x25519_wide_base_mul`'s model writes is the u of s times the point with u 9.
proof/x25519_wide_select_harness.c proves that `recode`'s digits add up to the clamped scalar.

This module is written from the C, not from a standard, and CONTRACT.md says why.
-/

namespace Spec.X25519Base

open Spec.X25519Edwards Spec.Ed25519Verify

/-- L is the literal that `Spec.Prime25519.prime_L` names. -/
theorem L_eq :
    Spec.Ed25519ModL.L =
      7237005577332262213973186563042994240857116359379907606001950938285454250989 := by
  norm_num [Spec.Ed25519ModL.L]

instance : Fact (Nat.Prime Spec.Ed25519ModL.L) := ⟨by rw [L_eq]; exact Spec.Prime25519.prime_L⟩

/-- B's x is not zero. -/
theorem base_x_ne_zero : base.x ≠ 0 := by
  show baseX ≠ 0
  decide +kernel

/-- The image of B has u 9, the u of curve25519's base point (RFC 7748 section 4.1). -/
theorem montU_toMont_base : montU edwards25519.d (toMont base) = 9 := by
  rw [toMont_generic base_x_ne_zero, montU, monX]
  have h_k := edwards25519.one_add_d_ne_zero
  have h_m : (1 : ZMod Ed25519Decode.p) - baseY ≠ 0 := by decide +kernel
  have h_9 : (1 : ZMod Ed25519Decode.p) + baseY = 9 * (1 - baseY) := by decide +kernel
  change -(-(1 + edwards25519.d) * (1 + baseY) / (1 - baseY)) / (1 + edwards25519.d) = 9
  field_simp
  linear_combination h_9

/-- L B, computed in extended coordinates over 253 bits: x is zero and y is z, which is not
zero. -/
theorem L_mul_base_extended :
    let a := loopExtended (entryOf edwards25519.d base.x base.y)
      (entryOf edwards25519.d (-base.x) base.y) Spec.Ed25519ModL.L 0 253 ⟨0, 1, 1, 0⟩
    a.x = 0 ∧ a.y = a.z ∧ a.z ≠ 0 := by
  decide +kernel

/-- L times the image of B is the identity. -/
theorem L_smul_base : (Spec.Ed25519ModL.L : ℤ) • toMont base = 0 := by
  obtain ⟨P, h_x, h_y, h_mont⟩ := verify_point (s := Spec.Ed25519ModL.L) (h := 0) base base
    (by norm_num [Spec.Ed25519ModL.L]) (by norm_num)
  obtain ⟨h_ax, h_ay, h_az⟩ := L_mul_base_extended
  rw [h_ax, zero_mul] at h_x
  rw [h_ay, mul_inv_cancel₀ h_az] at h_y
  rw [Nat.cast_zero, zero_smul, sub_zero] at h_mont
  rw [← h_mont]
  exact toMont_identity h_x.symm h_y.symm

/-- The image of B is not the identity. -/
theorem toMont_base_ne_zero : toMont base ≠ 0 := by
  rw [toMont_generic base_x_ne_zero]
  exact WeierstrassCurve.Affine.Point.some_ne_zero _

/-- The image of B has order L. -/
theorem addOrderOf_base : addOrderOf (toMont base) = Spec.Ed25519ModL.L :=
  addOrderOf_eq_prime (by rw [← natCast_zsmul]; exact L_smul_base) toMont_base_ne_zero

/-- An integer multiple of the image of B is the identity only for a multiple of L. -/
theorem dvd_of_zsmul_base {s : ℤ} (h : s • toMont base = 0) :
    (Spec.Ed25519ModL.L : ℤ) ∣ s := by
  rw [← addOrderOf_base]
  exact addOrderOf_dvd_iff_zsmul_eq_zero.mpr h

/-- The point of order two is its own negative. -/
theorem torsion_add_self :
    (.some 0 0 nonsingular_zero_zero : (mont edwards25519.d).Point) +
      .some 0 0 nonsingular_zero_zero = 0 := by
  have h_neg : -(.some 0 0 nonsingular_zero_zero : (mont edwards25519.d).Point) =
      .some 0 0 nonsingular_zero_zero := by
    rw [WeierstrassCurve.Affine.Point.neg_some]
    congr 1
  nth_rewrite 2 [← h_neg]
  exact add_neg_cancel _

/-- The loop's point has an x that is not zero when L does not divide the sum of the digits. -/
theorem baseMul_x_ne_zero (e : ℕ → ℤ)
    (h : ¬(Spec.Ed25519ModL.L : ℤ) ∣ ∑ j ∈ Finset.range 64, e j * 16 ^ j) :
    (baseMul base e).x ≠ 0 := by
  intro h_x
  have h_mont := toMont_baseMul base e
  rcases EdPoint.y_eq_of_x_eq_zero h_x with h_y | h_y
  · rw [toMont_identity h_x h_y] at h_mont
    exact h (dvd_of_zsmul_base h_mont.symm)
  · rw [toMont_torsion h_x h_y] at h_mont
    have h_two : (2 * ∑ j ∈ Finset.range 64, e j * 16 ^ j) • toMont base = 0 := by
      rw [mul_smul, ← h_mont, two_smul, torsion_add_self]
    have h_prime : Prime (Spec.Ed25519ModL.L : ℤ) :=
      Nat.prime_iff_prime_int.mp (Fact.out : Nat.Prime Spec.Ed25519ModL.L)
    rcases h_prime.dvd_or_dvd (dvd_of_zsmul_base h_two) with h_2 | h_s
    · have := Int.le_of_dvd (by norm_num) h_2
      norm_num [Spec.Ed25519ModL.L] at this
    · exact h h_s

/-- L divides no clamped scalar: a multiple of 8 from 2^254 up to 2^255 - 1. A multiple of L
that 8 divides is a multiple of 8 L, since L is odd, and 8 L is above 2^255. -/
theorem not_dvd_of_clamped {s : ℕ} (h_8 : 8 ∣ s) (h_lo : 2 ^ 254 ≤ s) (h_hi : s < 2 ^ 255) :
    ¬(Spec.Ed25519ModL.L : ℤ) ∣ s := by
  rw [Int.natCast_dvd_natCast]
  rintro ⟨m, rfl⟩
  have h_coprime : Nat.Coprime 8 Spec.Ed25519ModL.L := by
    rw [L_eq]
    norm_num
  obtain ⟨k, rfl⟩ := h_coprime.dvd_of_dvd_mul_left h_8
  rw [L_eq] at h_lo h_hi
  omega

/-- `x25519_wide_base_mul`'s model writes the u of s times the point with u 9 for digits whose sum
is a clamped scalar s. -/
theorem toU_keygen (e : ℕ → ℤ) {s : ℕ} (h_sum : ∑ j ∈ Finset.range 64, e j * 16 ^ j = s)
    (h_8 : 8 ∣ s) (h_lo : 2 ^ 254 ≤ s) (h_hi : s < 2 ^ 255) :
    toU (baseMulExtended base e) = montU edwards25519.d ((s : ℤ) • toMont base) ∧
      montU edwards25519.d (toMont base) = 9 := by
  refine ⟨?_, montU_toMont_base⟩
  rw [← h_sum]
  exact toU_baseMulExtended base e
    (baseMul_x_ne_zero e (h_sum ▸ not_dvd_of_clamped h_8 h_lo h_hi))

end Spec.X25519Base
