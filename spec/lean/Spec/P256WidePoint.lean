import Mathlib.AlgebraicGeometry.EllipticCurve.Affine.Point
import Spec.P256

/-!
The doubling of `p256_wide_point.c`, `p256_wide_point_double`, its incomplete
mixed addition, `p256_wide_point_add_affine_incomplete`, and what they compute.

The C runs the Explicit-Formulas Database's dbl-2007-bl-2 for curves
`y^2 = x^3 - 3x + b`, in homogeneous projective coordinates, and then one
masked move for the point at infinity. `double` is that function: one `let`
for each C statement, in the order the C runs them, under the C's names. A
statement that writes a local the C already wrote is a second `let` of the
same name, so each line here reads against one line of the C. The database's
`B` is `b` in both, and it is not the curve's coefficient, which `double`
never reads.

`double` takes its coordinates in any commutative ring. The C keeps each
coordinate `v` of P-256 as `v * 2^256 mod p`, the Montgomery domain. There a
sum is a sum, and the Montgomery product of `u * 2^256` and `v * 2^256` is
`u * v * 2^256`, so the C computes this function's answer in that domain.
`test/diff_p256_wide_test.c` compares the C with `double` over `ZMod p`,
moving each coordinate into the domain and back out.

`double_represents` proves that `double` computes `P + P` for every point `P`
of every curve `y^2 = x^3 - 3x + b` over a field in which 2 and 3 are not
zero, unless `b` is 2 or -2. `double_represents_p256` states it at P-256's
`b`. Neither theorem reads the curve's order.

`addAffineIncomplete` is the incomplete addition in the same form: the
Explicit-Formulas Database's madd-1998-cmo. `addAffineIncomplete_represents`
proves that it computes `P + Q` for a finite `P` and an affine `Q` whose x
differ, over every field. `p256_wide_base_mul` (`p256_wide_mul.c`) adds windows
1 to 41 by it, and `windowSum` is that loop. `windowSum_represents` proves that
every one of those additions meets the condition, so the loop computes the sum
of the windows' multiples of `G`, for digits that are odd and at most 63 in
size, wherever `G`'s order is at least `64 ^ 42 = 2 ^ 252`.
`windowSum_represents_p256` states it at P-256, with `n` prime and `n • G = 0`
as hypotheses.

This module is written from the C, not from a standard, and CONTRACT.md says
why.
-/

namespace Spec.P256WidePoint

/-- A point's three coordinates, `(X : Y : Z)`, as `p256_wide_point` holds them
(`p256_wide_point.h`). -/
structure Projective (R : Type*) where
  /-- `X`. -/
  x : R
  /-- `Y`. -/
  y : R
  /-- `Z`. -/
  z : R

/-- `p256_wide_point_double` (`p256_wide_point.c`): the Explicit-Formulas
Database's dbl-2007-bl-2 for `a = -3`, with `w = 3 (X1 - Z1) (X1 + Z1)`,
`s = 2 Y1 Z1`, `r = Y1 s`, `b = 2 X1 r` and `h = w^2 - 2 b`, giving
`X3 = h s`, `Y3 = w (b - h) - 2 r^2` and `Z3 = s^3`. Then `Y3 = 1` where
`Z1 = 0`, which the C does by mask. -/
def double {R : Type*} [CommRing R] [DecidableEq R] (a : Projective R) : Projective R :=
  let t := a.x - a.z
  let w := a.x + a.z
  let w := t * w
  let t := w + w
  let w := t + w
  let s := a.y * a.z
  let s := s + s
  let ss := s ^ 2
  let sss := s * ss
  let r := a.y * s
  let rr := r ^ 2
  let b := a.x * r
  let b := b + b
  let h := w ^ 2
  let t := b + b
  let h := h - t
  let x3 := h * s
  let t := b - h
  let y3 := w * t
  let t := rr + rr
  let y3 := y3 - t
  let y3 := if a.z = 0 then 1 else y3
  ⟨x3, y3, sss⟩

/-- A finite point's two affine coordinates, `(x, y)`, as `p256_wide_affine` holds them
(`p256_wide_point.h`). -/
structure Affine (R : Type*) where
  /-- `x`. -/
  x : R
  /-- `y`. -/
  y : R

/-- `p256_wide_point_add_affine_incomplete` (`p256_wide_point.c`): the Explicit-Formulas
Database's madd-1998-cmo, with `u = Y2 Z1 - Y1`, `v = X2 Z1 - X1`, `r = v^2 X1` and
`A = u^2 Z1 - v^3 - 2 r`, giving `X3 = v A`, `Y3 = u (r - A) - v^3 Y1` and `Z3 = v^3 Z1`. `b` is
`(X2, Y2)`, and the database's `A` is the C's `x3_numerator`. -/
def addAffineIncomplete {R : Type*} [CommRing R] (a : Projective R) (b : Affine R) :
    Projective R :=
  let u := b.y * a.z
  let u := u - a.y
  let v := b.x * a.z
  let v := v - a.x
  let uu := u ^ 2
  let vv := v ^ 2
  let vvv := v * vv
  let r := vv * a.x
  let x3_numerator := uu * a.z
  let x3_numerator := x3_numerator - vvv
  let t := r + r
  let x3_numerator := x3_numerator - t
  let x3 := v * x3_numerator
  let t := r - x3_numerator
  let y3 := u * t
  let t := vvv * a.y
  let y3 := y3 - t
  let z3 := vvv * a.z
  ⟨x3, y3, z3⟩

/-- The sum `p256_wide_base_mul` (`p256_wide_mul.c`) holds after windows 0 to `i - 1`, for the
entry `entry j` of window `j`: window 0's entry with `Z = 1`, and each later window's entry added
by `addAffineIncomplete`. The C runs it to `i = 42` and adds window 42 and the correction by the
complete addition, which this module does not model. No window at all is the point at infinity,
which the C never holds. -/
def windowSum {R : Type*} [CommRing R] (entry : ℕ → Affine R) : ℕ → Projective R
  | 0 => ⟨0, 1, 0⟩
  | 1 => ⟨(entry 0).x, (entry 0).y, 1⟩
  | i + 2 => addAffineIncomplete (windowSum entry (i + 1)) (entry (i + 1))

/-- One window's step of the bound `windowSum_represents` rests on: an odd `S` below `64 ^ i` in
size, plus a digit of at most 63 in size times `64 ^ i`, is odd and below `64 ^ (i + 1)` in
size. -/
private theorem odd_lt_add_digit {S e : ℤ} {i : ℕ} (h_i : 1 ≤ i) (h_odd : Odd S)
    (h_lt : |S| < 64 ^ i) (h_e : |e| ≤ 63) :
    Odd (S + e * 64 ^ i) ∧ |S + e * 64 ^ i| < 64 ^ (i + 1) := by
  refine ⟨h_odd.add_even ((Int.even_pow.mpr ⟨by decide, by omega⟩).mul_left e), ?_⟩
  have h_term : |e * 64 ^ i| ≤ 63 * 64 ^ i := by
    rw [abs_mul, abs_of_pos (by positivity : (0 : ℤ) < 64 ^ i)]
    exact mul_le_mul_of_nonneg_right h_e (by positivity)
  calc |S + e * 64 ^ i| ≤ |S| + |e * 64 ^ i| := abs_add_le _ _
    _ < 64 ^ i + 63 * 64 ^ i := by linarith
    _ = 64 ^ (i + 1) := by ring

/-- The digits of windows 0 to `i - 1`, each odd and at most 63 in size, times their powers of
64, sum to an odd number below `64 ^ i` in size. -/
private theorem digit_sum_odd_lt {d : ℕ → ℤ} (h_odd : ∀ j, Odd (d j))
    (h_size : ∀ j, |d j| ≤ 63) {i : ℕ} (h_i : 1 ≤ i) :
    Odd (∑ j ∈ Finset.range i, d j * 64 ^ j) ∧ |∑ j ∈ Finset.range i, d j * 64 ^ j| < 64 ^ i := by
  induction i with
  | zero => omega
  | succ i ih =>
    rw [Finset.sum_range_succ]
    rcases Nat.eq_zero_or_pos i with rfl | h_pos
    · simp only [Finset.range_zero, Finset.sum_empty, pow_zero, mul_one, zero_add, pow_one]
      exact ⟨h_odd 0, by linarith [h_size 0]⟩
    · obtain ⟨h_sum_odd, h_sum_lt⟩ := ih h_pos
      exact odd_lt_add_digit h_pos h_sum_odd h_sum_lt (h_size i)

/-- An odd multiple of `G`, below `G`'s order in size, is not zero. -/
private theorem zsmul_ne_zero_of_odd {A : Type*} [AddCommGroup A] {G : A} {S : ℤ}
    (h_odd : Odd S) (h_lt : |S| < addOrderOf G) : S • G ≠ 0 := by
  intro h_zero
  have h_sum_zero : S = 0 :=
    Int.eq_zero_of_abs_lt_dvd (addOrderOf_dvd_iff_zsmul_eq_zero.mpr h_zero) h_lt
  rw [Int.odd_iff] at h_odd
  omega

section Curve

variable {F : Type*} [Field F] [DecidableEq F]

/-- The curve `y^2 = x^3 - 3x + b` over `F` as Mathlib's Weierstrass curve,
`a₄ = -3` and `a₆ = b`: FIPS 186-4 §D.1.2 fixes `a = -3` for every NIST
prime curve. -/
def curve (b : F) : WeierstrassCurve.Affine F := ⟨0, 0, 0, -3, b⟩

/-- `a` holds the point `P` of `curve b` in homogeneous projective coordinates:
the point at infinity as `(0 : Y : 0)` with `Y ≠ 0`, the shape
`p256_wide_point.h` names, and the affine point `(x, y)` as `(X : Y : Z)` with
`Z ≠ 0`, `x = X / Z` and `y = Y / Z`. -/
def Represents (b : F) (a : Projective F) : (curve b).Point → Prop
  | .zero => a.x = 0 ∧ a.y ≠ 0 ∧ a.z = 0
  | .some x y _ => a.z ≠ 0 ∧ x = a.x / a.z ∧ y = a.y / a.z

/-- `double` doubles: where `a` holds `P`, `double a` holds `P + P`. That
covers every point of the curve, the point at infinity and a point with
`y = 0` among them, on every curve `y^2 = x^3 - 3x + b` whose `b` is neither 2
nor -2, over every field in which 2 and 3 are not zero. -/
theorem double_represents (h_two : (2 : F) ≠ 0) (h_three : (3 : F) ≠ 0) {b : F}
    (h_b : b ≠ 2 ∧ b ≠ -2) {a : Projective F} {P : (curve b).Point}
    (h_represents : Represents b a P) : Represents b (double a) (P + P) := by
  obtain ⟨x, y, z⟩ := a
  cases P with
  | zero =>
    obtain ⟨rfl, -, rfl⟩ := h_represents
    change (double _).x = 0 ∧ (double _).y ≠ 0 ∧ (double _).z = 0
    simp [double]
  | some u v h_nonsingular =>
    obtain ⟨h_z, rfl, rfl⟩ := h_represents
    dsimp only at h_z h_nonsingular ⊢
    have h_equation : (y / z) ^ 2 = (x / z) ^ 3 - 3 * (x / z) + b := by
      have h_mathlib := h_nonsingular.1
      rw [WeierstrassCurve.Affine.equation_iff] at h_mathlib
      simp only [curve] at h_mathlib
      linear_combination h_mathlib
    by_cases h_y : y = 0
    · subst h_y
      have h_own_negative : 0 / z = (curve b).negY (x / z) (0 / z) := by simp [curve]
      rw [WeierstrassCurve.Affine.Point.add_self_of_Y_eq h_own_negative]
      have h_minus : x - z ≠ 0 := by
        intro h_sub
        rw [sub_eq_zero.mp h_sub, div_self h_z] at h_equation
        exact h_b.1 (by linear_combination -h_equation)
      have h_plus : x + z ≠ 0 := by
        intro h_add
        rw [eq_neg_of_add_eq_zero_left h_add, neg_div, div_self h_z] at h_equation
        exact h_b.2 (by linear_combination -h_equation)
      change (double _).x = 0 ∧ (double _).y ≠ 0 ∧ (double _).z = 0
      simp only [double, if_neg h_z]
      refine ⟨by ring, ?_, by ring⟩
      have h_w : 3 * ((x - z) * (x + z)) ≠ 0 := mul_ne_zero h_three (mul_ne_zero h_minus h_plus)
      intro h_y3
      exact h_w (pow_eq_zero_iff (n := 3) (by norm_num) |>.mp (by linear_combination -h_y3))
    · have h_s : y * z + y * z ≠ 0 := by
        rw [← two_mul]
        exact mul_ne_zero h_two (mul_ne_zero h_y h_z)
      have h_negY : y / z ≠ (curve b).negY (x / z) (y / z) := by
        simp only [curve, WeierstrassCurve.Affine.negY]
        intro h_eq
        have h_twice : 2 * (y / z) = 0 := by linear_combination h_eq
        rcases mul_eq_zero.mp h_twice with h_two_zero | h_quotient
        · exact h_two h_two_zero
        · exact h_y ((div_eq_zero_iff.mp h_quotient).resolve_right h_z)
      rw [WeierstrassCurve.Affine.Point.add_of_Y_ne h_negY]
      simp only [Represents, double, if_neg h_z]
      -- The C's s, 2 Y1 Z1, stays one name until the denominators are gone, so that no numeral
      -- lands in a denominator, where field_simp would need it to be nonzero.
      set s := y * z + y * z with h_s_def
      have h_slope : (curve b).slope (x / z) (x / z) (y / z) (y / z) =
          3 * ((x - z) * (x + z)) / s := by
        rw [WeierstrassCurve.Affine.slope_of_Y_ne rfl h_negY,
          div_eq_div_iff (sub_ne_zero.mpr h_negY) h_s]
        simp only [curve, WeierstrassCurve.Affine.negY]
        field_simp
        rw [h_s_def]
        ring
      rw [h_slope]
      refine ⟨mul_ne_zero h_s (pow_ne_zero 2 h_s), ?_, ?_⟩
      · simp only [WeierstrassCurve.Affine.addX, curve]
        field_simp
        rw [h_s_def]
        ring
      · simp only [WeierstrassCurve.Affine.addY, WeierstrassCurve.Affine.negAddY,
          WeierstrassCurve.Affine.addX, curve, WeierstrassCurve.Affine.negY]
        field_simp
        rw [h_s_def]
        ring

/-- `addAffineIncomplete` adds: where `a` holds a finite point `(x₁, y₁)` and `(x₂, y₂)` is a
point with `x₁ ≠ x₂`, `addAffineIncomplete a ⟨x₂, y₂⟩` holds their sum. That covers every such
pair on every curve `y^2 = x^3 - 3x + b`, over every field: the sum of two points with different
x is the third point on the line through them, and that formula reads no coefficient of the
curve but the two that are zero here. -/
theorem addAffineIncomplete_represents {b : F} {a : Projective F} {x₁ y₁ x₂ y₂ : F}
    {h₁ : (curve b).Nonsingular x₁ y₁} {h₂ : (curve b).Nonsingular x₂ y₂}
    (h_represents : Represents b a (.some x₁ y₁ h₁)) (h_x : x₁ ≠ x₂) :
    Represents b (addAffineIncomplete a ⟨x₂, y₂⟩) (.some x₁ y₁ h₁ + .some x₂ y₂ h₂) := by
  obtain ⟨x, y, z⟩ := a
  obtain ⟨h_z, h_x₁, h_y₁⟩ := h_represents
  dsimp only at h_z h_x₁ h_y₁ ⊢
  -- The C's coordinates are the affine ones times Z.
  obtain rfl : x = x₁ * z := by rw [h_x₁, div_mul_cancel₀ _ h_z]
  obtain rfl : y = y₁ * z := by rw [h_y₁, div_mul_cancel₀ _ h_z]
  rw [WeierstrassCurve.Affine.Point.add_of_X_ne h_x]
  have h_sub : x₁ - x₂ ≠ 0 := sub_ne_zero.mpr h_x
  have h_v : x₂ * z - x₁ * z ≠ 0 := by
    rw [← sub_mul, ← neg_sub]
    exact mul_ne_zero (neg_ne_zero.mpr h_sub) h_z
  have h_z3 : (x₂ * z - x₁ * z) * (x₂ * z - x₁ * z) ^ 2 * z ≠ 0 :=
    mul_ne_zero (mul_ne_zero h_v (pow_ne_zero 2 h_v)) h_z
  simp only [Represents, addAffineIncomplete]
  rw [WeierstrassCurve.Affine.slope_of_X_ne h_x]
  refine ⟨h_z3, ?_, ?_⟩
  · rw [eq_div_iff h_z3]
    simp only [WeierstrassCurve.Affine.addX, curve]
    field_simp
    ring
  · rw [eq_div_iff h_z3]
    simp only [WeierstrassCurve.Affine.addY, WeierstrassCurve.Affine.negAddY,
      WeierstrassCurve.Affine.addX, curve, WeierstrassCurve.Affine.negY]
    field_simp
    ring

omit [DecidableEq F] in
/-- Two finite points of `curve b` that are neither equal nor each other's negative have
different x. -/
private theorem x_ne_of_ne {b : F} {x₁ y₁ x₂ y₂ : F} {h₁ : (curve b).Nonsingular x₁ y₁}
    {h₂ : (curve b).Nonsingular x₂ y₂}
    (h_ne : (.some x₁ y₁ h₁ : (curve b).Point) ≠ .some x₂ y₂ h₂)
    (h_ne_neg : (.some x₁ y₁ h₁ : (curve b).Point) ≠ -.some x₂ y₂ h₂) : x₁ ≠ x₂ := by
  intro h_x
  subst h_x
  rcases WeierstrassCurve.Affine.Y_eq_of_X_eq h₁.1 h₂.1 rfl with h_y | h_y
  · subst h_y
    exact h_ne rfl
  · subst h_y
    exact h_ne_neg (WeierstrassCurve.Affine.Point.neg_some h₂).symm

/-- `windowSum` sums the windows' multiples of `G`: where each digit `d j` is odd and at most 63
in size, as `p256_wide_mul.c`'s are, and `entry j` is the multiple `d j * 64 ^ j` of `G`, as
`p256_wide_table.h`'s row and the C's negation of `Y` make it, `windowSum entry i` holds
`(∑ j < i, d j * 64 ^ j) • G` for every `i` with `64 ^ i` at most `G`'s order. Every addition
meets `addAffineIncomplete_represents`'s conditions: before window `j` the sum is `S • G` for an
odd `S` below `64 ^ j` in size, and `S + E` and `S - E`, for the entry `E • G`, are odd and below
`64 ^ (j + 1)` in size, so neither `S`, `S + E` nor `S - E` is a multiple of the order. -/
theorem windowSum_represents {b : F} {G : (curve b).Point} {d : ℕ → ℤ}
    (h_odd : ∀ j, Odd (d j)) (h_size : ∀ j, |d j| ≤ 63) {entry : ℕ → Affine F}
    (h_entry : ∀ j, ∃ h, (.some (entry j).x (entry j).y h : (curve b).Point) = (d j * 64 ^ j) • G)
    {i : ℕ} (h_i : 1 ≤ i) (h_order : 64 ^ i ≤ addOrderOf G) :
    Represents b (windowSum entry i) ((∑ j ∈ Finset.range i, d j * 64 ^ j) • G) := by
  induction i with
  | zero => omega
  | succ i ih =>
    rcases Nat.eq_zero_or_pos i with rfl | h_pos
    · obtain ⟨h_nonsingular, h_entry_eq⟩ := h_entry 0
      rw [Finset.sum_range_one, ← h_entry_eq]
      exact ⟨one_ne_zero, (div_one _).symm, (div_one _).symm⟩
    · obtain ⟨k, rfl⟩ : ∃ k, i = k + 1 := ⟨i - 1, by omega⟩
      have h_order_int : (64 : ℤ) ^ (k + 1 + 1) ≤ addOrderOf G := by exact_mod_cast h_order
      have h_pow_le : (64 : ℤ) ^ (k + 1) ≤ 64 ^ (k + 1 + 1) :=
        pow_le_pow_right₀ (by norm_num) (by omega)
      have h_before := ih (by omega) (by exact_mod_cast h_pow_le.trans h_order_int)
      obtain ⟨h_sum_odd, h_sum_lt⟩ := digit_sum_odd_lt h_odd h_size (i := k + 1) (by omega)
      obtain ⟨h_plus_odd, h_plus_lt⟩ :=
        odd_lt_add_digit (by omega) h_sum_odd h_sum_lt (h_size (k + 1))
      obtain ⟨h_minus_odd, h_minus_lt⟩ :=
        odd_lt_add_digit (e := -d (k + 1)) (by omega) h_sum_odd h_sum_lt
          (by rw [abs_neg]; exact h_size (k + 1))
      have h_plus_ne := zsmul_ne_zero_of_odd (G := G) h_plus_odd (h_plus_lt.trans_le h_order_int)
      have h_minus_ne :=
        zsmul_ne_zero_of_odd (G := G) h_minus_odd (h_minus_lt.trans_le h_order_int)
      have h_sum_ne := zsmul_ne_zero_of_odd (G := G) h_sum_odd
        (h_sum_lt.trans_le (h_pow_le.trans h_order_int))
      obtain ⟨h_entry_nonsingular, h_entry_eq⟩ := h_entry (k + 1)
      rcases h_sum_point : (∑ j ∈ Finset.range (k + 1), d j * 64 ^ j) • G with _ | ⟨x₁, y₁, h₁⟩
      · exact absurd h_sum_point h_sum_ne
      · rw [h_sum_point] at h_before
        have h_x : x₁ ≠ (entry (k + 1)).x := by
          refine x_ne_of_ne (h₁ := h₁) (h₂ := h_entry_nonsingular) ?_ ?_
          · rw [← h_sum_point, h_entry_eq]
            intro h_equal
            apply h_minus_ne
            rw [add_zsmul, neg_mul, neg_zsmul, h_equal, add_neg_cancel]
          · rw [← h_sum_point, h_entry_eq]
            intro h_negative
            apply h_plus_ne
            rw [add_zsmul, h_negative, neg_add_cancel]
        have h_added := addAffineIncomplete_represents (h₂ := h_entry_nonsingular) h_before h_x
        rw [Finset.sum_range_succ, add_zsmul, h_sum_point, ← h_entry_eq]
        exact h_added

end Curve

/-- `(n : ZMod Spec.P256.p) ≠ m` for two numbers whose difference `p` does not divide, which
`decide` settles on the literals. -/
private theorem cast_ne_of_mod_ne {n m : ℕ} (h_mod : n % Spec.P256.p ≠ m % Spec.P256.p) :
    (n : ZMod Spec.P256.p) ≠ m := by
  rwa [Ne, ZMod.natCast_eq_natCast_iff']

/-- `double_represents` at P-256: over `ZMod p` for P-256's prime `p`, on
`Spec.P256.curve.weierstrass`, whose `b` is P-256's (FIPS 186-4 §D.1.2.3).
`p` prime is the one hypothesis, as for every theorem here about the curve
(Spec/Weierstrass.lean); `decide` settles that 2 and 3 are not zero mod `p`
and that `b` is neither 2 nor -2 mod `p`. -/
theorem double_represents_p256 [Fact Spec.P256.p.Prime] {a : Projective (ZMod Spec.P256.p)}
    {P : Spec.P256.curve.weierstrass.Point}
    (h_represents : Represents (Spec.P256.b : ZMod Spec.P256.p) a P) :
    Represents (Spec.P256.b : ZMod Spec.P256.p) (double a) (P + P) := by
  refine double_represents ?_ ?_ ⟨?_, ?_⟩ h_represents
  · exact_mod_cast cast_ne_of_mod_ne (n := 2) (m := 0) (by decide)
  · exact_mod_cast cast_ne_of_mod_ne (n := 3) (m := 0) (by decide)
  · exact_mod_cast cast_ne_of_mod_ne (n := Spec.P256.b) (m := 2) (by decide)
  · intro h_eq
    have h_sum : ((Spec.P256.b + 2 : ℕ) : ZMod Spec.P256.p) = ((0 : ℕ) : ZMod Spec.P256.p) := by
      push_cast
      linear_combination h_eq
    exact cast_ne_of_mod_ne (by decide) h_sum

/-- `windowSum_represents` at P-256, for windows 0 to 41, the ones `p256_wide_base_mul` adds by
`addAffineIncomplete`: `64 ^ 42 = 2 ^ 252` is below `n`. `n` prime and `n • G = 0` are the
group facts taken as hypotheses, as `Spec.P256.ecdsaVerify_ecdsaSign` takes them; they make `n`
the order of `G`, which is not the point at infinity. -/
theorem windowSum_represents_p256 [Fact Spec.P256.p.Prime] [Fact Spec.P256.n.Prime]
    (h_order : Spec.P256.n • Spec.P256.basePoint = 0) {d : ℕ → ℤ} (h_odd : ∀ j, Odd (d j))
    (h_size : ∀ j, |d j| ≤ 63) {entry : ℕ → Affine (ZMod Spec.P256.p)}
    (h_entry : ∀ j, ∃ h, (.some (entry j).x (entry j).y h : Spec.P256.curve.weierstrass.Point) =
      (d j * 64 ^ j) • Spec.P256.basePoint)
    {i : ℕ} (h_i : 1 ≤ i ∧ i ≤ 42) :
    Represents (Spec.P256.b : ZMod Spec.P256.p) (windowSum entry i)
      ((∑ j ∈ Finset.range i, d j * 64 ^ j) • Spec.P256.basePoint) := by
  have h_order_eq : addOrderOf Spec.P256.basePoint = Spec.P256.n :=
    addOrderOf_eq_prime h_order (WeierstrassCurve.Affine.Point.some_ne_zero _)
  refine windowSum_represents h_odd h_size h_entry h_i.1 (le_of_le_of_eq ?_ h_order_eq.symm)
  calc 64 ^ i ≤ 64 ^ 42 := Nat.pow_le_pow_right (by norm_num) h_i.2
    _ ≤ Spec.P256.n := by decide

set_option compiler.extract_closed false in
/-- `double` against the affine group law `Spec.P256.add`: the generator with
`Z = 1` and with another `Z`, a point `Spec.P256.smul` computes, and the point
at infinity as `(0 : 1 : 0)` and as `(0 : 5 : 0)`. Then `addAffineIncomplete`
against the same law on three pairs with different x, and on a point and
itself, where it writes zero to every coordinate. -/
def selftest (_ : Unit) : Bool :=
  let affine := fun (a : Projective (ZMod Spec.P256.p)) =>
    if a.z = 0 then (none : Spec.P256.Point) else some ((a.x * a.z⁻¹).val, (a.y * a.z⁻¹).val)
  let projective := fun (q : Spec.P256.Point) (scale : ZMod Spec.P256.p) =>
    match q with
    | some (x, y) => (⟨x * scale, y * scale, scale⟩ : Projective (ZMod Spec.P256.p))
    | none => ⟨0, scale, 0⟩
  let finite := fun (q : Spec.P256.Point) =>
    match q with
    | some (x, y) => (⟨x, y⟩ : Affine (ZMod Spec.P256.p))
    | none => ⟨0, 0⟩
  let three_g := Spec.P256.smul 3 Spec.P256.g
  let five_g := Spec.P256.smul 5 Spec.P256.g
  let cases : List (Spec.P256.Point × ZMod Spec.P256.p) :=
    [(Spec.P256.g, 1), (Spec.P256.g, 0x6b8e05f5ee0f8b25101f13b6dc3d514c), (three_g, 7),
     (none, 1), (none, 5)]
  let pairs : List (Spec.P256.Point × ZMod Spec.P256.p × Spec.P256.Point) :=
    [(Spec.P256.g, 1, three_g), (three_g, 0x6b8e05f5ee0f8b25101f13b6dc3d514c, Spec.P256.g),
     (five_g, 7, three_g)]
  cases.all (fun (q, scale) =>
    affine (double (projective q scale)) == Spec.P256.add q q) &&
  (let o := double (projective none 5)
   o.x == 0 && o.y == 1 && o.z == 0) &&
  pairs.all (fun (q, scale, r) =>
    affine (addAffineIncomplete (projective q scale) (finite r)) == Spec.P256.add q r) &&
  -- A point plus itself: the x are equal, the addition does not apply, and every coordinate
  -- comes out zero.
  (let o := addAffineIncomplete (projective three_g 7) (finite three_g)
   o.x == 0 && o.y == 0 && o.z == 0)

end Spec.P256WidePoint
