import Mathlib.AlgebraicGeometry.EllipticCurve.Affine.Point
import Spec.P256

/-!
The point formulas of `p256_wide_point.c` that have no counterpart in
`p256_point.c`, and what they compute: the incomplete mixed addition
`p256_wide_point_add_affine_incomplete`, and the four routines on Jacobian
points that `p256_wide_mul` runs, `p256_wide_point_to_jacobian`,
`p256_wide_point_from_jacobian`, `p256_wide_point_double_jacobian` and
`p256_wide_point_add_jacobian_incomplete`.

Each definition here is one of those C functions: one `let` for each C
statement, in the order the C runs them, under the C's names. A statement that
writes a local the C already wrote is a second `let` of the same name, so each
line here reads against one line of the C. Each takes its coordinates in any
commutative ring. The C keeps each coordinate `v` of P-256 as `v * 2^256 mod
p`, the Montgomery domain. There a sum is a sum, and the Montgomery product of
`u * 2^256` and `v * 2^256` is `u * v * 2^256`, so the C computes each
function's answer in that domain. `test/diff_p256_wide_test.c` compares the C
with these definitions over `ZMod p`, moving each coordinate into the domain
and back out.

`addAffineIncomplete` is the Explicit-Formulas Database's madd-1998-cmo.
`addAffineIncomplete_represents` proves that it computes `P + Q` for a finite
`P` and an affine `Q` whose x differ, over every field. `p256_wide_base_mul`
(`p256_wide_mul.c`) adds windows 1 to 41 by it, and `windowSum` is that loop.
`windowSum_represents` proves that every one of those additions meets the
condition, so the loop computes the sum of the windows' multiples of `G`, for
digits that are odd and at most 63 in size, wherever `G`'s order is at least
`64 ^ 42 = 2 ^ 252`. `windowSum_represents_p256` states it at P-256, with `n`
prime and `n • G = 0` as hypotheses.

`doubleJacobian` is the database's dbl-1986-cc-2 and `addJacobianIncomplete`
its add-1998-cmo-2. `doubleJacobian_represents` proves that the first computes
`P + P` for every point `P` of every curve `y^2 = x^3 - 3x + b`, over a field
in which 2 is not zero, and `addJacobianIncomplete_represents` that the second
computes `P + Q` for two finite points whose x differ, over every field.
`toJacobian_represents` and `fromJacobian_represents` prove that the
conversions keep every point. `p256_wide_mul` computes the odd multiples of its
point by `addJacobianIncomplete`, which `multiples` is, and adds windows 62 to
1 by it, which `ladderSum` is. `multiples_represents` and
`ladderSum_represents` prove that every one of those additions meets the
condition, for digits that are odd and at most 15 in size, wherever the
point's order is at least `16 ^ 63 = 2 ^ 252`, and the `_p256` theorems state
both at P-256 for every finite point, with `n` prime and `n • P = 0` as
hypotheses. `multiples_z_eq_zero` and `ladderSum_z_eq_zero` prove the case the
C leaves to the conversion back: from the point at infinity, every multiple and
every sum is the point at infinity too.

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

/-- A point's three coordinates in Jacobian coordinates, `(X : Y : Z)`, as
`p256_wide_jacobian` holds them (`p256_wide_point.h`). -/
structure Jacobian (R : Type*) where
  /-- `X`. -/
  x : R
  /-- `Y`. -/
  y : R
  /-- `Z`. -/
  z : R

/-- `p256_wide_point_to_jacobian` (`p256_wide_point.c`): `(X Z : Y Z^2 : Z)`. -/
def toJacobian {R : Type*} [CommRing R] (a : Projective R) : Jacobian R :=
  let x := a.x * a.z
  let zz := a.z ^ 2
  let y := a.y * zz
  ⟨x, y, a.z⟩

/-- `p256_wide_point_from_jacobian` (`p256_wide_point.c`): `(X Z : Y : Z^3)`, and then `Y = 1`
where `Z = 0`, which the C does by mask. -/
def fromJacobian {R : Type*} [CommRing R] [DecidableEq R] (a : Jacobian R) : Projective R :=
  let x := a.x * a.z
  let zz := a.z ^ 2
  let z := zz * a.z
  let y := a.y
  let y := if a.z = 0 then 1 else y
  ⟨x, y, z⟩

/-- `p256_wide_point_double_jacobian` (`p256_wide_point.c`): the Explicit-Formulas Database's
dbl-1986-cc-2 for `a = -3`, with `s = 4 X1 Y1^2` and `m = 3 (X1 - Z1^2) (X1 + Z1^2)`, giving
`X3 = m^2 - 2 s`, `Y3 = m (s - X3) - 8 Y1^4` and `Z3 = 2 Y1 Z1`. -/
def doubleJacobian {R : Type*} [CommRing R] (a : Jacobian R) : Jacobian R :=
  let z3 := a.y * a.z
  let z3 := z3 + z3
  let zz := a.z ^ 2
  let t := a.x - zz
  let m := a.x + zz
  let m := t * m
  let t := m + m
  let m := t + m
  let yy := a.y ^ 2
  let s := a.x * yy
  let s := s + s
  let s := s + s
  let x3 := m ^ 2
  let t := s + s
  let x3 := x3 - t
  let t := s - x3
  let y3 := m * t
  let yyyy := yy ^ 2
  let yyyy := yyyy + yyyy
  let yyyy := yyyy + yyyy
  let yyyy := yyyy + yyyy
  let y3 := y3 - yyyy
  ⟨x3, y3, z3⟩

/-- `p256_wide_point_add_jacobian_incomplete` (`p256_wide_point.c`): the Explicit-Formulas
Database's add-1998-cmo-2, with `h = X2 Z1^2 - X1 Z2^2`, `r = Y2 Z1^3 - Y1 Z2^3` and
`v = X1 Z2^2 h^2`, giving `X3 = r^2 - h^3 - 2 v`, `Y3 = r (v - X3) - Y1 Z2^3 h^3` and
`Z3 = Z1 Z2 h`. -/
def addJacobianIncomplete {R : Type*} [CommRing R] (a b : Jacobian R) : Jacobian R :=
  let z1z1 := a.z ^ 2
  let z2z2 := b.z ^ 2
  let u1 := a.x * z2z2
  let u2 := b.x * z1z1
  let s1 := a.y * b.z
  let s1 := s1 * z2z2
  let s2 := b.y * a.z
  let s2 := s2 * z1z1
  let h := u2 - u1
  let z3 := a.z * b.z
  let z3 := z3 * h
  let hh := h ^ 2
  let hhh := h * hh
  let r := s2 - s1
  let v := u1 * hh
  let x3 := r ^ 2
  let x3 := x3 - hhh
  let t := v + v
  let x3 := x3 - t
  let t := v - x3
  let y3 := r * t
  let t := s1 * hhh
  let y3 := y3 - t
  ⟨x3, y3, z3⟩

/-- The odd multiples `p256_wide_mul` (`p256_wide_mul.c`) computes first: `multiples a 0` is `a`,
and `multiples a (j + 1)` is `multiples a j` plus `doubleJacobian a`, by
`addJacobianIncomplete`. The C computes them for `j` up to 7. -/
def multiples {R : Type*} [CommRing R] (a : Jacobian R) : ℕ → Jacobian R
  | 0 => a
  | j + 1 => addJacobianIncomplete (multiples a j) (doubleJacobian a)

/-- The sum `p256_wide_mul` (`p256_wide_mul.c`) holds after windows 63 down to `63 - m`, for the
entry `entry j` of window `63 - j`: window 63's entry, and for each later window four doublings
by `doubleJacobian` and that window's entry added by `addJacobianIncomplete`. The C runs it to
`m = 62` and adds window 0 and the correction by the complete addition, in homogeneous
coordinates, which this module does not model. -/
def ladderSum {R : Type*} [CommRing R] (entry : ℕ → Jacobian R) : ℕ → Jacobian R
  | 0 => entry 0
  | m + 1 =>
    addJacobianIncomplete
      (doubleJacobian (doubleJacobian (doubleJacobian (doubleJacobian (ladderSum entry m)))))
      (entry (m + 1))

/-- The multiple of its point `ladderSum` holds, for the digit `e j` of window `63 - j`: `e 0`, and
then sixteen times the multiple so far plus each next digit. -/
def ladderScalar (e : ℕ → ℤ) : ℕ → ℤ
  | 0 => e 0
  | m + 1 => 16 * ladderScalar e m + e (m + 1)

/-- Where `a`'s `Z` is zero, so is the `Z` of every multiple `multiples a` computes: the point at
infinity's multiples are the point at infinity. -/
theorem multiples_z_eq_zero {R : Type*} [CommRing R] {a : Jacobian R} (h_z : a.z = 0) (j : ℕ) :
    (multiples a j).z = 0 := by
  induction j with
  | zero => exact h_z
  | succ j ih =>
    simp only [multiples, addJacobianIncomplete, ih]
    ring

/-- Where every entry's `Z` is zero, so is the `Z` of every sum `ladderSum` computes. -/
theorem ladderSum_z_eq_zero {R : Type*} [CommRing R] {entry : ℕ → Jacobian R}
    (h_z : ∀ j, (entry j).z = 0) (m : ℕ) : (ladderSum entry m).z = 0 := by
  cases m with
  | zero => exact h_z 0
  | succ m =>
    simp only [ladderSum, addJacobianIncomplete, h_z]
    ring

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

/-- A multiple of `G` by a number that is not zero, below `G`'s order in size, is not zero. -/
private theorem zsmul_ne_zero_of_ne_zero {A : Type*} [AddCommGroup A] {G : A} {S : ℤ}
    (h_ne : S ≠ 0) (h_lt : |S| < addOrderOf G) : S • G ≠ 0 := fun h_zero =>
  h_ne (Int.eq_zero_of_abs_lt_dvd (addOrderOf_dvd_iff_zsmul_eq_zero.mpr h_zero) h_lt)

/-- An odd multiple of `G`, below `G`'s order in size, is not zero. -/
private theorem zsmul_ne_zero_of_odd {A : Type*} [AddCommGroup A] {G : A} {S : ℤ}
    (h_odd : Odd S) (h_lt : |S| < addOrderOf G) : S • G ≠ 0 :=
  zsmul_ne_zero_of_ne_zero (fun h_zero => by simp [h_zero] at h_odd) h_lt

/-- One window's step of the bound `ladderSum_represents` rests on: sixteen times an `S` below
`16 ^ (m + 1)` in size, plus an odd digit of at most 15 in size, is odd and below `16 ^ (m + 2)`
in size. -/
private theorem odd_lt_next_window {S e : ℤ} {m : ℕ} (h_lt : |S| < 16 ^ (m + 1))
    (h_e_odd : Odd e) (h_e : |e| ≤ 15) :
    Odd (16 * S + e) ∧ |16 * S + e| < 16 ^ (m + 2) := by
  refine ⟨Even.add_odd ⟨8 * S, by ring⟩ h_e_odd, ?_⟩
  have h_S : |S| + 1 ≤ 16 ^ (m + 1) := Int.lt_iff_add_one_le.mp h_lt
  have h_pow : (16 : ℤ) ^ (m + 2) = 16 * 16 ^ (m + 1) := by ring
  calc |16 * S + e| ≤ |16 * S| + |e| := abs_add_le _ _
    _ = 16 * |S| + |e| := by rw [abs_mul, abs_of_pos (by norm_num : (0 : ℤ) < 16)]
    _ < 16 ^ (m + 2) := by linarith

/-- The multiple `ladderScalar` gives after window `63 - m` is odd and below `16 ^ (m + 1)` in size,
for digits that are odd and at most 15 in size. -/
private theorem ladderScalar_odd_lt {e : ℕ → ℤ} (h_odd : ∀ j, Odd (e j))
    (h_size : ∀ j, |e j| ≤ 15) (m : ℕ) :
    Odd (ladderScalar e m) ∧ |ladderScalar e m| < 16 ^ (m + 1) := by
  induction m with
  | zero => exact ⟨h_odd 0, by simp only [ladderScalar, zero_add, pow_one]; linarith [h_size 0]⟩
  | succ m ih => exact odd_lt_next_window ih.2 (h_odd (m + 1)) (h_size (m + 1))

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

/-- `a` holds the point `P` of `curve b` in Jacobian coordinates: the point at infinity as any
`(X : Y : 0)`, and the affine point `(x, y)` as `(X : Y : Z)` with `Z ≠ 0`, `x = X / Z^2` and
`y = Y / Z^3`. -/
def RepresentsJacobian (b : F) (a : Jacobian F) : (curve b).Point → Prop
  | .zero => a.z = 0
  | .some x y _ => a.z ≠ 0 ∧ x = a.x / a.z ^ 2 ∧ y = a.y / a.z ^ 3

omit [DecidableEq F] in
/-- `toJacobian` keeps the point: where `a` holds `P` in homogeneous coordinates, `toJacobian a`
holds `P` in Jacobian ones, for every point of every curve, over every field. -/
theorem toJacobian_represents {b : F} {a : Projective F} {P : (curve b).Point}
    (h_represents : Represents b a P) : RepresentsJacobian b (toJacobian a) P := by
  obtain ⟨x, y, z⟩ := a
  cases P with
  | zero =>
    obtain ⟨-, -, rfl⟩ := h_represents
    rfl
  | some u v h_nonsingular =>
    obtain ⟨h_z, rfl, rfl⟩ := h_represents
    refine ⟨h_z, ?_, ?_⟩ <;> simp only [toJacobian] <;> field_simp

/-- `fromJacobian` keeps the point: where `a` holds `P` in Jacobian coordinates, `fromJacobian a`
holds `P` in homogeneous ones, the point at infinity as `(0 : 1 : 0)`, for every point of every
curve, over every field. -/
theorem fromJacobian_represents {b : F} {a : Jacobian F} {P : (curve b).Point}
    (h_represents : RepresentsJacobian b a P) : Represents b (fromJacobian a) P := by
  obtain ⟨x, y, z⟩ := a
  cases P with
  | zero =>
    change z = 0 at h_represents
    subst h_represents
    simp [Represents, fromJacobian]
  | some u v h_nonsingular =>
    obtain ⟨h_z, rfl, rfl⟩ := h_represents
    simp only [Represents, fromJacobian, if_neg h_z]
    refine ⟨mul_ne_zero (pow_ne_zero 2 h_z) h_z, ?_, ?_⟩ <;> field_simp

/-- `doubleJacobian` doubles: where `a` holds `P`, `doubleJacobian a` holds `P + P`. That covers
every point of the curve, the point at infinity and a point with `y = 0` among them, on every curve
`y^2 = x^3 - 3x + b`, over every field in which 2 is not zero. -/
theorem doubleJacobian_represents (h_two : (2 : F) ≠ 0) {b : F} {a : Jacobian F}
    {P : (curve b).Point} (h_represents : RepresentsJacobian b a P) :
    RepresentsJacobian b (doubleJacobian a) (P + P) := by
  obtain ⟨x, y, z⟩ := a
  cases P with
  | zero =>
    change z = 0 at h_represents
    subst h_represents
    change (doubleJacobian _).z = 0
    simp [doubleJacobian]
  | some u v h_nonsingular =>
    obtain ⟨h_z, rfl, rfl⟩ := h_represents
    dsimp only at h_z h_nonsingular ⊢
    by_cases h_y : y = 0
    · subst h_y
      have h_own_negative : 0 / z ^ 3 = (curve b).negY (x / z ^ 2) (0 / z ^ 3) := by simp [curve]
      rw [WeierstrassCurve.Affine.Point.add_self_of_Y_eq h_own_negative]
      change (doubleJacobian _).z = 0
      simp [doubleJacobian]
    · have h_z3 : y * z + y * z ≠ 0 := by
        rw [← two_mul]
        exact mul_ne_zero h_two (mul_ne_zero h_y h_z)
      have h_negY : y / z ^ 3 ≠ (curve b).negY (x / z ^ 2) (y / z ^ 3) := by
        simp only [curve, WeierstrassCurve.Affine.negY]
        intro h_eq
        have h_twice : 2 * (y / z ^ 3) = 0 := by linear_combination h_eq
        rcases mul_eq_zero.mp h_twice with h_two_zero | h_quotient
        · exact h_two h_two_zero
        · exact h_y ((div_eq_zero_iff.mp h_quotient).resolve_right (pow_ne_zero 3 h_z))
      rw [WeierstrassCurve.Affine.Point.add_of_Y_ne h_negY]
      simp only [RepresentsJacobian, doubleJacobian]
      -- The C's Z3, 2 Y1 Z1, stays one name until the denominators are gone, so that no numeral
      -- lands in a denominator, where field_simp would need it to be nonzero.
      set z3 := y * z + y * z with h_z3_def
      have h_slope : (curve b).slope (x / z ^ 2) (x / z ^ 2) (y / z ^ 3) (y / z ^ 3) =
          3 * ((x - z ^ 2) * (x + z ^ 2)) / z3 := by
        rw [WeierstrassCurve.Affine.slope_of_Y_ne rfl h_negY,
          div_eq_div_iff (sub_ne_zero.mpr h_negY) h_z3]
        simp only [curve, WeierstrassCurve.Affine.negY]
        field_simp
        rw [h_z3_def]
        ring
      rw [h_slope]
      refine ⟨h_z3, ?_, ?_⟩
      · simp only [WeierstrassCurve.Affine.addX, curve]
        field_simp
        rw [h_z3_def]
        ring
      · simp only [WeierstrassCurve.Affine.addY, WeierstrassCurve.Affine.negAddY,
          WeierstrassCurve.Affine.addX, curve, WeierstrassCurve.Affine.negY]
        field_simp
        rw [h_z3_def]
        ring

/-- `addJacobianIncomplete` adds: where `a` holds a finite point `(x₁, y₁)` and `c` a finite point
`(x₂, y₂)` with `x₁ ≠ x₂`, `addJacobianIncomplete a c` holds their sum. That covers every such pair
on every curve `y^2 = x^3 - 3x + b`, over every field. -/
theorem addJacobianIncomplete_represents {b : F} {a c : Jacobian F} {x₁ y₁ x₂ y₂ : F}
    {h₁ : (curve b).Nonsingular x₁ y₁} {h₂ : (curve b).Nonsingular x₂ y₂}
    (h_a : RepresentsJacobian b a (.some x₁ y₁ h₁))
    (h_c : RepresentsJacobian b c (.some x₂ y₂ h₂)) (h_x : x₁ ≠ x₂) :
    RepresentsJacobian b (addJacobianIncomplete a c) (.some x₁ y₁ h₁ + .some x₂ y₂ h₂) := by
  obtain ⟨X₁, Y₁, Z₁⟩ := a
  obtain ⟨X₂, Y₂, Z₂⟩ := c
  obtain ⟨h_z₁, h_x₁, h_y₁⟩ := h_a
  obtain ⟨h_z₂, h_x₂, h_y₂⟩ := h_c
  dsimp only at h_z₁ h_x₁ h_y₁ h_z₂ h_x₂ h_y₂ ⊢
  -- The C's coordinates are the affine ones times powers of Z.
  obtain rfl : X₁ = x₁ * Z₁ ^ 2 := by rw [h_x₁, div_mul_cancel₀ _ (pow_ne_zero 2 h_z₁)]
  obtain rfl : Y₁ = y₁ * Z₁ ^ 3 := by rw [h_y₁, div_mul_cancel₀ _ (pow_ne_zero 3 h_z₁)]
  obtain rfl : X₂ = x₂ * Z₂ ^ 2 := by rw [h_x₂, div_mul_cancel₀ _ (pow_ne_zero 2 h_z₂)]
  obtain rfl : Y₂ = y₂ * Z₂ ^ 3 := by rw [h_y₂, div_mul_cancel₀ _ (pow_ne_zero 3 h_z₂)]
  rw [WeierstrassCurve.Affine.Point.add_of_X_ne h_x]
  have h_z3 : Z₁ * Z₂ * (x₂ * Z₂ ^ 2 * Z₁ ^ 2 - x₁ * Z₁ ^ 2 * Z₂ ^ 2) ≠ 0 := by
    have h_h : x₂ * Z₂ ^ 2 * Z₁ ^ 2 - x₁ * Z₁ ^ 2 * Z₂ ^ 2 = (x₂ - x₁) * (Z₁ ^ 2 * Z₂ ^ 2) := by
      ring
    rw [h_h]
    exact mul_ne_zero (mul_ne_zero h_z₁ h_z₂)
      (mul_ne_zero (sub_ne_zero.mpr h_x.symm) (mul_ne_zero (pow_ne_zero 2 h_z₁) (pow_ne_zero 2 h_z₂)))
  simp only [RepresentsJacobian, addJacobianIncomplete]
  rw [WeierstrassCurve.Affine.slope_of_X_ne h_x]
  refine ⟨h_z3, ?_, ?_⟩
  · rw [eq_div_iff (pow_ne_zero 2 h_z3)]
    simp only [WeierstrassCurve.Affine.addX, curve]
    field_simp
    ring
  · rw [eq_div_iff (pow_ne_zero 3 h_z3)]
    simp only [WeierstrassCurve.Affine.addY, WeierstrassCurve.Affine.negAddY,
      WeierstrassCurve.Affine.addX, curve, WeierstrassCurve.Affine.negY]
    field_simp
    ring

/-- The incomplete addition of `Q • P` and `E • P` meets `addJacobianIncomplete_represents`'s
conditions where `Q`, `E`, `Q + E` and `Q - E` are not zero and are below `P`'s order in size:
both points are finite, and neither is the other or its negative. -/
private theorem addJacobianIncomplete_zsmul {b : F} {P : (curve b).Point} {a c : Jacobian F}
    {Q E : ℤ} (h_a : RepresentsJacobian b a (Q • P)) (h_c : RepresentsJacobian b c (E • P))
    (h_Q : Q ≠ 0 ∧ |Q| < addOrderOf P) (h_E : E ≠ 0 ∧ |E| < addOrderOf P)
    (h_plus : Q + E ≠ 0 ∧ |Q + E| < addOrderOf P) (h_minus : Q - E ≠ 0 ∧ |Q - E| < addOrderOf P) :
    RepresentsJacobian b (addJacobianIncomplete a c) ((Q + E) • P) := by
  have h_Q_ne := zsmul_ne_zero_of_ne_zero (G := P) h_Q.1 h_Q.2
  have h_E_ne := zsmul_ne_zero_of_ne_zero (G := P) h_E.1 h_E.2
  have h_plus_ne := zsmul_ne_zero_of_ne_zero (G := P) h_plus.1 h_plus.2
  have h_minus_ne := zsmul_ne_zero_of_ne_zero (G := P) h_minus.1 h_minus.2
  rw [add_zsmul]
  rcases h_Q_point : Q • P with _ | ⟨x₁, y₁, h₁⟩
  · exact absurd h_Q_point h_Q_ne
  rcases h_E_point : E • P with _ | ⟨x₂, y₂, h₂⟩
  · exact absurd h_E_point h_E_ne
  rw [h_Q_point] at h_a
  rw [h_E_point] at h_c
  refine addJacobianIncomplete_represents h_a h_c (x_ne_of_ne (h₁ := h₁) (h₂ := h₂) ?_ ?_)
  · rw [← h_Q_point, ← h_E_point]
    intro h_equal
    apply h_minus_ne
    rw [sub_zsmul, h_equal]
    exact sub_self _
  · rw [← h_Q_point, ← h_E_point]
    intro h_negative
    apply h_plus_ne
    rw [add_zsmul, h_negative, neg_add_cancel]

/-- `multiples` computes the odd multiples of its point: where `a` holds `P` and `P`'s order is at
least 16, `multiples a j` holds `(2 j + 1) • P` for `j` up to 7. Every addition meets
`addJacobianIncomplete_represents`'s conditions: `2 j - 1`, `2`, `2 j + 1` and `2 j - 3` are not
zero and are at most 15 in size. -/
theorem multiples_represents (h_two : (2 : F) ≠ 0) {b : F} {a : Jacobian F}
    {P : (curve b).Point} (h_represents : RepresentsJacobian b a P) (h_order : 16 ≤ addOrderOf P)
    {j : ℕ} (h_j : j ≤ 7) : RepresentsJacobian b (multiples a j) ((2 * j + 1 : ℤ) • P) := by
  have h_order_int : (16 : ℤ) ≤ addOrderOf P := by exact_mod_cast h_order
  induction j with
  | zero => simpa [multiples] using h_represents
  | succ j ih =>
    simp only [multiples]
    have h_twice : RepresentsJacobian b (doubleJacobian a) ((2 : ℤ) • P) := by
      rw [two_zsmul]
      exact doubleJacobian_represents h_two h_represents
    have h_sum := addJacobianIncomplete_zsmul (ih (by omega)) h_twice
      ⟨by omega, by rw [abs_lt]; constructor <;> omega⟩
      ⟨by norm_num, by rw [abs_lt]; constructor <;> omega⟩
      ⟨by omega, by rw [abs_lt]; constructor <;> omega⟩
      ⟨by omega, by rw [abs_lt]; constructor <;> omega⟩
    convert h_sum using 2
    push_cast
    ring

/-- `ladderSum` sums the windows' multiples of `P`: where each digit `e j` is odd and at most 15 in
size, as `p256_wide_mul.c`'s are, and `entry j` holds `e j • P`, as the C's scan of its odd
multiples and its negation of `Y` make it, `ladderSum entry m` holds `ladderScalar e m • P` for
every `m` with `16 ^ (m + 1)` at most `P`'s order. Every addition meets
`addJacobianIncomplete_represents`'s conditions: before window `63 - (m + 1)` the four doublings
leave `(16 S) • P` for an odd `S` below `16 ^ (m + 1)` in size, and `16 S`, `16 S + E` and
`16 S - E`, for the entry `E • P`, are not zero and are below `16 ^ (m + 2)` in size, so none is a
multiple of the order. -/
theorem ladderSum_represents (h_two : (2 : F) ≠ 0) {b : F} {P : (curve b).Point} {e : ℕ → ℤ}
    (h_odd : ∀ j, Odd (e j)) (h_size : ∀ j, |e j| ≤ 15) {entry : ℕ → Jacobian F}
    (h_entry : ∀ j, RepresentsJacobian b (entry j) (e j • P)) {m : ℕ}
    (h_order : 16 ^ (m + 1) ≤ addOrderOf P) :
    RepresentsJacobian b (ladderSum entry m) (ladderScalar e m • P) := by
  induction m with
  | zero => exact h_entry 0
  | succ m ih =>
    have h_order_int : (16 : ℤ) ^ (m + 2) ≤ addOrderOf P := by exact_mod_cast h_order
    have h_pow_le : (16 : ℤ) ^ (m + 1) ≤ 16 ^ (m + 2) := pow_le_pow_right₀ (by norm_num) (by omega)
    have h_before := ih (by exact_mod_cast h_pow_le.trans h_order_int)
    set S := ladderScalar e m with h_S_def
    obtain ⟨h_S_odd, h_S_lt⟩ := ladderScalar_odd_lt h_odd h_size m
    rw [← h_S_def] at h_S_odd h_S_lt
    have h_doubled : RepresentsJacobian b
        (doubleJacobian (doubleJacobian (doubleJacobian (doubleJacobian (ladderSum entry m)))))
        ((16 * S) • P) := by
      have h_four := doubleJacobian_represents h_two (doubleJacobian_represents h_two
        (doubleJacobian_represents h_two (doubleJacobian_represents h_two h_before)))
      convert h_four using 1
      simp only [← add_zsmul]
      congr 1
      ring
    obtain ⟨h_plus_odd, h_plus_lt⟩ := odd_lt_next_window h_S_lt (h_odd (m + 1)) (h_size (m + 1))
    obtain ⟨h_minus_odd, h_minus_lt⟩ := odd_lt_next_window (e := -e (m + 1)) h_S_lt
      (h_odd (m + 1)).neg (by rw [abs_neg]; exact h_size (m + 1))
    have h_S_ne : S ≠ 0 := fun h_zero => by obtain ⟨k, h_k⟩ := h_S_odd; omega
    have h_sixteen_lt : |16 * S| < 16 ^ (m + 2) := by
      rw [abs_mul, abs_of_pos (by norm_num : (0 : ℤ) < 16)]
      calc 16 * |S| < 16 * 16 ^ (m + 1) := by linarith
        _ = 16 ^ (m + 2) := by ring
    have h_e_lt : |e (m + 1)| < 16 ^ (m + 2) := by
      calc |e (m + 1)| ≤ 15 := h_size (m + 1)
        _ < 16 ^ 1 := by norm_num
        _ ≤ 16 ^ (m + 2) := pow_le_pow_right₀ (by norm_num) (by omega)
    have h_e_ne : e (m + 1) ≠ 0 := fun h_zero => by obtain ⟨k, h_k⟩ := h_odd (m + 1); omega
    have h_sum := addJacobianIncomplete_zsmul h_doubled (h_entry (m + 1))
      ⟨mul_ne_zero (by norm_num) h_S_ne, h_sixteen_lt.trans_le h_order_int⟩
      ⟨h_e_ne, h_e_lt.trans_le h_order_int⟩
      ⟨fun h_zero => by obtain ⟨k, h_k⟩ := h_plus_odd; omega, h_plus_lt.trans_le h_order_int⟩
      ⟨fun h_zero => by obtain ⟨k, h_k⟩ := h_minus_odd; omega,
        (by rw [sub_eq_add_neg]; exact h_minus_lt.trans_le h_order_int)⟩
    simpa only [ladderSum, ladderScalar] using h_sum

end Curve

/-- `(n : ZMod Spec.P256.p) ≠ m` for two numbers whose difference `p` does not divide, which
`decide` settles on the literals. -/
private theorem cast_ne_of_mod_ne {n m : ℕ} (h_mod : n % Spec.P256.p ≠ m % Spec.P256.p) :
    (n : ZMod Spec.P256.p) ≠ m := by
  rwa [Ne, ZMod.natCast_eq_natCast_iff']

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

/-- `(2 : ZMod p) ≠ 0` for P-256's prime `p`, which `decide` settles on the literals. -/
private theorem two_ne_zero_p256 [Fact Spec.P256.p.Prime] : (2 : ZMod Spec.P256.p) ≠ 0 := by
  exact_mod_cast cast_ne_of_mod_ne (n := 2) (m := 0) (by decide)

/-- `multiples_represents` at P-256, for every finite point `P`: `n` prime and `n • P = 0` make
`n` the order of `P`, and `n` is above 16. -/
theorem multiples_represents_p256 [Fact Spec.P256.p.Prime] [Fact Spec.P256.n.Prime]
    {P : Spec.P256.curve.weierstrass.Point} (h_order : Spec.P256.n • P = 0) (h_P : P ≠ 0)
    {a : Jacobian (ZMod Spec.P256.p)}
    (h_represents : RepresentsJacobian (Spec.P256.b : ZMod Spec.P256.p) a P) {j : ℕ}
    (h_j : j ≤ 7) :
    RepresentsJacobian (Spec.P256.b : ZMod Spec.P256.p) (multiples a j) ((2 * j + 1 : ℤ) • P) := by
  have h_order_eq : addOrderOf P = Spec.P256.n := addOrderOf_eq_prime h_order h_P
  refine multiples_represents two_ne_zero_p256 h_represents (le_of_le_of_eq ?_ h_order_eq.symm) h_j
  decide

/-- `ladderSum_represents` at P-256, for windows 63 down to 1, the ones `p256_wide_mul` adds by
`addJacobianIncomplete`, and every finite point `P`: `16 ^ 63 = 2 ^ 252` is below `n`. `n` prime
and `n • P = 0` are the group facts taken as hypotheses, as `windowSum_represents_p256` takes
them for `G`; they make `n` the order of `P`. -/
theorem ladderSum_represents_p256 [Fact Spec.P256.p.Prime] [Fact Spec.P256.n.Prime]
    {P : Spec.P256.curve.weierstrass.Point} (h_order : Spec.P256.n • P = 0) (h_P : P ≠ 0)
    {e : ℕ → ℤ} (h_odd : ∀ j, Odd (e j)) (h_size : ∀ j, |e j| ≤ 15)
    {entry : ℕ → Jacobian (ZMod Spec.P256.p)}
    (h_entry : ∀ j, RepresentsJacobian (Spec.P256.b : ZMod Spec.P256.p) (entry j) (e j • P))
    {m : ℕ} (h_m : m ≤ 62) :
    RepresentsJacobian (Spec.P256.b : ZMod Spec.P256.p) (ladderSum entry m)
      (ladderScalar e m • P) := by
  have h_order_eq : addOrderOf P = Spec.P256.n := addOrderOf_eq_prime h_order h_P
  refine ladderSum_represents two_ne_zero_p256 h_odd h_size h_entry
    (le_of_le_of_eq ?_ h_order_eq.symm)
  calc 16 ^ (m + 1) ≤ 16 ^ 63 := Nat.pow_le_pow_right (by norm_num) (by omega)
    _ ≤ Spec.P256.n := by decide

set_option compiler.extract_closed false in
/-- `addAffineIncomplete` against the affine group law `Spec.P256.add` on three pairs with
different x, and on a point and itself, where it writes zero to every coordinate. Then the
Jacobian routines against the same law: `doubleJacobian` on the generator with `Z = 1` and with
another `Z`, a point `Spec.P256.smul` computes, and the point at infinity as `(5 : 7 : 0)`;
`addJacobianIncomplete` on the same three pairs; and each conversion on the same points, with the
point at infinity's `Y` moved to 1 where it is 0. -/
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
  let jacobian := fun (q : Spec.P256.Point) (scale : ZMod Spec.P256.p) =>
    match q with
    | some (x, y) => (⟨x * scale ^ 2, y * scale ^ 3, scale⟩ : Jacobian (ZMod Spec.P256.p))
    | none => ⟨5, 7, 0⟩
  let affineJacobian := fun (a : Jacobian (ZMod Spec.P256.p)) =>
    if a.z = 0 then (none : Spec.P256.Point)
    else some ((a.x * (a.z ^ 2)⁻¹).val, (a.y * (a.z ^ 3)⁻¹).val)
  let three_g := Spec.P256.smul 3 Spec.P256.g
  let five_g := Spec.P256.smul 5 Spec.P256.g
  let cases : List (Spec.P256.Point × ZMod Spec.P256.p) :=
    [(Spec.P256.g, 1), (Spec.P256.g, 0x6b8e05f5ee0f8b25101f13b6dc3d514c), (three_g, 7),
     (none, 1), (none, 5)]
  let pairs : List (Spec.P256.Point × ZMod Spec.P256.p × Spec.P256.Point) :=
    [(Spec.P256.g, 1, three_g), (three_g, 0x6b8e05f5ee0f8b25101f13b6dc3d514c, Spec.P256.g),
     (five_g, 7, three_g)]
  pairs.all (fun (q, scale, r) =>
    affine (addAffineIncomplete (projective q scale) (finite r)) == Spec.P256.add q r) &&
  -- A point plus itself: the x are equal, the addition does not apply, and every coordinate
  -- comes out zero.
  (let o := addAffineIncomplete (projective three_g 7) (finite three_g)
   o.x == 0 && o.y == 0 && o.z == 0) &&
  cases.all (fun (q, scale) =>
    affineJacobian (doubleJacobian (jacobian q scale)) == Spec.P256.add q q) &&
  pairs.all (fun (q, scale, r) =>
    affineJacobian (addJacobianIncomplete (jacobian q scale) (jacobian r 3)) ==
      Spec.P256.add q r) &&
  cases.all (fun (q, scale) =>
    affineJacobian (toJacobian (projective q scale)) == q &&
      affine (fromJacobian (jacobian q scale)) == q) &&
  (let o := fromJacobian (⟨5, 0, 0⟩ : Jacobian (ZMod Spec.P256.p))
   o.x == 0 && o.y == 1 && o.z == 0)

end Spec.P256WidePoint
