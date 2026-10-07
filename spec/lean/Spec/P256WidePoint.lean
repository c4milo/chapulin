import Mathlib.AlgebraicGeometry.EllipticCurve.Affine.Point
import Spec.P256

/-!
The doubling of `p256_wide_point.c`, `p256_wide_point_double`, and what it
computes.

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

set_option compiler.extract_closed false in
/-- `double` against the affine group law `Spec.P256.add`: the generator with
`Z = 1` and with another `Z`, a point `Spec.P256.smul` computes, and the point
at infinity as `(0 : 1 : 0)` and as `(0 : 5 : 0)`. -/
def selftest (_ : Unit) : Bool :=
  let affine := fun (a : Projective (ZMod Spec.P256.p)) =>
    if a.z = 0 then (none : Spec.P256.Point) else some ((a.x * a.z⁻¹).val, (a.y * a.z⁻¹).val)
  let projective := fun (q : Spec.P256.Point) (scale : ZMod Spec.P256.p) =>
    match q with
    | some (x, y) => (⟨x * scale, y * scale, scale⟩ : Projective (ZMod Spec.P256.p))
    | none => ⟨0, scale, 0⟩
  let three_g := Spec.P256.smul 3 Spec.P256.g
  let cases : List (Spec.P256.Point × ZMod Spec.P256.p) :=
    [(Spec.P256.g, 1), (Spec.P256.g, 0x6b8e05f5ee0f8b25101f13b6dc3d514c), (three_g, 7),
     (none, 1), (none, 5)]
  cases.all (fun (q, scale) =>
    affine (double (projective q scale)) == Spec.P256.add q q) &&
  (let o := double (projective none 5)
   o.x == 0 && o.y == 1 && o.z == 0)

end Spec.P256WidePoint
