import Mathlib.AlgebraicGeometry.EllipticCurve.Affine.Point
import Mathlib.Data.ZMod.Basic
import Mathlib.Tactic

/-!
The key generation of `x25519_wide.c`, in `x25519_wide_edwards.h`, and why it computes the u
that the ladder computes: s times the base point of edwards25519, mapped to curve25519
(docs/decisions.md 148).

The first part is the C. `addEntry`, `doublePoint` and `toExtended` are `add_entry`,
`double_point` and `to_extended`, one `let` for each C statement, in the order the C runs them,
under the C's names. `entryOf` is an entry of the table, `negate` what `select_entry` does to an
entry for a negative digit, and `toU` the u the C writes last. `addEntry_represents` and
`doublePoint_represents` prove that the formulas compute the twisted Edwards addition law, `edAdd`,
of -x² + y² = 1 + d x² y², wherever its denominators are not zero, and `product_sq_ne_one` proves
that they never are for two points of the curve when d is not a square and -1 is: the addition
law is complete (Bernstein, Birkner, Joye, Lange and Peters, 2008).

The second part is the map. `mont d` is the Montgomery curve of the Edwards curve as a Weierstrass
curve of Mathlib: y² = x³ + 2 (d - 1) x² + (1 + d)² x, which is B v² = u³ + A u² + u with
A = 2 (1 - d) / (1 + d) and B = -4 / (1 + d) under x = -(1 + d) u and y = 2 (1 + d) v. At
d = -121665 / 121666 it is curve25519, with x = -u / 121666, since B = -486664 is a square. `toMont` maps a point (x, y) of the Edwards curve to the point with
u = (1 + y) / (1 - y) (RFC 7748 section 4.1), the identity to the identity, and (0, -1) to the
point of order two. `toMont_add` proves that it takes the sum of two points to the sum of their
images, for every field in which 2 is not zero, d is not a square and -1 is.

The third part puts the two together. `baseMul` is `x25519_wide_base_mul`'s loop over points of
the curve: the entries of the 32 odd digits, four doublings and the entries of the 32 even digits,
an entry being k 256^i B. `toMont_baseMul` proves that its image is the sum of the digits times the
image of B, so it is s times the image of B for digits that add up to s, which
proof/x25519_wide_select_harness.c proves of `recode`. `baseMulExtended` is the same loop in
extended coordinates, as the C runs it, `baseMulExtended_represents` proves that it holds
`baseMul`'s point at every step, and `toU_baseMulExtended` that the u it ends with is the u of
the sum of the digits times the image of B.

What no theorem here states: that the ladder of spec/lean/Spec/X25519.lean computes the u of s
times the point u = 9 of Mathlib's group. bin/x25519_equiv_test and bin/diff_x25519_wide hold the
two to the same bytes, and test/diff_x25519_edwards_test.c holds the C's formulas to the ones
here.

This module is written from the C, not from a standard, and CONTRACT.md says why.
-/

namespace Spec.X25519Edwards

/-- A point in extended coordinates, `edwards_point`: x = X / Z, y = Y / Z and T = X Y / Z. -/
structure Extended (R : Type*) where
  /-- X. -/
  x : R
  /-- Y. -/
  y : R
  /-- Z. -/
  z : R
  /-- T. -/
  t : R

/-- A sum before its last four products, `edwards_sum`: x = E / G and y = H / F. -/
structure Completed (R : Type*) where
  /-- E. -/
  e : R
  /-- H. -/
  h : R
  /-- G. -/
  g : R
  /-- F. -/
  f : R

/-- An entry of the table, `edwards_entry`: y + x, y - x and 2 d x y. -/
structure Entry (R : Type*) where
  /-- y + x. -/
  yPlusX : R
  /-- y - x. -/
  yMinusX : R
  /-- 2 d x y. -/
  xy2d : R

section Formulas

variable {R : Type*} [CommRing R]

/-- `add_entry`: madd-2008-hwcd-3, with `difference_and_sum` as its two last steps. -/
def addEntry (a : Extended R) (b : Entry R) : Completed R :=
  let e := a.y + a.x
  let h := a.y - a.x
  let e := e * b.yPlusX
  let h := h * b.yMinusX
  let g := a.t * b.xy2d
  let f := a.z + a.z
  let first := e
  let e := first - h
  let h := first + h
  let first := f
  let f := first - g
  let g := first + g
  ⟨e, h, g, f⟩

/-- `double_point`: dbl-2008-hwcd for a = -1. -/
def doublePoint (a : Extended R) : Completed R :=
  let e := a.x * a.x
  let h := a.y * a.y
  let f := a.z * a.z
  let g := a.x + a.y
  let g := g * g
  let sum := h + e
  let difference := h - e
  let h := sum
  let e := g - sum
  let g := difference
  let f := 2 * f - difference
  ⟨e, h, g, f⟩

/-- `to_extended`: X = E F, Y = G H, Z = G F and T = E H. -/
def toExtended (s : Completed R) : Extended R :=
  ⟨s.e * s.f, s.g * s.h, s.g * s.f, s.e * s.h⟩

/-- The entry of the affine point (x, y), as tools/x25519_wide.py writes it. -/
def entryOf (d x y : R) : Entry R := ⟨y + x, y - x, 2 * d * x * y⟩

/-- What `select_entry` does to an entry for a negative digit. -/
def negate (b : Entry R) : Entry R := ⟨b.yMinusX, b.yPlusX, -b.xy2d⟩

/-- The negated entry of (x, y) is the entry of (-x, y), the negative of the point. -/
theorem negate_entryOf (d x y : R) : negate (entryOf d x y) = entryOf d (-x) y := by
  simp only [negate, entryOf, Entry.mk.injEq]
  refine ⟨by ring, by ring, by ring⟩

/-- `x25519_wide_base_mul`'s last step: `u = (Z + Y) (Z - Y)⁻¹`, with `invert`'s inverse, which
takes zero to zero as `ZMod`'s does. -/
def toU [Inv R] (a : Extended R) : R := (a.z + a.y) * (a.z - a.y)⁻¹

end Formulas

section Affine

variable {F : Type*} [Field F]

/-- The affine addition law of -x² + y² = 1 + d x² y². -/
def edAdd (d : F) (p q : F × F) : F × F :=
  ((p.1 * q.2 + p.2 * q.1) / (1 + d * p.1 * q.1 * p.2 * q.2),
    (p.2 * q.2 + p.1 * q.1) / (1 - d * p.1 * q.1 * p.2 * q.2))

/-- The extended point `a` holds the affine point `p`. -/
def Represents (a : Extended F) (p : F × F) : Prop :=
  a.z ≠ 0 ∧ a.x = p.1 * a.z ∧ a.y = p.2 * a.z ∧ a.t = p.1 * p.2 * a.z

theorem addEntry_represents {d : F} {a : Extended F} {p q : F × F} (h_two : (2 : F) ≠ 0)
    (h_represents : Represents a p) (h_plus : 1 + d * p.1 * q.1 * p.2 * q.2 ≠ 0)
    (h_minus : 1 - d * p.1 * q.1 * p.2 * q.2 ≠ 0) :
    Represents (toExtended (addEntry a (entryOf d q.1 q.2))) (edAdd d p q) := by
  obtain ⟨x, y, z, t⟩ := a
  obtain ⟨x₁, y₁⟩ := p
  obtain ⟨x₂, y₂⟩ := q
  obtain ⟨h_z, h_x, h_y, h_t⟩ := h_represents
  dsimp only at h_z h_x h_y h_t h_plus h_minus
  subst h_x h_y h_t
  simp only [Represents, toExtended, addEntry, entryOf, edAdd]
  refine ⟨?_, ?_, ?_, ?_⟩
  · have : (2 * z * (1 + d * x₁ * x₂ * y₁ * y₂)) * (2 * z * (1 - d * x₁ * x₂ * y₁ * y₂)) ≠ 0 :=
      mul_ne_zero (mul_ne_zero (mul_ne_zero h_two h_z) h_plus)
        (mul_ne_zero (mul_ne_zero h_two h_z) h_minus)
    convert this using 1
    ring
  · rw [div_mul_eq_mul_div, eq_div_iff h_plus]
    ring
  · rw [div_mul_eq_mul_div, eq_div_iff h_minus]
    ring
  · rw [div_mul_div_comm, div_mul_eq_mul_div, eq_div_iff (mul_ne_zero h_plus h_minus)]
    ring

/-- (x, y) is on the twisted Edwards curve with a = -1 and this d. -/
def OnCurve (d x y : F) : Prop := -x ^ 2 + y ^ 2 = 1 + d * x ^ 2 * y ^ 2

theorem doublePoint_represents {d : F} {a : Extended F} {p : F × F}
    (h_represents : Represents a p) (h_curve : OnCurve d p.1 p.2)
    (h_plus : 1 + d * p.1 * p.1 * p.2 * p.2 ≠ 0) (h_minus : 1 - d * p.1 * p.1 * p.2 * p.2 ≠ 0) :
    Represents (toExtended (doublePoint a)) (edAdd d p p) := by
  obtain ⟨x, y, z, t⟩ := a
  obtain ⟨x₁, y₁⟩ := p
  obtain ⟨h_z, h_x, h_y, h_t⟩ := h_represents
  dsimp only [OnCurve] at h_z h_x h_y h_t h_plus h_minus h_curve
  subst h_x h_y h_t
  simp only [Represents, toExtended, doublePoint, edAdd]
  have h_z3 : ((y₁ * z) * (y₁ * z) - (x₁ * z) * (x₁ * z)) *
      (2 * (z * z) - ((y₁ * z) * (y₁ * z) - (x₁ * z) * (x₁ * z))) =
      (1 + d * x₁ * x₁ * y₁ * y₁) * (1 - d * x₁ * x₁ * y₁ * y₁) * z ^ 4 := by
    linear_combination (-z ^ 4 * (d * x₁ ^ 2 * y₁ ^ 2 - x₁ ^ 2 + y₁ ^ 2 - 1)) * h_curve
  refine ⟨?_, ?_, ?_, ?_⟩
  · rw [h_z3]
    exact mul_ne_zero (mul_ne_zero h_plus h_minus) (pow_ne_zero 4 h_z)
  · rw [div_mul_eq_mul_div, eq_div_iff h_plus]
    linear_combination (-2 * x₁ * y₁ * z ^ 4 * (x₁ ^ 2 - y₁ ^ 2 + 2)) * h_curve
  · rw [div_mul_eq_mul_div, eq_div_iff h_minus]
    linear_combination (-z ^ 4 * (x₁ - y₁) * (x₁ + y₁) * (x₁ ^ 2 + y₁ ^ 2)) * h_curve
  · rw [div_mul_div_comm, div_mul_eq_mul_div, eq_div_iff (mul_ne_zero h_plus h_minus)]
    linear_combination (2 * x₁ * y₁ * z ^ 4 * (x₁ ^ 2 + y₁ ^ 2) *
      (d * x₁ ^ 2 * y₁ ^ 2 - x₁ ^ 2 + y₁ ^ 2 - 1)) * h_curve

/-- Completeness. -/
theorem product_sq_ne_one {d x₁ y₁ x₂ y₂ : F} (h_two : (2 : F) ≠ 0) (h_d : ¬IsSquare d)
    (h_i : IsSquare (-1 : F)) (h₁ : OnCurve d x₁ y₁) (h₂ : OnCurve d x₂ y₂) :
    (d * x₁ * x₂ * y₁ * y₂) ^ 2 ≠ 1 := by
  intro h_one
  obtain ⟨i, h_i⟩ := h_i
  unfold OnCurve at h₁ h₂
  have h_x₁ : x₁ ≠ 0 := by rintro rfl; simp at h_one
  have h_y₁ : y₁ ≠ 0 := by rintro rfl; simp at h_one
  have h_root : ∀ j : F, j * j = -1 → j * x₂ + y₂ = 0 := by
    intro j h_j
    by_contra h_ne
    apply h_d
    have h_den : x₁ * y₁ * (j * x₂ + y₂) ≠ 0 := mul_ne_zero (mul_ne_zero h_x₁ h_y₁) h_ne
    refine ⟨(j * x₁ + d * x₁ * x₂ * y₁ * y₂ * y₁) / (x₁ * y₁ * (j * x₂ + y₂)), ?_⟩
    rw [div_mul_div_comm, eq_div_iff (mul_ne_zero h_den h_den)]
    linear_combination (d * x₁ ^ 2 * y₁ ^ 2 * x₂ ^ 2 - x₁ ^ 2) * h_j + d * x₁ ^ 2 * y₁ ^ 2 * h₂ +
      (1 - y₁ ^ 2) * h_one - h₁
  have h_plus := h_root i h_i.symm
  have h_minus := h_root (-i) (by rw [neg_mul_neg]; exact h_i.symm)
  have h_y₂ : y₂ = 0 := by
    have : 2 * y₂ = 0 := by linear_combination h_plus + h_minus
    exact (mul_eq_zero.mp this).resolve_left h_two
  subst h_y₂
  simp at h_one

end Affine


section Group

variable {F : Type*} [Field F]

/-- The curve's parameter d, with what the proofs need of the field. -/
structure Params (F : Type*) [Field F] where
  /-- d. -/
  d : F
  /-- 2 is not zero. -/
  two_ne_zero : (2 : F) ≠ 0
  /-- d is not a square. -/
  d_not_square : ¬IsSquare d
  /-- -1 is a square. -/
  neg_one_square : IsSquare (-1 : F)

variable (c : Params F)

/-- d is not zero, since zero is a square. -/
theorem Params.d_ne_zero : c.d ≠ 0 := fun h => c.d_not_square ⟨0, by rw [h, mul_zero]⟩

/-- d is not -1, since -1 is a square. -/
theorem Params.one_add_d_ne_zero : 1 + c.d ≠ 0 := by
  intro h
  obtain ⟨i, h_i⟩ := c.neg_one_square
  exact c.d_not_square ⟨i, by linear_combination h + h_i⟩

/-- 1 + d y² is never zero, or d would be (i / y)². -/
theorem Params.one_add_d_mul_sq_ne_zero (y : F) : 1 + c.d * y ^ 2 ≠ 0 := by
  intro h
  have h_y : y ≠ 0 := by rintro rfl; simp at h
  obtain ⟨i, h_i⟩ := c.neg_one_square
  refine c.d_not_square ⟨i / y, ?_⟩
  rw [div_mul_div_comm, eq_div_iff (mul_ne_zero h_y h_y)]
  linear_combination h + h_i

/-- A point of the curve. -/
@[ext]
structure EdPoint (c : Params F) where
  /-- x. -/
  x : F
  /-- y. -/
  y : F
  /-- (x, y) is on the curve. -/
  on_curve : OnCurve c.d x y

variable {c}

/-- A point with x not zero has y not 1. -/
theorem EdPoint.y_ne_one {P : EdPoint c} (h_x : P.x ≠ 0) : P.y ≠ 1 := by
  intro h_y
  have h := P.on_curve
  unfold OnCurve at h
  rw [h_y] at h
  have : (1 + c.d) * P.x ^ 2 = 0 := by linear_combination -h
  exact h_x (pow_eq_zero_iff (n := 2) (by norm_num) |>.mp
    ((mul_eq_zero.mp this).resolve_left c.one_add_d_ne_zero))

/-- A point with x not zero has y not -1. -/
theorem EdPoint.y_ne_neg_one {P : EdPoint c} (h_x : P.x ≠ 0) : P.y ≠ -1 := by
  intro h_y
  have h := P.on_curve
  unfold OnCurve at h
  rw [h_y] at h
  have : (1 + c.d) * P.x ^ 2 = 0 := by linear_combination -h
  exact h_x (pow_eq_zero_iff (n := 2) (by norm_num) |>.mp
    ((mul_eq_zero.mp this).resolve_left c.one_add_d_ne_zero))

/-- A point with x zero is the identity or the point of order two. -/
theorem EdPoint.y_eq_of_x_eq_zero {P : EdPoint c} (h_x : P.x = 0) : P.y = 1 ∨ P.y = -1 := by
  have h := P.on_curve
  unfold OnCurve at h
  rw [h_x] at h
  have : (P.y - 1) * (P.y + 1) = 0 := by linear_combination h
  rcases mul_eq_zero.mp this with h' | h'
  · left; linear_combination h'
  · right; linear_combination h'

/-- The addition law's two denominators are not zero for any two points. -/
theorem denominators_ne_zero (P Q : EdPoint c) :
    1 + c.d * P.x * Q.x * P.y * Q.y ≠ 0 ∧ 1 - c.d * P.x * Q.x * P.y * Q.y ≠ 0 := by
  have h := product_sq_ne_one c.two_ne_zero c.d_not_square c.neg_one_square P.on_curve Q.on_curve
  constructor
  · intro h_zero
    exact h (by linear_combination (c.d * P.x * Q.x * P.y * Q.y - 1) * h_zero)
  · intro h_zero
    exact h (by linear_combination (-(c.d * P.x * Q.x * P.y * Q.y) - 1) * h_zero)

/-- The sum of two points is on the curve. -/
theorem onCurve_edAdd (P Q : EdPoint c) :
    OnCurve c.d (edAdd c.d (P.x, P.y) (Q.x, Q.y)).1 (edAdd c.d (P.x, P.y) (Q.x, Q.y)).2 := by
  obtain ⟨h_plus, h_minus⟩ := denominators_ne_zero P Q
  obtain ⟨x₁, y₁, h₁⟩ := P
  obtain ⟨x₂, y₂, h₂⟩ := Q
  unfold OnCurve at h₁ h₂ ⊢
  dsimp only at h_plus h_minus
  simp only [edAdd]
  generalize h_p : 1 + c.d * x₁ * x₂ * y₁ * y₂ = p at h_plus ⊢
  generalize h_m : 1 - c.d * x₁ * x₂ * y₁ * y₂ = m at h_minus ⊢
  field_simp
  linear_combination (-(-m + x₁ * x₂ + y₁ * y₂) * (m + x₁ * x₂ + y₁ * y₂) * (c.d * x₁ * x₂ * y₁ * y₂
    + p + 1)) * h_p + (-(c.d * x₁ * x₂ * y₁ * y₂ - m - 1) * (c.d^2 * x₁^2 * x₂^2 * y₁^2 * y₂^2 + 2 *
    c.d * x₁ * x₂ * y₁ * y₂ + x₁^2 * y₂^2 + 2 * x₁ * x₂ * y₁ * y₂ + x₂^2 * y₁^2 + 1)) * h_m + (c.d^3
    * x₁^2 * x₂^4 * y₁^2 * y₂^4 - c.d^2 * x₁^2 * x₂^4 * y₂^4 + c.d^2 * x₂^4 * y₁^2 * y₂^4 - c.d^2 *
    x₂^4 * y₂^4 - c.d * x₁^2 * x₂^4 * y₂^2 + c.d * x₁^2 * x₂^2 * y₂^4 + c.d * x₂^4 * y₁^2 * y₂^2 - 2
    * c.d * x₂^4 * y₂^4 - c.d * x₂^2 * y₁^2 * y₂^4 - 2 * c.d * x₂^2 * y₂^2 - 2 * x₂^4 * y₂^2 + x₂^4
    + 2 * x₂^2 * y₂^4 - 4 * x₂^2 * y₂^2 + y₂^4) * h₁ + (c.d * x₁^4 * x₂^2 * y₂^2 + 2 * c.d * x₁^2 *
    x₂^2 * y₂^2 + c.d * x₂^2 * y₁^4 * y₂^2 - 2 * c.d * x₂^2 * y₁^2 * y₂^2 + c.d * x₂^2 * y₂^2 + 2 *
    x₁^2 * x₂^2 * y₂^2 - x₁^2 * x₂^2 + x₁^2 * y₂^2 - 2 * x₂^2 * y₁^2 * y₂^2 + x₂^2 * y₁^2 + 2 * x₂^2
    * y₂^2 - x₂^2 - y₁^2 * y₂^2 + y₂^2 + 1) * h₂

/-- The sum of two points of the curve, which is on the curve. -/
def EdPoint.add (P Q : EdPoint c) : EdPoint c :=
  ⟨(edAdd c.d (P.x, P.y) (Q.x, Q.y)).1, (edAdd c.d (P.x, P.y) (Q.x, Q.y)).2, onCurve_edAdd P Q⟩

/-- The Montgomery curve of the Edwards curve as a Weierstrass curve: y² = x³ + 2 (d - 1) x² +
(1 + d)² x. Under x = -(1 + d) u and y = 2 (1 + d) v it is B v² = u³ + A u² + u with
A = 2 (1 - d) / (1 + d) and B = -4 / (1 + d). At d = -121665 / 121666, A = 486662 and
B = -486664, a square modulo 2^255 - 19, so it is curve25519 with the same u. -/
def mont (d : F) : WeierstrassCurve.Affine F := ⟨0, 2 * (d - 1), 0, (1 + d) ^ 2, 0⟩

/-- The x of a point's image in `mont d`: -(1 + d) u for u = (1 + y) / (1 - y). -/
def monX (d y : F) : F := -(1 + d) * (1 + y) / (1 - y)

/-- The y of a point's image in `mont d`. -/
def monY (d x y : F) : F := 2 * (1 + d) * (1 + y) / ((1 - y) * x)

/-- The image of a point with x not zero is a nonsingular point of `mont d`. -/
theorem nonsingular_mon (P : EdPoint c) (h_x : P.x ≠ 0) :
    (mont c.d).Nonsingular (monX c.d P.y) (monY c.d P.x P.y) := by
  have h_m : 1 - P.y ≠ 0 := sub_ne_zero.mpr (EdPoint.y_ne_one h_x).symm
  have h_n : 1 + P.y ≠ 0 := by
    intro h; exact EdPoint.y_ne_neg_one h_x (by linear_combination h)
  have h_k := c.one_add_d_ne_zero
  have h_curve := P.on_curve
  unfold OnCurve at h_curve
  rw [WeierstrassCurve.Affine.nonsingular_iff']
  refine ⟨?_, Or.inr ?_⟩
  · rw [WeierstrassCurve.Affine.equation_iff']
    simp only [mont, monX, monY]
    generalize h_mm : 1 - P.y = m at h_m ⊢
    field_simp
    linear_combination (-(c.d + 1)^2 * (P.y + 1) * (c.d * m * P.x^2 - 3 * c.d * P.x^2 * P.y - c.d *
      P.x^2 + m * P.x^2 + P.x^2 * P.y + 3 * P.x^2 + 4 * P.y + 4)) * h_mm + (-4 * (c.d + 1)^2 * (P.y
      + 1)) * h_curve
  · simp only [mont, monY]
    have : 2 * (2 * (1 + c.d) * (1 + P.y) / ((1 - P.y) * P.x)) ≠ 0 :=
      mul_ne_zero c.two_ne_zero (div_ne_zero (mul_ne_zero (mul_ne_zero c.two_ne_zero h_k) h_n)
        (mul_ne_zero h_m h_x))
    simpa using this

/-- (0, 0), the point of order two, is nonsingular. -/
theorem nonsingular_zero_zero : (mont c.d).Nonsingular 0 0 := by
  rw [WeierstrassCurve.Affine.nonsingular_zero]
  exact ⟨rfl, Or.inr (pow_ne_zero 2 c.one_add_d_ne_zero)⟩

open Classical in
/-- The map from the Edwards curve to `mont d`: u = (1 + y) / (1 - y), the identity to the
identity and (0, -1) to (0, 0). -/
noncomputable def toMont (P : EdPoint c) : (mont c.d).Point :=
  if h_x : P.x = 0 then (if P.y = 1 then 0 else .some 0 0 nonsingular_zero_zero)
  else .some (monX c.d P.y) (monY c.d P.x P.y) (nonsingular_mon P h_x)

section Identities

variable {d x₁ y₁ x₂ y₂ : F}

/-- The chord's slope between two images, in the points' coordinates. -/
theorem slope_chord (h_two : (2 : F) ≠ 0) (h_k : 1 + d ≠ 0) (h_x₁ : x₁ ≠ 0) (h_x₂ : x₂ ≠ 0)
    (h_m₁ : 1 - y₁ ≠ 0) (h_m₂ : 1 - y₂ ≠ 0) (h_w : y₁ - y₂ ≠ 0) :
    (monY d x₁ y₁ - monY d x₂ y₂) / (monX d y₁ - monX d y₂) =
      ((1 + y₂) * (1 - y₁) * x₁ - (1 + y₁) * (1 - y₂) * x₂) / ((y₁ - y₂) * x₁ * x₂) := by
  have h_X : monX d y₁ - monX d y₂ = -2 * (1 + d) * (y₁ - y₂) / ((1 - y₁) * (1 - y₂)) := by
    simp only [monX]
    field_simp
    ring
  rw [h_X]
  simp only [monY]
  field_simp
  ring

/-- `monX` of a y written as a fraction. -/
theorem monX_frac {n m : F} (h_m : m ≠ 0) (h_e : m - n ≠ 0) :
    monX d (n / m) = -(1 + d) * (m + n) / (m - n) := by
  simp only [monX]
  rw [one_add_div h_m, one_sub_div h_m]
  field_simp

/-- The x of a chord sum, against the sum of the points' images. -/
theorem chord_x (h_d : d ≠ 0) (h_x₁ : x₁ ≠ 0)
    (h_x₂ : x₂ ≠ 0) (h_m₁ : 1 - y₁ ≠ 0) (h_m₂ : 1 - y₂ ≠ 0) (h_w : y₁ - y₂ ≠ 0)
    (h₁ : OnCurve d x₁ y₁) (h₂ : OnCurve d x₂ y₂)
    (h_e : (1 - d * x₁ * x₂ * y₁ * y₂) - (y₁ * y₂ + x₁ * x₂) ≠ 0) :
    -(1 + d) * ((1 - d * x₁ * x₂ * y₁ * y₂) + (y₁ * y₂ + x₁ * x₂)) /
        ((1 - d * x₁ * x₂ * y₁ * y₂) - (y₁ * y₂ + x₁ * x₂)) =
      (mont d).addX (monX d y₁) (monX d y₂)
        (((1 + y₂) * (1 - y₁) * x₁ - (1 + y₁) * (1 - y₂) * x₂) / ((y₁ - y₂) * x₁ * x₂)) := by
  unfold OnCurve at h₁ h₂
  simp only [WeierstrassCurve.Affine.addX, mont, monX]
  generalize h_mm : 1 - d * x₁ * x₂ * y₁ * y₂ = m at h_e ⊢
  generalize h_ee : m - (y₁ * y₂ + x₁ * x₂) = e at h_e ⊢
  generalize h_ww : y₁ - y₂ = w at h_w ⊢
  generalize h_aa : 1 - y₁ = a at h_m₁ ⊢
  generalize h_bb : 1 - y₂ = b at h_m₂ ⊢
  field_simp
  refine mul_left_cancel₀ (show (d^2 : F) ≠ 0 from ?_) ?_
  · exact pow_ne_zero _ h_d
  · linear_combination (d^2 * (a^3 * b * x₁^2 * y₂^2 + 2 * a^3 * b * x₁^2 * y₂ + a^3 * b * x₁^2 - 2
      * a^2 * b^2 * x₁ * x₂ * y₁ * y₂ - 2 * a^2 * b^2 * x₁ * x₂ * y₁ - 2 * a^2 * b^2 * x₁ * x₂ * y₂
      - 2 * a^2 * b^2 * x₁ * x₂ + a * b^3 * x₂^2 * y₁^2 + 2 * a * b^3 * x₂^2 * y₁ + a * b^3 * x₂^2 -
      2 * a * b * d * w^2 * x₁^2 * x₂^2 + 2 * a * b * w^2 * x₁^2 * x₂^2 + a * d * w^2 * x₁^2 * x₂^2
      * y₂ + a * d * w^2 * x₁^2 * x₂^2 + a * w^2 * x₁^2 * x₂^2 * y₂ + a * w^2 * x₁^2 * x₂^2 + b * d
      * w^2 * x₁^2 * x₂^2 * y₁ + b * d * w^2 * x₁^2 * x₂^2 + b * w^2 * x₁^2 * x₂^2 * y₁ + b * w^2 *
      x₁^2 * x₂^2)) * h_ee + (d^2 * (a^3 * b * x₁^2 * y₂^2 + 2 * a^3 * b * x₁^2 * y₂ + a^3 * b *
      x₁^2 - 2 * a^2 * b^2 * x₁ * x₂ * y₁ * y₂ - 2 * a^2 * b^2 * x₁ * x₂ * y₁ - 2 * a^2 * b^2 * x₁ *
      x₂ * y₂ - 2 * a^2 * b^2 * x₁ * x₂ + a * b^3 * x₂^2 * y₁^2 + 2 * a * b^3 * x₂^2 * y₁ + a * b^3
      * x₂^2 - a * b * d * w^2 * x₁^2 * x₂^2 + 3 * a * b * w^2 * x₁^2 * x₂^2 + a * d * w^2 * x₁^2 *
      x₂^2 * y₂ + a * d * w^2 * x₁^2 * x₂^2 + a * w^2 * x₁^2 * x₂^2 * y₂ + a * w^2 * x₁^2 * x₂^2 + b
      * d * w^2 * x₁^2 * x₂^2 * y₁ + b * d * w^2 * x₁^2 * x₂^2 + b * w^2 * x₁^2 * x₂^2 * y₁ + b *
      w^2 * x₁^2 * x₂^2)) * h_mm + (-d^2 * x₁^2 * x₂^2 * (w + y₁ - y₂) * (-a * b * d^2 * x₁ * x₂ *
      y₁ * y₂ + 3 * a * b * d * x₁ * x₂ * y₁ * y₂ - 3 * a * b * d * x₁ * x₂ - 3 * a * b * d * y₁ *
      y₂ + a * b * d + a * b * x₁ * x₂ + a * b * y₁ * y₂ - 3 * a * b + a * d^2 * x₁ * x₂ * y₁ * y₂^2
      + a * d^2 * x₁ * x₂ * y₁ * y₂ + a * d * x₁ * x₂ * y₁ * y₂^2 + a * d * x₁ * x₂ * y₁ * y₂ + a *
      d * x₁ * x₂ * y₂ + a * d * x₁ * x₂ + a * d * y₁ * y₂^2 + a * d * y₁ * y₂ - a * d * y₂ - a * d
      + a * x₁ * x₂ * y₂ + a * x₁ * x₂ + a * y₁ * y₂^2 + a * y₁ * y₂ - a * y₂ - a + b * d^2 * x₁ *
      x₂ * y₁^2 * y₂ + b * d^2 * x₁ * x₂ * y₁ * y₂ + b * d * x₁ * x₂ * y₁^2 * y₂ + b * d * x₁ * x₂ *
      y₁ * y₂ + b * d * x₁ * x₂ * y₁ + b * d * x₁ * x₂ + b * d * y₁^2 * y₂ + b * d * y₁ * y₂ - b * d
      * y₁ - b * d + b * x₁ * x₂ * y₁ + b * x₁ * x₂ + b * y₁^2 * y₂ + b * y₁ * y₂ - b * y₁ - b)) *
      h_ww + (-d^2 * (a^2 * b * d * x₁^3 * x₂ * y₁ * y₂^3 + 2 * a^2 * b * d * x₁^3 * x₂ * y₁ * y₂^2
      + a^2 * b * d * x₁^3 * x₂ * y₁ * y₂ + a^2 * b * x₁^3 * x₂ * y₂^2 + 2 * a^2 * b * x₁^3 * x₂ *
      y₂ + a^2 * b * x₁^3 * x₂ + a^2 * b * x₁^2 * y₁ * y₂^3 + 2 * a^2 * b * x₁^2 * y₁ * y₂^2 + a^2 *
      b * x₁^2 * y₁ * y₂ - a^2 * b * x₁^2 * y₂^2 - 2 * a^2 * b * x₁^2 * y₂ - a^2 * b * x₁^2 - 2 * a
      * b^2 * d * x₁^2 * x₂^2 * y₁^2 * y₂^2 - 2 * a * b^2 * d * x₁^2 * x₂^2 * y₁^2 * y₂ - 2 * a *
      b^2 * d * x₁^2 * x₂^2 * y₁ * y₂^2 - 2 * a * b^2 * d * x₁^2 * x₂^2 * y₁ * y₂ - 2 * a * b^2 *
      x₁^2 * x₂^2 * y₁ * y₂ - 2 * a * b^2 * x₁^2 * x₂^2 * y₁ - 2 * a * b^2 * x₁^2 * x₂^2 * y₂ - 2 *
      a * b^2 * x₁^2 * x₂^2 - 2 * a * b^2 * x₁ * x₂ * y₁^2 * y₂^2 - 2 * a * b^2 * x₁ * x₂ * y₁^2 *
      y₂ - 2 * a * b^2 * x₁ * x₂ * y₁ * y₂^2 + 2 * a * b^2 * x₁ * x₂ * y₁ + 2 * a * b^2 * x₁ * x₂ *
      y₂ + 2 * a * b^2 * x₁ * x₂ - a * b * d * x₁^3 * x₂ * y₁^2 * y₂^3 - 2 * a * b * d * x₁^3 * x₂ *
      y₁^2 * y₂^2 - a * b * d * x₁^3 * x₂ * y₁^2 * y₂ + a * b * d * x₁^3 * x₂ * y₁ * y₂^3 + 2 * a *
      b * d * x₁^3 * x₂ * y₁ * y₂^2 + a * b * d * x₁^3 * x₂ * y₁ * y₂ - a * b * x₁^3 * x₂ * y₁ *
      y₂^2 - 2 * a * b * x₁^3 * x₂ * y₁ * y₂ - a * b * x₁^3 * x₂ * y₁ + a * b * x₁^3 * x₂ * y₂^2 + 2
      * a * b * x₁^3 * x₂ * y₂ + a * b * x₁^3 * x₂ - a * b * x₁^2 * y₁^2 * y₂^3 - 2 * a * b * x₁^2 *
      y₁^2 * y₂^2 - a * b * x₁^2 * y₁^2 * y₂ + a * b * x₁^2 * y₁ * y₂^3 + 3 * a * b * x₁^2 * y₁ *
      y₂^2 + 3 * a * b * x₁^2 * y₁ * y₂ + a * b * x₁^2 * y₁ - a * b * x₁^2 * y₂^2 - 2 * a * b * x₁^2
      * y₂ - a * b * x₁^2 + b^3 * d * x₁ * x₂^3 * y₁^3 * y₂ + 2 * b^3 * d * x₁ * x₂^3 * y₁^2 * y₂ +
      b^3 * d * x₁ * x₂^3 * y₁ * y₂ + b^3 * x₁ * x₂^3 * y₁^2 + 2 * b^3 * x₁ * x₂^3 * y₁ + b^3 * x₁ *
      x₂^3 + b^3 * x₂^2 * y₁^3 * y₂ + 2 * b^3 * x₂^2 * y₁^2 * y₂ - b^3 * x₂^2 * y₁^2 + b^3 * x₂^2 *
      y₁ * y₂ - 2 * b^3 * x₂^2 * y₁ - b^3 * x₂^2 + 2 * b^2 * d * x₁^2 * x₂^2 * y₁^3 * y₂^2 + 2 * b^2
      * d * x₁^2 * x₂^2 * y₁^3 * y₂ - 2 * b^2 * d * x₁^2 * x₂^2 * y₁ * y₂^2 - 2 * b^2 * d * x₁^2 *
      x₂^2 * y₁ * y₂ + 2 * b^2 * x₁^2 * x₂^2 * y₁^2 * y₂ + 2 * b^2 * x₁^2 * x₂^2 * y₁^2 - 2 * b^2 *
      x₁^2 * x₂^2 * y₂ - 2 * b^2 * x₁^2 * x₂^2 + 2 * b^2 * x₁ * x₂ * y₁^3 * y₂^2 + 2 * b^2 * x₁ * x₂
      * y₁^3 * y₂ - 2 * b^2 * x₁ * x₂ * y₁^2 * y₂ - 2 * b^2 * x₁ * x₂ * y₁^2 - 2 * b^2 * x₁ * x₂ *
      y₁ * y₂^2 - 2 * b^2 * x₁ * x₂ * y₁ * y₂ + 2 * b^2 * x₁ * x₂ * y₂ + 2 * b^2 * x₁ * x₂ - b * d^2
      * x₁^3 * x₂^3 * y₁^3 * y₂ + 2 * b * d^2 * x₁^3 * x₂^3 * y₁^2 * y₂^2 - b * d^2 * x₁^3 * x₂^3 *
      y₁ * y₂^3 + 3 * b * d * x₁^3 * x₂^3 * y₁^3 * y₂ - 6 * b * d * x₁^3 * x₂^3 * y₁^2 * y₂^2 - 3 *
      b * d * x₁^3 * x₂^3 * y₁^2 + 3 * b * d * x₁^3 * x₂^3 * y₁ * y₂^3 + 6 * b * d * x₁^3 * x₂^3 *
      y₁ * y₂ - 3 * b * d * x₁^3 * x₂^3 * y₂^2 + b * d * x₁^3 * x₂ * y₁^3 * y₂^3 + 2 * b * d * x₁^3
      * x₂ * y₁^3 * y₂^2 + b * d * x₁^3 * x₂ * y₁^3 * y₂ - 2 * b * d * x₁^3 * x₂ * y₁^2 * y₂^3 - 4 *
      b * d * x₁^3 * x₂ * y₁^2 * y₂^2 - 2 * b * d * x₁^3 * x₂ * y₁^2 * y₂ + b * d * x₁^3 * x₂ * y₁ *
      y₂^3 + 2 * b * d * x₁^3 * x₂ * y₁ * y₂^2 + b * d * x₁^3 * x₂ * y₁ * y₂ - 3 * b * d * x₁^2 *
      x₂^2 * y₁^3 * y₂ + 6 * b * d * x₁^2 * x₂^2 * y₁^2 * y₂^2 + b * d * x₁^2 * x₂^2 * y₁^2 - 3 * b
      * d * x₁^2 * x₂^2 * y₁ * y₂^3 - 2 * b * d * x₁^2 * x₂^2 * y₁ * y₂ + b * d * x₁^2 * x₂^2 * y₂^2
      + b * x₁^3 * x₂^3 * y₁^2 - 2 * b * x₁^3 * x₂^3 * y₁ * y₂ + b * x₁^3 * x₂^3 * y₂^2 + b * x₁^3 *
      x₂ * y₁^2 * y₂^2 + 2 * b * x₁^3 * x₂ * y₁^2 * y₂ + b * x₁^3 * x₂ * y₁^2 - 2 * b * x₁^3 * x₂ *
      y₁ * y₂^2 - 4 * b * x₁^3 * x₂ * y₁ * y₂ - 2 * b * x₁^3 * x₂ * y₁ + b * x₁^3 * x₂ * y₂^2 + 2 *
      b * x₁^3 * x₂ * y₂ + b * x₁^3 * x₂ + b * x₁^2 * x₂^2 * y₁^3 * y₂ - 2 * b * x₁^2 * x₂^2 * y₁^2
      * y₂^2 - 3 * b * x₁^2 * x₂^2 * y₁^2 + b * x₁^2 * x₂^2 * y₁ * y₂^3 + 6 * b * x₁^2 * x₂^2 * y₁ *
      y₂ - 3 * b * x₁^2 * x₂^2 * y₂^2 + b * x₁^2 * y₁^3 * y₂^3 + 2 * b * x₁^2 * y₁^3 * y₂^2 + b *
      x₁^2 * y₁^3 * y₂ - 2 * b * x₁^2 * y₁^2 * y₂^3 - 5 * b * x₁^2 * y₁^2 * y₂^2 - 4 * b * x₁^2 *
      y₁^2 * y₂ - b * x₁^2 * y₁^2 + b * x₁^2 * y₁ * y₂^3 + 4 * b * x₁^2 * y₁ * y₂^2 + 5 * b * x₁^2 *
      y₁ * y₂ + 2 * b * x₁^2 * y₁ - b * x₁^2 * y₂^2 - 2 * b * x₁^2 * y₂ - b * x₁^2 + d^2 * x₁^3 *
      x₂^3 * y₁^3 * y₂^2 + d^2 * x₁^3 * x₂^3 * y₁^3 * y₂ - 2 * d^2 * x₁^3 * x₂^3 * y₁^2 * y₂^3 - 2 *
      d^2 * x₁^3 * x₂^3 * y₁^2 * y₂^2 + d^2 * x₁^3 * x₂^3 * y₁ * y₂^4 + d^2 * x₁^3 * x₂^3 * y₁ *
      y₂^3 + d * x₁^3 * x₂^3 * y₁^3 * y₂^2 + d * x₁^3 * x₂^3 * y₁^3 * y₂ - 2 * d * x₁^3 * x₂^3 *
      y₁^2 * y₂^3 - 2 * d * x₁^3 * x₂^3 * y₁^2 * y₂^2 + d * x₁^3 * x₂^3 * y₁^2 * y₂ + d * x₁^3 *
      x₂^3 * y₁^2 + d * x₁^3 * x₂^3 * y₁ * y₂^4 + d * x₁^3 * x₂^3 * y₁ * y₂^3 - 2 * d * x₁^3 * x₂^3
      * y₁ * y₂^2 - 2 * d * x₁^3 * x₂^3 * y₁ * y₂ + d * x₁^3 * x₂^3 * y₂^3 + d * x₁^3 * x₂^3 * y₂^2
      + d * x₁^2 * x₂^2 * y₁^3 * y₂^2 + d * x₁^2 * x₂^2 * y₁^3 * y₂ - 2 * d * x₁^2 * x₂^2 * y₁^2 *
      y₂^3 - 2 * d * x₁^2 * x₂^2 * y₁^2 * y₂^2 - d * x₁^2 * x₂^2 * y₁^2 * y₂ - d * x₁^2 * x₂^2 *
      y₁^2 + d * x₁^2 * x₂^2 * y₁ * y₂^4 + d * x₁^2 * x₂^2 * y₁ * y₂^3 + 2 * d * x₁^2 * x₂^2 * y₁ *
      y₂^2 + 2 * d * x₁^2 * x₂^2 * y₁ * y₂ - d * x₁^2 * x₂^2 * y₂^3 - d * x₁^2 * x₂^2 * y₂^2 + x₁^3
      * x₂^3 * y₁^2 * y₂ + x₁^3 * x₂^3 * y₁^2 - 2 * x₁^3 * x₂^3 * y₁ * y₂^2 - 2 * x₁^3 * x₂^3 * y₁ *
      y₂ + x₁^3 * x₂^3 * y₂^3 + x₁^3 * x₂^3 * y₂^2 + x₁^2 * x₂^2 * y₁^3 * y₂^2 + x₁^2 * x₂^2 * y₁^3
      * y₂ - 2 * x₁^2 * x₂^2 * y₁^2 * y₂^3 - 2 * x₁^2 * x₂^2 * y₁^2 * y₂^2 - x₁^2 * x₂^2 * y₁^2 * y₂
      - x₁^2 * x₂^2 * y₁^2 + x₁^2 * x₂^2 * y₁ * y₂^4 + x₁^2 * x₂^2 * y₁ * y₂^3 + 2 * x₁^2 * x₂^2 *
      y₁ * y₂^2 + 2 * x₁^2 * x₂^2 * y₁ * y₂ - x₁^2 * x₂^2 * y₂^3 - x₁^2 * x₂^2 * y₂^2)) * h_aa +
      (-d^2 * (-b^2 * d * x₁ * x₂^3 * y₁^4 * y₂ - b^2 * d * x₁ * x₂^3 * y₁^3 * y₂ + b^2 * d * x₁ *
      x₂^3 * y₁^2 * y₂ + b^2 * d * x₁ * x₂^3 * y₁ * y₂ - b^2 * x₁ * x₂^3 * y₁^3 - b^2 * x₁ * x₂^3 *
      y₁^2 + b^2 * x₁ * x₂^3 * y₁ + b^2 * x₁ * x₂^3 - b^2 * x₂^2 * y₁^4 * y₂ - b^2 * x₂^2 * y₁^3 *
      y₂ + b^2 * x₂^2 * y₁^3 + b^2 * x₂^2 * y₁^2 * y₂ + b^2 * x₂^2 * y₁^2 + b^2 * x₂^2 * y₁ * y₂ -
      b^2 * x₂^2 * y₁ - b^2 * x₂^2 - 2 * b * d * x₁^2 * x₂^2 * y₁^4 * y₂^2 - 2 * b * d * x₁^2 * x₂^2
      * y₁^4 * y₂ + 2 * b * d * x₁^2 * x₂^2 * y₁^3 * y₂^2 + 2 * b * d * x₁^2 * x₂^2 * y₁^3 * y₂ + 2
      * b * d * x₁^2 * x₂^2 * y₁^2 * y₂^2 + 2 * b * d * x₁^2 * x₂^2 * y₁^2 * y₂ - 2 * b * d * x₁^2 *
      x₂^2 * y₁ * y₂^2 - 2 * b * d * x₁^2 * x₂^2 * y₁ * y₂ + b * d * x₁ * x₂^3 * y₁^4 * y₂^2 - b * d
      * x₁ * x₂^3 * y₁^4 * y₂ + b * d * x₁ * x₂^3 * y₁^3 * y₂^2 - b * d * x₁ * x₂^3 * y₁^3 * y₂ - b
      * d * x₁ * x₂^3 * y₁^2 * y₂^2 + b * d * x₁ * x₂^3 * y₁^2 * y₂ - b * d * x₁ * x₂^3 * y₁ * y₂^2
      + b * d * x₁ * x₂^3 * y₁ * y₂ - 2 * b * x₁^2 * x₂^2 * y₁^3 * y₂ - 2 * b * x₁^2 * x₂^2 * y₁^3 +
      2 * b * x₁^2 * x₂^2 * y₁^2 * y₂ + 2 * b * x₁^2 * x₂^2 * y₁^2 + 2 * b * x₁^2 * x₂^2 * y₁ * y₂ +
      2 * b * x₁^2 * x₂^2 * y₁ - 2 * b * x₁^2 * x₂^2 * y₂ - 2 * b * x₁^2 * x₂^2 + b * x₁ * x₂^3 *
      y₁^3 * y₂ - b * x₁ * x₂^3 * y₁^3 + b * x₁ * x₂^3 * y₁^2 * y₂ - b * x₁ * x₂^3 * y₁^2 - b * x₁ *
      x₂^3 * y₁ * y₂ + b * x₁ * x₂^3 * y₁ - b * x₁ * x₂^3 * y₂ + b * x₁ * x₂^3 - 2 * b * x₁ * x₂ *
      y₁^4 * y₂^2 - 2 * b * x₁ * x₂ * y₁^4 * y₂ + 2 * b * x₁ * x₂ * y₁^3 * y₂^2 + 4 * b * x₁ * x₂ *
      y₁^3 * y₂ + 2 * b * x₁ * x₂ * y₁^3 + 2 * b * x₁ * x₂ * y₁^2 * y₂^2 - 2 * b * x₁ * x₂ * y₁^2 -
      2 * b * x₁ * x₂ * y₁ * y₂^2 - 4 * b * x₁ * x₂ * y₁ * y₂ - 2 * b * x₁ * x₂ * y₁ + 2 * b * x₁ *
      x₂ * y₂ + 2 * b * x₁ * x₂ + b * x₂^2 * y₁^4 * y₂^2 - b * x₂^2 * y₁^4 * y₂ + b * x₂^2 * y₁^3 *
      y₂^2 - 2 * b * x₂^2 * y₁^3 * y₂ + b * x₂^2 * y₁^3 - b * x₂^2 * y₁^2 * y₂^2 + b * x₂^2 * y₁^2 -
      b * x₂^2 * y₁ * y₂^2 + 2 * b * x₂^2 * y₁ * y₂ - b * x₂^2 * y₁ + b * x₂^2 * y₂ - b * x₂^2 + 2 *
      d^2 * x₁^3 * x₂^3 * y₁^4 * y₂ - 4 * d^2 * x₁^3 * x₂^3 * y₁^3 * y₂^2 + 2 * d^2 * x₁^3 * x₂^3 *
      y₁^2 * y₂^3 - 2 * d * x₁^3 * x₂^3 * y₁^4 * y₂ + 4 * d * x₁^3 * x₂^3 * y₁^3 * y₂^2 + 4 * d *
      x₁^3 * x₂^3 * y₁^3 * y₂ + 4 * d * x₁^3 * x₂^3 * y₁^3 - 2 * d * x₁^3 * x₂^3 * y₁^2 * y₂^3 - 8 *
      d * x₁^3 * x₂^3 * y₁^2 * y₂^2 - 8 * d * x₁^3 * x₂^3 * y₁^2 * y₂ - 2 * d * x₁^3 * x₂^3 * y₁^2 +
      4 * d * x₁^3 * x₂^3 * y₁ * y₂^3 + 4 * d * x₁^3 * x₂^3 * y₁ * y₂^2 + 4 * d * x₁^3 * x₂^3 * y₁ *
      y₂ - 2 * d * x₁^3 * x₂^3 * y₂^2 - d * x₁^3 * x₂ * y₁^4 * y₂^3 - 2 * d * x₁^3 * x₂ * y₁^4 *
      y₂^2 - d * x₁^3 * x₂ * y₁^4 * y₂ + 3 * d * x₁^3 * x₂ * y₁^3 * y₂^3 + 6 * d * x₁^3 * x₂ * y₁^3
      * y₂^2 + 3 * d * x₁^3 * x₂ * y₁^3 * y₂ - 3 * d * x₁^3 * x₂ * y₁^2 * y₂^3 - 6 * d * x₁^3 * x₂ *
      y₁^2 * y₂^2 - 3 * d * x₁^3 * x₂ * y₁^2 * y₂ + d * x₁^3 * x₂ * y₁ * y₂^3 + 2 * d * x₁^3 * x₂ *
      y₁ * y₂^2 + d * x₁^3 * x₂ * y₁ * y₂ + 2 * d * x₁^2 * x₂^2 * y₁^4 * y₂^3 + 2 * d * x₁^2 * x₂^2
      * y₁^4 * y₂ - 2 * d * x₁^2 * x₂^2 * y₁^3 * y₂^3 - 8 * d * x₁^2 * x₂^2 * y₁^3 * y₂^2 - 2 * d *
      x₁^2 * x₂^2 * y₁^3 + 2 * d * x₁^2 * x₂^2 * y₁^2 * y₂^3 + 4 * d * x₁^2 * x₂^2 * y₁^2 * y₂^2 + 6
      * d * x₁^2 * x₂^2 * y₁^2 * y₂ - 2 * d * x₁^2 * x₂^2 * y₁ * y₂^2 - 2 * d * x₁^2 * x₂^2 * y₁ *
      y₂ - d * x₁ * x₂^3 * y₁^4 * y₂^3 + 2 * d * x₁ * x₂^3 * y₁^4 * y₂^2 - d * x₁ * x₂^3 * y₁^4 * y₂
      - d * x₁ * x₂^3 * y₁^3 * y₂^3 + 2 * d * x₁ * x₂^3 * y₁^3 * y₂^2 - d * x₁ * x₂^3 * y₁^3 * y₂ +
      d * x₁ * x₂^3 * y₁^2 * y₂^3 - 2 * d * x₁ * x₂^3 * y₁^2 * y₂^2 + d * x₁ * x₂^3 * y₁^2 * y₂ + d
      * x₁ * x₂^3 * y₁ * y₂^3 - 2 * d * x₁ * x₂^3 * y₁ * y₂^2 + d * x₁ * x₂^3 * y₁ * y₂ + 2 * x₁^3 *
      x₂^3 * y₁^2 - 4 * x₁^3 * x₂^3 * y₁ * y₂ + 2 * x₁^3 * x₂^3 * y₂^2 - x₁^3 * x₂ * y₁^3 * y₂^2 - 2
      * x₁^3 * x₂ * y₁^3 * y₂ - x₁^3 * x₂ * y₁^3 + 3 * x₁^3 * x₂ * y₁^2 * y₂^2 + 6 * x₁^3 * x₂ *
      y₁^2 * y₂ + 3 * x₁^3 * x₂ * y₁^2 - 3 * x₁^3 * x₂ * y₁ * y₂^2 - 6 * x₁^3 * x₂ * y₁ * y₂ - 3 *
      x₁^3 * x₂ * y₁ + x₁^3 * x₂ * y₂^2 + 2 * x₁^3 * x₂ * y₂ + x₁^3 * x₂ + 2 * x₁^2 * x₂^2 * y₁^3 *
      y₂^2 + 2 * x₁^2 * x₂^2 * y₁^3 * y₂ - 6 * x₁^2 * x₂^2 * y₁^2 * y₂^2 - 4 * x₁^2 * x₂^2 * y₁^2 *
      y₂ - 2 * x₁^2 * x₂^2 * y₁^2 + 2 * x₁^2 * x₂^2 * y₁ * y₂^3 + 8 * x₁^2 * x₂^2 * y₁ * y₂ + 2 *
      x₁^2 * x₂^2 * y₁ - 2 * x₁^2 * x₂^2 * y₂^2 - 2 * x₁^2 * x₂^2 - x₁^2 * y₁^4 * y₂^3 - 2 * x₁^2 *
      y₁^4 * y₂^2 - x₁^2 * y₁^4 * y₂ + 3 * x₁^2 * y₁^3 * y₂^3 + 7 * x₁^2 * y₁^3 * y₂^2 + 5 * x₁^2 *
      y₁^3 * y₂ + x₁^2 * y₁^3 - 3 * x₁^2 * y₁^2 * y₂^3 - 9 * x₁^2 * y₁^2 * y₂^2 - 9 * x₁^2 * y₁^2 *
      y₂ - 3 * x₁^2 * y₁^2 + x₁^2 * y₁ * y₂^3 + 5 * x₁^2 * y₁ * y₂^2 + 7 * x₁^2 * y₁ * y₂ + 3 * x₁^2
      * y₁ - x₁^2 * y₂^2 - 2 * x₁^2 * y₂ - x₁^2 - x₁ * x₂^3 * y₁^3 * y₂^2 + 2 * x₁ * x₂^3 * y₁^3 *
      y₂ - x₁ * x₂^3 * y₁^3 - x₁ * x₂^3 * y₁^2 * y₂^2 + 2 * x₁ * x₂^3 * y₁^2 * y₂ - x₁ * x₂^3 * y₁^2
      + x₁ * x₂^3 * y₁ * y₂^2 - 2 * x₁ * x₂^3 * y₁ * y₂ + x₁ * x₂^3 * y₁ + x₁ * x₂^3 * y₂^2 - 2 * x₁
      * x₂^3 * y₂ + x₁ * x₂^3 + 2 * x₁ * x₂ * y₁^4 * y₂^3 - 2 * x₁ * x₂ * y₁^4 * y₂ - 2 * x₁ * x₂ *
      y₁^3 * y₂^3 - 2 * x₁ * x₂ * y₁^3 * y₂^2 + 2 * x₁ * x₂ * y₁^3 * y₂ + 2 * x₁ * x₂ * y₁^3 - 2 *
      x₁ * x₂ * y₁^2 * y₂^3 + 2 * x₁ * x₂ * y₁^2 * y₂^2 + 2 * x₁ * x₂ * y₁^2 * y₂ - 2 * x₁ * x₂ *
      y₁^2 + 2 * x₁ * x₂ * y₁ * y₂^3 + 2 * x₁ * x₂ * y₁ * y₂^2 - 2 * x₁ * x₂ * y₁ * y₂ - 2 * x₁ * x₂
      * y₁ - 2 * x₁ * x₂ * y₂^2 + 2 * x₁ * x₂ - x₂^2 * y₁^4 * y₂^3 + 2 * x₂^2 * y₁^4 * y₂^2 - x₂^2 *
      y₁^4 * y₂ - x₂^2 * y₁^3 * y₂^3 + 3 * x₂^2 * y₁^3 * y₂^2 - 3 * x₂^2 * y₁^3 * y₂ + x₂^2 * y₁^3 +
      x₂^2 * y₁^2 * y₂^3 - x₂^2 * y₁^2 * y₂^2 - x₂^2 * y₁^2 * y₂ + x₂^2 * y₁^2 + x₂^2 * y₁ * y₂^3 -
      3 * x₂^2 * y₁ * y₂^2 + 3 * x₂^2 * y₁ * y₂ - x₂^2 * y₁ - x₂^2 * y₂^2 + 2 * x₂^2 * y₂ - x₂^2)) *
      h_bb + (3 * d^3 * x₁ * x₂^3 * y₁^2 * y₂^2 - d^3 * x₁ * x₂^3 * y₁^2 * y₂ - 6 * d^3 * x₁ * x₂^3
      * y₁ * y₂^3 + d^3 * x₁ * x₂^3 * y₁ * y₂^2 - d^3 * x₁ * x₂^3 * y₁ * y₂ + 3 * d^3 * x₁ * x₂^3 *
      y₂^4 + d^3 * x₁ * x₂^3 * y₂^3 + 2 * d^3 * x₁ * x₂^3 * y₂^2 - d^2 * x₁ * x₂^3 * y₁^2 * y₂^2 + 3
      * d^2 * x₁ * x₂^3 * y₁^2 * y₂ + 2 * d^2 * x₁ * x₂^3 * y₁ * y₂^3 - 3 * d^2 * x₁ * x₂^3 * y₁ *
      y₂^2 - 3 * d^2 * x₁ * x₂^3 * y₁ - d^2 * x₁ * x₂^3 * y₂^4 - 3 * d^2 * x₁ * x₂^3 * y₂^3 - 3 *
      d^2 * x₁ * x₂^3 * y₂^2 + 4 * d^2 * x₁ * x₂^3 * y₂ + d^2 * x₁ * x₂^3 - d^2 * x₁ * x₂ * y₁^2 *
      y₂^4 - d^2 * x₁ * x₂ * y₁^2 * y₂^3 + d^2 * x₁ * x₂ * y₁^2 * y₂^2 + d^2 * x₁ * x₂ * y₁^2 * y₂ +
      3 * d^2 * x₁ * x₂ * y₁ * y₂^4 + 3 * d^2 * x₁ * x₂ * y₁ * y₂^3 - 3 * d^2 * x₁ * x₂ * y₁ * y₂^2
      - 3 * d^2 * x₁ * x₂ * y₁ * y₂ - 3 * d^2 * x₁ * x₂ * y₂^4 - 3 * d^2 * x₁ * x₂ * y₂^3 + 3 * d^2
      * x₁ * x₂ * y₂^2 + 3 * d^2 * x₁ * x₂ * y₂ + 2 * d^2 * x₂^2 * y₁^2 * y₂^4 - 2 * d^2 * x₂^2 *
      y₁^2 * y₂^3 + 3 * d^2 * x₂^2 * y₁^2 * y₂^2 - d^2 * x₂^2 * y₁^2 * y₂ - 2 * d^2 * x₂^2 * y₁ *
      y₂^4 - 8 * d^2 * x₂^2 * y₁ * y₂^3 + 5 * d^2 * x₂^2 * y₁ * y₂^2 - 4 * d^2 * x₂^2 * y₁ * y₂ +
      d^2 * x₂^2 * y₁ + 3 * d^2 * x₂^2 * y₂^4 + 5 * d^2 * x₂^2 * y₂^3 + 6 * d^2 * x₂^2 * y₂^2 - 3 *
      d^2 * x₂^2 * y₂ + d^2 * x₂^2 + d * x₁ * x₂^3 * y₁ * y₂ + d * x₁ * x₂^3 * y₁ - d * x₁ * x₂^3 *
      y₂^2 - 4 * d * x₁ * x₂^3 * y₂ - 3 * d * x₁ * x₂^3 - d * x₁ * x₂ * y₁ * y₂^3 - d * x₁ * x₂ * y₁
      * y₂^2 + d * x₁ * x₂ * y₁ * y₂ + d * x₁ * x₂ * y₁ + d * x₁ * x₂ * y₂^4 + 4 * d * x₁ * x₂ *
      y₂^3 + 2 * d * x₁ * x₂ * y₂^2 - 4 * d * x₁ * x₂ * y₂ - 3 * d * x₁ * x₂ + d * x₂^2 * y₁^2 *
      y₂^2 + d * x₂^2 * y₁^2 * y₂ - 3 * d * x₂^2 * y₁ * y₂^2 - 4 * d * x₂^2 * y₁ * y₂ - d * x₂^2 *
      y₁ - d * x₂^2 * y₂^4 - d * x₂^2 * y₂^3 + 3 * d * x₂^2 * y₂^2 + 6 * d * x₂^2 * y₂ + 3 * d *
      x₂^2 - d * y₁^2 * y₂^4 - d * y₁^2 * y₂^3 + d * y₁^2 * y₂^2 + d * y₁^2 * y₂ + 3 * d * y₁ * y₂^4
      + 4 * d * y₁ * y₂^3 - 2 * d * y₁ * y₂^2 - 4 * d * y₁ * y₂ - d * y₁ - 3 * d * y₂^4 - 6 * d *
      y₂^3 + 6 * d * y₂ + 3 * d - x₂^2 * y₂^2 - x₂^2 * y₂ + y₂^4 + y₂^3 - y₂^2 - y₂) * h₁ + (-d^3 *
      x₁^3 * x₂ * y₁ * y₂^2 - d^3 * x₁^3 * x₂ * y₁ * y₂ + 3 * d^2 * x₁^3 * x₂ * y₁ * y₂^2 + 6 * d^2
      * x₁^3 * x₂ * y₁ * y₂ + 3 * d^2 * x₁^3 * x₂ * y₁ - 3 * d^2 * x₁^3 * x₂ * y₂^2 - 4 * d^2 * x₁^3
      * x₂ * y₂ - d^2 * x₁^3 * x₂ - d^2 * x₁^2 * y₁ * y₂^2 - 4 * d^2 * x₁^2 * y₁ * y₂ - 3 * d^2 *
      x₁^2 * y₁ + d^2 * x₁^2 * y₂ + d^2 * x₁^2 - d^2 * x₁ * x₂ * y₁^4 * y₂^2 + 3 * d^2 * x₁ * x₂ *
      y₁^4 * y₂ - d^2 * x₁ * x₂ * y₁^3 * y₂^2 - 3 * d^2 * x₁ * x₂ * y₁^3 * y₂ - 2 * d^2 * x₁ * x₂ *
      y₁^3 + 4 * d^2 * x₁ * x₂ * y₁^2 * y₂^2 - 2 * d^2 * x₁ * x₂ * y₁^2 * y₂ + 2 * d^2 * x₁ * x₂ *
      y₁^2 + d^2 * x₁ * x₂ * y₁ * y₂^2 + 3 * d^2 * x₁ * x₂ * y₁ * y₂ + 2 * d^2 * x₁ * x₂ * y₁ - 3 *
      d^2 * x₁ * x₂ * y₂^2 - d^2 * x₁ * x₂ * y₂ - 2 * d^2 * x₁ * x₂ - d * x₁^3 * x₂ * y₁ * y₂ - d *
      x₁^3 * x₂ * y₁ + d * x₁^3 * x₂ * y₂^2 + 4 * d * x₁^3 * x₂ * y₂ + 3 * d * x₁^3 * x₂ + 3 * d *
      x₁^2 * y₁ * y₂^2 + 4 * d * x₁^2 * y₁ * y₂ + d * x₁^2 * y₁ - 3 * d * x₁^2 * y₂^2 - 6 * d * x₁^2
      * y₂ - 3 * d * x₁^2 + d * x₁ * x₂ * y₁^3 * y₂ + d * x₁ * x₂ * y₁^3 - d * x₁ * x₂ * y₁^2 * y₂^2
      - 4 * d * x₁ * x₂ * y₁^2 * y₂ - 3 * d * x₁ * x₂ * y₁^2 - d * x₁ * x₂ * y₁ * y₂ - d * x₁ * x₂ *
      y₁ + d * x₁ * x₂ * y₂^2 + 4 * d * x₁ * x₂ * y₂ + 3 * d * x₁ * x₂ + d * y₁^4 * y₂^2 + d * y₁^4
      * y₂ - 3 * d * y₁^3 * y₂^2 - 4 * d * y₁^3 * y₂ - d * y₁^3 + 2 * d * y₁^2 * y₂^2 + 5 * d * y₁^2
      * y₂ + 3 * d * y₁^2 + 3 * d * y₁ * y₂^2 + 4 * d * y₁ * y₂ + d * y₁ - 3 * d * y₂^2 - 6 * d * y₂
      - 3 * d + x₁^2 * y₂^2 + x₁^2 * y₂ - y₁^2 * y₂^2 - y₁^2 * y₂ + y₂^2 + y₂) * h₂

/-- `monY` of an x and a y written as fractions. -/
theorem monY_frac {n m u v : F} (h_m : m ≠ 0) (h_e : m - n ≠ 0) (h_v : v ≠ 0) (h_u : u ≠ 0) :
    monY d (u / v) (n / m) = 2 * (1 + d) * (m + n) * v / ((m - n) * u) := by
  simp only [monY]
  rw [one_add_div h_m, one_sub_div h_m]
  field_simp

/-- The y of a chord sum. -/
theorem chord_y (h_d : d ≠ 0) (h_x₁ : x₁ ≠ 0)
    (h_x₂ : x₂ ≠ 0) (h_m₁ : 1 - y₁ ≠ 0) (h_m₂ : 1 - y₂ ≠ 0) (h_w : y₁ - y₂ ≠ 0)
    (h₁ : OnCurve d x₁ y₁) (h₂ : OnCurve d x₂ y₂)
    (h_e : (1 - d * x₁ * x₂ * y₁ * y₂) - (y₁ * y₂ + x₁ * x₂) ≠ 0)
    (h_u : x₁ * y₂ + y₁ * x₂ ≠ 0) :
    2 * (1 + d) * ((1 - d * x₁ * x₂ * y₁ * y₂) + (y₁ * y₂ + x₁ * x₂)) *
        (1 + d * x₁ * x₂ * y₁ * y₂) /
        (((1 - d * x₁ * x₂ * y₁ * y₂) - (y₁ * y₂ + x₁ * x₂)) * (x₁ * y₂ + y₁ * x₂)) =
      (mont d).addY (monX d y₁) (monX d y₂) (monY d x₁ y₁)
        (((1 + y₂) * (1 - y₁) * x₁ - (1 + y₁) * (1 - y₂) * x₂) / ((y₁ - y₂) * x₁ * x₂)) := by
  simp only [WeierstrassCurve.Affine.addY, WeierstrassCurve.Affine.negAddY,
    WeierstrassCurve.Affine.negY]
  rw [← chord_x h_d h_x₁ h_x₂ h_m₁ h_m₂ h_w h₁ h₂ h_e]
  unfold OnCurve at h₁ h₂
  simp only [mont, monX, monY]
  generalize h_pp : 1 + d * x₁ * x₂ * y₁ * y₂ = p
  generalize h_mm : 1 - d * x₁ * x₂ * y₁ * y₂ = m at h_e ⊢
  generalize h_ee : m - (y₁ * y₂ + x₁ * x₂) = e at h_e ⊢
  generalize h_uu : x₁ * y₂ + y₁ * x₂ = u at h_u ⊢
  generalize h_ww : y₁ - y₂ = w at h_w ⊢
  generalize h_aa : 1 - y₁ = a at h_m₁ ⊢
  generalize h_bb : 1 - y₂ = b at h_m₂ ⊢
  field_simp
  refine mul_left_cancel₀ (show (d ^ 1 : F) ≠ 0 from ?_) ?_
  · exact pow_ne_zero _ h_d
  · linear_combination (-2 * a * d * w * x₁ * x₂ * (d + 1) * (m + x₁ * x₂ + y₁ * y₂)) * h_pp + (d *
      (d + 1) * (a^2 * m * x₁ * y₂ + a^2 * m * x₁ + a^2 * x₁^2 * x₂ * y₂ + a^2 * x₁^2 * x₂ + a^2 *
      x₁ * y₁ * y₂^2 + a^2 * x₁ * y₁ * y₂ - a * b * m * x₂ * y₁ - a * b * m * x₂ - a * b * x₁ * x₂^2
      * y₁ - a * b * x₁ * x₂^2 - a * b * x₂ * y₁^2 * y₂ - a * b * x₂ * y₁ * y₂ - a * e * x₁ * y₁ *
      y₂ - a * e * x₁ * y₁ - a * e * x₁ * y₂ - a * e * x₁ + b * e * x₂ * y₁^2 + 2 * b * e * x₂ * y₁
      + b * e * x₂ - 2 * e * w * x₂ * y₁ - 2 * e * w * x₂)) * h_uu + (-d * (d + 1) * (y₁ + 1) * (x₁
      * y₂ + x₂ * y₁) * (a * x₁ * y₂ + a * x₁ - b * x₂ * y₁ - b * x₂ + 2 * w * x₂)) * h_ee + (-d *
      (d + 1) * (-a^2 * x₁^2 * y₂^2 - a^2 * x₁^2 * y₂ - a^2 * x₁ * x₂ * y₁ * y₂ - a^2 * x₁ * x₂ * y₁
      + a * b * x₁ * x₂ * y₁ * y₂ + a * b * x₁ * x₂ * y₂ + a * b * x₂^2 * y₁^2 + a * b * x₂^2 * y₁ +
      2 * a * d * w * x₁^2 * x₂^2 * y₁ * y₂ + 2 * a * w * x₁ * x₂ + a * x₁^2 * y₁ * y₂^2 + a * x₁^2
      * y₁ * y₂ + a * x₁^2 * y₂^2 + a * x₁^2 * y₂ + a * x₁ * x₂ * y₁^2 * y₂ + a * x₁ * x₂ * y₁^2 + a
      * x₁ * x₂ * y₁ * y₂ + a * x₁ * x₂ * y₁ - b * x₁ * x₂ * y₁^2 * y₂ - 2 * b * x₁ * x₂ * y₁ * y₂ -
      b * x₁ * x₂ * y₂ - b * x₂^2 * y₁^3 - 2 * b * x₂^2 * y₁^2 - b * x₂^2 * y₁ + 2 * w * x₁ * x₂ *
      y₁ * y₂ + 2 * w * x₁ * x₂ * y₂ + 2 * w * x₂^2 * y₁^2 + 2 * w * x₂^2 * y₁)) * h_mm + (2 * d *
      x₂ * (d + 1) * (a * d^2 * x₁^3 * x₂^2 * y₁^2 * y₂^2 - a * d * x₁^3 * x₂^2 * y₁ * y₂ - a * d *
      x₁^2 * x₂ * y₁^2 * y₂^2 - a * x₁^2 * x₂ - a * x₁ * y₁ * y₂ - a * x₁ + d * x₁^2 * x₂ * y₁^2 *
      y₂^2 + d * x₁^2 * x₂ * y₁ * y₂^2 + d * x₁ * x₂^2 * y₁^3 * y₂ + d * x₁ * x₂^2 * y₁^2 * y₂ +
      x₁^2 * x₂ * y₁ * y₂ + x₁^2 * x₂ * y₂ + x₁ * x₂^2 * y₁^2 + x₁ * x₂^2 * y₁ + x₁ * y₁^2 * y₂^2 +
      x₁ * y₁ * y₂^2 - x₁ * y₁ * y₂ - x₁ * y₂ + x₂ * y₁^3 * y₂ + x₂ * y₁^2 * y₂ - x₂ * y₁^2 - x₂ *
      y₁)) * h_ww + (d * (d + 1) * (-a * d * x₁^3 * x₂ * y₁ * y₂^3 - a * d * x₁^3 * x₂ * y₁ * y₂^2 -
      a * d * x₁^2 * x₂^2 * y₁^2 * y₂^2 - a * d * x₁^2 * x₂^2 * y₁^2 * y₂ + a * x₁^3 * x₂ * y₂^2 + a
      * x₁^3 * x₂ * y₂ + a * x₁^2 * x₂^2 * y₁ * y₂ + a * x₁^2 * x₂^2 * y₁ + a * x₁^2 * y₁ * y₂^3 + a
      * x₁^2 * y₁ * y₂^2 + a * x₁^2 * y₂^2 + a * x₁^2 * y₂ + a * x₁ * x₂ * y₁^2 * y₂^2 + a * x₁ * x₂
      * y₁^2 * y₂ + a * x₁ * x₂ * y₁ * y₂ + a * x₁ * x₂ * y₁ + b * d * x₁^2 * x₂^2 * y₁^2 * y₂^2 + b
      * d * x₁^2 * x₂^2 * y₁ * y₂^2 + b * d * x₁ * x₂^3 * y₁^3 * y₂ + b * d * x₁ * x₂^3 * y₁^2 * y₂
      - b * x₁^2 * x₂^2 * y₁ * y₂ - b * x₁^2 * x₂^2 * y₂ - b * x₁ * x₂^3 * y₁^2 - b * x₁ * x₂^3 * y₁
      - b * x₁ * x₂ * y₁^2 * y₂^2 - b * x₁ * x₂ * y₁ * y₂^2 - b * x₁ * x₂ * y₁ * y₂ - b * x₁ * x₂ *
      y₂ - b * x₂^2 * y₁^3 * y₂ - b * x₂^2 * y₁^2 * y₂ - b * x₂^2 * y₁^2 - b * x₂^2 * y₁ + 2 * d^2 *
      x₁^3 * x₂^3 * y₁^3 * y₂^2 - 2 * d^2 * x₁^3 * x₂^3 * y₁^2 * y₂^3 - 2 * d * x₁^3 * x₂^3 * y₁^2 *
      y₂ + 2 * d * x₁^3 * x₂^3 * y₁ * y₂^2 + 2 * d * x₁^3 * x₂ * y₁^2 * y₂^3 + 2 * d * x₁^3 * x₂ *
      y₁^2 * y₂^2 + 2 * d * x₁^2 * x₂^2 * y₁^3 * y₂ + 2 * d * x₁^2 * x₂^2 * y₁^2 * y₂^3 + 2 * x₁^3 *
      x₂ * y₂^2 + 2 * x₁^3 * x₂ * y₂ + 2 * x₁^2 * x₂^2 * y₁ * y₂ + 2 * x₁^2 * x₂^2 * y₂ + 2 * x₁^2 *
      y₁ * y₂^3 - 2 * x₁^2 * y₁ * y₂ + 2 * x₁ * x₂ * y₁^2 * y₂^2 - 2 * x₁ * x₂ * y₁^2 * y₂ - 2 * x₁
      * x₂ * y₁^2 + 2 * x₁ * x₂ * y₁ * y₂^2 - 2 * x₁ * x₂ * y₁ + 2 * x₁ * x₂ * y₂)) * h_aa + (-2 * d
      * x₂ * (d + 1) * (y₁ + 1) * (x₁ * y₂ + x₂ * y₁) * (d * x₁ * x₂ * y₁^2 * y₂ + x₁ * x₂ + y₁ * y₂
      - y₁)) * h_bb + (-2 * y₂ * (d + 1) * (d^2 * x₁ * x₂^3 * y₁^2 * y₂ - d^2 * x₁ * x₂^3 * y₁ *
      y₂^2 - d^2 * x₁ * x₂^3 * y₁ * y₂ + d^2 * x₁ * x₂^3 * y₂^2 - d * x₁ * x₂^3 * y₁ + d * x₁ * x₂^3
      + d * x₁ * x₂ * y₁ * y₂^2 + d * x₁ * x₂ * y₁ * y₂ - d * x₁ * x₂ * y₂^2 - d * x₁ * x₂ * y₂ + d
      * x₂^2 * y₁^2 - d * x₂^2 * y₁ - d * x₂^2 * y₂^2 - x₂^2 + y₂^2 - 1)) * h₁ + (-2 * (d + 1) * (d
      * x₁^3 * x₂ * y₁ * y₂ - d * x₁^3 * x₂ * y₂ + d * x₁^2 * y₁ * y₂ - d * x₁ * x₂ * y₁^3 * y₂ - d
      * x₁ * x₂ * y₁^3 + d * x₁ * x₂ * y₁^2 * y₂ + d * x₁ * x₂ * y₁ * y₂ + d * x₁ * x₂ * y₁ - d * x₁
      * x₂ * y₂ + x₁^2 * y₂ - y₁^2 * y₂ + y₂)) * h₂

/-- The tangent's slope at an image, in the point's coordinates. -/
theorem slope_tangent (h_two : (2 : F) ≠ 0) (h_k : 1 + d ≠ 0) (h_x₁ : x₁ ≠ 0)
    (h_m₁ : 1 - y₁ ≠ 0) (h_n₁ : 1 + y₁ ≠ 0) :
    (3 * monX d y₁ ^ 2 + 2 * (2 * (d - 1)) * monX d y₁ + (1 + d) ^ 2 - 0 * monY d x₁ y₁) /
        (monY d x₁ y₁ - (-monY d x₁ y₁ - 0 * monX d y₁ - 0)) =
      x₁ * (2 * d * y₁ ^ 2 + (1 + d) * y₁ + 2) / ((1 - y₁) * (1 + y₁)) := by
  have h_den : monY d x₁ y₁ - (-monY d x₁ y₁ - 0 * monX d y₁ - 0) ≠ 0 := by
    have : monY d x₁ y₁ - (-monY d x₁ y₁ - 0 * monX d y₁ - 0) = 2 * monY d x₁ y₁ := by ring
    rw [this, monY]
    exact mul_ne_zero h_two (div_ne_zero (mul_ne_zero (mul_ne_zero h_two h_k) h_n₁)
      (mul_ne_zero h_m₁ h_x₁))
  rw [div_eq_iff h_den]
  simp only [monX, monY]
  generalize h_kk : 1 + d = k at h_k ⊢
  generalize h_aa : 1 - y₁ = a at h_m₁ ⊢
  generalize h_nn : 1 + y₁ = n at h_n₁ ⊢
  field_simp
  linear_combination (n * x₁ * (-a^2 * d - a^2 * k - a^2 + 4 * a * d * n - 4 * a * n - 3 * d * n^2 +
    8 * d * y₁^2 + 4 * d * y₁ - 3 * k * n^2 + 4 * k * y₁ - 3 * n^2 + 4 * y₁ + 8)) * h_kk + (n * x₁ *
    (d + 1) * (-a * d - a + 4 * d * n + d * y₁ - d - 4 * n + y₁ - 1)) * h_aa + (-n * x₁ * (d + 1) *
    (3 * d * n + 7 * d * y₁ - d + 3 * n - y₁ + 7)) * h_nn

/-- The x of a doubling, against the doubling of the point's image. -/
theorem tangent_x (h_m₁ : 1 - y₁ ≠ 0) (h_n₁ : 1 + y₁ ≠ 0) (h₁ : OnCurve d x₁ y₁)
    (h_e : (1 - d * x₁ * x₁ * y₁ * y₁) - (y₁ * y₁ + x₁ * x₁) ≠ 0) :
    -(1 + d) * ((1 - d * x₁ * x₁ * y₁ * y₁) + (y₁ * y₁ + x₁ * x₁)) /
        ((1 - d * x₁ * x₁ * y₁ * y₁) - (y₁ * y₁ + x₁ * x₁)) =
      (mont d).addX (monX d y₁) (monX d y₁)
        (x₁ * (2 * d * y₁ ^ 2 + (1 + d) * y₁ + 2) / ((1 - y₁) * (1 + y₁))) := by
  unfold OnCurve at h₁
  simp only [WeierstrassCurve.Affine.addX, mont, monX]
  generalize h_mm : 1 - d * x₁ * x₁ * y₁ * y₁ = m at h_e ⊢
  generalize h_ee : m - (y₁ * y₁ + x₁ * x₁) = e at h_e ⊢
  generalize h_aa : 1 - y₁ = a at h_m₁ ⊢
  generalize h_nn : 1 + y₁ = n at h_n₁ ⊢
  field_simp
  linear_combination (-2 * a^2 * d * n^2 + 2 * a^2 * n^2 + 2 * a * d * n^3 + 2 * a * n^3 + 4 * d^2 *
    x₁^2 * y₁^4 + 4 * d^2 * x₁^2 * y₁^3 + d^2 * x₁^2 * y₁^2 + 4 * d * x₁^2 * y₁^3 + 10 * d * x₁^2 *
    y₁^2 + 4 * d * x₁^2 * y₁ + x₁^2 * y₁^2 + 4 * x₁^2 * y₁ + 4 * x₁^2) * h_ee + (-a^2 * d * n^2 + 3
    * a^2 * n^2 + 2 * a * d * n^3 + 2 * a * n^3 + 4 * d^2 * x₁^2 * y₁^4 + 4 * d^2 * x₁^2 * y₁^3 +
    d^2 * x₁^2 * y₁^2 + 4 * d * x₁^2 * y₁^3 + 10 * d * x₁^2 * y₁^2 + 4 * d * x₁^2 * y₁ + x₁^2 * y₁^2
    + 4 * x₁^2 * y₁ + 4 * x₁^2) * h_mm + (-n^2 * (-a * d^2 * x₁^2 * y₁^2 + 3 * a * d * x₁^2 * y₁^2 -
    3 * a * d * x₁^2 - 3 * a * d * y₁^2 + a * d + a * x₁^2 + a * y₁^2 - 3 * a + 2 * d^2 * n * x₁^2 *
    y₁^2 + d^2 * x₁^2 * y₁^3 - d^2 * x₁^2 * y₁^2 + 2 * d * n * x₁^2 * y₁^2 + 2 * d * n * x₁^2 + 2 *
    d * n * y₁^2 - 2 * d * n - 3 * d * x₁^2 * y₁^3 + 3 * d * x₁^2 * y₁^2 + 3 * d * x₁^2 * y₁ - 3 * d
    * x₁^2 + 3 * d * y₁^3 - 3 * d * y₁^2 - d * y₁ + d + 2 * n * x₁^2 + 2 * n * y₁^2 - 2 * n - x₁^2 *
    y₁ + x₁^2 - y₁^3 + y₁^2 + 3 * y₁ - 3)) * h_aa + ((y₁ - 1) * (2 * d^2 * n^2 * x₁^2 * y₁^2 + 3 *
    d^2 * n * x₁^2 * y₁^3 + d^2 * n * x₁^2 * y₁^2 + 3 * d^2 * x₁^2 * y₁^4 + 4 * d^2 * x₁^2 * y₁^3 +
    d^2 * x₁^2 * y₁^2 + 2 * d * n^2 * x₁^2 * y₁^2 + 2 * d * n^2 * x₁^2 + 2 * d * n^2 * y₁^2 - 2 * d
    * n^2 - d * n * x₁^2 * y₁^3 + 5 * d * n * x₁^2 * y₁^2 + 5 * d * n * x₁^2 * y₁ - d * n * x₁^2 + 5
    * d * n * y₁^3 - d * n * y₁^2 - 3 * d * n * y₁ - d * n - d * x₁^2 * y₁^4 + 4 * d * x₁^2 * y₁^3 +
    10 * d * x₁^2 * y₁^2 + 4 * d * x₁^2 * y₁ - d * x₁^2 + 5 * d * y₁^4 + 4 * d * y₁^3 - 4 * d * y₁^2
    - 4 * d * y₁ - d + 2 * n^2 * x₁^2 + 2 * n^2 * y₁^2 - 2 * n^2 + n * x₁^2 * y₁ + 3 * n * x₁^2 + n
    * y₁^3 + 3 * n * y₁^2 + n * y₁ - 5 * n + x₁^2 * y₁^2 + 4 * x₁^2 * y₁ + 3 * x₁^2 + y₁^4 + 4 *
    y₁^3 + 4 * y₁^2 - 4 * y₁ - 5)) * h_nn + (-4 * d^2 * x₁^2 * y₁^4 - 4 * d^2 * x₁^2 * y₁^3 - d^2 *
    x₁^2 * y₁^2 - 4 * d * x₁^2 * y₁^3 - 10 * d * x₁^2 * y₁^2 - 4 * d * x₁^2 * y₁ - 5 * d * y₁^4 - 4
    * d * y₁^3 + 4 * d * y₁^2 + 4 * d * y₁ + d - x₁^2 * y₁^2 - 4 * x₁^2 * y₁ - 4 * x₁^2 - y₁^4 - 4 *
    y₁^3 - 4 * y₁^2 + 4 * y₁ + 5) * h₁

/-- The y of a doubling. -/
theorem tangent_y (h_x₁ : x₁ ≠ 0)
    (h_m₁ : 1 - y₁ ≠ 0) (h_n₁ : 1 + y₁ ≠ 0) (h₁ : OnCurve d x₁ y₁)
    (h_e : (1 - d * x₁ * x₁ * y₁ * y₁) - (y₁ * y₁ + x₁ * x₁) ≠ 0)
    (h_u : x₁ * y₁ + y₁ * x₁ ≠ 0) :
    2 * (1 + d) * ((1 - d * x₁ * x₁ * y₁ * y₁) + (y₁ * y₁ + x₁ * x₁)) *
        (1 + d * x₁ * x₁ * y₁ * y₁) /
        (((1 - d * x₁ * x₁ * y₁ * y₁) - (y₁ * y₁ + x₁ * x₁)) * (x₁ * y₁ + y₁ * x₁)) =
      (mont d).addY (monX d y₁) (monX d y₁) (monY d x₁ y₁)
        (x₁ * (2 * d * y₁ ^ 2 + (1 + d) * y₁ + 2) / ((1 - y₁) * (1 + y₁))) := by
  simp only [WeierstrassCurve.Affine.addY, WeierstrassCurve.Affine.negAddY,
    WeierstrassCurve.Affine.negY]
  rw [← tangent_x h_m₁ h_n₁ h₁ h_e]
  unfold OnCurve at h₁
  simp only [mont, monX, monY]
  generalize h_pp : 1 + d * x₁ * x₁ * y₁ * y₁ = p
  generalize h_mm : 1 - d * x₁ * x₁ * y₁ * y₁ = m at h_e ⊢
  generalize h_ee : m - (y₁ * y₁ + x₁ * x₁) = e at h_e ⊢
  generalize h_uu : x₁ * y₁ + y₁ * x₁ = u at h_u ⊢
  generalize h_aa : 1 - y₁ = a at h_m₁ ⊢
  generalize h_nn : 1 + y₁ = n at h_n₁ ⊢
  field_simp
  linear_combination (-2 * a^2 * n * x₁ * (d + 1) * (m + x₁^2 + y₁^2)) * h_pp + ((d + 1) * (2 * a *
    d * m * x₁^2 * y₁^2 + a * d * m * x₁^2 * y₁ + 2 * a * d * x₁^4 * y₁^2 + a * d * x₁^4 * y₁ + 2 *
    a * d * x₁^2 * y₁^4 + a * d * x₁^2 * y₁^3 - 2 * a * e * n^2 + a * m * x₁^2 * y₁ + 2 * a * m *
    x₁^2 + a * x₁^4 * y₁ + 2 * a * x₁^4 + a * x₁^2 * y₁^3 + 2 * a * x₁^2 * y₁^2 - 2 * d * e * n *
    x₁^2 * y₁^2 - d * e * n * x₁^2 * y₁ - e * n * x₁^2 * y₁ - 2 * e * n * x₁^2)) * h_uu + (-2 * n *
    x₁ * y₁ * (d + 1) * (2 * a * n + 2 * d * x₁^2 * y₁^2 + d * x₁^2 * y₁ + x₁^2 * y₁ + 2 * x₁^2)) *
    h_ee + (2 * x₁ * (d + 1) * (-a^2 * d * n * x₁^2 * y₁^2 - a^2 * n + 2 * a * d * x₁^2 * y₁^3 + a *
    d * x₁^2 * y₁^2 - 2 * a * n^2 * y₁ + a * x₁^2 * y₁^2 + 2 * a * x₁^2 * y₁ - 2 * d * n * x₁^2 *
    y₁^3 - d * n * x₁^2 * y₁^2 - n * x₁^2 * y₁^2 - 2 * n * x₁^2 * y₁)) * h_mm + (-2 * x₁ * (d + 1) *
    (-a * d^2 * n * x₁^4 * y₁^4 + a * d * n * x₁^4 * y₁^2 + a * d * n * x₁^2 * y₁^4 + a * n * x₁^2 +
    a * n * y₁^2 + a * n + d^2 * n * x₁^4 * y₁^5 - d^2 * n * x₁^4 * y₁^4 + 2 * d^2 * x₁^4 * y₁^5 +
    d^2 * x₁^4 * y₁^4 - 2 * d * n^2 * x₁^2 * y₁^3 - d * n * x₁^4 * y₁^3 + d * n * x₁^4 * y₁^2 - d *
    n * x₁^2 * y₁^5 + d * n * x₁^2 * y₁^4 + d * x₁^4 * y₁^4 - d * x₁^4 * y₁^2 - 2 * d * x₁^2 * y₁^5
    - d * x₁^2 * y₁^4 - 2 * d * x₁^2 * y₁^3 - d * x₁^2 * y₁^2 - 2 * n^2 * x₁^2 * y₁ - 2 * n^2 * y₁^3
    + 2 * n^2 * y₁ - n * x₁^2 * y₁ + n * x₁^2 - n * y₁^3 + n * y₁^2 - n * y₁ + n - x₁^4 * y₁^2 - 2 *
    x₁^4 * y₁ - x₁^2 * y₁^4 - 2 * x₁^2 * y₁^3 - x₁^2 * y₁^2 - 2 * x₁^2 * y₁)) * h_aa + (2 * x₁ * (d
    + 1) * (d^2 * x₁^4 * y₁^6 + 2 * d^2 * x₁^4 * y₁^4 - 2 * d * n * x₁^2 * y₁^4 + 2 * d * n * x₁^2 *
    y₁^3 + 6 * d * x₁^4 * y₁^3 - d * x₁^2 * y₁^6 + 2 * d * x₁^2 * y₁^5 - d * x₁^2 * y₁^2 - 2 * n *
    x₁^2 * y₁^2 + 2 * n * x₁^2 * y₁ - 2 * n * y₁^4 + 2 * n * y₁^3 + 2 * n * y₁^2 - 2 * n * y₁ + x₁^4
    * y₁^2 + 2 * x₁^4 * y₁ + x₁^2 * y₁^4 - 2 * x₁^2 * y₁^2 + 2 * x₁^2 * y₁ - x₁^2 - 2 * y₁^5 - y₁^4
    + 6 * y₁^3 - 2 * y₁^2 - 1)) * h_nn + (2 * x₁ * (d + 1) * (d * x₁^2 * y₁^5 + 3 * d * x₁^2 * y₁^4
    + d * x₁^2 * y₁^3 + d * x₁^2 * y₁^2 + 2 * x₁^2 * y₁^2 + 4 * x₁^2 * y₁ + 2 * y₁^4 + 3 * y₁^3 - 3
    * y₁^2 - y₁ - 1)) * h₁

/-- The chord's slope between (0, 0) and an image. -/
theorem slope_two_torsion (h_k : 1 + d ≠ 0) (h_x₂ : x₂ ≠ 0)
    (h_m₂ : 1 - y₂ ≠ 0) (h_n₂ : 1 + y₂ ≠ 0) :
    (0 - monY d x₂ y₂) / (0 - monX d y₂) = -2 / x₂ := by
  have h_X : 0 - monX d y₂ ≠ 0 := by
    rw [zero_sub, neg_ne_zero, monX]
    exact div_ne_zero (mul_ne_zero (neg_ne_zero.mpr h_k) h_n₂) h_m₂
  rw [div_eq_iff h_X]
  simp only [monX, monY]
  field_simp
  ring

/-- The x of (0, -1) plus a point, against (0, 0) plus its image. -/
theorem two_torsion_x (h_x₂ : x₂ ≠ 0)
    (h_m₂ : 1 - y₂ ≠ 0) (h_n₂ : 1 + y₂ ≠ 0) (h₂ : OnCurve d x₂ y₂) :
    monX d (-y₂) = (mont d).addX 0 (monX d y₂) (-2 / x₂) := by
  unfold OnCurve at h₂
  simp only [WeierstrassCurve.Affine.addX, mont, monX]
  rw [sub_neg_eq_add]
  generalize h_bb : 1 - y₂ = b at h_m₂ ⊢
  generalize h_nn : 1 + y₂ = n at h_n₂ ⊢
  field_simp
  linear_combination (-2 * d * n * x₂^2 - d * x₂^2 * y₂ + d * x₂^2 + 2 * n * x₂^2 + 4 * n - x₂^2 *
    y₂ + x₂^2) * h_bb + (d * n * x₂^2 + 3 * d * x₂^2 * y₂ - d * x₂^2 + n * x₂^2 - x₂^2 * y₂ + 3 *
    x₂^2 - 4 * y₂ + 4) * h_nn + (4) * h₂

/-- The y of (0, -1) plus a point. -/
theorem two_torsion_y (h_x₂ : x₂ ≠ 0)
    (h_m₂ : 1 - y₂ ≠ 0) (h_n₂ : 1 + y₂ ≠ 0) (h₂ : OnCurve d x₂ y₂) :
    monY d (-x₂) (-y₂) = (mont d).addY 0 (monX d y₂) 0 (-2 / x₂) := by
  simp only [WeierstrassCurve.Affine.addY, WeierstrassCurve.Affine.negAddY,
    WeierstrassCurve.Affine.negY]
  rw [← two_torsion_x h_x₂ h_m₂ h_n₂ h₂]
  simp only [mont, monX, monY]
  rw [sub_neg_eq_add]
  generalize h_bb : 1 - y₂ = b at h_m₂ ⊢
  generalize h_nn : 1 + y₂ = n at h_n₂ ⊢
  field_simp
  linear_combination

/-- The chord through the images of (x, y) and (x, -y) gives x 0: their sum is (0, -1). -/
theorem chord_zero_x (h_two : (2 : F) ≠ 0) (h_x₁ : x₁ ≠ 0)
    (h_m₁ : 1 - y₁ ≠ 0) (h_n₁ : 1 + y₁ ≠ 0) (h_y₁ : y₁ ≠ 0) (h₁ : OnCurve d x₁ y₁) :
    (mont d).addX (monX d y₁) (monX d (-y₁))
        (((1 + -y₁) * (1 - y₁) * x₁ - (1 + y₁) * (1 - -y₁) * x₁) / ((y₁ - -y₁) * x₁ * x₁)) = 0 := by
  unfold OnCurve at h₁
  simp only [WeierstrassCurve.Affine.addX, mont, monX]
  rw [sub_neg_eq_add, sub_neg_eq_add]
  generalize h_aa : 1 - y₁ = a at h_m₁ ⊢
  generalize h_nn : 1 + y₁ = n at h_n₁ ⊢
  have h_w : y₁ + y₁ ≠ 0 := by
    rw [← two_mul]; exact mul_ne_zero h_two h_y₁
  generalize h_ww : y₁ + y₁ = w at h_w ⊢
  field_simp
  linear_combination (x₁^2 * (w + 2 * y₁) * (2 * a * d * n + a * d * y₁ - a * d - 2 * a * n + a * y₁
    - a - d * n^2 - n^2)) * h_ww + (-a^2 * n * y₁^2 + 2 * a^2 * n * y₁ - a^2 * n - 2 * a * n^3 * y₁
    + 2 * a * n^3 + a * n * y₁^3 - 3 * a * n * y₁^2 + 3 * a * n * y₁ - a * n + 8 * d * n * x₁^2 *
    y₁^2 + 4 * d * x₁^2 * y₁^3 - 4 * d * x₁^2 * y₁^2 - n^5 + 2 * n^3 * y₁^2 - 4 * n^3 * y₁ + 2 * n^3
    - 8 * n * x₁^2 * y₁^2 - n * y₁^4 + 4 * n * y₁^3 - 6 * n * y₁^2 + 4 * n * y₁ - n + 4 * x₁^2 *
    y₁^3 - 4 * x₁^2 * y₁^2) * h_aa + (-4 * d * n * x₁^2 * y₁^2 - 12 * d * x₁^2 * y₁^3 + 4 * d * x₁^2
    * y₁^2 + n^4 * y₁ - n^4 + n^3 * y₁^2 - n^3 - n^2 * y₁^3 + 7 * n^2 * y₁^2 - 7 * n^2 * y₁ + n^2 -
    4 * n * x₁^2 * y₁^2 - n * y₁^4 + 6 * n * y₁^3 - 6 * n * y₁ + n + 4 * x₁^2 * y₁^3 - 12 * x₁^2 *
    y₁^2 + 16 * y₁^3 - 16 * y₁^2) * h_nn + (-16 * y₁^2) * h₁

/-- The same chord gives y 0. -/
theorem chord_zero_y (h_two : (2 : F) ≠ 0) (h_x₁ : x₁ ≠ 0)
    (h_m₁ : 1 - y₁ ≠ 0) (h_n₁ : 1 + y₁ ≠ 0) (h_y₁ : y₁ ≠ 0) (h₁ : OnCurve d x₁ y₁) :
    (mont d).addY (monX d y₁) (monX d (-y₁)) (monY d x₁ y₁)
        (((1 + -y₁) * (1 - y₁) * x₁ - (1 + y₁) * (1 - -y₁) * x₁) / ((y₁ - -y₁) * x₁ * x₁)) = 0 := by
  simp only [WeierstrassCurve.Affine.addY, WeierstrassCurve.Affine.negAddY,
    WeierstrassCurve.Affine.negY]
  rw [chord_zero_x h_two h_x₁ h_m₁ h_n₁ h_y₁ h₁]
  unfold OnCurve at h₁
  simp only [mont, monX, monY]
  rw [sub_neg_eq_add, sub_neg_eq_add]
  generalize h_aa : 1 - y₁ = a at h_m₁ ⊢
  generalize h_nn : 1 + y₁ = n at h_n₁ ⊢
  have h_w : y₁ + y₁ ≠ 0 := by
    rw [← two_mul]; exact mul_ne_zero h_two h_y₁
  generalize h_ww : y₁ + y₁ = w at h_w ⊢
  field_simp
  linear_combination (2 * n * (d + 1)) * h_ww + (-n * (d + 1) * (y₁ - 1)) * h_aa + (-n * (d + 1) *
    (n + y₁ + 1)) * h_nn

/-- Twice the image of a point with y zero is (0, 0). -/
theorem tangent_zero (h_x : x₁ ^ 2 = -1) :
    (mont d).addX (monX d 0) (monX d 0) (x₁ * (2 * d * 0 ^ 2 + (1 + d) * 0 + 2) / ((1 - 0) * (1 + 0))) = 0 ∧
      (mont d).addY (monX d 0) (monX d 0) (monY d x₁ 0)
        (x₁ * (2 * d * 0 ^ 2 + (1 + d) * 0 + 2) / ((1 - 0) * (1 + 0))) = 0 := by
  have h_x₁ : x₁ ≠ 0 := by
    rintro rfl
    have : (1 : F) = 0 := by linear_combination h_x
    exact one_ne_zero this
  have h_addX : (mont d).addX (monX d 0) (monX d 0)
      (x₁ * (2 * d * 0 ^ 2 + (1 + d) * 0 + 2) / ((1 - 0) * (1 + 0))) = 0 := by
    simp only [WeierstrassCurve.Affine.addX, mont, monX]
    linear_combination 4 * h_x
  refine ⟨h_addX, ?_⟩
  simp only [WeierstrassCurve.Affine.addY, WeierstrassCurve.Affine.negAddY,
    WeierstrassCurve.Affine.negY]
  rw [h_addX]
  simp only [mont, monX, monY]
  field_simp
  linear_combination (-2 * (1 + d)) * h_x

/-- A sum that is the identity is a point and its negative: the addition law has unique
inverses on the curve when d is not a square and -1 is. -/
theorem neg_of_sum_zero (h_d : ¬IsSquare d) (h_i : IsSquare (-1 : F))
    (h₁ : OnCurve d x₁ y₁) (h₂ : OnCurve d x₂ y₂) (h_x : x₁ * y₂ + y₁ * x₂ = 0)
    (h_y : y₁ * y₂ + x₁ * x₂ = 1 - d * x₁ * x₂ * y₁ * y₂) : x₂ = -x₁ ∧ y₂ = y₁ := by
  unfold OnCurve at h₁ h₂
  have key₁ : (y₂ - y₁) * (1 - d * x₁ ^ 2 * y₁ * y₂) = 0 := by
    linear_combination y₁ * h_y - y₂ * h₁ - (x₁ + d * x₁ * y₁ * y₂) * h_x
  have key₂ : (y₁ - y₂) * (1 - d * x₂ ^ 2 * y₁ * y₂) = 0 := by
    linear_combination y₂ * h_y - y₁ * h₂ - (x₂ + d * x₂ * y₁ * y₂) * h_x
  have h_eq : y₂ = y₁ := by
    by_contra h_ne
    have h_ne₁ : y₂ - y₁ ≠ 0 := sub_ne_zero.mpr h_ne
    have h_ne₂ : y₁ - y₂ ≠ 0 := sub_ne_zero.mpr (Ne.symm h_ne)
    have h_one₁ : d * x₁ ^ 2 * y₁ * y₂ = 1 := by
      linear_combination -((mul_eq_zero.mp key₁).resolve_left h_ne₁)
    have h_one₂ : d * x₂ ^ 2 * y₁ * y₂ = 1 := by
      linear_combination -((mul_eq_zero.mp key₂).resolve_left h_ne₂)
    have h_x₁ : x₁ ≠ 0 := by rintro rfl; simp at h_one₁
    have h_dy : d * y₁ * y₂ ≠ 0 := by
      intro h_zero
      have : (1 : F) = 0 := by linear_combination -h_one₁ + x₁ ^ 2 * h_zero
      exact one_ne_zero this
    have h_sq : x₁ ^ 2 = x₂ ^ 2 := by
      have : d * y₁ * y₂ * (x₁ ^ 2 - x₂ ^ 2) = 0 := by linear_combination h_one₁ - h_one₂
      linear_combination (mul_eq_zero.mp this).resolve_left h_dy
    have h_ysq : x₁ ^ 2 * ((y₂ - y₁) * (y₂ + y₁)) = 0 := by
      linear_combination (x₁ * y₂ - y₁ * x₂) * h_x - y₁ ^ 2 * h_sq
    have h_neg : y₂ = -y₁ := by
      have := ((mul_eq_zero.mp h_ysq).resolve_left (pow_ne_zero 2 h_x₁))
      linear_combination (mul_eq_zero.mp this).resolve_left h_ne₁
    obtain ⟨i, h_i⟩ := h_i
    have h_y₁ : y₁ ≠ 0 := by rintro rfl; simp at h_one₁
    apply h_d
    refine ⟨i / (x₁ * y₁), ?_⟩
    rw [div_mul_div_comm, eq_div_iff (mul_ne_zero (mul_ne_zero h_x₁ h_y₁) (mul_ne_zero h_x₁ h_y₁))]
    rw [h_neg] at h_one₁
    linear_combination -h_one₁ + h_i
  subst h_eq
  refine ⟨?_, rfl⟩
  have h_factor : y₂ * (x₁ + x₂) = 0 := by linear_combination h_x
  rcases mul_eq_zero.mp h_factor with h_zero | h_sum
  · subst h_zero
    linear_combination -x₁ * h_y - x₂ * h₁
  · linear_combination h_sum

end Identities

variable [DecidableEq F]

/-- Mathlib's slope of a doubling, in the point's coordinates. -/
theorem mont_slope_tangent {d x₁ y₁ : F} (h_two : (2 : F) ≠ 0) (h_k : 1 + d ≠ 0) (h_x₁ : x₁ ≠ 0)
    (h_m₁ : 1 - y₁ ≠ 0) (h_n₁ : 1 + y₁ ≠ 0)
    (h_Y : monY d x₁ y₁ ≠ (mont d).negY (monX d y₁) (monY d x₁ y₁)) :
    (mont d).slope (monX d y₁) (monX d y₁) (monY d x₁ y₁) (monY d x₁ y₁) =
      x₁ * (2 * d * y₁ ^ 2 + (1 + d) * y₁ + 2) / ((1 - y₁) * (1 + y₁)) := by
  rw [WeierstrassCurve.Affine.slope_of_Y_ne rfl h_Y]
  exact slope_tangent h_two h_k h_x₁ h_m₁ h_n₁

/-- Mathlib's slope of a chord, in the points' coordinates. -/
theorem mont_slope_chord {d x₁ y₁ x₂ y₂ : F} (h_two : (2 : F) ≠ 0) (h_k : 1 + d ≠ 0)
    (h_x₁ : x₁ ≠ 0) (h_x₂ : x₂ ≠ 0) (h_m₁ : 1 - y₁ ≠ 0) (h_m₂ : 1 - y₂ ≠ 0) (h_w : y₁ - y₂ ≠ 0)
    (h_X : monX d y₁ ≠ monX d y₂) :
    (mont d).slope (monX d y₁) (monX d y₂) (monY d x₁ y₁) (monY d x₂ y₂) =
      ((1 + y₂) * (1 - y₁) * x₁ - (1 + y₁) * (1 - y₂) * x₂) / ((y₁ - y₂) * x₁ * x₂) := by
  rw [WeierstrassCurve.Affine.slope_of_X_ne h_X]
  exact slope_chord h_two h_k h_x₁ h_x₂ h_m₁ h_m₂ h_w

section Hom

variable {c : Params F}

omit [DecidableEq F] in
/-- `toMont` of a point with x not zero. -/
theorem toMont_generic {P : EdPoint c} (h_x : P.x ≠ 0) :
    toMont P = .some (monX c.d P.y) (monY c.d P.x P.y) (nonsingular_mon P h_x) := by
  simp only [toMont, dif_neg h_x]

omit [DecidableEq F] in
/-- `toMont` of the identity. -/
theorem toMont_identity {P : EdPoint c} (h_x : P.x = 0) (h_y : P.y = 1) : toMont P = 0 := by
  simp only [toMont, dif_pos h_x, if_pos h_y]

omit [DecidableEq F] in
/-- `toMont` of the point of order two. -/
theorem toMont_torsion {P : EdPoint c} (h_x : P.x = 0) (h_y : P.y = -1) :
    toMont P = .some 0 0 nonsingular_zero_zero := by
  have h_ne : P.y ≠ 1 := by
    rw [h_y]
    intro h
    exact c.two_ne_zero (by linear_combination -h)
  simp only [toMont, dif_pos h_x, if_neg h_ne]

omit [DecidableEq F] in
/-- The x of a sum. -/
theorem EdPoint.add_x (P Q : EdPoint c) :
    (P.add Q).x = (P.x * Q.y + P.y * Q.x) / (1 + c.d * P.x * Q.x * P.y * Q.y) := rfl

omit [DecidableEq F] in
/-- The y of a sum. -/
theorem EdPoint.add_y (P Q : EdPoint c) :
    (P.add Q).y = (P.y * Q.y + P.x * Q.x) / (1 - c.d * P.x * Q.x * P.y * Q.y) := rfl

omit [DecidableEq F] in
/-- The addition law is symmetric. -/
theorem EdPoint.add_comm (P Q : EdPoint c) : P.add Q = Q.add P := by
  ext
  · rw [EdPoint.add_x, EdPoint.add_x]
    ring_nf
  · rw [EdPoint.add_y, EdPoint.add_y]
    ring_nf

omit [DecidableEq F] in
/-- The identity adds nothing. -/
theorem EdPoint.identity_add {P : EdPoint c} (h_x : P.x = 0) (h_y : P.y = 1) (Q : EdPoint c) :
    P.add Q = Q := by
  ext
  · rw [EdPoint.add_x, h_x, h_y]
    simp
  · rw [EdPoint.add_y, h_x, h_y]
    simp

/-- `toMont_add` when the first point is the identity. -/
theorem toMont_identity_add {P : EdPoint c} (h_x : P.x = 0) (h_y : P.y = 1) (Q : EdPoint c) :
    toMont (P.add Q) = toMont P + toMont Q := by
  rw [EdPoint.identity_add h_x h_y, toMont_identity h_x h_y, zero_add]

omit [DecidableEq F] in
/-- The image of a point with x not zero is not (0, 0). -/
theorem monX_ne_zero {d y : F} (h_k : 1 + d ≠ 0) (h_m : 1 - y ≠ 0) (h_n : 1 + y ≠ 0) :
    monX d y ≠ 0 :=
  div_ne_zero (mul_ne_zero (neg_ne_zero.mpr h_k) h_n) h_m

/-- `toMont_add` when the first point is the point of order two. -/
theorem toMont_torsion_add {P : EdPoint c} (h_x : P.x = 0) (h_y : P.y = -1) (Q : EdPoint c) :
    toMont (P.add Q) = toMont P + toMont Q := by
  have h_sx : (P.add Q).x = -Q.x := by
    rw [EdPoint.add_x, h_x, h_y]
    simp
  have h_sy : (P.add Q).y = -Q.y := by
    rw [EdPoint.add_y, h_x, h_y]
    simp
  rw [toMont_torsion h_x h_y]
  by_cases h_qx : Q.x = 0
  · rcases Q.y_eq_of_x_eq_zero h_qx with h_qy | h_qy
    · rw [toMont_identity h_qx h_qy, add_zero]
      exact toMont_torsion (by rw [h_sx, h_qx, neg_zero]) (by rw [h_sy, h_qy])
    · rw [toMont_torsion h_qx h_qy,
        toMont_identity (by rw [h_sx, h_qx, neg_zero]) (by rw [h_sy, h_qy, neg_neg])]
      exact (WeierstrassCurve.Affine.Point.add_of_Y_eq rfl
        (by simp [WeierstrassCurve.Affine.negY, mont])).symm
  · have h_m : 1 - Q.y ≠ 0 := sub_ne_zero.mpr (EdPoint.y_ne_one h_qx).symm
    have h_n : 1 + Q.y ≠ 0 := by
      intro h
      exact EdPoint.y_ne_neg_one h_qx (by linear_combination h)
    have h_sx' : (P.add Q).x ≠ 0 := by
      rw [h_sx]
      exact neg_ne_zero.mpr h_qx
    have h_X : (0 : F) ≠ monX c.d Q.y := (monX_ne_zero c.one_add_d_ne_zero h_m h_n).symm
    rw [toMont_generic h_sx', toMont_generic h_qx,
      WeierstrassCurve.Affine.Point.add_of_X_ne h_X, WeierstrassCurve.Affine.Point.some.injEq,
      WeierstrassCurve.Affine.slope_of_X_ne h_X,
      slope_two_torsion c.one_add_d_ne_zero h_qx h_m h_n]
    simp only [h_sx, h_sy]
    exact ⟨two_torsion_x h_qx h_m h_n Q.on_curve,
      two_torsion_y h_qx h_m h_n Q.on_curve⟩

omit [DecidableEq F] in
/-- Two images with the same x come from points with the same y. -/
theorem monX_inj {d y₁ y₂ : F} (h_two : (2 : F) ≠ 0) (h_k : 1 + d ≠ 0) (h_m₁ : 1 - y₁ ≠ 0)
    (h_m₂ : 1 - y₂ ≠ 0) (h : monX d y₁ = monX d y₂) : y₁ = y₂ := by
  simp only [monX] at h
  rw [div_eq_div_iff h_m₁ h_m₂] at h
  have : (2 * (1 + d)) * (y₁ - y₂) = 0 := by linear_combination -h
  linear_combination (mul_eq_zero.mp this).resolve_left (mul_ne_zero h_two h_k)

omit [DecidableEq F] in
/-- Two points with the same y have x equal up to sign. -/
theorem x_sq_eq {P Q : EdPoint c} (h_y : P.y = Q.y) : P.x ^ 2 = Q.x ^ 2 := by
  have h₁ := P.on_curve
  have h₂ := Q.on_curve
  unfold OnCurve at h₁ h₂
  rw [h_y] at h₁
  have : (1 + c.d * Q.y ^ 2) * (P.x ^ 2 - Q.x ^ 2) = 0 := by linear_combination -h₁ + h₂
  linear_combination (mul_eq_zero.mp this).resolve_left (c.one_add_d_mul_sq_ne_zero Q.y)

/-- `toMont_add` for two points whose x is not zero. -/
theorem toMont_generic_add {P Q : EdPoint c} (h_px : P.x ≠ 0) (h_qx : Q.x ≠ 0) :
    toMont (P.add Q) = toMont P + toMont Q := by
  obtain ⟨h_plus, h_minus⟩ := denominators_ne_zero P Q
  have h_two := c.two_ne_zero
  have h_d := c.d_ne_zero
  have h_k := c.one_add_d_ne_zero
  have h_m₁ : 1 - P.y ≠ 0 := sub_ne_zero.mpr (EdPoint.y_ne_one h_px).symm
  have h_m₂ : 1 - Q.y ≠ 0 := sub_ne_zero.mpr (EdPoint.y_ne_one h_qx).symm
  have h_n₁ : 1 + P.y ≠ 0 := by
    intro h
    exact EdPoint.y_ne_neg_one h_px (by linear_combination h)
  have h_n₂ : 1 + Q.y ≠ 0 := by
    intro h
    exact EdPoint.y_ne_neg_one h_qx (by linear_combination h)
  have h_c₁ := P.on_curve
  have h_c₂ := Q.on_curve
  rw [toMont_generic h_px, toMont_generic h_qx]
  by_cases h_X : monX c.d P.y = monX c.d Q.y
  · have h_y : P.y = Q.y := monX_inj h_two h_k h_m₁ h_m₂ h_X
    by_cases h_Y : monY c.d P.x P.y = (mont c.d).negY (monX c.d Q.y) (monY c.d Q.x Q.y)
    · -- A point and its negative: the sum is the identity.
      have h_x : Q.x = -P.x := by
        simp only [WeierstrassCurve.Affine.negY, mont, monY] at h_Y
        rw [h_y] at h_Y
        field_simp at h_Y
        have : (2 * (1 + c.d) * (1 + Q.y)) * (Q.x + P.x) = 0 := by linear_combination h_Y
        linear_combination (mul_eq_zero.mp this).resolve_left
          (mul_ne_zero (mul_ne_zero h_two h_k) (h_y ▸ h_n₁))
      rw [WeierstrassCurve.Affine.Point.add_of_Y_eq h_X h_Y]
      refine toMont_identity ?_ ?_
      · rw [EdPoint.add_x, h_x, ← h_y, show P.x * P.y + P.y * -P.x = 0 by ring, zero_div]
      · rw [h_x, ← h_y] at h_minus
        rw [EdPoint.add_y, h_x, ← h_y, div_eq_one_iff_eq h_minus]
        unfold OnCurve at h_c₁
        linear_combination h_c₁
    · -- The same point twice.
      have h_x : P.x = Q.x := by
        have h_sq := x_sq_eq h_y
        have : (P.x - Q.x) * (P.x + Q.x) = 0 := by linear_combination h_sq
        rcases mul_eq_zero.mp this with h | h
        · linear_combination h
        · exfalso
          apply h_Y
          have h_q : Q.x = -P.x := by linear_combination h
          simp only [WeierstrassCurve.Affine.negY, mont, monY]
          rw [h_q, ← h_y]
          field_simp
          ring
      have h_eq : P = Q := EdPoint.ext h_x h_y
      subst h_eq
      rw [WeierstrassCurve.Affine.Point.add_self_of_Y_ne h_Y]
      by_cases h_y0 : P.y = 0
      · -- Twice a point whose y is zero is the point of order two.
        have h_xsq : P.x ^ 2 = -1 := by
          unfold OnCurve at h_c₁
          rw [h_y0] at h_c₁
          linear_combination -h_c₁
        have h_sx : (P.add P).x = 0 := by
          rw [EdPoint.add_x, h_y0]
          simp
        have h_sy : (P.add P).y = -1 := by
          rw [EdPoint.add_y, h_y0]
          simp only [mul_zero, sub_zero, zero_add, div_one]
          linear_combination h_xsq
        rw [toMont_torsion h_sx h_sy, WeierstrassCurve.Affine.Point.some.injEq,
          mont_slope_tangent h_two h_k h_px h_m₁ h_n₁ h_Y, h_y0]
        obtain ⟨h_a, h_b⟩ := tangent_zero h_xsq
        exact ⟨h_a.symm, h_b.symm⟩
      · have h_u : P.x * P.y + P.y * P.x ≠ 0 := by
          rw [show P.x * P.y + P.y * P.x = 2 * (P.x * P.y) by ring]
          exact mul_ne_zero h_two (mul_ne_zero h_px h_y0)
        have h_sx : (P.add P).x ≠ 0 := by
          rw [EdPoint.add_x]
          exact div_ne_zero h_u h_plus
        have h_e : (1 - c.d * P.x * P.x * P.y * P.y) - (P.y * P.y + P.x * P.x) ≠ 0 := by
          have h_ne := EdPoint.y_ne_one h_sx
          rw [EdPoint.add_y] at h_ne
          intro h
          apply h_ne
          rw [div_eq_one_iff_eq h_minus]
          linear_combination -h
        rw [toMont_generic h_sx, WeierstrassCurve.Affine.Point.some.injEq,
          mont_slope_tangent h_two h_k h_px h_m₁ h_n₁ h_Y, EdPoint.add_x,
          EdPoint.add_y, monX_frac h_minus h_e, monY_frac h_minus h_e h_plus h_u]
        exact ⟨tangent_x h_m₁ h_n₁ P.on_curve h_e,
          tangent_y h_px h_m₁ h_n₁ P.on_curve h_e h_u⟩
  · -- Two points with different x on the Montgomery curve.
    have h_w : P.y - Q.y ≠ 0 := by
      intro h
      apply h_X
      rw [show P.y = Q.y by linear_combination h]
    rw [WeierstrassCurve.Affine.Point.add_of_X_ne h_X]
    by_cases h_u : P.x * Q.y + P.y * Q.x = 0
    · -- The sum is the point of order two, and Q is (x₁, -y₁).
      have h_sx : (P.add Q).x = 0 := by rw [EdPoint.add_x, h_u, zero_div]
      have h_sy : (P.add Q).y = -1 := by
        rcases (P.add Q).y_eq_of_x_eq_zero h_sx with h | h
        · exfalso
          rw [EdPoint.add_y, div_eq_one_iff_eq h_minus] at h
          obtain ⟨-, h_yy⟩ := neg_of_sum_zero c.d_not_square c.neg_one_square P.on_curve
            Q.on_curve h_u h
          exact h_w (by rw [h_yy]; ring)
        · exact h
      have h_mirror : OnCurve c.d (-Q.x) (-Q.y) := by
        unfold OnCurve at h_c₂ ⊢
        linear_combination h_c₂
      have h_sy' := h_sy
      rw [EdPoint.add_y, div_eq_iff h_minus] at h_sy'
      obtain ⟨h_qx', h_qy'⟩ := neg_of_sum_zero c.d_not_square c.neg_one_square P.on_curve
        h_mirror (by linear_combination -h_u) (by linear_combination -h_sy')
      have h_qx2 : Q.x = P.x := by linear_combination -h_qx'
      have h_qy2 : Q.y = -P.y := by linear_combination -h_qy'
      have h_y₁ : P.y ≠ 0 := by
        intro h
        apply h_w
        rw [h_qy2, h]
        ring
      rw [toMont_torsion h_sx h_sy, WeierstrassCurve.Affine.Point.some.injEq,
        mont_slope_chord h_two h_k h_px h_qx h_m₁ h_m₂ h_w h_X, h_qx2, h_qy2]
      exact ⟨(chord_zero_x h_two h_px h_m₁ h_n₁ h_y₁ P.on_curve).symm,
        (chord_zero_y h_two h_px h_m₁ h_n₁ h_y₁ P.on_curve).symm⟩
    · have h_sx : (P.add Q).x ≠ 0 := by
        rw [EdPoint.add_x]
        exact div_ne_zero h_u h_plus
      have h_e : (1 - c.d * P.x * Q.x * P.y * Q.y) - (P.y * Q.y + P.x * Q.x) ≠ 0 := by
        have h_ne := EdPoint.y_ne_one h_sx
        rw [EdPoint.add_y] at h_ne
        intro h
        apply h_ne
        rw [div_eq_one_iff_eq h_minus]
        linear_combination -h
      rw [toMont_generic h_sx, WeierstrassCurve.Affine.Point.some.injEq,
        mont_slope_chord h_two h_k h_px h_qx h_m₁ h_m₂ h_w h_X, EdPoint.add_x,
        EdPoint.add_y, monX_frac h_minus h_e, monY_frac h_minus h_e h_plus h_u]
      exact ⟨chord_x h_d h_px h_qx h_m₁ h_m₂ h_w P.on_curve Q.on_curve h_e,
        chord_y h_d h_px h_qx h_m₁ h_m₂ h_w P.on_curve Q.on_curve h_e h_u⟩

/-- The map to the Montgomery curve takes the sum of two points of edwards25519 to the sum of
their images. -/
theorem toMont_add (P Q : EdPoint c) : toMont (P.add Q) = toMont P + toMont Q := by
  by_cases h_px : P.x = 0
  · rcases P.y_eq_of_x_eq_zero h_px with h_py | h_py
    · exact toMont_identity_add h_px h_py Q
    · exact toMont_torsion_add h_px h_py Q
  · by_cases h_qx : Q.x = 0
    · rcases Q.y_eq_of_x_eq_zero h_qx with h_qy | h_qy
      · rw [EdPoint.add_comm, toMont_identity_add h_qx h_qy, add_comm]
      · rw [EdPoint.add_comm, toMont_torsion_add h_qx h_qy, add_comm]
    · exact toMont_generic_add h_px h_qx

end Hom

section Multiples

variable {c : Params F}

/-- The identity of edwards25519, (0, 1). -/
def EdPoint.identity : EdPoint c := ⟨0, 1, by unfold OnCurve; ring⟩

/-- The negative of a point, (-x, y). -/
def EdPoint.neg (P : EdPoint c) : EdPoint c :=
  ⟨-P.x, P.y, by have h := P.on_curve; unfold OnCurve at h ⊢; linear_combination h⟩

/-- `n` times `P`, by `n` additions. -/
def EdPoint.nsmul : ℕ → EdPoint c → EdPoint c
  | 0, _ => EdPoint.identity
  | n + 1, P => P.add (EdPoint.nsmul n P)

/-- `k` times `P` for an integer `k`: the negative of `-k` times `P` when `k` is negative. -/
def EdPoint.zsmul (k : ℤ) (P : EdPoint c) : EdPoint c :=
  if 0 ≤ k then EdPoint.nsmul k.toNat P else (EdPoint.nsmul (-k).toNat P).neg

omit [DecidableEq F] in
/-- `toMont` of `EdPoint.identity`. -/
theorem toMont_identity' : toMont (EdPoint.identity : EdPoint c) = 0 :=
  toMont_identity rfl rfl

/-- The map takes a negative to the negative. -/
theorem toMont_neg (P : EdPoint c) : toMont P.neg = -toMont P := by
  by_cases h_x : P.x = 0
  · have h_nx : P.neg.x = 0 := by simp [EdPoint.neg, h_x]
    rcases P.y_eq_of_x_eq_zero h_x with h_y | h_y
    · rw [toMont_identity h_nx h_y, toMont_identity h_x h_y, neg_zero]
    · rw [toMont_torsion h_nx h_y, toMont_torsion h_x h_y, WeierstrassCurve.Affine.Point.neg_some]
      simp [WeierstrassCurve.Affine.negY, mont]
  · have h_nx : P.neg.x ≠ 0 := by simp [EdPoint.neg, h_x]
    rw [toMont_generic h_nx, toMont_generic h_x, WeierstrassCurve.Affine.Point.neg_some,
      WeierstrassCurve.Affine.Point.some.injEq]
    refine ⟨rfl, ?_⟩
    simp only [EdPoint.neg, WeierstrassCurve.Affine.negY, mont, monY]
    rw [mul_neg, div_neg]
    ring

/-- The map takes n times a point to n times its image. -/
theorem toMont_nsmul (n : ℕ) (P : EdPoint c) : toMont (EdPoint.nsmul n P) = n • toMont P := by
  induction n with
  | zero => rw [EdPoint.nsmul, toMont_identity', zero_smul]
  | succ n ih => rw [EdPoint.nsmul, toMont_add, ih, succ_nsmul, add_comm]

/-- The map takes k times a point to k times its image, for an integer k. -/
theorem toMont_zsmul (k : ℤ) (P : EdPoint c) : toMont (EdPoint.zsmul k P) = k • toMont P := by
  unfold EdPoint.zsmul
  split_ifs with h_k
  · rw [toMont_nsmul, ← natCast_zsmul, Int.toNat_of_nonneg h_k]
  · rw [toMont_neg, toMont_nsmul, ← natCast_zsmul, Int.toNat_of_nonneg (by omega), ← neg_zsmul,
      neg_neg]

end Multiples

section BaseMul

variable {c : Params F}

/-- The entry of row `i` for a digit `k`: `k` times `256 ^ i` times `B`. -/
def entry (B : EdPoint c) (i : ℕ) (k : ℤ) : EdPoint c :=
  EdPoint.zsmul k (EdPoint.nsmul (256 ^ i) B)

/-- The loop over the rows: `start` plus the entries of digits `parity`, `2 + parity`, ...,
`2 (n - 1) + parity`, in that order. -/
def addRows (B : EdPoint c) (e : ℕ → ℤ) (parity : ℕ) (start : EdPoint c) : ℕ → EdPoint c
  | 0 => start
  | n + 1 => (addRows B e parity start n).add (entry B n (e (2 * n + parity)))

/-- Four doublings. -/
def doubleFour (P : EdPoint c) : EdPoint c :=
  let P := P.add P
  let P := P.add P
  let P := P.add P
  P.add P

/-- `x25519_wide_base_mul` over the points of the curve: the entries of the 32 odd digits, four
doublings, and the entries of the 32 even digits. -/
def baseMul (B : EdPoint c) (e : ℕ → ℤ) : EdPoint c :=
  addRows B e 0 (doubleFour (addRows B e 1 EdPoint.identity 32)) 32

/-- The image of the loop over the rows. -/
theorem toMont_addRows (B : EdPoint c) (e : ℕ → ℤ) (parity : ℕ) (start : EdPoint c) (n : ℕ) :
    toMont (addRows B e parity start n) =
      toMont start + (∑ i ∈ Finset.range n, e (2 * i + parity) * 256 ^ i) • toMont B := by
  induction n with
  | zero => simp [addRows]
  | succ n ih =>
    rw [addRows, toMont_add, ih, Finset.sum_range_succ, add_smul, add_assoc, entry, toMont_zsmul,
      toMont_nsmul, ← natCast_zsmul, smul_smul]
    push_cast
    rfl

/-- Four doublings are 16 times the point. -/
theorem toMont_doubleFour (P : EdPoint c) : toMont (doubleFour P) = (16 : ℤ) • toMont P := by
  simp only [doubleFour, toMont_add]
  abel

/-- The digits taken by parity, as the two loops take them. -/
theorem sum_digits (e : ℕ → ℤ) (n : ℕ) :
    ∑ j ∈ Finset.range (2 * n), e j * 16 ^ j =
      ∑ i ∈ Finset.range n, e (2 * i + 0) * 256 ^ i +
        16 * ∑ i ∈ Finset.range n, e (2 * i + 1) * 256 ^ i := by
  induction n with
  | zero => simp
  | succ n ih =>
    rw [show 2 * (n + 1) = 2 * n + 1 + 1 by ring, Finset.sum_range_succ, Finset.sum_range_succ, ih,
      Finset.sum_range_succ, Finset.sum_range_succ]
    rw [show (256 : ℤ) ^ n = 16 ^ (2 * n) by rw [pow_mul]; norm_num]
    ring_nf

/-- The map takes `baseMul B e` to the sum of the digits times the image of `B`. -/
theorem toMont_baseMul (B : EdPoint c) (e : ℕ → ℤ) :
    toMont (baseMul B e) = (∑ j ∈ Finset.range 64, e j * 16 ^ j) • toMont B := by
  rw [baseMul, toMont_addRows, toMont_doubleFour, toMont_addRows, toMont_identity', zero_add,
    smul_smul, ← add_smul, show 64 = 2 * 32 by rfl, sum_digits]
  ring_nf

end BaseMul

section Chain

variable {c : Params F}


/-- The u of a point of the Montgomery curve: `-X / (1 + d)` in the model `mont d`, whose `X` is
`-(1 + d) u`. The identity has no u, and gets 0. -/
def montU (d : F) : (mont d).Point → F
  | .zero => 0
  | .some x _ _ => -x / (1 + d)

omit [DecidableEq F] in
/-- The extended point `(0 : 1 : 1 : 0)` holds the identity. -/
theorem identity_represents : Represents (⟨0, 1, 1, 0⟩ : Extended F) (0, 1) := by
  refine ⟨one_ne_zero, ?_, ?_, ?_⟩ <;> simp

omit [DecidableEq F] in
/-- An addition of an entry takes a point to its sum with the entry's point, for every two points
of the curve. -/
theorem addEntry_represents_add (P Q : EdPoint c) {a : Extended F}
    (h : Represents a (P.x, P.y)) :
    Represents (toExtended (addEntry a (entryOf c.d Q.x Q.y))) ((P.add Q).x, (P.add Q).y) := by
  obtain ⟨h_plus, h_minus⟩ := denominators_ne_zero P Q
  exact addEntry_represents (d := c.d) (p := (P.x, P.y)) (q := (Q.x, Q.y)) c.two_ne_zero h h_plus
    h_minus

omit [DecidableEq F] in
/-- A doubling takes a point to its sum with itself, for every point of the curve. -/
theorem doublePoint_represents_add (P : EdPoint c) {a : Extended F}
    (h : Represents a (P.x, P.y)) :
    Represents (toExtended (doublePoint a)) ((P.add P).x, (P.add P).y) := by
  obtain ⟨h_plus, h_minus⟩ := denominators_ne_zero P P
  exact doublePoint_represents (d := c.d) (p := (P.x, P.y)) h P.on_curve h_plus h_minus

/-- `x25519_wide_base_mul` in extended coordinates: each step adds the entry of the digit's point,
with `y + x`, `y - x` and `2 d x y` as `entryOf` writes them, or doubles. -/
def addRowsExtended (B : EdPoint c) (e : ℕ → ℤ) (parity : ℕ) (start : Extended F) :
    ℕ → Extended F
  | 0 => start
  | n + 1 =>
    toExtended (addEntry (addRowsExtended B e parity start n)
      (entryOf c.d (entry B n (e (2 * n + parity))).x (entry B n (e (2 * n + parity))).y))

/-- Four doublings in extended coordinates. -/
def doubleFourExtended (a : Extended F) : Extended F :=
  let a := toExtended (doublePoint a)
  let a := toExtended (doublePoint a)
  let a := toExtended (doublePoint a)
  toExtended (doublePoint a)

/-- The whole of `x25519_wide_base_mul` before its last step, in extended coordinates. -/
def baseMulExtended (B : EdPoint c) (e : ℕ → ℤ) : Extended F :=
  addRowsExtended B e 0 (doubleFourExtended (addRowsExtended B e 1 ⟨0, 1, 1, 0⟩ 32)) 32

omit [DecidableEq F] in
/-- The loop over the rows in extended coordinates holds the loop over points. -/
theorem addRowsExtended_represents (B : EdPoint c) (e : ℕ → ℤ) (parity : ℕ)
    {start : Extended F} {P : EdPoint c} (h : Represents start (P.x, P.y)) (n : ℕ) :
    Represents (addRowsExtended B e parity start n)
      ((addRows B e parity P n).x, (addRows B e parity P n).y) := by
  induction n with
  | zero => exact h
  | succ n ih => exact addEntry_represents_add _ _ ih

omit [DecidableEq F] in
/-- Four doublings in extended coordinates hold four doublings of points. -/
theorem doubleFourExtended_represents {a : Extended F} {P : EdPoint c}
    (h : Represents a (P.x, P.y)) :
    Represents (doubleFourExtended a) ((doubleFour P).x, (doubleFour P).y) :=
  doublePoint_represents_add _ (doublePoint_represents_add _ (doublePoint_represents_add _
    (doublePoint_represents_add _ h)))

omit [DecidableEq F] in
/-- `baseMulExtended` holds `baseMul`'s point. -/
theorem baseMulExtended_represents (B : EdPoint c) (e : ℕ → ℤ) :
    Represents (baseMulExtended B e) ((baseMul B e).x, (baseMul B e).y) :=
  addRowsExtended_represents B e 0
    (doubleFourExtended_represents (addRowsExtended_represents B e 1 identity_represents 32)) 32

/-- The u that `x25519_wide_base_mul`'s model writes is the u of the sum of its digits times the
image of `B` on the Montgomery curve, for every digits whose sum is not the identity or the
point of order two. -/
theorem toU_baseMulExtended (B : EdPoint c) (e : ℕ → ℤ) (h_x : (baseMul B e).x ≠ 0) :
    toU (baseMulExtended B e) =
      montU c.d ((∑ j ∈ Finset.range 64, e j * 16 ^ j) • toMont B) := by
  rw [← toMont_baseMul, toMont_generic h_x, montU]
  obtain ⟨h_z, -, h_y, -⟩ := baseMulExtended_represents B e
  have h_m : 1 - (baseMul B e).y ≠ 0 := sub_ne_zero.mpr (EdPoint.y_ne_one h_x).symm
  have h_k := c.one_add_d_ne_zero
  simp only [toU, monX, ← div_eq_mul_inv] at h_y ⊢
  rw [h_y]
  rw [div_eq_div_iff (by rw [← one_sub_mul]; exact mul_ne_zero h_m h_z) h_k]
  field_simp

end Chain

end Group

section Selftest

/-- The field prime of RFC 7748 section 4.1, 2^255 - 19. -/
def p : ℕ := 2 ^ 255 - 19

set_option compiler.extract_closed false in
/-- The formulas on edwards25519 over `ZMod p`, RFC 7748 section 4.1's d and base point B, whose
y is 4/5: one addition of B's entry to the identity has u 9, the u of curve25519's base point; a
second addition and a doubling of B both give 2 B, whose u is not 9; and 2 B plus the negated
entry of B is B again. -/
def selftest (_ : Unit) : Bool :=
  let d : ZMod p := -121665 * 121666⁻¹
  let x : ZMod p := 15112221349535400772501151409588531511454012693041857206046113283949847762202
  let y : ZMod p := 4 * 5⁻¹
  let b := entryOf d x y
  let one := toExtended (addEntry ⟨0, 1, 1, 0⟩ b)
  let two := toExtended (addEntry one b)
  let twice := toExtended (doublePoint one)
  let back := toExtended (addEntry two (negate b))
  toU one == 9 && toU two == toU twice && toU two != 9 && toU back == 9

end Selftest

end Spec.X25519Edwards
