import Spec.X25519Base
import Spec.X25519

/-!
# The RFC 7748 ladder computes s times the point with u 9

`Spec.X25519.ladder` is the Montgomery ladder of RFC 7748 section 5 over `Nat`. This module
proves that on u = 9 it returns the u of k times the image of edwards25519's base point B on the
Montgomery curve `mont d` of `Spec.X25519Edwards`, for every k below 2^255.

The first part works over every field in which 2 is not zero, d is not a square and -1 is.
`XRep c X Z P` says that the pair `(X : Z)` holds the u of the point P: Z is zero and X is not
for the identity, and X = u Z with Z not zero for every other point.

* `doubleRep` proves that `doubleX` and `doubleZ`, the ladder's formulas for `x_2` and `z_2`,
  hold the u of P + P, for every point P, with a24 (1 + d) = -d.
* `addRep` proves that `differentialAddX` and `differentialAddZ`, the formulas for `x_3` and
  `z_3`, hold the u of P + Q when `(x1 : 1)` holds the u of Q - P, for every P and Q, x1 not
  zero.
* `ringLadder` proves that the ladder over the field, `ringLoop` from `(1 : 0)` and `(x1 : 1)`
  and the final swap, ends with x_2 z_2^-1 the u of k B. `Invariant` is the property each
  iteration keeps: the pair holds n B and (n + 1) B, in the order `swap` names, for the bits of
  k above the iteration's bit.

The second part casts the `Nat` ladder to `ZMod p`. `step_cast` and `loop_cast` prove that each
`Nat` iteration is the field iteration on the casts of its numbers, and `finv_cast` proves that
`finv` is the inverse, since p is prime (`Spec.Prime25519`).

The third part puts the two together over edwards25519's field. `ladder_nine` and
`ladder_nine_val` state the result, and `toU_keygen_eq_ladder` proves that the key generation of
`Spec.X25519Base` and the ladder write the same u for every clamped scalar.

This module is written from the specification of `Spec.X25519`, not from the C. The C is held to
that specification by bin/x25519_equiv_test and bin/diff_x25519_wide.
-/

namespace Spec.X25519Ladder

open Spec.X25519Edwards

section Field

variable {F : Type*} [Field F] [DecidableEq F] {c : Params F}

/-- `(X : Z)` holds the u of P: Z is zero and X is not for the identity, and X is u Z with Z not
zero for every other point. -/
def XRep (c : Params F) (X Z : F) : (mont c.d).Point → Prop
  | .zero => Z = 0 ∧ X ≠ 0
  | .some x _ _ => Z ≠ 0 ∧ X = -x / (1 + c.d) * Z

/-- The ladder's `x_2 = AA * BB` for the pair `(X : Z)`. -/
def doubleX {R : Type*} [CommRing R] (X Z : R) : R :=
  let a := X + Z
  let aa := a * a
  let b := X - Z
  let bb := b * b
  aa * bb

/-- The ladder's `z_2 = E * (AA + a24 * E)` for the pair `(X : Z)`. -/
def doubleZ {R : Type*} [CommRing R] (a24 X Z : R) : R :=
  let a := X + Z
  let aa := a * a
  let b := X - Z
  let bb := b * b
  let e := aa - bb
  e * (aa + a24 * e)

omit [DecidableEq F] in
/-- The curve equation of `mont d`: y² = x³ + 2 (d - 1) x² + (1 + d)² x. -/
theorem equation_mont {x y : F} (h : (mont c.d).Nonsingular x y) :
    y ^ 2 = x ^ 3 + 2 * (c.d - 1) * x ^ 2 + (1 + c.d) ^ 2 * x := by
  have h_eq := h.1
  rw [WeierstrassCurve.Affine.equation_iff] at h_eq
  simpa [mont] using h_eq

omit [DecidableEq F] in
/-- The negation of `mont d` changes the sign of y. -/
theorem negY_mont (x y : F) : (mont c.d).negY x y = -y := by
  simp [WeierstrassCurve.Affine.negY, mont]

/-- The doubling formulas hold the u of P + P, for every point P. -/
theorem doubleRep {a24 X Z : F} (h_a24 : a24 * (1 + c.d) = -c.d) {P : (mont c.d).Point}
    (h : XRep c X Z P) : XRep c (doubleX X Z) (doubleZ a24 X Z) (P + P) := by
  have h_k := c.one_add_d_ne_zero
  have h_d := c.d_ne_zero
  have h_two := c.two_ne_zero
  have h_a := eq_div_of_mul_eq h_k h_a24
  have h_four : (4 : F) ≠ 0 := by
    rw [show (4 : F) = 2 * 2 by norm_num]; exact mul_ne_zero h_two h_two
  match P, h with
  | .zero, ⟨h_z, h_x⟩ =>
    subst h_z
    refine ⟨by simp [doubleZ], ?_⟩
    simp only [doubleX, add_zero, sub_zero]
    exact mul_ne_zero (mul_ne_zero h_x h_x) (mul_ne_zero h_x h_x)
  | .some x y h_ns, ⟨h_z, h_x⟩ =>
    have h_curve := equation_mont h_ns
    have h_Z : doubleZ a24 X Z =
        -4 * Z ^ 4 * (x ^ 3 + 2 * (c.d - 1) * x ^ 2 + (1 + c.d) ^ 2 * x) / (1 + c.d) ^ 3 := by
      rw [h_x, h_a]
      simp only [doubleZ]
      field_simp
      ring
    by_cases h_y : y = 0
    · rw [WeierstrassCurve.Affine.Point.add_self_of_Y_eq (by rw [negY_mont, h_y, neg_zero])]
      have h_f : x ^ 3 + 2 * (c.d - 1) * x ^ 2 + (1 + c.d) ^ 2 * x = 0 := by
        rw [← h_curve, h_y]; ring
      refine ⟨by rw [h_Z, h_f]; ring, ?_⟩
      have h_X : doubleX X Z = (x ^ 2 - (1 + c.d) ^ 2) ^ 2 * Z ^ 4 / (1 + c.d) ^ 4 := by
        rw [h_x]
        simp only [doubleX]
        field_simp
        ring
      rw [h_X]
      refine div_ne_zero (mul_ne_zero (pow_ne_zero 2 ?_) (pow_ne_zero 4 h_z)) (pow_ne_zero 4 h_k)
      intro h_sq
      rcases sq_eq_sq_iff_eq_or_eq_neg.mp (sub_eq_zero.mp h_sq) with h_e | h_e
      · have h_0 : 4 * c.d * (1 + c.d) ^ 2 = 0 := by rw [← h_f, h_e]; ring
        exact mul_ne_zero (mul_ne_zero h_four h_d) (pow_ne_zero 2 h_k) h_0
      · have h_0 : -4 * (1 + c.d) ^ 2 = 0 := by rw [← h_f, h_e]; ring
        exact mul_ne_zero (neg_ne_zero.mpr h_four) (pow_ne_zero 2 h_k) h_0
    · have h_ne : y ≠ (mont c.d).negY x y := by
        rw [negY_mont]
        intro h'
        exact h_y ((mul_eq_zero.mp (by linear_combination h' : (2 : F) * y = 0)).resolve_left
          h_two)
      have h_f : x ^ 3 + 2 * (c.d - 1) * x ^ 2 + (1 + c.d) ^ 2 * x ≠ 0 := by
        rw [← h_curve]; exact pow_ne_zero 2 h_y
      have h_l : (mont c.d).slope x x y y ^ 2 =
          (3 * x ^ 2 + 4 * (c.d - 1) * x + (1 + c.d) ^ 2) ^ 2 /
            (4 * (x ^ 3 + 2 * (c.d - 1) * x ^ 2 + (1 + c.d) ^ 2 * x)) := by
        rw [WeierstrassCurve.Affine.slope_of_Y_ne rfl h_ne, negY_mont,
          show y - -y = 2 * y by ring, div_pow, mul_pow, h_curve]
        simp only [mont]
        ring
      rw [WeierstrassCurve.Affine.Point.add_self_of_Y_ne h_ne]
      refine ⟨?_, ?_⟩
      · rw [h_Z]
        exact div_ne_zero
          (mul_ne_zero (mul_ne_zero (neg_ne_zero.mpr h_four) (pow_ne_zero 4 h_z)) h_f)
          (pow_ne_zero 3 h_k)
      · rw [h_Z]
        simp only [WeierstrassCurve.Affine.addX]
        rw [h_l, h_x]
        simp only [mont, zero_mul, add_zero]
        simp only [doubleX]
        generalize h_F : x ^ 3 + 2 * (c.d - 1) * x ^ 2 + (1 + c.d) ^ 2 * x = f at h_f ⊢
        field_simp
        rw [← h_F]
        ring

/-- The ladder's `x_3 = (DA + CB)^2` for the pairs `(X2 : Z2)` and `(X3 : Z3)`. -/
def differentialAddX {R : Type*} [CommRing R] (X2 Z2 X3 Z3 : R) : R :=
  let a := X2 + Z2
  let bs := X2 - Z2
  let c := X3 + Z3
  let d := X3 - Z3
  let da := d * a
  let cb := c * bs
  let s := da + cb
  s * s

/-- The ladder's `z_3 = x_1 * (DA - CB)^2` for the pairs `(X2 : Z2)` and `(X3 : Z3)`. -/
def differentialAddZ {R : Type*} [CommRing R] (x1 X2 Z2 X3 Z3 : R) : R :=
  let a := X2 + Z2
  let bs := X2 - Z2
  let c := X3 + Z3
  let d := X3 - Z3
  let da := d * a
  let cb := c * bs
  let t2 := da - cb
  x1 * (t2 * t2)

omit [DecidableEq F] in
/-- A pair that holds the u of P holds the u of -P. -/
theorem XRep_neg {X Z : F} {P : (mont c.d).Point} (h : XRep c X Z P) : XRep c X Z (-P) := by
  match P, h with
  | .zero, h => exact h
  | .some x y _, h => rw [WeierstrassCurve.Affine.Point.neg_some]; exact h

omit [DecidableEq F] in
/-- The product of the x of P + Q and the x of P - Q, for two points whose x differ:
(x₁ x₂ - (1 + d)²)² / (x₁ - x₂)². -/
theorem addX_mul_addX {x₁ y₁ x₂ y₂ : F}
    (h₁ : y₁ ^ 2 = x₁ ^ 3 + 2 * (c.d - 1) * x₁ ^ 2 + (1 + c.d) ^ 2 * x₁)
    (h₂ : y₂ ^ 2 = x₂ ^ 3 + 2 * (c.d - 1) * x₂ ^ 2 + (1 + c.d) ^ 2 * x₂) (h_x : x₁ ≠ x₂) :
    (mont c.d).addX x₁ x₂ ((y₁ - y₂) / (x₁ - x₂)) *
        (mont c.d).addX x₁ x₂ ((y₁ + y₂) / (x₁ - x₂)) =
      (x₁ * x₂ - (1 + c.d) ^ 2) ^ 2 / (x₁ - x₂) ^ 2 := by
  have h_D : x₁ - x₂ ≠ 0 := sub_ne_zero.mpr h_x
  simp only [WeierstrassCurve.Affine.addX, mont, zero_mul, add_zero]
  have h_e : ∀ l m : F,
      (l ^ 2 - 2 * (c.d - 1) - x₁ - x₂) * (m ^ 2 - 2 * (c.d - 1) - x₁ - x₂) =
      l ^ 2 * m ^ 2 - (2 * (c.d - 1) + x₁ + x₂) * (l ^ 2 + m ^ 2) +
        (2 * (c.d - 1) + x₁ + x₂) ^ 2 := by
    intro l m; ring
  rw [h_e, show ((y₁ - y₂) / (x₁ - x₂)) ^ 2 * ((y₁ + y₂) / (x₁ - x₂)) ^ 2 =
      (y₁ ^ 2 - y₂ ^ 2) ^ 2 / (x₁ - x₂) ^ 4 by field_simp; ring,
    show ((y₁ - y₂) / (x₁ - x₂)) ^ 2 + ((y₁ + y₂) / (x₁ - x₂)) ^ 2 =
      2 * (y₁ ^ 2 + y₂ ^ 2) / (x₁ - x₂) ^ 2 by field_simp; ring, h₁, h₂]
  field_simp
  ring

omit [DecidableEq F] in
/-- Two pairs that hold the u of one point, the first with Z one, give X = x₁ Z. -/
theorem XRep_eq {x₁ X Z : F} {R : (mont c.d).Point} (h_B : XRep c x₁ 1 R)
    (h : XRep c X Z R) : Z ≠ 0 ∧ X = x₁ * Z := by
  match R, h_B, h with
  | .zero, h_B, _ => exact absurd h_B.1 one_ne_zero
  | .some _ _ _, ⟨_, h_u⟩, ⟨h_z, h_x⟩ => exact ⟨h_z, by rw [h_x, h_u, mul_one]⟩

/-- The differential addition holds the u of P + Q when `(x₁ : 1)` holds the u of Q - P or of
P - Q, for every two points, with x₁ not zero. -/
theorem addRep {a24 x₁ X₂ Z₂ X₃ Z₃ : F} (h_a24 : a24 * (1 + c.d) = -c.d)
    {B P Q : (mont c.d).Point} (h_B : XRep c x₁ 1 B) (h_x₁ : x₁ ≠ 0)
    (h_diff : Q - P = B ∨ P - Q = B) (h_P : XRep c X₂ Z₂ P) (h_Q : XRep c X₃ Z₃ Q) :
    XRep c (differentialAddX X₂ Z₂ X₃ Z₃) (differentialAddZ x₁ X₂ Z₂ X₃ Z₃) (P + Q) := by
  have h_k := c.one_add_d_ne_zero
  have h_two := c.two_ne_zero
  have h_four : (4 : F) ≠ 0 := by
    rw [show (4 : F) = 2 * 2 by norm_num]; exact mul_ne_zero h_two h_two
  have h_AX : differentialAddX X₂ Z₂ X₃ Z₃ = 4 * (X₂ * X₃ - Z₂ * Z₃) ^ 2 := by
    simp only [differentialAddX]; ring
  have h_AZ : differentialAddZ x₁ X₂ Z₂ X₃ Z₃ = 4 * x₁ * (X₂ * Z₃ - Z₂ * X₃) ^ 2 := by
    simp only [differentialAddZ]; ring
  have h_PQ : XRep c x₁ 1 (P - Q) := by
    rcases h_diff with h | h
    · rw [← neg_sub, h]; exact XRep_neg h_B
    · rw [h]; exact h_B
  rw [h_AX, h_AZ]
  match P, Q, h_P, h_Q, h_PQ with
  | .zero, .zero, _, _, h_PQ =>
    change XRep c x₁ 1 (0 - 0) at h_PQ
    rw [sub_self] at h_PQ
    exact absurd h_PQ.1 one_ne_zero
  | .zero, .some xq yq hq, ⟨h_z₂, h_x₂⟩, ⟨h_z₃, h_x₃⟩, h_PQ =>
    change XRep c x₁ 1 (0 - _) at h_PQ
    rw [zero_sub, WeierstrassCurve.Affine.Point.neg_some] at h_PQ
    obtain ⟨-, h_u⟩ := h_PQ
    rw [mul_one] at h_u
    change XRep c _ _ (0 + _)
    rw [zero_add]
    refine ⟨?_, ?_⟩
    · rw [h_z₂, zero_mul, sub_zero]
      exact mul_ne_zero (mul_ne_zero h_four h_x₁) (pow_ne_zero 2 (mul_ne_zero h_x₂ h_z₃))
    · rw [h_z₂, h_x₃, ← h_u]
      ring
  | .some xp yp hp, .zero, ⟨h_z₂, h_x₂⟩, ⟨h_z₃, h_x₃⟩, h_PQ =>
    change XRep c x₁ 1 (_ - 0) at h_PQ
    rw [sub_zero] at h_PQ
    obtain ⟨-, h_u⟩ := h_PQ
    rw [mul_one] at h_u
    change XRep c _ _ (_ + 0)
    rw [add_zero]
    refine ⟨?_, ?_⟩
    · rw [h_z₃, mul_zero, zero_sub, neg_sq]
      exact mul_ne_zero (mul_ne_zero h_four h_x₁) (pow_ne_zero 2 (mul_ne_zero h_z₂ h_x₃))
    · rw [h_z₃, h_x₂, ← h_u]
      ring
  | .some xp yp hp, .some xq yq hq, ⟨h_z₂, h_x₂⟩, ⟨h_z₃, h_x₃⟩, h_PQ =>
    have h_cp := equation_mont hp
    have h_cq := equation_mont hq
    by_cases h_x : xp = xq
    · subst h_x
      by_cases h_y : yp = yq
      · subst h_y
        change XRep c x₁ 1 (WeierstrassCurve.Affine.Point.some xp yp hp -
          WeierstrassCurve.Affine.Point.some xp yp hp) at h_PQ
        rw [sub_self] at h_PQ
        exact absurd h_PQ.1 one_ne_zero
      have h_neg : yp = -yq := by
        have h_mul : (yp - yq) * (yp + yq) = 0 := by linear_combination h_cp - h_cq
        rcases mul_eq_zero.mp h_mul with h | h
        · exact absurd (sub_eq_zero.mp h) h_y
        · linear_combination h
      subst h_neg
      rw [WeierstrassCurve.Affine.Point.add_of_Y_eq rfl (by rw [negY_mont])]
      have h_P_eq : (WeierstrassCurve.Affine.Point.some xp (-yq) hp : (mont c.d).Point) =
          -WeierstrassCurve.Affine.Point.some xp yq hq := by
        rw [WeierstrassCurve.Affine.Point.neg_some]
        simp only [negY_mont]
      have h_QQ : XRep c x₁ 1 (WeierstrassCurve.Affine.Point.some xp yq hq +
          WeierstrassCurve.Affine.Point.some xp yq hq) := by
        have h_n := XRep_neg h_PQ
        rwa [h_P_eq, show ∀ R : (mont c.d).Point, -(-R - R) = R + R by intro R; abel] at h_n
      obtain ⟨h_dz, h_dx⟩ := XRep_eq h_QQ (doubleRep h_a24 ⟨h_z₃, h_x₃⟩)
      have h_dne : doubleX X₃ Z₃ ≠ 0 := by rw [h_dx]; exact mul_ne_zero h_x₁ h_dz
      refine ⟨by rw [h_x₂, h_x₃]; ring, ?_⟩
      intro h_0
      have h_1 : X₂ * X₃ - Z₂ * Z₃ = 0 :=
        pow_eq_zero_iff (two_ne_zero) |>.mp ((mul_eq_zero.mp h_0).resolve_left h_four)
      have h_2 : doubleX X₃ Z₃ * Z₂ ^ 2 = Z₃ ^ 2 * (X₂ * X₃ - Z₂ * Z₃) ^ 2 := by
        simp only [doubleX]; rw [h_x₂, h_x₃]; ring
      rw [h_1] at h_2
      exact h_dne ((mul_eq_zero.mp (by rw [h_2]; ring)).resolve_right (pow_ne_zero 2 h_z₂))
    · rw [WeierstrassCurve.Affine.Point.add_of_X_ne h_x]
      rw [sub_eq_add_neg, WeierstrassCurve.Affine.Point.neg_some,
        WeierstrassCurve.Affine.Point.add_of_X_ne h_x] at h_PQ
      obtain ⟨-, h_u⟩ := h_PQ
      rw [mul_one, WeierstrassCurve.Affine.slope_of_X_ne h_x, negY_mont, sub_neg_eq_add] at h_u
      have h_prod := addX_mul_addX h_cp h_cq h_x
      have h_D : xp - xq ≠ 0 := sub_ne_zero.mpr h_x
      have h_m : (mont c.d).addX xp xq ((yp + yq) / (xp - xq)) = -(1 + c.d) * x₁ := by
        rw [h_u]; field_simp
      rw [h_m] at h_prod
      have h_A := eq_div_of_mul_eq (mul_ne_zero (neg_ne_zero.mpr h_k) h_x₁) h_prod
      refine ⟨?_, ?_⟩
      · rw [h_x₂, h_x₃]
        have h_e :
            4 * x₁ * (-xp / (1 + c.d) * Z₂ * Z₃ - Z₂ * (-xq / (1 + c.d) * Z₃)) ^ 2 =
            4 * x₁ * (Z₂ * Z₃ * (xq - xp) / (1 + c.d)) ^ 2 := by ring
        rw [h_e]
        exact mul_ne_zero (mul_ne_zero h_four h_x₁) (pow_ne_zero 2 (div_ne_zero
          (mul_ne_zero (mul_ne_zero h_z₂ h_z₃) (sub_ne_zero.mpr (Ne.symm h_x))) h_k))
      · rw [WeierstrassCurve.Affine.slope_of_X_ne h_x, h_A, h_x₂, h_x₃]
        field_simp
        ring

/-- The ladder's working variables over a ring. -/
structure RingState (R : Type*) where
  /-- `x_2`. -/
  x2 : R
  /-- `z_2`. -/
  z2 : R
  /-- `x_3`. -/
  x3 : R
  /-- `z_3`. -/
  z3 : R
  /-- `swap`. -/
  swap : ℕ

/-- `Spec.X25519.ladderStep` over a ring: the swap, then the doubling and the differential
addition. -/
def ringStep {R : Type*} [CommRing R] (x1 a24 : R) (kt : ℕ) (st : RingState R) : RingState R :=
  let swap := st.swap ^^^ kt
  let x2 := if swap = 1 then st.x3 else st.x2
  let z2 := if swap = 1 then st.z3 else st.z2
  let x3 := if swap = 1 then st.x2 else st.x3
  let z3 := if swap = 1 then st.z2 else st.z3
  { x2 := doubleX x2 z2
    z2 := doubleZ a24 x2 z2
    x3 := differentialAddX x2 z2 x3 z3
    z3 := differentialAddZ x1 x2 z2 x3 z3
    swap := kt }

/-- `Spec.X25519.ladderLoop` over a ring. -/
def ringLoop {R : Type*} [CommRing R] (k : ℕ) (x1 a24 : R) (t : ℕ) (st : RingState R) :
    RingState R :=
  Spec.X25519.downFrom (fun t st => ringStep x1 a24 ((k >>> t) &&& 1) st) t st

/-- What each iteration keeps: the pair holds n B and (n + 1) B, in the order `swap` names. -/
def Invariant (c : Params F) (B : (mont c.d).Point) (n : ℕ) (st : RingState F) : Prop :=
  (st.swap = 0 ∧ XRep c st.x2 st.z2 (n • B) ∧ XRep c st.x3 st.z3 ((n + 1) • B)) ∨
    (st.swap = 1 ∧ XRep c st.x2 st.z2 ((n + 1) • B) ∧ XRep c st.x3 st.z3 (n • B))

/-- An iteration from n B and (n + 1) B gives 2 n B and (2 n + 1) B. -/
theorem step_low {a24 x1 X2 Z2 X3 Z3 : F} (h_a24 : a24 * (1 + c.d) = -c.d)
    {B : (mont c.d).Point} (h_B : XRep c x1 1 B) (h_x1 : x1 ≠ 0) {n : ℕ}
    (h_P : XRep c X2 Z2 (n • B)) (h_Q : XRep c X3 Z3 ((n + 1) • B)) :
    XRep c (doubleX X2 Z2) (doubleZ a24 X2 Z2) ((2 * n) • B) ∧
      XRep c (differentialAddX X2 Z2 X3 Z3) (differentialAddZ x1 X2 Z2 X3 Z3)
        ((2 * n + 1) • B) := by
  refine ⟨?_, ?_⟩
  · rw [two_mul, add_nsmul]; exact doubleRep h_a24 h_P
  · rw [show 2 * n + 1 = n + (n + 1) by ring, add_nsmul]
    exact addRep h_a24 h_B h_x1 (Or.inl (by rw [add_nsmul, one_nsmul]; abel)) h_P h_Q

/-- An iteration from (n + 1) B and n B gives (2 n + 2) B and (2 n + 1) B. -/
theorem step_high {a24 x1 X2 Z2 X3 Z3 : F} (h_a24 : a24 * (1 + c.d) = -c.d)
    {B : (mont c.d).Point} (h_B : XRep c x1 1 B) (h_x1 : x1 ≠ 0) {n : ℕ}
    (h_P : XRep c X2 Z2 ((n + 1) • B)) (h_Q : XRep c X3 Z3 (n • B)) :
    XRep c (doubleX X2 Z2) (doubleZ a24 X2 Z2) ((2 * n + 1 + 1) • B) ∧
      XRep c (differentialAddX X2 Z2 X3 Z3) (differentialAddZ x1 X2 Z2 X3 Z3)
        ((2 * n + 1) • B) := by
  refine ⟨?_, ?_⟩
  · rw [show 2 * n + 1 + 1 = (n + 1) + (n + 1) by ring, add_nsmul]; exact doubleRep h_a24 h_P
  · rw [show 2 * n + 1 = (n + 1) + n by ring, add_nsmul]
    exact addRep h_a24 h_B h_x1 (Or.inr (by rw [add_nsmul, one_nsmul]; abel)) h_P h_Q

/-- An iteration on bit kt takes the invariant at n to the invariant at 2 n + kt. -/
theorem invariant_step {a24 x1 : F} (h_a24 : a24 * (1 + c.d) = -c.d)
    {B : (mont c.d).Point} (h_B : XRep c x1 1 B) (h_x1 : x1 ≠ 0) {n kt : ℕ} (h_kt : kt < 2)
    {st : RingState F} (h : Invariant c B n st) :
    Invariant c B (2 * n + kt) (ringStep x1 a24 kt st) := by
  rcases h with ⟨h_s, h_P, h_Q⟩ | ⟨h_s, h_P, h_Q⟩ <;>
    interval_cases kt <;> simp only [ringStep, h_s] <;> norm_num
  · exact Or.inl ⟨rfl, step_low h_a24 h_B h_x1 h_P h_Q⟩
  · exact Or.inr ⟨rfl, step_high h_a24 h_B h_x1 h_Q h_P⟩
  · exact Or.inl ⟨rfl, step_low h_a24 h_B h_x1 h_Q h_P⟩
  · exact Or.inr ⟨rfl, step_high h_a24 h_B h_x1 h_P h_Q⟩

omit [DecidableEq F] in
/-- k >>> m is twice k >>> (m + 1) plus the bit the iteration reads. -/
theorem shiftRight_bit (k m : ℕ) : 2 * (k >>> (m + 1)) + ((k >>> m) &&& 1) = k >>> m := by
  rw [Nat.and_one_is_mod, Nat.shiftRight_succ]
  exact Nat.div_add_mod _ 2

/-- The loop over bits m - 1 down to 0 takes the invariant at k >>> m to the invariant at k. -/
theorem invariant_loop {a24 x1 : F} (h_a24 : a24 * (1 + c.d) = -c.d)
    {B : (mont c.d).Point} (h_B : XRep c x1 1 B) (h_x1 : x1 ≠ 0) (k : ℕ) :
    ∀ (m : ℕ) (st : RingState F), Invariant c B (k >>> m) st →
      Invariant c B k (ringLoop k x1 a24 m st) := by
  intro m
  induction m with
  | zero => intro st h; simpa [ringLoop, Spec.X25519.downFrom] using h
  | succ m ih =>
    intro st h
    have h_kt : (k >>> m) &&& 1 < 2 := by
      rw [Nat.and_one_is_mod]; exact Nat.mod_lt _ (by norm_num)
    have h_next := invariant_step h_a24 h_B h_x1 h_kt h
    rw [shiftRight_bit] at h_next
    rw [ringLoop, Spec.X25519.downFrom]
    exact ih _ h_next

omit [DecidableEq F] in
/-- X Z⁻¹ is the u of the point a pair holds, and 0 for the identity, as `montU` writes it. -/
theorem XRep_div {X Z : F} {R : (mont c.d).Point} (h : XRep c X Z R) :
    X * Z⁻¹ = montU c.d R := by
  match R, h with
  | .zero, ⟨h_z, _⟩ => rw [h_z, inv_zero, mul_zero]; rfl
  | .some x y _, ⟨h_z, h_x⟩ => rw [h_x, mul_assoc, mul_inv_cancel₀ h_z, mul_one]; rfl

/-- The ladder over the field: 255 steps from `(1 : 0)` and `(x1 : 1)`, the final swap, and
`x_2 / z_2`, which is the u of k B for every k below 2^255. -/
theorem ringLadder {a24 x1 : F} (h_a24 : a24 * (1 + c.d) = -c.d)
    {B : (mont c.d).Point} (h_B : XRep c x1 1 B) (h_x1 : x1 ≠ 0) {k : ℕ} (h_k : k < 2 ^ 255) :
    let st := ringLoop k x1 a24 255 ⟨1, 0, x1, 1, 0⟩
    (if st.swap = 1 then st.x3 else st.x2) * (if st.swap = 1 then st.z3 else st.z2)⁻¹ =
      montU c.d (k • B) := by
  intro st
  have h_0 : k >>> 255 = 0 := by
    rw [Nat.shiftRight_eq_div_pow]; exact Nat.div_eq_of_lt h_k
  have h_init : Invariant c B (k >>> 255) ⟨1, 0, x1, 1, 0⟩ := by
    rw [h_0]
    refine Or.inl ⟨rfl, ⟨rfl, one_ne_zero⟩, ?_⟩
    rw [zero_add, one_nsmul]
    exact h_B
  rcases invariant_loop h_a24 h_B h_x1 k 255 _ h_init with ⟨h_s, h_P, -⟩ | ⟨h_s, -, h_P⟩
  · rw [if_neg (by rw [h_s]; norm_num), if_neg (by rw [h_s]; norm_num)]
    exact XRep_div h_P
  · rw [if_pos h_s, if_pos h_s]
    exact XRep_div h_P

end Field

section Nat

/-- The two specifications name one prime. -/
theorem p_eq : Spec.X25519.p = Ed25519Decode.p := rfl

/-- The casts of a `Nat` state's numbers to `ZMod p`. -/
def castState (st : Spec.X25519.LadderState) : RingState (ZMod Ed25519Decode.p) :=
  ⟨st.x2, st.z2, st.x3, st.z3, st.swap⟩

/-- Each number of a `Nat` state is below p. -/
def Reduced (st : Spec.X25519.LadderState) : Prop :=
  st.x2 < Spec.X25519.p ∧ st.z2 < Spec.X25519.p ∧ st.x3 < Spec.X25519.p ∧
    st.z3 < Spec.X25519.p

/-- The cast of `a % p` is the cast of a. -/
theorem cast_mod (a : ℕ) : ((a % Spec.X25519.p : ℕ) : ZMod Ed25519Decode.p) = a := by
  rw [p_eq, ZMod.natCast_mod]

/-- The cast of `a + p - b`, for b at most p, is a - b. -/
theorem cast_sub {a b : ℕ} (h : b ≤ Spec.X25519.p) :
    ((a + Spec.X25519.p - b : ℕ) : ZMod Ed25519Decode.p) = a - b := by
  rw [Nat.cast_sub (by omega), Nat.cast_add, p_eq, ZMod.natCast_self, add_zero]

/-- `a % p` is at most p. -/
theorem mod_le_p (a : ℕ) : a % Spec.X25519.p ≤ Spec.X25519.p :=
  (Nat.mod_lt _ (by norm_num [Spec.X25519.p])).le

/-- One `Nat` iteration is `ringStep` on the casts, with a24 = 121665. -/
theorem step_cast (x1 kt : ℕ) {st : Spec.X25519.LadderState} (h : Reduced st) :
    castState (Spec.X25519.ladderStep x1 kt st) =
      ringStep (x1 : ZMod Ed25519Decode.p) 121665 kt (castState st) := by
  obtain ⟨h_x2, h_z2, h_x3, h_z3⟩ := h
  by_cases h_s : st.swap ^^^ kt = 1 <;>
    simp only [castState, Spec.X25519.ladderStep, ringStep, doubleX, doubleZ, differentialAddX,
      differentialAddZ, h_s, ↓reduceIte, cast_mod, cast_sub, mod_le_p, h_z2.le, h_z3.le,
      Spec.X25519.a24, Nat.cast_add, Nat.cast_mul, Nat.cast_ofNat]

/-- One `Nat` iteration leaves every number below p. -/
theorem step_reduced (x1 kt : ℕ) (st : Spec.X25519.LadderState) :
    Reduced (Spec.X25519.ladderStep x1 kt st) := by
  have h_p : 0 < Spec.X25519.p := by norm_num [Spec.X25519.p]
  exact ⟨Nat.mod_lt _ h_p, Nat.mod_lt _ h_p, Nat.mod_lt _ h_p, Nat.mod_lt _ h_p⟩

/-- A map that takes each step of one loop to a step of the other takes the loop to the
loop. -/
theorem downFrom_map {α β : Type _} (f : α → β) (P : α → Prop) (s₁ : ℕ → α → α)
    (s₂ : ℕ → β → β) (h_step : ∀ t a, P a → f (s₁ t a) = s₂ t (f a))
    (h_P : ∀ t a, P (s₁ t a)) :
    ∀ (m : ℕ) (a : α), P a →
      f (Spec.X25519.downFrom s₁ m a) = Spec.X25519.downFrom s₂ m (f a) := by
  intro m
  induction m with
  | zero => intro a _; rfl
  | succ m ih =>
    intro a h
    rw [Spec.X25519.downFrom, Spec.X25519.downFrom, ih _ (h_P _ _), h_step _ _ h]

/-- The `Nat` loop is `ringLoop` on the casts. -/
theorem loop_cast (k x1 m : ℕ) {st : Spec.X25519.LadderState} (h : Reduced st) :
    castState (Spec.X25519.ladderLoop k x1 m st) =
      ringLoop k (x1 : ZMod Ed25519Decode.p) 121665 m (castState st) :=
  downFrom_map castState Reduced
    (fun t st => Spec.X25519.ladderStep x1 ((k >>> t) &&& 1) st)
    (fun t st => ringStep (x1 : ZMod Ed25519Decode.p) 121665 ((k >>> t) &&& 1) st)
    (fun _ _ h_r => step_cast _ _ h_r) (fun _ _ => step_reduced _ _ _) m st h

/-- The squarings of `Spec.X25519.powMod` compute `acc * b ^ e` modulo m. -/
theorem powMod_go_cast (m : ℕ) :
    ∀ e b acc : ℕ, ((Spec.X25519.powMod.go m b e acc : ℕ) : ZMod m) = acc * b ^ e := by
  intro e
  induction e using Nat.strong_induction_on with
  | _ e ih =>
    intro b acc
    rw [Spec.X25519.powMod.go.eq_1]
    by_cases h_e : e = 0
    · rw [dif_pos h_e, h_e, pow_zero, mul_one]
    · rw [dif_neg h_e, ih _ (Nat.div_lt_self (Nat.pos_of_ne_zero h_e) (by norm_num))]
      have h_split : (b : ZMod m) ^ e = (b * b) ^ (e / 2) * b ^ (e % 2) := by
        rw [← pow_two, ← pow_mul, ← pow_add, Nat.div_add_mod]
      rcases Nat.mod_two_eq_zero_or_one e with h_bit | h_bit
      · rw [if_neg (by omega), h_split, h_bit, ZMod.natCast_mod, Nat.cast_mul]
        ring
      · rw [if_pos h_bit, h_split, h_bit, ZMod.natCast_mod, ZMod.natCast_mod, Nat.cast_mul,
          Nat.cast_mul]
        ring

/-- `finv` is the inverse in `ZMod p`, and 0 for 0. -/
theorem finv_cast (z : ℕ) :
    ((Spec.X25519.finv z : ℕ) : ZMod Ed25519Decode.p) = (z : ZMod Ed25519Decode.p)⁻¹ := by
  rw [Spec.X25519.finv, Spec.X25519.powMod, p_eq, powMod_go_cast, ZMod.natCast_mod,
    ZMod.natCast_mod, Nat.cast_one, one_mul]
  by_cases h_z : (z : ZMod Ed25519Decode.p) = 0
  · rw [h_z, inv_zero, zero_pow (by norm_num [Ed25519Decode.p])]
  · have h_p := ZMod.pow_card_sub_one_eq_one h_z
    apply eq_inv_of_mul_eq_one_left
    rw [← pow_succ, show Ed25519Decode.p - 2 + 1 = Ed25519Decode.p - 1 by
      norm_num [Ed25519Decode.p]]
    exact h_p

end Nat

section Curve25519

open Spec.Ed25519Verify Spec.X25519Base

/-- a24 = 121665 is -d / (1 + d) for edwards25519's d. -/
theorem a24_eq :
    (121665 : ZMod Ed25519Decode.p) * (1 + edwards25519.d) = -edwards25519.d := by
  decide +kernel

/-- `(9 : 1)` holds the image of B. -/
theorem nine_rep : XRep edwards25519 9 1 (toMont base) := by
  have h_u := montU_toMont_base
  rw [toMont_generic base_x_ne_zero, montU] at h_u
  rw [toMont_generic base_x_ne_zero]
  exact ⟨one_ne_zero, by rw [mul_one, h_u]⟩

/-- The Nat ladder of `Spec.X25519` on u = 9 writes the u of k times the image of B, for every
k below 2^255. -/
theorem ladder_nine {k : ℕ} (h_k : k < 2 ^ 255) :
    ((Spec.X25519.ladder k 9 : ℕ) : ZMod Ed25519Decode.p) =
      montU edwards25519.d ((k : ℤ) • toMont base) := by
  have h_init : Reduced ⟨1, 0, 9 % Spec.X25519.p, 1, 0⟩ := by
    refine ⟨?_, ?_, Nat.mod_lt _ ?_, ?_⟩ <;> norm_num [Spec.X25519.p]
  have h_loop := loop_cast k (9 % Spec.X25519.p) 255 h_init
  have h_cast : castState ⟨1, 0, 9 % Spec.X25519.p, 1, 0⟩ =
      (⟨1, 0, 9, 1, 0⟩ : RingState (ZMod Ed25519Decode.p)) := by
    simp only [castState, cast_mod, Nat.cast_one, Nat.cast_zero, Nat.cast_ofNat]
  rw [h_cast, cast_mod, Nat.cast_ofNat] at h_loop
  have h_ring := ringLadder a24_eq nine_rep (by decide +kernel) h_k
  rw [natCast_zsmul, ← h_ring, ← h_loop]
  simp only [Spec.X25519.ladder, castState, cast_mod, Nat.cast_mul, finv_cast, Nat.cast_ite]
  rfl

/-- The same as a statement about the number the ladder returns: it is the u of k times the
image of B, below p. -/
theorem ladder_nine_val {k : ℕ} (h_k : k < 2 ^ 255) :
    Spec.X25519.ladder k 9 = (montU edwards25519.d ((k : ℤ) • toMont base)).val := by
  rw [← ladder_nine h_k, ZMod.val_natCast, Nat.mod_eq_of_lt]
  rw [← p_eq]
  exact Nat.mod_lt _ (by norm_num [Spec.X25519.p])

/-- The key generation and the ladder agree: for digits whose sum is a clamped scalar s,
`x25519_wide_base_mul`'s model writes the u the RFC 7748 ladder computes for s and 9. -/
theorem toU_keygen_eq_ladder (e : ℕ → ℤ) {s : ℕ}
    (h_sum : ∑ j ∈ Finset.range 64, e j * 16 ^ j = s) (h_8 : 8 ∣ s) (h_lo : 2 ^ 254 ≤ s)
    (h_hi : s < 2 ^ 255) :
    toU (baseMulExtended base e) = ((Spec.X25519.ladder s 9 : ℕ) : ZMod Ed25519Decode.p) := by
  rw [ladder_nine h_hi]
  exact (toU_keygen e h_sum h_8 h_lo h_hi).1

end Curve25519

end Spec.X25519Ladder
