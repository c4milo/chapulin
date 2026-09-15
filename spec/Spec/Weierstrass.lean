import Mathlib.AlgebraicGeometry.EllipticCurve.Affine.Point
import Mathlib.FieldTheory.Finite.Basic
import Spec.Bytes

/-!
ECDSA over a short Weierstrass curve `y^2 = x^3 - 3x + b` over the
prime field GF(p), FIPS 186-4 §6 with the group law of SEC 1 v2 §2.2.1.
`Spec/P256.lean` and `Spec/P384.lean` are this module at their own
domain parameters (FIPS 186-4 §D.1.2.3 and §D.1.2.4); both NIST curves
fix `a = -3`, so the parameter set is `p`, `b`, `n`, the base point and
the coordinate length.

Everything is plain `Nat` arithmetic with an explicit `% p` (or `% n`)
after every operation; points are affine `Option (Nat × Nat)` with
`none` for the point at infinity; inversion is Fermat's little theorem.
Subtraction in GF(p) is `(x + p - y) % p` on reduced operands, so the
`Nat` difference never underflows.

Signing lives here so the oracle can mint signatures the C verifier
must accept; the C side never signs.

The theorems relate this arithmetic to Mathlib's `WeierstrassCurve`
over `ZMod p`: curve membership is Mathlib's `Equation`, `add` and
`smul` compute Mathlib's group operation and `nsmul`, and a signature
`ecdsaSign` mints verifies under the key `pubKey?` derives. Every
theorem about the curve takes `Fact p.Prime` as a hypothesis: the NIST
primes are 256- and 384-bit numbers no tactic certifies, and a
primality certificate is out of scope (spec/CONTRACT.md).
-/

namespace Spec.Weierstrass

open Spec.Bytes

/-- Domain parameters of one curve `y^2 = x^3 - 3x + b` over GF(p):
the group order `n`, the base point `(gx, gy)`, and `coordLen`, the
bytes in one coordinate or scalar (SEC 1 v2 §3.1.1). -/
structure Curve where
  /-- Field prime. -/
  p : Nat
  /-- Coefficient `b`. -/
  b : Nat
  /-- Group order; the cofactor is 1. -/
  n : Nat
  /-- Base point x-coordinate. -/
  gx : Nat
  /-- Base point y-coordinate. -/
  gy : Nat
  /-- Bytes in one coordinate or scalar. -/
  coordLen : Nat

/-- Coefficient `a ≡ -3 (mod p)`, as the reduced `Nat` `p - 3`. -/
def Curve.a (C : Curve) : Nat := C.p - 3

/-- Affine point; `none` is the point at infinity. -/
abbrev Point := Option (Nat × Nat)

/-- The base point `G`. -/
def Curve.g (C : Curve) : Point := some (C.gx, C.gy)

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

/-- Inversion mod a prime `m` by Fermat's little theorem: `x^(m-2) mod m`. -/
def inv (x m : Nat) : Nat := powMod x (m - 2) m

/-- Curve membership: reduced coordinates with
`y^2 ≡ x^3 + ax + b (mod p)`. With cofactor 1 this is the whole
public-key validation (SEC 1 v2 §3.2.2.1; the order check is redundant). -/
def Curve.onCurve (C : Curve) (x y : Nat) : Bool :=
  x < C.p && y < C.p &&
    y * y % C.p == ((x * x % C.p * x % C.p + C.a * x % C.p) + C.b) % C.p

/-- The slope of the line through two affine points (SEC 1 v2 §2.2.1):
the tangent `(3x1^2 + a) / 2y1` when `x1 = x2`, else the chord
`(y2 - y1) / (x2 - x1)`. The caller has ruled out `P + (-P)`, so the
divisor is non-zero. -/
def Curve.slope (C : Curve) (x1 y1 x2 y2 : Nat) : Nat :=
  if x1 == x2 then (3 * (x1 * x1 % C.p) + C.a) % C.p * inv (2 * y1 % C.p) C.p % C.p
  else (y2 + C.p - y1) % C.p * inv ((x2 + C.p - x1) % C.p) C.p % C.p

/-- Affine group law (SEC 1 v2 §2.2.1). `P + (-P) = O` covers doubling a
point with `y = 0`; otherwise the chord (or tangent, for `P = Q`) slope
`lam` gives `x3 = lam^2 - x1 - x2` and `y3 = lam(x1 - x3) - y1`. -/
def Curve.add (C : Curve) : Point → Point → Point
  | none, q => q
  | pt, none => pt
  | some (x1, y1), some (x2, y2) =>
    if x1 == x2 && (y1 + y2) % C.p == 0 then none
    else
      let lam := C.slope x1 y1 x2 y2
      let x3 := (lam * lam % C.p + (C.p - x1) + (C.p - x2)) % C.p
      let y3 := (lam * ((x1 + C.p - x3) % C.p) % C.p + (C.p - y1)) % C.p
      some (x3, y3)

/-- Scalar multiplication by double-and-add over the bits of `k`. -/
def Curve.smul (C : Curve) (k : Nat) (pt : Point) : Point :=
  go k pt none
where
  go (k : Nat) (q acc : Point) : Point :=
    if _h : k = 0 then acc
    else go (k / 2) (C.add q q) (if k % 2 = 1 then C.add acc q else acc)
  termination_by k
  decreasing_by omega

/-- Public key `Q = d·G` encoded as X‖Y, `coordLen` bytes each
big-endian (SEC 1 v2 §2.3.3 uncompressed, without the 0x04 tag); `none`
unless `d ∈ [1, n-1]` (FIPS 186-4 §B.4). -/
def Curve.pubKey? (C : Curve) (d : Nat) : Option ByteArray :=
  if d == 0 || d ≥ C.n then none
  else match C.smul d C.g with
    | none => none
    | some (x, y) => some (natToBytesBE x C.coordLen ++ natToBytesBE y C.coordLen)

/-- ECDSA signing (FIPS 186-4 §6.4) with `d`, `k`, and the
hash-as-integer `z` given explicitly: `r = (k·G).x mod n` and
`s = k^-1 (z + r·d) mod n`. The digest and `n` have the same bit length
on both NIST curves, so `z` is the whole digest, no truncation. `none`
when `d` or `k` is outside `[1, n-1]` or `r`/`s` degenerates to 0. -/
def Curve.ecdsaSign (C : Curve) (d k z : Nat) : Option (Nat × Nat) :=
  if d == 0 || d ≥ C.n || k == 0 || k ≥ C.n then none
  else match C.smul k C.g with
    | none => none
    | some (x, _) =>
      let r := x % C.n
      let s := inv k C.n * ((z % C.n + r * d) % C.n) % C.n
      if r == 0 || s == 0 then none else some (r, s)

/-- ECDSA verification (FIPS 186-4 §6.4 / SEC 1 v2 §4.1.4): `pub` is
X‖Y (`2 * coordLen` bytes), `hash` the `coordLen`-byte digest, `r`/`s`
the signature integers. Requires `r, s ∈ [1, n-1]` and the public point
on the curve, then accepts iff `r ≡ (u1·G + u2·Q).x (mod n)` for
`u1 = z·s^-1 mod n`, `u2 = r·s^-1 mod n`. -/
def Curve.ecdsaVerify (C : Curve) (pub hash : ByteArray) (r s : Nat) : Bool :=
  if pub.size != 2 * C.coordLen || hash.size != C.coordLen then false
  else
    let qx := bytesToNatBE (pub.extract 0 C.coordLen)
    let qy := bytesToNatBE (pub.extract C.coordLen (2 * C.coordLen))
    if !C.onCurve qx qy then false
    else if r == 0 || r ≥ C.n || s == 0 || s ≥ C.n then false
    else
      let w := inv s C.n
      let u1 := bytesToNatBE hash * w % C.n
      let u2 := r * w % C.n
      match C.add (C.smul u1 C.g) (C.smul u2 (some (qx, qy))) with
      | none => false
      | some (x, _) => x % C.n == r

/-! ## Modular exponentiation and inversion -/

/-- Loop invariant of `powMod.go`: with the accumulator reduced, the
loop computes `acc * b^e mod m`. -/
private theorem powMod_go_eq (m e : Nat) : ∀ (b acc : Nat), acc % m = acc →
    powMod.go m b e acc = acc * b ^ e % m := by
  induction e using Nat.strong_induction_on with
  | _ e ih =>
    intro b acc h_reduced
    unfold powMod.go
    split
    · rename_i h_zero
      rw [h_zero, Nat.pow_zero, Nat.mul_one, h_reduced]
    · rename_i h_pos
      rw [ih (e / 2) (by omega) _ _ (by split <;> simp [h_reduced])]
      have h_split : b ^ e = b ^ (e % 2) * (b * b) ^ (e / 2) := by
        rw [← Nat.pow_two, ← Nat.pow_mul, ← Nat.pow_add, Nat.mod_add_div]
      have h_square : (b * b % m) ^ (e / 2) ≡ (b * b) ^ (e / 2) [MOD m] :=
        (Nat.mod_modEq _ _).pow _
      have h_accumulator : (if e % 2 = 1 then acc * b % m else acc) ≡ acc * b ^ (e % 2) [MOD m] := by
        split
        · rename_i h_odd
          rw [h_odd, Nat.pow_one]
          exact Nat.mod_modEq _ _
        · rename_i h_even
          rw [Nat.mod_two_ne_one.mp h_even, Nat.pow_zero, Nat.mul_one]
      calc (if e % 2 = 1 then acc * b % m else acc) * (b * b % m) ^ (e / 2) % m
          = acc * b ^ (e % 2) * (b * b) ^ (e / 2) % m := h_accumulator.mul h_square
        _ = acc * b ^ e % m := by rw [h_split, Nat.mul_assoc]

/-- `powMod` is modular exponentiation. No hypothesis: the accumulator
starts at `1 % m`, which is what makes `m = 1` and `m = 0` come out
as `b ^ e % m` too. -/
theorem powMod_eq (b e m : Nat) : powMod b e m = b ^ e % m := by
  rw [powMod, powMod_go_eq m e (b % m) (1 % m) (Nat.mod_mod 1 m)]
  have h_reduce : 1 % m * (b % m) ^ e ≡ 1 * b ^ e [MOD m] :=
    (Nat.mod_modEq 1 m).mul ((Nat.mod_modEq b m).pow e)
  rw [Nat.one_mul] at h_reduce
  exact h_reduce

/-- In `ZMod m` for a prime `m`, `inv` is the field inverse of a
non-zero element: `x^(m-2) * x = x^(m-1) = 1` by Fermat's little theorem. -/
theorem inv_cast {x m : Nat} [Fact m.Prime] (h_nonzero : (x : ZMod m) ≠ 0) :
    ((inv x m : ℕ) : ZMod m) = (x : ZMod m)⁻¹ := by
  have h_two_le : 2 ≤ m := (Fact.out : m.Prime).two_le
  have h_fermat : (x : ZMod m) ^ (m - 2) * x = 1 := by
    rw [← pow_succ, show m - 2 + 1 = m - 1 by omega]
    exact ZMod.pow_card_sub_one_eq_one h_nonzero
  rw [inv, powMod_eq, ZMod.natCast_mod, Nat.cast_pow]
  exact eq_inv_of_mul_eq_one_left h_fermat

/-- Fermat inversion inverts: for a prime `m` and `x` not a multiple of
`m`, `x * inv x m ≡ 1 (mod m)`. -/
theorem inv_mul {x m : Nat} [Fact m.Prime] (h_nonzero : x % m ≠ 0) : x * inv x m % m = 1 := by
  have : Fact (1 < m) := ⟨(Fact.out : m.Prime).one_lt⟩
  have h_cast_nonzero : (x : ZMod m) ≠ 0 := by
    rw [Ne, ZMod.natCast_eq_zero_iff, Nat.dvd_iff_mod_eq_zero]
    exact h_nonzero
  have h_product : ((x * inv x m % m : ℕ) : ZMod m) = 1 := by
    rw [ZMod.natCast_mod, Nat.cast_mul, inv_cast h_cast_nonzero, mul_inv_cancel₀ h_cast_nonzero]
  calc x * inv x m % m
      = ((x * inv x m % m : ℕ) : ZMod m).val :=
        (ZMod.val_cast_of_lt (Nat.mod_lt _ (Fact.out : m.Prime).pos)).symm
    _ = 1 := by rw [h_product, ZMod.val_one]

/-! ## The curve in Mathlib -/

/-- The same curve as Mathlib's `WeierstrassCurve` over `ZMod p`:
`a₁ = a₂ = a₃ = 0`, `a₄ = -3`, `a₆ = b`. -/
def Curve.weierstrass (C : Curve) : WeierstrassCurve.Affine (ZMod C.p) :=
  ⟨0, 0, 0, -3, (C.b : ZMod C.p)⟩

/-- A Mathlib point as the reduced `Nat` pair the arithmetic here works
on: `ZMod.val` of each coordinate, and `none` for the point at
infinity. -/
def Curve.ofPoint (C : Curve) : C.weierstrass.Point → Point
  | .zero => none
  | .some x y _ => some (x.val, y.val)

/-- Membership reduces both coordinates. -/
private theorem lt_of_onCurve (C : Curve) {x y : Nat} (h_on : C.onCurve x y = true) :
    x < C.p ∧ y < C.p := by
  simp only [Curve.onCurve, Bool.and_eq_true, decide_eq_true_eq] at h_on
  exact ⟨h_on.1.1, h_on.1.2⟩

section Bridge

variable (C : Curve) [Fact C.p.Prime]

private theorem a_cast (h_odd : 2 < C.p) : ((C.a : ℕ) : ZMod C.p) = -3 := by
  rw [Curve.a, Nat.cast_sub (by omega), ZMod.natCast_self, zero_sub, Nat.cast_ofNat]

/-- Membership by the arithmetic here is Mathlib's Weierstrass equation
on the reduced coordinates. The `2 < p` hypothesis is what makes the
reduced `p - 3` cast to `-3`. -/
theorem Curve.onCurve_iff (h_odd : 2 < C.p) {x y : Nat} (h_x_lt : x < C.p) (h_y_lt : y < C.p) :
    C.onCurve x y = true ↔ C.weierstrass.Equation x y := by
  rw [WeierstrassCurve.Affine.equation_iff]
  simp only [Curve.onCurve, h_x_lt, h_y_lt, decide_true, Bool.true_and, beq_iff_eq,
    ← ZMod.natCast_eq_natCast_iff', Curve.weierstrass]
  push_cast [ZMod.natCast_mod]
  rw [a_cast C h_odd]
  constructor <;> intro h_equation <;> linear_combination h_equation

/-- On the reduced coordinates of a Mathlib point, membership is its
Weierstrass equation. -/
private theorem onCurve_val_iff (h_odd : 2 < C.p) (x y : ZMod C.p) :
    C.onCurve x.val y.val = true ↔ C.weierstrass.Equation x y := by
  rw [C.onCurve_iff h_odd (ZMod.val_lt x) (ZMod.val_lt y), ZMod.natCast_zmod_val,
    ZMod.natCast_zmod_val]

private theorem negY_eq (x y : ZMod C.p) : C.weierstrass.negY x y = -y := by
  simp [WeierstrassCurve.Affine.negY, Curve.weierstrass]

/-- The slope here casts to Mathlib's, for two points not each other's
negation. -/
private theorem slope_cast (h_odd : 2 < C.p) {x₁ y₁ x₂ y₂ : ZMod C.p}
    (h_equation₁ : C.weierstrass.Equation x₁ y₁) (h_equation₂ : C.weierstrass.Equation x₂ y₂)
    (h_not_neg : ¬(x₁ = x₂ ∧ y₁ = C.weierstrass.negY x₂ y₂)) :
    ((C.slope x₁.val y₁.val x₂.val y₂.val : ℕ) : ZMod C.p) = C.weierstrass.slope x₁ x₂ y₁ y₂ := by
  by_cases h_x_eq : x₁ = x₂
  · have h_y_ne : y₁ ≠ C.weierstrass.negY x₂ y₂ := fun h_eq => h_not_neg ⟨h_x_eq, h_eq⟩
    have h_y_eq : y₁ = y₂ :=
      WeierstrassCurve.Affine.Y_eq_of_Y_ne h_equation₁ h_equation₂ h_x_eq h_y_ne
    subst h_x_eq h_y_eq
    have h_double_nonzero : ((2 * y₁.val % C.p : ℕ) : ZMod C.p) ≠ 0 := by
      push_cast [ZMod.natCast_mod, ZMod.natCast_zmod_val]
      rw [negY_eq, Ne, ← add_eq_zero_iff_eq_neg, ← two_mul] at h_y_ne
      exact h_y_ne
    rw [WeierstrassCurve.Affine.slope_of_Y_ne rfl h_y_ne, Curve.slope, if_pos (beq_self_eq_true _)]
    push_cast [ZMod.natCast_mod, ZMod.natCast_zmod_val]
    rw [inv_cast h_double_nonzero, a_cast C h_odd, negY_eq, div_eq_mul_inv]
    push_cast [ZMod.natCast_mod, ZMod.natCast_zmod_val]
    simp only [Curve.weierstrass]
    congr 1
    · ring
    · congr 1
      ring
  · have h_val_ne : ¬((x₁.val == x₂.val) = true) := fun h_eq =>
      h_x_eq (ZMod.val_injective C.p (beq_iff_eq.mp h_eq))
    have h_diff_nonzero : (((x₂.val + C.p - x₁.val) % C.p : ℕ) : ZMod C.p) ≠ 0 := by
      rw [ZMod.natCast_mod, Nat.cast_sub (by have := ZMod.val_lt x₁; omega)]
      push_cast [ZMod.natCast_zmod_val, ZMod.natCast_self]
      rw [add_zero]
      exact sub_ne_zero.mpr (Ne.symm h_x_eq)
    rw [WeierstrassCurve.Affine.slope_of_X_ne h_x_eq, Curve.slope, if_neg h_val_ne]
    push_cast [ZMod.natCast_mod]
    rw [inv_cast h_diff_nonzero, ZMod.natCast_mod,
      Nat.cast_sub (by have := ZMod.val_lt y₁; omega),
      Nat.cast_sub (by have := ZMod.val_lt x₁; omega)]
    push_cast [ZMod.natCast_zmod_val, ZMod.natCast_self]
    rw [add_zero, add_zero, div_eq_mul_inv, ← neg_sub y₂ y₁, ← neg_sub x₂ x₁, inv_neg,
      neg_mul_neg]

/-- `add` on two affine Mathlib points, read through `ofPoint`, is their
Mathlib sum: the `P + (-P) = O` test agrees, and otherwise the chord or
tangent formulas agree coordinate by coordinate. -/
private theorem add_some_some (h_odd : 2 < C.p) {x₁ y₁ x₂ y₂ : ZMod C.p}
    (h_nonsingular₁ : C.weierstrass.Nonsingular x₁ y₁)
    (h_nonsingular₂ : C.weierstrass.Nonsingular x₂ y₂) :
    C.add (some (x₁.val, y₁.val)) (some (x₂.val, y₂.val)) =
      C.ofPoint (.some x₁ y₁ h_nonsingular₁ + .some x₂ y₂ h_nonsingular₂) := by
  have h_pos : 0 < C.p := (Fact.out : C.p.Prime).pos
  have h_test : (x₁.val == x₂.val && (y₁.val + y₂.val) % C.p == 0) = true ↔
      (x₁ = x₂ ∧ y₁ = C.weierstrass.negY x₂ y₂) := by
    rw [negY_eq, Bool.and_eq_true, beq_iff_eq, beq_iff_eq, ← ZMod.val_add, ZMod.val_eq_zero,
      add_eq_zero_iff_eq_neg, (ZMod.val_injective C.p).eq_iff]
  by_cases h_not_neg : x₁ = x₂ ∧ y₁ = C.weierstrass.negY x₂ y₂
  · rw [WeierstrassCurve.Affine.Point.add_of_Y_eq h_not_neg.1 h_not_neg.2]
    simp only [Curve.add, if_pos (h_test.mpr h_not_neg)]
    rfl
  · rw [WeierstrassCurve.Affine.Point.add_some h_not_neg]
    simp only [Curve.add, if_neg (mt h_test.mp h_not_neg), Curve.ofPoint, Option.some.injEq,
      Prod.mk.injEq]
    have h_slope := slope_cast C h_odd h_nonsingular₁.1 h_nonsingular₂.1 h_not_neg
    set lam := C.slope x₁.val y₁.val x₂.val y₂.val
    set ℓ := C.weierstrass.slope x₁ x₂ y₁ y₂
    have h_x₁_lt := ZMod.val_lt x₁
    have h_x₂_lt := ZMod.val_lt x₂
    have h_y₁_lt := ZMod.val_lt y₁
    have h_x3_cast : (((lam * lam % C.p + (C.p - x₁.val) + (C.p - x₂.val)) % C.p : ℕ) : ZMod C.p)
        = C.weierstrass.addX x₁ x₂ ℓ := by
      rw [ZMod.natCast_mod, Nat.cast_add, Nat.cast_add, ZMod.natCast_mod,
        Nat.cast_sub (by omega), Nat.cast_sub (by omega)]
      push_cast [ZMod.natCast_zmod_val, ZMod.natCast_self]
      rw [h_slope]
      simp only [WeierstrassCurve.Affine.addX, Curve.weierstrass]
      ring
    have h_x3 : (lam * lam % C.p + (C.p - x₁.val) + (C.p - x₂.val)) % C.p
        = (C.weierstrass.addX x₁ x₂ ℓ).val := by
      rw [← h_x3_cast, ZMod.val_cast_of_lt (Nat.mod_lt _ h_pos)]
    refine ⟨h_x3, ?_⟩
    rw [h_x3]
    have h_x3_lt := ZMod.val_lt (C.weierstrass.addX x₁ x₂ ℓ)
    have h_y3_cast : (((lam * ((x₁.val + C.p - (C.weierstrass.addX x₁ x₂ ℓ).val) % C.p) % C.p
        + (C.p - y₁.val)) % C.p : ℕ) : ZMod C.p) = C.weierstrass.addY x₁ x₂ y₁ ℓ := by
      rw [ZMod.natCast_mod, Nat.cast_add, ZMod.natCast_mod, Nat.cast_mul, ZMod.natCast_mod,
        Nat.cast_sub (by omega), Nat.cast_sub (by omega)]
      push_cast [ZMod.natCast_zmod_val, ZMod.natCast_self]
      rw [h_slope]
      simp only [WeierstrassCurve.Affine.addY, WeierstrassCurve.Affine.negY,
        WeierstrassCurve.Affine.negAddY, WeierstrassCurve.Affine.addX, Curve.weierstrass]
      ring
    rw [← h_y3_cast, ZMod.val_cast_of_lt (Nat.mod_lt _ h_pos)]

/-- `add` computes Mathlib's group law: on points read through
`ofPoint`, the arithmetic here and Mathlib's `+` agree, the point at
infinity included (SEC 1 v2 §2.2.1). -/
theorem Curve.add_ofPoint (h_odd : 2 < C.p) (P Q : C.weierstrass.Point) :
    C.add (C.ofPoint P) (C.ofPoint Q) = C.ofPoint (P + Q) := by
  cases P with
  | zero => rw [← WeierstrassCurve.Affine.Point.zero_def, zero_add]; rfl
  | some x₁ y₁ h_nonsingular₁ =>
    cases Q with
    | zero => rw [← WeierstrassCurve.Affine.Point.zero_def, add_zero]; rfl
    | some x₂ y₂ h_nonsingular₂ => exact add_some_some C h_odd h_nonsingular₁ h_nonsingular₂

/-- Loop invariant of `smul.go`: the accumulator plus `k` times the
running point, in Mathlib's group. -/
private theorem smul_go_ofPoint (h_odd : 2 < C.p) (k : Nat) :
    ∀ (Q A : C.weierstrass.Point),
      Curve.smul.go C k (C.ofPoint Q) (C.ofPoint A) = C.ofPoint (A + k • Q) := by
  induction k using Nat.strong_induction_on with
  | _ k ih =>
    intro Q A
    unfold Curve.smul.go
    split
    · rename_i h_zero
      rw [h_zero, zero_nsmul, add_zero]
    · rename_i h_pos
      have h_accumulator : (if k % 2 = 1 then C.add (C.ofPoint A) (C.ofPoint Q) else C.ofPoint A)
          = C.ofPoint (if k % 2 = 1 then A + Q else A) := by
        split <;> simp only [C.add_ofPoint h_odd]
      rw [C.add_ofPoint h_odd Q Q, h_accumulator, ih (k / 2) (by omega)]
      congr 1
      have h_bits : k • Q = (k / 2) • (Q + Q) + (k % 2) • Q := by
        conv_lhs => rw [← Nat.div_add_mod k 2]
        rw [add_nsmul, mul_nsmul, two_nsmul]
      rw [h_bits]
      split
      · rename_i h_odd_bit
        rw [h_odd_bit, one_nsmul]
        abel
      · rename_i h_even_bit
        rw [Nat.mod_two_ne_one.mp h_even_bit, zero_nsmul, add_zero]

/-- `smul` computes Mathlib's `nsmul`: double-and-add over the bits of
`k` equals `k • P`. -/
theorem Curve.smul_ofPoint (h_odd : 2 < C.p) (k : Nat) (P : C.weierstrass.Point) :
    C.smul k (C.ofPoint P) = C.ofPoint (k • P) := by
  rw [Curve.smul, show (none : Point) = C.ofPoint 0 from rfl, smul_go_ofPoint C h_odd k P 0,
    zero_add]

/-- The curve is nonsingular when `4a^3 + 27b^2 ≢ 0 (mod p)` (SEC 1 v2
§3.1.1.2.1): that quantity is Mathlib's discriminant up to the unit
`-16`, which `2 < p` keeps non-zero. -/
private theorem Δ_ne_zero (h_odd : 2 < C.p)
    (h_discriminant : (4 * C.a ^ 3 + 27 * C.b ^ 2) % C.p ≠ 0) : C.weierstrass.Δ ≠ 0 := by
  have h_discriminant_cast : ((4 * C.a ^ 3 + 27 * C.b ^ 2 : ℕ) : ZMod C.p) ≠ 0 := by
    rw [Ne, ZMod.natCast_eq_zero_iff, Nat.dvd_iff_mod_eq_zero]
    exact h_discriminant
  have h_two_ne_zero : (2 : ZMod C.p) ≠ 0 := by
    rw [Ne, show (2 : ZMod C.p) = ((2 : ℕ) : ZMod C.p) from rfl, ZMod.natCast_eq_zero_iff]
    intro h_dvd
    have := Nat.le_of_dvd (by decide) h_dvd
    omega
  have h_sixteen_ne_zero : (16 : ZMod C.p) ≠ 0 := by
    rw [show (16 : ZMod C.p) = 2 ^ 4 by norm_num]
    exact pow_ne_zero 4 h_two_ne_zero
  have h_Δ_eq : C.weierstrass.Δ = -16 * ((4 * C.a ^ 3 + 27 * C.b ^ 2 : ℕ) : ZMod C.p) := by
    simp only [WeierstrassCurve.Δ, WeierstrassCurve.b₂, WeierstrassCurve.b₄, WeierstrassCurve.b₆,
      WeierstrassCurve.b₈, Curve.weierstrass]
    push_cast
    rw [a_cast C h_odd]
    ring
  rw [h_Δ_eq]
  exact mul_ne_zero (neg_ne_zero.mpr h_sixteen_ne_zero) h_discriminant_cast

/-- Every point the arithmetic here accepts is a nonsingular Mathlib
point, on a curve with non-zero discriminant. -/
private theorem nonsingular_of_onCurve (h_odd : 2 < C.p)
    (h_discriminant : (4 * C.a ^ 3 + 27 * C.b ^ 2) % C.p ≠ 0) {x y : Nat}
    (h_on : C.onCurve x y = true) : C.weierstrass.Nonsingular x y :=
  (WeierstrassCurve.Affine.equation_iff_nonsingular_of_Δ_ne_zero
    (Δ_ne_zero C h_odd h_discriminant)).mp
    ((C.onCurve_iff h_odd (lt_of_onCurve C h_on).1 (lt_of_onCurve C h_on).2).mp h_on)

/-- Closure: the sum of two points on the curve is on the curve, whenever
the sum is affine. The proof reads both sides through `add_ofPoint`. -/
theorem Curve.onCurve_add (h_odd : 2 < C.p)
    (h_discriminant : (4 * C.a ^ 3 + 27 * C.b ^ 2) % C.p ≠ 0) {x₁ y₁ x₂ y₂ x₃ y₃ : Nat}
    (h_on₁ : C.onCurve x₁ y₁ = true) (h_on₂ : C.onCurve x₂ y₂ = true)
    (h_sum : C.add (some (x₁, y₁)) (some (x₂, y₂)) = some (x₃, y₃)) :
    C.onCurve x₃ y₃ = true := by
  have h_bounds₁ := lt_of_onCurve C h_on₁
  have h_bounds₂ := lt_of_onCurve C h_on₂
  let P : C.weierstrass.Point :=
    .some x₁ y₁ (nonsingular_of_onCurve C h_odd h_discriminant h_on₁)
  let Q : C.weierstrass.Point :=
    .some x₂ y₂ (nonsingular_of_onCurve C h_odd h_discriminant h_on₂)
  have h_ofPoint_P : C.ofPoint P = some (x₁, y₁) := by
    simp only [P, Curve.ofPoint, ZMod.val_cast_of_lt h_bounds₁.1, ZMod.val_cast_of_lt h_bounds₁.2]
  have h_ofPoint_Q : C.ofPoint Q = some (x₂, y₂) := by
    simp only [Q, Curve.ofPoint, ZMod.val_cast_of_lt h_bounds₂.1, ZMod.val_cast_of_lt h_bounds₂.2]
  rw [← h_ofPoint_P, ← h_ofPoint_Q, C.add_ofPoint h_odd] at h_sum
  cases h_sum_point : P + Q with
  | zero => rw [h_sum_point] at h_sum; exact absurd h_sum (by simp [Curve.ofPoint])
  | some x y h_nonsingular =>
    rw [h_sum_point] at h_sum
    simp only [Curve.ofPoint, Option.some.injEq, Prod.mk.injEq] at h_sum
    rw [← h_sum.1, ← h_sum.2]
    exact (onCurve_val_iff C h_odd x y).mpr h_nonsingular.1

/-- The base point `G` as a Mathlib point. -/
def Curve.basePoint (h_odd : 2 < C.p)
    (h_discriminant : (4 * C.a ^ 3 + 27 * C.b ^ 2) % C.p ≠ 0)
    (h_base : C.onCurve C.gx C.gy = true) : C.weierstrass.Point :=
  .some C.gx C.gy (nonsingular_of_onCurve C h_odd h_discriminant h_base)

private theorem ofPoint_basePoint (h_odd : 2 < C.p)
    (h_discriminant : (4 * C.a ^ 3 + 27 * C.b ^ 2) % C.p ≠ 0)
    (h_base : C.onCurve C.gx C.gy = true) :
    C.ofPoint (C.basePoint h_odd h_discriminant h_base) = C.g := by
  simp only [Curve.basePoint, Curve.ofPoint, Curve.g, ZMod.val_cast_of_lt (lt_of_onCurve C h_base).1,
    ZMod.val_cast_of_lt (lt_of_onCurve C h_base).2]

end Bridge

/-! ## ECDSA round trip -/

/-- A multiple of a point of order dividing `n` depends only on the
multiplier mod `n`. -/
private theorem nsmul_mod {G : Type*} [AddCommGroup G] {P : G} {n : Nat} (h_order : n • P = 0)
    (m : Nat) : m • P = (m % n) • P := by
  conv_lhs => rw [← Nat.mod_add_div m n]
  rw [add_nsmul, mul_nsmul, h_order, nsmul_zero, add_zero]

/-- The scalar the verifier recombines, `u1 + u2·d`, is `k` modulo `n`:
with `w = s^-1` and `s = k^-1 (z + r d)`, `u1 + u2 d = w (z + r d) = k`.
Stated on the reduced `Nat` values the two functions compute. -/
private theorem recombine_eq {n d k z r : Nat} [Fact n.Prime] (h_k_nonzero : k % n ≠ 0)
    (h_s_nonzero : inv k n * ((z % n + r * d) % n) % n ≠ 0) :
    (z * inv (inv k n * ((z % n + r * d) % n) % n) n % n
      + d * (r * inv (inv k n * ((z % n + r * d) % n) % n) n % n)) % n = k % n := by
  have h_k_cast : (k : ZMod n) ≠ 0 := by
    rw [Ne, ZMod.natCast_eq_zero_iff, Nat.dvd_iff_mod_eq_zero]
    exact h_k_nonzero
  have h_s_cast : ((inv k n * ((z % n + r * d) % n) % n : ℕ) : ZMod n) ≠ 0 := by
    rw [Ne, ZMod.natCast_eq_zero_iff, Nat.dvd_iff_mod_eq_zero, Nat.mod_mod]
    exact h_s_nonzero
  have h_message : ((z : ZMod n) + r * d) ≠ 0 := by
    intro h_zero
    apply h_s_cast
    push_cast [ZMod.natCast_mod]
    rw [h_zero, mul_zero]
  rw [← ZMod.natCast_eq_natCast_iff']
  push_cast [ZMod.natCast_mod]
  rw [inv_cast h_s_cast]
  push_cast [ZMod.natCast_mod]
  rw [inv_cast h_k_cast]
  field_simp

/-- Sign-then-verify round trip (FIPS 186-4 §6.4): a signature
`ecdsaSign` mints for `d` verifies under `pubKey? d`, given the group
facts the algorithm requires — `n` prime and `n • G = 0` — as
hypotheses. The theorem does not claim soundness of the verifier: it
is completeness, the direction that says the oracle's signatures are
ones the C must accept. -/
theorem Curve.ecdsaVerify_ecdsaSign (C : Curve) [Fact C.p.Prime] [Fact C.n.Prime]
    (h_odd : 2 < C.p) (h_discriminant : (4 * C.a ^ 3 + 27 * C.b ^ 2) % C.p ≠ 0)
    (h_base : C.onCurve C.gx C.gy = true) (h_fits : C.p < 2 ^ (8 * C.coordLen))
    (h_order : C.n • C.basePoint h_odd h_discriminant h_base = 0)
    {d k r s : Nat} {pub hash : ByteArray}
    (h_sign : C.ecdsaSign d k (bytesToNatBE hash) = some (r, s))
    (h_pub : C.pubKey? d = some pub) (h_hash : hash.size = C.coordLen) :
    C.ecdsaVerify pub hash r s = true := by
  set G := C.basePoint h_odd h_discriminant h_base
  have h_g_ofPoint : C.g = C.ofPoint G := (ofPoint_basePoint C h_odd h_discriminant h_base).symm
  have h_n_pos : 0 < C.n := (Fact.out : C.n.Prime).pos
  -- What signing established: d and k in range, k • G affine, r and s
  -- non-zero, and their values.
  unfold Curve.ecdsaSign at h_sign
  rw [Option.ite_none_left_eq_some] at h_sign
  obtain ⟨h_range, h_sign⟩ := h_sign
  simp only [Bool.or_eq_true, beq_iff_eq, decide_eq_true_eq, not_or] at h_range
  obtain ⟨⟨⟨h_d_nonzero, h_d_lt⟩, h_k_nonzero⟩, h_k_lt⟩ := h_range
  obtain ⟨x, y_k, h_kG_eq⟩ : ∃ x y, C.smul k C.g = some (x, y) := by
    cases h_point : C.smul k C.g with
    | none => rw [h_point] at h_sign; exact absurd h_sign (by simp)
    | some xy => exact ⟨xy.1, xy.2, rfl⟩
  rw [h_kG_eq] at h_sign
  simp only [Option.ite_none_left_eq_some, Bool.or_eq_true, beq_iff_eq, not_or,
    Option.some.injEq, Prod.mk.injEq] at h_sign
  obtain ⟨⟨h_r_nonzero, h_s_nonzero⟩, h_r_eq, h_s_eq⟩ := h_sign
  subst h_r_eq
  -- What the key derivation established: d • G affine, and pub its
  -- encoding.
  unfold Curve.pubKey? at h_pub
  rw [if_neg (by simp [h_d_nonzero, h_d_lt])] at h_pub
  obtain ⟨qx, qy, h_dG_eq⟩ : ∃ x y, C.smul d C.g = some (x, y) := by
    cases h_point : C.smul d C.g with
    | none => rw [h_point] at h_pub; exact absurd h_pub (by simp)
    | some xy => exact ⟨xy.1, xy.2, rfl⟩
  rw [h_dG_eq] at h_pub
  simp only [Option.some.injEq] at h_pub
  -- The two multiples of G, as Mathlib points; d • G is affine, so its
  -- coordinates are reduced and on the curve.
  rw [h_g_ofPoint, C.smul_ofPoint h_odd] at h_kG_eq h_dG_eq
  obtain ⟨qx', qy', h_nonsingular, h_point⟩ : ∃ (qx' qy' : ZMod C.p)
      (h_nonsingular : C.weierstrass.Nonsingular qx' qy'), d • G = .some qx' qy' h_nonsingular := by
    cases h_point : d • G with
    | zero => rw [h_point] at h_dG_eq; exact absurd h_dG_eq (by simp [Curve.ofPoint])
    | some qx' qy' h_nonsingular => exact ⟨qx', qy', h_nonsingular, rfl⟩
  obtain ⟨h_qx_val, h_qy_val⟩ : qx'.val = qx ∧ qy'.val = qy := by
    simpa [Curve.ofPoint, h_point] using h_dG_eq
  subst h_qx_val h_qy_val
  have h_on : C.onCurve qx'.val qy'.val = true :=
    (onCurve_val_iff C h_odd qx' qy').mpr h_nonsingular.1
  have h_qx_lt := ZMod.val_lt qx'
  have h_qy_lt := ZMod.val_lt qy'
  -- The verifier's decoding of pub.
  have h_pub_size : pub.size = 2 * C.coordLen := by
    rw [← h_pub, ByteArray.size_append, natToBytesBE_size, natToBytesBE_size]
    omega
  have h_qx_decode : bytesToNatBE (pub.extract 0 C.coordLen) = qx'.val := by
    rw [← h_pub, ByteArray.extract_append_eq_left (natToBytesBE_size _ _).symm,
      bytesToNatBE_natToBytesBE]
    exact Nat.mod_eq_of_lt (by omega)
  have h_qy_decode : bytesToNatBE (pub.extract C.coordLen (2 * C.coordLen)) = qy'.val := by
    rw [← h_pub, ByteArray.extract_append_eq_right (natToBytesBE_size _ _).symm
      (by rw [natToBytesBE_size, natToBytesBE_size]; omega), bytesToNatBE_natToBytesBE]
    exact Nat.mod_eq_of_lt (by omega)
  -- The verifier's recombination equals k • G.
  have h_k_reduced : k % C.n ≠ 0 := by
    rw [Nat.mod_eq_of_lt (Nat.not_le.mp h_k_lt)]
    exact h_k_nonzero
  have h_recombine : C.add (C.smul (bytesToNatBE hash * inv s C.n % C.n) C.g)
      (C.smul (x % C.n * inv s C.n % C.n) (some (qx'.val, qy'.val))) = some (x, y_k) := by
    rw [h_g_ofPoint, ← h_dG_eq, C.smul_ofPoint h_odd, C.smul_ofPoint h_odd, C.add_ofPoint h_odd,
      ← h_kG_eq]
    congr 1
    rw [← mul_nsmul, ← add_nsmul, nsmul_mod h_order, nsmul_mod h_order k, ← h_s_eq,
      recombine_eq h_k_reduced h_s_nonzero]
  -- Run the verifier.
  unfold Curve.ecdsaVerify
  rw [if_neg (by simp [h_pub_size, h_hash])]
  simp only [h_qx_decode, h_qy_decode]
  rw [if_neg (by simp [h_on])]
  rw [if_neg (by
    simp only [Bool.or_eq_true, beq_iff_eq, decide_eq_true_eq, not_or]
    rw [← h_s_eq]
    exact ⟨⟨⟨h_r_nonzero, Nat.not_le.mpr (Nat.mod_lt _ h_n_pos)⟩, h_s_nonzero⟩,
      Nat.not_le.mpr (Nat.mod_lt _ h_n_pos)⟩)]
  simp only [h_recombine, beq_self_eq_true]

end Spec.Weierstrass
