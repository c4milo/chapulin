import Spec.X25519Edwards
import Spec.Ed25519ModL
import Spec.Ed25519Decode

/-!
# The DNSSEC Ed25519 check's equation

`ed25519_verify_hram` (`x25519_wide_ed25519.h`) checks an Ed25519 signature
(R, S) by RFC 8032 §5.1.7 without the cofactor
(https://github.com/c4milo/chapulin/issues/189): it computes [S]B + [h](-A)
for h = SHA-512(R ‖ A ‖ M) mod L, and compares the point's encoding with
R's bytes. This module models the loop that computes the point, from the
C, and proves what it computes.

* `loop` is the C's loop over points of the curve: from bit k - 1 down to
  bit 0, a doubling, then B added where S has the bit, then -A added where
  h has it.
* `loopExtended` is the same loop in extended coordinates, as the C runs
  it, over `Spec.X25519Edwards`'s `doublePoint`, `addEntry` and
  `toExtended`, with B's entry and the entry of (-x, y) for A = (x, y).
* `pointR` is the encoding of the loop's point over `ZMod p`, for
  `bin/diff_ed25519`: `decode`, `reduceModL`, `loopExtended` from the
  identity over 253 bits, and the point's y with its x's low bit as bit
  255. `verifyR` is the whole check: the refusals of an S at or above L,
  of a key `decode` refuses and of a key of small order, then `pointR`.
  It is the R that the C accepts, and nothing for a refusal.

`toMont_loop` proves that the image of `loop` under
`Spec.X25519Edwards.toMont`, a map to a group of Mathlib that takes sums
to sums, is 2^k times the image of the start plus `S mod 2^k` times B's
image less `h mod 2^k` times A's. `loopExtended_represents` proves that
the extended loop holds `loop`'s point at every step, and `verify_point`
puts the two together: from the identity, over the 253 bits below L's top,
the C's affine x and y are those of a point whose image is S B - h A. Both
hold in every field in which 2 is not zero, d is not a square and -1 is.

What no theorem here states: that `ZMod p`, with p = 2^255 - 19, is such
a field, which needs p to be prime, and that `verifyR` is the composition
of the theorems' parts over it. `bin/diff_ed25519` holds the C to `verifyR`, and the Wycheproof
suite holds both to RFC 8032's verdicts.

This module is written from the C, not from a standard, and CONTRACT.md
says why.
-/

namespace Spec.Ed25519Verify

open Spec.X25519Edwards

section Loop

variable {F : Type*} [Field F] [DecidableEq F] {c : Params F}

/-- The C's loop over points: bits `k - 1` down to 0 of `s` and `h`, from `acc`. -/
def loop (B A : EdPoint c) (s h : ℕ) : ℕ → EdPoint c → EdPoint c
  | 0, acc => acc
  | k + 1, acc =>
    let acc := acc.add acc
    let acc := if s.testBit k then acc.add B else acc
    let acc := if h.testBit k then acc.add A.neg else acc
    loop B A s h k acc

/-- A bit of `n` as a number. -/
theorem bit_val (n k : ℕ) : (if n.testBit k then 1 else 0) = n / 2 ^ k % 2 := by
  rw [Nat.testBit_eq_decide_div_mod_eq]
  rcases Nat.mod_two_eq_zero_or_one (n / 2 ^ k) with h | h <;> simp [h]

/-- The image of the loop: the start doubled k times, plus `S mod 2^k` times B and less
`h mod 2^k` times A. -/
theorem toMont_loop (B A : EdPoint c) (s h : ℕ) :
    ∀ (k : ℕ) (acc : EdPoint c), toMont (loop B A s h k acc) =
      ((2 ^ k : ℕ) : ℤ) • toMont acc + ((s % 2 ^ k : ℕ) : ℤ) • toMont B -
        ((h % 2 ^ k : ℕ) : ℤ) • toMont A := by
  intro k
  induction k with
  | zero => intro acc; simp [loop]
  | succ k ih =>
    intro acc
    have h_step : toMont ((if h.testBit k then
        (if s.testBit k then (acc.add acc).add B else acc.add acc).add A.neg
        else (if s.testBit k then (acc.add acc).add B else acc.add acc))) =
        (2 : ℤ) • toMont acc + ((s / 2 ^ k % 2 : ℕ) : ℤ) • toMont B -
          ((h / 2 ^ k % 2 : ℕ) : ℤ) • toMont A := by
      rw [← bit_val s k, ← bit_val h k]
      split_ifs <;> simp only [toMont_add, toMont_neg] <;> push_cast <;> module
    simp only [loop]
    rw [ih, h_step, Nat.mod_pow_succ (x := s), Nat.mod_pow_succ (x := h), pow_succ]
    push_cast
    module

/-- The C's loop in extended coordinates, over B's entry and A's negated entry. -/
def loopExtended {R : Type*} [CommRing R] (bEntry aEntry : Entry R) (s h : ℕ) :
    ℕ → Extended R → Extended R
  | 0, acc => acc
  | k + 1, acc =>
    let acc := toExtended (doublePoint acc)
    let acc := if s.testBit k then toExtended (addEntry acc bEntry) else acc
    let acc := if h.testBit k then toExtended (addEntry acc aEntry) else acc
    loopExtended bEntry aEntry s h k acc

omit [DecidableEq F] in
/-- The extended loop holds the loop's point at every step. -/
theorem loopExtended_represents (B A : EdPoint c) (s h : ℕ) :
    ∀ (k : ℕ) (acc : EdPoint c) (a : Extended F), Represents a (acc.x, acc.y) →
      Represents (loopExtended (entryOf c.d B.x B.y) (entryOf c.d (-A.x) A.y) s h k a)
        ((loop B A s h k acc).x, (loop B A s h k acc).y) := by
  intro k
  induction k with
  | zero => intro acc a h_a; exact h_a
  | succ k ih =>
    intro acc a h_a
    simp only [loopExtended, loop]
    apply ih
    have h_double := doublePoint_represents_add acc h_a
    have h_b : Represents (if s.testBit k then toExtended (addEntry (toExtended (doublePoint a))
        (entryOf c.d B.x B.y)) else toExtended (doublePoint a))
        ((if s.testBit k then (acc.add acc).add B else acc.add acc).x,
          (if s.testBit k then (acc.add acc).add B else acc.add acc).y) := by
      split_ifs
      · exact addEntry_represents_add (acc.add acc) B h_double
      · exact h_double
    split_ifs at h_b ⊢ <;>
      first
      | exact h_b
      | exact addEntry_represents_add _ A.neg h_b

/-- The C's point: from the identity over the 253 bits below L's top, for S and h below 2^253,
its affine x and y are those of a point whose image is S B - h A. -/
theorem verify_point (B A : EdPoint c) {s h : ℕ} (h_s : s < 2 ^ 253) (h_h : h < 2 ^ 253) :
    let a := loopExtended (entryOf c.d B.x B.y) (entryOf c.d (-A.x) A.y) s h 253 ⟨0, 1, 1, 0⟩
    ∃ P : EdPoint c, a.x * a.z⁻¹ = P.x ∧ a.y * a.z⁻¹ = P.y ∧
      toMont P = (s : ℤ) • toMont B - (h : ℤ) • toMont A := by
  intro a
  obtain ⟨h_z, h_x, h_y, -⟩ := loopExtended_represents B A s h 253 EdPoint.identity _
    identity_represents
  refine ⟨loop B A s h 253 EdPoint.identity, ?_, ?_, ?_⟩
  · rw [h_x, mul_assoc, mul_inv_cancel₀ h_z, mul_one]
  · rw [h_y, mul_assoc, mul_inv_cancel₀ h_z, mul_one]
  · rw [toMont_loop, toMont_identity', smul_zero, zero_add, Nat.mod_eq_of_lt h_s,
      Nat.mod_eq_of_lt h_h]

end Loop

section Check

/-- The base point B's x, the even root of its y (RFC 8032 §5.1). -/
def baseX : ZMod Ed25519Decode.p :=
  ((15112221349535400772501151409588531511454012693041857206046113283949847762202 : ℕ) :
    ZMod Ed25519Decode.p)

/-- The base point B's y, 4 / 5. -/
def baseY : ZMod Ed25519Decode.p :=
  ((46316835694926478169428394003475163141307993866256225615783033603165251855960 : ℕ) :
    ZMod Ed25519Decode.p)

/-- The encoding of the loop's point for a key `decode` accepts, with no refusal: y, and x's low
bit as bit 255. -/
def pointR (key hram sigS : ℕ) : Option ℕ :=
  match Ed25519Decode.decode key with
  | none => none
  | some (ax, ay) =>
    let h := Spec.Ed25519ModL.reduceModL hram
    let acc := loopExtended (entryOf Ed25519Decode.d baseX baseY)
      (entryOf Ed25519Decode.d (-ax) ay) sigS h 253 ⟨0, 1, 1, 0⟩
    let x := acc.x * acc.z⁻¹
    let y := acc.y * acc.z⁻¹
    some (y.val + 2 ^ 255 * (x.val % 2))

/-- The C's small-order refusal: [8]A, three doublings, has x zero. -/
def smallOrder (ax ay : ZMod Ed25519Decode.p) : Prop :=
  let a : Extended (ZMod Ed25519Decode.p) := ⟨ax, ay, 1, ax * ay⟩
  (toExtended (doublePoint (toExtended (doublePoint (toExtended (doublePoint a)))))).x = 0

instance (ax ay : ZMod Ed25519Decode.p) : Decidable (smallOrder ax ay) := by
  unfold smallOrder
  infer_instance

/-- The whole check, as `ed25519_verify_hram` runs it: the R it accepts for the key's 32 bytes,
the 64 bytes of SHA-512(R ‖ A ‖ M) and S, all little-endian, or nothing for a refusal of an S at
or above L, a key `decode` refuses or a key of small order. -/
def verifyR (key hram sigS : ℕ) : Option ℕ :=
  if Spec.Ed25519ModL.L ≤ sigS then none
  else
    match Ed25519Decode.decode key with
    | none => none
    | some (ax, ay) => if smallOrder ax ay then none else pointR key hram sigS

end Check

end Spec.Ed25519Verify
