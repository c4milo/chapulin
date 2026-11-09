import Mathlib.Data.ZMod.Basic
import Mathlib.Tactic

/-!
Poly1305's block step on three 64-bit limbs, `poly1305_wide.h`, modeled from the C.

The accumulator is `h0 + h1 2 ^ 64 + h2 2 ^ 128` (`Acc`), and `r` is `r0 + r1 2 ^ 64` (`Key`),
with `s1 = r1 + r1 / 4`. `fold` is the C's `poly1305_wide_fold`: the bits of `h2` at `2 ^ 130`
and up, times 5, added at `2 ^ 0`. `block` is `poly1305_wide_block`: the block and its `2 ^ 128`
bit added with carries, the products of RFC 8439 §2.5's multiply, and a fold. Each `%` and `/`
by `2 ^ 64` is a C narrow or a shift of a 128-bit sum. The model computes over `Nat`, so it
holds the C's values where the C wraps no sum; the `poly1305_wide` CBMC harnesses prove that
at the bounds the step keeps.

`fold_mod` proves that a fold keeps the value modulo `p = 2 ^ 130 - 5`. `block_mod` proves that
a block step computes `(h + m + 2 ^ 128) r` modulo `p` for every `r` whose `r1` is a multiple of
4, which RFC 8439 §2.5.1's clamp makes it. The conversions to and from `poly1305.c`'s five
26-bit words rest on the CBMC harnesses and the equivalence test, not on this module.

This module is written from the C, not from a standard, and CONTRACT.md says why.
-/

namespace Spec.Poly1305Wide

/-- The Poly1305 prime, `2 ^ 130 - 5`. -/
def prime : Nat := 2 ^ 130 - 5

/-- One limb's base, `2 ^ 64`. -/
def base : Nat := 2 ^ 64

/-- The accumulator: three limbs. -/
structure Acc where
  /-- The limb at `2 ^ 0`. -/
  h0 : Nat
  /-- The limb at `2 ^ 64`. -/
  h1 : Nat
  /-- The limb at `2 ^ 128`. -/
  h2 : Nat
  deriving Repr, DecidableEq

/-- The number the limbs hold. -/
def Acc.value (a : Acc) : Nat := a.h0 + base * a.h1 + base ^ 2 * a.h2

/-- `r` in two limbs. -/
structure Key where
  /-- The limb at `2 ^ 0`. -/
  r0 : Nat
  /-- The limb at `2 ^ 64`. -/
  r1 : Nat
  deriving Repr, DecidableEq

/-- The number the key's limbs hold. -/
def Key.value (k : Key) : Nat := k.r0 + base * k.r1

/-- `k->s1`: `r1 + r1 / 4`, which is `5 r1 / 4` when `r1` is a multiple of 4. -/
def Key.s1 (k : Key) : Nat := k.r1 + k.r1 / 4

/-- `poly1305_wide_fold`. -/
def fold (a : Acc) : Acc :=
  let c := a.h2 / 4 * 5
  let t := a.h0 + c
  let t1 := a.h1 + t / base
  ⟨t % base, t1 % base, a.h2 % 4 + t1 / base⟩

/-- `poly1305_wide_block` on the block whose little-endian halves are `m0` and `m1`. -/
def block (a : Acc) (k : Key) (m0 m1 : Nat) : Acc :=
  let t := a.h0 + m0
  let h0 := t % base
  let t' := a.h1 + m1 + t / base
  let h1 := t' % base
  let h2 := a.h2 + 1 + t' / base
  let d0 := h0 * k.r0 + h1 * k.s1
  let d1 := h0 * k.r1 + h1 * k.r0 + h2 * k.s1 + d0 / base
  let d2 := h2 * k.r0 + d1 / base
  fold ⟨d0 % base, d1 % base, d2⟩

/-- `2 ^ 130` is 5 modulo `p`. -/
theorem two_pow_130 : ((2 ^ 130 : Nat) : ZMod prime) = 5 := by
  rw [show (2 ^ 130 : Nat) = prime + 5 by norm_num [prime]]
  push_cast
  simp

/-- `x` is its remainder by `base` and `base` times its quotient, in `ZMod p`. -/
theorem split (x : Nat) : ((x : Nat) : ZMod prime) =
    ((x % base : Nat) : ZMod prime) + (base : ZMod prime) * ((x / base : Nat) : ZMod prime) := by
  conv_lhs => rw [← Nat.mod_add_div x base]
  push_cast
  ring

/-- `2 ^ 128 * 4` is 5 modulo `p`. -/
theorem base_sq : (base : ZMod prime) ^ 2 * 4 = 5 := by
  have h := two_pow_130
  rw [show (2 ^ 130 : Nat) = base ^ 2 * 4 by norm_num [base]] at h
  push_cast at h
  exact h

/-- A fold keeps the value modulo `p`. -/
theorem fold_mod (a : Acc) : ((fold a).value : ZMod prime) = (a.value : ZMod prime) := by
  have hs := base_sq
  have e1 := split (a.h0 + a.h2 / 4 * 5)
  have e2 := split (a.h1 + (a.h0 + a.h2 / 4 * 5) / base)
  have e3 : ((a.h2 : Nat) : ZMod prime) =
      ((a.h2 % 4 : Nat) : ZMod prime) + 4 * ((a.h2 / 4 : Nat) : ZMod prime) := by
    conv_lhs => rw [← Nat.mod_add_div a.h2 4]
    push_cast
    ring
  simp only [fold, Acc.value]
  push_cast at e1 e2 ⊢
  linear_combination (-1 : ZMod prime) * e1 - (base : ZMod prime) * e2 -
    (base : ZMod prime) ^ 2 * e3 - ((a.h2 / 4 : Nat) : ZMod prime) * hs

/-- A block step computes `(h + m0 + 2 ^ 64 m1 + 2 ^ 128) r` modulo `p`, where `r1` is a
multiple of 4. -/
theorem block_mod (a : Acc) (k : Key) (m0 m1 : Nat) (h_r1 : k.r1 % 4 = 0) :
    ((block a k m0 m1).value : ZMod prime) =
      ((a.value + m0 + base * m1 + base ^ 2 : Nat) : ZMod prime) * (k.value : ZMod prime) := by
  have hs := base_sq
  obtain ⟨q, hq⟩ : ∃ q, k.r1 = 4 * q := ⟨k.r1 / 4, by omega⟩
  have h_s1 : k.s1 = 5 * q := by simp only [Key.s1]; omega
  simp only [block]
  rw [fold_mod]
  simp only [Acc.value, Key.value, h_s1, hq]
  have e1 := split (a.h0 + m0)
  have e2 := split (a.h1 + m1 + (a.h0 + m0) / base)
  have e3 := split ((a.h0 + m0) % base * k.r0 + (a.h1 + m1 + (a.h0 + m0) / base) % base * (5 * q))
  have e4 := split ((a.h0 + m0) % base * (4 * q) + (a.h1 + m1 + (a.h0 + m0) / base) % base * k.r0 +
    (a.h2 + 1 + (a.h1 + m1 + (a.h0 + m0) / base) / base) * (5 * q) +
    ((a.h0 + m0) % base * k.r0 + (a.h1 + m1 + (a.h0 + m0) / base) % base * (5 * q)) / base)
  push_cast at e1 e2 e3 e4 ⊢
  linear_combination (-1 : ZMod prime) * e3 - (base : ZMod prime) * e4 -
    ((k.r0 : ZMod prime) + 4 * (base : ZMod prime) * q) * (e1 + (base : ZMod prime) * e2) -
    ((q : ZMod prime) * (((a.h1 + m1 + (a.h0 + m0) / base) % base : Nat) : ZMod prime) +
      (base : ZMod prime) * q *
        ((a.h2 : ZMod prime) + 1 + (((a.h1 + m1 + (a.h0 + m0) / base) / base : Nat) : ZMod prime))) * hs

/-! ## The selftest -/

/-- Horner's rule modulo `p` on numbers, the selftest's reference. -/
private def hornerMod (r : Nat) (h : Nat) (blocks : List (Nat × Nat)) : Nat :=
  blocks.foldl (fun acc b => (acc + b.1 + base * b.2 + base ^ 2) * r % prime) h

set_option compiler.extract_closed false in
/-- Block steps on a clamped key and on blocks of all ones bits and of zero bits, against
Horner's rule modulo `p`, and `h2` at most 4 after them. -/
def selftest (_ : Unit) : Bool :=
  let k : Key := ⟨0x0ffffffc0fffffff, 0x0ffffffc0ffffffc⟩
  let start : Acc := ⟨2 ^ 64 - 1, 2 ^ 64 - 1, 4⟩
  let blocks := (List.range 40).map fun i =>
    if i % 3 == 0 then (0, 0) else (2 ^ 64 - 1, 2 ^ 64 - 1)
  let out := blocks.foldl (fun a b => block a k b.1 b.2) start
  out.value % prime == hornerMod k.value start.value blocks && out.h2 ≤ 4

end Spec.Poly1305Wide
