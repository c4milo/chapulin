import Mathlib.Tactic
import Spec.RsaExp

/-!
# The DNSSEC Ed25519 check's reduction modulo L

`ed25519_verify_hram` (`x25519_wide_ed25519.h`) reduces the 64-byte hash
SHA-512(R ‖ A ‖ M) modulo the group order L before it reads the hash as a
scalar (RFC 8032 §5.1.7, https://github.com/c4milo/chapulin/issues/189).
`reduce_mod_l` does that one bit at a time from the top, through
`reduce_step`. This module models both from the C, with the four words of a
remainder held as one `Nat` below `2 ^ 256`, and proves that they compute
`h mod L`.

* `step` is `reduce_step`: the four words shifted up by one, which drops
  the top bit of word 3, with the bit in at bit 0, then, where
  `at_or_above_l` holds, the four words less L with the borrow out dropped.
* `reduceModL` is `reduce_mod_l`: `step` from 0 over bits 511 down to 0.

`step_eq` proves that a step from a remainder below L is `(2 o + bit) mod
L`, which is below L, so the doubling never passes `2 ^ 256` and one
subtraction is enough. `reduceModL_eq` proves that the whole reduction is
`h mod L` for every 512-bit h. `bin/diff_ed25519` holds the C to both.

This module is written from the C, not from a standard, and CONTRACT.md
says why.
-/

namespace Spec.Ed25519ModL

/-- The order of edwards25519's base point, `2 ^ 252 +
27742317777372353535851937790883648493` (RFC 8032 §5.1), `ED25519_L`. -/
def L : ℕ := 2 ^ 252 + 27742317777372353535851937790883648493

/-- `reduce_step`: `2 o + bit` in four words, then those words less L where they are at or above
L. The shift writes bit 0 with `|`, which is a sum because the shift leaves that bit clear. -/
def step (o bit : ℕ) : ℕ :=
  let s := 2 * o % 2 ^ 256 + bit
  if L ≤ s then (s + 2 ^ 256 - L) % 2 ^ 256 else s

/-- `reduce_mod_l`'s loop over bits `k - 1` down to 0 of `h`, from `o`. -/
def go (h : ℕ) : ℕ → ℕ → ℕ
  | 0, o => o
  | k + 1, o => go h k (step o (if h.testBit k then 1 else 0))

/-- `reduce_mod_l`: `step` from 0 over the 512 bits of h, from the top. -/
def reduceModL (h : ℕ) : ℕ := go h 512 0

/-- A step from a remainder below L takes in one bit and stays below L. -/
theorem step_eq {o bit : ℕ} (h_o : o < L) (h_bit : bit < 2) : step o bit = (2 * o + bit) % L := by
  have h_double : 2 * o % 2 ^ 256 = 2 * o := Nat.mod_eq_of_lt (by simp only [L] at h_o; omega)
  simp only [step, h_double]
  by_cases h_ge : L ≤ 2 * o + bit
  · rw [if_pos h_ge]
    simp only [L] at *
    omega
  · rw [if_neg h_ge]
    simp only [L] at *
    omega

/-- The loop's invariant: from `(h >>> k) mod L` the bits below k leave `h mod L`. -/
theorem go_eq (h : ℕ) : ∀ k : ℕ, go h k (h >>> k % L) = h % L := by
  intro k
  induction k with
  | zero => simp [go]
  | succ k ih =>
    have h_pos : 0 < L := by simp [L]
    have h_bit : (if h.testBit k then 1 else 0) < 2 := by split_ifs <;> norm_num
    rw [go, step_eq (Nat.mod_lt _ h_pos) h_bit]
    convert ih using 2
    rw [Spec.RsaExp.shiftRight_succ h k, Nat.add_mod, Nat.mul_mod, Nat.mod_mod,
      ← Nat.mul_mod, ← Nat.add_mod]

/-- `reduce_mod_l` writes `h mod L` for every 512-bit h. -/
theorem reduceModL_eq {h : ℕ} (h_lt : h < 2 ^ 512) : reduceModL h = h % L := by
  have h_bits : ∀ n, h < 2 ^ n → go h n 0 = h % L := fun n h_fits => by
    simpa [Nat.shiftRight_eq_zero h n h_fits] using go_eq h n
  exact h_bits 512 h_lt

end Spec.Ed25519ModL
