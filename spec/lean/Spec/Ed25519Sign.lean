import Mathlib.Tactic
import Spec.RsaExp
import Spec.Ed25519ModL

/-!
# The Ed25519 signer's arithmetic modulo L

`ed25519_sign` (`x25519_wide_ed25519_sign.h`, docs/decisions.md 223)
computes two scalars modulo the group order L (RFC 8032 §5.1.6): the nonce
r = SHA-512(prefix ‖ M) mod L, through `scalar_reduce`, and
S = r + k a mod L, through `scalar_muladd`. Both run on secret values, so
each step subtracts L always and keeps one of its two results by mask.
This module models the five functions from the C, with the four words of
a scalar held as one `Nat` below `2 ^ 256`, and proves what the two loops
compute. A select by mask is an `if` here: the model states the value a
step writes, and the taint lane holds how the C writes it (INV-60).

* `settle` is `scalar_settle`: the four words less L with the borrow out
  dropped, kept where the borrow is clear, and the words as they are
  where it is set.
* `double` is `scalar_double`: the four words shifted up by one, which
  drops the top bit of word 3, with the bit in at bit 0, then `settle`.
* `add` is `scalar_add`: the sum of two scalars in four words, with the
  carry out of word 3 dropped, then `settle`.
* `reduce` is `scalar_reduce`: `double` from 0 over the 512 bits of the
  hash, from the top.
* `mulAdd` is `scalar_muladd`: from 0 over the 256 bits of a, from the
  top, a `double` with a 0 bit and then an `add` of k where a has the
  bit; then an `add` of r.

`settle_eq` proves that a value below 2 L leaves as that value mod L.
`double_eq` and `add_eq` follow: from scalars below L, neither the
doubling nor the sum passes 2 L, so nothing passes `2 ^ 256` and one
subtraction is enough. `reduce_eq` proves that the reduction is `h mod L`
for every 512-bit h, and `mulAdd_eq` that `scalar_muladd` writes
`(r + k a) mod L` for r and k below L and every 256-bit a.
`bin/diff_ed25519` holds the C to `reduce` and `mulAdd`.

This module is written from the C, not from a standard, and CONTRACT.md
says why.
-/

namespace Spec.Ed25519Sign

open Spec.Ed25519ModL (L)

/-- `scalar_settle`: the four words less L where they are at or above L, and the words as they
are where they are below it. -/
def settle (o : ℕ) : ℕ :=
  if o < L then o else (o + 2 ^ 256 - L) % 2 ^ 256

/-- `scalar_double`: `2 o + bit` in four words, then `settle`. The shift writes bit 0 with `|`,
which is a sum because the shift leaves that bit clear. -/
def double (o bit : ℕ) : ℕ :=
  settle (2 * o % 2 ^ 256 + bit)

/-- `scalar_add`: `o + a` in four words, then `settle`. -/
def add (o a : ℕ) : ℕ :=
  settle ((o + a) % 2 ^ 256)

/-- `scalar_reduce`'s loop over bits `i - 1` down to 0 of `h`, from `o`. -/
def reduceGo (h : ℕ) : ℕ → ℕ → ℕ
  | 0, o => o
  | i + 1, o => reduceGo h i (double o (if h.testBit i then 1 else 0))

/-- `scalar_reduce`: `double` from 0 over the 512 bits of h, from the top. -/
def reduce (h : ℕ) : ℕ := reduceGo h 512 0

/-- `scalar_muladd`'s loop over bits `i - 1` down to 0 of `a`, from `sum`: a doubling, then k
added where a has the bit. The C adds `k & mask`, which is k or 0. -/
def mulGo (k a : ℕ) : ℕ → ℕ → ℕ
  | 0, sum => sum
  | i + 1, sum => mulGo k a i (add (double sum 0) (if a.testBit i then k else 0))

/-- `scalar_muladd`: the loop from 0 over the 256 bits of a, from the top, then r added. -/
def mulAdd (r k a : ℕ) : ℕ := add (mulGo k a 256 0) r

theorem L_pos : 0 < L := by simp [L]

/-- A value below 2 L leaves `settle` as that value mod L. -/
theorem settle_eq {o : ℕ} (h_o : o < 2 * L) : settle o = o % L := by
  unfold settle
  by_cases h_below : o < L
  · rw [if_pos h_below, Nat.mod_eq_of_lt h_below]
  · rw [if_neg h_below]
    simp only [L] at *
    omega

/-- A doubling of a scalar below L takes in one bit and stays below L. -/
theorem double_eq {o bit : ℕ} (h_o : o < L) (h_bit : bit < 2) :
    double o bit = (2 * o + bit) % L := by
  have h_fits : 2 * o % 2 ^ 256 = 2 * o := Nat.mod_eq_of_lt (by simp only [L] at h_o; omega)
  rw [double, h_fits, settle_eq (by omega)]

/-- The sum of two scalars below L, modulo L. -/
theorem add_eq {o a : ℕ} (h_o : o < L) (h_a : a < L) : add o a = (o + a) % L := by
  have h_fits : (o + a) % 2 ^ 256 = o + a :=
    Nat.mod_eq_of_lt (by simp only [L] at h_o h_a; omega)
  rw [add, h_fits, settle_eq (by omega)]

/-- The reduction's invariant: from `(h >>> i) mod L` the bits below i leave `h mod L`. -/
theorem reduceGo_eq (h : ℕ) : ∀ i : ℕ, reduceGo h i (h >>> i % L) = h % L := by
  intro i
  induction i with
  | zero => simp [reduceGo]
  | succ i ih =>
    have h_bit : (if h.testBit i then 1 else 0) < 2 := by split_ifs <;> norm_num
    rw [reduceGo, double_eq (Nat.mod_lt _ L_pos) h_bit]
    convert ih using 2
    rw [Spec.RsaExp.shiftRight_succ h i, Nat.add_mod, Nat.mul_mod, Nat.mod_mod,
      ← Nat.mul_mod, ← Nat.add_mod]

/-- `scalar_reduce` writes `h mod L` for every 512-bit h. -/
theorem reduce_eq {h : ℕ} (h_fits : h < 2 ^ 512) : reduce h = h % L := by
  have h_bits : ∀ n, h < 2 ^ n → reduceGo h n 0 = h % L := fun n h_below => by
    simpa [Nat.shiftRight_eq_zero h n h_below] using reduceGo_eq h n
  exact h_bits 512 h_fits

/-- One step of the product: twice `k q mod L`, plus k where the bit is set, is
`k (2 q + bit) mod L`. -/
theorem mulStep_eq (k q : ℕ) (bit : Bool) :
    ((2 * (k * q % L) + 0) % L + if bit then k else 0) % L =
      k * (2 * q + if bit then 1 else 0) % L := by
  have h_double : (2 * (k * q % L) + 0) % L = 2 * (k * q) % L := by
    rw [Nat.add_zero, Nat.mul_mod, Nat.mod_mod, ← Nat.mul_mod]
  rw [h_double, Nat.mod_add_mod]
  congr 1
  cases bit <;> simp <;> ring

/-- The product's invariant: from `k (a >>> i) mod L` the bits below i leave `k a mod L`. -/
theorem mulGo_eq {k : ℕ} (h_k : k < L) (a : ℕ) :
    ∀ i : ℕ, mulGo k a i (k * (a >>> i) % L) = k * a % L := by
  intro i
  induction i with
  | zero => simp [mulGo]
  | succ i ih =>
    have h_term : (if a.testBit i then k else 0) < L := by
      split_ifs <;> first | exact h_k | exact L_pos
    rw [mulGo, double_eq (Nat.mod_lt _ L_pos) (by norm_num), add_eq (Nat.mod_lt _ L_pos) h_term]
    convert ih using 2
    rw [mulStep_eq, ← Spec.RsaExp.shiftRight_succ a i]

/-- `scalar_muladd` writes `(r + k a) mod L`, RFC 8032 §5.1.6's S, for r and k below L and every
256-bit a. -/
theorem mulAdd_eq {r k a : ℕ} (h_r : r < L) (h_k : k < L) (h_a : a < 2 ^ 256) :
    mulAdd r k a = (r + k * a) % L := by
  have h_product : mulGo k a 256 0 = k * a % L := by
    simpa [Nat.shiftRight_eq_zero a 256 h_a] using mulGo_eq h_k a 256
  rw [mulAdd, h_product, add_eq (Nat.mod_lt _ L_pos) h_r, Nat.mod_add_mod, Nat.add_comm]

end Spec.Ed25519Sign
