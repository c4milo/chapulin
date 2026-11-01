import Mathlib

/-!
# The DNSSEC public operation's schedule

`rsa_mont64_public_exp` (rsa_mont64_exp.c) raises a base to a DNSSEC key's
own exponent `e`, odd and at least 3, in the Montgomery domain
(https://github.com/c4milo/chapulin/issues/189). This module models its
schedule over `ZMod m`, where a Montgomery product is `a * b * rInv` and
`r * rInv = 1`, and proves it computes `x ^ e`.

The C runs, with `xr = x * R`:
* `acc := xr`, for `e`'s top bit;
* for each bit `i` from `bitLen e - 2` down to 1: square `acc`, then
  multiply by `xr` where bit `i` is set;
* square `acc` once more, for bit 0, and take the product by `x` itself,
  outside the domain, which divides by `R`.

The invariant is that `acc` holds `x ^ (e >>> i) * R` once the bits above
`i` are in.
-/

namespace Spec.RsaExp

variable {m : ℕ}

/-- The Montgomery product the model takes: `a * b / R`. -/
def mont (rInv a b : ZMod m) : ZMod m := a * b * rInv

/-- The loop over bits `k` down to 1, from `acc`, the C's for-loop. -/
def go (rInv xr : ZMod m) (e : ℕ) : ℕ → ZMod m → ZMod m
  | 0, acc => acc
  | k + 1, acc =>
    go rInv xr e k
      (if e.testBit (k + 1) then mont rInv (mont rInv acc acc) xr else mont rInv acc acc)

/-- The whole operation, as `rsa_mont64_public_exp` runs it. -/
def publicExp (r rInv x : ZMod m) (e : ℕ) : ZMod m :=
  let xr := x * r
  let acc := go rInv xr e (Nat.log2 e - 1) xr
  mont rInv x (mont rInv acc acc)

/-- One bit of the shift: `e >>> j` is twice `e >>> (j+1)`, plus bit `j`. -/
theorem shiftRight_succ (e j : ℕ) :
    e >>> j = 2 * (e >>> (j + 1)) + (if e.testBit j then 1 else 0) := by
  rw [Nat.shiftRight_eq_div_pow, Nat.shiftRight_eq_div_pow, pow_succ, ← Nat.div_div_eq_div_mul]
  have h := Nat.div_add_mod (e / 2 ^ j) 2
  rw [Nat.testBit_eq_decide_div_mod_eq] at *
  rcases Nat.mod_two_eq_zero_or_one (e / 2 ^ j) with h2 | h2 <;> simp [h2] at h ⊢ <;> omega

/-- One squaring in the domain: `x ^ p * R` becomes `x ^ (2 p) * R`. -/
theorem mont_sq {r rInv x : ZMod m} (h : r * rInv = 1) (p : ℕ) :
    mont rInv (x ^ p * r) (x ^ p * r) = x ^ (2 * p) * r := by
  unfold mont
  rw [two_mul, pow_add]
  linear_combination (x ^ p * x ^ p * r) * h

/-- One product by `xr` in the domain: `x ^ q * R` becomes `x ^ (q + 1) * R`. -/
theorem mont_xr {r rInv x : ZMod m} (h : r * rInv = 1) (q : ℕ) :
    mont rInv (x ^ q * r) (x * r) = x ^ (q + 1) * r := by
  unfold mont
  rw [pow_succ]
  linear_combination (x ^ q * x * r) * h

/-- The loop's invariant, carried from bit `k` down to bit 1. -/
theorem go_eq {r rInv x : ZMod m} (h : r * rInv = 1) (e : ℕ) :
    ∀ k : ℕ, go rInv (x * r) e k (x ^ (e >>> (k + 1)) * r) = x ^ (e >>> 1) * r := by
  intro k
  induction k with
  | zero => simp [go]
  | succ k ih =>
    rw [go]
    convert ih using 2
    rw [shiftRight_succ e (k + 1), mont_sq h]
    split_ifs
    · exact mont_xr h _
    · simp

/-- The schedule computes `x ^ e` for every odd `e` of at least 3. -/
theorem publicExp_eq {r rInv x : ZMod m} (h : r * rInv = 1) {e : ℕ} (h_odd : e % 2 = 1)
    (h3 : 3 ≤ e) : publicExp r rInv x e = x ^ e := by
  have hl : 1 ≤ Nat.log2 e := by
    rw [Nat.log2_eq_log_two]
    exact Nat.log_pos (by norm_num) (by omega)
  have htop : e >>> Nat.log2 e = 1 := by
    rw [Nat.shiftRight_eq_div_pow, Nat.log2_eq_log_two]
    have hle := Nat.pow_log_le_self 2 (show e ≠ 0 by omega)
    have hlt := Nat.lt_pow_succ_log_self (by norm_num : 1 < 2) e
    rw [pow_succ] at hlt
    exact Nat.div_eq_of_lt_le (by simpa using hle) (by rw [Nat.succ_mul, one_mul]; linarith)
  have hhalf : 2 * (e >>> 1) + 1 = e := by
    rw [Nat.shiftRight_eq_div_pow]
    omega
  have hgo := go_eq h (x := x) e (Nat.log2 e - 1)
  rw [Nat.sub_add_cancel hl, htop, pow_one] at hgo
  simp only [publicExp]
  rw [hgo, mont_sq h]
  unfold mont
  conv_rhs => rw [← hhalf, pow_succ']
  linear_combination (x * x ^ (2 * (e >>> 1))) * h

end Spec.RsaExp
