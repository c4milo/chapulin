import Mathlib.Tactic
import Spec.RsaMont64Adx

/-!
The long division of `rsa_mont.c`'s host arm, `rsa_mont_division.h`, and the public operation
it starts, modeled from the C on a `Nat` (docs/decisions.md 103 and 208).

For a modulus `m` of `k` words whose top bit is set, `rsa_vp1` computes no `R ^ 2`, with
`R = 2 ^ (64 k)`. `public_by_division` subtracts `m` from the base once (`finalSub`), and
`times_r_mod` multiplies the result by `R` modulo `m` in `k` steps (`timesR`). Sixteen Montgomery
squares and a Montgomery product by the base follow (`publicOp`).

A step, `times_word_mod`, multiplies a remainder below `m` by `2 ^ 64` modulo `m`.
`quotient_estimate` divides the remainder's top two words by `m`'s top word (`estimate`). The
step subtracts the estimate times `m` and adds `m` back while the difference is below zero, at
most twice (`addBack`, `timesWord`). The C holds the difference in two's complement over `k + 1`
words, and this module holds it as an `Int`. `times_word_mod_blocks` adds the estimate times
`R - m` to the remainder moved up one word, and takes the estimate off the word above the `k`
(`timesWordBlocks`).

`quotient_le_estimate` and `estimate_le_quotient_add_two` prove Knuth's Theorem B for the
estimate: it is the quotient or at most 2 above it. `timesWord_eq` proves that a step writes
`rem 2 ^ 64 mod m`, `timesWordBlocks_eq` that the step in blocks writes the same value, and
`timesR_eq` that `k` steps write `x R mod m`. `publicOp_eq` proves that the public operation
writes `sig ^ 65537 mod m`.

This module is written from the C, not from a standard, and CONTRACT.md says why.
-/

namespace Spec.RsaDivision

open Spec.RsaMont64Adx (word div_succ finalSub finalSub_lt finalSub_mod montMul montMul_lt
  montMul_mod)

/-- `quotient_estimate`: the top two words of `rem` divided by the top word of `m`, and
`2 ^ 64 - 1` where the top word of `rem` is not below `m`'s. -/
def estimate (k m rem : Nat) : Nat :=
  if word rem (k - 1) < word m (k - 1) then
    (word rem (k - 1) * 2 ^ 64 + word rem (k - 2)) / word m (k - 1)
  else
    2 ^ 64 - 1

/-- The two passes that end a step: each adds `m` where the value is below zero. -/
def addBack (m : Nat) (v : Int) : Int :=
  if v < 0 then (if v + m < 0 then v + m + m else v + m) else v

/-- `times_word_mod`: `rem 2 ^ 64` less the estimate times `m`, then the two passes. -/
def timesWord (k m rem : Nat) : Nat :=
  (addBack m (((rem * 2 ^ 64 : Nat) : Int) - ((estimate k m rem * m : Nat) : Int))).toNat

/-- `times_word_mod_blocks`: `rem 2 ^ 64` plus the estimate times `R - m`, less the estimate at
the word above the `k`, then the two passes. -/
def timesWordBlocks (k m rem : Nat) : Nat :=
  (addBack m (((rem * 2 ^ 64 + estimate k m rem * (2 ^ (64 * k) - m) : Nat) : Int) -
    ((estimate k m rem * 2 ^ (64 * k) : Nat) : Int))).toNat

/-- `times_r_mod` after `i` steps from `x`. -/
def timesR (k m : Nat) : Nat → Nat → Nat
  | 0, x => x
  | i + 1, x => timesWord k m (timesR k m i x)

/-- `public_by_division`: the base less `m` once, `k` steps of the division, sixteen Montgomery
squares, and a Montgomery product by the base. -/
def publicOp (k m m0inv sig : Nat) : Nat :=
  montMul k m m0inv (finalSub m sig)
    ((fun a => montMul k m m0inv a a)^[16] (timesR k m k (finalSub m sig)))

/-! ## Knuth's Theorem B on plain numbers

`m` is `d B P` plus lower words, `r` is `U P` plus lower words, and `q` is `r B / m`. -/

/-- The quotient times the divisor's top word is at most the dividend's top words. -/
theorem quotient_mul_le {B P d m r U q : Nat} (h_word : 0 < B) (h_top : d * (B * P) ≤ m)
    (h_dividend : r < (U + 1) * P) (h_quotient : q * m ≤ r * B) : q * d ≤ U := by
  have h_scaled : q * (d * (B * P)) ≤ q * m := Nat.mul_le_mul_left q h_top
  have h_moved : (r + 1) * B ≤ (U + 1) * P * B := Nat.mul_le_mul_right B h_dividend
  have h_below : q * d * (B * P) < (U + 1) * (B * P) := by nlinarith
  exact Nat.lt_succ_iff.mp (Nat.lt_of_mul_lt_mul_right h_below)

/-- An estimate whose product with the divisor's top word is at most the dividend's top words is
at most 2 above the quotient, where the divisor's top word is at least half of `B`. -/
theorem estimate_le {B P d m r U q e : Nat} (h_top : m < (d + 1) * (B * P))
    (h_half : B ≤ 2 * d) (h_dividend : U * P ≤ r) (h_quotient : r * B < (q + 1) * m)
    (h_fits : q < B) (h_estimate : e * d ≤ U) : e ≤ q + 2 := by
  by_contra h_far
  have h_three : (q + 3) * d ≤ U :=
    le_trans (Nat.mul_le_mul_right d (by omega)) h_estimate
  have h_scaled : (q + 3) * d * (B * P) ≤ U * (B * P) := Nat.mul_le_mul_right (B * P) h_three
  have h_moved : U * P * B ≤ r * B := Nat.mul_le_mul_right B h_dividend
  have h_modulus : (q + 1) * (m + 1) ≤ (q + 1) * ((d + 1) * (B * P)) :=
    Nat.mul_le_mul_left (q + 1) h_top
  have h_below : (q + 3) * d * (B * P) < (q + 1) * (d + 1) * (B * P) := by nlinarith
  have h_words : (q + 3) * d < (q + 1) * (d + 1) := Nat.lt_of_mul_lt_mul_right h_below
  nlinarith

/-! ## The words of the C -/

/-- The top word of a number below `2 ^ (64 (j + 2))` is the number over `2 ^ (64 (j + 1))`. -/
theorem top_word {x j : Nat} (h_x : x < 2 ^ (64 * (j + 2))) :
    word x (j + 1) = x / 2 ^ (64 * (j + 1)) := by
  unfold word
  apply Nat.mod_eq_of_lt
  rw [Nat.div_lt_iff_lt_mul (by positivity), ← pow_add]
  convert h_x using 2
  ring

/-- Its top two words are the number over `2 ^ (64 j)`. -/
theorem top_two_words {x j : Nat} (h_x : x < 2 ^ (64 * (j + 2))) :
    word x (j + 1) * 2 ^ 64 + word x j = x / 2 ^ (64 * j) := by
  rw [top_word h_x, div_succ x j]
  ring

/-- The estimate is the quotient or at most 2 above it: Knuth's Theorem B (The Art of Computer
Programming, vol. 2, 4.3.1), for a modulus of `k` words whose top bit is set and a remainder
below it. -/
theorem estimate_bounds {k m rem : Nat} (h_k : 2 ≤ k) (h_top : 2 ^ (64 * k - 1) ≤ m)
    (h_m : m < 2 ^ (64 * k)) (h_rem : rem < m) :
    rem * 2 ^ 64 / m ≤ estimate k m rem ∧ estimate k m rem ≤ rem * 2 ^ 64 / m + 2 := by
  obtain ⟨j, rfl⟩ : ∃ j, k = j + 2 := ⟨k - 2, by omega⟩
  have h_m_pos : 0 < m := Nat.lt_of_le_of_lt (Nat.zero_le _) h_rem
  have h_word_pos : (0 : Nat) < 2 ^ 64 := by positivity
  have h_low_pos : (0 : Nat) < 2 ^ (64 * j) := by positivity
  have h_split : (2 : Nat) ^ (64 * (j + 1)) = 2 ^ 64 * 2 ^ (64 * j) := by
    rw [show 64 * (j + 1) = 64 + 64 * j by ring, pow_add]
  have h_half_split : (2 : Nat) ^ (64 * (j + 2) - 1) = 2 ^ 63 * (2 ^ 64 * 2 ^ (64 * j)) := by
    rw [show 64 * (j + 2) - 1 = 63 + (64 + 64 * j) by omega, pow_add, pow_add]
  -- The divisor's top word, d, and the dividend's top two words, U.
  have h_d_low : m / (2 ^ 64 * 2 ^ (64 * j)) * (2 ^ 64 * 2 ^ (64 * j)) ≤ m :=
    Nat.div_mul_le_self _ _
  have h_d_high : m < (m / (2 ^ 64 * 2 ^ (64 * j)) + 1) * (2 ^ 64 * 2 ^ (64 * j)) := by
    rw [Nat.mul_comm]
    exact Nat.lt_mul_div_succ m (by positivity)
  have h_d_half : 2 ^ 64 ≤ 2 * (m / (2 ^ 64 * 2 ^ (64 * j))) := by
    have h_d_bit : 2 ^ 63 ≤ m / (2 ^ 64 * 2 ^ (64 * j)) := by
      rw [Nat.le_div_iff_mul_le (by positivity)]
      rw [h_half_split] at h_top
      exact h_top
    calc (2 : Nat) ^ 64 = 2 * 2 ^ 63 := by norm_num
      _ ≤ 2 * (m / (2 ^ 64 * 2 ^ (64 * j))) := Nat.mul_le_mul_left 2 h_d_bit
  have h_u_low : rem / 2 ^ (64 * j) * 2 ^ (64 * j) ≤ rem := Nat.div_mul_le_self _ _
  have h_u_high : rem < (rem / 2 ^ (64 * j) + 1) * 2 ^ (64 * j) := by
    rw [Nat.mul_comm]
    exact Nat.lt_mul_div_succ rem h_low_pos
  -- The quotient, q.
  have h_q_low : rem * 2 ^ 64 / m * m ≤ rem * 2 ^ 64 := Nat.div_mul_le_self _ _
  have h_q_high : rem * 2 ^ 64 < (rem * 2 ^ 64 / m + 1) * m := by
    have h_next := Nat.lt_mul_div_succ (rem * 2 ^ 64) h_m_pos
    rwa [Nat.mul_comm m] at h_next
  have h_q_fits : rem * 2 ^ 64 / m < 2 ^ 64 := by
    rw [Nat.div_lt_iff_lt_mul h_m_pos]
    nlinarith
  have h_q_top := quotient_mul_le h_word_pos h_d_low h_u_high h_q_low
  -- The words the C reads.
  have h_m_word : word m (j + 1) = m / (2 ^ 64 * 2 ^ (64 * j)) := by rw [top_word h_m, h_split]
  have h_rem_word : word rem (j + 1) = rem / (2 ^ 64 * 2 ^ (64 * j)) := by
    rw [top_word (h_rem.trans h_m), h_split]
  have h_rem_words := top_two_words (h_rem.trans h_m)
  have h_d_pos : 0 < m / (2 ^ 64 * 2 ^ (64 * j)) := by omega
  -- The estimate times d is at most U, in both arms.
  have h_estimate_top :
      estimate (j + 2) m rem * (m / (2 ^ 64 * 2 ^ (64 * j))) ≤ rem / 2 ^ (64 * j) := by
    unfold estimate
    simp only [Nat.add_sub_cancel, show j + 2 - 1 = j + 1 from rfl, h_m_word, h_rem_words]
    split_ifs with h_below
    · exact Nat.div_mul_le_self _ _
    · rw [h_rem_word] at h_below
      rw [← h_rem_words, h_rem_word]
      calc (2 ^ 64 - 1) * (m / (2 ^ 64 * 2 ^ (64 * j)))
          ≤ 2 ^ 64 * (m / (2 ^ 64 * 2 ^ (64 * j))) := Nat.mul_le_mul_right _ (Nat.sub_le _ _)
        _ ≤ 2 ^ 64 * (rem / (2 ^ 64 * 2 ^ (64 * j))) :=
          Nat.mul_le_mul_left _ (Nat.le_of_not_lt h_below)
        _ = rem / (2 ^ 64 * 2 ^ (64 * j)) * 2 ^ 64 := Nat.mul_comm _ _
        _ ≤ rem / (2 ^ 64 * 2 ^ (64 * j)) * 2 ^ 64 + word rem j := Nat.le_add_right _ _
  refine ⟨?_, estimate_le h_d_high h_d_half h_u_low h_q_high h_q_fits h_estimate_top⟩
  unfold estimate
  simp only [Nat.add_sub_cancel, show j + 2 - 1 = j + 1 from rfl, h_m_word, h_rem_words]
  split_ifs with h_below
  · exact (Nat.le_div_iff_mul_le h_d_pos).mpr h_q_top
  · omega

/-- The quotient is at most the estimate. -/
theorem quotient_le_estimate {k m rem : Nat} (h_k : 2 ≤ k) (h_top : 2 ^ (64 * k - 1) ≤ m)
    (h_m : m < 2 ^ (64 * k)) (h_rem : rem < m) : rem * 2 ^ 64 / m ≤ estimate k m rem :=
  (estimate_bounds h_k h_top h_m h_rem).1

/-- The estimate is at most 2 above the quotient. -/
theorem estimate_le_quotient_add_two {k m rem : Nat} (h_k : 2 ≤ k)
    (h_top : 2 ^ (64 * k - 1) ≤ m) (h_m : m < 2 ^ (64 * k)) (h_rem : rem < m) :
    estimate k m rem ≤ rem * 2 ^ 64 / m + 2 :=
  (estimate_bounds h_k h_top h_m h_rem).2

/-! ## A step, and `k` steps -/

/-- The two passes bring a remainder that is 0, 1 or 2 moduli below zero back. -/
theorem addBack_eq {m r c : Nat} (h_r : r < m) (h_c : c ≤ 2) :
    addBack m ((r : Int) - ((c * m : Nat) : Int)) = r := by
  unfold addBack
  interval_cases c <;> split_ifs <;> omega

/-- The estimate times `R - m` added, and the estimate times `R` taken off, is the estimate
times `m` taken off. -/
theorem blocks_sum {a q R m : Nat} (h_m : m ≤ R) :
    ((a + q * (R - m) : Nat) : Int) - ((q * R : Nat) : Int) =
      ((a : Nat) : Int) - ((q * m : Nat) : Int) := by
  have h_parts : q * (R - m) + q * m = q * R := by rw [← Nat.mul_add, Nat.sub_add_cancel h_m]
  omega

/-- `timesWord_eq`: a step writes `rem 2 ^ 64 mod m`. -/
theorem timesWord_eq {k m rem : Nat} (h_k : 2 ≤ k) (h_top : 2 ^ (64 * k - 1) ≤ m)
    (h_m : m < 2 ^ (64 * k)) (h_rem : rem < m) : timesWord k m rem = rem * 2 ^ 64 % m := by
  have h_m_pos : 0 < m := Nat.lt_of_le_of_lt (Nat.zero_le _) h_rem
  obtain ⟨h_at_least, h_at_most⟩ := estimate_bounds h_k h_top h_m h_rem
  obtain ⟨c, h_over⟩ : ∃ c, estimate k m rem = rem * 2 ^ 64 / m + c :=
    ⟨_, (Nat.add_sub_cancel' h_at_least).symm⟩
  have h_division := Nat.div_add_mod (rem * 2 ^ 64) m
  have h_difference : ((rem * 2 ^ 64 : Nat) : Int) - ((estimate k m rem * m : Nat) : Int) =
      ((rem * 2 ^ 64 % m : Nat) : Int) - ((c * m : Nat) : Int) := by
    rw [h_over]
    generalize rem * 2 ^ 64 = dividend at h_division ⊢
    have h_product : (dividend / m + c) * m = m * (dividend / m) + c * m := by ring
    omega
  unfold timesWord
  rw [h_difference, addBack_eq (Nat.mod_lt _ h_m_pos) (by omega), Int.toNat_natCast]

/-- `timesWordBlocks_eq`: the step in blocks writes the value of `timesWord`. -/
theorem timesWordBlocks_eq {k m : Nat} (rem : Nat) (h_m : m < 2 ^ (64 * k)) :
    timesWordBlocks k m rem = timesWord k m rem := by
  unfold timesWordBlocks timesWord
  rw [blocks_sum h_m.le]

/-- `timesR_eq`: `i` steps from an `x` below `m` write `x 2 ^ (64 i) mod m`. -/
theorem timesR_eq {k m x : Nat} (h_k : 2 ≤ k) (h_top : 2 ^ (64 * k - 1) ≤ m)
    (h_m : m < 2 ^ (64 * k)) (h_x : x < m) (i : Nat) :
    timesR k m i x = x * 2 ^ (64 * i) % m := by
  have h_m_pos : 0 < m := Nat.lt_of_le_of_lt (Nat.zero_le _) h_x
  induction i with
  | zero => simp [timesR, Nat.mod_eq_of_lt h_x]
  | succ i ih =>
    rw [timesR, ih, timesWord_eq h_k h_top h_m (Nat.mod_lt _ h_m_pos), Nat.mod_mul_mod,
      show 64 * (i + 1) = 64 * i + 64 by ring, pow_add, Nat.mul_assoc]

/-! ## The public operation -/

/-- A modulus that has `m0inv` is odd, so it is coprime to every power of 2. -/
theorem coprime_pow_two {m m0inv : Nat} (h_inv : (m * m0inv + 1) % 2 ^ 64 = 0) (n : Nat) :
    Nat.gcd m (2 ^ n) = 1 := by
  have h_even_sum : 2 ∣ m * m0inv + 1 :=
    Dvd.dvd.trans (by norm_num : 2 ∣ 2 ^ 64) (Nat.dvd_of_mod_eq_zero h_inv)
  have h_odd : ¬2 ∣ m := by
    intro h_even
    have h_one : 2 ∣ 1 := (Nat.dvd_add_right (Dvd.dvd.mul_right h_even m0inv)).mp h_even_sum
    omega
  exact Nat.Coprime.pow_right n
    (Nat.Coprime.symm ((Nat.Prime.coprime_iff_not_dvd Nat.prime_two).mpr h_odd))

/-- After `n` Montgomery squares from `b R mod m`, the value is below `m` and is
`b ^ (2 ^ n) R` modulo `m`. -/
theorem squares_spec {k m m0inv b : Nat} (h_inv : (m * m0inv + 1) % 2 ^ 64 = 0)
    (h_m : m < 2 ^ (64 * k)) (h_m_pos : 0 < m) (n : Nat) :
    (fun a => montMul k m m0inv a a)^[n] (b * 2 ^ (64 * k) % m) < m ∧
      (fun a => montMul k m m0inv a a)^[n] (b * 2 ^ (64 * k) % m) ≡
        b ^ 2 ^ n * 2 ^ (64 * k) [MOD m] := by
  induction n with
  | zero =>
    refine ⟨Nat.mod_lt _ h_m_pos, ?_⟩
    simpa using Nat.mod_modEq _ _
  | succ n ih =>
    obtain ⟨h_below, h_value⟩ := ih
    rw [Function.iterate_succ_apply']
    refine ⟨montMul_lt h_inv h_m h_below h_below, ?_⟩
    apply Nat.ModEq.cancel_right_of_coprime (coprime_pow_two h_inv (64 * k))
    have h_square : montMul k m m0inv _ _ * 2 ^ (64 * k) ≡ _ [MOD m] :=
      montMul_mod h_inv h_m h_below h_below
    refine h_square.trans ((h_value.mul h_value).trans ?_)
    rw [pow_succ 2 n, pow_mul b (2 ^ n) 2]
    unfold Nat.ModEq
    congr 1
    ring

/-- `publicOp_eq`: for a modulus of `k` words whose top bit is set and a base of `k` words, the
public operation writes `sig ^ 65537 mod m` (RSAVP1, RFC 8017 5.2.2). -/
theorem publicOp_eq {k m m0inv sig : Nat} (h_inv : (m * m0inv + 1) % 2 ^ 64 = 0) (h_k : 2 ≤ k)
    (h_top : 2 ^ (64 * k - 1) ≤ m) (h_m : m < 2 ^ (64 * k)) (h_sig : sig < 2 ^ (64 * k)) :
    publicOp k m m0inv sig = sig ^ 65537 % m := by
  have h_twice : 2 ^ (64 * k) = 2 * 2 ^ (64 * k - 1) := by
    rw [← pow_succ', show 64 * k - 1 + 1 = 64 * k by omega]
  have h_m_pos : 0 < m := lt_of_lt_of_le (by positivity) h_top
  have h_base : finalSub m sig < m := finalSub_lt (by omega)
  have h_base_mod : finalSub m sig ≡ sig [MOD m] := finalSub_mod m sig
  obtain ⟨h_below, h_value⟩ := squares_spec (b := finalSub m sig) h_inv h_m h_m_pos 16
  unfold publicOp
  rw [timesR_eq h_k h_top h_m h_base k]
  have h_result := montMul_lt h_inv h_m h_base h_below
  have h_product : montMul k m m0inv (finalSub m sig) _ * 2 ^ (64 * k) ≡ _ [MOD m] :=
    montMul_mod h_inv h_m h_base h_below
  have h_power : montMul k m m0inv (finalSub m sig)
      ((fun a => montMul k m m0inv a a)^[16] (finalSub m sig * 2 ^ (64 * k) % m)) ≡
      sig ^ 65537 [MOD m] := by
    apply Nat.ModEq.cancel_right_of_coprime (coprime_pow_two h_inv (64 * k))
    refine h_product.trans (((Nat.ModEq.refl _).mul h_value).trans ?_)
    have h_exponent : finalSub m sig * (finalSub m sig ^ 2 ^ 16 * 2 ^ (64 * k)) =
        finalSub m sig ^ 65537 * 2 ^ (64 * k) := by
      rw [show (65537 : Nat) = 2 ^ 16 + 1 by norm_num, pow_succ]; ring
    rw [h_exponent]
    exact (h_base_mod.pow 65537).mul_right _
  rw [← Nat.mod_eq_of_lt h_result]
  exact h_power

/-! ## Selftest -/

/-- Checks of the model against `Nat` arithmetic at two words: a step in both forms, at the
remainder `m - 1`, whose estimate is `2 ^ 64 - 1`, at 0 and at two more remainders, then `k`
steps, and the public operation for a base below `m` and for one above it. -/
def selftest (_ : Unit) : Bool :=
  let k := 2
  let m := 2 ^ 127 + 2 ^ 64 + 1
  -- m is 1 mod 2 ^ 64, so m⁻¹ is 1 and m0inv is 2 ^ 64 - 1.
  let m0inv := 2 ^ 64 - 1
  let x := 2 ^ 126 + 12345
  let step := fun rem => timesWord k m rem == rem * 2 ^ 64 % m &&
    timesWordBlocks k m rem == rem * 2 ^ 64 % m
  step x && step (m - 1) && step 0 && step (2 ^ 127 - 1) &&
    timesR k m k x == x * 2 ^ 128 % m &&
    publicOp k m m0inv x == x ^ 65537 % m && publicOp k m m0inv (m + 5) == 5 ^ 65537 % m

end Spec.RsaDivision
