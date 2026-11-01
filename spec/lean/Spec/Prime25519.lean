import Mathlib.NumberTheory.LucasPrimality
import Mathlib.Tactic

/-!
# 2^255 - 19 is prime

The field of X25519 and Ed25519 is `ZMod p` for p = 2^255 - 19, and it is
a field only because p is prime. This module proves that, by a Pratt
certificate: Lucas's test, Mathlib's `lucas_primality`, at p and at each
prime of p - 1 above 100,000, down to primes `norm_num` proves by trial
division.

`powMod` computes `b ^ e % m` by squarings, so that Lean's kernel can
evaluate the test's powers, and `powMod_eq` proves that it does.
`lucas_list` is `lucas_primality` for an n whose n - 1 is the product of a
list of primes, with a witness a, in the terms `decide` evaluates. Each
`prime_*` theorem is one node of the certificate. A search by Pollard's
rho and ECM found the lists once. A check needs no tool: `norm_num`
checks that each list multiplies to n - 1, and the kernel checks the
powers.
-/

namespace Spec.Prime25519

/-- `b ^ e % m` by squarings from the low bit of e, with `fuel` steps. -/
def powModAux (m : ℕ) : ℕ → ℕ → ℕ → ℕ → ℕ
  | 0, _, _, acc => acc % m
  | fuel + 1, b, e, acc =>
    powModAux m fuel (b * b % m) (e / 2) (if e % 2 = 1 then acc * b % m else acc)

/-- `b ^ e % m`, with one step for each bit of e. -/
def powMod (m b e : ℕ) : ℕ := powModAux m (Nat.log2 e + 1) b e 1

/-- The squarings compute `acc * b ^ e % m` once the fuel covers e's bits. -/
theorem powModAux_eq (m : ℕ) :
    ∀ (fuel b e acc : ℕ), e < 2 ^ fuel → powModAux m fuel b e acc = acc * b ^ e % m := by
  intro fuel
  induction fuel with
  | zero =>
    intro b e acc h_e
    have : e = 0 := by omega
    simp [powModAux, this]
  | succ fuel ih =>
    intro b e acc h_e
    rw [powModAux, ih _ _ _ (by rw [pow_succ] at h_e; omega)]
    have h_split : b ^ e = (b * b) ^ (e / 2) * b ^ (e % 2) := by
      rw [← pow_two, ← pow_mul, ← pow_add, Nat.div_add_mod]
    have h_square : (b * b % m) ^ (e / 2) ≡ (b * b) ^ (e / 2) [MOD m] :=
      (Nat.mod_modEq _ _).pow _
    rcases Nat.mod_two_eq_zero_or_one e with h_bit | h_bit
    · simp only [h_bit, zero_ne_one, if_false, pow_zero, mul_one] at h_split ⊢
      rw [h_split]
      exact (Nat.ModEq.refl acc).mul h_square
    · simp only [h_bit, if_true, pow_one] at h_split ⊢
      rw [h_split, show acc * ((b * b) ^ (e / 2) * b) = acc * b * (b * b) ^ (e / 2) by ring]
      exact (Nat.mod_modEq _ _).mul h_square

/-- `powMod` computes `b ^ e % m`. -/
theorem powMod_eq (m b e : ℕ) : powMod m b e = b ^ e % m := by
  have h_bits : e < 2 ^ (Nat.log2 e + 1) := by
    rw [Nat.log2_eq_log_two]
    exact Nat.lt_pow_succ_log_self (by norm_num) e
  rw [powMod, powModAux_eq m _ _ _ _ h_bits, one_mul]

/-- Lucas's test for an n whose n - 1 is the product of a list of primes, with witness a:
`a ^ (n - 1)` is 1 modulo n and `a ^ ((n - 1) / q)` is not, for each q of the list. -/
theorem lucas_list (n a : ℕ) (L : List ℕ) (h_two : 2 ≤ n) (h_prod : L.prod = n - 1)
    (h_primes : ∀ q ∈ L, q.Prime) (h_one : powMod n a (n - 1) = 1)
    (h_not_one : ∀ q ∈ L, powMod n a ((n - 1) / q) ≠ 1) : n.Prime := by
  have h_cast : ∀ k, ((a : ZMod n) ^ k) = ((powMod n a k : ℕ) : ZMod n) := fun k => by
    rw [powMod_eq, ZMod.natCast_mod, Nat.cast_pow]
  refine lucas_primality n (a : ZMod n) ?_ ?_
  · rw [h_cast, h_one, Nat.cast_one]
  · intro q h_q h_dvd
    rw [← h_prod] at h_dvd
    obtain ⟨r, h_r, h_qr⟩ := (Prime.dvd_prod_iff h_q.prime).mp h_dvd
    have h_eq : q = r := (Nat.prime_dvd_prime_iff_eq h_q (h_primes r h_r)).mp h_qr
    subst h_eq
    rw [h_cast]
    intro h_eq_one
    have h_lt : powMod n a ((n - 1) / q) < n := by
      rw [powMod_eq]
      exact Nat.mod_lt _ (by omega)
    have h_mod : powMod n a ((n - 1) / q) % n = 1 % n :=
      (ZMod.natCast_eq_natCast_iff' _ 1 n).mp (by rw [Nat.cast_one]; exact h_eq_one)
    rw [Nat.mod_eq_of_lt h_lt, Nat.mod_eq_of_lt (by omega)] at h_mod
    exact h_not_one q h_r h_mod

theorem prime_132049 : Nat.Prime 132049 := by norm_num
theorem prime_430751 : Nat.Prime 430751 := by norm_num
theorem prime_569003 : Nat.Prime 569003 := by norm_num
theorem prime_1923133 : Nat.Prime 1923133 := by norm_num
theorem prime_8574133 : Nat.Prime 8574133 := by norm_num

theorem prime_2773320623 : Nat.Prime 2773320623 :=
  lucas_list 2773320623 5 [2, 2437, 569003] (by norm_num) (by norm_num)
    (by
      intro q h_q
      simp only [List.mem_cons, List.not_mem_nil, or_false] at h_q
      rcases h_q with rfl | rfl | rfl
      · norm_num
      · norm_num
      · exact prime_569003)
    (by decide +kernel) (by decide +kernel)

theorem prime_72106336199 : Nat.Prime 72106336199 :=
  lucas_list 72106336199 7 [2, 13, 2773320623] (by norm_num) (by norm_num)
    (by
      intro q h_q
      simp only [List.mem_cons, List.not_mem_nil, or_false] at h_q
      rcases h_q with rfl | rfl | rfl
      · norm_num
      · norm_num
      · exact prime_2773320623)
    (by decide +kernel) (by decide +kernel)

theorem prime_1919519569386763 : Nat.Prime 1919519569386763 :=
  lucas_list 1919519569386763 2 [2, 3, 7, 19, 47, 47, 127, 8574133] (by norm_num) (by norm_num)
    (by
      intro q h_q
      simp only [List.mem_cons, List.not_mem_nil, or_false] at h_q
      rcases h_q with rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl
      all_goals first | exact prime_8574133 | norm_num)
    (by decide +kernel) (by decide +kernel)

theorem prime_31757755568855353 : Nat.Prime 31757755568855353 :=
  lucas_list 31757755568855353 10 [2, 2, 2, 3, 31, 107, 223, 4153, 430751] (by norm_num)
    (by norm_num)
    (by
      intro q h_q
      simp only [List.mem_cons, List.not_mem_nil, or_false] at h_q
      rcases h_q with rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl
      all_goals first | exact prime_430751 | norm_num)
    (by decide +kernel) (by decide +kernel)

theorem prime_75445702479781427272750846543864801 :
    Nat.Prime 75445702479781427272750846543864801 :=
  lucas_list 75445702479781427272750846543864801 7
    [2, 2, 2, 2, 2, 3, 3, 5, 5, 75707, 72106336199, 1919519569386763] (by norm_num) (by norm_num)
    (by
      intro q h_q
      simp only [List.mem_cons, List.not_mem_nil, or_false] at h_q
      rcases h_q with rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl
      all_goals first | exact prime_72106336199 | exact prime_1919519569386763 | norm_num)
    (by decide +kernel) (by decide +kernel)

theorem prime_74058212732561358302231226437062788676166966415465897661863160754340907 :
    Nat.Prime 74058212732561358302231226437062788676166966415465897661863160754340907 :=
  lucas_list 74058212732561358302231226437062788676166966415465897661863160754340907 2
    [2, 3, 353, 57467, 132049, 1923133, 31757755568855353, 75445702479781427272750846543864801]
    (by norm_num) (by norm_num)
    (by
      intro q h_q
      simp only [List.mem_cons, List.not_mem_nil, or_false] at h_q
      rcases h_q with rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl
      all_goals first | exact prime_132049 | exact prime_1923133 |
        exact prime_31757755568855353 | exact prime_75445702479781427272750846543864801 | norm_num)
    (by decide +kernel) (by decide +kernel)

/-- p = 2^255 - 19 is prime. -/
theorem prime_p : Nat.Prime (2 ^ 255 - 19) :=
  lucas_list (2 ^ 255 - 19) 2
    [2, 2, 3, 65147, 74058212732561358302231226437062788676166966415465897661863160754340907]
    (by norm_num) (by norm_num)
    (by
      intro q h_q
      simp only [List.mem_cons, List.not_mem_nil, or_false] at h_q
      rcases h_q with rfl | rfl | rfl | rfl | rfl
      all_goals first |
        exact prime_74058212732561358302231226437062788676166966415465897661863160754340907 |
        norm_num)
    (by decide +kernel) (by decide +kernel)

end Spec.Prime25519
