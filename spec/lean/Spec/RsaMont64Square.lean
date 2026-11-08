import Mathlib.Tactic
import Spec.RsaMont64Adx

/-!
The square of `rsa_mont64_blocks.c`, `rsa_mont64_blocks_square`, modeled from the C on a `Nat`
(docs/decisions.md 192).

The C keeps a vector `v` of `k + 1` words. It starts as the words of `2 a`: word `j` is `aⱼ`
moved up one bit with the top bit of `aⱼ₋₁` below it, and word `k` is the top bit of `aₖ₋₁`.
Row `i` reads `v` with zero below word `i`, `aᵢ` at word `i` and `aᵢ₊₁` moved up one bit at word
`i + 1` (`rowValue`), and the last row reads zero at word `k`. The row adds `aᵢ` times those words
at word `i`, then `u m` at word `i`, with `u` the low word of word `i` of that sum times `m0inv`
(`squareRow`). The result is the sum after `k` rows divided by `2 ^ (64 k)`, the words and the
top word the C returns before the last subtraction (`blocksSquare`).

`twice_words` proves that the C's words of `2 x` are `2 x`, the argument that the doubling
moves each top bit into the word above. `rowValue_eq` proves that a row's words are
`aᵢ 2^(64 i) + 2 (a / 2^(64 (i + 1))) 2^(64 (i + 1))`, and `rowSum_eq` that the rows add up to
`a a`. `blocksSquare_eq` proves that the rows, with the multiples of `m` between them, give the
value `RsaMont64Adx` reduces from `a a`, and `blocksSquare_montMul` that one last subtraction
gives `RsaMont64Adx.montMul k m m0inv a a`, which `RsaMont64Adx.montMul_lt` and
`RsaMont64Adx.montMul_mod` state.

This module is written from the C, not from a standard, and CONTRACT.md says why.
-/

namespace Spec.RsaMont64Square

open Spec.RsaMont64Adx (word redRow redRows finalSub montMul mod_succ productRows_eq)

/-! ## The words of `2 x` -/

/-- Word `j` of `2 x` as the C writes it: word `j` of `x` moved up one bit, with the top bit of
word `j - 1` below it, and nothing below word 0. -/
def twiceWord (x j : Nat) : Nat :=
  2 * word x j % 2 ^ 64 + (if j = 0 then 0 else word x (j - 1) / 2 ^ 63)

/-- The first `n` of those words. -/
def twiceLow (x : Nat) : Nat → Nat
  | 0 => 0
  | n + 1 => twiceLow x n + twiceWord x n * 2 ^ (64 * n)

/-- The first `n` of those words, and above them the top bit of word `n - 1`: the `n + 1` words
the C writes for `2 x` from `n` words of `x`. -/
def twiceWords (x n : Nat) : Nat :=
  twiceLow x n + (if n = 0 then 0 else word x (n - 1) / 2 ^ 63 * 2 ^ (64 * n))

theorem word_lt (x i : Nat) : word x i < 2 ^ 64 := Nat.mod_lt _ (by positivity)

/-- A word moved up one bit is its low 64 bits and its top bit one word up. -/
theorem double_split (w : Nat) : 2 * w % 2 ^ 64 + 2 ^ 64 * (w / 2 ^ 63) = 2 * w := by
  have h : 2 * w / 2 ^ 64 = w / 2 ^ 63 := by
    rw [show (2 : Nat) ^ 64 = 2 * 2 ^ 63 by norm_num, Nat.mul_div_mul_left _ _ (by norm_num)]
  have := Nat.mod_add_div (2 * w) (2 ^ 64)
  rw [h] at this
  omega

/-- The C's words of `2 x` from `n` words of `x` are `2 (x mod 2^(64 n))`. -/
theorem twiceWords_eq (x n : Nat) : twiceWords x n = 2 * (x % 2 ^ (64 * n)) := by
  induction n with
  | zero => simp [twiceWords, twiceLow, Nat.mod_one]
  | succ n ih =>
    have h_d := double_split (word x n)
    have h_p : 2 ^ (64 * (n + 1)) = 2 ^ (64 * n) * 2 ^ 64 := by
      rw [← pow_add]; ring_nf
    unfold twiceWords at ih ⊢
    rw [if_neg (Nat.succ_ne_zero n), twiceLow, mod_succ, Nat.add_sub_cancel, h_p]
    unfold twiceWord
    by_cases h_n : n = 0
    · subst h_n
      simp only [twiceLow, if_true, Nat.zero_add, Nat.mul_zero, pow_zero, Nat.mod_one] at ih ⊢
      linarith [h_d]
    · rw [if_neg h_n] at ih ⊢
      have h_e : 2 ^ (64 * n) * (2 * word x n % 2 ^ 64 + 2 ^ 64 * (word x n / 2 ^ 63)) =
          2 ^ (64 * n) * (2 * word x n) := by rw [h_d]
      nlinarith [ih, h_e]

/-- `twice_words`: for `x` below `2 ^ (64 n)`, the C's words of `2 x` are `2 x`. -/
theorem twice_words {x n : Nat} (h_x : x < 2 ^ (64 * n)) : twiceWords x n = 2 * x := by
  rw [twiceWords_eq, Nat.mod_eq_of_lt h_x]

/-! ## A row's words -/

/-- Word `j` of `a / 2^(64 i)` is word `i + j` of `a`: the words `rowValue` reads are the words
of `a` the C reads, `a[i + 1 + j]`. -/
theorem div_word (a i j : Nat) : word (a / 2 ^ (64 * i)) j = word a (i + j) := by
  unfold word
  rw [Nat.div_div_eq_div_mul, ← pow_add]
  ring_nf

/-- The value of row `i`'s words: zero below word `i`, `aᵢ` at word `i`, and from word `i + 1`
up the C's words of `2 x` for `x = a / 2^(64 (i + 1))`, the words of `a` above word `i`. Its
words from `i + 1` are `v[i + 1]`, which the row writes, and `v[j]`, which the start wrote. -/
def rowValue (a k i : Nat) : Nat :=
  word a i * 2 ^ (64 * i) +
    twiceWords (a / 2 ^ (64 * (i + 1))) (k - (i + 1)) * 2 ^ (64 * (i + 1))

/-- `rowValue_eq`: row `i`'s words are `aᵢ 2^(64 i) + 2 (a / 2^(64 (i + 1))) 2^(64 (i + 1))`. -/
theorem rowValue_eq {a k i : Nat} (h_a : a < 2 ^ (64 * k)) (h_i : i < k) :
    rowValue a k i =
      word a i * 2 ^ (64 * i) + 2 * (a / 2 ^ (64 * (i + 1))) * 2 ^ (64 * (i + 1)) := by
  unfold rowValue
  rw [twice_words]
  rw [Nat.div_lt_iff_lt_mul (by positivity), ← pow_add]
  convert h_a using 2
  omega

/-! ## The rows -/

/-- Rows `0` to `i - 1` of the square, each `aᵢ` times its words at word `i`. -/
def rowSum (a k : Nat) : Nat → Nat
  | 0 => 0
  | i + 1 => rowSum a k i + word a i * rowValue a k i * 2 ^ (64 * i)

/-- `rowSum_eq`: the `k` rows add up to `a a`. -/
theorem rowSum_eq {a k : Nat} (h_a : a < 2 ^ (64 * k)) : rowSum a k k = a * a := by
  have h_rows : ∀ i, i ≤ k → rowSum a k i =
      2 * Spec.RsaMont64Adx.crossRows a i + Spec.RsaMont64Adx.diagonal a i := by
    intro i
    induction i with
    | zero => simp [rowSum, Spec.RsaMont64Adx.crossRows, Spec.RsaMont64Adx.diagonal]
    | succ i ih =>
      intro h_i
      rw [rowSum, ih (by omega), rowValue_eq h_a (by omega), Spec.RsaMont64Adx.crossRows,
        Spec.RsaMont64Adx.diagonal]
      have h_p2 : 2 ^ (64 * (2 * i + 1)) = 2 ^ (64 * (i + 1)) * 2 ^ (64 * i) := by
        rw [← pow_add]; ring_nf
      have h_p3 : 2 ^ (128 * i) = 2 ^ (64 * i) * 2 ^ (64 * i) := by
        rw [← pow_add]; ring_nf
      rw [h_p2, h_p3]
      ring
  rw [h_rows k le_rfl]
  exact Spec.RsaMont64Adx.square_eq h_a

/-- Row `i` of the C: add `aᵢ` times the row's words at word `i`, then `u m` at word `i`. -/
def squareRow (m m0inv a k i t : Nat) : Nat :=
  redRow m m0inv i (t + word a i * rowValue a k i * 2 ^ (64 * i))

/-- The first `i` rows of the C over a sum that starts at zero. -/
def squareRows (m m0inv a k : Nat) : Nat → Nat
  | 0 => 0
  | i + 1 => squareRow m m0inv a k i (squareRows m m0inv a k i)

/-- `rsa_mont64_blocks_square`: the sum after `k` rows, divided by `2 ^ (64 k)`. -/
def blocksSquare (k m m0inv a : Nat) : Nat :=
  squareRows m m0inv a k k / 2 ^ (64 * k)

/-! ## The rows with the reduction between them -/

/-- Rows `i` to `k - 1`, the part of `a a` the C has not added after row `i - 1`. -/
def rowRest (a k i : Nat) : Nat :=
  a * a - rowSum a k i

/-- The rows from `i` on add a multiple of `2 ^ (64 i)`. -/
theorem rowSum_step (a k i : Nat) :
    ∀ j, ∃ c, rowSum a k (i + j) = rowSum a k i + 2 ^ (64 * i) * c := by
  intro j
  induction j with
  | zero => exact ⟨0, by simp⟩
  | succ j ih =>
    obtain ⟨c, h_c⟩ := ih
    refine ⟨c + word a (i + j) * rowValue a k (i + j) * 2 ^ (64 * j), ?_⟩
    rw [← Nat.add_assoc, rowSum, h_c, show 64 * (i + j) = 64 * i + 64 * j by ring, pow_add]
    ring

/-- What rows `i` to `k - 1` add, `rowRest`, is a multiple of `2 ^ (64 i)`, and `rowSum` is
`a a` less it. -/
theorem rowRest_dvd {a k : Nat} (h_a : a < 2 ^ (64 * k)) {i : Nat} (h_i : i ≤ k) :
    rowSum a k i ≤ a * a ∧ 2 ^ (64 * i) ∣ rowRest a k i := by
  obtain ⟨c, h_c⟩ := rowSum_step a k i (k - i)
  rw [Nat.add_sub_cancel' h_i, rowSum_eq h_a] at h_c
  unfold rowRest
  rw [h_c, Nat.add_sub_cancel_left]
  exact ⟨Nat.le_add_right _ _, Dvd.intro c rfl⟩

/-- Word `i` of a sum does not see a multiple of `2 ^ (64 (i + 1))` added to it. -/
theorem word_add_dvd (t c i : Nat) (h_c : 2 ^ (64 * (i + 1)) ∣ c) :
    word (t + c) i = word t i := by
  obtain ⟨d, rfl⟩ := h_c
  unfold word
  rw [show 64 * (i + 1) = 64 * i + 64 by ring, pow_add, mul_assoc,
    Nat.add_mul_div_left _ _ (by positivity), Nat.add_mul_mod_self_left]

/-- After `i` rows, the C's sum and the rows it has not added are the reduction's sum after `i`
of its rows over `a a`: each `u` is the same, because word `i` does not see the later rows. -/
theorem squareRows_add_rest {m m0inv a k : Nat} (h_a : a < 2 ^ (64 * k)) :
    ∀ i, i ≤ k → squareRows m m0inv a k i + rowRest a k i = redRows m m0inv (a * a) i := by
  intro i
  induction i with
  | zero => intro _; simp [squareRows, rowRest, rowSum, redRows]
  | succ i ih =>
    intro h_i
    have h_ih := ih (by omega)
    have h_le := (rowRest_dvd h_a (show i + 1 ≤ k by omega)).1
    have h_rest : rowRest a k i =
        word a i * rowValue a k i * 2 ^ (64 * i) + rowRest a k (i + 1) := by
      unfold rowRest
      rw [rowSum] at h_le ⊢
      omega
    have h_dvd := (rowRest_dvd h_a (show i + 1 ≤ k by omega)).2
    rw [squareRows, redRows, ← h_ih, h_rest, squareRow]
    unfold redRow
    rw [← Nat.add_assoc, word_add_dvd _ _ _ h_dvd]
    ring

/-- `blocksSquare_eq`: the C's rows give the value the reduction's `k` rows give from `a a`. -/
theorem blocksSquare_eq {m m0inv a k : Nat} (h_a : a < 2 ^ (64 * k)) :
    blocksSquare k m m0inv a = redRows m m0inv (a * a) k / 2 ^ (64 * k) := by
  unfold blocksSquare
  have h := squareRows_add_rest (m := m) (m0inv := m0inv) h_a k le_rfl
  have h_zero : rowRest a k k = 0 := by
    unfold rowRest
    rw [rowSum_eq h_a, Nat.sub_self]
  rw [h_zero, Nat.add_zero] at h
  rw [h]

/-- `blocksSquare_montMul`: one last subtraction of `m` gives `montMul k m m0inv a a`. -/
theorem blocksSquare_montMul {m m0inv a k : Nat} (h_a : a < 2 ^ (64 * k)) :
    finalSub m (blocksSquare k m m0inv a) = montMul k m m0inv a a := by
  rw [blocksSquare_eq h_a]
  unfold montMul
  rw [productRows_eq a h_a]

/-! ## Selftest -/

set_option compiler.extract_closed false in
/-- Checks of the model against `RsaMont64Adx.montMul` and `Nat` arithmetic: a value whose
words have their top bits set, under a modulus of two words and of three. -/
def selftest (_ : Unit) : Bool :=
  let check := fun (k m m0inv a : Nat) =>
    (m * m0inv + 1) % 2 ^ 64 == 0 && a < m &&
      finalSub m (blocksSquare k m m0inv a) == montMul k m m0inv a a &&
      twiceWords a k == 2 * a
  -- m is 1 mod 2 ^ 64, so m⁻¹ is 1 and m0inv is 2 ^ 64 - 1.
  check 2 (2 ^ 127 + 2 ^ 64 + 1) (2 ^ 64 - 1) (2 ^ 127 - 2 ^ 63 - 1) &&
    check 3 (2 ^ 191 + 2 ^ 64 + 1) (2 ^ 64 - 1) (2 ^ 190 + 2 ^ 127 + 2 ^ 63 + 12345)

end Spec.RsaMont64Square
