import Mathlib.Tactic

/-!
The x86-64 RSA signer's multiplication and square, `rsa_mont64_adx.c`, modeled from the C on a
`Nat` (docs/decisions.md 183).

`rsa_mont64_adx_asm.h` adds rows of products into a sum of 64-bit words, and
`test/rsa_mont64_adx_model.h` writes the same words in portable C. Each row adds its products
exactly, so this module models a row as one addition on a `Nat`: the multiplication's row `i`
adds `aᵢ b` at word `i` (`productRows`), and the square's row `i` adds `aᵢ` times the words of
`a` above word `i`, at word `2 i + 1` (`crossRows`), which `adx_double_add_diagonal` doubles
before it adds each `aᵢ ²` at word `2 i` (`diagonal`). The reduction's row `i` adds `u m` at word
`i`, with `u` the low word of word `i` of the sum times `m0inv` (`redRow`). `finalSub` subtracts
`m` once where the value is `m` or more.

`productRows_eq` proves that the rows of a product are `a b` for `a` below `2 ^ (64 k)`, and
`square_eq` that twice the cross rows plus the diagonal are `a a`. `redRows_low` proves that `k`
reduction rows clear the low `k` words, for an `m0inv` with `m m0inv = -1` modulo `2 ^ 64`, and
`redRows_value` that they add `m U` for a `U` below `2 ^ (64 k)`. `montMul_lt` and `montMul_mod`
state the result: for `a` and `b` below `m`, `montMul` is below `m` and `montMul R` is `a b`
modulo `m`, and `montSquare_eq` that the square's rows give `montMul a a`.

This module is written from the C, not from a standard, and CONTRACT.md says why.
-/

namespace Spec.RsaMont64Adx

/-- Word `i` of `x`. -/
def word (x i : Nat) : Nat :=
  x / 2 ^ (64 * i) % 2 ^ 64

/-- The product rows of `rsa_mont64_adx_mul`: row `i` adds `aᵢ b` at word `i`. -/
def productRows (a b : Nat) : Nat → Nat
  | 0 => 0
  | i + 1 => productRows a b i + word a i * b * 2 ^ (64 * i)

/-- The cross-product rows of `rsa_mont64_adx_square`: row `i` adds `aᵢ` times the words of `a`
above word `i` at word `2 i + 1`, the C's `a[i] * a[i + 1 .. k - 1]`. -/
def crossRows (a : Nat) : Nat → Nat
  | 0 => 0
  | i + 1 => crossRows a i + word a i * (a / 2 ^ (64 * (i + 1))) * 2 ^ (64 * (2 * i + 1))

/-- The diagonal `adx_double_add_diagonal` adds: `aᵢ ²` at word `2 i`. -/
def diagonal (a : Nat) : Nat → Nat
  | 0 => 0
  | i + 1 => diagonal a i + word a i ^ 2 * 2 ^ (128 * i)

/-- A reduction row: `u`, the low word of word `i` of `t` times `m0inv`, then `u m` at word `i`. -/
def redRow (m m0inv i t : Nat) : Nat :=
  t + word t i * m0inv % 2 ^ 64 * m * 2 ^ (64 * i)

/-- The first `i` reduction rows over `t`. -/
def redRows (m m0inv t : Nat) : Nat → Nat
  | 0 => t
  | i + 1 => redRow m m0inv i (redRows m m0inv t i)

/-- `adx_final_sub`: `v - m` where `v` is `m` or more, and `v` otherwise. -/
def finalSub (m v : Nat) : Nat :=
  if m ≤ v then v - m else v

/-- `rsa_mont64_adx_mul` under a modulus of `k` words: the product rows, the `k` reduction rows,
the words above word `k - 1`, then `finalSub`. -/
def montMul (k m m0inv a b : Nat) : Nat :=
  finalSub m (redRows m m0inv (productRows a b k) k / 2 ^ (64 * k))

/-- `rsa_mont64_adx_square`: the same from twice the cross rows plus the diagonal. -/
def montSquare (k m m0inv a : Nat) : Nat :=
  finalSub m (redRows m m0inv (2 * crossRows a k + diagonal a k) k / 2 ^ (64 * k))

/-! ## Two splits of a number at a word -/

/-- The low `i + 1` words are the low `i` words and word `i`. -/
theorem mod_succ (a i : Nat) :
    a % 2 ^ (64 * (i + 1)) = a % 2 ^ (64 * i) + 2 ^ (64 * i) * word a i := by
  rw [show 64 * (i + 1) = 64 * i + 64 by ring, pow_add, Nat.mod_mul]
  rfl

/-- The words from word `i` up are word `i` and the words from word `i + 1` up. -/
theorem div_succ (a i : Nat) :
    a / 2 ^ (64 * i) = word a i + 2 ^ 64 * (a / 2 ^ (64 * (i + 1))) := by
  rw [show 64 * (i + 1) = 64 * i + 64 by ring, pow_add, ← Nat.div_div_eq_div_mul, word]
  exact (Nat.mod_add_div _ _).symm

/-! ## The product and the square -/

/-- The product rows of `i` words of `a` are those words times `b`. -/
theorem productRows_mod (a b i : Nat) : productRows a b i = a % 2 ^ (64 * i) * b := by
  induction i with
  | zero => simp [productRows, Nat.mod_one]
  | succ i ih =>
    rw [productRows, ih, mod_succ]
    ring

/-- For `a` below `2 ^ (64 k)`, the product rows are `a b`. -/
theorem productRows_eq {a k : Nat} (b : Nat) (h_a : a < 2 ^ (64 * k)) :
    productRows a b k = a * b := by
  rw [productRows_mod, Nat.mod_eq_of_lt h_a]

/-- After `i` rows, twice the cross rows plus the diagonal are the square of the low `i` words
plus twice those words times the words from word `i` up, at word `i`. -/
theorem square_rows (a i : Nat) :
    2 * crossRows a i + diagonal a i =
      (a % 2 ^ (64 * i)) ^ 2 + 2 * (a % 2 ^ (64 * i)) * (a / 2 ^ (64 * i)) * 2 ^ (64 * i) := by
  induction i with
  | zero => simp [crossRows, diagonal, Nat.mod_one]
  | succ i ih =>
    rw [crossRows, diagonal, mod_succ]
    rw [div_succ a i] at ih
    have h_p1 : 2 ^ (64 * (i + 1)) = 2 ^ (64 * i) * 2 ^ 64 := by
      rw [← pow_add]; ring_nf
    have h_p2 : 2 ^ (64 * (2 * i + 1)) = 2 ^ (64 * i) * 2 ^ (64 * i) * 2 ^ 64 := by
      rw [← pow_add, ← pow_add]; ring_nf
    have h_p3 : 2 ^ (128 * i) = 2 ^ (64 * i) * 2 ^ (64 * i) := by
      rw [← pow_add]; ring_nf
    rw [h_p1, h_p2, h_p3]
    rw [h_p1] at ih
    -- The two new terms ride beside the old sum, which ih states.
    have h_split : ∀ c d X Y : Nat, 2 * (c + X) + (d + Y) = (2 * c + d) + (2 * X + Y) :=
      fun c d X Y => by ring
    rw [h_split, ih]
    ring

/-- For `a` below `2 ^ (64 k)`, twice the cross rows plus the diagonal are `a a`. -/
theorem square_eq {a k : Nat} (h_a : a < 2 ^ (64 * k)) :
    2 * crossRows a k + diagonal a k = a * a := by
  rw [square_rows, Nat.mod_eq_of_lt h_a, Nat.div_eq_of_lt h_a]
  ring

/-! ## The reduction -/

/-- Every reduction row adds a multiple of `m`, below `2 ^ 64` times the word's weight. -/
theorem redRows_value (m m0inv t : Nat) :
    ∀ i, ∃ U, U < 2 ^ (64 * i) ∧ redRows m m0inv t i = t + m * U := by
  intro i
  induction i with
  | zero => exact ⟨0, by positivity, by simp [redRows]⟩
  | succ i ih =>
    obtain ⟨U, h_U, h_eq⟩ := ih
    set u := word (redRows m m0inv t i) i * m0inv % 2 ^ 64 with h_u
    refine ⟨U + u * 2 ^ (64 * i), ?_, ?_⟩
    · have h_ult : u < 2 ^ 64 := Nat.mod_lt _ (by positivity)
      rw [show 64 * (i + 1) = 64 * i + 64 by ring, pow_add]
      nlinarith [h_ult, h_U]
    · rw [redRows, redRow, ← h_u, h_eq]
      ring

/-- Where `m m0inv = -1` modulo `2 ^ 64`, `i` reduction rows clear the low `i` words. -/
theorem redRows_low {m m0inv : Nat} (t : Nat) (h_inv : (m * m0inv + 1) % 2 ^ 64 = 0) :
    ∀ i, redRows m m0inv t i % 2 ^ (64 * i) = 0 := by
  intro i
  induction i with
  | zero => simp [Nat.mod_one]
  | succ i ih =>
    set s := redRows m m0inv t i with h_s
    set u := word s i * m0inv % 2 ^ 64 with h_u
    obtain ⟨q, h_q⟩ : 2 ^ (64 * i) ∣ s := Nat.dvd_of_mod_eq_zero ih
    have h_next : redRows m m0inv t (i + 1) = 2 ^ (64 * i) * (q + u * m) := by
      rw [redRows, redRow, ← h_s, ← h_u, h_q]
      ring
    have h_word : word s i = q % 2 ^ 64 := by
      rw [word, h_q, Nat.mul_div_cancel_left _ (by positivity)]
    -- q + u m is 0 modulo 2 ^ 64: u is q m0inv modulo 2 ^ 64, so q + u m is q (m m0inv + 1).
    have h_u_mod : u ≡ q * m0inv [MOD 2 ^ 64] := by
      rw [h_u, h_word]
      exact (Nat.mod_modEq _ _).trans ((Nat.mod_modEq q _).mul_right m0inv)
    have h_sum : q + u * m ≡ q * (m * m0inv + 1) [MOD 2 ^ 64] := by
      have h_add := (Nat.ModEq.refl q).add (h_u_mod.mul_right m)
      rw [show q + q * m0inv * m = q * (m * m0inv + 1) by ring] at h_add
      exact h_add
    have h_zero : (q + u * m) % 2 ^ 64 = 0 := by
      unfold Nat.ModEq at h_sum
      rw [h_sum, Nat.mul_mod, h_inv, mul_zero, Nat.zero_mod]
    obtain ⟨r, h_r⟩ := Nat.dvd_of_mod_eq_zero h_zero
    rw [h_next, h_r, show 64 * (i + 1) = 64 * i + 64 by ring, pow_add, ← mul_assoc]
    exact Nat.mul_mod_right _ _

/-! ## The result -/

/-- `finalSub` of a value below `2 m` is below `m`. -/
theorem finalSub_lt {m v : Nat} (h_v : v < 2 * m) : finalSub m v < m := by
  unfold finalSub
  split <;> omega

/-- `finalSub` leaves the value's residue modulo `m`. -/
theorem finalSub_mod (m v : Nat) : finalSub m v % m = v % m := by
  unfold finalSub
  split
  · rename_i h
    conv_rhs => rw [show v = v - m + m by omega]
    simp
  · rfl

/-- For `t` below `m 2 ^ (64 k)`, the reduction's value above word `k - 1` is below `2 m`, and
that value times `2 ^ (64 k)` is `t` modulo `m`. -/
theorem reduce_spec {m m0inv t k : Nat} (h_inv : (m * m0inv + 1) % 2 ^ 64 = 0)
    (h_t : t < m * 2 ^ (64 * k)) :
    redRows m m0inv t k / 2 ^ (64 * k) < 2 * m ∧
      redRows m m0inv t k / 2 ^ (64 * k) * 2 ^ (64 * k) % m = t % m := by
  obtain ⟨U, h_U, h_eq⟩ := redRows_value m m0inv t k
  have h_low := redRows_low t h_inv k
  have h_exact : redRows m m0inv t k / 2 ^ (64 * k) * 2 ^ (64 * k) = redRows m m0inv t k :=
    Nat.div_mul_cancel (Nat.dvd_of_mod_eq_zero h_low)
  refine ⟨?_, ?_⟩
  · rw [Nat.div_lt_iff_lt_mul (by positivity), h_eq]
    nlinarith [h_U, h_t]
  · rw [h_exact, h_eq, Nat.add_mul_mod_self_left]

/-- For `a` and `b` below `m` and `m` below `2 ^ (64 k)`, `montMul` is below `m`. -/
theorem montMul_lt {k m m0inv a b : Nat} (h_inv : (m * m0inv + 1) % 2 ^ 64 = 0)
    (h_m : m < 2 ^ (64 * k)) (h_a : a < m) (h_b : b < m) : montMul k m m0inv a b < m := by
  have h_t : a * b < m * 2 ^ (64 * k) := by nlinarith
  unfold montMul
  rw [productRows_eq b (by omega)]
  exact finalSub_lt (reduce_spec h_inv h_t).1

/-- Under the same terms, `montMul 2 ^ (64 k)` is `a b` modulo `m`. -/
theorem montMul_mod {k m m0inv a b : Nat} (h_inv : (m * m0inv + 1) % 2 ^ 64 = 0)
    (h_m : m < 2 ^ (64 * k)) (h_a : a < m) (h_b : b < m) :
    montMul k m m0inv a b * 2 ^ (64 * k) % m = a * b % m := by
  have h_t : a * b < m * 2 ^ (64 * k) := by nlinarith
  unfold montMul
  rw [productRows_eq b (by omega), Nat.mul_mod, finalSub_mod, ← Nat.mul_mod]
  exact (reduce_spec h_inv h_t).2

/-- The square's rows give the multiplication's result. -/
theorem montSquare_eq {k m m0inv a : Nat} (h_a : a < 2 ^ (64 * k)) :
    montSquare k m m0inv a = montMul k m m0inv a a := by
  unfold montSquare montMul
  rw [square_eq h_a, productRows_eq a h_a]

/-! ## Selftest -/

/-- RSA-sized checks of the model against `Nat` arithmetic: a product of two words below a
modulus of two words, against `a b R⁻¹ mod m` computed with the inverse of `R`. -/
def selftest (_ : Unit) : Bool :=
  let k := 2
  let m := 2 ^ 127 + 2 ^ 64 + 1
  -- m0inv = -m⁻¹ mod 2 ^ 64; m is 1 mod 2 ^ 64, so m⁻¹ is 1 and m0inv is 2 ^ 64 - 1.
  let m0inv := 2 ^ 64 - 1
  let a := 2 ^ 126 + 12345
  let b := 2 ^ 100 + 678910
  let r := 2 ^ (64 * k)
  let p := montMul k m m0inv a b
  (m * m0inv + 1) % 2 ^ 64 == 0 && p < m && p * r % m == a * b % m &&
    montSquare k m m0inv a == montMul k m m0inv a a

end Spec.RsaMont64Adx
