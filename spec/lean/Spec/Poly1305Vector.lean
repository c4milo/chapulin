import Mathlib.Data.ZMod.Basic
import Mathlib.Tactic

/-!
Poly1305's block loop on NEON and SSE2, `poly1305_vector.c`, modeled from the C, one lane at a
time, and its entry `poly1305_vector_blocks` with both lanes.

A lane holds a number as five 26-bit words, `w0 + w1 2 ^ 26 + ... + w4 2 ^ 104` (`Words`). Its
five sums are 64-bit lanes (`Sums`). `multiplyAdd` is the C's `multiply_add`: 25 widening
products of 32-bit words, those past `2 ^ 130` taken by 5 times a word of the power, because
modulo `p = 2 ^ 130 - 5`, `2 ^ 130` is 5. `carryRound` is the C's `carry_round` and `carry` its
`carry`, two rounds and a narrow to 32 bits. `pairsSums` is `pairs_sums` on one lane:
`(h + b0) x0 + b1 x1 + ... + bk xk`, and `passStep` adds the carry.

A pass takes two pairs of blocks on SSE2 and on a short NEON call, and four pairs on a NEON call
of 2,048 bytes or more (docs/decisions.md 194). `passStep_bounds` proves that from words that
fit (below `2 ^ 26 + 2 ^ 10`), blocks below `2 ^ 26` and powers whose words are at most
`2 ^ 26`, for up to four pairs, every operand of a product is below `2 ^ 32`, every sum is below
`2 ^ 59`, the carry `sums_add_carry_times_5` narrows is below `2 ^ 32`, every value of the first
round is below `2 ^ 34`, and the result fits again. So the C's lanes hold the model's numbers at
every pass, by induction over the loop. `passStep_mod` proves that a pass computes
`(h + b0) x0 + ... + bk xk` modulo `p`.

`blocks` is the whole entry, both lanes, the powers `multiply_scalar` computes and the totals
`carry_scalar` carries, as the differential runs it against the C.

This module is written from the C, not from a standard, and CONTRACT.md says why.
-/

namespace Spec.Poly1305Vector

/-- The Poly1305 prime, `2 ^ 130 - 5`. -/
def prime : Nat := 2 ^ 130 - 5

/-! ## Words and sums -/

/-- One lane's number: five 26-bit words. -/
structure Words where
  /-- Word 0, at `2 ^ 0`. -/
  w0 : Nat
  /-- Word 1, at `2 ^ 26`. -/
  w1 : Nat
  /-- Word 2, at `2 ^ 52`. -/
  w2 : Nat
  /-- Word 3, at `2 ^ 78`. -/
  w3 : Nat
  /-- Word 4, at `2 ^ 104`. -/
  w4 : Nat
  deriving Repr, DecidableEq

/-- The number five words hold. -/
def Words.value (x : Words) : Nat :=
  x.w0 + 2 ^ 26 * x.w1 + 2 ^ 52 * x.w2 + 2 ^ 78 * x.w3 + 2 ^ 104 * x.w4

/-- `words_add` on each word: `first[i] + h[i]` in `pairs_sums`. -/
def Words.add (a b : Words) : Words :=
  ⟨a.w0 + b.w0, a.w1 + b.w1, a.w2 + b.w2, a.w3 + b.w3, a.w4 + b.w4⟩

/-- Words as `carry` leaves them: each below `2 ^ 26 + 2 ^ 10`. -/
def Fits (x : Words) : Prop :=
  x.w0 < 2 ^ 26 + 2 ^ 10 ∧ x.w1 < 2 ^ 26 + 2 ^ 10 ∧ x.w2 < 2 ^ 26 + 2 ^ 10 ∧
    x.w3 < 2 ^ 26 + 2 ^ 10 ∧ x.w4 < 2 ^ 26 + 2 ^ 10

/-- `Fits` as a test the oracle can run on its inputs. -/
instance (x : Words) : Decidable (Fits x) :=
  inferInstanceAs (Decidable (_ ∧ _ ∧ _ ∧ _ ∧ _))

/-- Words as `load_blocks` writes them: each below `2 ^ 26`. -/
def BlockFits (x : Words) : Prop :=
  x.w0 < 2 ^ 26 ∧ x.w1 < 2 ^ 26 ∧ x.w2 < 2 ^ 26 ∧ x.w3 < 2 ^ 26 ∧ x.w4 < 2 ^ 26

/-- A power of `r` as `multiply_scalar` leaves it: each word at most `2 ^ 26`. -/
def PowerFits (x : Words) : Prop :=
  x.w0 ≤ 2 ^ 26 ∧ x.w1 ≤ 2 ^ 26 ∧ x.w2 ≤ 2 ^ 26 ∧ x.w3 ≤ 2 ^ 26 ∧ x.w4 ≤ 2 ^ 26

/-- `PowerFits` as a test the oracle can run on its inputs. -/
instance (x : Words) : Decidable (PowerFits x) :=
  inferInstanceAs (Decidable (_ ∧ _ ∧ _ ∧ _ ∧ _))

/-- One lane's five sums of products. -/
structure Sums where
  /-- The sum at `2 ^ 0`. -/
  d0 : Nat
  /-- The sum at `2 ^ 26`. -/
  d1 : Nat
  /-- The sum at `2 ^ 52`. -/
  d2 : Nat
  /-- The sum at `2 ^ 78`. -/
  d3 : Nat
  /-- The sum at `2 ^ 104`. -/
  d4 : Nat
  deriving Repr

/-- `sums_zero` in each sum. -/
def Sums.zero : Sums :=
  ⟨0, 0, 0, 0, 0⟩

/-- The number five sums hold. -/
def Sums.value (s : Sums) : Nat :=
  s.d0 + 2 ^ 26 * s.d1 + 2 ^ 52 * s.d2 + 2 ^ 78 * s.d3 + 2 ^ 104 * s.d4

/-- `multiply_add`: the 25 products of `a` and the power `r`, each sum in the C's order, with
`s1` to `s4` of `multiplier_set`, 5 times a word of `r`. -/
def multiplyAdd (s : Sums) (a r : Words) : Sums :=
  ⟨s.d0 + a.w2 * (5 * r.w3) + a.w3 * (5 * r.w2) + a.w4 * (5 * r.w1) + a.w0 * r.w0 +
      a.w1 * (5 * r.w4),
    s.d1 + a.w2 * (5 * r.w4) + a.w3 * (5 * r.w3) + a.w4 * (5 * r.w2) + a.w0 * r.w1 + a.w1 * r.w0,
    s.d2 + a.w2 * r.w0 + a.w3 * (5 * r.w4) + a.w4 * (5 * r.w3) + a.w0 * r.w2 + a.w1 * r.w1,
    s.d3 + a.w2 * r.w1 + a.w3 * r.w0 + a.w4 * (5 * r.w4) + a.w0 * r.w3 + a.w1 * r.w2,
    s.d4 + a.w2 * r.w2 + a.w3 * r.w1 + a.w4 * r.w0 + a.w0 * r.w4 + a.w1 * r.w3⟩

/-- `carry_round`: each sum's low 26 bits plus the carry out of the sum below it, and for sum 0
5 times the carry out of sum 4, which `sums_add_carry_times_5` narrows to 32 bits first. -/
def carryRound (s : Sums) : Sums :=
  ⟨s.d0 % 2 ^ 26 + s.d4 / 2 ^ 26 % 2 ^ 32 * 5, s.d1 % 2 ^ 26 + s.d0 / 2 ^ 26,
    s.d2 % 2 ^ 26 + s.d1 / 2 ^ 26, s.d3 % 2 ^ 26 + s.d2 / 2 ^ 26, s.d4 % 2 ^ 26 + s.d3 / 2 ^ 26⟩

/-- `carry`: two rounds, then `sums_narrow`, each sum's low 32 bits. -/
def carry (s : Sums) : Words :=
  let t := carryRound (carryRound s)
  ⟨t.d0 % 2 ^ 32, t.d1 % 2 ^ 32, t.d2 % 2 ^ 32, t.d3 % 2 ^ 32, t.d4 % 2 ^ 32⟩

/-- `pairs_sums` on one lane: the products of the pairs after the first, last pair first, then
`(h + first) x`. -/
def pairsSums (h first x : Words) (rest : List (Words × Words)) : Sums :=
  multiplyAdd (rest.reverse.foldl (fun s p => multiplyAdd s p.1 p.2) Sums.zero) (h.add first) x

/-- A pass of the group loop on one lane: `pairs_sums` and `carry`. -/
def passStep (h first x : Words) (rest : List (Words × Words)) : Words :=
  carry (pairsSums h first x rest)

/-! ## Values -/

/-- In the field of `p`, `2 ^ 130` is 5. -/
private theorem two_pow_130 : (2 : ZMod prime) ^ 130 = 5 := by
  have h_sum : (2 ^ 130 : Nat) = prime + 5 := by norm_num [prime]
  have h_cast := congrArg (Nat.cast : Nat → ZMod prime) h_sum
  rw [Nat.cast_add, ZMod.natCast_self, zero_add, Nat.cast_pow, Nat.cast_ofNat,
    Nat.cast_ofNat] at h_cast
  exact h_cast

/-- `multiply_add` adds `a r` to the sums' number modulo `p`. -/
theorem multiplyAdd_mod (s : Sums) (a r : Words) :
    ((multiplyAdd s a r).value : ZMod prime) =
      (s.value : ZMod prime) + (a.value : ZMod prime) * (r.value : ZMod prime) := by
  have h_power := two_pow_130
  simp only [multiplyAdd, Sums.value, Words.value]
  push_cast
  linear_combination (-(a.w1 * r.w4 + a.w2 * r.w3 + a.w3 * r.w2 + a.w4 * r.w1 : ZMod prime) -
    2 ^ 26 * (a.w2 * r.w4 + a.w3 * r.w3 + a.w4 * r.w2) - 2 ^ 52 * (a.w3 * r.w4 + a.w4 * r.w3) -
    2 ^ 78 * (a.w4 * r.w4)) * h_power

/-- A carry round keeps the number modulo `p`, when the carry out of sum 4 is below `2 ^ 32`. -/
theorem carryRound_mod {s : Sums} (h_d4 : s.d4 / 2 ^ 26 < 2 ^ 32) :
    ((carryRound s).value : ZMod prime) = (s.value : ZMod prime) := by
  have h_power := two_pow_130
  have h0 := congrArg (fun n : Nat => (n : ZMod prime)) (Nat.mod_add_div s.d0 (2 ^ 26))
  have h1 := congrArg (fun n : Nat => (n : ZMod prime)) (Nat.mod_add_div s.d1 (2 ^ 26))
  have h2 := congrArg (fun n : Nat => (n : ZMod prime)) (Nat.mod_add_div s.d2 (2 ^ 26))
  have h3 := congrArg (fun n : Nat => (n : ZMod prime)) (Nat.mod_add_div s.d3 (2 ^ 26))
  have h4 := congrArg (fun n : Nat => (n : ZMod prime)) (Nat.mod_add_div s.d4 (2 ^ 26))
  simp only [carryRound, Sums.value, Nat.mod_eq_of_lt h_d4] at h0 h1 h2 h3 h4 ⊢
  push_cast at h0 h1 h2 h3 h4 ⊢
  linear_combination h0 + 2 ^ 26 * h1 + 2 ^ 52 * h2 + 2 ^ 78 * h3 + 2 ^ 104 * h4 -
    ((s.d4 / 2 ^ 26 : Nat) : ZMod prime) * h_power

/-- The sum of two words is the sum of their numbers. -/
theorem add_value (a b : Words) : (a.add b).value = a.value + b.value := by
  simp only [Words.add, Words.value]
  ring

/-! ## Bounds -/

/-- Every word of `a` at most `A`. -/
def WordsLe (a : Words) (A : Nat) : Prop :=
  a.w0 ≤ A ∧ a.w1 ≤ A ∧ a.w2 ≤ A ∧ a.w3 ≤ A ∧ a.w4 ≤ A

/-- `multiply_add` from words at most `A` and a power that fits: sums 0 to 3 grow by at most
`21 A 2 ^ 26`, and sum 4, which no product by 5 times a word adds to, by at most `5 A 2 ^ 26`. -/
theorem multiplyAdd_le {s : Sums} {a r : Words} {A : Nat} (h_a : WordsLe a A)
    (h_r : PowerFits r) :
    (multiplyAdd s a r).d0 ≤ s.d0 + 21 * (A * 2 ^ 26) ∧
      (multiplyAdd s a r).d1 ≤ s.d1 + 21 * (A * 2 ^ 26) ∧
      (multiplyAdd s a r).d2 ≤ s.d2 + 21 * (A * 2 ^ 26) ∧
      (multiplyAdd s a r).d3 ≤ s.d3 + 21 * (A * 2 ^ 26) ∧
      (multiplyAdd s a r).d4 ≤ s.d4 + 5 * (A * 2 ^ 26) := by
  obtain ⟨a0, a1, a2, a3, a4⟩ := h_a
  obtain ⟨r0, r1, r2, r3, r4⟩ := h_r
  have m : ∀ {x y : Nat}, x ≤ A → y ≤ 2 ^ 26 → x * y ≤ A * 2 ^ 26 :=
    fun hx hy => Nat.mul_le_mul hx hy
  have m5 : ∀ {x y : Nat}, x ≤ A → y ≤ 2 ^ 26 → x * (5 * y) ≤ 5 * (A * 2 ^ 26) := by
    intro x y hx hy
    have := Nat.mul_le_mul hx hy
    rw [Nat.mul_left_comm]
    omega
  simp only [multiplyAdd]
  refine ⟨?_, ?_, ?_, ?_, ?_⟩
  · have := m5 a2 r3; have := m5 a3 r2; have := m5 a4 r1; have := m a0 r0; have := m5 a1 r4
    omega
  · have := m5 a2 r4; have := m5 a3 r3; have := m5 a4 r2; have := m a0 r1; have := m a1 r0
    omega
  · have := m a2 r0; have := m5 a3 r4; have := m5 a4 r3; have := m a0 r2; have := m a1 r1
    omega
  · have := m a2 r1; have := m a3 r0; have := m5 a4 r4; have := m a0 r3; have := m a1 r2
    omega
  · have := m a2 r2; have := m a3 r1; have := m a4 r0; have := m a0 r4; have := m a1 r3
    omega

/-- The rest of a pass, at most three pairs of blocks below `2 ^ 26` and powers that fit. -/
def RestFits (rest : List (Words × Words)) : Prop :=
  rest.length ≤ 3 ∧ ∀ p ∈ rest, BlockFits p.1 ∧ PowerFits p.2

/-- The sums of the rest of a pass, from zero: sums 0 to 3 at most `21 k 2 ^ 52` and sum 4 at
most `5 k 2 ^ 52` for `k` pairs. -/
private theorem rest_le (rest : List (Words × Words)) (h_rest : ∀ p ∈ rest, BlockFits p.1 ∧
    PowerFits p.2) (s : Sums) :
    (rest.foldl (fun s p => multiplyAdd s p.1 p.2) s).d0 ≤ s.d0 + rest.length * (21 * 2 ^ 52) ∧
      (rest.foldl (fun s p => multiplyAdd s p.1 p.2) s).d1 ≤
        s.d1 + rest.length * (21 * 2 ^ 52) ∧
      (rest.foldl (fun s p => multiplyAdd s p.1 p.2) s).d2 ≤
        s.d2 + rest.length * (21 * 2 ^ 52) ∧
      (rest.foldl (fun s p => multiplyAdd s p.1 p.2) s).d3 ≤
        s.d3 + rest.length * (21 * 2 ^ 52) ∧
      (rest.foldl (fun s p => multiplyAdd s p.1 p.2) s).d4 ≤
        s.d4 + rest.length * (5 * 2 ^ 52) := by
  induction rest generalizing s with
  | nil => simp
  | cons p rest ih =>
    obtain ⟨h_block, h_power⟩ := h_rest p (by simp)
    obtain ⟨b0, b1, b2, b3, b4⟩ := h_block
    have h_le : WordsLe p.1 (2 ^ 26) := ⟨by omega, by omega, by omega, by omega, by omega⟩
    obtain ⟨e0, e1, e2, e3, e4⟩ := multiplyAdd_le (s := s) h_le h_power
    obtain ⟨f0, f1, f2, f3, f4⟩ := ih (fun q hq => h_rest q (by simp [hq]))
      (multiplyAdd s p.1 p.2)
    simp only [List.foldl_cons, List.length_cons]
    refine ⟨?_, ?_, ?_, ?_, ?_⟩ <;> nlinarith

/-- A pass from words that fit, a first block below `2 ^ 26`, a power that fits, and the rest of
the pass: every operand of a product below `2 ^ 32`, every sum below `2 ^ 59`, the carry the
first round narrows below `2 ^ 32`, the first round's values below `2 ^ 34`, the second round's
narrowed carry below `2 ^ 32`, the second round's values fit, so `sums_narrow` keeps them, and the
result fits. -/
theorem passStep_bounds {h first x : Words} {rest : List (Words × Words)} (h_h : Fits h)
    (h_first : BlockFits first) (h_x : PowerFits x) (h_rest : RestFits rest) :
    WordsLe (h.add first) (2 ^ 32 - 1) ∧ 5 * 2 ^ 26 < 2 ^ 32 ∧
      (pairsSums h first x rest).d0 < 2 ^ 59 ∧ (pairsSums h first x rest).d1 < 2 ^ 59 ∧
      (pairsSums h first x rest).d2 < 2 ^ 59 ∧ (pairsSums h first x rest).d3 < 2 ^ 59 ∧
      (pairsSums h first x rest).d4 < 2 ^ 59 ∧
      (pairsSums h first x rest).d4 / 2 ^ 26 < 2 ^ 32 ∧
      (carryRound (pairsSums h first x rest)).d0 < 2 ^ 34 ∧
      (carryRound (pairsSums h first x rest)).d1 < 2 ^ 34 ∧
      (carryRound (pairsSums h first x rest)).d2 < 2 ^ 34 ∧
      (carryRound (pairsSums h first x rest)).d3 < 2 ^ 34 ∧
      (carryRound (pairsSums h first x rest)).d4 < 2 ^ 34 ∧
      (carryRound (pairsSums h first x rest)).d4 / 2 ^ 26 < 2 ^ 32 ∧
      Fits ⟨(carryRound (carryRound (pairsSums h first x rest))).d0,
        (carryRound (carryRound (pairsSums h first x rest))).d1,
        (carryRound (carryRound (pairsSums h first x rest))).d2,
        (carryRound (carryRound (pairsSums h first x rest))).d3,
        (carryRound (carryRound (pairsSums h first x rest))).d4⟩ ∧
      Fits (passStep h first x rest) := by
  obtain ⟨h0, h1, h2, h3, h4⟩ := h_h
  obtain ⟨f0, f1, f2, f3, f4⟩ := h_first
  obtain ⟨h_length, h_each⟩ := h_rest
  have h_rev : ∀ p ∈ rest.reverse, BlockFits p.1 ∧ PowerFits p.2 :=
    fun p hp => h_each p (List.mem_reverse.mp hp)
  obtain ⟨g0, g1, g2, g3, g4⟩ := rest_le rest.reverse h_rev Sums.zero
  rw [List.length_reverse] at g0 g1 g2 g3 g4
  have h_add : WordsLe (h.add first) (2 ^ 27 + 2 ^ 10) := by
    simp only [WordsLe, Words.add]
    omega
  obtain ⟨e0, e1, e2, e3, e4⟩ :=
    multiplyAdd_le (s := rest.reverse.foldl (fun s p => multiplyAdd s p.1 p.2) Sums.zero) h_add h_x
  have z0 : Sums.zero.d0 = 0 := rfl
  have z1 : Sums.zero.d1 = 0 := rfl
  have z2 : Sums.zero.d2 = 0 := rfl
  have z3 : Sums.zero.d3 = 0 := rfl
  have z4 : Sums.zero.d4 = 0 := rfl
  have k3 : rest.length * (21 * 2 ^ 52) ≤ 3 * (21 * 2 ^ 52) := Nat.mul_le_mul_right _ h_length
  have k4 : rest.length * (5 * 2 ^ 52) ≤ 3 * (5 * 2 ^ 52) := Nat.mul_le_mul_right _ h_length
  have s0 : (pairsSums h first x rest).d0 ≤ 21 * 2 ^ 52 * 3 + 21 * ((2 ^ 27 + 2 ^ 10) * 2 ^ 26) := by
    simp only [pairsSums]; omega
  have s1 : (pairsSums h first x rest).d1 ≤ 21 * 2 ^ 52 * 3 + 21 * ((2 ^ 27 + 2 ^ 10) * 2 ^ 26) := by
    simp only [pairsSums]; omega
  have s2 : (pairsSums h first x rest).d2 ≤ 21 * 2 ^ 52 * 3 + 21 * ((2 ^ 27 + 2 ^ 10) * 2 ^ 26) := by
    simp only [pairsSums]; omega
  have s3 : (pairsSums h first x rest).d3 ≤ 21 * 2 ^ 52 * 3 + 21 * ((2 ^ 27 + 2 ^ 10) * 2 ^ 26) := by
    simp only [pairsSums]; omega
  have s4 : (pairsSums h first x rest).d4 ≤ 5 * 2 ^ 52 * 3 + 5 * ((2 ^ 27 + 2 ^ 10) * 2 ^ 26) := by
    simp only [pairsSums]; omega
  have w : WordsLe (h.add first) (2 ^ 32 - 1) := by
    simp only [WordsLe, Words.add]
    omega
  refine ⟨w, by norm_num, by omega, by omega, by omega, by omega, by omega, by omega, ?_⟩
  simp only [passStep, carry]
  generalize pairsSums h first x rest = s at s0 s1 s2 s3 s4
  have t0 : (carryRound s).d0 < 2 ^ 34 := by simp only [carryRound]; omega
  have t1 : (carryRound s).d1 < 2 ^ 34 := by simp only [carryRound]; omega
  have t2 : (carryRound s).d2 < 2 ^ 34 := by simp only [carryRound]; omega
  have t3 : (carryRound s).d3 < 2 ^ 34 := by simp only [carryRound]; omega
  have t4 : (carryRound s).d4 < 2 ^ 26 + 2 ^ 33 := by simp only [carryRound]; omega
  refine ⟨t0, t1, t2, t3, by omega, by omega, ?_⟩
  generalize carryRound s = t at t0 t1 t2 t3 t4
  have u0 : (carryRound t).d0 < 2 ^ 26 + 2 ^ 10 := by simp only [carryRound]; omega
  have u1 : (carryRound t).d1 < 2 ^ 26 + 2 ^ 10 := by simp only [carryRound]; omega
  have u2 : (carryRound t).d2 < 2 ^ 26 + 2 ^ 10 := by simp only [carryRound]; omega
  have u3 : (carryRound t).d3 < 2 ^ 26 + 2 ^ 10 := by simp only [carryRound]; omega
  have u4 : (carryRound t).d4 < 2 ^ 26 + 2 ^ 10 := by simp only [carryRound]; omega
  refine ⟨⟨u0, u1, u2, u3, u4⟩, ?_⟩
  generalize carryRound t = u at u0 u1 u2 u3 u4
  simp only [Fits]
  omega

/-- A pass computes `(h + first) x + b1 x1 + ... + bk xk` modulo `p`, under `passStep_bounds`'s
hypotheses. -/
theorem passStep_mod {h first x : Words} {rest : List (Words × Words)} (h_h : Fits h)
    (h_first : BlockFits first) (h_x : PowerFits x) (h_rest : RestFits rest) :
    ((passStep h first x rest).value : ZMod prime) =
      ((h.value + first.value : Nat) : ZMod prime) * x.value +
        (rest.map fun p => (p.1.value : ZMod prime) * p.2.value).sum := by
  obtain ⟨-, -, -, -, -, -, -, h_d4, -, -, -, -, -, h_d4', ⟨u0, u1, u2, u3, u4⟩, -⟩ :=
    passStep_bounds h_h h_first h_x h_rest
  have h_fold : ∀ (l : List (Words × Words)) (s : Sums),
      ((l.foldl (fun s p => multiplyAdd s p.1 p.2) s).value : ZMod prime) =
        (s.value : ZMod prime) + (l.map fun p => (p.1.value : ZMod prime) * p.2.value).sum := by
    intro l
    induction l with
    | nil => intro s; simp
    | cons p l ih =>
      intro s
      simp only [List.foldl_cons, List.map_cons, List.sum_cons]
      rw [ih, multiplyAdd_mod]
      ring
  have h_value : (passStep h first x rest).value =
      (carryRound (carryRound (pairsSums h first x rest))).value := by
    simp only at u0 u1 u2 u3 u4
    simp only [passStep, carry, Words.value, Sums.value]
    rw [Nat.mod_eq_of_lt (u0.trans (by norm_num)), Nat.mod_eq_of_lt (u1.trans (by norm_num)),
      Nat.mod_eq_of_lt (u2.trans (by norm_num)), Nat.mod_eq_of_lt (u3.trans (by norm_num)),
      Nat.mod_eq_of_lt (u4.trans (by norm_num))]
  rw [h_value, carryRound_mod h_d4', carryRound_mod h_d4, pairsSums, multiplyAdd_mod, h_fold,
    add_value]
  simp only [Sums.zero, Sums.value, List.map_reverse, List.sum_reverse]
  push_cast
  ring

/-! ## The entry -/

/-- `carry_scalar` of `poly1305_scalar.h`: five sums below `2 ^ 60` carried into five words, twice
around, with the C's masks and its 32-bit casts. -/
def carryScalar (d0 d1 d2 d3 d4 : Nat) : Words :=
  let d1 := d1 + d0 / 2 ^ 26
  let d2 := d2 + d1 / 2 ^ 26
  let d3 := d3 + d2 / 2 ^ 26
  let d4 := d4 + d3 / 2 ^ 26
  let h0 := d0 % 2 ^ 26 + d4 / 2 ^ 26 * 5
  let h1 := d1 % 2 ^ 26 + h0 / 2 ^ 26
  let h2 := d2 % 2 ^ 26
  let h3 := d3 % 2 ^ 26
  let h4 := d4 % 2 ^ 26
  let w0 := h0 % 2 ^ 26
  let w1 := h1 % 2 ^ 32 % 2 ^ 26
  let h2 := (h2 + h1 / 2 ^ 26 % 2 ^ 32) % 2 ^ 32
  let w2 := h2 % 2 ^ 26
  let h3 := (h3 + h2 / 2 ^ 26) % 2 ^ 32
  let w3 := h3 % 2 ^ 26
  let h4 := (h4 + h3 / 2 ^ 26) % 2 ^ 32
  let w4 := h4 % 2 ^ 26
  let w0 := (w0 + h4 / 2 ^ 26 * 5) % 2 ^ 32
  let w1 := (w1 + w0 / 2 ^ 26) % 2 ^ 32
  ⟨w0 % 2 ^ 26, w1, w2, w3, w4⟩

/-- `multiply_scalar`: the product of two numbers modulo `p`, as `carry_scalar` leaves it. -/
def multiplyScalar (a r : Words) : Words :=
  let s := multiplyAdd Sums.zero a r
  carryScalar s.d0 s.d1 s.d2 s.d3 s.d4

/-- The five words `load_blocks` reads from a block's two little-endian halves, with its
`2 ^ 128` bit. -/
def blockWords (low high : Nat) : Words :=
  ⟨low % 2 ^ 26, low / 2 ^ 26 % 2 ^ 26, (low / 2 ^ 52 + high * 2 ^ 12) % 2 ^ 26,
    high / 2 ^ 14 % 2 ^ 26, high / 2 ^ 40 + 2 ^ 24⟩

/-- The two lanes' accumulators. -/
structure Lanes where
  /-- Lane 0. -/
  lane0 : Words
  /-- Lane 1. -/
  lane1 : Words

/-- `pairs_sums` on both lanes over `pairs` pairs of `blocks` from block `at`: lane `l` takes
block `2 k + l` of each pair `k` with multiplier `by (k, l)`. -/
def lanesSums (h : Lanes) (blocks : Nat → Words) (at_ pairs : Nat) (by_ : Nat → Nat → Words) :
    Sums × Sums :=
  let rest (l : Nat) := (List.range (pairs - 1)).map fun k =>
    (blocks (at_ + 2 * (k + 1) + l), by_ (k + 1) l)
  (pairsSums h.lane0 (blocks at_) (by_ 0 0) (rest 0),
    pairsSums h.lane1 (blocks (at_ + 1)) (by_ 0 1) (rest 1))

/-- `poly1305_vector_blocks` on `groups` groups of four blocks, `blocks j` the words of block `j`,
from the accumulator `h` and the key's `r`, with passes of `pairsMax` pairs from
`POLY1305_VECTOR_WIDE_MIN` bytes on: 4 on NEON and 2 on SSE2. -/
def entry (pairsMax : Nat) (r h : Words) (blocks : Nat → Words) (groups : Nat) : Words :=
  let pairs := if pairsMax > 2 ∧ 64 * groups ≥ 2048 then pairsMax else 2
  -- power i is r ^ (i + 1), as powers_compute writes it.
  let p1 := multiplyScalar r r
  let p2 := multiplyScalar p1 r
  let p3 := multiplyScalar p1 p1
  let p4 := multiplyScalar p3 r
  let p5 := multiplyScalar p3 p1
  let p6 := multiplyScalar p3 p2
  let p7 := multiplyScalar p3 p3
  let power : Nat → Words := fun i =>
    match i with
    | 0 => r | 1 => p1 | 2 => p2 | 3 => p3 | 4 => p4 | 5 => p5 | 6 => p6 | _ => p7
  -- multipliers_set: pair k of a pass of `pairs` pairs multiplies by r ^ (2 (pairs - k)), and
  -- in the last pass lane 1 by one power less.
  let steady : Nat → Nat → Nat → Words := fun n k _ => power (2 * (n - k) - 1)
  let last : Nat → Nat → Nat → Words := fun n k l => power (2 * (n - k) - 1 - l)
  let step (h : Lanes) (at_ n : Nat) : Lanes :=
    let (s0, s1) := lanesSums h blocks at_ n (steady n)
    ⟨carry s0, carry s1⟩
  let start : Lanes := ⟨h, ⟨0, 0, 0, 0, 0⟩⟩
  let passGroups := pairs / 2
  let lead := groups % passGroups
  -- The lead group, when there is one before the passes.
  let (h1, at1, left1) :=
    if lead ≠ 0 ∧ groups > lead then (step start 0 2, 4 * lead, groups - lead)
    else (start, 0, groups)
  -- Every pass but the last.
  let full := (left1 - 1) / passGroups
  let h2 := (List.range full).foldl (fun acc i => step acc (at1 + 4 * passGroups * i) pairs) h1
  let at2 := at1 + 4 * passGroups * full
  let left2 := left1 - passGroups * full
  let n := if left2 = passGroups then pairs else 2
  let (s0, s1) := lanesSums h2 blocks at2 n (last n)
  carryScalar (s0.d0 + s1.d0) (s0.d1 + s1.d1) (s0.d2 + s1.d2) (s0.d3 + s1.d3) (s0.d4 + s1.d4)

/-! ## The selftest -/

/-- `r ^ e` times `x` modulo `p` on numbers, the selftest's reference. -/
private def hornerMod (r : Nat) (h : Nat) (blocks : List Nat) : Nat :=
  blocks.foldl (fun acc b => (acc + b) * r % prime) h

set_option compiler.extract_closed false in
/-- The entry on a key's `r` and blocks of all ones bits, at one to forty groups and both pass
widths, against Horner's rule modulo `p`. -/
def selftest (_ : Unit) : Bool :=
  let r : Words := ⟨0x2c88c77, 0x0849d64, 0x1aa82e8, 0x1aab840, 0x000a4dc⟩
  let h : Words := ⟨2 ^ 26 - 1, 2 ^ 26, 2 ^ 26 - 1, 2 ^ 26 - 1, 2 ^ 26 - 1⟩
  let block := blockWords (2 ^ 64 - 1) (2 ^ 64 - 1)
  (List.range 40).all fun g =>
    let groups := g + 1
    let want := hornerMod r.value h.value (List.replicate (4 * groups) block.value)
    [2, 4].all fun pairsMax =>
      (entry pairsMax r h (fun _ => block) groups).value % prime == want

end Spec.Poly1305Vector
