import Mathlib.Data.ZMod.Basic
import Mathlib.Tactic

/-!
Poly1305's block loop on AVX-512 IFMA, `poly1305_ifma.c`, modeled from the C, one 64-bit lane at a
time: every lane operation the kernel runs acts on each lane alone, but for the loads, which
`blockDigits` and `blockOf` state, the broadcast of lane 0 and the lane totals at the end.

A lane holds a number as three digits, `x0 + x1 2 ^ 44 + x2 2 ^ 88` (`Digits`). A power of `r` in a
lane is a `Multiplier`: its digits and 20 times digits 1 and 2, because modulo `p = 2 ^ 130 - 5`,
`2 ^ 132` is `20`. `multiplyAdd` is the C's `multiply_add`: eighteen VPMADD52LUQ and VPMADD52HUQ,
which add bits 51..0 and bits 103..52 of a product to six sums. `carry` is the C's `carry`, one
round that turns the six sums into three digits. `groupStep` is a lane of the group loop's body,
`group_sums` and `carry`: `(h + first) x + second y`. `computePowers` is `compute_powers`.

`groupStep_mod` proves that a group step computes that value modulo `p`, and `groupStep_bounds`
that from digits within `Fits` (digits 0 and 1 below `2 ^ 44 + 2 ^ 17`, digit 2 below
`2 ^ 42 + 2 ^ 17`), blocks as `blockDigits` reads them and multipliers whose digits fit, every
operand of a multiplication is below `2 ^ 52`, the six sums after each `multiply_add` and the
three numbers the carry splits are below `2 ^ 56`, and the result fits again. A sum inside a
`multiply_add` is at most the sum after it, because each step only adds. So the C's 64-bit lanes
hold the model's numbers at every group, by induction over the loop. `product_mod` and
`product_bounds` prove the same of `multiplier_product`, and `powers_mod` that lane `l` of the
four multipliers `compute_powers` writes holds `r ^ (16 - b)`, `r ^ (8 - b)`, `r ^ 16` and
`r ^ 8` modulo `p`, `b` being the block `load_blocks` gives lane `l`. `blockDigits_value`,
`digitsOfWords_value` and `totals_value` prove that the loads and the two conversions keep the
number they convert.

This module is written from the C, not from a standard, and CONTRACT.md says why.
-/

namespace Spec.Poly1305Ifma

/-- The Poly1305 prime, `2 ^ 130 - 5`. -/
def prime : Nat := 2 ^ 130 - 5

/-! ## Digits and multipliers -/

/-- One lane's number: three digits, at `2 ^ 0`, `2 ^ 44` and `2 ^ 88`. -/
structure Digits where
  /-- Digit 0, at `2 ^ 0`. -/
  d0 : Nat
  /-- Digit 1, at `2 ^ 44`. -/
  d1 : Nat
  /-- Digit 2, at `2 ^ 88`. -/
  d2 : Nat
  deriving Repr, DecidableEq

/-- The number three digits hold. -/
def Digits.value (x : Digits) : Nat :=
  x.d0 + 2 ^ 44 * x.d1 + 2 ^ 88 * x.d2

/-- `lanes_add` on each digit: `first_blocks[i] + h[i]` in `group_sums`. -/
def Digits.add (a b : Digits) : Digits :=
  ⟨a.d0 + b.d0, a.d1 + b.d1, a.d2 + b.d2⟩

/-- Digits as a carry leaves them: digits 0 and 1 below `2 ^ 44 + 2 ^ 17` and digit 2 below
`2 ^ 42 + 2 ^ 17`, the bounds `proof/poly1305_ifma_stubs.h` names. -/
def Fits (x : Digits) : Prop :=
  x.d0 < 2 ^ 44 + 2 ^ 17 ∧ x.d1 < 2 ^ 44 + 2 ^ 17 ∧ x.d2 < 2 ^ 42 + 2 ^ 17

/-- `Fits` as a test the oracle can run on its inputs. -/
instance (x : Digits) : Decidable (Fits x) :=
  inferInstanceAs (Decidable (_ ∧ _ ∧ _))

/-- Digits as `load_blocks` writes them: digits 0 and 1 below `2 ^ 44` and digit 2 below
`2 ^ 41`. -/
def BlockFits (x : Digits) : Prop :=
  x.d0 < 2 ^ 44 ∧ x.d1 < 2 ^ 44 ∧ x.d2 < 2 ^ 41

/-- A power of `r` in one lane, the C's `multiplier`: its digits, and `s1` and `s2`, 20 times
digits 1 and 2. -/
structure Multiplier where
  /-- Digit 0. -/
  r0 : Nat
  /-- Digit 1. -/
  r1 : Nat
  /-- Digit 2. -/
  r2 : Nat
  /-- 20 times digit 1. -/
  s1 : Nat
  /-- 20 times digit 2. -/
  s2 : Nat
  deriving Repr

/-- `lanes_times_20`: 16 times a digit plus 4 times it, two shifts and an add. -/
def times20 (x : Nat) : Nat :=
  2 ^ 4 * x + 2 ^ 2 * x

/-- `lanes_times_5`: a digit plus 4 times it. -/
def times5 (x : Nat) : Nat :=
  x + 2 ^ 2 * x

/-- `multiplier_complete`: a power's digits and the two multiples by 20. -/
def complete (r : Digits) : Multiplier :=
  ⟨r.d0, r.d1, r.d2, times20 r.d1, times20 r.d2⟩

/-! ## A product -/

/-- `lanes_multiply_add_low` (VPMADD52LUQ) on one lane: `sum` plus bits 51..0 of the product of
bits 51..0 of `x` and bits 51..0 of `y`. -/
def multiplyAddLow (sum x y : Nat) : Nat :=
  sum + x % 2 ^ 52 * (y % 2 ^ 52) % 2 ^ 52

/-- `lanes_multiply_add_high` (VPMADD52HUQ) on one lane: `sum` plus bits 103..52 of the same
product. -/
def multiplyAddHigh (sum x y : Nat) : Nat :=
  sum + x % 2 ^ 52 * (y % 2 ^ 52) / 2 ^ 52

/-- The six sums of a product in one lane: `lo i` adds bits 51..0 and `hi i` bits 103..52 of the
products of digit pairs at `2 ^ (44 i)`. -/
structure Sums where
  /-- `lo[0]`. -/
  lo0 : Nat
  /-- `lo[1]`. -/
  lo1 : Nat
  /-- `lo[2]`. -/
  lo2 : Nat
  /-- `hi[0]`. -/
  hi0 : Nat
  /-- `hi[1]`. -/
  hi1 : Nat
  /-- `hi[2]`. -/
  hi2 : Nat
  deriving Repr

/-- `sums_zero`. -/
def Sums.zero : Sums :=
  ⟨0, 0, 0, 0, 0, 0⟩

/-- The number six sums hold: `lo i + 2 ^ 52 hi i` at `2 ^ (44 i)`. -/
def Sums.value (s : Sums) : Nat :=
  s.lo0 + 2 ^ 52 * s.hi0 + 2 ^ 44 * (s.lo1 + 2 ^ 52 * s.hi1) +
    2 ^ 88 * (s.lo2 + 2 ^ 52 * s.hi2)

/-- `multiply_add`: the eighteen multiplications in the C's order, `a1`'s, then `a2`'s, then
`a0`'s. -/
def multiplyAdd (s : Sums) (a : Digits) (b : Multiplier) : Sums :=
  let lo0 := multiplyAddLow s.lo0 a.d1 b.s2
  let hi0 := multiplyAddHigh s.hi0 a.d1 b.s2
  let lo1 := multiplyAddLow s.lo1 a.d1 b.r0
  let hi1 := multiplyAddHigh s.hi1 a.d1 b.r0
  let lo2 := multiplyAddLow s.lo2 a.d1 b.r1
  let hi2 := multiplyAddHigh s.hi2 a.d1 b.r1
  let lo0 := multiplyAddLow lo0 a.d2 b.s1
  let hi0 := multiplyAddHigh hi0 a.d2 b.s1
  let lo1 := multiplyAddLow lo1 a.d2 b.s2
  let hi1 := multiplyAddHigh hi1 a.d2 b.s2
  let lo2 := multiplyAddLow lo2 a.d2 b.r0
  let hi2 := multiplyAddHigh hi2 a.d2 b.r0
  let lo0 := multiplyAddLow lo0 a.d0 b.r0
  let hi0 := multiplyAddHigh hi0 a.d0 b.r0
  let lo1 := multiplyAddLow lo1 a.d0 b.r1
  let hi1 := multiplyAddHigh hi1 a.d0 b.r1
  let lo2 := multiplyAddLow lo2 a.d0 b.r2
  let hi2 := multiplyAddHigh hi2 a.d0 b.r2
  ⟨lo0, lo1, lo2, hi0, hi1, hi2⟩

/-- `carry`'s `t0`: `lo0 + 5 (hi2 << 10)`, the number at `2 ^ 0`, because `2 ^ 140` is
`5 2 ^ 10` modulo `p`. -/
def Sums.t0 (s : Sums) : Nat :=
  s.lo0 + times5 (2 ^ 10 * s.hi2)

/-- `carry`'s `t1`: `lo1 + (hi0 << 8)`, the number at `2 ^ 44`. -/
def Sums.t1 (s : Sums) : Nat :=
  s.lo1 + 2 ^ 8 * s.hi0

/-- `carry`'s `t2`: `lo2 + (hi1 << 8)`, the number at `2 ^ 88`. -/
def Sums.t2 (s : Sums) : Nat :=
  s.lo2 + 2 ^ 8 * s.hi1

/-- `carry`: the six sums carried into three digits in one round. Each digit keeps its own bits of
`t0`, `t1` or `t2` and takes the bits above the digit below; `t2`'s bits from 42 up, at `2 ^ 130`,
come back to digit 0 times 5. -/
def carry (s : Sums) : Digits :=
  ⟨s.t0 % 2 ^ 44 + times5 (s.t2 / 2 ^ 42), s.t1 % 2 ^ 44 + s.t0 / 2 ^ 44,
    s.t2 % 2 ^ 42 + s.t1 / 2 ^ 44⟩

/-- `multiplier_product` on one lane: `a` times `b`, carried by one round. -/
def product (a b : Digits) : Digits :=
  carry (multiplyAdd Sums.zero a (complete b))

/-- `group_sums` on one lane: the lane's second block times `y`, then `h` plus its first block
times `x`. -/
def groupSums (h first second : Digits) (x y : Multiplier) : Sums :=
  multiplyAdd (multiplyAdd Sums.zero second y) (h.add first) x

/-- One lane of the group loop's body, `group_sums` and `carry`. -/
def groupStep (h first second : Digits) (x y : Multiplier) : Digits :=
  carry (groupSums h first second x y)

/-! ## Loads and conversions -/

/-- `load_blocks` on one block, its two 64-bit halves `low` and `high`: bits 0 to 43, 44 to 87
and 88 to 127, with the `2 ^ 128` bit at bit 40 of the top digit. The C's ors join bits that do not
overlap, so they are the adds here. -/
def blockDigits (low high : Nat) : Digits :=
  ⟨low % 2 ^ 44, (low / 2 ^ 44 + 2 ^ 20 * high) % 2 ^ 44, high / 2 ^ 24 + 2 ^ 40⟩

/-- The block of a group's first eight that `load_blocks` gives lane `l`: VPUNPCKLQDQ and
VPUNPCKHQDQ pair the lanes of two loads of four blocks, so lanes 0 to 7 take blocks 0, 4, 1, 5,
2, 6, 3 and 7. Lane `l` takes block `8 + blockOf l` of the group's last eight. -/
def blockOf (l : Fin 8) : Nat :=
  [0, 4, 1, 5, 2, 6, 3, 7].getD l.val 0

/-- `digits_of_words`: five 26-bit words as three digits. -/
def digitsOfWords (w0 w1 w2 w3 w4 : Nat) : Digits :=
  let l0 := w0 + 2 ^ 26 * w1
  let l1 := 2 ^ 8 * w2 + 2 ^ 34 * w3 + l0 / 2 ^ 44
  ⟨l0 % 2 ^ 44, l1 % 2 ^ 44, 2 ^ 16 * w4 + l1 / 2 ^ 44⟩

/-- `words_of_totals`' five sums `d[0]` to `d[4]` before `carry_scalar`, from the three lane
totals. -/
def totalsSums (t0 t1 t2 : Nat) : List Nat :=
  [t0 % 2 ^ 26, t0 / 2 ^ 26 + 2 ^ 18 * (t1 % 2 ^ 8), t1 / 2 ^ 8, 2 ^ 10 * (t2 % 2 ^ 16),
    t2 / 2 ^ 16]

/-! ## The powers of `r` -/

/-- A register of eight lanes, a power of `r` in each. -/
abbrev Register := Fin 8 → Digits

/-- The number 1 as digits, which `multiplier_select_one` writes where a bit is clear. -/
def one : Digits :=
  ⟨1, 0, 0⟩

/-- `multiplier_select` (VPBLENDMQ): lane `l` of `b` where bit `l` of `bits` is set, of `a`
where it is clear. -/
def select (bits : Nat) (a b : Register) : Register :=
  fun l => if bits / 2 ^ l.val % 2 = 1 then b l else a l

/-- `multiplier_select_one`: lane `l` of `b` where bit `l` of `bits` is set, 1 where it is
clear. -/
def selectOne (bits : Nat) (b : Register) : Register :=
  fun l => if bits / 2 ^ l.val % 2 = 1 then b l else one

/-- `multiplier_first`: lane 0 in every lane. -/
def broadcastFirst (b : Register) : Register :=
  fun _ => b 0

/-- `multiplier_product` on every lane. -/
def productLanes (a b : Register) : Register :=
  fun l => product (a l) (b l)

/-- The four multipliers `compute_powers` writes, in the C's struct order. -/
structure Powers where
  /-- `last_first`, the last group's first multiplier. -/
  lastFirst : Register
  /-- `last_second`, the last group's second multiplier. -/
  lastSecond : Register
  /-- `by_16`, every other group's first multiplier. -/
  by16 : Register
  /-- `by_8`, every other group's second multiplier. -/
  by8 : Register

/-- `compute_powers` from `r`'s digits, each statement the C's in its order. -/
def computePowers (r : Digits) : Powers :=
  let rOne : Register := fun _ => r
  let rTwo := productLanes rOne rOne
  let by8 := productLanes rTwo rTwo
  let lastSecond := select 0x0f rOne rTwo
  let by16 := selectOne 0x3f rOne
  let by16 := select 0x03 by16 rTwo
  let lastFirst := productLanes lastSecond by16
  let by8 := selectOne 0x55 by8
  let lastSecond := productLanes lastFirst by8
  let by8 := broadcastFirst lastSecond
  let lastFirst := productLanes lastSecond by8
  ⟨lastFirst, lastSecond, broadcastFirst lastFirst, by8⟩

/-! ## Values -/

/-- In the field of `p`, `2 ^ 130` is 5. -/
private theorem two_pow_130 : (2 : ZMod prime) ^ 130 = 5 := by
  have h_sum : (2 ^ 130 : Nat) = prime + 5 := by norm_num [prime]
  have h_cast := congrArg (Nat.cast : Nat → ZMod prime) h_sum
  rw [Nat.cast_add, ZMod.natCast_self, zero_add, Nat.cast_pow, Nat.cast_ofNat,
    Nat.cast_ofNat] at h_cast
  exact h_cast

/-- A product of operands below `2 ^ 52` is its two halves. -/
private theorem low_add_high {x y : Nat} (h_x : x < 2 ^ 52) (h_y : y < 2 ^ 52) :
    x % 2 ^ 52 * (y % 2 ^ 52) % 2 ^ 52 + 2 ^ 52 * (x % 2 ^ 52 * (y % 2 ^ 52) / 2 ^ 52) =
      x * y := by
  rw [Nat.mod_eq_of_lt h_x, Nat.mod_eq_of_lt h_y, Nat.mod_add_div]

/-- Every digit and every multiple of a multiplier below `2 ^ 52`, the bits a multiplication
reads. -/
def Operands (a : Digits) (b : Multiplier) : Prop :=
  a.d0 < 2 ^ 52 ∧ a.d1 < 2 ^ 52 ∧ a.d2 < 2 ^ 52 ∧ b.r0 < 2 ^ 52 ∧ b.r1 < 2 ^ 52 ∧
    b.r2 < 2 ^ 52 ∧ b.s1 < 2 ^ 52 ∧ b.s2 < 2 ^ 52

/-- The number the eighteen products add: each digit pair's product at its place, the products
past `2 ^ 132` taken by the multiples by 20. -/
def productValue (a : Digits) (b : Multiplier) : Nat :=
  a.d0 * b.r0 + a.d1 * b.s2 + a.d2 * b.s1 +
    2 ^ 44 * (a.d0 * b.r1 + a.d1 * b.r0 + a.d2 * b.s2) +
    2 ^ 88 * (a.d0 * b.r2 + a.d1 * b.r1 + a.d2 * b.r0)

/-- `multiply_add` adds `productValue` to the six sums, exactly, for operands below `2 ^ 52`. -/
theorem multiplyAdd_value {s : Sums} {a : Digits} {b : Multiplier} (h_operands : Operands a b) :
    (multiplyAdd s a b).value = s.value + productValue a b := by
  obtain ⟨h_a0, h_a1, h_a2, h_r0, h_r1, h_r2, h_s1, h_s2⟩ := h_operands
  simp only [multiplyAdd, Sums.value, productValue, multiplyAddLow, multiplyAddHigh]
  have := low_add_high h_a1 h_s2
  have := low_add_high h_a1 h_r0
  have := low_add_high h_a1 h_r1
  have := low_add_high h_a2 h_s1
  have := low_add_high h_a2 h_s2
  have := low_add_high h_a2 h_r0
  have := low_add_high h_a0 h_r0
  have := low_add_high h_a0 h_r1
  have := low_add_high h_a0 h_r2
  nlinarith

/-- With the multiples by 20 a completed multiplier holds, the products are `a b` modulo `p`. -/
theorem productValue_mod (a r : Digits) :
    (productValue a (complete r) : ZMod prime) =
      (a.value : ZMod prime) * (r.value : ZMod prime) := by
  have h_power := two_pow_130
  simp only [productValue, complete, times20, Digits.value]
  push_cast
  linear_combination (-(4 * (a.d1 : ZMod prime) * r.d2 + 4 * a.d2 * r.d1 +
    2 ^ 46 * a.d2 * r.d2)) * h_power

/-- The carry keeps the number the six sums hold, modulo `p`. -/
theorem carry_mod (s : Sums) :
    ((carry s).value : ZMod prime) = (s.value : ZMod prime) := by
  have h_power := two_pow_130
  have h_split0 := congrArg (fun n : Nat => (n : ZMod prime)) (Nat.mod_add_div s.t0 (2 ^ 44))
  have h_split1 := congrArg (fun n : Nat => (n : ZMod prime)) (Nat.mod_add_div s.t1 (2 ^ 44))
  have h_split2 := congrArg (fun n : Nat => (n : ZMod prime)) (Nat.mod_add_div s.t2 (2 ^ 42))
  have h_t0 : (s.t0 : ZMod prime) = s.lo0 + 5 * 2 ^ 10 * s.hi2 := by
    simp only [Sums.t0, times5]
    push_cast
    ring
  have h_t1 : (s.t1 : ZMod prime) = s.lo1 + 2 ^ 8 * s.hi0 := by
    simp only [Sums.t1]
    push_cast
    ring
  have h_t2 : (s.t2 : ZMod prime) = s.lo2 + 2 ^ 8 * s.hi1 := by
    simp only [Sums.t2]
    push_cast
    ring
  simp only [carry, Digits.value, Sums.value, times5] at h_split0 h_split1 h_split2 ⊢
  push_cast at h_split0 h_split1 h_split2 ⊢
  linear_combination h_split0 + 2 ^ 44 * h_split1 + 2 ^ 88 * h_split2 + h_t0 + 2 ^ 44 * h_t1 +
    2 ^ 88 * h_t2 + (-((s.t2 / 2 ^ 42 : Nat) : ZMod prime) - 2 ^ 10 * s.hi2) * h_power

/-- The sum of two digits is the sum of their numbers. -/
theorem add_value (a b : Digits) : (a.add b).value = a.value + b.value := by
  simp only [Digits.add, Digits.value]
  ring

/-! ## Bounds -/

/-- `multiplyAddLow` adds less than `2 ^ 52`. -/
private theorem low_lt (s x y : Nat) : multiplyAddLow s x y < s + 2 ^ 52 := by
  have := Nat.mod_lt (x % 2 ^ 52 * (y % 2 ^ 52)) (by norm_num : 2 ^ 52 > 0)
  simp only [multiplyAddLow]
  omega

/-- `multiplyAddHigh` adds at most `X Y / 2 ^ 52` for operands at most `X` and `Y`. -/
private theorem high_le {s x y X Y : Nat} (h_x : x ≤ X) (h_y : y ≤ Y) :
    multiplyAddHigh s x y ≤ s + X * Y / 2 ^ 52 := by
  have h_product : x % 2 ^ 52 * (y % 2 ^ 52) ≤ X * Y :=
    Nat.mul_le_mul ((Nat.mod_le x (2 ^ 52)).trans h_x) ((Nat.mod_le y (2 ^ 52)).trans h_y)
  have : x % 2 ^ 52 * (y % 2 ^ 52) / 2 ^ 52 ≤ X * Y / 2 ^ 52 := Nat.div_le_div_right h_product
  simp only [multiplyAddHigh]
  omega

/-- `multiply_add`'s six sums, from bounds on its operands: each `lo` sum grows by less than
`3 2 ^ 52`, and each `hi` sum by at most its three products' bounds over `2 ^ 52`. -/
theorem multiplyAdd_le {s : Sums} {a : Digits} {b : Multiplier} {A0 A1 A2 R0 R1 R2 S1 S2 : Nat}
    (h_a0 : a.d0 ≤ A0) (h_a1 : a.d1 ≤ A1) (h_a2 : a.d2 ≤ A2) (h_r0 : b.r0 ≤ R0)
    (h_r1 : b.r1 ≤ R1) (h_r2 : b.r2 ≤ R2) (h_s1 : b.s1 ≤ S1) (h_s2 : b.s2 ≤ S2) :
    (multiplyAdd s a b).lo0 < s.lo0 + 3 * 2 ^ 52 ∧
      (multiplyAdd s a b).lo1 < s.lo1 + 3 * 2 ^ 52 ∧
      (multiplyAdd s a b).lo2 < s.lo2 + 3 * 2 ^ 52 ∧
      (multiplyAdd s a b).hi0 ≤ s.hi0 + A1 * S2 / 2 ^ 52 + A2 * S1 / 2 ^ 52 + A0 * R0 / 2 ^ 52 ∧
      (multiplyAdd s a b).hi1 ≤ s.hi1 + A1 * R0 / 2 ^ 52 + A2 * S2 / 2 ^ 52 + A0 * R1 / 2 ^ 52 ∧
      (multiplyAdd s a b).hi2 ≤
        s.hi2 + A1 * R1 / 2 ^ 52 + A2 * R0 / 2 ^ 52 + A0 * R2 / 2 ^ 52 := by
  simp only [multiplyAdd]
  refine ⟨?_, ?_, ?_, ?_, ?_, ?_⟩
  · have := low_lt s.lo0 a.d1 b.s2
    have := low_lt (multiplyAddLow s.lo0 a.d1 b.s2) a.d2 b.s1
    have := low_lt (multiplyAddLow (multiplyAddLow s.lo0 a.d1 b.s2) a.d2 b.s1) a.d0 b.r0
    omega
  · have := low_lt s.lo1 a.d1 b.r0
    have := low_lt (multiplyAddLow s.lo1 a.d1 b.r0) a.d2 b.s2
    have := low_lt (multiplyAddLow (multiplyAddLow s.lo1 a.d1 b.r0) a.d2 b.s2) a.d0 b.r1
    omega
  · have := low_lt s.lo2 a.d1 b.r1
    have := low_lt (multiplyAddLow s.lo2 a.d1 b.r1) a.d2 b.r0
    have := low_lt (multiplyAddLow (multiplyAddLow s.lo2 a.d1 b.r1) a.d2 b.r0) a.d0 b.r2
    omega
  · have := high_le (s := s.hi0) h_a1 h_s2
    have := high_le (s := multiplyAddHigh s.hi0 a.d1 b.s2) h_a2 h_s1
    have := high_le (s := multiplyAddHigh (multiplyAddHigh s.hi0 a.d1 b.s2) a.d2 b.s1) h_a0 h_r0
    omega
  · have := high_le (s := s.hi1) h_a1 h_r0
    have := high_le (s := multiplyAddHigh s.hi1 a.d1 b.r0) h_a2 h_s2
    have := high_le (s := multiplyAddHigh (multiplyAddHigh s.hi1 a.d1 b.r0) a.d2 b.s2) h_a0 h_r1
    omega
  · have := high_le (s := s.hi2) h_a1 h_r1
    have := high_le (s := multiplyAddHigh s.hi2 a.d1 b.r1) h_a2 h_r0
    have := high_le (s := multiplyAddHigh (multiplyAddHigh s.hi2 a.d1 b.r1) a.d2 b.r0) h_a0 h_r2
    omega

/-- Six sums as a group leaves them: each `lo` sum below `6 2 ^ 52` and each `hi` sum below
`2 ^ 42`. -/
def SumsFit (s : Sums) : Prop :=
  s.lo0 < 6 * 2 ^ 52 ∧ s.lo1 < 6 * 2 ^ 52 ∧ s.lo2 < 6 * 2 ^ 52 ∧ s.hi0 < 2 ^ 42 ∧
    s.hi1 < 2 ^ 42 ∧ s.hi2 < 2 ^ 42

/-- From sums that fit, the carry's `t0`, `t1` and `t2` are below `2 ^ 56`, and so is every
shift and every multiple by 5 that adds to them, and the carry's digits fit. -/
theorem carry_fits {s : Sums} (h_fit : SumsFit s) :
    s.t0 < 2 ^ 56 ∧ s.t1 < 2 ^ 56 ∧ s.t2 < 2 ^ 56 ∧ Fits (carry s) := by
  obtain ⟨h_lo0, h_lo1, h_lo2, h_hi0, h_hi1, h_hi2⟩ := h_fit
  simp only [Fits, carry, Sums.t0, Sums.t1, Sums.t2, times5]
  omega

/-- A completed multiplier's digits and multiples, from digits that fit. -/
private theorem complete_le {x : Digits} (h_fits : Fits x) :
    (complete x).r0 ≤ 2 ^ 44 + 2 ^ 17 ∧ (complete x).r1 ≤ 2 ^ 44 + 2 ^ 17 ∧
      (complete x).r2 ≤ 2 ^ 42 + 2 ^ 17 ∧ (complete x).s1 ≤ 20 * (2 ^ 44 + 2 ^ 17) ∧
      (complete x).s2 ≤ 20 * (2 ^ 42 + 2 ^ 17) := by
  obtain ⟨h_d0, h_d1, h_d2⟩ := h_fits
  simp only [complete, times20]
  omega

/-- A group step from digits that fit, two blocks as `blockDigits` reads them and two multipliers
whose digits fit: every multiplication's operands are below `2 ^ 52`, the sums after each
`multiply_add` fit, the carry's numbers are below `2 ^ 56`, and the result fits. -/
theorem groupStep_bounds {h first second x y : Digits} (h_h : Fits h) (h_first : BlockFits first)
    (h_second : BlockFits second) (h_x : Fits x) (h_y : Fits y) :
    Operands second (complete y) ∧ Operands (h.add first) (complete x) ∧
      SumsFit (multiplyAdd Sums.zero second (complete y)) ∧
      SumsFit (groupSums h first second (complete x) (complete y)) ∧
      (groupSums h first second (complete x) (complete y)).t0 < 2 ^ 56 ∧
      (groupSums h first second (complete x) (complete y)).t1 < 2 ^ 56 ∧
      (groupSums h first second (complete x) (complete y)).t2 < 2 ^ 56 ∧
      Fits (groupStep h first second (complete x) (complete y)) := by
  obtain ⟨h_h0, h_h1, h_h2⟩ := h_h
  obtain ⟨h_first0, h_first1, h_first2⟩ := h_first
  obtain ⟨h_second0, h_second1, h_second2⟩ := h_second
  obtain ⟨h_x0, h_x1, h_x2, h_x20_1, h_x20_2⟩ := complete_le h_x
  obtain ⟨h_y0, h_y1, h_y2, h_y20_1, h_y20_2⟩ := complete_le h_y
  have h_block0 : second.d0 ≤ 2 ^ 44 := by omega
  have h_block1 : second.d1 ≤ 2 ^ 44 := by omega
  have h_block2 : second.d2 ≤ 2 ^ 41 := by omega
  have h_add0 : (h.add first).d0 ≤ 2 ^ 45 + 2 ^ 17 := by simp only [Digits.add]; omega
  have h_add1 : (h.add first).d1 ≤ 2 ^ 45 + 2 ^ 17 := by simp only [Digits.add]; omega
  have h_add2 : (h.add first).d2 ≤ 2 ^ 42 + 2 ^ 41 + 2 ^ 17 := by simp only [Digits.add]; omega
  obtain ⟨h_second_lo0, h_second_lo1, h_second_lo2, h_second_hi0, h_second_hi1, h_second_hi2⟩ :=
    multiplyAdd_le (s := Sums.zero) h_block0 h_block1 h_block2 h_y0 h_y1 h_y2 h_y20_1 h_y20_2
  obtain ⟨h_group_lo0, h_group_lo1, h_group_lo2, h_group_hi0, h_group_hi1, h_group_hi2⟩ :=
    multiplyAdd_le (s := multiplyAdd Sums.zero second (complete y)) h_add0 h_add1 h_add2 h_x0
      h_x1 h_x2 h_x20_1 h_x20_2
  have h_zero : Sums.zero.lo0 = 0 ∧ Sums.zero.lo1 = 0 ∧ Sums.zero.lo2 = 0 ∧
      Sums.zero.hi0 = 0 ∧ Sums.zero.hi1 = 0 ∧ Sums.zero.hi2 = 0 :=
    ⟨rfl, rfl, rfl, rfl, rfl, rfl⟩
  norm_num at h_second_lo0 h_second_lo1 h_second_lo2 h_second_hi0 h_second_hi1 h_second_hi2
  norm_num at h_group_lo0 h_group_lo1 h_group_lo2 h_group_hi0 h_group_hi1 h_group_hi2
  have fit_second : SumsFit (multiplyAdd Sums.zero second (complete y)) := by
    simp only [SumsFit]
    omega
  have fit_group : SumsFit (groupSums h first second (complete x) (complete y)) := by
    simp only [SumsFit, groupSums]
    omega
  obtain ⟨h_t0, h_t1, h_t2, h_fits⟩ := carry_fits fit_group
  refine ⟨?_, ?_, fit_second, fit_group, h_t0, h_t1, h_t2, h_fits⟩
  · simp only [Operands]
    omega
  · simp only [Operands]
    omega

/-- A group step computes `(h + first) x + second y` modulo `p`, under `groupStep_bounds`'s
hypotheses. -/
theorem groupStep_mod {h first second x y : Digits} (h_h : Fits h) (h_first : BlockFits first)
    (h_second : BlockFits second) (h_x : Fits x) (h_y : Fits y) :
    ((groupStep h first second (complete x) (complete y)).value : ZMod prime) =
      ((h.value + first.value : Nat) : ZMod prime) * x.value + second.value * y.value := by
  obtain ⟨o_second, o_first, -⟩ := groupStep_bounds h_h h_first h_second h_x h_y
  rw [groupStep, carry_mod, groupSums, multiplyAdd_value o_first, multiplyAdd_value o_second]
  push_cast
  rw [productValue_mod, productValue_mod, add_value]
  simp only [Sums.zero, Sums.value]
  push_cast
  ring

/-- `multiplier_product` from digits that fit: every operand below `2 ^ 52`, the sums fit, the
carry's numbers below `2 ^ 56`, and the product fits. -/
theorem product_bounds {a b : Digits} (h_a : Fits a) (h_b : Fits b) :
    Operands a (complete b) ∧ SumsFit (multiplyAdd Sums.zero a (complete b)) ∧
      (multiplyAdd Sums.zero a (complete b)).t0 < 2 ^ 56 ∧
      (multiplyAdd Sums.zero a (complete b)).t1 < 2 ^ 56 ∧
      (multiplyAdd Sums.zero a (complete b)).t2 < 2 ^ 56 ∧ Fits (product a b) := by
  obtain ⟨h_a0, h_a1, h_a2⟩ := h_a
  obtain ⟨h_b0, h_b1, h_b2, h_b20_1, h_b20_2⟩ := complete_le h_b
  obtain ⟨h_lo0, h_lo1, h_lo2, h_hi0, h_hi1, h_hi2⟩ :=
    multiplyAdd_le (s := Sums.zero) (a := a) h_a0.le h_a1.le h_a2.le h_b0 h_b1 h_b2 h_b20_1 h_b20_2
  have h_zero : Sums.zero.lo0 = 0 ∧ Sums.zero.lo1 = 0 ∧ Sums.zero.lo2 = 0 ∧
      Sums.zero.hi0 = 0 ∧ Sums.zero.hi1 = 0 ∧ Sums.zero.hi2 = 0 :=
    ⟨rfl, rfl, rfl, rfl, rfl, rfl⟩
  norm_num at h_lo0 h_lo1 h_lo2 h_hi0 h_hi1 h_hi2
  have fit : SumsFit (multiplyAdd Sums.zero a (complete b)) := by
    simp only [SumsFit]
    omega
  obtain ⟨h_t0, h_t1, h_t2, h_fits⟩ := carry_fits fit
  refine ⟨?_, fit, h_t0, h_t1, h_t2, h_fits⟩
  simp only [Operands]
  omega

/-- `multiplier_product` computes `a b` modulo `p` from digits that fit. -/
theorem product_mod {a b : Digits} (h_a : Fits a) (h_b : Fits b) :
    ((product a b).value : ZMod prime) = (a.value : ZMod prime) * b.value := by
  obtain ⟨o, -⟩ := product_bounds h_a h_b
  rw [product, carry_mod, multiplyAdd_value o]
  push_cast
  rw [productValue_mod]
  simp only [Sums.zero, Sums.value]
  push_cast
  ring

/-! ## Loads, conversions and powers -/

/-- `load_blocks` keeps a block's number: its 128 bits and the `2 ^ 128` bit. -/
theorem blockDigits_value {low high : Nat} (h_low : low < 2 ^ 64) :
    (blockDigits low high).value = low + 2 ^ 64 * high + 2 ^ 128 := by
  simp only [blockDigits, Digits.value]
  omega

/-- `load_blocks` writes digits that `BlockFits`. -/
theorem blockDigits_fits {low high : Nat} (h_high : high < 2 ^ 64) :
    BlockFits (blockDigits low high) := by
  simp only [BlockFits, blockDigits]
  omega

/-- `digits_of_words` keeps the number five 26-bit words hold. -/
theorem digitsOfWords_value (w0 w1 w2 w3 w4 : Nat) :
    (digitsOfWords w0 w1 w2 w3 w4).value =
      w0 + 2 ^ 26 * w1 + 2 ^ 52 * w2 + 2 ^ 78 * w3 + 2 ^ 104 * w4 := by
  simp only [digitsOfWords, Digits.value]
  omega

/-- `digits_of_words` on words of at most `2 ^ 26`, the bounds `poly1305.c`'s loop leaves in the
accumulator and the clamp leaves in `r`, writes digits that fit. -/
theorem digitsOfWords_fits {w0 w1 w2 w3 w4 : Nat} (h_w0 : w0 ≤ 2 ^ 26) (h_w1 : w1 ≤ 2 ^ 26)
    (h_w2 : w2 ≤ 2 ^ 26) (h_w3 : w3 ≤ 2 ^ 26) (h_w4 : w4 ≤ 2 ^ 26) :
    Fits (digitsOfWords w0 w1 w2 w3 w4) := by
  simp only [Fits, digitsOfWords]
  omega

/-- `words_of_totals`' five sums hold the number the three lane totals hold. -/
theorem totals_value (t0 t1 t2 : Nat) :
    (totalsSums t0 t1 t2).getD 0 0 + 2 ^ 26 * (totalsSums t0 t1 t2).getD 1 0 +
        2 ^ 52 * (totalsSums t0 t1 t2).getD 2 0 + 2 ^ 78 * (totalsSums t0 t1 t2).getD 3 0 +
        2 ^ 104 * (totalsSums t0 t1 t2).getD 4 0 =
      t0 + 2 ^ 44 * t1 + 2 ^ 88 * t2 := by
  simp only [totalsSums, List.getD_cons_zero, List.getD_cons_succ]
  omega

/-- From totals below `2 ^ 48`, which eight lanes of digits that fit give, each of
`words_of_totals`' five sums is below `2 ^ 60`, the bound `carry_scalar` takes. -/
theorem totals_lt {t0 t1 t2 : Nat} (h_t0 : t0 < 2 ^ 48) (h_t1 : t1 < 2 ^ 48)
    (h_t2 : t2 < 2 ^ 48) :
    ∀ d ∈ totalsSums t0 t1 t2, d < 2 ^ 60 := by
  simp only [totalsSums, List.mem_cons, List.not_mem_nil, or_false]
  omega

/-- Digits that fit and hold `r ^ e` modulo `p`. -/
def Holds (r x : Digits) (e : Nat) : Prop :=
  Fits x ∧ (x.value : ZMod prime) = (r.value : ZMod prime) ^ e

private theorem holds_product {r a b : Digits} {e f g : Nat} (h_a : Holds r a e)
    (h_b : Holds r b f) (h_g : e + f = g) : Holds r (product a b) g := by
  refine ⟨(product_bounds h_a.1 h_b.1).2.2.2.2.2, ?_⟩
  rw [product_mod h_a.1 h_b.1, h_a.2, h_b.2, ← h_g, pow_add]

private theorem holds_one (r : Digits) : Holds r one 0 := by
  refine ⟨?_, ?_⟩
  · simp only [Fits, one]
    norm_num
  · simp [one, Digits.value]

private theorem holds_base {r : Digits} (h_fits : Fits r) : Holds r r 1 :=
  ⟨h_fits, (pow_one _).symm⟩

/-- Proves `Holds r x e` for `x` a tree of products of `r` and `one`: `holds_product` at each
product, `holds_base` and `holds_one` at the leaves, which give the exponents, and then each sum of
exponents, inner sums first. -/
macro "holds_tree" : tactic =>
  `(tactic| (repeat' (first
      | exact holds_base ‹_›
      | exact holds_one _
      | apply holds_product)) <;> rfl)

/-- Lane `l` of the four multipliers `compute_powers` writes from `r`'s digits that fit: they fit
and hold `r ^ (16 - b)`, `r ^ (8 - b)`, `r ^ 16` and `r ^ 8` modulo `p`, `b` being `blockOf l`. -/
theorem powers_mod {r : Digits} (h_fits : Fits r) (l : Fin 8) :
    Holds r ((computePowers r).lastFirst l) (16 - blockOf l) ∧
      Holds r ((computePowers r).lastSecond l) (8 - blockOf l) ∧
      Holds r ((computePowers r).by16 l) 16 ∧ Holds r ((computePowers r).by8 l) 8 := by
  fin_cases l <;>
    simp only [computePowers, productLanes, select, selectOne, broadcastFirst, blockOf] <;>
    norm_num <;>
    refine ⟨?_, ?_, ?_, ?_⟩ <;> holds_tree

/-! ## The selftest -/

/-- `r ^ e` modulo `p` on numbers, the selftest's reference. -/
private def powMod (r e : Nat) : Nat :=
  (List.range e).foldl (fun x _ => x * r % (2 ^ 130 - 5)) 1

set_option compiler.extract_closed false in
/-- A group step on the largest digits `Fits` admits and the largest blocks against
`(h + first) x + second y` modulo `p`, `load_blocks` on a block of all ones bits, and the four
multipliers `compute_powers` writes from an `r` against the powers of `r`. -/
def selftest (_ : Unit) : Bool :=
  let top : Digits := ⟨2 ^ 44 + 2 ^ 17 - 1, 2 ^ 44 + 2 ^ 17 - 1, 2 ^ 42 + 2 ^ 17 - 1⟩
  let block := blockDigits (2 ^ 64 - 1) (2 ^ 64 - 1)
  let step := groupStep top block block (complete top) (complete top)
  let stepOk := step.value % prime ==
    ((top.value + block.value) * top.value + block.value * top.value) % prime
  let blockOk := block.value == 2 ^ 129 - 1
  let r := digitsOfWords 0x2c88c77 0x0849d64 0x1aa82e8 0x1aab840 0x000a4dc
  let powers := computePowers r
  let powersOk := (List.finRange 8).all fun l =>
    (powers.lastFirst l).value % prime == powMod r.value (16 - blockOf l) &&
      (powers.lastSecond l).value % prime == powMod r.value (8 - blockOf l) &&
      (powers.by16 l).value % prime == powMod r.value 16 &&
      (powers.by8 l).value % prime == powMod r.value 8
  stepOk && blockOk && powersOk

end Spec.Poly1305Ifma
