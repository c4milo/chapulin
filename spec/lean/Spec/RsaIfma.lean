import Mathlib.Data.ZMod.Basic
import Mathlib.Tactic

/-!
RSA's public operation on AVX-512 IFMA, `rsa_ifma.c`, and the power of two `rsa_mont.c`'s
`power_of_two_mod` writes for it, modeled from the C.

`rsa_ifma.c` holds a number in digits of 52 bits, one to a 64-bit lane, eight lanes to a 512-bit
register. `product` is `almost_montgomery_product`: `rounds` of `round`, one for each digit of `b`,
and `normalize`, which is `normalize_digits`. A round is `add_round`: it adds bits 51..0 of each
digit product to the lane of its digit (`lowPass`), moves every lane down one lane, which divides
by `2 ^ 52` (`moveDown`), and adds bits 103..52 of each product (`highPass`), while `digitZero`
holds digit 0 with every carry into it. `normalize` carries each lane's bits from 52 up into the
lane above (`carryPass`), and then the carries of one bit that pass leaves (`registerStep`, eight
lanes at a time, as the C's mask registers do).

The model computes over `Nat`, where the C's lanes are 64-bit words. Each lane operation is the
one `test/rsa_ifma_model_lanes.h` writes from Intel's pseudocode for its instruction, with the
registers laid end to end, lane `8 i + t` for lane `t` of register `i`. `rounds_fit` and
`round_fits` prove that no lane and no scalar sum the C computes passes its type, so the C's
words hold the model's numbers.

`product_lt` and `product_mul` prove that the product is below `2 m` and congruent to
`a b 2 ^ (-52 n)` modulo `m` for `a` and `b` below `2 m` and `4 m ≤ 2 ^ (52 n)`, which
`digitCount_room` gives. `normalize_value` and `normalize_lt` prove what `normalize_digits` does
to any lanes below `2 ^ 64`, and `publicOp_eq` that `rsa_ifma_public`'s chain of products
computes `base ^ 65537 mod m`. `powerOfTwoMod_eq` proves that `power_of_two_mod` writes
`2 ^ e mod m`.

This module is written from the C, not from a standard, and CONTRACT.md says why.
-/

namespace Spec.RsaIfma

/-! ## Digits and lanes -/

/-- `RSA_IFMA_DIGIT_COUNT` in `rsa_ifma.h`: the digits of 52 bits that hold `words` 64-bit words
with two bits to spare, `⌈(64 words + 2) / 52⌉`. -/
def digitCount (words : Nat) : Nat :=
  (64 * words + 2 + 51) / 52

/-- `(digit_count + 7) / 8` registers of eight lanes: the lanes a product of `n` digits takes. -/
def laneCount (n : Nat) : Nat :=
  8 * ((n + 7) / 8)

/-- Digit `j` of `x`: its bits `52 j` to `52 j + 51`, which `words_to_digits` writes to lane
`j`. -/
def digit (x j : Nat) : Nat :=
  x / 2 ^ (52 * j) % 2 ^ 52

/-- The number lanes `0` to `count - 1` hold, lane `j` weighing `2 ^ (52 j)`. A lane may hold
more than 52 bits: the lanes of a running sum carry nothing into each other until
`normalize`. -/
def value (count : Nat) (lanes : Nat → Nat) : Nat :=
  ∑ j ∈ Finset.range count, lanes j * 2 ^ (52 * j)

/-- The lanes of an array of them, the C's array of `uint64_t`: 0 past its end. -/
def lanesOf (lanes : Array Nat) (j : Nat) : Nat :=
  lanes.getD j 0

/-- `words_to_digits` on a number: its digits in `count` lanes, the array a product reads. -/
def toDigits (count x : Nat) : Array Nat :=
  Array.ofFn (n := count) fun j => digit x j

/-! ## A round -/

/-- `lanes_multiply_add_low` (VPMADD52LUQ) on one lane: `sum` plus bits 51..0 of the product of
bits 51..0 of `x` and bits 51..0 of `y`. -/
def multiplyAddLow (sum x y : Nat) : Nat :=
  sum + x % 2 ^ 52 * (y % 2 ^ 52) % 2 ^ 52

/-- `lanes_multiply_add_high` (VPMADD52HUQ) on one lane: `sum` plus bits 103..52 of the same
product. -/
def multiplyAddHigh (sum x y : Nat) : Nat :=
  sum + x % 2 ^ 52 * (y % 2 ^ 52) / 2 ^ 52

/-- A product's running sum between rounds: `lanes`, the C's registers `sum` laid end to end, and
`digitZero`, the C's `digit_zero`, which holds digit 0 with every carry into it. No round reads
lane 0: `digitZero` stands in its place. -/
structure State where
  /-- `sum`, lane `8 i + t` for lane `t` of register `i`. -/
  lanes : Nat → Nat
  /-- `digit_zero`. -/
  digitZero : Nat

/-- `add_round`'s first sum, `ct_mul128(a[0], b_digit) + *digit_zero`. -/
def lowSum (a : Nat → Nat) (bDigit : Nat) (s : State) : Nat :=
  a 0 * bDigit + s.digitZero

/-- `add_round`'s quotient: the low 64 bits of `low` times `m0inv`, cut to 64 bits and masked to
52. -/
def quotient (m0inv low : Nat) : Nat :=
  low % 2 ^ 64 * m0inv % 2 ^ 64 % 2 ^ 52

/-- `add_round`'s first two loops: each lane plus bits 51..0 of `a j * bDigit`, and then of
`m j * q`. -/
def lowPass (a m : Nat → Nat) (bDigit q : Nat) (lanes : Nat → Nat) (j : Nat) : Nat :=
  multiplyAddLow (multiplyAddLow (lanes j) (a j) bDigit) (m j) q

/-- `add_round`'s division by `2 ^ 52`, `lanes_down_one` over the registers: lane `j` takes lane
`j + 1`, and the top of `count` lanes takes 0. -/
def moveDown (count : Nat) (lanes : Nat → Nat) (j : Nat) : Nat :=
  if j + 1 < count then lanes (j + 1) else 0

/-- `add_round`'s last two loops: each lane plus bits 103..52 of `a j * bDigit`, and then of
`m j * q`. -/
def highPass (a m : Nat → Nat) (bDigit q : Nat) (lanes : Nat → Nat) (j : Nat) : Nat :=
  multiplyAddHigh (multiplyAddHigh (lanes j) (a j) bDigit) (m j) q

/-- `add_round` on `count` lanes: the quotient from digit 0's sum and `m0inv`, both products by
digit 0 added to `digit_zero`, which then drops its low 52 bits, the low pass, the move down,
the lane that moves into lane 0 added to `digit_zero`, and the high pass. -/
def round (count : Nat) (a m : Nat → Nat) (m0inv bDigit : Nat) (s : State) : State :=
  let low := lowSum a bDigit s
  let q := quotient m0inv low
  let low := low + m 0 * q
  let moved := moveDown count (lowPass a m bDigit q s.lanes)
  { lanes := highPass a m bDigit q moved
    digitZero := low / 2 ^ 52 + moved 0 }

/-- The rounds of `almost_montgomery_product_core` from a zero sum: round `i` takes digit `i` of
`b`. -/
def rounds (count : Nat) (a b m : Nat → Nat) (m0inv : Nat) : Nat → State
  | 0 => ⟨fun _ => 0, 0⟩
  | i + 1 => round count a m m0inv (b i) (rounds count a b m m0inv i)

/-! ## `normalize_digits` -/

/-- `normalize_digits`'s first loop: each lane keeps its bits 51..0 (`lanes_and` with the mask)
and takes the bits from 52 up of the lane below it (`lanes_shift_right_52`, and `lanes_up_one`
with the register below). The carry of the top lane leaves. -/
def carryPass (lanes : Nat → Nat) (j : Nat) : Nat :=
  lanes j % 2 ^ 52 + if j = 0 then 0 else lanes (j - 1) / 2 ^ 52

/-- A mask register from its bits: bit `t` of `bitsOf bit width` is `bit t`, for `t` below
`width`. -/
def bitsOf (bit : Nat → Bool) : Nat → Nat
  | 0 => 0
  | width + 1 => (bit 0).toNat + 2 * bitsOf (fun t => bit (t + 1)) width

/-- `lanes_above(sum[i], mask)`: bit `t` is set where lane `8 i + t` is above `2 ^ 52 - 1`. Such a
lane sends a carry. -/
def generate (lanes : Nat → Nat) (i : Nat) : Nat :=
  bitsOf (fun t => decide (2 ^ 52 - 1 < lanes (8 * i + t))) 8

/-- `lanes_equal(sum[i], mask)`: bit `t` is set where lane `8 i + t` is `2 ^ 52 - 1`. Such a lane
sends a carry on when one arrives. -/
def propagate (lanes : Nat → Nat) (i : Nat) : Nat :=
  bitsOf (fun t => decide (lanes (8 * i + t) = 2 ^ 52 - 1)) 8

/-- `generate_from_below` and `carry_from_below`, the carries between registers. -/
structure Carries where
  /-- `generate_from_below`: bit 7 of the register below's `generate`. -/
  generateFromBelow : Nat
  /-- `carry_from_below`: the carry out of the register below's 8-bit sum. -/
  carryFromBelow : Nat

/-- One pass of `normalize_digits`'s second loop, on a register whose masks are `generate` and
`propagate`: the register's `receives`, `((generate << 1) + propagate) ^ propagate` over its eight
bits with the carries from below, and the carries for the register above. -/
def registerStep (generate propagate : Nat) (below : Carries) : Nat × Carries :=
  let shifted := ((generate <<< 1) ||| below.generateFromBelow) &&& 0xff
  let total := shifted + propagate + below.carryFromBelow
  ((total ^^^ propagate) &&& 0xff, ⟨generate >>> 7, total >>> 8⟩)

/-- The carries into register `i` of the second loop, from none into register 0. -/
def carriesInto (lanes : Nat → Nat) : Nat → Carries
  | 0 => ⟨0, 0⟩
  | i + 1 => (registerStep (generate lanes i) (propagate lanes i) (carriesInto lanes i)).2

/-- `receives` for register `i`: bit `t` is set where lane `8 i + t` takes a carry. -/
def receives (lanes : Nat → Nat) (i : Nat) : Nat :=
  (registerStep (generate lanes i) (propagate lanes i) (carriesInto lanes i)).1

/-- `normalize_digits`: the first loop, and then 1 added to each lane that receives a carry
(`lanes_add_where`) and the lane masked to 52 bits. Lane `j` reads lanes up to the top of its
register only, so the model computes the C's lanes for any count of registers. -/
def normalize (lanes : Nat → Nat) (j : Nat) : Nat :=
  let first := carryPass lanes
  (if (receives first (j / 8)).testBit (j % 8) then first j + 1 else first j) % 2 ^ 52

/-! ## The product -/

/-- The sum with `digit_zero` in lane 0, `lanes_replace_first(sum[0], digit_zero)`: the number a
state holds. -/
def replaceFirst (s : State) (j : Nat) : Nat :=
  if j = 0 then s.digitZero else s.lanes j

/-- `almost_montgomery_product_core`'s `n` rounds on the digits of `a`, `b` and `m`, in
`laneCount n` lanes. -/
def productRounds (n m0inv a b m : Nat) : State :=
  let count := laneCount n
  rounds count (lanesOf (toDigits count a)) (lanesOf (toDigits count b))
    (lanesOf (toDigits count m)) m0inv n

/-- `almost_montgomery_product`: its rounds, `digit_zero` into lane 0, and `normalize_digits` on
the `laneCount n` lanes, of which the C holds no others. It writes the lanes of `out`. -/
def product (n m0inv a b m : Nat) : Array Nat :=
  let s := productRounds n m0inv a b m
  let sum := Array.ofFn (n := laneCount n) fun j => replaceFirst s j
  Array.ofFn (n := laneCount n) fun j => normalize (lanesOf sum) j

/-- `rsa_mont64_reduce_once_with_top`'s answer: `x - m` for `x` at least `m`, else `x`. -/
def reduceOnce (m x : Nat) : Nat :=
  if m ≤ x then x - m else x

/-- `rsa_ifma_public` on numbers, for a modulus of `k` words: the product of `base` and
`digitR2`, sixteen squares, the product of `base` and that power, and one subtraction of `m`. -/
def publicOp (k m0inv m base digitR2 : Nat) : Nat :=
  let n := digitCount k
  let multiply := fun a b => value (laneCount n) (lanesOf (product n m0inv a b m))
  let power := multiply base digitR2
  let power := (fun p => multiply p p)^[16] power
  reduceOnce m (multiply base power)

/-- The `m0inv` of `rsa_ifma_modulus`: `-m⁻¹ mod 2 ^ 52`, for an odd `m`. -/
def m0invOf (m : Nat) : Nat :=
  (2 ^ 52 - ((m : ZMod (2 ^ 52))⁻¹).val) % 2 ^ 52

/-! ## `power_of_two_mod` -/

/-- `times_word_mod`'s answer: `rem * 2 ^ 64 mod m`. -/
def timesWordMod (m rem : Nat) : Nat :=
  rem * 2 ^ 64 % m

/-- `power_of_two_mod`'s start: bit `exponent & 63` of word `k - 1`. -/
def powerOfTwoStart (k exponent : Nat) : Nat :=
  2 ^ (64 * (k - 1) + exponent % 64)

/-- `power_of_two_mod`'s steps of `times_word_mod`: `(exponent >> 6) - (k - 1)`. -/
def powerOfTwoSteps (k exponent : Nat) : Nat :=
  exponent / 64 - (k - 1)

/-- `power_of_two_mod`: its start, multiplied by `2 ^ 64` modulo `m` in each of its steps. -/
def powerOfTwoMod (m k exponent : Nat) : Nat :=
  (timesWordMod m)^[powerOfTwoSteps k exponent] (powerOfTwoStart k exponent)

/-! ## The digit count -/

/-- `RSA_IFMA_DIGIT_COUNT`'s two spare bits: for every `m` below `2 ^ (64 k)`,
`4 m < 2 ^ (52 n)`, which `product_lt` and `product_mul` take. -/
theorem digitCount_room {k m : Nat} (h_m : m < 2 ^ (64 * k)) :
    4 * m < 2 ^ (52 * digitCount k) := by
  have h_bits : 64 * k + 2 ≤ 52 * digitCount k := by
    unfold digitCount
    omega
  calc 4 * m < 2 ^ 2 * 2 ^ (64 * k) := by omega
    _ = 2 ^ (64 * k + 2) := by rw [← pow_add, add_comm]
    _ ≤ 2 ^ (52 * digitCount k) := Nat.pow_le_pow_right (by norm_num) h_bits

/-! ## Lanes -/

/-- The number in `count + 1` lanes, the top lane apart. -/
private theorem value_succ (count : Nat) (lanes : Nat → Nat) :
    value (count + 1) lanes = value count lanes + lanes count * 2 ^ (52 * count) :=
  Finset.sum_range_succ _ _

/-- The digits of `x` in `count` lanes hold `x mod 2 ^ (52 count)`. -/
private theorem value_digit (x : Nat) : ∀ count, value count (digit x) = x % 2 ^ (52 * count)
  | 0 => by simp [value, Nat.mod_one]
  | count + 1 => by
    rw [value_succ, value_digit x count, show 52 * (count + 1) = 52 * count + 52 by ring,
      pow_add, Nat.mod_mul, digit]
    ring

/-- Digits below `2 ^ 52` in `count` lanes hold a number below `2 ^ (52 count)`. -/
private theorem value_lt {lanes : Nat → Nat} :
    ∀ {count}, (∀ j < count, lanes j < 2 ^ 52) → value count lanes < 2 ^ (52 * count)
  | 0, _ => by simp [value]
  | count + 1, h_lanes => by
    have h_below := value_lt (count := count) fun j h_j => h_lanes j (by omega)
    have h_top := h_lanes count (by omega)
    rw [value_succ, show 52 * (count + 1) = 52 * count + 52 by ring, pow_add]
    calc value count lanes + lanes count * 2 ^ (52 * count)
        < 2 ^ (52 * count) + lanes count * 2 ^ (52 * count) := by omega
      _ = (lanes count + 1) * 2 ^ (52 * count) := by ring
      _ ≤ 2 ^ 52 * 2 ^ (52 * count) := Nat.mul_le_mul_right _ h_top
      _ = 2 ^ (52 * count) * 2 ^ 52 := by ring

/-- Lanes that agree below `count` hold the same number there. -/
private theorem value_congr {f g : Nat → Nat} {count : Nat} (h_same : ∀ j < count, f j = g j) :
    value count f = value count g :=
  Finset.sum_congr rfl fun j h_j => by rw [h_same j (Finset.mem_range.mp h_j)]

/-- An array's lanes below its size are its entries. -/
private theorem lanesOf_ofFn {count j : Nat} (f : Fin count → Nat) (h_j : j < count) :
    lanesOf (Array.ofFn f) j = f ⟨j, h_j⟩ := by
  rw [lanesOf, Array.getD_eq_getD_getElem?, Array.getElem?_ofFn, dif_pos h_j]
  rfl

/-- A digit is below `2 ^ 52`. -/
private theorem digit_lt (x j : Nat) : digit x j < 2 ^ 52 :=
  Nat.mod_lt _ (by norm_num)

/-- Every lane of a number's digits is below `2 ^ 52`, those past the array included. -/
private theorem toDigits_lt (count x j : Nat) : lanesOf (toDigits count x) j < 2 ^ 52 := by
  rw [lanesOf, toDigits, Array.getD_eq_getD_getElem?, Array.getElem?_ofFn]
  split_ifs
  · exact digit_lt x j
  · norm_num

/-- Lane `j` of a number's digits in `count` lanes, `j` below `count`, is its digit `j`. -/
private theorem toDigits_eq {count j : Nat} (x : Nat) (h_j : j < count) :
    lanesOf (toDigits count x) j = digit x j :=
  lanesOf_ofFn _ h_j

/-- The first `i` lanes of a number's digits in `count` lanes, `i` at most `count`, hold
`x mod 2 ^ (52 i)`. -/
private theorem value_toDigits {count i x : Nat} (h_i : i ≤ count) :
    value i (lanesOf (toDigits count x)) = x % 2 ^ (52 * i) := by
  rw [← value_digit x i]
  exact value_congr fun j h_j => toDigits_eq x (by omega)

/-- The number in `count + 1` lanes, lane 0 apart. -/
private theorem value_succ' (count : Nat) (lanes : Nat → Nat) :
    value (count + 1) lanes =
      lanes 0 + ∑ j ∈ Finset.range count, lanes (j + 1) * 2 ^ (52 * (j + 1)) := by
  rw [value, Finset.sum_range_succ']
  simp [add_comm]

/-! ## What a round computes -/

/-- A product of two digits below `2 ^ 52` is its bits 51..0 and its bits from 52 up. -/
private theorem low_add_high {x y : Nat} (h_x : x < 2 ^ 52) (h_y : y < 2 ^ 52) :
    x % 2 ^ 52 * (y % 2 ^ 52) % 2 ^ 52 + 2 ^ 52 * (x % 2 ^ 52 * (y % 2 ^ 52) / 2 ^ 52) =
      x * y := by
  rw [Nat.mod_eq_of_lt h_x, Nat.mod_eq_of_lt h_y, Nat.mod_add_div]

/-- The quotient makes digit 0 of the sum zero: `m0inv` is `-m⁻¹ mod 2 ^ 52`. -/
private theorem low_exact {m0 m0inv low : Nat} (h_m0inv : (m0inv * m0 + 1) % 2 ^ 52 = 0) :
    (low + m0 * quotient m0inv low) % 2 ^ 52 = 0 := by
  have h_dvd : (2 ^ 52 : Nat) ∣ 2 ^ 64 := pow_dvd_pow 2 (by norm_num)
  have h_q : quotient m0inv low % 2 ^ 52 = low * m0inv % 2 ^ 52 := by
    rw [quotient, Nat.mod_mod, Nat.mod_mod_of_dvd _ h_dvd, Nat.mul_mod,
      Nat.mod_mod_of_dvd _ h_dvd, ← Nat.mul_mod]
  have h_same : (low + m0 * quotient m0inv low) % 2 ^ 52 =
      (low + m0 * (low * m0inv)) % 2 ^ 52 := by
    rw [Nat.add_mod, Nat.mul_mod m0, h_q, ← Nat.mul_mod, ← Nat.add_mod]
  rw [h_same, show low + m0 * (low * m0inv) = low * (m0inv * m0 + 1) by ring, Nat.mul_mod,
    h_m0inv, mul_zero, Nat.zero_mod]

/-- A round divides by `2 ^ 52` and drops no set bit: `2 ^ 52` times the number after it is the
number before it plus `a` times `b`'s digit and the quotient times `m`. -/
private theorem round_value {count : Nat} {a m : Nat → Nat} {m0inv bDigit : Nat} (s : State)
    (h_count : 1 ≤ count) (h_a : ∀ j < count, a j < 2 ^ 52) (h_m : ∀ j < count, m j < 2 ^ 52)
    (h_b : bDigit < 2 ^ 52) (h_m0inv : (m0inv * m 0 + 1) % 2 ^ 52 = 0) :
    2 ^ 52 * value count (replaceFirst (round count a m m0inv bDigit s)) =
      value count (replaceFirst s) + value count a * bDigit +
        quotient m0inv (lowSum a bDigit s) * value count m := by
  obtain ⟨c, rfl⟩ : ∃ c, count = c + 1 := ⟨count - 1, by omega⟩
  set q := quotient m0inv (lowSum a bDigit s)
  set low := lowPass a m bDigit q s.lanes with h_low
  set moved := moveDown (c + 1) low with h_moved
  have h_q_lt : q < 2 ^ 52 := Nat.mod_lt _ (by norm_num)
  have h_zero : 2 ^ 52 * ((lowSum a bDigit s + m 0 * q) / 2 ^ 52) =
      a 0 * bDigit + s.digitZero + m 0 * q :=
    Nat.mul_div_cancel' (Nat.dvd_of_mod_eq_zero (low_exact h_m0inv))
  have h_lanes : 2 ^ 52 * ∑ j ∈ Finset.range c,
        highPass a m bDigit q moved (j + 1) * 2 ^ (52 * (j + 1)) +
      ∑ j ∈ Finset.range c, low (j + 1) * 2 ^ (52 * (j + 1)) =
      ∑ j ∈ Finset.range c, moved (j + 1) * 2 ^ (52 * (j + 1 + 1)) +
        ∑ j ∈ Finset.range c, s.lanes (j + 1) * 2 ^ (52 * (j + 1)) +
        bDigit * ∑ j ∈ Finset.range c, a (j + 1) * 2 ^ (52 * (j + 1)) +
        q * ∑ j ∈ Finset.range c, m (j + 1) * 2 ^ (52 * (j + 1)) := by
    rw [Finset.mul_sum, Finset.mul_sum, Finset.mul_sum, ← Finset.sum_add_distrib,
      ← Finset.sum_add_distrib, ← Finset.sum_add_distrib, ← Finset.sum_add_distrib]
    refine Finset.sum_congr rfl fun j h_j => ?_
    have h_j : j + 1 < c + 1 := by simp at h_j; omega
    have h_a_split := low_add_high (h_a (j + 1) h_j) h_b
    have h_m_split := low_add_high (h_m (j + 1) h_j) h_q_lt
    simp only [highPass, multiplyAddHigh, h_low, lowPass, multiplyAddLow]
    rw [show 52 * (j + 1 + 1) = 52 + 52 * (j + 1) by ring, pow_add]
    linear_combination 2 ^ (52 * (j + 1)) * h_a_split + 2 ^ (52 * (j + 1)) * h_m_split
  have h_shift : ∑ j ∈ Finset.range c, moved (j + 1) * 2 ^ (52 * (j + 1 + 1)) +
      moved 0 * 2 ^ 52 = ∑ j ∈ Finset.range c, low (j + 1) * 2 ^ (52 * (j + 1)) := by
    have h_top : moved c = 0 := by simp [h_moved, moveDown]
    have h_sum := Finset.sum_range_succ' (fun j => moved j * 2 ^ (52 * (j + 1))) c
    simp only [zero_add, mul_one] at h_sum
    rw [← h_sum, Finset.sum_range_succ, h_top, zero_mul, add_zero]
    refine Finset.sum_congr rfl fun j h_j => ?_
    have h_j : j + 1 < c + 1 := by simp at h_j; omega
    simp [h_moved, moveDown, h_j]
  rw [value_succ', value_succ', value_succ', value_succ']
  simp only [replaceFirst, Nat.add_one_ne_zero, ↓reduceIte]
  show 2 ^ 52 * ((lowSum a bDigit s + m 0 * q) / 2 ^ 52 + moved 0 +
    ∑ j ∈ Finset.range c, highPass a m bDigit q moved (j + 1) * 2 ^ (52 * (j + 1))) = _
  linear_combination h_zero + h_lanes + h_shift

/-! ## No lane wraps -/

/-- What VPMADD52LUQ adds to a lane is below `2 ^ 52`. -/
private theorem low_lt (x y : Nat) : x % 2 ^ 52 * (y % 2 ^ 52) % 2 ^ 52 < 2 ^ 52 :=
  Nat.mod_lt _ (by norm_num)

/-- So is what VPMADD52HUQ adds. -/
private theorem high_lt (x y : Nat) : x % 2 ^ 52 * (y % 2 ^ 52) / 2 ^ 52 < 2 ^ 52 :=
  Nat.div_lt_of_lt_mul
    (Nat.mul_lt_mul'' (Nat.mod_lt _ (by norm_num)) (Nat.mod_lt _ (by norm_num)))

/-- A round from a state whose lanes are at most `2 ^ 54 i` and whose `digit_zero` is at most
`2 ^ 54 i + 2 ^ 11`: what it computes on the way, and the bounds one round later. -/
private theorem round_bound {count i : Nat} {a m : Nat → Nat} {m0inv bDigit : Nat} {s : State}
    (h_a0 : a 0 < 2 ^ 52) (h_m0 : m 0 < 2 ^ 52) (h_b : bDigit < 2 ^ 52) (h_i : i < 128)
    (h_lanes : ∀ j, s.lanes j ≤ 2 ^ 54 * i) (h_zero : s.digitZero ≤ 2 ^ 54 * i + 2 ^ 11) :
    (∀ j, lowPass a m bDigit (quotient m0inv (lowSum a bDigit s)) s.lanes j <
        2 ^ 54 * i + 2 ^ 53) ∧
      lowSum a bDigit s + m 0 * quotient m0inv (lowSum a bDigit s) < 2 ^ 105 + 2 ^ 62 ∧
      (∀ j, (round count a m m0inv bDigit s).lanes j ≤ 2 ^ 54 * (i + 1)) ∧
      (round count a m m0inv bDigit s).digitZero ≤ 2 ^ 54 * (i + 1) + 2 ^ 11 := by
  set q := quotient m0inv (lowSum a bDigit s)
  have h_q : q < 2 ^ 52 := Nat.mod_lt _ (by norm_num)
  have h_low : ∀ j, lowPass a m bDigit q s.lanes j < 2 ^ 54 * i + 2 ^ 53 := by
    intro j
    have h_lane := h_lanes j
    have h_low_a := low_lt (a j) bDigit
    have h_low_m := low_lt (m j) q
    simp only [lowPass, multiplyAddLow]
    omega
  have h_sum : lowSum a bDigit s + m 0 * q < 2 ^ 105 + 2 ^ 62 := by
    have h_a_b : a 0 * bDigit < 2 ^ 52 * 2 ^ 52 := Nat.mul_lt_mul'' h_a0 h_b
    have h_m_q : m 0 * q < 2 ^ 52 * 2 ^ 52 := Nat.mul_lt_mul'' h_m0 h_q
    simp only [lowSum]
    omega
  have h_moved :
      ∀ j, moveDown count (lowPass a m bDigit q s.lanes) j < 2 ^ 54 * i + 2 ^ 53 := by
    intro j
    unfold moveDown
    split_ifs
    · exact h_low (j + 1)
    · omega
  refine ⟨h_low, h_sum, fun j => ?_, ?_⟩
  · have h_moved_lane := h_moved j
    have h_high_a := high_lt (a j) bDigit
    have h_high_m := high_lt (m j) q
    show multiplyAddHigh (multiplyAddHigh (moveDown count (lowPass a m bDigit q s.lanes) j) (a j)
      bDigit) (m j) q ≤ _
    simp only [multiplyAddHigh]
    omega
  · have h_moved_zero := h_moved 0
    have h_div : (lowSum a bDigit s + m 0 * q) / 2 ^ 52 ≤ 2 ^ 53 + 2 ^ 10 :=
      Nat.le_of_lt_succ (Nat.div_lt_of_lt_mul (by omega))
    show (lowSum a bDigit s + m 0 * q) / 2 ^ 52 +
      moveDown count (lowPass a m bDigit q s.lanes) 0 ≤ _
    omega

/-- After `i` rounds, `i` at most 128, every lane is at most `2 ^ 54 i` and `digit_zero` at most
`2 ^ 54 i + 2 ^ 11`. -/
private theorem rounds_bound {count m0inv : Nat} {a b m : Nat → Nat} (h_a0 : a 0 < 2 ^ 52)
    (h_m0 : m 0 < 2 ^ 52) (h_b : ∀ i, b i < 2 ^ 52) :
    ∀ i ≤ 128, (∀ j, (rounds count a b m m0inv i).lanes j ≤ 2 ^ 54 * i) ∧
      (rounds count a b m m0inv i).digitZero ≤ 2 ^ 54 * i + 2 ^ 11
  | 0, _ => ⟨fun _ => by simp [rounds], by simp [rounds]⟩
  | i + 1, h_i => by
    obtain ⟨h_lanes, h_zero⟩ := rounds_bound h_a0 h_m0 h_b i (by omega)
    obtain ⟨-, -, h_next⟩ := round_bound (count := count) (m0inv := m0inv) h_a0 h_m0 (h_b i)
      (by omega) h_lanes h_zero
    exact h_next

/-- No lane and no `digit_zero` the C's rounds write passes its 64 bits: for digits below
`2 ^ 52`, after `i` rounds, `i` at most 128, every lane is at most `2 ^ 61` and `digit_zero` is
below `2 ^ 62`. A product runs `digit_count` rounds, at most 79. -/
theorem rounds_fit {count m0inv i : Nat} {a b m : Nat → Nat} (h_a : a 0 < 2 ^ 52)
    (h_m : m 0 < 2 ^ 52) (h_b : ∀ i, b i < 2 ^ 52) (h_i : i ≤ 128) :
    (∀ j, (rounds count a b m m0inv i).lanes j ≤ 2 ^ 61) ∧
      (rounds count a b m m0inv i).digitZero < 2 ^ 62 := by
  obtain ⟨h_lanes, h_zero⟩ := rounds_bound (count := count) (m0inv := m0inv) h_a h_m h_b i h_i
  exact ⟨fun j => (h_lanes j).trans (by omega), by omega⟩

/-- Nor does any value a round computes on the way: in round `i`, below 128, the scalar sum
`low` with `ct_mul128(m[0], quotient)` added stays below `2 ^ 106`, so `low >> 52` fits 64
bits, and every lane after the low pass stays below `2 ^ 62`. -/
theorem round_fits {count m0inv i : Nat} {a b m : Nat → Nat} (h_a : a 0 < 2 ^ 52)
    (h_m : m 0 < 2 ^ 52) (h_b : ∀ i, b i < 2 ^ 52) (h_i : i < 128) :
    let s := rounds count a b m m0inv i
    let q := quotient m0inv (lowSum a (b i) s)
    lowSum a (b i) s + m 0 * q < 2 ^ 106 ∧ ∀ j, lowPass a m (b i) q s.lanes j < 2 ^ 62 := by
  obtain ⟨h_lanes, h_zero⟩ :=
    rounds_bound (count := count) (m0inv := m0inv) h_a h_m h_b i (by omega)
  obtain ⟨h_low, h_sum, -⟩ := round_bound (count := count) (m0inv := m0inv) h_a h_m (h_b i) h_i
    h_lanes h_zero
  exact ⟨by omega, fun j => (h_low j).trans_le (by omega)⟩

/-! ## `normalize_digits` -/

/-- Whether lane `j` takes a carry in `normalize_digits`'s second loop: lane 0 takes none, and
lane `j + 1` takes one where lane `j` is above `2 ^ 52 - 1`, or is `2 ^ 52 - 1` and takes one. -/
private def takesCarry (lanes : Nat → Nat) : Nat → Bool
  | 0 => false
  | j + 1 =>
    decide (2 ^ 52 - 1 < lanes j) || (decide (lanes j = 2 ^ 52 - 1) && takesCarry lanes j)

/-- The same carry within one register's bits, from `c` into bit 0. -/
private def ripple (gen prop : Nat → Bool) (c : Bool) : Nat → Bool
  | 0 => c
  | t + 1 => gen t || (prop t && ripple gen prop c t)

/-- The carry from bit 1 up is the carry of the bits from 1 up, from the carry into bit 1. -/
private theorem ripple_succ (gen prop : Nat → Bool) (c : Bool) :
    ∀ t, ripple gen prop c (t + 1) =
      ripple (fun t => gen (t + 1)) (fun t => prop (t + 1)) (ripple gen prop c 1) t
  | 0 => rfl
  | t + 1 => by
    rw [ripple, ripple_succ gen prop c t]
    rfl

/-- Bit `t` of a mask register is `bit t`. -/
private theorem bitsOf_testBit (bit : Nat → Bool) :
    ∀ width t, (bitsOf bit width).testBit t = (decide (t < width) && bit t)
  | 0, t => by simp [bitsOf]
  | width + 1, 0 => by
    rw [bitsOf, Nat.testBit_zero]
    cases bit 0 <;> simp
  | width + 1, t + 1 => by
    have h_half : ((bit 0).toNat + 2 * bitsOf (fun t => bit (t + 1)) width) / 2 =
        bitsOf (fun t => bit (t + 1)) width := by
      have h_bit := Bool.toNat_le (bit 0)
      omega
    rw [bitsOf, Nat.testBit_succ, h_half, bitsOf_testBit _ width t]
    simp

/-- A mask register of `width` bits is below `2 ^ width`. -/
private theorem bitsOf_lt (bit : Nat → Bool) : ∀ width, bitsOf bit width < 2 ^ width
  | 0 => by simp [bitsOf]
  | width + 1 => by
    have h_below := bitsOf_lt (fun t => bit (t + 1)) width
    have h_bit := Bool.toNat_le (bit 0)
    rw [bitsOf, pow_succ]
    omega

/-- A register's `total`, for `width` bits: `shifted + propagate + carry_from_below`, with
`shifted` the generate bits moved up one and `gin` below them. -/
private def registerTotal (gen prop : Nat → Bool) (gin cin : Bool) (width : Nat) : Nat :=
  (2 * bitsOf gen width + gin.toNat) % 2 ^ width + bitsOf prop width + cin.toNat

/-- The bit that leaves the top of a register's shifted generate bits: `gin` itself for no
bits. -/
private def topGenerate (gen : Nat → Bool) (gin : Bool) (width : Nat) : Bool :=
  if width = 0 then gin else gen (width - 1)

/-- A register's `total` is its bit 0 and, above it, the `total` of its bits from 1 up with the
carry out of bit 0. -/
private theorem registerTotal_succ (gen prop : Nat → Bool) (gin cin : Bool) (width : Nat)
    (h_one : !(gin && cin)) :
    registerTotal gen prop gin cin (width + 1) =
      (gin.toNat + (prop 0).toNat + cin.toNat) % 2 +
        2 * registerTotal (fun t => gen (t + 1)) (fun t => prop (t + 1)) (gen 0)
          (prop 0 && (gin || cin)) width := by
  have h_gin := Bool.toNat_le gin
  have h_y : 2 * bitsOf gen (width + 1) + gin.toNat =
      gin.toNat + 2 * (2 * bitsOf (fun t => gen (t + 1)) width + (gen 0).toNat) := by
    simp only [bitsOf]
    ring
  have h_prop : bitsOf prop (width + 1) =
      (prop 0).toNat + 2 * bitsOf (fun t => prop (t + 1)) width := rfl
  unfold registerTotal
  rw [h_y, pow_succ, mul_comm (2 ^ width) 2, Nat.mod_mul, h_prop]
  generalize 2 * bitsOf (fun t => gen (t + 1)) width + (gen 0).toNat = high
  have h_mod : (gin.toNat + 2 * high) % 2 = gin.toNat := by omega
  have h_div : (gin.toNat + 2 * high) / 2 = high := by omega
  rw [h_mod, h_div]
  generalize bitsOf (fun t => prop (t + 1)) width = upper
  generalize high % 2 ^ width = low
  generalize prop 0 = p0
  cases gin <;> cases cin <;> cases p0 <;> simp at h_one ⊢ <;> omega

/-- `normalize_digits`'s second loop on one register of `width` bits, from the carries `gin`
(`generate_from_below`) and `cin` (`carry_from_below`) into bit 0: each bit of
`total ^ propagate` is the carry into its lane, and the bit that leaves the top, either
`generate`'s top bit or `total`'s carry out, is the carry into the register above. -/
private theorem register_ripple :
    ∀ (width : Nat) (gen prop : Nat → Bool) (gin cin : Bool), (∀ t, !(gen t && prop t)) →
      !(gin && cin) →
      (∀ t < width, ((registerTotal gen prop gin cin width).testBit t ^^
          (bitsOf prop width).testBit t) = ripple gen prop (gin || cin) t) ∧
        registerTotal gen prop gin cin width / 2 ^ width ≤ 1 ∧
        (topGenerate gen gin width ||
            decide (registerTotal gen prop gin cin width / 2 ^ width = 1)) =
          ripple gen prop (gin || cin) width ∧
        !(topGenerate gen gin width &&
            decide (registerTotal gen prop gin cin width / 2 ^ width = 1))
  | 0, gen, prop, gin, cin, _, h_one => by
    simp only [registerTotal, bitsOf, topGenerate, ripple, pow_zero, Nat.mod_one, Nat.div_one,
      ↓reduceIte]
    cases gin <;> cases cin <;> simp at h_one ⊢
  | width + 1, gen, prop, gin, cin, h_disjoint, h_one => by
    have h_one' : !(gen 0 && (prop 0 && (gin || cin))) := by
      have h_disjoint_zero := h_disjoint 0
      revert h_disjoint_zero
      cases gen 0 <;> cases prop 0 <;> simp
    obtain ⟨h_bits, h_le, h_out, h_not⟩ :=
      register_ripple width (fun t => gen (t + 1)) (fun t => prop (t + 1)) (gen 0)
        (prop 0 && (gin || cin)) (fun t => h_disjoint (t + 1)) h_one'
    have h_step := registerTotal_succ gen prop gin cin width h_one
    have h_half : registerTotal gen prop gin cin (width + 1) / 2 =
        registerTotal (fun t => gen (t + 1)) (fun t => prop (t + 1)) (gen 0)
          (prop 0 && (gin || cin)) width := by
      rw [h_step]
      omega
    have h_prop_half : bitsOf prop (width + 1) / 2 = bitsOf (fun t => prop (t + 1)) width := by
      have h_bit := Bool.toNat_le (prop 0)
      show ((prop 0).toNat + 2 * bitsOf (fun t => prop (t + 1)) width) / 2 = _
      omega
    have h_top : registerTotal gen prop gin cin (width + 1) / 2 ^ (width + 1) =
        registerTotal (fun t => gen (t + 1)) (fun t => prop (t + 1)) (gen 0)
          (prop 0 && (gin || cin)) width / 2 ^ width := by
      rw [pow_succ, mul_comm, ← Nat.div_div_eq_div_mul, h_half]
    have h_top_generate :
        topGenerate gen gin (width + 1) = topGenerate (fun t => gen (t + 1)) (gen 0) width := by
      cases width <;> simp [topGenerate]
    refine ⟨fun t h_t => ?_, h_top ▸ h_le, ?_, h_top ▸ h_top_generate ▸ h_not⟩
    · cases t with
      | zero =>
        have h_total_mod : registerTotal gen prop gin cin (width + 1) % 2 =
            (gin.toNat + (prop 0).toNat + cin.toNat) % 2 := by
          rw [h_step]
          omega
        have h_prop_mod : bitsOf prop (width + 1) % 2 = (prop 0).toNat := by
          have h_bit := Bool.toNat_le (prop 0)
          show ((prop 0).toNat + 2 * bitsOf (fun t => prop (t + 1)) width) % 2 = _
          omega
        rw [Nat.testBit_zero, Nat.testBit_zero, h_total_mod, h_prop_mod]
        show _ = (gin || cin)
        cases gin <;> cases cin <;> cases prop 0 <;> simp at h_one ⊢
      | succ t =>
        rw [Nat.testBit_succ, Nat.testBit_succ, h_half, h_prop_half, h_bits t (by omega),
          ripple_succ gen prop (gin || cin) t]
        rfl
    · rw [h_top, h_top_generate, h_out, ripple_succ gen prop (gin || cin) width]
      rfl

/-- `(generate << 1) | generate_from_below` for a `generate_from_below` of one bit. -/
private theorem shift_or (x : Nat) (b : Bool) : (x <<< 1 ||| b.toNat) = 2 * x + b.toNat := by
  apply Nat.eq_of_testBit_eq
  intro i
  cases i with
  | zero => cases b <;> simp [Nat.testBit_zero, Nat.shiftLeft_eq]
  | succ i =>
    have h_bit := Bool.toNat_le b
    have h_half : (2 * x + b.toNat) / 2 = x := by omega
    have h_b : b.toNat / 2 = 0 := by omega
    rw [Nat.testBit_or, Nat.testBit_shiftLeft, Nat.testBit_succ b.toNat, h_b,
      Nat.testBit_succ, h_half]
    simp

/-- The masks of register `i` of `lanes`, one bit for each of its eight lanes. -/
private theorem generate_eq (lanes : Nat → Nat) (i : Nat) :
    generate lanes i = bitsOf (fun t => decide (2 ^ 52 - 1 < lanes (8 * i + t))) 8 := rfl

/-- The same for the propagate mask. -/
private theorem propagate_eq (lanes : Nat → Nat) (i : Nat) :
    propagate lanes i = bitsOf (fun t => decide (lanes (8 * i + t) = 2 ^ 52 - 1)) 8 := rfl

/-- Within register `i`, the carry is `takesCarry`'s from the register's lane 0 up. -/
private theorem ripple_takesCarry (lanes : Nat → Nat) (i : Nat) :
    ∀ t, ripple (fun t => decide (2 ^ 52 - 1 < lanes (8 * i + t)))
        (fun t => decide (lanes (8 * i + t) = 2 ^ 52 - 1)) (takesCarry lanes (8 * i)) t =
      takesCarry lanes (8 * i + t)
  | 0 => rfl
  | t + 1 => by
    rw [ripple, ripple_takesCarry lanes i t]
    rfl

/-- No lane is both above `2 ^ 52 - 1` and equal to it. -/
private theorem lanes_disjoint (lanes : Nat → Nat) (i t : Nat) :
    !(decide (2 ^ 52 - 1 < lanes (8 * i + t)) && decide (lanes (8 * i + t) = 2 ^ 52 - 1)) := by
  simp only [Bool.not_and, Bool.or_eq_true, Bool.not_eq_true', decide_eq_false_iff_not]
  omega

/-- A register's `total`, as `registerStep` computes it from the masks. -/
private theorem registerStep_total (gen prop : Nat → Bool) (g c : Bool) :
    ((bitsOf gen 8 <<< 1 ||| g.toNat) &&& 0xff) + bitsOf prop 8 + c.toNat =
      registerTotal gen prop g c 8 := by
  rw [shift_or, show (0xff : Nat) = 2 ^ 8 - 1 from rfl, Nat.and_two_pow_sub_one_eq_mod]
  rfl

/-- `generate >> 7`: the top bit of the register's generate mask. -/
private theorem bitsOf_top (gen : Nat → Bool) : bitsOf gen 8 >>> 7 = (gen 7).toNat := by
  have h_lt := bitsOf_lt gen 8
  have h_bit := Nat.toNat_testBit (bitsOf gen 8) 7
  rw [bitsOf_testBit] at h_bit
  rw [Nat.shiftRight_eq_div_pow]
  norm_num at h_lt h_bit ⊢
  omega

/-- The carries into register `i`: one bit each, never both set, and either set exactly where
lane `8 i` takes a carry. -/
private theorem carriesInto_eq (lanes : Nat → Nat) :
    ∀ i, ∃ g c : Bool, carriesInto lanes i = ⟨g.toNat, c.toNat⟩ ∧ !(g && c) ∧
      (g || c) = takesCarry lanes (8 * i)
  | 0 => ⟨false, false, rfl, rfl, rfl⟩
  | i + 1 => by
    obtain ⟨g, c, h_into, h_one, h_carry⟩ := carriesInto_eq lanes i
    set gen := fun t => decide (2 ^ 52 - 1 < lanes (8 * i + t))
    set prop := fun t => decide (lanes (8 * i + t) = 2 ^ 52 - 1)
    obtain ⟨-, h_le, h_out, h_not⟩ :=
      register_ripple 8 gen prop g c (lanes_disjoint lanes i) h_one
    rw [h_carry, ripple_takesCarry] at h_out
    simp only [topGenerate] at h_out h_not
    refine ⟨gen 7, decide (registerTotal gen prop g c 8 / 2 ^ 8 = 1), ?_, h_not, h_out⟩
    show (registerStep (generate lanes i) (propagate lanes i) (carriesInto lanes i)).2 = _
    rw [h_into, generate_eq, propagate_eq]
    simp only [registerStep]
    rw [registerStep_total, bitsOf_top, Nat.shiftRight_eq_div_pow]
    congr 1
    generalize registerTotal gen prop g c 8 / 2 ^ 8 = top at h_le ⊢
    interval_cases top <;> rfl

/-- Bit `t` of register `i`'s `receives` is whether lane `8 i + t` takes a carry. -/
private theorem receives_testBit (lanes : Nat → Nat) (j : Nat) :
    (receives lanes (j / 8)).testBit (j % 8) = takesCarry lanes j := by
  obtain ⟨g, c, h_into, h_one, h_carry⟩ := carriesInto_eq lanes (j / 8)
  obtain ⟨h_bits, -⟩ := register_ripple 8 _ _ g c (lanes_disjoint lanes (j / 8)) h_one
  have h_t : j % 8 < 8 := Nat.mod_lt _ (by norm_num)
  have h_bit := h_bits (j % 8) h_t
  rw [h_carry, ripple_takesCarry, Nat.div_add_mod] at h_bit
  rw [← h_bit, receives, h_into, generate_eq, propagate_eq]
  simp only [registerStep]
  rw [registerStep_total, Nat.testBit_and, Nat.testBit_xor,
    show (0xff : Nat) = 2 ^ 8 - 1 from rfl, Nat.testBit_two_pow_sub_one]
  simp [h_t]

/-- One lane of the second loop: its 52 bits after the carry it takes, and the carry it sends,
weighing `2 ^ 52`, are the lane and the carry it takes. -/
private theorem lane_carry {x : Nat} (c : Bool) (h_x : x ≤ 2 ^ 53 - 2) :
    (x + c.toNat) % 2 ^ 52 +
        2 ^ 52 * (decide (2 ^ 52 - 1 < x) || (decide (x = 2 ^ 52 - 1) && c)).toNat =
      x + c.toNat := by
  norm_num at h_x ⊢
  by_cases h_above : 4503599627370495 < x <;> by_cases h_equal : x = 4503599627370495 <;>
    cases c <;> simp [h_above, h_equal] <;> omega

/-- The second loop keeps the number, less the carry out of the top lane. -/
private theorem carry_value (first : Nat → Nat) :
    ∀ count, (∀ j < count, first j ≤ 2 ^ 53 - 2) →
      value count (fun j => (first j + (takesCarry first j).toNat) % 2 ^ 52) +
          (takesCarry first count).toNat * 2 ^ (52 * count) = value count first
  | 0, _ => by simp [value, takesCarry]
  | count + 1, h_first => by
    have h_below := carry_value first count fun j h_j => h_first j (by omega)
    have h_lane := lane_carry (takesCarry first count) (h_first count (by omega))
    rw [value_succ, value_succ, takesCarry, show 52 * (count + 1) = 52 * count + 52 by ring,
      pow_add]
    linear_combination h_below + 2 ^ (52 * count) * h_lane

/-- The first loop keeps the number, less the carry out of the top lane. -/
private theorem carryPass_value (lanes : Nat → Nat) :
    ∀ count, value count (carryPass lanes) +
        (if count = 0 then 0 else lanes (count - 1) / 2 ^ 52) * 2 ^ (52 * count) =
      value count lanes
  | 0 => by simp [value]
  | count + 1 => by
    have h_below := carryPass_value lanes count
    have h_split := Nat.mod_add_div (lanes count) (2 ^ 52)
    rw [value_succ, value_succ, carryPass, show 52 * (count + 1) = 52 * count + 52 by ring,
      pow_add]
    simp only [Nat.add_one_ne_zero, ↓reduceIte, Nat.add_sub_cancel]
    linear_combination h_below + 2 ^ (52 * count) * h_split

/-- After the first loop a lane below `2 ^ 64` is at most `2 ^ 52 - 1 + 2 ^ 12 - 1`. -/
private theorem carryPass_le {lanes : Nat → Nat} {count : Nat}
    (h_lanes : ∀ j < count, lanes j < 2 ^ 64) :
    ∀ j < count, carryPass lanes j ≤ 2 ^ 53 - 2 := by
  intro j h_j
  have h_low := Nat.mod_lt (lanes j) (show 0 < 2 ^ 52 by norm_num)
  unfold carryPass
  split_ifs with h_zero
  · omega
  · have h_below := h_lanes (j - 1) (by omega)
    have h_high : lanes (j - 1) / 2 ^ 52 < 2 ^ 12 :=
      Nat.div_lt_of_lt_mul (by norm_num at h_below ⊢; omega)
    norm_num at h_low h_high ⊢
    omega

/-- Every lane `normalize_digits` writes is below `2 ^ 52`: it ends with the mask. -/
theorem normalize_lt (lanes : Nat → Nat) (j : Nat) : normalize lanes j < 2 ^ 52 :=
  Nat.mod_lt _ (by norm_num)

/-- `normalize_digits` on `count` lanes, each below `2 ^ 64`, writes the number they hold modulo
`2 ^ (52 count)` in digits below `2 ^ 52`: what it drops is the carry out of the top lane, which
is zero for a number below `2 ^ (52 count)`. -/
theorem normalize_value {lanes : Nat → Nat} {count : Nat}
    (h_lanes : ∀ j < count, lanes j < 2 ^ 64) :
    value count (normalize lanes) = value count lanes % 2 ^ (52 * count) := by
  have h_carry := carry_value (carryPass lanes) count (carryPass_le h_lanes)
  have h_pass := carryPass_value lanes count
  have h_normalize : value count (normalize lanes) = value count fun j =>
      (carryPass lanes j + (takesCarry (carryPass lanes) j).toNat) % 2 ^ 52 := by
    refine value_congr fun j _ => ?_
    simp only [normalize]
    rw [receives_testBit]
    cases takesCarry (carryPass lanes) j <;> simp
  have h_lt : value count (normalize lanes) < 2 ^ (52 * count) :=
    value_lt fun j _ => normalize_lt lanes j
  rw [← h_normalize] at h_carry
  have h_sum : value count (normalize lanes) + 2 ^ (52 * count) *
      ((takesCarry (carryPass lanes) count).toNat +
        if count = 0 then 0 else lanes (count - 1) / 2 ^ 52) = value count lanes := by
    linear_combination h_carry + h_pass
  rw [← h_sum, Nat.add_mul_mod_self_left, Nat.mod_eq_of_lt h_lt]

/-! ## What the product computes -/

/-- After `i` rounds, `2 ^ (52 i)` times the number is `a` times the first `i` digits of `b`
and some multiple of `m` below `2 ^ (52 i)` of it. -/
private theorem rounds_value {count m0inv : Nat} {a b m : Nat → Nat} (h_count : 1 ≤ count)
    (h_a : ∀ j < count, a j < 2 ^ 52) (h_m : ∀ j < count, m j < 2 ^ 52)
    (h_b : ∀ i, b i < 2 ^ 52) (h_m0inv : (m0inv * m 0 + 1) % 2 ^ 52 = 0) :
    ∀ i, ∃ Q < 2 ^ (52 * i),
      value count (replaceFirst (rounds count a b m m0inv i)) * 2 ^ (52 * i) =
        value count a * value i b + Q * value count m
  | 0 => ⟨0, by simp, by simp [value, replaceFirst, rounds]⟩
  | i + 1 => by
    obtain ⟨Q, h_Q, h_eq⟩ := rounds_value h_count h_a h_m h_b h_m0inv i
    have h_round := round_value (rounds count a b m m0inv i) h_count h_a h_m (h_b i) h_m0inv
    set q := quotient m0inv (lowSum a (b i) (rounds count a b m m0inv i))
    have h_q : q < 2 ^ 52 := Nat.mod_lt _ (by norm_num)
    refine ⟨Q + q * 2 ^ (52 * i), ?_, ?_⟩
    · calc Q + q * 2 ^ (52 * i) < 2 ^ (52 * i) + q * 2 ^ (52 * i) := by omega
        _ = (q + 1) * 2 ^ (52 * i) := by ring
        _ ≤ 2 ^ 52 * 2 ^ (52 * i) := Nat.mul_le_mul_right _ h_q
        _ = 2 ^ (52 * (i + 1)) := by ring
    · show value count (replaceFirst (round count a m m0inv (b i) (rounds count a b m m0inv i))) *
          2 ^ (52 * (i + 1)) = _
      rw [value_succ, show 52 * (i + 1) = 52 + 52 * i by ring, pow_add]
      linear_combination 2 ^ (52 * i) * h_round + h_eq

/-- The number below `2 m`: `R W = a b + Q m` with `Q` below `W`, `a` and `b` below `2 m` and
`4 m ≤ W`. -/
private theorem lt_two_mul {R W Q a b m : Nat} (h_eq : R * W = a * b + Q * m) (h_Q : Q < W)
    (h_a : a < 2 * m) (h_b : b < 2 * m) (h_room : 4 * m ≤ W) : R < 2 * m := by
  have h_ab : a * b < m * W := calc
    a * b < 2 * m * (2 * m) := Nat.mul_lt_mul'' h_a h_b
    _ = m * (4 * m) := by ring
    _ ≤ m * W := Nat.mul_le_mul_left _ h_room
  have h_Qm : Q * m < W * m := Nat.mul_lt_mul_of_pos_right h_Q (by omega)
  refine Nat.lt_of_mul_lt_mul_right (a := W) ?_
  calc R * W = a * b + Q * m := h_eq
    _ < m * W + W * m := Nat.add_lt_add h_ab h_Qm
    _ = 2 * m * W := by ring

/-- The product's rounds, under the hypotheses `product_lt` and `product_mul` state. -/
private theorem product_rounds {n m0inv a b m : Nat} (h_m0inv : (m0inv * m + 1) % 2 ^ 52 = 0)
    (h_room : 4 * m ≤ 2 ^ (52 * n)) (h_a : a < 2 * m) (h_b : b < 2 * m) :
    ∃ Q < 2 ^ (52 * n), value (laneCount n) (replaceFirst (productRounds n m0inv a b m)) *
        2 ^ (52 * n) = a * b + Q * m := by
  have h_n : 1 ≤ n := by
    rcases Nat.eq_zero_or_pos n with h_zero | h_pos
    · subst h_zero
      omega
    · exact h_pos
  have h_count : n ≤ laneCount n := by
    unfold laneCount
    omega
  have h_pow : 2 ^ (52 * n) ≤ 2 ^ (52 * laneCount n) :=
    Nat.pow_le_pow_right (by norm_num) (by omega)
  have h_m0inv' : (m0inv * lanesOf (toDigits (laneCount n) m) 0 + 1) % 2 ^ 52 = 0 := by
    rw [toDigits_eq m (by omega), digit, mul_zero, pow_zero, Nat.div_one, Nat.add_mod,
      Nat.mul_mod, Nat.mod_mod, ← Nat.mul_mod, ← Nat.add_mod]
    exact h_m0inv
  obtain ⟨Q, h_Q, h_eq⟩ := rounds_value (count := laneCount n) (by omega)
    (fun j _ => toDigits_lt _ a j) (fun j _ => toDigits_lt _ m j) (toDigits_lt _ b) h_m0inv' n
  rw [value_toDigits le_rfl, value_toDigits h_count, value_toDigits le_rfl,
    Nat.mod_eq_of_lt (a := a) (by omega), Nat.mod_eq_of_lt (a := b) (by omega),
    Nat.mod_eq_of_lt (a := m) (by omega)] at h_eq
  exact ⟨Q, h_Q, h_eq⟩

/-- `normalize_digits` keeps the product's number. -/
private theorem product_eq {n m0inv a b m : Nat} (h_n : n ≤ 128)
    (h_lt : value (laneCount n) (replaceFirst (productRounds n m0inv a b m)) <
      2 ^ (52 * laneCount n)) :
    value (laneCount n) (lanesOf (product n m0inv a b m)) =
      value (laneCount n) (replaceFirst (productRounds n m0inv a b m)) := by
  have h_fit : (∀ j, (productRounds n m0inv a b m).lanes j ≤ 2 ^ 61) ∧
      (productRounds n m0inv a b m).digitZero < 2 ^ 62 :=
    rounds_fit (toDigits_lt (laneCount n) a 0) (toDigits_lt (laneCount n) m 0)
      (toDigits_lt (laneCount n) b) h_n
  obtain ⟨h_lanes, h_zero⟩ := h_fit
  set s := productRounds n m0inv a b m
  set sum := Array.ofFn (n := laneCount n) fun j => replaceFirst s j
  have h_sum : ∀ j < laneCount n, lanesOf sum j = replaceFirst s j :=
    fun j h_j => lanesOf_ofFn _ h_j
  have h_product : ∀ j < laneCount n, lanesOf (product n m0inv a b m) j =
      normalize (lanesOf sum) j :=
    fun j h_j => lanesOf_ofFn _ h_j
  rw [value_congr h_product, normalize_value, value_congr h_sum, Nat.mod_eq_of_lt h_lt]
  intro j h_j
  rw [h_sum j h_j]
  unfold replaceFirst
  split_ifs
  · omega
  · exact (h_lanes j).trans_lt (by norm_num)

/-- The product is below `2 m`, for `a` and `b` below `2 m` and `4 m ≤ 2 ^ (52 n)`, with
`m0inv` the C's `-m⁻¹ mod 2 ^ 52` and at most 128 digits, so that no lane wraps
(`rounds_fit`). -/
theorem product_lt {n m0inv a b m : Nat} (h_m0inv : (m0inv * m + 1) % 2 ^ 52 = 0)
    (h_room : 4 * m ≤ 2 ^ (52 * n)) (h_n : n ≤ 128) (h_a : a < 2 * m) (h_b : b < 2 * m) :
    value (laneCount n) (lanesOf (product n m0inv a b m)) < 2 * m := by
  obtain ⟨Q, h_Q, h_eq⟩ := product_rounds h_m0inv h_room h_a h_b
  have h_lt := lt_two_mul h_eq h_Q h_a h_b h_room
  have h_pow : 2 ^ (52 * n) ≤ 2 ^ (52 * laneCount n) :=
    Nat.pow_le_pow_right (by norm_num) (by unfold laneCount; omega)
  rw [product_eq h_n (by omega)]
  exact h_lt

/-- The product is `a b 2 ^ (-52 n)` modulo `m`, under `product_lt`'s hypotheses. -/
theorem product_mul {n m0inv a b m : Nat} (h_m0inv : (m0inv * m + 1) % 2 ^ 52 = 0)
    (h_room : 4 * m ≤ 2 ^ (52 * n)) (h_n : n ≤ 128) (h_a : a < 2 * m) (h_b : b < 2 * m) :
    (value (laneCount n) (lanesOf (product n m0inv a b m)) : ZMod m) * 2 ^ (52 * n) = a * b := by
  obtain ⟨Q, h_Q, h_eq⟩ := product_rounds h_m0inv h_room h_a h_b
  have h_lt := lt_two_mul h_eq h_Q h_a h_b h_room
  have h_pow : 2 ^ (52 * n) ≤ 2 ^ (52 * laneCount n) :=
    Nat.pow_le_pow_right (by norm_num) (by unfold laneCount; omega)
  rw [product_eq h_n (by omega)]
  have h_cast := congrArg (Nat.cast : Nat → ZMod m) h_eq
  push_cast at h_cast
  rw [ZMod.natCast_self, mul_zero, add_zero] at h_cast
  exact h_cast

/-! ## What `power_of_two_mod` computes -/

/-- `power_of_two_mod`'s start, a single bit in word `k - 1`, is below an odd `m` of `k` words
whose top bit is set, as `times_word_mod` requires of what it takes. -/
theorem powerOfTwoStart_lt {m k e : Nat} (h_odd : m % 2 = 1) (h_top : 2 ^ (64 * k - 1) ≤ m)
    (h_k : 1 ≤ k) : powerOfTwoStart k e < m := by
  have h_le : powerOfTwoStart k e ≤ 2 ^ (64 * k - 1) :=
    Nat.pow_le_pow_right (by norm_num) (by omega)
  have h_even : 2 ^ (64 * k - 1) % 2 = 0 := by
    rw [show 64 * k - 1 = 64 * k - 2 + 1 by omega, pow_succ]
    simp
  omega

/-- Steps of `times_word_mod` multiply by `2 ^ 64` each, modulo `m`. -/
private theorem iterate_timesWordMod_mod (m x : Nat) :
    ∀ i, (timesWordMod m)^[i] x % m = x * 2 ^ (64 * i) % m
  | 0 => by simp
  | i + 1 => by
    rw [Function.iterate_succ_apply', timesWordMod, Nat.mod_mod, Nat.mul_mod,
      iterate_timesWordMod_mod m x i, ← Nat.mul_mod, mul_assoc, ← pow_add]
    ring_nf

/-- `power_of_two_mod` writes `2 ^ e mod m` for an odd `m` of `k` words whose top bit is set and
an exponent of at least `64 (k - 1)`: each step multiplies by `2 ^ 64`, and the start times
`2 ^ (64 steps)` is `2 ^ e`. -/
theorem powerOfTwoMod_eq {m k e : Nat} (h_odd : m % 2 = 1) (h_top : 2 ^ (64 * k - 1) ≤ m)
    (h_k : 1 ≤ k) (h_e : 64 * (k - 1) ≤ e) : powerOfTwoMod m k e = 2 ^ e % m := by
  have h_lt : powerOfTwoMod m k e < m := by
    unfold powerOfTwoMod
    cases h_steps : powerOfTwoSteps k e with
    | zero => exact powerOfTwoStart_lt h_odd h_top h_k
    | succ i =>
      rw [Function.iterate_succ_apply']
      exact Nat.mod_lt _ (by omega)
  have h_exponent : 64 * (k - 1) + e % 64 + 64 * powerOfTwoSteps k e = e := by
    unfold powerOfTwoSteps
    omega
  rw [← Nat.mod_eq_of_lt h_lt, powerOfTwoMod, iterate_timesWordMod_mod, powerOfTwoStart,
    ← pow_add, h_exponent]

/-! ## `rsa_ifma_public` -/

/-- `rsa_ifma_public`'s chain of products computes RSAVP1 (RFC 8017 5.2.2) for every base below
`2 ^ (64 k)`: `base ^ 65537 mod m`, for an `m` of `k` words whose top bit is set, `m0inv` the C's
`-m⁻¹ mod 2 ^ 52`, `digit_r2 = 2 ^ (104 n) mod m` and at most 128 digits. -/
theorem publicOp_eq {k m0inv m base : Nat} (h_m0inv : (m0inv * m + 1) % 2 ^ 52 = 0)
    (h_top : 2 ^ (64 * k - 1) ≤ m) (h_m : m < 2 ^ (64 * k)) (h_n : digitCount k ≤ 128)
    (h_base : base < 2 ^ (64 * k)) :
    publicOp k m0inv m base (2 ^ (104 * digitCount k) % m) = base ^ 65537 % m := by
  have h_room : 4 * m ≤ 2 ^ (52 * digitCount k) := (digitCount_room h_m).le
  have h_k : 1 ≤ k := by
    rcases Nat.eq_zero_or_pos k with h_zero | h_pos
    · subst h_zero
      simp at h_top h_m
      omega
    · exact h_pos
  have h_base_lt : base < 2 * m := by
    have h_double : 2 ^ (64 * k) = 2 * 2 ^ (64 * k - 1) := by
      rw [← pow_succ']
      congr 1
      omega
    omega
  have h_odd : m % 2 = 1 := by
    have h_two : (m0inv * m + 1) % 2 = 0 := by
      rw [← Nat.mod_mod_of_dvd _ (show 2 ∣ 2 ^ 52 by norm_num), h_m0inv]
    rcases Nat.mod_two_eq_zero_or_one m with h_even | h_one
    · have : m0inv * m % 2 = 0 := by rw [Nat.mul_mod, h_even, mul_zero, Nat.zero_mod]
      omega
    · exact h_one
  have h_unit : IsUnit ((2 : ZMod m) ^ (52 * digitCount k)) := by
    have h_two : IsUnit ((2 : ℕ) : ZMod m) :=
      (ZMod.isUnit_iff_coprime 2 m).mpr (Nat.coprime_two_left.mpr (Nat.odd_iff.mpr h_odd))
    exact (by exact_mod_cast h_two : IsUnit (2 : ZMod m)).pow _
  have h_product : ∀ x y, x < 2 * m → y < 2 * m →
      value (laneCount (digitCount k)) (lanesOf (product (digitCount k) m0inv x y m)) < 2 * m ∧
        (value (laneCount (digitCount k)) (lanesOf (product (digitCount k) m0inv x y m)) : ZMod m) *
          2 ^ (52 * digitCount k) = x * y :=
    fun x y h_x h_y =>
      ⟨product_lt h_m0inv h_room h_n h_x h_y, product_mul h_m0inv h_room h_n h_x h_y⟩
  have h_r2_lt : 2 ^ (104 * digitCount k) % m < 2 * m := by
    have := Nat.mod_lt (2 ^ (104 * digitCount k)) (show 0 < m by omega)
    omega
  have h_r2 : ((2 ^ (104 * digitCount k) % m : ℕ) : ZMod m) =
      2 ^ (52 * digitCount k) * 2 ^ (52 * digitCount k) := by
    rw [ZMod.natCast_mod, ← pow_add, show 52 * digitCount k + 52 * digitCount k =
      104 * digitCount k by ring]
    push_cast
    rfl
  set square := fun p =>
    value (laneCount (digitCount k)) (lanesOf (product (digitCount k) m0inv p p m))
    with h_square
  obtain ⟨h_first_lt, h_first⟩ := h_product base _ h_base_lt h_r2_lt
  set first := value (laneCount (digitCount k))
    (lanesOf (product (digitCount k) m0inv base (2 ^ (104 * digitCount k) % m) m))
  have h_squares : ∀ j, square^[j] first < 2 * m ∧
      (square^[j] first : ZMod m) = base ^ 2 ^ j * 2 ^ (52 * digitCount k) := by
    intro j
    induction j with
    | zero =>
      refine ⟨h_first_lt, h_unit.mul_right_cancel ?_⟩
      rw [Function.iterate_zero_apply, h_first, h_r2]
      ring
    | succ j ih =>
      obtain ⟨h_lt, h_eq⟩ := ih
      obtain ⟨h_next_lt, h_next⟩ := h_product _ _ h_lt h_lt
      rw [Function.iterate_succ_apply']
      refine ⟨h_next_lt, h_unit.mul_right_cancel ?_⟩
      rw [h_next, h_eq]
      ring
  obtain ⟨h_power_lt, h_power⟩ := h_squares 16
  obtain ⟨h_last_lt, h_last⟩ := h_product base _ h_base_lt h_power_lt
  set last := value (laneCount (digitCount k))
    (lanesOf (product (digitCount k) m0inv base (square^[16] first) m))
  have h_last' : (last : ZMod m) = base ^ 65537 := by
    refine h_unit.mul_right_cancel ?_
    rw [h_last, h_power]
    ring
  have h_reduce_lt : reduceOnce m last < m := by
    unfold reduceOnce
    split_ifs <;> omega
  have h_reduce : (reduceOnce m last : ZMod m) = base ^ 65537 := by
    rw [← h_last']
    unfold reduceOnce
    split_ifs with h_ge
    · rw [Nat.cast_sub h_ge, ZMod.natCast_self, sub_zero]
    · rfl
  show reduceOnce m last = _
  rw [← Nat.mod_eq_of_lt h_reduce_lt]
  exact (ZMod.natCast_eq_natCast_iff' _ _ m).mp (by push_cast; exact h_reduce)

/-! ## Selftest -/

/-- `base ^ 65537 mod m` by sixteen squares and a product modulo `m`, which shares nothing with
the model: the selftest's reference. -/
private def referencePublic (m base : Nat) : Nat :=
  (fun x => x * x % m)^[16] (base % m) * base % m

set_option compiler.extract_closed false in
/-- The digit counts and `power_of_two_mod`'s steps at RSA-2048, RSA-3072 and RSA-4096;
`normalize` on lanes whose carries run across a register's edge and out of the top lane,
against the number they hold; and at RSA-2048, under `2 ^ 2048 - 1`, `2 ^ 2047 + 1` and a third
odd modulus with the top bit set, `power_of_two_mod` against `2 ^ (104 n) mod m` and
`rsa_ifma_public` against `base ^ 65537 mod m` for the bases 2, `m - 1` and `2 ^ 2048 - 1`. -/
def selftest (_ : Unit) : Bool :=
  let counts := [32, 48, 64].map digitCount == [40, 60, 79]
  let steps := [32, 48, 64].map (fun k => powerOfTwoSteps k (104 * digitCount k)) == [34, 50, 65]
  let lanes := fun j => [0, 0, 0, 0, 2 ^ 52, 2 ^ 52 - 1, 2 ^ 52 - 1, 2 ^ 52 - 1, 2 ^ 52 - 1,
    2 ^ 52 - 1, 5, 2 ^ 64 - 1, 2 ^ 63, 2 ^ 52 - 1, 2 ^ 52 - 1, 2 ^ 64 - 1].getD j 0
  let normalized := value 16 (normalize lanes) == value 16 lanes % 2 ^ (52 * 16) &&
    (List.range 16).all fun j => normalize lanes j < 2 ^ 52
  let moduli := [2 ^ 2048 - 1, 2 ^ 2047 + 1,
    2 ^ 2047 + 0x9f3a5c7e1b2d4f60 * 2 ^ 1500 + 0x5ad1c3e2f4b60718 * 2 ^ 700 + 0x2b]
  let check := fun m =>
    let digitR2 := powerOfTwoMod m 32 (104 * 40)
    digitR2 == 2 ^ (104 * 40) % m && [2, m - 1, 2 ^ 2048 - 1].all fun base =>
      publicOp 32 (m0invOf m) m base digitR2 == referencePublic m base
  counts && steps && normalized && moduli.all check

end Spec.RsaIfma
