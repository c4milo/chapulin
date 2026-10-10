import Mathlib.Data.ZMod.Basic
import Mathlib.Tactic
import Spec.RsaIfma

/-!
RSA's public operation on AVX2, `rsa_avx2.c`, modeled from the C.

`rsa_avx2.c` holds a number in digits of `D` bits, 28 up to 48 words and 27 above, one to a
64-bit lane, four lanes to a 256-bit register. Its product is the almost-Montgomery product in
radix `2 ^ D` by operand scanning: row `i` adds `b_i a` and `y_i m` to the sum at digit `i`, and
the sum's lanes carry into each other only in the triangles and in the last pass.

The model holds the sum as lanes laid end to end, lane `p` for digit position `p`, each in a
`Nat` where the C holds a 64-bit word, and computes for each lane what the C adds to it. The C
adds the same numbers in another order: four rows at a time, register by register, in a window
of registers that moves down one register a group. `rows p` is what the rows of `a` add to lane
`p`: `multiplyRows`, or `squareRows` for a square, whose row `r` multiplies `a_s` by `2 a_r`,
`a_r` or nothing (`squareMultiplier`, the blends of `add_square_rows`). `lower` is the triangles:
lane `p`'s `y` comes from the lane once every row below it has added its `y_i m_(p - i)` and the
carry from lane `p - 1` has arrived (`laneSum`), and the lane keeps its low `D` bits and carries
the rest. `upperLane` is what the sum holds after the last triangle, and `carryPass` is
`product_core`'s last loop.

`squareRows_eq` proves that a square's rows put in each lane what a multiplication of `a` by
itself puts there, so `square` is `multiply` of `a` and `a`. `lanes_fit` proves that no lane the
C sums passes `2 ^ 64`, for any digit width and digit count that leave room for `2 n` digit
products and two carries, and `room_28` and `room_27` that the C's widths and counts leave it.
`product_lt` and `product_mul` prove that the product of `a` and `b` below `2 m` is below `2 m`
and is `a b 2 ^ (-D n)` modulo `m`, for `4 m ≤ 2 ^ (D n)`, which `digitCount_room` gives, and
`publicOp_eq` that `rsa_avx2_public`'s chain of products computes `base ^ 65537 mod m`.

This module is written from the C, not from a standard, and CONTRACT.md says why.
-/

namespace Spec.RsaAvx2

open Finset

/-! ## Digits -/

/-- `RSA_AVX2_DIGIT_BITS` in `rsa_avx2.h`: 28 bits up to RSA-3072's 48 words, 27 above. -/
def digitBits (words : Nat) : Nat :=
  if words ≤ 48 then 28 else 27

/-- `RSA_AVX2_DIGIT_COUNT`: the digits that hold `words` 64-bit words with two bits to spare,
`⌈(64 words + 2) / D⌉`. -/
def digitCount (words : Nat) : Nat :=
  if words ≤ 48 then (64 * words + 2 + 27) / 28 else (64 * words + 2 + 26) / 27

/-- The lanes of the registers whose triangles run: `4 ⌈n / 4⌉`, four lanes for each of
`product_core`'s groups. -/
def triangleLanes (n : Nat) : Nat :=
  4 * ((n + 3) / 4)

/-- Digit `j` of `x` in digits of `D` bits: its bits `D j` to `D j + D - 1`. -/
def digit (D x j : Nat) : Nat :=
  x / 2 ^ (D * j) % 2 ^ D

/-- `words_to_digits` on a number: its first `n` digits, which the C's layout holds from lane
`PAD`, with zeros below and above them. -/
def toDigits (D n x : Nat) : Array Nat :=
  Array.ofFn (n := n) fun j => digit D x j

/-- The lanes of an array of them, the C's array of `uint64_t`: 0 past its end. -/
def lanesOf (lanes : Array Nat) (j : Nat) : Nat :=
  lanes.getD j 0

/-- The number lanes `0` to `count - 1` hold, lane `j` weighing `2 ^ (D j)`. A lane of the sum may
hold more than `D` bits. -/
def value (D count : Nat) (lanes : Nat → Nat) : Nat :=
  ∑ j ∈ range count, lanes j * 2 ^ (D * j)

/-! ## Rows -/

/-- What a multiplication's rows add to lane `p`: row `i` adds `b_i a_(p - i)`, for every row up
to `p`. A row above `p` meets the zero lanes below `a`'s digit 0 there. -/
def multiplyRows (a b : Nat → Nat) (p : Nat) : Nat :=
  ∑ i ∈ range (p + 1), b i * a (p - i)

/-- The multiplier of a square's row `r` at `a`'s digit `s`: `2 a_r` above its own digit, `a_r`
at it, and nothing below it, as `broadcast_twice_four`, `broadcast_four` and the blends of
`add_square_rows` make them. -/
def squareMultiplier (a : Nat → Nat) (r s : Nat) : Nat :=
  if r < s then 2 * a r else if r = s then a r else 0

/-- What a square's rows add to lane `p`. -/
def squareRows (a : Nat → Nat) (p : Nat) : Nat :=
  ∑ r ∈ range (p + 1), squareMultiplier a r (p - r) * a (p - r)

/-! ## The triangles -/

/-- What the triangles have written once lanes `0` to `p - 1` are done: the `y`s of those rows,
the carry into lane `p`, and what those lanes keep. -/
structure Lower where
  /-- `y_i` for each row `i` below `p`, and 0 from `p` up. -/
  y : Nat → Nat
  /-- The carry out of lane `p - 1`, `*carry` or the `x >> bits` of the step below. -/
  carry : Nat
  /-- What lanes below `p` keep, `x & mask`, and 0 from `p` up. -/
  lanes : Nat → Nat

/-- Lane `p` when its triangle reads it: its rows, `y_i m_(p - i)` for each row `i` below it, and
the carry from lane `p - 1`. -/
def laneSum (rows m : Nat → Nat) (s : Lower) (p : Nat) : Nat :=
  rows p + (∑ i ∈ range p, s.y i * m (p - i)) + s.carry

/-- `triangle`'s `y` at lane `p`: `((l & mask) * k0) & mask` for a row below `n`, and 0 for a row
at or past it, which `step1` to `step3` mask. -/
def quotient (D n k0 l p : Nat) : Nat :=
  if p < n then l * k0 % 2 ^ D else 0

/-- `triangle`'s step at lane `p`: the lane's `y`, the lane plus `y m_0` as `x`, its low `D` bits
kept and the rest carried. -/
def step (D n k0 : Nat) (rows m : Nat → Nat) (s : Lower) (p : Nat) : Lower :=
  let l := laneSum rows m s p
  let y := quotient D n k0 l p
  let x := l + y * m 0
  ⟨Function.update s.y p y, x / 2 ^ D, Function.update s.lanes p (x % 2 ^ D)⟩

/-- The triangles' steps at lanes `0` to `p - 1`. -/
def lower (D n k0 : Nat) (rows m : Nat → Nat) : Nat → Lower
  | 0 => ⟨fun _ => 0, 0, fun _ => 0⟩
  | p + 1 => step D n k0 rows m (lower D n k0 rows m p) p

/-- The `x` of `triangle` at lane `p`, the most lane `p` holds: its sum and `y_p m_0`. -/
def triangleSum (D n k0 : Nat) (rows m : Nat → Nat) (p : Nat) : Nat :=
  let l := laneSum rows m (lower D n k0 rows m p) p
  l + quotient D n k0 l p * m 0

/-- Lane `p` of the sum after the last triangle, the triangles' `L` lanes done: what they kept
below `L`, and from `L` up the rows, the `y`s' rows of `m`, and at `L` the last carry
(`window[4] += carry`). -/
def upperLane (rows m : Nat → Nat) (s : Lower) (L p : Nat) : Nat :=
  if p < L then s.lanes p
  else rows p + (∑ i ∈ range L, s.y i * m (p - i)) + if p = L then s.carry else 0

/-- `product_core`'s last loop over `q` lanes: the digits it writes and `moved`. -/
def carryPass (D : Nat) (lanes : Nat → Nat) : Nat → (Nat → Nat) × Nat
  | 0 => (fun _ => 0, 0)
  | q + 1 =>
    let prev := carryPass D lanes q
    let v := lanes q + prev.2
    (Function.update prev.1 q (v % 2 ^ D), v / 2 ^ D)

/-- The lanes `product_core`'s last loop reads, `n` to `2n - 1` of the sum after the triangles
over `4 ⌈n / 4⌉` lanes. -/
def resultLanes (D n k0 : Nat) (rows m : Nat → Nat) (q : Nat) : Nat :=
  upperLane rows m (lower D n k0 rows m (triangleLanes n)) (triangleLanes n) (n + q)

/-- `product_core`: the result's `n` digits, from its last loop. -/
def product (D n k0 : Nat) (rows m : Nat → Nat) : Array Nat :=
  let s := lower D n k0 rows m (triangleLanes n)
  let out := (carryPass D (fun q => upperLane rows m s (triangleLanes n) (n + q)) n).1
  Array.ofFn (n := n) fun q => out q

/-- The C's multiplication of `a` by `b`, on their digits and `m`'s. -/
def multiply (D n k0 a b m : Nat) : Array Nat :=
  product D n k0 (multiplyRows (lanesOf (toDigits D n a)) (lanesOf (toDigits D n b)))
    (lanesOf (toDigits D n m))

/-- The C's square of `a`. -/
def square (D n k0 a m : Nat) : Array Nat :=
  product D n k0 (squareRows (lanesOf (toDigits D n a))) (lanesOf (toDigits D n m))

/-! ## `rsa_avx2_public` -/

/-- `rsa_mont64_reduce_once_with_top`'s answer: `x - m` for `x` at least `m`, else `x`. -/
def reduceOnce (m x : Nat) : Nat :=
  if m ≤ x then x - m else x

/-- `rsa_avx2_public` on numbers, for a modulus of `k` words: the product of `base` and
`digitR2`, sixteen squares, the product of `base` and that power, and one subtraction of `m`. -/
def publicOp (k k0 m base digitR2 : Nat) : Nat :=
  let D := digitBits k
  let n := digitCount k
  let power := value D n (lanesOf (multiply D n k0 base digitR2 m))
  let power := (fun p => value D n (lanesOf (square D n k0 p m)))^[16] power
  reduceOnce m (value D n (lanesOf (multiply D n k0 base power m)))

/-- The `k0` of `rsa_avx2_modulus`: `-m⁻¹ mod 2 ^ D`, for an odd `m`. -/
def k0Of (D m : Nat) : Nat :=
  (2 ^ D - ((m : ZMod (2 ^ D))⁻¹).val) % 2 ^ D

/-! ## Lanes -/

/-- The number in `count + 1` lanes, the top lane apart. -/
private theorem value_succ (D count : Nat) (lanes : Nat → Nat) :
    value D (count + 1) lanes = value D count lanes + lanes count * 2 ^ (D * count) :=
  Finset.sum_range_succ _ _

/-- Lanes that agree below `count` hold the same number there. -/
private theorem value_congr {D count : Nat} {f g : Nat → Nat} (h_same : ∀ j < count, f j = g j) :
    value D count f = value D count g :=
  Finset.sum_congr rfl fun j h_j => by rw [h_same j (Finset.mem_range.mp h_j)]

/-- The digits of `x` in `count` lanes hold `x mod 2 ^ (D count)`. -/
private theorem value_digit (D x : Nat) : ∀ count, value D count (digit D x) = x % 2 ^ (D * count)
  | 0 => by simp [value, Nat.mod_one]
  | count + 1 => by
    rw [value_succ, value_digit D x count, show D * (count + 1) = D * count + D by ring,
      pow_add, Nat.mod_mul, digit]
    ring

/-- Lanes below `2 ^ D` in `count` lanes hold a number below `2 ^ (D count)`. -/
private theorem value_lt {D : Nat} {lanes : Nat → Nat} :
    ∀ {count}, (∀ j < count, lanes j < 2 ^ D) → value D count lanes < 2 ^ (D * count)
  | 0, _ => by simp [value]
  | count + 1, h_lanes => by
    have h_below := value_lt (count := count) fun j h_j => h_lanes j (by omega)
    have h_top := h_lanes count (by omega)
    rw [value_succ, show D * (count + 1) = D * count + D by ring, pow_add]
    calc value D count lanes + lanes count * 2 ^ (D * count)
        < 2 ^ (D * count) + lanes count * 2 ^ (D * count) := by omega
      _ = (lanes count + 1) * 2 ^ (D * count) := by ring
      _ ≤ 2 ^ D * 2 ^ (D * count) := Nat.mul_le_mul_right _ h_top
      _ = 2 ^ (D * count) * 2 ^ D := by ring

/-- An array's lanes below its size are its entries. -/
private theorem lanesOf_ofFn {count j : Nat} (f : Fin count → Nat) (h_j : j < count) :
    lanesOf (Array.ofFn f) j = f ⟨j, h_j⟩ := by
  rw [lanesOf, Array.getD_eq_getD_getElem?, Array.getElem?_ofFn, dif_pos h_j]
  rfl

/-- An array's lanes from its size up are 0. -/
private theorem lanesOf_ofFn_ge {count j : Nat} (f : Fin count → Nat) (h_j : count ≤ j) :
    lanesOf (Array.ofFn f) j = 0 := by
  rw [lanesOf, Array.getD_eq_getD_getElem?, Array.getElem?_ofFn, dif_neg (by omega)]
  rfl

/-- Lane `j` of a number's digits is its digit `j` below `n`, and 0 from `n` up. -/
private theorem lanesOf_toDigits (D n x j : Nat) :
    lanesOf (toDigits D n x) j = if j < n then digit D x j else 0 := by
  split_ifs with h_j
  · exact lanesOf_ofFn _ h_j
  · exact lanesOf_ofFn_ge _ (by omega)

/-- A number's digits are below `2 ^ D`. -/
private theorem toDigits_lt (D n x j : Nat) : lanesOf (toDigits D n x) j < 2 ^ D := by
  rw [lanesOf_toDigits]
  split_ifs
  · exact Nat.mod_lt _ (by positivity)
  · positivity

/-- A number's digits are 0 from `n` up. -/
private theorem toDigits_zero {D n x j : Nat} (h_j : n ≤ j) : lanesOf (toDigits D n x) j = 0 := by
  rw [lanesOf_toDigits, if_neg (by omega)]

/-- A number's `n` digits hold `x mod 2 ^ (D n)`. -/
private theorem value_toDigits (D n x : Nat) :
    value D n (lanesOf (toDigits D n x)) = x % 2 ^ (D * n) := by
  rw [← value_digit D x n]
  exact value_congr fun j h_j => by rw [lanesOf_toDigits, if_pos h_j]

/-! ## Sums of products -/

/-- Lanes below `N` of the convolution of `f` and `g`, `∑ f_i g_(p - i)` at lane `p`, against the
products of `f` and `g`'s lanes whose positions add to less than `N`. -/
private theorem convolution_sum (f g : Nat → Nat) (x : Nat) : ∀ N,
    ∑ p ∈ range N, (∑ i ∈ range (p + 1), f i * g (p - i)) * x ^ p =
      ∑ i ∈ range N, ∑ j ∈ range (N - i), f i * x ^ i * (g j * x ^ j)
  | 0 => by simp
  | N + 1 => by
    rw [Finset.sum_range_succ, convolution_sum f g x N,
      Finset.sum_range_succ (fun i => ∑ j ∈ range (N + 1 - i), f i * x ^ i * (g j * x ^ j)) N]
    have h_inner : ∀ i ∈ range N, ∑ j ∈ range (N + 1 - i), f i * x ^ i * (g j * x ^ j) =
        ∑ j ∈ range (N - i), f i * x ^ i * (g j * x ^ j) +
          f i * x ^ i * (g (N - i) * x ^ (N - i)) := by
      intro i h_i
      rw [Finset.mem_range] at h_i
      rw [show N + 1 - i = N - i + 1 by omega, Finset.sum_range_succ]
    rw [Finset.sum_congr rfl h_inner, Finset.sum_add_distrib, Nat.add_sub_cancel_left,
      Finset.sum_range_one, Finset.sum_mul, Finset.sum_range_succ (fun i => f i * g (N - i) * _),
      Nat.sub_self]
    have h_terms : ∀ i ∈ range N, f i * g (N - i) * x ^ N =
        f i * x ^ i * (g (N - i) * x ^ (N - i)) := by
      intro i h_i
      rw [Finset.mem_range] at h_i
      have h_pow : x ^ N = x ^ i * x ^ (N - i) := by rw [← pow_add]; congr 1; omega
      rw [h_pow]
      ring
    rw [Finset.sum_congr rfl h_terms]
    ring

/-- The convolution of two sequences of `n` lanes, over `2 n` lanes or more, holds the product
of their numbers. -/
private theorem convolution_value {f g : Nat → Nat} {x n N : Nat} (h_f : ∀ i, n ≤ i → f i = 0)
    (h_g : ∀ j, n ≤ j → g j = 0) (h_N : 2 * n ≤ N) :
    ∑ p ∈ range N, (∑ i ∈ range (p + 1), f i * g (p - i)) * x ^ p =
      (∑ i ∈ range n, f i * x ^ i) * ∑ j ∈ range n, g j * x ^ j := by
  rw [convolution_sum, Finset.sum_mul]
  have h_outer : ∑ i ∈ range N, ∑ j ∈ range (N - i), f i * x ^ i * (g j * x ^ j) =
      ∑ i ∈ range n, ∑ j ∈ range (N - i), f i * x ^ i * (g j * x ^ j) := by
    symm
    refine Finset.sum_subset (Finset.range_mono (show n ≤ N by omega)) fun i _ h_i => ?_
    rw [Finset.mem_range, not_lt] at h_i
    simp [h_f i h_i]
  rw [h_outer]
  refine Finset.sum_congr rfl fun i h_i => ?_
  rw [Finset.mem_range] at h_i
  rw [Finset.mul_sum]
  symm
  refine Finset.sum_subset (Finset.range_mono (show n ≤ N - i by omega)) fun j _ h_j => ?_
  rw [Finset.mem_range, not_lt] at h_j
  simp [h_g j h_j]

/-- A sum of lanes that are 0 from `n` up and at most `c` each is at most `n c`. -/
private theorem sum_le_count {f : Nat → Nat} {n c : Nat} (h_zero : ∀ i, n ≤ i → f i = 0)
    (h_le : ∀ i, f i ≤ c) (P : Nat) : ∑ i ∈ range P, f i ≤ n * c := by
  calc ∑ i ∈ range P, f i = ∑ i ∈ range P with i < n, f i := by
        rw [Finset.sum_filter]
        refine Finset.sum_congr rfl fun i _ => ?_
        split_ifs with h_i
        · rfl
        · exact h_zero i (by omega)
    _ ≤ ∑ i ∈ range n, f i := by
        refine Finset.sum_le_sum_of_subset fun i h_i => ?_
        simp only [Finset.mem_filter, Finset.mem_range] at h_i ⊢
        exact h_i.2
    _ ≤ ∑ _i ∈ range n, c := Finset.sum_le_sum fun i _ => h_le i
    _ = n * c := by simp

/-! ## The square's rows -/

/-- A square's rows put in each lane what the multiplication of `a` by itself puts there: at lane
`p` the terms of rows `r` and `p - r` add up to `2 a_r a_(p - r)` for every `r`, as rows `r` and
`p - r` of the multiplication do. -/
theorem squareRows_eq (a : Nat → Nat) (p : Nat) : squareRows a p = multiplyRows a a p := by
  set f := fun r => squareMultiplier a r (p - r) * a (p - r) with h_f
  have h_pair : ∀ r ∈ range (p + 1), f r + f (p - r) = 2 * (a r * a (p - r)) := by
    intro r h_r
    rw [Finset.mem_range] at h_r
    simp only [h_f, show p - (p - r) = r by omega, squareMultiplier]
    split_ifs <;> first | omega | ring
  have h_reflect : ∑ r ∈ range (p + 1), f (p - r) = ∑ r ∈ range (p + 1), f r := by
    have h := Finset.sum_range_reflect f (p + 1)
    simp only [Nat.add_sub_cancel] at h
    exact h
  have h_twice : 2 * squareRows a p = 2 * multiplyRows a a p := by
    calc 2 * squareRows a p = ∑ r ∈ range (p + 1), f r + ∑ r ∈ range (p + 1), f (p - r) := by
          rw [h_reflect, squareRows]
          ring
      _ = ∑ r ∈ range (p + 1), 2 * (a r * a (p - r)) := by
          rw [← Finset.sum_add_distrib]
          exact Finset.sum_congr rfl h_pair
      _ = 2 * multiplyRows a a p := by
          rw [multiplyRows, Finset.mul_sum]
  omega

/-- The square of `a` is the multiplication of `a` by itself, lane for lane. -/
theorem square_eq_multiply (D n k0 a m : Nat) : square D n k0 a m = multiply D n k0 a a m := by
  unfold square multiply
  congr 1
  funext p
  exact squareRows_eq _ p

/-! ## What the triangles keep -/

section Lower

variable {D n k0 : Nat} {rows m : Nat → Nat}

/-- No step writes a `y` from its own lane up. -/
private theorem lower_y_ge : ∀ p i, p ≤ i → (lower D n k0 rows m p).y i = 0
  | 0, _, _ => rfl
  | p + 1, i, h_i => by
    show Function.update (lower D n k0 rows m p).y p _ i = 0
    rw [Function.update_of_ne (by omega)]
    exact lower_y_ge p i (by omega)

/-- No step writes a lane from its own lane up. -/
private theorem lower_lanes_ge : ∀ p i, p ≤ i → (lower D n k0 rows m p).lanes i = 0
  | 0, _, _ => rfl
  | p + 1, i, h_i => by
    show Function.update (lower D n k0 rows m p).lanes p _ i = 0
    rw [Function.update_of_ne (by omega)]
    exact lower_lanes_ge p i (by omega)

/-- A later step leaves a `y` alone. -/
private theorem lower_y_stable (p i : Nat) (h_i : i < p) :
    ∀ q, (lower D n k0 rows m (p + q)).y i = (lower D n k0 rows m p).y i
  | 0 => rfl
  | q + 1 => by
    show Function.update (lower D n k0 rows m (p + q)).y (p + q) _ i = _
    rw [Function.update_of_ne (by omega)]
    exact lower_y_stable p i h_i q

/-- A later step leaves a lane alone. -/
private theorem lower_lanes_stable (p i : Nat) (h_i : i < p) :
    ∀ q, (lower D n k0 rows m (p + q)).lanes i = (lower D n k0 rows m p).lanes i
  | 0 => rfl
  | q + 1 => by
    show Function.update (lower D n k0 rows m (p + q)).lanes (p + q) _ i = _
    rw [Function.update_of_ne (by omega)]
    exact lower_lanes_stable p i h_i q

/-- Every `y` is below `2 ^ D`, and 0 for a row at or past `n`. -/
private theorem lower_y_lt : ∀ p i, (lower D n k0 rows m p).y i < 2 ^ D ∧
    (n ≤ i → (lower D n k0 rows m p).y i = 0)
  | 0, _ => ⟨by positivity, fun _ => rfl⟩
  | p + 1, i => by
    show Function.update (lower D n k0 rows m p).y p _ i < 2 ^ D ∧
      (n ≤ i → Function.update (lower D n k0 rows m p).y p _ i = 0)
    by_cases h_ip : i = p
    · subst h_ip
      rw [Function.update_self]
      unfold quotient
      constructor
      · split_ifs
        · exact Nat.mod_lt _ (by positivity)
        · positivity
      · intro h_n
        rw [if_neg (by omega)]
    · rw [Function.update_of_ne h_ip]
      exact lower_y_lt p i

/-- The triangles keep the number their lanes hold: what lanes below `p` keep and the carry into
lane `p` are the rows and the `y`s' rows of `m` at those lanes. -/
private theorem lower_value : ∀ p,
    value D p (lower D n k0 rows m p).lanes + (lower D n k0 rows m p).carry * 2 ^ (D * p) =
      ∑ q ∈ range p, (rows q + ∑ i ∈ range (q + 1), (lower D n k0 rows m p).y i * m (q - i)) *
        2 ^ (D * q)
  | 0 => by simp [value, lower]
  | p + 1 => by
    set s := lower D n k0 rows m p with h_s
    set l := laneSum rows m s p with h_l
    set y := quotient D n k0 l p with h_y
    have h_next : lower D n k0 rows m (p + 1) =
        ⟨Function.update s.y p y, (l + y * m 0) / 2 ^ D,
          Function.update s.lanes p ((l + y * m 0) % 2 ^ D)⟩ := rfl
    have h_ih := lower_value p
    rw [h_next]
    simp only
    have h_lanes : value D p (Function.update s.lanes p ((l + y * m 0) % 2 ^ D)) =
        value D p s.lanes :=
      value_congr fun j h_j => Function.update_of_ne (by omega) _ _
    have h_rows : ∀ q ∈ range p, (rows q + ∑ i ∈ range (q + 1),
        Function.update s.y p y i * m (q - i)) * 2 ^ (D * q) =
        (rows q + ∑ i ∈ range (q + 1), s.y i * m (q - i)) * 2 ^ (D * q) := by
      intro q h_q
      rw [Finset.mem_range] at h_q
      congr 2
      refine Finset.sum_congr rfl fun i h_i => ?_
      rw [Finset.mem_range] at h_i
      rw [Function.update_of_ne (by omega)]
    have h_top : ∑ i ∈ range (p + 1), Function.update s.y p y i * m (p - i) =
        ∑ i ∈ range p, s.y i * m (p - i) + y * m 0 := by
      rw [Finset.sum_range_succ, Function.update_self, Nat.sub_self]
      congr 1
      refine Finset.sum_congr rfl fun i h_i => ?_
      rw [Finset.mem_range] at h_i
      rw [Function.update_of_ne (by omega)]
    rw [value_succ, h_lanes, Function.update_self, Finset.sum_range_succ, Finset.sum_congr rfl h_rows,
      h_top, ← h_ih]
    have h_split := Nat.mod_add_div (l + y * m 0) (2 ^ D)
    rw [show D * (p + 1) = D * p + D by ring, pow_add]
    simp only [h_l, laneSum] at h_split ⊢
    linear_combination 2 ^ (D * p) * h_split

end Lower

/-! ## What the product computes -/

section Product

variable {D n k0 : Nat} {rows m : Nat → Nat}

/-- `y` makes the lane of a row below `n` a multiple of `2 ^ D`: `k0` is `-m_0⁻¹ mod 2 ^ D`. -/
private theorem step_exact {l m0 p : Nat} (h_k0 : (k0 * m0 + 1) % 2 ^ D = 0) (h_p : p < n) :
    (l + quotient D n k0 l p * m0) % 2 ^ D = 0 := by
  unfold quotient
  rw [if_pos h_p]
  have h_mod : l + l * k0 % 2 ^ D * m0 ≡ l * (k0 * m0 + 1) [MOD 2 ^ D] := by
    have h_y : l * k0 % 2 ^ D * m0 ≡ l * k0 * m0 [MOD 2 ^ D] :=
      Nat.ModEq.mul_right _ (Nat.mod_modEq _ _)
    calc l + l * k0 % 2 ^ D * m0 ≡ l + l * k0 * m0 [MOD 2 ^ D] := Nat.ModEq.add_left _ h_y
      _ = l * (k0 * m0 + 1) := by ring
  rw [h_mod, Nat.mul_mod, h_k0, mul_zero, Nat.zero_mod]

/-- The triangles leave the lanes of rows below `n` zero. -/
private theorem lower_lanes_zero (h_k0 : (k0 * m 0 + 1) % 2 ^ D = 0) {p q : Nat} (h_q : q < n)
    (h_qp : q < p) : (lower D n k0 rows m p).lanes q = 0 := by
  obtain ⟨r, rfl⟩ : ∃ r, p = q + 1 + r := ⟨p - (q + 1), by omega⟩
  rw [lower_lanes_stable (q + 1) q (by omega) r]
  show Function.update (lower D n k0 rows m q).lanes q _ q = 0
  rw [Function.update_self]
  exact step_exact h_k0 h_q

/-- The sum after the triangles holds, below lane `2 n`, the rows and the `y`s' rows of `m`. -/
private theorem upper_value (h_L : triangleLanes n < 2 * n) :
    ∑ p ∈ range (2 * n), upperLane rows m (lower D n k0 rows m (triangleLanes n))
        (triangleLanes n) p * 2 ^ (D * p) =
      ∑ p ∈ range (2 * n), (rows p + ∑ i ∈ range (p + 1),
        (lower D n k0 rows m (triangleLanes n)).y i * m (p - i)) * 2 ^ (D * p) := by
  set L := triangleLanes n
  set S := lower D n k0 rows m L with h_S
  obtain ⟨N, h_N⟩ : ∃ N, 2 * n = L + (N + 1) := ⟨2 * n - L - 1, by omega⟩
  have h_upper : ∀ x, ∑ i ∈ range (L + x + 1), S.y i * m (L + x - i) =
      ∑ i ∈ range L, S.y i * m (L + x - i) := by
    intro x
    symm
    refine Finset.sum_subset (Finset.range_mono (by omega)) fun i _ h_i => ?_
    rw [Finset.mem_range, not_lt] at h_i
    rw [h_S, lower_y_ge L i h_i, zero_mul]
  set F := fun p => upperLane rows m S L p * 2 ^ (D * p) with h_F
  set G := fun p => (rows p + ∑ i ∈ range (p + 1), S.y i * m (p - i)) * 2 ^ (D * p) with h_G
  show ∑ p ∈ range (2 * n), F p = ∑ p ∈ range (2 * n), G p
  have h_left : ∑ p ∈ range (2 * n), F p =
      ∑ p ∈ range L, F p + (∑ x ∈ range N, F (L + (x + 1)) + F (L + 0)) := by
    rw [h_N, Finset.sum_range_add F L (N + 1), Finset.sum_range_succ' (fun x => F (L + x)) N]
  have h_right : ∑ p ∈ range (2 * n), G p =
      ∑ p ∈ range L, G p + (∑ x ∈ range N, G (L + (x + 1)) + G (L + 0)) := by
    rw [h_N, Finset.sum_range_add G L (N + 1), Finset.sum_range_succ' (fun x => G (L + x)) N]
  have h_low : ∑ p ∈ range L, F p = value D L S.lanes :=
    Finset.sum_congr rfl fun p h_p => by
      rw [Finset.mem_range] at h_p
      simp only [h_F, upperLane, if_pos h_p]
  have h_mid : ∀ x ∈ range N, F (L + (x + 1)) = G (L + (x + 1)) := by
    intro x _
    simp only [h_F, h_G, upperLane, if_neg (show ¬L + (x + 1) < L by omega),
      if_neg (show L + (x + 1) ≠ L by omega), add_zero, h_upper (x + 1)]
  have h_first : F (L + 0) = G (L + 0) + S.carry * 2 ^ (D * L) := by
    show upperLane rows m S L (L + 0) * 2 ^ (D * (L + 0)) =
      (rows (L + 0) + ∑ i ∈ range (L + 0 + 1), S.y i * m (L + 0 - i)) * 2 ^ (D * (L + 0)) +
        S.carry * 2 ^ (D * L)
    rw [h_upper 0, upperLane, if_neg (by omega), if_pos (by omega)]
    simp only [add_zero]
    ring
  have h_lower : ∑ p ∈ range L, G p = value D L S.lanes + S.carry * 2 ^ (D * L) :=
    (lower_value L).symm
  rw [h_left, h_right, h_low, Finset.sum_congr rfl h_mid, h_first, h_lower]
  ring

/-- The sum's lanes `n` to `2 n - 1`, the lanes `product_core`'s last loop reads, hold
`(rows + y m) / 2 ^ (D n)`: the rows of `a`, as one number, plus `y` times `m`. -/
private theorem result_value (h_k0 : (k0 * m 0 + 1) % 2 ^ D = 0) (h_L : triangleLanes n < 2 * n)
    (h_m : ∀ j, n ≤ j → m j = 0) :
    (∑ q ∈ range n, resultLanes D n k0 rows m q * 2 ^ (D * q)) * 2 ^ (D * n) =
      ∑ p ∈ range (2 * n), rows p * 2 ^ (D * p) +
        value D n (lower D n k0 rows m (triangleLanes n)).y * value D n m := by
  set S := lower D n k0 rows m (triangleLanes n) with h_S
  have h_total := upper_value (D := D) (k0 := k0) (rows := rows) (m := m) h_L
  have h_ge : n ≤ triangleLanes n := by unfold triangleLanes; omega
  have h_zero : ∑ p ∈ range n, upperLane rows m S (triangleLanes n) p * 2 ^ (D * p) = 0 :=
    Finset.sum_eq_zero fun p h_p => by
      rw [Finset.mem_range] at h_p
      rw [upperLane, if_pos (by omega), h_S, lower_lanes_zero h_k0 h_p (by omega), zero_mul]
  rw [show 2 * n = n + n by ring, Finset.sum_range_add, h_zero, zero_add] at h_total
  have h_y : ∀ i, n ≤ i → S.y i = 0 := fun i h_i => (lower_y_lt _ i).2 h_i
  have h_conv := convolution_value (x := 2 ^ D) (N := 2 * n) h_y h_m le_rfl
  simp only [← pow_mul] at h_conv
  have h_split : ∑ p ∈ range (2 * n), (rows p + ∑ i ∈ range (p + 1), S.y i * m (p - i)) *
      2 ^ (D * p) = ∑ p ∈ range (2 * n), rows p * 2 ^ (D * p) +
        ∑ p ∈ range (2 * n), (∑ i ∈ range (p + 1), S.y i * m (p - i)) * 2 ^ (D * p) := by
    rw [← Finset.sum_add_distrib]
    exact Finset.sum_congr rfl fun p _ => by ring
  rw [show n + n = 2 * n by ring, h_split, h_conv] at h_total
  simp only [value]
  rw [Finset.sum_mul, ← h_total]
  refine Finset.sum_congr rfl fun q _ => ?_
  rw [resultLanes, show D * (n + q) = D * q + D * n by ring, pow_add]
  ring

/-- `product_core`'s last loop keeps the number its lanes hold: the digits it writes and the carry
out of the top lane. -/
private theorem carryPass_value (lanes : Nat → Nat) : ∀ q,
    value D q (carryPass D lanes q).1 + (carryPass D lanes q).2 * 2 ^ (D * q) =
      ∑ j ∈ range q, lanes j * 2 ^ (D * j)
  | 0 => by simp [value, carryPass]
  | q + 1 => by
    have h_ih := carryPass_value lanes q
    set prev := carryPass D lanes q
    show value D (q + 1) (Function.update prev.1 q ((lanes q + prev.2) % 2 ^ D)) +
      (lanes q + prev.2) / 2 ^ D * 2 ^ (D * (q + 1)) = _
    have h_same : value D q (Function.update prev.1 q ((lanes q + prev.2) % 2 ^ D)) =
        value D q prev.1 := value_congr fun j h_j => Function.update_of_ne (by omega) _ _
    have h_split := Nat.mod_add_div (lanes q + prev.2) (2 ^ D)
    rw [value_succ, h_same, Function.update_self, Finset.sum_range_succ, ← h_ih,
      show D * (q + 1) = D * q + D by ring, pow_add]
    linear_combination 2 ^ (D * q) * h_split

/-- Every digit the last loop writes is below `2 ^ D`. -/
private theorem carryPass_lt (lanes : Nat → Nat) : ∀ q j, (carryPass D lanes q).1 j < 2 ^ D
  | 0, _ => by simp [carryPass]
  | q + 1, j => by
    show Function.update (carryPass D lanes q).1 q _ j < 2 ^ D
    by_cases h_j : j = q
    · subst h_j
      rw [Function.update_self]
      exact Nat.mod_lt _ (by positivity)
    · rw [Function.update_of_ne h_j]
      exact carryPass_lt lanes q j

/-- The number in the product's digits, when the lanes it reads hold a number below `2 ^ (D n)`:
that number. -/
private theorem product_digits (h_lt : ∑ q ∈ range n, resultLanes D n k0 rows m q * 2 ^ (D * q) <
    2 ^ (D * n)) :
    value D n (lanesOf (product D n k0 rows m)) =
      ∑ q ∈ range n, resultLanes D n k0 rows m q * 2 ^ (D * q) := by
  set lanes := resultLanes D n k0 rows m
  have h_value := carryPass_value (D := D) lanes n
  have h_out : value D n (lanesOf (product D n k0 rows m)) = value D n (carryPass D lanes n).1 :=
    value_congr fun j h_j => lanesOf_ofFn _ h_j
  have h_digits : value D n (carryPass D lanes n).1 < 2 ^ (D * n) :=
    value_lt fun j _ => carryPass_lt lanes n j
  rw [h_out]
  have h_moved : (carryPass D lanes n).2 = 0 := by
    by_contra h_ne
    have : 2 ^ (D * n) ≤ (carryPass D lanes n).2 * 2 ^ (D * n) :=
      Nat.le_mul_of_pos_left _ (Nat.pos_of_ne_zero h_ne)
    omega
  rw [h_moved, zero_mul, add_zero] at h_value
  exact h_value

end Product

/-! ## The product's value -/

/-- `RSA_AVX2_DIGIT_COUNT`'s two spare bits: for every `m` below `2 ^ (64 k)`,
`4 m < 2 ^ (D n)`, which `product_lt` and `product_mul` take. -/
theorem digitCount_room {k m : Nat} (h_m : m < 2 ^ (64 * k)) :
    4 * m < 2 ^ (digitBits k * digitCount k) := by
  have h_bits : 64 * k + 2 ≤ digitBits k * digitCount k := by
    unfold digitBits digitCount
    split_ifs <;> omega
  calc 4 * m < 2 ^ 2 * 2 ^ (64 * k) := by omega
    _ = 2 ^ (64 * k + 2) := by rw [← pow_add, add_comm]
    _ ≤ 2 ^ (digitBits k * digitCount k) := Nat.pow_le_pow_right (by norm_num) h_bits

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

/-- A multiplication's rows over `2 n` lanes hold the product of the numbers in `a`'s and `b`'s
`n` digits. -/
private theorem multiplyRows_value (D n a b : Nat) :
    ∑ p ∈ range (2 * n), multiplyRows (lanesOf (toDigits D n a)) (lanesOf (toDigits D n b)) p *
        2 ^ (D * p) = b % 2 ^ (D * n) * (a % 2 ^ (D * n)) := by
  have h_conv := convolution_value (x := 2 ^ D) (N := 2 * n)
    (fun i h_i => toDigits_zero (D := D) (x := b) h_i)
    (fun j h_j => toDigits_zero (D := D) (x := a) h_j) le_rfl
  simp only [← pow_mul] at h_conv
  rw [← value_toDigits D n b, ← value_toDigits D n a, value, value, ← h_conv]
  rfl

/-- The multiplication's number, `2 ^ (D n)` times over, is `a b` and some multiple of `m` below
`2 ^ (D n)` of it, and is below `2 m`, for `a` and `b` below `2 m`, `4 m ≤ 2 ^ (D n)`, `k0` the
C's `-m⁻¹ mod 2 ^ D`, and the four digits a group takes at least. -/
private theorem multiply_value {D n k0 a b m : Nat} (h_k0 : (k0 * m + 1) % 2 ^ D = 0)
    (h_room : 4 * m ≤ 2 ^ (D * n)) (h_n : 4 ≤ n) (h_a : a < 2 * m) (h_b : b < 2 * m) :
    value D n (lanesOf (multiply D n k0 a b m)) < 2 * m ∧
      ∃ Q < 2 ^ (D * n), value D n (lanesOf (multiply D n k0 a b m)) * 2 ^ (D * n) =
        a * b + Q * m := by
  set W := 2 ^ (D * n) with h_W
  set rows := multiplyRows (lanesOf (toDigits D n a)) (lanesOf (toDigits D n b))
  set mDigits := lanesOf (toDigits D n m)
  have h_mod : ∀ x, x < 2 * m → x % W = x := fun x h_x => Nat.mod_eq_of_lt (by omega)
  have h_m_zero : ∀ j, n ≤ j → mDigits j = 0 := fun j h_j => toDigits_zero h_j
  have h_k0' : (k0 * mDigits 0 + 1) % 2 ^ D = 0 := by
    have h_digit : mDigits 0 = m % 2 ^ D := by
      simp only [mDigits, lanesOf_toDigits, if_pos (show 0 < n by omega), digit, mul_zero,
        pow_zero, Nat.div_one]
    rw [h_digit, Nat.add_mod, Nat.mul_mod, Nat.mod_mod, ← Nat.mul_mod, ← Nat.add_mod]
    exact h_k0
  have h_L : triangleLanes n < 2 * n := by unfold triangleLanes; omega
  have h_res := result_value (D := D) (k0 := k0) (rows := rows) h_k0' h_L h_m_zero
  rw [multiplyRows_value, h_mod a h_a, h_mod b h_b] at h_res
  have h_m_value : value D n mDigits = m := by
    rw [value_toDigits, h_mod m (by omega)]
  rw [h_m_value] at h_res
  set Y := value D n (lower D n k0 rows mDigits (triangleLanes n)).y
  have h_Y : Y < W := value_lt fun j _ => (lower_y_lt _ j).1
  set R := ∑ q ∈ range n, resultLanes D n k0 rows mDigits q * 2 ^ (D * q)
  have h_eq : R * W = a * b + Y * m := by rw [h_res]; ring
  have h_R : R < 2 * m := lt_two_mul h_eq h_Y h_a h_b h_room
  have h_value : value D n (lanesOf (multiply D n k0 a b m)) = R :=
    product_digits (show R < W by omega)
  rw [h_value]
  exact ⟨h_R, Y, h_Y, h_eq⟩

/-- The product is below `2 m`, for `a` and `b` below `2 m`, `4 m ≤ 2 ^ (D n)` and `k0` the C's
`-m⁻¹ mod 2 ^ D`. -/
theorem product_lt {D n k0 a b m : Nat} (h_k0 : (k0 * m + 1) % 2 ^ D = 0)
    (h_room : 4 * m ≤ 2 ^ (D * n)) (h_n : 4 ≤ n) (h_a : a < 2 * m) (h_b : b < 2 * m) :
    value D n (lanesOf (multiply D n k0 a b m)) < 2 * m :=
  (multiply_value h_k0 h_room h_n h_a h_b).1

/-- The product is `a b 2 ^ (-D n)` modulo `m`, under `product_lt`'s hypotheses. -/
theorem product_mul {D n k0 a b m : Nat} (h_k0 : (k0 * m + 1) % 2 ^ D = 0)
    (h_room : 4 * m ≤ 2 ^ (D * n)) (h_n : 4 ≤ n) (h_a : a < 2 * m) (h_b : b < 2 * m) :
    (value D n (lanesOf (multiply D n k0 a b m)) : ZMod m) * 2 ^ (D * n) = a * b := by
  obtain ⟨Q, _, h_eq⟩ := (multiply_value h_k0 h_room h_n h_a h_b).2
  have h_cast := congrArg (Nat.cast : Nat → ZMod m) h_eq
  push_cast at h_cast
  rw [ZMod.natCast_self, mul_zero, add_zero] at h_cast
  exact h_cast

/-! ## No lane wraps -/

section Fit

variable {D n k0 : Nat} {rows m : Nat → Nat}

/-- Every lane a triangle keeps is below `2 ^ D`. -/
private theorem lower_lanes_lt : ∀ p i, (lower D n k0 rows m p).lanes i < 2 ^ D
  | 0, _ => by positivity
  | p + 1, i => by
    show Function.update (lower D n k0 rows m p).lanes p _ i < 2 ^ D
    by_cases h_i : i = p
    · subst h_i
      rw [Function.update_self]
      exact Nat.mod_lt _ (by positivity)
    · rw [Function.update_of_ne h_i]
      exact lower_lanes_lt p i

/-- The `y`s' rows of `m` at a lane are at most `n` products of two digits: a `y` from row `n` up
is 0. -/
private theorem yRows_le (h_m : ∀ j, m j < 2 ^ D) (s p : Nat) (P : Nat) :
    ∑ i ∈ range P, (lower D n k0 rows m s).y i * m (p - i) ≤ n * (2 ^ D - 1) ^ 2 := by
  refine sum_le_count (fun i h_i => by rw [(lower_y_lt s i).2 h_i, zero_mul]) (fun i => ?_) P
  have h_y := (lower_y_lt (D := D) (n := n) (k0 := k0) (rows := rows) (m := m) s i).1
  have h_mi := h_m (p - i)
  rw [sq]
  exact Nat.mul_le_mul (by omega) (by omega)

/-- A triangle's `x` at lane `p` is at most `2 n` digit products and the carry into the lane. -/
private theorem triangleSum_le (h_rows : ∀ p, rows p ≤ n * (2 ^ D - 1) ^ 2)
    (h_m : ∀ j, m j < 2 ^ D) (p : Nat) :
    triangleSum D n k0 rows m p ≤ 2 * n * (2 ^ D - 1) ^ 2 + (lower D n k0 rows m p).carry := by
  have h_sum : triangleSum D n k0 rows m p = rows p + (lower D n k0 rows m p).carry +
      ∑ i ∈ range (p + 1), (lower D n k0 rows m (p + 1)).y i * m (p - i) := by
    show _ = _ + _ + ∑ i ∈ range (p + 1), Function.update (lower D n k0 rows m p).y p _ i * m (p - i)
    rw [Finset.sum_range_succ, Function.update_self, Nat.sub_self]
    have h_below : ∑ i ∈ range p, Function.update (lower D n k0 rows m p).y p
        (quotient D n k0 (laneSum rows m (lower D n k0 rows m p) p) p) i * m (p - i) =
        ∑ i ∈ range p, (lower D n k0 rows m p).y i * m (p - i) :=
      Finset.sum_congr rfl fun i h_i => by
        rw [Finset.mem_range] at h_i
        rw [Function.update_of_ne (by omega)]
    rw [h_below]
    simp only [triangleSum, laneSum]
    ring
  have h_y := yRows_le (D := D) (n := n) (k0 := k0) (rows := rows) h_m (p + 1) p (p + 1)
  have h_r := h_rows p
  rw [h_sum]
  nlinarith

/-- The carry out of every lane is below `2 ^ (64 - D)`, when `2 n` digit products and two carries
fit in 64 bits. -/
private theorem lower_carry_lt (h_D : D ≤ 32)
    (h_room : 2 * n * (2 ^ D - 1) ^ 2 + 2 * 2 ^ (64 - D) ≤ 2 ^ 64)
    (h_rows : ∀ p, rows p ≤ n * (2 ^ D - 1) ^ 2) (h_m : ∀ j, m j < 2 ^ D) :
    ∀ p, (lower D n k0 rows m p).carry < 2 ^ (64 - D)
  | 0 => by positivity
  | p + 1 => by
    have h_ih := lower_carry_lt h_D h_room h_rows h_m p
    have h_x := triangleSum_le (k0 := k0) h_rows h_m p
    show triangleSum D n k0 rows m p / 2 ^ D < 2 ^ (64 - D)
    rw [Nat.div_lt_iff_lt_mul (by positivity), ← pow_add, show 64 - D + D = 64 by omega]
    omega

/-- No lane the C sums passes `2 ^ 64`, for digit products and carries that fit: every triangle's
`x`, the most its lane holds, and every sum of the last loop, a lane `n` to `2 n - 1` and the
carry into it, the most those lanes hold. Each sum the C forms in a lane before the last term is
at most the lane's whole sum, for every term it adds is a natural number. -/
theorem lanes_fit (h_D : D ≤ 32)
    (h_room : 2 * n * (2 ^ D - 1) ^ 2 + 2 * 2 ^ (64 - D) ≤ 2 ^ 64)
    (h_rows : ∀ p, rows p ≤ n * (2 ^ D - 1) ^ 2) (h_m : ∀ j, m j < 2 ^ D) :
    (∀ p, triangleSum D n k0 rows m p < 2 ^ 64) ∧
      ∀ q, resultLanes D n k0 rows m q + (carryPass D (resultLanes D n k0 rows m) q).2 <
        2 ^ 64 := by
  have h_carry := lower_carry_lt (k0 := k0) h_D h_room h_rows h_m
  have h_small : 2 ^ D ≤ 2 ^ (64 - D) := Nat.pow_le_pow_right (by norm_num) (by omega)
  refine ⟨fun p => ?_, ?_⟩
  · have := triangleSum_le (k0 := k0) h_rows h_m p
    have := h_carry p
    omega
  · set S := lower D n k0 rows m (triangleLanes n)
    have h_two : 2 * n * (2 ^ D - 1) ^ 2 = n * (2 ^ D - 1) ^ 2 + n * (2 ^ D - 1) ^ 2 := by ring
    have h_pos : 0 < 2 ^ (64 - D) := by positivity
    have h_lane : ∀ q, resultLanes D n k0 rows m q < 2 * n * (2 ^ D - 1) ^ 2 + 2 ^ (64 - D) := by
      intro q
      unfold resultLanes upperLane
      split_ifs with h_low h_top
      · have := lower_lanes_lt (D := D) (n := n) (k0 := k0) (rows := rows) (m := m)
          (triangleLanes n) (n + q)
        omega
      · have := yRows_le (D := D) (n := n) (k0 := k0) (rows := rows) h_m (triangleLanes n) (n + q)
          (triangleLanes n)
        have := h_rows (n + q)
        have := h_carry (triangleLanes n)
        omega
      · have := yRows_le (D := D) (n := n) (k0 := k0) (rows := rows) h_m (triangleLanes n) (n + q)
          (triangleLanes n)
        have := h_rows (n + q)
        omega
    have h_moved : ∀ q, (carryPass D (resultLanes D n k0 rows m) q).2 < 2 ^ (64 - D) := by
      intro q
      induction q with
      | zero => show 0 < 2 ^ (64 - D); positivity
      | succ q ih =>
        show (resultLanes D n k0 rows m q + (carryPass D (resultLanes D n k0 rows m) q).2) /
          2 ^ D < 2 ^ (64 - D)
        rw [Nat.div_lt_iff_lt_mul (by positivity), ← pow_add, show 64 - D + D = 64 by omega]
        have := h_lane q
        omega
    intro q
    have := h_lane q
    have := h_moved q
    omega

end Fit

/-- A multiplication's rows of digits are at most `n` digit products at every lane. -/
theorem multiplyRows_le (D n a b p : Nat) :
    multiplyRows (lanesOf (toDigits D n a)) (lanesOf (toDigits D n b)) p ≤ n * (2 ^ D - 1) ^ 2 := by
  refine sum_le_count (fun i h_i => by rw [toDigits_zero h_i, zero_mul]) (fun i => ?_) (p + 1)
  have h_b := toDigits_lt D n b i
  have h_a := toDigits_lt D n a (p - i)
  rw [sq]
  exact Nat.mul_le_mul (by omega) (by omega)

/-- The C's digit counts leave room at its digit widths: 110 digits of 28 bits and 152 of 27, the
counts at RSA-3072 and RSA-4096, and fewer. -/
theorem room_28 {n : Nat} (h_n : n ≤ 110) :
    2 * n * (2 ^ 28 - 1) ^ 2 + 2 * 2 ^ (64 - 28) ≤ 2 ^ 64 :=
  calc 2 * n * (2 ^ 28 - 1) ^ 2 + 2 * 2 ^ (64 - 28)
      ≤ 2 * 110 * (2 ^ 28 - 1) ^ 2 + 2 * 2 ^ (64 - 28) :=
        Nat.add_le_add_right (Nat.mul_le_mul_right _ (Nat.mul_le_mul_left _ h_n)) _
    _ ≤ 2 ^ 64 := by norm_num

/-- The same at 27 bits, for 152 digits and fewer. -/
theorem room_27 {n : Nat} (h_n : n ≤ 152) :
    2 * n * (2 ^ 27 - 1) ^ 2 + 2 * 2 ^ (64 - 27) ≤ 2 ^ 64 :=
  calc 2 * n * (2 ^ 27 - 1) ^ 2 + 2 * 2 ^ (64 - 27)
      ≤ 2 * 152 * (2 ^ 27 - 1) ^ 2 + 2 * 2 ^ (64 - 27) :=
        Nat.add_le_add_right (Nat.mul_le_mul_right _ (Nat.mul_le_mul_left _ h_n)) _
    _ ≤ 2 ^ 64 := by norm_num

/-- No lane of the C's multiplication passes `2 ^ 64` at any word count it takes, up to 64: its
digit width and count leave room, and every digit of `a`, `b` and `m` is below `2 ^ D`. The
square's lanes hold the same sums (`square_eq_multiply`). -/
theorem multiply_fits {k k0 a b m : Nat} (h_k : k ≤ 64) :
    let D := digitBits k
    let n := digitCount k
    let rows := multiplyRows (lanesOf (toDigits D n a)) (lanesOf (toDigits D n b))
    (∀ p, triangleSum D n k0 rows (lanesOf (toDigits D n m)) p < 2 ^ 64) ∧
      ∀ q, resultLanes D n k0 rows (lanesOf (toDigits D n m)) q +
        (carryPass D (resultLanes D n k0 rows (lanesOf (toDigits D n m))) q).2 < 2 ^ 64 := by
  intro D n rows
  have h_room : 2 * n * (2 ^ D - 1) ^ 2 + 2 * 2 ^ (64 - D) ≤ 2 ^ 64 := by
    simp only [D, n, digitBits, digitCount]
    split_ifs with h_48
    · exact room_28 (by omega)
    · exact room_27 (by omega)
  have h_D : D ≤ 32 := by simp only [D, digitBits]; split_ifs <;> omega
  exact lanes_fit h_D h_room (fun p => multiplyRows_le D n a b p) (fun j => toDigits_lt D n m j)

/-! ## `rsa_avx2_public` -/

/-- `rsa_avx2_public`'s chain of products computes RSAVP1 (RFC 8017 5.2.2) for every base below
`2 ^ (64 k)`: `base ^ 65537 mod m`, for an `m` of `k` words, two or more, whose top bit is set,
`k0` the C's `-m⁻¹ mod 2 ^ D`, and `digitR2 = 2 ^ (2 D n) mod m`, the power of two
`rsa_vp1_cpu` passes. -/
theorem publicOp_eq {k k0 m base : Nat} (h_k0 : (k0 * m + 1) % 2 ^ digitBits k = 0)
    (h_top : 2 ^ (64 * k - 1) ≤ m) (h_m : m < 2 ^ (64 * k)) (h_k : 2 ≤ k)
    (h_base : base < 2 ^ (64 * k)) :
    publicOp k k0 m base (2 ^ (2 * digitBits k * digitCount k) % m) = base ^ 65537 % m := by
  set D := digitBits k with h_D
  set n := digitCount k with h_n_def
  have h_room : 4 * m ≤ 2 ^ (D * n) := (digitCount_room h_m).le
  have h_n : 4 ≤ n := by simp only [h_n_def, digitCount]; split_ifs <;> omega
  have h_D1 : 1 ≤ D := by simp only [h_D, digitBits]; split_ifs <;> omega
  have h_base_lt : base < 2 * m := by
    have h_double : 2 ^ (64 * k) = 2 * 2 ^ (64 * k - 1) := by
      rw [← pow_succ']
      congr 1
      omega
    omega
  have h_odd : m % 2 = 1 := by
    have h_two : (k0 * m + 1) % 2 = 0 := by
      have h_dvd : (2 : Nat) ∣ 2 ^ D := dvd_pow_self 2 (by omega)
      rw [← Nat.mod_mod_of_dvd _ h_dvd, h_k0]
    rcases Nat.mod_two_eq_zero_or_one m with h_even | h_one
    · have : k0 * m % 2 = 0 := by rw [Nat.mul_mod, h_even, mul_zero, Nat.zero_mod]
      omega
    · exact h_one
  have h_unit : IsUnit ((2 : ZMod m) ^ (D * n)) := by
    have h_two : IsUnit ((2 : ℕ) : ZMod m) :=
      (ZMod.isUnit_iff_coprime 2 m).mpr (Nat.coprime_two_left.mpr (Nat.odd_iff.mpr h_odd))
    exact (by exact_mod_cast h_two : IsUnit (2 : ZMod m)).pow _
  have h_product : ∀ x y, x < 2 * m → y < 2 * m →
      value D n (lanesOf (multiply D n k0 x y m)) < 2 * m ∧
        (value D n (lanesOf (multiply D n k0 x y m)) : ZMod m) * 2 ^ (D * n) = x * y :=
    fun x y h_x h_y =>
      ⟨product_lt h_k0 h_room h_n h_x h_y, product_mul h_k0 h_room h_n h_x h_y⟩
  have h_r2_lt : 2 ^ (2 * D * n) % m < 2 * m := by
    have := Nat.mod_lt (2 ^ (2 * D * n)) (show 0 < m by omega)
    omega
  have h_r2 : ((2 ^ (2 * D * n) % m : ℕ) : ZMod m) = 2 ^ (D * n) * 2 ^ (D * n) := by
    rw [ZMod.natCast_mod, ← pow_add, show D * n + D * n = 2 * D * n by ring]
    push_cast
    rfl
  set squareOf := fun p => value D n (lanesOf (square D n k0 p m)) with h_squareOf
  have h_square : ∀ p, squareOf p = value D n (lanesOf (multiply D n k0 p p m)) := by
    intro p
    simp only [h_squareOf, square_eq_multiply]
  obtain ⟨h_first_lt, h_first⟩ := h_product base _ h_base_lt h_r2_lt
  set first := value D n (lanesOf (multiply D n k0 base (2 ^ (2 * D * n) % m) m))
  have h_squares : ∀ j, squareOf^[j] first < 2 * m ∧
      (squareOf^[j] first : ZMod m) = base ^ 2 ^ j * 2 ^ (D * n) := by
    intro j
    induction j with
    | zero =>
      refine ⟨h_first_lt, h_unit.mul_right_cancel ?_⟩
      rw [Function.iterate_zero_apply, h_first, h_r2]
      ring
    | succ j ih =>
      obtain ⟨h_lt, h_eq⟩ := ih
      obtain ⟨h_next_lt, h_next⟩ := h_product _ _ h_lt h_lt
      rw [Function.iterate_succ_apply', h_square]
      refine ⟨h_next_lt, h_unit.mul_right_cancel ?_⟩
      rw [h_next, h_eq]
      ring
  obtain ⟨h_power_lt, h_power⟩ := h_squares 16
  obtain ⟨h_last_lt, h_last⟩ := h_product base _ h_base_lt h_power_lt
  set last := value D n (lanesOf (multiply D n k0 base (squareOf^[16] first) m))
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
/-- The digit widths and counts at RSA-2048, RSA-3072 and RSA-4096, the lanes their triangles
run, and `power_of_two_mod`'s steps for `2 ^ (2 D n)`; a square's rows against a
multiplication's on the digits of one number; and at RSA-2048, under `2 ^ 2048 - 1`,
`2 ^ 2047 + 1` and a third odd modulus with the top bit set, `power_of_two_mod` against
`2 ^ (2 D n) mod m` and `rsa_avx2_public` against `base ^ 65537 mod m` for the bases 2, `m - 1`
and `2 ^ 2048 - 1`. -/
def selftest (_ : Unit) : Bool :=
  let widths := [32, 48, 64].map digitBits == [28, 28, 27]
  let counts := [32, 48, 64].map digitCount == [74, 110, 152]
  let lanes := [74, 110, 152].map triangleLanes == [76, 112, 152]
  let steps := [32, 48, 64].map (fun k =>
    Spec.RsaIfma.powerOfTwoSteps k (2 * digitBits k * digitCount k)) == [33, 49, 65]
  let a := lanesOf (toDigits 28 9 (2 ^ 250 - 12345))
  let squares := (List.range 18).all fun p => squareRows a p == multiplyRows a a p
  let moduli := [2 ^ 2048 - 1, 2 ^ 2047 + 1,
    2 ^ 2047 + 0x9f3a5c7e1b2d4f60 * 2 ^ 1500 + 0x5ad1c3e2f4b60718 * 2 ^ 700 + 0x2b]
  let check := fun m =>
    let exponent := 2 * digitBits 32 * digitCount 32
    let digitR2 := Spec.RsaIfma.powerOfTwoMod m 32 exponent
    digitR2 == 2 ^ exponent % m && [2, m - 1, 2 ^ 2048 - 1].all fun base =>
      publicOp 32 (k0Of (digitBits 32) m) m base digitR2 == referencePublic m base
  widths && counts && lanes && steps && squares && moduli.all check

end Spec.RsaAvx2
