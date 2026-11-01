import Mathlib.Tactic

/-!
The x86-64 P-256 field's product and square, `p256_adx_field.c`, modeled from the C, one element
at a time.

`p256_adx_asm.h` computes the eight words of a product and then reduces them in four rounds and a
final subtraction, as `p256_wide_field.c`'s `reduce()` does. `test/p256_adx_model.h` writes the
same words in portable C, and this module models that C on a `Nat`. Round `k` reads `u`, word `k`
of the value, and adds `u 2 ^ 32` and `u p3` at word `k + 1` and `k + 3`, which is `u (p + 1)` at
word `k`, because `p + 1 = 2 ^ 64 (2 ^ 32 + p3 2 ^ 128)`. Word `k` itself stays, as the C leaves
`t[k]` and never reads it again. `reduce` reads the value above word 3, `t[4]` to `t[7]` and the
carry above them, and subtracts `p` once where that value is `p` or more.

`round_add` states what a round adds, and `round_mod` that it changes no word up to its own.
`reduce_low` proves that the low four words after the four rounds spell `low t`, the four values
of `u`, `reduce_value` that the value is then `T + (p + 1) L` for that `L`, and `reduce_shift`
that the value above the four words times `2 ^ 256` is `T + p L`. `reduce_lt` and `reduce_mod` prove
the result: for every `T` below `p 2 ^ 256`, which every product of two elements below `p` is,
`reduce T` is below `p` and is `T / 2 ^ 256` modulo `p`. `mulMont_lt` and `mulMont_mod` state it
for `a b`.

This module is written from the C, not from a standard, and CONTRACT.md says why.
-/

namespace Spec.P256Adx

/-- The field prime of SEC 2's secp256r1, `2 ^ 256 - 2 ^ 224 + 2 ^ 192 + 2 ^ 96 - 1`. -/
def p : Nat := 2 ^ 256 - 2 ^ 224 + 2 ^ 192 + 2 ^ 96 - 1

/-- `p`'s top word, `2 ^ 64 - 2 ^ 32 + 1`, the one factor a round multiplies by. -/
def p3 : Nat := 2 ^ 64 - 2 ^ 32 + 1

/-- Round `k` of `model_reduce`: `u`, word `k` of `t`, then `u << 32` and `u >> 32` at words
`k + 1` and `k + 2`, which is `u 2 ^ 32` at word `k + 1`, and the two words of `u p3` at words
`k + 3` and `k + 4`. The C's carry out of word `k + 4` is the part of the value above it. -/
def round (k t : Nat) : Nat :=
  let u := t / 2 ^ (64 * k) % 2 ^ 64
  t + (u * 2 ^ 32 + u * p3 * 2 ^ 128) * 2 ^ (64 * (k + 1))

/-- The four rounds, then the value above word 3 less `p` where it is `p` or more:
`model_reduce`, and the reduction both assembly statements end with. -/
def reduce (t : Nat) : Nat :=
  let w := round 3 (round 2 (round 1 (round 0 t)))
  let v := w / 2 ^ 256
  if p ≤ v then v - p else v

/-- `p256_adx_mul_mont`: the eight words of `a b`, then `reduce`. `p256_adx_sqr_mont` is
`mulMont a a`. -/
def mulMont (a b : Nat) : Nat := reduce (a * b)

/-! ## A round -/

/-- `p + 1` is `2 ^ 64` times the two addends' factor. -/
theorem p_succ : p + 1 = 2 ^ 64 * (2 ^ 32 + p3 * 2 ^ 128) := by
  norm_num [p, p3]

/-- A round adds `u (p + 1)` at word `k`. -/
theorem round_add (k t : Nat) :
    round k t = t + t / 2 ^ (64 * k) % 2 ^ 64 * (p + 1) * 2 ^ (64 * k) := by
  simp only [round, p_succ]
  rw [show 64 * (k + 1) = 64 * k + 64 by ring, pow_add]
  ring

/-! ## The four rounds -/

/-- A round changes no word up to its own: what it adds is a multiple of `2 ^ (64 k + 64)`. -/
theorem round_mod (k t : Nat) : round k t % 2 ^ (64 * k + 64) = t % 2 ^ (64 * k + 64) := by
  rw [round_add, p_succ]
  have h_shift : t / 2 ^ (64 * k) % 2 ^ 64 * (2 ^ 64 * (2 ^ 32 + p3 * 2 ^ 128)) * 2 ^ (64 * k) =
      t / 2 ^ (64 * k) % 2 ^ 64 * (2 ^ 32 + p3 * 2 ^ 128) * 2 ^ (64 * k + 64) := by
    rw [pow_add]
    ring
  rw [h_shift, Nat.add_mul_mod_self_right]

/-- The low `a + 64` bits of `x` are its low `a` bits and the word above them. -/
theorem mod_split (x a : Nat) : x % 2 ^ (a + 64) = x % 2 ^ a + x / 2 ^ a % 2 ^ 64 * 2 ^ a := by
  rw [pow_add, Nat.mod_mul]
  ring

/-- The number the low four words spell after the four rounds: the four values of `u`. -/
def low (t : Nat) : Nat :=
  t % 2 ^ 64 + round 0 t / 2 ^ 64 % 2 ^ 64 * 2 ^ 64 +
    round 1 (round 0 t) / 2 ^ 128 % 2 ^ 64 * 2 ^ 128 +
    round 2 (round 1 (round 0 t)) / 2 ^ 192 % 2 ^ 64 * 2 ^ 192

/-- The low four words after the four rounds are `low t`: each round's own word stays, and no
later round changes it. -/
theorem reduce_low (t : Nat) : round 3 (round 2 (round 1 (round 0 t))) % 2 ^ 256 = low t := by
  have h3 : round 3 (round 2 (round 1 (round 0 t))) % 2 ^ 256 =
      round 2 (round 1 (round 0 t)) % 2 ^ 256 := round_mod 3 _
  have s3 : round 2 (round 1 (round 0 t)) % 2 ^ 256 = round 2 (round 1 (round 0 t)) % 2 ^ 192 +
      round 2 (round 1 (round 0 t)) / 2 ^ 192 % 2 ^ 64 * 2 ^ 192 := mod_split _ 192
  have h2 : round 2 (round 1 (round 0 t)) % 2 ^ 192 = round 1 (round 0 t) % 2 ^ 192 :=
    round_mod 2 _
  have s2 : round 1 (round 0 t) % 2 ^ 192 = round 1 (round 0 t) % 2 ^ 128 +
      round 1 (round 0 t) / 2 ^ 128 % 2 ^ 64 * 2 ^ 128 := mod_split _ 128
  have h1 : round 1 (round 0 t) % 2 ^ 128 = round 0 t % 2 ^ 128 := round_mod 1 _
  have s1 : round 0 t % 2 ^ 128 = round 0 t % 2 ^ 64 + round 0 t / 2 ^ 64 % 2 ^ 64 * 2 ^ 64 :=
    mod_split _ 64
  have h0 : round 0 t % 2 ^ 64 = t % 2 ^ 64 := round_mod 0 _
  rw [low, h3, s3, h2, s2, h1, s1, h0]

/-- The value after the four rounds is `T + (p + 1) L`, where `L` is `low t`. -/
theorem reduce_value (t : Nat) :
    round 3 (round 2 (round 1 (round 0 t))) = t + (p + 1) * low t := by
  unfold low
  rw [show round 3 (round 2 (round 1 (round 0 t))) = round 2 (round 1 (round 0 t)) +
    round 2 (round 1 (round 0 t)) / 2 ^ 192 % 2 ^ 64 * (p + 1) * 2 ^ 192 from round_add 3 _]
  generalize round 2 (round 1 (round 0 t)) / 2 ^ 192 % 2 ^ 64 = u3
  rw [show round 2 (round 1 (round 0 t)) = round 1 (round 0 t) +
    round 1 (round 0 t) / 2 ^ 128 % 2 ^ 64 * (p + 1) * 2 ^ 128 from round_add 2 _]
  generalize round 1 (round 0 t) / 2 ^ 128 % 2 ^ 64 = u2
  rw [show round 1 (round 0 t) = round 0 t + round 0 t / 2 ^ 64 % 2 ^ 64 * (p + 1) * 2 ^ 64
    from round_add 1 _]
  generalize round 0 t / 2 ^ 64 % 2 ^ 64 = u1
  rw [show round 0 t = t + t % 2 ^ 64 * (p + 1) by rw [round_add]; simp]
  ring

/-- The value above the low four words, times `2 ^ 256`, is `T + p L`: the low words are `L`, so
removing them leaves `T + (p + 1) L - L`. -/
theorem reduce_shift (t : Nat) :
    round 3 (round 2 (round 1 (round 0 t))) / 2 ^ 256 * 2 ^ 256 = t + p * low t := by
  have h_div := Nat.div_add_mod (round 3 (round 2 (round 1 (round 0 t)))) (2 ^ 256)
  rw [reduce_low] at h_div
  generalize round 3 (round 2 (round 1 (round 0 t))) / 2 ^ 256 = v at h_div ⊢
  rw [reduce_value, Nat.add_mul, one_mul] at h_div
  generalize p * low t = m at h_div ⊢
  omega

/-- `low t` is below `2 ^ 256`: it is the remainder of a division by `2 ^ 256`. -/
theorem low_lt (t : Nat) : low t < 2 ^ 256 := by
  rw [← reduce_low]
  exact Nat.mod_lt _ (by norm_num)

/-! ## The result -/

/-- For `T` below `p 2 ^ 256`, the four rounds leave a value below `2 p` above word 3, so one
subtraction of `p` lands it below `p`. -/
theorem reduce_lt {t : Nat} (h_t : t < p * 2 ^ 256) : reduce t < p := by
  have h_shift := reduce_shift t
  have h_l := low_lt t
  have h_p : 0 < p := by norm_num [p]
  simp only [reduce]
  generalize round 3 (round 2 (round 1 (round 0 t))) / 2 ^ 256 = v at h_shift ⊢
  generalize low t = l at h_shift h_l
  generalize (2 : Nat) ^ 256 = r at h_shift h_l h_t
  have h_pl : p * l < p * r := Nat.mul_lt_mul_of_pos_left h_l h_p
  have h_vr : v * r < 2 * p * r := by
    rw [h_shift, Nat.mul_assoc, Nat.two_mul]
    omega
  have h_v : v < 2 * p := Nat.lt_of_mul_lt_mul_right h_vr
  split_ifs <;> omega

/-- `reduce T` times `2 ^ 256` is `T` modulo `p`: the result is `T / 2 ^ 256` in the field, the
Montgomery reduction. -/
theorem reduce_mod (t : Nat) : reduce t * 2 ^ 256 % p = t % p := by
  have h_shift := reduce_shift t
  simp only [reduce]
  generalize round 3 (round 2 (round 1 (round 0 t))) / 2 ^ 256 = v at h_shift ⊢
  split_ifs with h_le
  · have h_sum : (v - p) * 2 ^ 256 + p * 2 ^ 256 = t + p * low t := by
      rw [← h_shift, ← Nat.add_mul, Nat.sub_add_cancel h_le]
    have h_mod := congrArg (· % p) h_sum
    simp only [Nat.add_mul_mod_self_left] at h_mod
    exact h_mod
  · rw [h_shift, Nat.add_mul_mod_self_left]

/-- The product of two elements below `p` is below `p 2 ^ 256`, the domain of `reduce`. -/
theorem product_lt {a b : Nat} (h_a : a < p) (h_b : b < p) : a * b < p * 2 ^ 256 := by
  calc a * b < p * p := Nat.mul_lt_mul'' h_a h_b
    _ ≤ p * 2 ^ 256 := Nat.mul_le_mul_left _ (by norm_num [p])

/-- The Montgomery product of two elements below `p` is below `p`. -/
theorem mulMont_lt {a b : Nat} (h_a : a < p) (h_b : b < p) : mulMont a b < p :=
  reduce_lt (product_lt h_a h_b)

/-- The Montgomery product times `2 ^ 256` is `a b` modulo `p`. -/
theorem mulMont_mod (a b : Nat) : mulMont a b * 2 ^ 256 % p = a * b % p :=
  reduce_mod (a * b)

/-! ## Self test -/

/-- The product against `% p` on elements at the ends of the rounds: the model's own check. -/
def selftest (_ : Unit) : Bool :=
  let values := [0, 1, 2, p - 1, p - 2, 2 ^ 256 % p, (p - 1) / 2, 2 ^ 255, 2 ^ 224 - 1,
    0x1d2c3b4a59687786a5b4c3d2e1f00f1e2d3c4b5a69788796a5b4c3d2e1f0abc]
  values.all fun a => values.all fun b =>
    mulMont a b < p && mulMont a b * 2 ^ 256 % p == a * b % p

end Spec.P256Adx
