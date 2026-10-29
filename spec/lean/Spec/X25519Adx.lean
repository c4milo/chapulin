import Mathlib.Tactic

/-!
The x86-64 X25519 field, `x25519_adx.c`, modeled from the C, one element at a time.

The C keeps an element as four 64-bit words, a value below `2 ^ 256` that is not reduced modulo
`p = 2 ^ 255 - 19`. The model holds that value in a `Nat`. Because `2 ^ 256 = 2 p + 38`, every
operation adds what passes `2 ^ 256` back in at word 0 times 38. `fold` is that step as the C
writes it, `model_fold` and the line after it in `test/x25519_adx_model.h`: `r + 38 c` gives four
words and a carry out, and word 0 takes 38 times that carry. `mul`, `add`, `sub` and `mulA24` are
the four operations of `test/x25519_adx_model.h` that the assembly in `x25519_adx_asm.h` computes,
and `adx_sqr` is `mul` of `a` and `a`. `reduce` is `adx_reduce`, the final reduction.

`fold_lt` and `fold_carried` are the bounds of the fold. For `r` below `2 ^ 256` and
`38 (c + 1) ≤ 2 ^ 256` the result is below `2 ^ 256`. When `r + 38 c` passes `2 ^ 256` the result
is below `38 (c + 1)`, for any `r` below `2 ^ 256`. The second bound is what lets the C add `38` to word 0 with no carry out of
that word. `fold_mod` proves that the fold keeps the value modulo `p`. `mul_lt` and `mul_mod`,
`add_lt` and `add_mod`, `sub_lt` and `sub_mod`, and `mulA24_lt` and `mulA24_mod` prove that each
operation takes elements below `2 ^ 256` to an element below `2 ^ 256` with the right value
modulo `p`. `reduce_eq` proves that `adx_reduce` writes `a mod p`.

This module is written from the C, not from a standard, and CONTRACT.md says why.
-/

namespace Spec.X25519Adx

/-- The field prime, `2 ^ 255 - 19` (RFC 7748 §4.1). -/
def p : Nat := 2 ^ 255 - 19

/-- `r + 38 c`, then the carry out of `2 ^ 256` times 38 added to word 0: `model_fold` and the
line after it. -/
def fold (r c : Nat) : Nat :=
  let s := r + 38 * c
  s % 2 ^ 256 + 38 * (s / 2 ^ 256)

/-- `adx_mul`: the eight words of `a b`, the low four plus 38 times the high four, then `fold` of
that sum's four words and its carry (`model_product`, `model_reduce`). -/
def mul (a b : Nat) : Nat :=
  let t := a * b
  let s := t % 2 ^ 256 + 38 * (t / 2 ^ 256)
  fold (s % 2 ^ 256) (s / 2 ^ 256)

/-- `adx_add`: the four words of `a + b` and its carry, then `fold`. -/
def add (a b : Nat) : Nat :=
  let s := a + b
  fold (s % 2 ^ 256) (s / 2 ^ 256)

/-- `adx_mul_a24`: the four words of `121666 a` and its carry, then `fold`. -/
def mulA24 (a : Nat) : Nat :=
  let s := 121666 * a
  fold (s % 2 ^ 256) (s / 2 ^ 256)

/-- Four words minus four words, as `adx_sub`'s loops compute it: the difference modulo
`2 ^ 256` and the borrow out. -/
def subtract (a b : Nat) : Nat × Nat :=
  if a < b then (a + 2 ^ 256 - b, 1) else (a - b, 0)

/-- `adx_sub`: `a - b`, then 38 times its borrow taken from the result the same way, then 38 times
that second borrow taken from word 0. -/
def sub (a b : Nat) : Nat :=
  let d := subtract a b
  let e := subtract d.1 (38 * d.2)
  e.1 - 38 * e.2

/-- One of `adx_reduce`'s two passes: bit 255 cleared and added back at word 0 times 19, since
`2 ^ 255 = 19` modulo `p`. -/
def clearTop (a : Nat) : Nat :=
  a % 2 ^ 255 + 19 * (a / 2 ^ 255)

/-- `adx_reduce`: two passes of `clearTop`, then `a + 19 - 2 ^ 255` when `a + 19` sets bit 255,
which is when `a` is `p` or more, and `a` otherwise. -/
def reduce (a : Nat) : Nat :=
  let b := clearTop (clearTop a)
  if 2 ^ 255 ≤ b + 19 then b + 19 - 2 ^ 255 else b

/-! ## The fold -/

/-- The fold of `r` below `2 ^ 256` and a carry `c` with `38 (c + 1) ≤ 2 ^ 256` is below
`2 ^ 256`. -/
theorem fold_lt {r c : Nat} (h_r : r < 2 ^ 256) (h_room : 38 * (c + 1) ≤ 2 ^ 256) :
    fold r c < 2 ^ 256 := by
  simp only [fold]
  omega

/-- When `r + 38 c` passes `2 ^ 256`, the fold is below `38 (c + 1)`: the four words the carry
leaves are below `38 c`, so adding 38 to word 0 carries out of no word. -/
theorem fold_carried {r c : Nat} (h_r : r < 2 ^ 256)
    (h_carried : 2 ^ 256 ≤ r + 38 * c) : fold r c < 38 * (c + 1) := by
  simp only [fold]
  omega

/-- The fold keeps the value modulo `p`. -/
theorem fold_mod (r c : Nat) : fold r c % p = (r + 38 * c) % p := by
  simp only [fold, p]
  omega

/-! ## The operations -/

/-- The product of two elements below `2 ^ 256` is below `2 ^ 256`. -/
theorem mul_lt {a b : Nat} (h_a : a < 2 ^ 256) (h_b : b < 2 ^ 256) : mul a b < 2 ^ 256 := by
  have h_t : a * b < 2 ^ 512 := by
    calc a * b < 2 ^ 256 * 2 ^ 256 := Nat.mul_lt_mul'' h_a h_b
      _ = 2 ^ 512 := by rw [← pow_add]
  simp only [mul]
  generalize a * b = t at h_t ⊢
  apply fold_lt <;> omega

/-- The product is `a b` modulo `p`. -/
theorem mul_mod (a b : Nat) : mul a b % p = a * b % p := by
  simp only [mul]
  rw [fold_mod]
  generalize a * b = t
  simp only [p]
  omega

/-- The sum of two elements below `2 ^ 256` is below `2 ^ 256`. -/
theorem add_lt {a b : Nat} (h_a : a < 2 ^ 256) (h_b : b < 2 ^ 256) : add a b < 2 ^ 256 := by
  simp only [add]
  apply fold_lt <;> omega

/-- The sum is `a + b` modulo `p`. -/
theorem add_mod (a b : Nat) : add a b % p = (a + b) % p := by
  simp only [add]
  rw [fold_mod]
  simp only [p]
  omega

/-- The product by 121666 of an element below `2 ^ 256` is below `2 ^ 256`. -/
theorem mulA24_lt {a : Nat} (h_a : a < 2 ^ 256) : mulA24 a < 2 ^ 256 := by
  simp only [mulA24]
  apply fold_lt <;> omega

/-- The product by 121666 is `121666 a` modulo `p`. -/
theorem mulA24_mod (a : Nat) : mulA24 a % p = 121666 * a % p := by
  simp only [mulA24]
  rw [fold_mod]
  simp only [p]
  omega

/-- The difference of two elements below `2 ^ 256` is below `2 ^ 256`. -/
theorem sub_lt {a b : Nat} (h_a : a < 2 ^ 256) (h_b : b < 2 ^ 256) : sub a b < 2 ^ 256 := by
  simp only [sub, subtract]
  split_ifs <;> simp only [] <;> omega

/-- The difference plus `b` is `a` modulo `p`. -/
theorem sub_mod {a b : Nat} (h_a : a < 2 ^ 256) (h_b : b < 2 ^ 256) :
    (sub a b + b) % p = a % p := by
  simp only [sub, subtract, p]
  split_ifs <;> simp only [] <;> omega

/-! ## The final reduction -/

/-- A pass of `clearTop` on an element below `2 ^ 256` leaves it below `2 ^ 255 + 19`. -/
theorem clearTop_lt {a : Nat} (h_a : a < 2 ^ 256) : clearTop a < 2 ^ 255 + 19 := by
  simp only [clearTop]
  omega

/-- A pass of `clearTop` keeps the value modulo `p`. -/
theorem clearTop_mod (a : Nat) : clearTop a % p = a % p := by
  simp only [clearTop, p]
  omega

/-- `adx_reduce` writes `a mod p`, the one value below `p`, for every `a` below `2 ^ 256`. -/
theorem reduce_eq {a : Nat} (h_a : a < 2 ^ 256) : reduce a = a % p := by
  have h_lt : clearTop (clearTop a) < 2 ^ 255 + 19 := clearTop_lt (by
    have := clearTop_lt h_a
    omega)
  have h_mod : clearTop (clearTop a) % p = a % p := by rw [clearTop_mod, clearTop_mod]
  simp only [reduce]
  generalize clearTop (clearTop a) = b at h_lt h_mod ⊢
  simp only [p] at h_mod ⊢
  split_ifs <;> omega

/-! ## Self test -/

/-- The four operations and the reduction against `% p` on the values at the ends of the carries:
the model's own check. -/
def selftest (_ : Unit) : Bool :=
  let values := [0, 1, 37, 38, 2 ^ 255 - 20, 2 ^ 255 - 19, 2 ^ 255 + 18, 2 ^ 256 - 39,
    2 ^ 256 - 38, 2 ^ 256 - 1, 0x1d2c3b4a59687786a5b4c3d2e1f00f1e2d3c4b5a69788796a5b4c3d2e1f0abc]
  values.all fun a => values.all fun b =>
    mul a b < 2 ^ 256 && mul a b % p == a * b % p &&
    add a b < 2 ^ 256 && add a b % p == (a + b) % p &&
    sub a b < 2 ^ 256 && (sub a b + b) % p == a % p &&
    mulA24 a < 2 ^ 256 && mulA24 a % p == 121666 * a % p &&
    reduce a == a % p

end Spec.X25519Adx
