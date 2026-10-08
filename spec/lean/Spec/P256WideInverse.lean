import Mathlib.Data.Nat.Size
import Mathlib.Data.ZMod.Basic
import Mathlib.Tactic
import Spec.P256

/-!
The inverse of `p256_wide_inverse.c`: the optimized binary GCD of Pornin's "Optimized Binary
GCD for Modular Inversion" (https://eprint.iacr.org/2020/972), modeled from the C.

The binary GCD holds `a` and `b`, `b` odd, from `a = y` and `b = m`. A step halves an even
`a`, and replaces an odd `a` by `|a - b| / 2`, moving the old `a` into `b` when it was the
smaller. The C runs a round of `steps` steps on 64-bit approximations of `a` and `b`, which
`approximation` is, records them as four factors, which `stepFactors` is, and applies the
factors to `a` and `b` once: `round`. `inverse` is `rounds` rounds.

`round_shrinks` proves that a round shortens `a` and `b` by `steps` bits between them while
`a` is not zero, although the approximations can decide a step otherwise than `a` and `b` would.
`inverse_mul_self` proves that `rounds` rounds invert every `y` coprime to an odd modulus below
`2 ^ 256`, and `inverse_zero` that they send 0 to 0. `stepFactors_range` proves the bound on the
factors that lets the C keep two of them in one 64-bit word.

This module is written from the C, not from a standard, and CONTRACT.md says why.
-/

namespace Spec.P256WideInverse

/-- `STEPS` in `p256_wide_inverse.c`: the steps of a round. -/
def steps : Nat := 31

/-- `ROUNDS` in `p256_wide_inverse.c`: the rounds of an inverse. -/
def rounds : Nat := 17

/-- What a step does to `(a, b)`: `halve` halves `a`, `subtract` replaces `a` by `(a - b) / 2`,
and `swap` replaces `a` by `(b - a) / 2` and `b` by the old `a`. -/
inductive Move
  /-- `a` becomes `a / 2`. -/
  | halve
  /-- `a` becomes `(a - b) / 2`. -/
  | subtract
  /-- `a` becomes `(b - a) / 2`, and `b` becomes the old `a`. -/
  | swap
  deriving DecidableEq

/-- The move `p256_wide_inverse.c`'s `step` makes on `(x, y)`: halve an even `x`, and for an odd
`x` swap when `x < y` and subtract otherwise. -/
def move (x y : Int) : Move :=
  if x % 2 = 0 then .halve else if x < y then .swap else .subtract

/-- A move on a pair. -/
def apply : Move → Int × Int → Int × Int
  | .halve, (x, y) => (x / 2, y)
  | .subtract, (x, y) => ((x - y) / 2, y)
  | .swap, (x, y) => ((y - x) / 2, x)

/-- A move on the factors `(f0, g0, f1, g1)`: a halving doubles `f1` and `g1`, a subtraction
also subtracts them from `f0` and `g0`, and a swap exchanges the two pairs first. -/
def applyFactors : Move → Int × Int × Int × Int → Int × Int × Int × Int
  | .halve, (f0, g0, f1, g1) => (f0, g0, 2 * f1, 2 * g1)
  | .subtract, (f0, g0, f1, g1) => (f0 - f1, g0 - g1, 2 * f1, 2 * g1)
  | .swap, (f0, g0, f1, g1) => (f1 - f0, g1 - g0, 2 * f0, 2 * g0)

/-- One step of `step_factors`: the move chosen from the approximations, applied to them and to
the factors. -/
def factorStep (s : (Int × Int) × (Int × Int × Int × Int)) :
    (Int × Int) × (Int × Int × Int × Int) :=
  (apply (move s.1.1 s.1.2) s.1, applyFactors (move s.1.1 s.1.2) s.2)

/-- `step_factors`: the factors `(f0, g0, f1, g1)` of `steps` steps on the approximations `x`
and `y`, from `f0 = g1 = 1` and `f1 = g0 = 0`. -/
def stepFactors (x y : Int) : Int × Int × Int × Int :=
  (factorStep^[steps] ((x, y), (1, 0, 0, 1))).2

/-- The bit length `n` the approximations read: that of `a ||| b`, the larger of the two
lengths. -/
def width (a b : Nat) : Nat :=
  max a.size b.size

/-- `approximations`, one of the two: `x` when `n ≤ 64`, and otherwise its 31 low bits beside
its 33 bits from bit `n - 33` up. -/
def approximation (n x : Nat) : Nat :=
  if n ≤ 64 then x else x % 2 ^ 31 + 2 ^ 31 * (x / 2 ^ (n - 33))

/-- The state of `p256_wide_inverse` between rounds: `a` and `b`, and `u` and `v` modulo `m`. -/
structure State (m : Nat) where
  /-- `a`. -/
  a : Nat
  /-- `b`. -/
  b : Nat
  /-- `u`, with `a = u y` modulo `m`. -/
  u : ZMod m
  /-- `v`, with `b = v y` modulo `m`. -/
  v : ZMod m

/-- `-1` when `x` is below zero and `1` otherwise: the sign a round gives the combination it
takes the magnitude of. -/
def signOf (x : Int) : Int :=
  if x < 0 then -1 else 1

/-- One round: the factors of the steps on the approximations, applied to `a` and `b` with the
division by `2 ^ steps` (`combine_exact`), and to `u` and `v` modulo `m`, divided by
`2 ^ steps` there and given the sign `a` and `b` took (`combine_modular`). -/
def round (m : Nat) (s : State m) : State m :=
  let n := width s.a s.b
  let r := stepFactors (approximation n s.a) (approximation n s.b)
  let A : Int := (s.a * r.1 + s.b * r.2.1) / 2 ^ steps
  let B : Int := (s.a * r.2.2.1 + s.b * r.2.2.2) / 2 ^ steps
  let half : ZMod m := ((2 : ZMod m) ^ steps)⁻¹
  { a := A.natAbs
    b := B.natAbs
    u := (signOf A : ZMod m) * (s.u * r.1 + s.v * r.2.1) * half
    v := (signOf B : ZMod m) * (s.u * r.2.2.1 + s.v * r.2.2.2) * half }

/-- `p256_wide_inverse`: `rounds` rounds from `a = y`, `b = m`, `u = 1` and `v = 0`, and `v`. -/
def inverse (m y : Nat) : ZMod m :=
  ((round m)^[rounds] ⟨y, m, 1, 0⟩).v


/-! ## Bit lengths -/

/-- The bit length of `|x|`. -/
def len (x : Int) : Nat :=
  x.natAbs.size

private theorem len_le_iff {x : Int} {k : Nat} : len x ≤ k ↔ |x| < 2 ^ k := by
  unfold len
  rw [Nat.size_le, Int.abs_eq_natAbs]
  exact_mod_cast Iff.rfl

private theorem lt_len_iff {x : Int} {k : Nat} : k < len x ↔ 2 ^ k ≤ |x| := by
  rw [← not_le, len_le_iff, not_lt]

private theorem len_zero : len 0 = 0 := by
  simp [len]

private theorem len_pos {x : Int} (h_x : x ≠ 0) : 0 < len x := by
  rw [lt_len_iff]
  simpa using Int.one_le_abs h_x

/-- Halving a value below `2 ^ k` leaves it below `2 ^ (k - 1)`. -/
private theorem half_lt {z : Int} {k : Nat} (h_lt : z < 2 ^ k) (h_k : 1 ≤ k) :
    z / 2 < 2 ^ (k - 1) := by
  have h_pow : (2 : Int) ^ k = 2 ^ (k - 1) * 2 := by
    rw [← pow_succ]
    congr 1
    omega
  exact Int.ediv_lt_of_lt_mul (by norm_num) (h_pow ▸ h_lt)

/-! ## The classic step

A step whose move is chosen from the values it applies to is a step of the classic binary
GCD. It takes at least one bit off the two values between them while the first is not zero. -/

private theorem classic_step {x y : Int} (h_x : 0 < x) (h_y : 0 < y) (h_odd : y % 2 = 1) :
    0 ≤ (apply (move x y) (x, y)).1 ∧ 0 < (apply (move x y) (x, y)).2 ∧
      (apply (move x y) (x, y)).2 % 2 = 1 ∧
      len (apply (move x y) (x, y)).1 + len (apply (move x y) (x, y)).2 + 1 ≤ len x + len y := by
  have h_x_len : |x| < 2 ^ len x := len_le_iff.mp le_rfl
  have h_y_len : |y| < 2 ^ len y := len_le_iff.mp le_rfl
  rw [abs_of_pos h_x] at h_x_len
  rw [abs_of_pos h_y] at h_y_len
  have h_x_one : 1 ≤ len x := len_pos h_x.ne'
  have h_y_one : 1 ≤ len y := len_pos h_y.ne'
  unfold move
  split_ifs with h_even h_lt
  · simp only [apply]
    refine ⟨by omega, h_y, h_odd, ?_⟩
    have h_half : len (x / 2) ≤ len x - 1 := by
      rw [len_le_iff, abs_of_nonneg (by omega)]
      exact half_lt h_x_len h_x_one
    omega
  · simp only [apply]
    refine ⟨by omega, h_x, by omega, ?_⟩
    have h_half : len ((y - x) / 2) ≤ len y - 1 := by
      rw [len_le_iff, abs_of_nonneg (by omega)]
      exact half_lt (by omega) h_y_one
    omega
  · simp only [apply]
    refine ⟨by omega, h_y, h_odd, ?_⟩
    have h_half : len ((x - y) / 2) ≤ len x - 1 := by
      rw [len_le_iff, abs_of_nonneg (by omega)]
      exact half_lt (by omega) h_x_one
    omega

/-! ## The paired run

A round's steps choose each move from the approximations, and the round applies the same moves
to `a` and `b` through the factors. `pairStep` follows both at once: the approximations in
`s.1`, and the exact values the moves make of `a` and `b` in `s.2`. -/

/-- One step of the paired run: the move chosen from the approximations, applied to them and
to the exact values. -/
def pairStep (s : (Int × Int) × (Int × Int)) : (Int × Int) × (Int × Int) :=
  (apply (move s.1.1 s.1.2) s.1, apply (move s.1.1 s.1.2) s.2)

/-- What every step keeps, `t` steps into a round: the approximations are at or above zero,
both second values are odd, and each exact value agrees with its approximation in its low
`31 - t` bits. So a step's halving and its differences divide exact values evenly. -/
def Agree (t : Nat) (s : (Int × Int) × (Int × Int)) : Prop :=
  0 ≤ s.1.1 ∧ 0 ≤ s.1.2 ∧ s.1.2 % 2 = 1 ∧ s.2.2 % 2 = 1 ∧
    (2 : Int) ^ (31 - t) ∣ s.2.1 - s.1.1 ∧ (2 : Int) ^ (31 - t) ∣ s.2.2 - s.1.2

private theorem dvd_half {a b : Int} {k : Nat} (h_dvd : (2 : Int) ^ (k + 1) ∣ a - b)
    (h_a : 2 ∣ a) (h_b : 2 ∣ b) : (2 : Int) ^ k ∣ a / 2 - b / 2 := by
  obtain ⟨c, h_c⟩ := h_dvd
  have h_half : a / 2 - b / 2 = (a - b) / 2 := by omega
  refine ⟨c, ?_⟩
  rw [h_half, h_c, pow_succ, mul_comm ((2 : Int) ^ k) 2, mul_assoc]
  exact Int.mul_ediv_cancel_left _ (by norm_num)

private theorem dvd_of_dvd_succ {z : Int} {k : Nat} (h_dvd : (2 : Int) ^ (k + 1) ∣ z) :
    (2 : Int) ^ k ∣ z :=
  dvd_trans (pow_dvd_pow 2 (Nat.le_succ k)) h_dvd

private theorem two_dvd_of_dvd_succ {z : Int} {k : Nat} (h_dvd : (2 : Int) ^ (k + 1) ∣ z) :
    2 ∣ z :=
  dvd_trans (dvd_pow_self 2 (Nat.succ_ne_zero k)) h_dvd

/-- A step keeps `Agree`, one bit fewer. -/
private theorem agree_step {t : Nat} {s : (Int × Int) × (Int × Int)} (h_t : t < 31) (h_agree : Agree t s) :
    Agree (t + 1) (pairStep s) := by
  obtain ⟨⟨x, y⟩, ⟨X, Y⟩⟩ := s
  obtain ⟨h_x, h_y, h_y_odd, h_Y_odd, h_X_dvd, h_Y_dvd⟩ := h_agree
  have h_k : 31 - t = (31 - (t + 1)) + 1 := by omega
  rw [h_k] at h_X_dvd h_Y_dvd
  have h_X_x := two_dvd_of_dvd_succ h_X_dvd
  have h_Y_y := two_dvd_of_dvd_succ h_Y_dvd
  simp only at h_x h_y h_y_odd h_Y_odd h_X_x h_Y_y
  simp only [pairStep, move]
  split_ifs with h_even h_lt
  · simp only [apply, Agree]
    refine ⟨by omega, h_y, h_y_odd, h_Y_odd,
      dvd_half h_X_dvd (by omega) (by omega), dvd_of_dvd_succ h_Y_dvd⟩
  · simp only [apply, Agree]
    have h_sub : (2 : Int) ^ (31 - (t + 1) + 1) ∣ (Y - X) - (y - x) := by
      have h := dvd_sub h_Y_dvd h_X_dvd
      rwa [show Y - y - (X - x) = (Y - X) - (y - x) by ring] at h
    refine ⟨by omega, by omega, by omega, by omega,
      dvd_half h_sub (by omega) (by omega), dvd_of_dvd_succ h_X_dvd⟩
  · simp only [apply, Agree]
    have h_sub : (2 : Int) ^ (31 - (t + 1) + 1) ∣ (X - Y) - (x - y) := by
      have h := dvd_sub h_X_dvd h_Y_dvd
      rwa [show X - x - (Y - y) = (X - Y) - (x - y) by ring] at h
    refine ⟨by omega, h_y, h_y_odd, h_Y_odd,
      dvd_half h_sub (by omega) (by omega), dvd_of_dvd_succ h_Y_dvd⟩

/-- Before the last step, an exact value is even exactly when its approximation is. -/
private theorem agree_parity {t : Nat} {s : (Int × Int) × (Int × Int)} (h_t : t < 31)
    (h_agree : Agree t s) : s.2.1 % 2 = s.1.1 % 2 := by
  obtain ⟨-, -, -, -, h_X_dvd, -⟩ := h_agree
  have h_k : 31 - t = (31 - (t + 1)) + 1 := by omega
  rw [h_k] at h_X_dvd
  have := two_dvd_of_dvd_succ h_X_dvd
  omega

/-- What a step keeps of how far the exact values are from `H` times their approximations:
each stays below `E` in size. -/
private theorem error_step {t : Nat} {s : (Int × Int) × (Int × Int)} {H E : Int} (h_t : t < 31)
    (h_agree : Agree t s) (h_error_x : |s.2.1 - H * s.1.1| < E)
    (h_error_y : |s.2.2 - H * s.1.2| < E) :
    |(pairStep s).2.1 - H * (pairStep s).1.1| < E ∧
      |(pairStep s).2.2 - H * (pairStep s).1.2| < E := by
  obtain ⟨⟨x, y⟩, ⟨X, Y⟩⟩ := s
  have h_parity := agree_parity h_t h_agree
  obtain ⟨h_x, h_y, h_y_odd, h_Y_odd, -, -⟩ := h_agree
  simp only at h_x h_y h_y_odd h_Y_odd h_parity h_error_x h_error_y
  simp only [pairStep, move]
  split_ifs with h_even h_lt
  · simp only [apply]
    refine ⟨?_, h_error_y⟩
    have h_eq : 2 * (X / 2 - H * (x / 2)) = X - H * x := by
      have h_X : 2 * (X / 2) = X := by omega
      have h_x2 : 2 * (x / 2) = x := by omega
      calc 2 * (X / 2 - H * (x / 2)) = 2 * (X / 2) - H * (2 * (x / 2)) := by ring
        _ = X - H * x := by rw [h_X, h_x2]
    have h_abs : 2 * |X / 2 - H * (x / 2)| = |X - H * x| := by
      rw [← h_eq, abs_mul, abs_two]
    have h_E : 0 < E := lt_of_le_of_lt (abs_nonneg _) h_error_x
    linarith [abs_nonneg (X / 2 - H * (x / 2))]
  · simp only [apply]
    refine ⟨?_, h_error_x⟩
    have h_eq : 2 * ((Y - X) / 2 - H * ((y - x) / 2)) = (Y - H * y) - (X - H * x) := by
      have h_X : 2 * ((Y - X) / 2) = Y - X := by omega
      have h_x2 : 2 * ((y - x) / 2) = y - x := by omega
      calc 2 * ((Y - X) / 2 - H * ((y - x) / 2))
          = 2 * ((Y - X) / 2) - H * (2 * ((y - x) / 2)) := by ring
        _ = (Y - H * y) - (X - H * x) := by rw [h_X, h_x2]; ring
    have h_abs : 2 * |(Y - X) / 2 - H * ((y - x) / 2)| ≤ |Y - H * y| + |X - H * x| := by
      calc 2 * |(Y - X) / 2 - H * ((y - x) / 2)|
          = |2 * ((Y - X) / 2 - H * ((y - x) / 2))| := by rw [abs_mul, abs_two]
        _ ≤ |Y - H * y| + |X - H * x| := by rw [h_eq]; exact abs_sub _ _
    linarith
  · simp only [apply]
    refine ⟨?_, h_error_y⟩
    have h_eq : 2 * ((X - Y) / 2 - H * ((x - y) / 2)) = (X - H * x) - (Y - H * y) := by
      have h_X : 2 * ((X - Y) / 2) = X - Y := by omega
      have h_x2 : 2 * ((x - y) / 2) = x - y := by omega
      calc 2 * ((X - Y) / 2 - H * ((x - y) / 2))
          = 2 * ((X - Y) / 2) - H * (2 * ((x - y) / 2)) := by ring
        _ = (X - H * x) - (Y - H * y) := by rw [h_X, h_x2]; ring
    have h_abs : 2 * |(X - Y) / 2 - H * ((x - y) / 2)| ≤ |X - H * x| + |Y - H * y| := by
      calc 2 * |(X - Y) / 2 - H * ((x - y) / 2)|
          = |2 * ((X - Y) / 2 - H * ((x - y) / 2))| := by rw [abs_mul, abs_two]
        _ ≤ |X - H * x| + |Y - H * y| := by rw [h_eq]; exact abs_sub _ _
    linarith

/-- A step leaves neither exact value larger in size than the larger of the two before it. -/
private theorem max_step {t : Nat} {s : (Int × Int) × (Int × Int)} {M : Int} (h_t : t < 31)
    (h_agree : Agree t s) (h_X : |s.2.1| ≤ M) (h_Y : |s.2.2| ≤ M) :
    |(pairStep s).2.1| ≤ M ∧ |(pairStep s).2.2| ≤ M := by
  obtain ⟨⟨x, y⟩, ⟨X, Y⟩⟩ := s
  have h_parity := agree_parity h_t h_agree
  obtain ⟨-, -, -, h_Y_odd, -, -⟩ := h_agree
  simp only at h_parity h_Y_odd h_X h_Y
  simp only [pairStep, move]
  split_ifs with h_even h_lt
  · simp only [apply]
    refine ⟨?_, h_Y⟩
    have h_two : 2 * (X / 2) = X := by omega
    have h_abs : 2 * |X / 2| = |X| := by
      calc 2 * |X / 2| = |2 * (X / 2)| := by rw [abs_mul, abs_two]
        _ = |X| := by rw [h_two]
    linarith [abs_nonneg (X / 2)]
  · simp only [apply]
    refine ⟨?_, h_X⟩
    have h_two : 2 * ((Y - X) / 2) = Y - X := by omega
    have h_abs : 2 * |(Y - X) / 2| ≤ |Y| + |X| := by
      calc 2 * |(Y - X) / 2| = |2 * ((Y - X) / 2)| := by rw [abs_mul, abs_two]
        _ ≤ |Y| + |X| := by rw [h_two]; exact abs_sub _ _
    linarith
  · simp only [apply]
    refine ⟨?_, h_Y⟩
    have h_two : 2 * ((X - Y) / 2) = X - Y := by omega
    have h_abs : 2 * |(X - Y) / 2| ≤ |X| + |Y| := by
      calc 2 * |(X - Y) / 2| = |2 * ((X - Y) / 2)| := by rw [abs_mul, abs_two]
        _ ≤ |X| + |Y| := by rw [h_two]; exact abs_sub _ _
    linarith

/-! ## The approximations

Above 64 bits, an approximation keeps the 31 low bits of its value exactly and its bits from
bit `n - 33` up, so `2 ^ (n - 64)` times it is within `2 ^ (n - 33)` of the value. -/

private theorem approximation_of_le {n x : Nat} (h_n : n ≤ 64) : approximation n x = x := by
  simp [approximation, h_n]

private theorem approximation_mod {n x : Nat} : approximation n x % 2 ^ 31 = x % 2 ^ 31 := by
  unfold approximation
  split_ifs
  · rfl
  · rw [Nat.add_mul_mod_self_left, Nat.mod_mod]

private theorem split_error (x D K : Nat) (h_D : 0 < D) (h_K : 0 < K) :
    |(x : Int) - D * ((x % K + K * (x / (D * K)) : Nat) : Int)| < D * K := by
  have h_x : (x : Int) = D * K * ((x / (D * K) : Nat) : Int) + ((x % (D * K) : Nat) : Int) := by
    exact_mod_cast (Nat.div_add_mod x (D * K)).symm
  have h_r : ((x % (D * K) : Nat) : Int) < D * K := by
    exact_mod_cast Nat.mod_lt _ (Nat.mul_pos h_D h_K)
  have h_l : ((x % K : Nat) : Int) < K := by exact_mod_cast Nat.mod_lt _ h_K
  have h_Dl : (D : Int) * ((x % K : Nat) : Int) < D * K :=
    mul_lt_mul_of_pos_left h_l (by exact_mod_cast h_D)
  have h_r_nonneg : (0 : Int) ≤ ((x % (D * K) : Nat) : Int) := Int.natCast_nonneg _
  have h_Dl_nonneg : (0 : Int) ≤ D * ((x % K : Nat) : Int) := by positivity
  have h_key : (x : Int) - D * ((x % K + K * (x / (D * K)) : Nat) : Int) =
      ((x % (D * K) : Nat) : Int) - D * ((x % K : Nat) : Int) := by
    rw [h_x]
    push_cast
    ring
  rw [h_key, abs_lt]
  constructor <;> linarith

/-- An approximation of a value is within `2 ^ (n - 33)` of it, scaled by `2 ^ (n - 64)`. -/
theorem approximation_error {n x : Nat} (h_n : 64 < n) :
    |(x : Int) - 2 ^ (n - 64) * (approximation n x : Int)| < 2 ^ (n - 33) := by
  have h_split : (2 : Nat) ^ (n - 33) = 2 ^ (n - 64) * 2 ^ 31 := by
    rw [← pow_add]
    congr 1
    omega
  have h_approx : approximation n x = x % 2 ^ 31 + 2 ^ 31 * (x / (2 ^ (n - 64) * 2 ^ 31)) := by
    simp [approximation, show ¬n ≤ 64 by omega, h_split]
  have h := split_error x (2 ^ (n - 64)) (2 ^ 31) (by positivity) (by positivity)
  rw [h_approx]
  rw [show (2 : Int) ^ (n - 33) = ((2 ^ (n - 64) * 2 ^ 31 : Nat) : Int) by
    rw [← h_split]; push_cast; ring]
  push_cast at h ⊢
  exact h

/-- The approximation of a value of `n` bits, `n` above 64, is at least `2 ^ 63`. -/
private theorem approximation_large {n x : Nat} (h_n : 64 < n) (h_size : x.size = n) :
    2 ^ 63 ≤ approximation n x := by
  have h_x : 2 ^ (n - 1) ≤ x := by
    have := Nat.lt_size.mp (show n - 1 < x.size by omega)
    exact this
  have h_top : 2 ^ 32 ≤ x / 2 ^ (n - 33) := by
    rw [Nat.le_div_iff_mul_le (by positivity), ← pow_add]
    calc 2 ^ (32 + (n - 33)) = 2 ^ (n - 1) := by congr 1; omega
      _ ≤ x := h_x
  simp only [approximation, show ¬n ≤ 64 by omega, if_false]
  calc 2 ^ 63 = 2 ^ 31 * 2 ^ 32 := by norm_num
    _ ≤ 2 ^ 31 * (x / 2 ^ (n - 33)) := Nat.mul_le_mul_left _ h_top
    _ ≤ x % 2 ^ 31 + 2 ^ 31 * (x / 2 ^ (n - 33)) := Nat.le_add_left _ _

/-- The approximation of a value of `n - 32` bits or fewer, `n` above 64, is below `2 ^ 32`. -/
private theorem approximation_small {n x : Nat} (h_n : 64 < n) (h_size : x.size ≤ n - 32) :
    approximation n x < 2 ^ 32 := by
  have h_x : x < 2 ^ (n - 32) := Nat.size_le.mp h_size
  have h_top : x / 2 ^ (n - 33) ≤ 1 := by
    rw [Nat.div_le_iff_le_mul_add_pred (by positivity)]
    have : (2 : Nat) ^ (n - 32) = 2 ^ (n - 33) * 2 := by rw [← pow_succ]; congr 1; omega
    omega
  have h_low : x % 2 ^ 31 < 2 ^ 31 := Nat.mod_lt _ (by positivity)
  simp only [approximation, show ¬n ≤ 64 by omega, if_false]
  calc x % 2 ^ 31 + 2 ^ 31 * (x / 2 ^ (n - 33)) < 2 ^ 31 + 2 ^ 31 * 1 := by
        have := Nat.mul_le_mul_left (2 ^ 31) h_top
        omega
    _ = 2 ^ 32 := by norm_num

/-! ## Rounds whose moves are the classic ones -/

/-- When the approximations choose every move as the exact values would, a round is 31 steps of
the classic binary GCD, which take 31 bits off the exact values between them unless the first
reaches zero. -/
private theorem shrinks_of_agree {a b : Int} {p : Int × Int} (h_a : 0 ≤ a) (h_b : 0 < b)
    (h_odd : b % 2 = 1)
    (h_moves : ∀ t < 31, move (pairStep^[t] (p, (a, b))).1.1 (pairStep^[t] (p, (a, b))).1.2 =
      move (pairStep^[t] (p, (a, b))).2.1 (pairStep^[t] (p, (a, b))).2.2) :
    (pairStep^[31] (p, (a, b))).2.1 = 0 ∨
      len (pairStep^[31] (p, (a, b))).2.1 + len (pairStep^[31] (p, (a, b))).2.2 + 31 ≤
        len a + len b := by
  have h_inv : ∀ t ≤ 31, 0 ≤ (pairStep^[t] (p, (a, b))).2.1 ∧
      0 < (pairStep^[t] (p, (a, b))).2.2 ∧ (pairStep^[t] (p, (a, b))).2.2 % 2 = 1 ∧
      ((pairStep^[t] (p, (a, b))).2.1 = 0 ∨
        len (pairStep^[t] (p, (a, b))).2.1 + len (pairStep^[t] (p, (a, b))).2.2 + t ≤
          len a + len b) := by
    intro t h_t
    induction t with
    | zero => exact ⟨h_a, h_b, h_odd, Or.inr (by simp)⟩
    | succ t ih =>
      have h_move := h_moves t (by omega)
      have h_prev := ih (by omega)
      rw [Function.iterate_succ_apply']
      generalize pairStep^[t] (p, (a, b)) = s at h_move h_prev ⊢
      obtain ⟨⟨x, y⟩, ⟨X, Y⟩⟩ := s
      obtain ⟨h_X, h_Y, h_Y_odd, h_len⟩ := h_prev
      simp only at h_move h_X h_Y h_Y_odd h_len ⊢
      simp only [pairStep, h_move]
      by_cases h_zero : X = 0
      · subst h_zero
        simp only [move, Int.zero_emod, if_true, apply]
        exact ⟨le_refl _, h_Y, h_Y_odd, Or.inl (by norm_num)⟩
      · have h_pos : 0 < X := lt_of_le_of_ne h_X (Ne.symm h_zero)
        obtain ⟨h_1, h_2, h_3, h_4⟩ := classic_step h_pos h_Y h_Y_odd
        refine ⟨h_1, h_2, h_3, Or.inr ?_⟩
        rcases h_len with h | h
        · exact absurd h h_zero
        · omega
  obtain ⟨-, -, -, h⟩ := h_inv 31 le_rfl
  exact h

/-! ## The start of a round -/

/-- The paired run's state at the start of a round on `a` and `b`: the two approximations, and
`a` and `b`. -/
def start (a b : Nat) : (Int × Int) × (Int × Int) :=
  ((((approximation (width a b) a : Nat) : Int), ((approximation (width a b) b : Nat) : Int)),
    ((a : Int), (b : Int)))

private theorem dvd_sub_of_mod {x y : Nat} (h_mod : y % 2 ^ 31 = x % 2 ^ 31) :
    (2 : Int) ^ 31 ∣ (x : Int) - (y : Int) := by
  have h : ((y : Int) % 2 ^ 31) = ((x : Int) % 2 ^ 31) := by exact_mod_cast h_mod
  exact Int.ModEq.dvd h

private theorem agree_start {a b : Nat} (h_odd : b % 2 = 1) : Agree 0 (start a b) := by
  have h_a := approximation_mod (n := width a b) (x := a)
  have h_b := approximation_mod (n := width a b) (x := b)
  have h_b_odd : approximation (width a b) b % 2 = 1 := by omega
  simp only [Agree, start]
  refine ⟨by positivity, by positivity, by exact_mod_cast h_b_odd, by exact_mod_cast h_odd,
    dvd_sub_of_mod h_a, dvd_sub_of_mod h_b⟩

private theorem agree_run {a b : Nat} (h_odd : b % 2 = 1) :
    ∀ t ≤ 31, Agree t (pairStep^[t] (start a b)) := by
  intro t h_t
  induction t with
  | zero => exact agree_start h_odd
  | succ t ih =>
    rw [Function.iterate_succ_apply']
    exact agree_step (by omega) (ih (by omega))

/-! ## Unbalanced rounds

When one of `a` and `b` is at least 32 bits shorter than the other, the shorter one's
approximation is below `2 ^ 32` and the longer one's at least `2 ^ 63`. The longer one then
stays above the shorter through the whole round, in the approximations and in the exact values
alike, so no step swaps them, and every move is the classic one. -/

private theorem dominant_gt {P Q C W X : Int} (h_P : 1 ≤ P) (h_P30 : P ≤ 2 ^ 30) (h_Q : 0 < Q)
    (h_C : 2 ^ 31 * Q ≤ C) (h_W : W < Q) (h_dom : C ≤ P * X + (P - 1) * W) : W < X := by
  by_contra h_not
  replace h_not := not_lt.mp h_not
  nlinarith [mul_le_mul_of_nonneg_left h_not (by linarith : (0 : Int) ≤ P),
    mul_pos (by linarith : (0 : Int) < 2 * P - 1) (by linarith : (0 : Int) < Q - W),
    mul_nonneg (by linarith : (0 : Int) ≤ 2 ^ 31 - 2 * P) h_Q.le]

/-- The invariant of an unbalanced round, `k` steps after a step whose first values were `B`
and `C` and whose second values were `Y0` and `W`: the second values have not moved, and each
first value has lost at most its second value at each step since. -/
def Dominant (B Y0 C W : Int) (k : Nat) (s : (Int × Int) × (Int × Int)) : Prop :=
  s.1.2 = Y0 ∧ s.2.2 = W ∧ B ≤ 2 ^ k * s.1.1 + (2 ^ k - 1) * Y0 ∧
    C ≤ 2 ^ k * s.2.1 + (2 ^ k - 1) * W

/-- A step of an unbalanced round chooses its move as the exact values would, and keeps the
invariant, one step longer. -/
private theorem dominant_step {t k : Nat} {s : (Int × Int) × (Int × Int)} {B Y0 C W Q : Int}
    (h_t : t < 31) (h_k : k ≤ 30) (h_agree : Agree t s) (h_B : 2 ^ 31 * 2 ^ 32 ≤ B)
    (h_Y0 : 0 ≤ Y0) (h_Y0_lt : Y0 < 2 ^ 32) (h_Q : 0 < Q) (h_C : 2 ^ 31 * Q ≤ C)
    (h_W0 : 0 ≤ W) (h_W : W < Q) (h_dom : Dominant B Y0 C W k s) :
    move s.1.1 s.1.2 = move s.2.1 s.2.2 ∧ Dominant B Y0 C W (k + 1) (pairStep s) := by
  have h_parity := agree_parity h_t h_agree
  obtain ⟨⟨x, y⟩, ⟨X, Y⟩⟩ := s
  obtain ⟨-, -, h_y_odd, h_Y_odd, -, -⟩ := h_agree
  obtain ⟨h_y, h_Y, h_B_dom, h_C_dom⟩ := h_dom
  simp only at h_parity h_y_odd h_Y_odd h_y h_Y h_B_dom h_C_dom ⊢
  subst y Y
  have h_P : (1 : Int) ≤ 2 ^ k := one_le_pow₀ (by norm_num)
  have h_P30 : (2 : Int) ^ k ≤ 2 ^ 30 := pow_le_pow_right₀ (by norm_num) h_k
  have h_x : Y0 < x := dominant_gt h_P h_P30 (by norm_num) h_B h_Y0_lt h_B_dom
  have h_X : W < X := dominant_gt h_P h_P30 h_Q h_C h_W h_C_dom
  have h_succ : (2 : Int) ^ (k + 1) = 2 * 2 ^ k := by ring
  have h_move : move x Y0 = move X W := by
    simp only [move, show ¬x < Y0 by omega, show ¬X < W by omega, h_parity]
  refine ⟨h_move, ?_⟩
  simp only [pairStep, move, if_neg (show ¬x < Y0 by omega)]
  have h_P0 : (0 : Int) ≤ 2 ^ k := by positivity
  split_ifs with h_even
  · refine ⟨rfl, rfl, ?_, ?_⟩ <;> simp only [apply] <;> rw [h_succ]
    · have h_x2 : 2 * 2 ^ k * (x / 2) = 2 ^ k * x := by
        rw [mul_comm 2 (2 ^ k), mul_assoc, show 2 * (x / 2) = x by omega]
      nlinarith [mul_nonneg h_P0 h_Y0]
    · have h_X2 : 2 * 2 ^ k * (X / 2) = 2 ^ k * X := by
        rw [mul_comm 2 (2 ^ k), mul_assoc, show 2 * (X / 2) = X by omega]
      nlinarith [mul_nonneg h_P0 h_W0]
  · refine ⟨rfl, rfl, ?_, ?_⟩ <;> simp only [apply] <;> rw [h_succ]
    · have h_x2 : 2 * 2 ^ k * ((x - Y0) / 2) = 2 ^ k * (x - Y0) := by
        rw [mul_comm 2 (2 ^ k), mul_assoc, show 2 * ((x - Y0) / 2) = x - Y0 by omega]
      nlinarith
    · have h_X2 : 2 * 2 ^ k * ((X - W) / 2) = 2 ^ k * (X - W) := by
        rw [mul_comm 2 (2 ^ k), mul_assoc, show 2 * ((X - W) / 2) = X - W by omega]
      nlinarith

/-- A halving at the start of a round in which `a` is the shorter: the values have only been
halved so far. -/
def Halving (A B AX BX : Int) (t : Nat) (s : (Int × Int) × (Int × Int)) : Prop :=
  s.1.1 * 2 ^ t = A ∧ s.2.1 * 2 ^ t = AX ∧ s.1.2 = B ∧ s.2.2 = BX

/-- In a round where one of `a` and `b` is at least 32 bits shorter than the other, every step
chooses its move as the exact values would. -/
private theorem agree_of_unbalanced {a b : Nat} (h_odd : b % 2 = 1) (h_n : 64 < width a b)
    (h_unbalanced : min a.size b.size + 32 ≤ width a b) :
    ∀ t < 31, move (pairStep^[t] (start a b)).1.1 (pairStep^[t] (start a b)).1.2 =
      move (pairStep^[t] (start a b)).2.1 (pairStep^[t] (start a b)).2.2 := by
  set n := width a b with h_n_def
  have h_max : max a.size b.size = n := rfl
  have h_Q : (0 : Int) < 2 ^ (n - 32) := by positivity
  have h_top : (2 : Int) ^ 31 * 2 ^ (n - 32) = 2 ^ (n - 1) := by
    rw [← pow_add]
    congr 1
    omega
  have h_agree := agree_run (a := a) (b := b) h_odd
  rcases le_total b.size a.size with h_ab | h_ab
  · -- a is the longer: a dominant state from the start.
    have h_a_size : a.size = n := by rw [← h_max]; exact (max_eq_left h_ab).symm
    have h_b_size : b.size ≤ n - 32 := by rw [min_eq_right h_ab] at h_unbalanced; omega
    have h_a_large := approximation_large h_n h_a_size
    have h_b_small := approximation_small h_n h_b_size
    have h_a_low : (2 : Int) ^ (n - 1) ≤ a := by
      exact_mod_cast Nat.lt_size.mp (show n - 1 < a.size by omega)
    have h_b_lt : (b : Int) < 2 ^ (n - 32) := by exact_mod_cast Nat.size_le.mp h_b_size
    have h_dom : ∀ t ≤ 31, Dominant (approximation n a) (approximation n b) a b t
        (pairStep^[t] (start a b)) := by
      intro t h_t
      induction t with
      | zero => simp [Dominant, start, h_n_def]
      | succ t ih =>
        rw [Function.iterate_succ_apply']
        exact (dominant_step (by omega) (by omega) (h_agree t (by omega))
          (by exact_mod_cast h_a_large) (by positivity) (by exact_mod_cast h_b_small) h_Q
          (by rw [h_top]; exact h_a_low) (by positivity) h_b_lt (ih (by omega))).2
    intro t h_t
    exact (dominant_step h_t (by omega) (h_agree t (by omega))
      (by exact_mod_cast h_a_large) (by positivity) (by exact_mod_cast h_b_small) h_Q
      (by rw [h_top]; exact h_a_low) (by positivity) h_b_lt (h_dom t (by omega))).1
  · -- b is the longer: halvings of a, then a swap, then a dominant state.
    have h_b_size : b.size = n := by rw [← h_max]; exact (max_eq_right h_ab).symm
    have h_a_size : a.size ≤ n - 32 := by rw [min_eq_left h_ab] at h_unbalanced; omega
    have h_b_large := approximation_large h_n h_b_size
    have h_a_small := approximation_small h_n h_a_size
    have h_b_low : (2 : Int) ^ (n - 1) ≤ b := by
      exact_mod_cast Nat.lt_size.mp (show n - 1 < b.size by omega)
    have h_a_lt : (a : Int) < 2 ^ (n - 32) := by exact_mod_cast Nat.size_le.mp h_a_size
    have h_n32 : (2 : Int) ^ (n - 32) ≤ 2 ^ (n - 1) := pow_le_pow_right₀ (by norm_num) (by omega)
    -- The invariant: still halving, or dominant since a step k ≥ 1 steps back.
    have h_inv : ∀ t ≤ 31,
        Halving (approximation n a) (approximation n b) a b t (pairStep^[t] (start a b)) ∨
        ∃ Y0 W : Int, ∃ k : Nat, 1 ≤ k ∧ k ≤ t ∧ 0 ≤ Y0 ∧ Y0 < 2 ^ 32 ∧ 0 ≤ W ∧
          W < 2 ^ (n - 32) ∧
          Dominant (approximation n b) Y0 b W k (pairStep^[t] (start a b)) := by
      intro t h_t
      induction t with
      | zero => exact Or.inl (by simp [Halving, start, h_n_def])
      | succ t ih =>
        have h_ag := h_agree t (by omega)
        have h_parity := agree_parity (by omega : t < 31) h_ag
        rw [Function.iterate_succ_apply']
        rcases ih (by omega) with h_half | ⟨Y0, W, k, h_k1, h_kt, h_Y00, h_Y0, h_W0, h_W, h_dom⟩
        · generalize pairStep^[t] (start a b) = s at h_half h_ag h_parity ⊢
          obtain ⟨⟨x, y⟩, ⟨X, Y⟩⟩ := s
          obtain ⟨h_x, h_X, h_y, h_Y⟩ := h_half
          obtain ⟨h_x0, -, h_y_odd, h_Y_odd, -, -⟩ := h_ag
          simp only at h_x h_X h_y h_Y h_x0 h_y_odd h_Y_odd h_parity ⊢
          subst y Y
          have h_pow : (1 : Int) ≤ 2 ^ t := one_le_pow₀ (by norm_num)
          have h_x_le : x ≤ approximation n a := by
            rw [← h_x]; nlinarith
          have h_X0 : 0 ≤ X := by
            by_contra h_neg
            replace h_neg := not_le.mp h_neg
            have : X * 2 ^ t < 0 := mul_neg_of_neg_of_pos h_neg (by positivity)
            have : (0 : Int) ≤ (a : Int) := by positivity
            linarith
          have h_X_le : X ≤ a := by rw [← h_X]; nlinarith
          simp only [pairStep, move]
          split_ifs with h_even h_lt
          · left
            refine ⟨?_, ?_, rfl, rfl⟩ <;> simp only [apply, pow_succ]
            · have : 2 * (x / 2) = x := by omega
              rw [← h_x]; linear_combination (2 ^ t) * this
            · have : 2 * (X / 2) = X := by omega
              rw [← h_X]; linear_combination (2 ^ t) * this
          · right
            refine ⟨x, X, 1, le_rfl, by omega, h_x0, by exact_mod_cast (lt_of_le_of_lt h_x_le
              (by exact_mod_cast h_a_small)), h_X0, lt_of_le_of_lt h_X_le h_a_lt, ?_⟩
            refine ⟨rfl, rfl, ?_, ?_⟩ <;> simp only [apply, pow_one] <;> omega
          · exfalso
            have : (x : Int) < approximation n b := by
              calc x ≤ approximation n a := h_x_le
                _ < 2 ^ 32 := by exact_mod_cast h_a_small
                _ ≤ 2 ^ 63 := by norm_num
                _ ≤ approximation n b := by exact_mod_cast h_b_large
            exact h_lt this
        · right
          refine ⟨Y0, W, k + 1, by omega, by omega, h_Y00, h_Y0, h_W0, h_W, ?_⟩
          exact (dominant_step (by omega) (by omega) h_ag (by exact_mod_cast h_b_large) h_Y00
            h_Y0 (by positivity) (by rw [h_top]; exact h_b_low) h_W0 h_W h_dom).2
    intro t h_t
    have h_ag := h_agree t (by omega)
    have h_parity := agree_parity h_t h_ag
    rcases h_inv t (by omega) with h_half | ⟨Y0, W, k, h_k1, h_kt, h_Y00, h_Y0, h_W0, h_W, h_dom⟩
    · generalize pairStep^[t] (start a b) = s at h_half h_ag h_parity ⊢
      obtain ⟨⟨x, y⟩, ⟨X, Y⟩⟩ := s
      obtain ⟨h_x, h_X, h_y, h_Y⟩ := h_half
      obtain ⟨h_x0, -, -, -, -, -⟩ := h_ag
      simp only at h_x h_X h_y h_Y h_x0 h_parity ⊢
      subst y Y
      have h_pow : (1 : Int) ≤ 2 ^ t := one_le_pow₀ (by norm_num)
      have h_x_le : x ≤ approximation n a := by rw [← h_x]; nlinarith
      have h_X0 : 0 ≤ X := by
        by_contra h_neg
        replace h_neg := not_le.mp h_neg
        have : X * 2 ^ t < 0 := mul_neg_of_neg_of_pos h_neg (by positivity)
        have : (0 : Int) ≤ (a : Int) := by positivity
        linarith
      have h_X_le : X ≤ a := by rw [← h_X]; nlinarith
      have h_x_lt : (x : Int) < approximation n b := by
        calc x ≤ approximation n a := h_x_le
          _ < 2 ^ 32 := by exact_mod_cast h_a_small
          _ ≤ 2 ^ 63 := by norm_num
          _ ≤ approximation n b := by exact_mod_cast h_b_large
      have h_X_lt : X < (b : Int) := by
        calc X ≤ a := h_X_le
          _ < 2 ^ (n - 32) := h_a_lt
          _ ≤ 2 ^ (n - 1) := h_n32
          _ ≤ b := h_b_low
      simp only [move, h_x_lt, h_X_lt, if_true, h_parity]
    · exact (dominant_step h_t (by omega) h_ag (by exact_mod_cast h_b_large) h_Y00 h_Y0
        (by positivity) (by rw [h_top]; exact h_b_low) h_W0 h_W h_dom).1

/-! ## Balanced rounds

When `a` and `b` are within 31 bits of each other, a comparison of the approximations can
differ from the comparison of the exact values. The first step where they differ leaves a
value below zero, `N`, beside a value above zero. `Phase` is what holds from step to step:

* the steps so far chose every move as the exact values would, and the exact values have lost
  a bit per step;
* or the first exact value reached zero, where it stays;
* or a comparison differed, the positive value `V` is still at least `2 E`, and every step
  since either halved `N` or brought `V` down to at most `(V + |N|) / 2`: then the approximation
  of `N` is below `2 ^ 31` and that of `V` above it, so the steps can do nothing else;
* or a comparison differed and both values are below `2 E` in size, where they stay.

`E` is `2 ^ (n - 33)`, the bound `approximation_error` gives, and `E = H * 2 ^ 31` for
`H = 2 ^ (n - 64)`. -/

/-- The phases of a balanced round's exact values `X` and `Y`, `t` steps in. -/
def Phase (E : Int) (L0 t : Nat) (X Y : Int) : Prop :=
  (0 ≤ X ∧ 0 < Y ∧ (X = 0 ∨ len X + len Y + t ≤ L0)) ∨
  X = 0 ∨
  (∃ N V P Q : Int, ∃ i j d : Nat,
      ((X = N ∧ Y = V) ∨ (X = V ∧ Y = N)) ∧ N < 0 ∧ 2 * E ≤ V ∧ 2 ^ i * |N| < E ∧
      2 ^ j * V ≤ Q + (E - 1) * (2 ^ j - 1) ∧ i + j + d + 1 = t ∧ 0 ≤ P ∧ Q < P + 2 * E ∧
      len P + len Q + d ≤ L0) ∨
  (|X| < 2 * E ∧ |Y| < 2 * E)

/-- After the first step whose moves differ, `X` and `Y` before it were the classic values `P`
and `Q`, and the step left `(P - Q) / 2` beside `Q`: what `Phase` makes of that. -/
private theorem phase_of_divergence {E : Int} {L0 t : Nat} {P Q : Int} (h_P : 0 ≤ P)
    (h_PQ : P ≤ Q) (h_P_odd : P % 2 = 1) (h_Q_odd : Q % 2 = 1) (h_close : Q - P < 2 * E)
    (h_len : len P + len Q + t ≤ L0) :
    Phase E L0 (t + 1) ((P - Q) / 2) Q := by
  have h_two : 2 * ((P - Q) / 2) = P - Q := by omega
  by_cases h_eq : P = Q
  · right; left
    rw [h_eq, sub_self]
    rfl
  have h_neg : (P - Q) / 2 < 0 := by omega
  have h_abs : |(P - Q) / 2| < E := by
    rw [abs_of_neg h_neg]
    omega
  by_cases h_big : 2 * E ≤ Q
  · right; right; left
    exact ⟨(P - Q) / 2, Q, P, Q, 0, 0, t, Or.inl ⟨rfl, rfl⟩, h_neg, h_big,
      by simpa using h_abs, by simp, by omega, h_P, by omega, h_len⟩
  · right; right; right
    refine ⟨by omega, ?_⟩
    rw [abs_of_nonneg (by omega)]
    omega

/-- A step keeps `Phase`. -/
private theorem phase_step {E H : Int} {L0 t : Nat} {s : (Int × Int) × (Int × Int)} (h_t : t < 31)
    (h_H : 0 < H) (h_E : E = H * 2 ^ 31) (h_agree : Agree t s)
    (h_error_x : |s.2.1 - H * s.1.1| < E) (h_error_y : |s.2.2 - H * s.1.2| < E)
    (h_phase : Phase E L0 t s.2.1 s.2.2) :
    Phase E L0 (t + 1) (pairStep s).2.1 (pairStep s).2.2 := by
  have h_parity := agree_parity h_t h_agree
  have h_max := max_step (M := max |s.2.1| |s.2.2|) h_t h_agree (le_max_left _ _)
    (le_max_right _ _)
  obtain ⟨⟨x, y⟩, ⟨X, Y⟩⟩ := s
  obtain ⟨h_x0, h_y0, h_y_odd, h_Y_odd, -, -⟩ := h_agree
  simp only at h_parity h_max h_x0 h_y0 h_y_odd h_Y_odd h_error_x h_error_y h_phase ⊢
  have h_E_pos : 0 < E := by rw [h_E]; positivity
  obtain ⟨h_ex_lo, h_ex_hi⟩ := abs_lt.mp h_error_x
  obtain ⟨h_ey_lo, h_ey_hi⟩ := abs_lt.mp h_error_y
  rcases h_phase with ⟨h_X0, h_Y0, h_len⟩ | h_zero |
      ⟨N, V, P, Q, i, j, d, h_slots, h_N, h_V, h_N_bound, h_V_bound, h_count, h_P, h_PQ,
        h_P_len⟩ | ⟨h_X_bound, h_Y_bound⟩
  · -- The moves have agreed so far.
    by_cases h_X_zero : X = 0
    · subst h_X_zero
      right; left
      have h_x_even : x % 2 = 0 := by omega
      simp only [pairStep, move, h_x_even, if_true, apply, Int.zero_ediv]
    have h_X_pos : 0 < X := lt_of_le_of_ne h_X0 (Ne.symm h_X_zero)
    have h_len' : len X + len Y + t ≤ L0 := h_len.resolve_left h_X_zero
    by_cases h_same : move x y = move X Y
    · left
      have h_step : (pairStep ((x, y), (X, Y))).2 = apply (move X Y) (X, Y) := by
        simp only [pairStep, h_same]
      rw [h_step]
      obtain ⟨h_1, h_2, -, h_4⟩ := classic_step h_X_pos h_Y0 h_Y_odd
      exact ⟨h_1, h_2, Or.inr (by omega)⟩
    · -- The first step whose moves differ: both values are odd.
      have h_x_odd : x % 2 = 1 := by
        by_contra h_even
        apply h_same
        simp only [move]
        rw [if_pos (by omega), if_pos (by omega)]
      have h_X_odd : X % 2 = 1 := by omega
      simp only [move, if_neg (show ¬x % 2 = 0 by omega), if_neg (show ¬X % 2 = 0 by omega)]
        at h_same
      simp only [pairStep, move, if_neg (show ¬x % 2 = 0 by omega)]
      by_cases h_xy : x < y
      · -- The approximations swap, the exact values would not: X is at least Y.
        have h_XY : ¬X < Y := by
          intro h_XY
          exact h_same (by rw [if_pos h_xy, if_pos h_XY])
        simp only [if_pos h_xy, apply]
        have h_Hxy : H * x ≤ H * y := mul_le_mul_of_nonneg_left h_xy.le h_H.le
        have h_close : X - Y < 2 * E := by linarith
        exact phase_of_divergence (by omega) (by omega) h_Y_odd h_X_odd h_close (by omega)
      · -- The approximations subtract, the exact values would swap: X is below Y.
        have h_XY : X < Y := by
          by_contra h_XY
          exact h_same (by rw [if_neg h_xy, if_neg h_XY])
        simp only [if_neg h_xy, apply]
        have h_Hxy : H * y ≤ H * x := mul_le_mul_of_nonneg_left (not_lt.mp h_xy) h_H.le
        have h_close : Y - X < 2 * E := by linarith
        exact phase_of_divergence h_X0 h_XY.le h_X_odd h_Y_odd h_close h_len'
  · -- X is zero, and its approximation is even.
    subst h_zero
    right; left
    have h_x_even : x % 2 = 0 := by omega
    simp only [pairStep, move, h_x_even, if_true, apply, Int.zero_ediv]
  · -- After a comparison differed, with V at least 2 E.
    have h_pow_i : (1 : Int) ≤ 2 ^ i := one_le_pow₀ (by norm_num)
    have h_pow_j : (1 : Int) ≤ 2 ^ j := one_le_pow₀ (by norm_num)
    have h_N_abs : |N| = -N := abs_of_neg h_N
    have h_N_lt : -N < E := by
      have := le_mul_of_one_le_left (abs_nonneg N) h_pow_i
      rw [h_N_abs] at this h_N_bound
      linarith
    have h_succ_j : (2 : Int) ^ (j + 1) = 2 * 2 ^ j := by ring
    have h_succ_i : (2 : Int) ^ (i + 1) = 2 * 2 ^ i := by ring
    have h_E_one : (0 : Int) ≤ E - 1 := by omega
    -- What V becomes when a step averages it with N.
    have h_average : ∀ V' : Int, 2 * V' = V - N →
        2 ^ (j + 1) * V' ≤ Q + (E - 1) * (2 ^ (j + 1) - 1) := by
      intro V' h_V'
      have h_N_le : 2 ^ j * -N ≤ 2 ^ j * (E - 1) :=
        mul_le_mul_of_nonneg_left (by omega) (by positivity)
      calc 2 ^ (j + 1) * V' = 2 ^ j * V + 2 ^ j * -N := by
            rw [h_succ_j]; linear_combination (2 : Int) ^ j * h_V'
        _ ≤ (Q + (E - 1) * (2 ^ j - 1)) + 2 ^ j * (E - 1) := add_le_add h_V_bound h_N_le
        _ = Q + (E - 1) * (2 ^ (j + 1) - 1) := by rw [h_succ_j]; ring
    -- Either state after such a step: V' still at least 2 E, or both below 2 E.
    have h_after : ∀ V' : Int, 0 < V' → 2 ^ (j + 1) * V' ≤ Q + (E - 1) * (2 ^ (j + 1) - 1) →
        Phase E L0 (t + 1) V' N := by
      intro V' h_V'_pos h_V'_bound
      by_cases h_big : 2 * E ≤ V'
      · right; right; left
        exact ⟨N, V', P, Q, i, j + 1, d, Or.inr ⟨rfl, rfl⟩, h_N, h_big, h_N_bound, h_V'_bound,
          by omega, h_P, h_PQ, h_P_len⟩
      · right; right; right
        refine ⟨by rw [abs_of_pos h_V'_pos]; omega, by rw [h_N_abs]; omega⟩
    rcases h_slots with ⟨h_XN, h_YV⟩ | ⟨h_XV, h_YN⟩
    · -- X = N, Y = V: the approximation of N is below 2^31, that of V above.
      subst X Y
      have h_x_small : x < 2 ^ 31 := by
        have : H * x < H * 2 ^ 31 := by rw [← h_E]; linarith
        exact lt_of_mul_lt_mul_left this h_H.le
      have h_y_large : 2 ^ 31 < y := by
        have : H * 2 ^ 31 < H * y := by rw [← h_E]; linarith
        exact lt_of_mul_lt_mul_left this h_H.le
      by_cases h_even : x % 2 = 0
      · -- N is halved.
        simp only [pairStep, move, if_pos h_even, apply]
        have h_two : 2 * (N / 2) = N := by omega
        right; right; left
        refine ⟨N / 2, V, P, Q, i + 1, j, d, Or.inl ⟨rfl, rfl⟩, by omega, h_V, ?_, h_V_bound,
          by omega, h_P, h_PQ, h_P_len⟩
        calc 2 ^ (i + 1) * |N / 2| = 2 ^ i * |N| := by
              rw [abs_of_neg (by omega : N / 2 < 0), h_N_abs, h_succ_i]
              linear_combination (-(2 : Int) ^ i) * h_two
          _ < E := h_N_bound
      · -- The approximations swap: V becomes (V - N) / 2 and N moves into Y.
        simp only [pairStep, move, if_neg h_even, if_pos (show x < y by omega), apply]
        have h_two : 2 * ((V - N) / 2) = V - N := by omega
        exact h_after _ (by omega) (h_average _ h_two)
    · -- X = V, Y = N: the approximation of V is above 2^31, that of N below.
      subst X Y
      have h_x_large : 2 ^ 31 < x := by
        have : H * 2 ^ 31 < H * x := by rw [← h_E]; linarith
        exact lt_of_mul_lt_mul_left this h_H.le
      have h_y_small : y < 2 ^ 31 := by
        have : H * y < H * 2 ^ 31 := by rw [← h_E]; linarith
        exact lt_of_mul_lt_mul_left this h_H.le
      by_cases h_even : x % 2 = 0
      · -- V is halved.
        simp only [pairStep, move, if_pos h_even, apply]
        have h_two : 2 * (V / 2) = V := by omega
        refine h_after _ (by omega) ?_
        have h_extra : (0 : Int) ≤ (E - 1) * 2 ^ j := mul_nonneg h_E_one (by positivity)
        calc 2 ^ (j + 1) * (V / 2) = 2 ^ j * V := by
              rw [h_succ_j]; linear_combination (2 : Int) ^ j * h_two
          _ ≤ Q + (E - 1) * (2 ^ j - 1) := h_V_bound
          _ ≤ Q + (E - 1) * (2 ^ j - 1) + (E - 1) * 2 ^ j := le_add_of_nonneg_right h_extra
          _ = Q + (E - 1) * (2 ^ (j + 1) - 1) := by rw [h_succ_j]; ring
      · -- The approximations subtract: V becomes (V - N) / 2.
        simp only [pairStep, move, if_neg h_even, if_neg (show ¬x < y by omega), apply]
        have h_two : 2 * ((V - N) / 2) = V - N := by omega
        exact h_after _ (by omega) (h_average _ h_two)
  · -- Both below 2 E in size, which no step undoes.
    right; right; right
    exact ⟨lt_of_le_of_lt h_max.1 (max_lt h_X_bound h_Y_bound),
      lt_of_le_of_lt h_max.2 (max_lt h_X_bound h_Y_bound)⟩

/-! ## A round shortens `a` and `b` by 31 bits -/

private theorem len_natCast (a : Nat) : len (a : Int) = a.size := by
  simp [len]

private theorem len_mono {z w : Int} (h : |z| ≤ |w|) : len z ≤ len w := by
  unfold len
  apply Nat.size_le_size
  have : (z.natAbs : Int) ≤ w.natAbs := by
    rw [Int.natCast_natAbs, Int.natCast_natAbs]
    exact h
  exact_mod_cast this

private theorem len_add_le_of_lt_pow {z : Int} {i k : Nat} (h_z : z ≠ 0)
    (h : 2 ^ i * |z| < 2 ^ k) : len z + i ≤ k := by
  have h_len := len_pos h_z
  have h_low : (2 : Int) ^ (len z - 1) ≤ |z| := lt_len_iff.mp (by omega)
  have h_mul : (2 : Int) ^ (i + (len z - 1)) < 2 ^ k := by
    rw [pow_add]
    calc (2 : Int) ^ i * 2 ^ (len z - 1) ≤ 2 ^ i * |z| :=
          mul_le_mul_of_nonneg_left h_low (by positivity)
      _ < 2 ^ k := h
  have := (pow_lt_pow_iff_right₀ (by norm_num : (1 : Int) < 2)).mp h_mul
  omega

/-- How far each exact value is from `2 ^ (n - 64)` times its approximation, step by step. -/
private theorem error_run {a b : Nat} (h_odd : b % 2 = 1) (h_n : 64 < width a b) :
    ∀ t ≤ 31,
      |(pairStep^[t] (start a b)).2.1 - 2 ^ (width a b - 64) * (pairStep^[t] (start a b)).1.1| <
        2 ^ (width a b - 33) ∧
      |(pairStep^[t] (start a b)).2.2 - 2 ^ (width a b - 64) * (pairStep^[t] (start a b)).1.2| <
        2 ^ (width a b - 33) := by
  intro t h_t
  induction t with
  | zero => exact ⟨approximation_error h_n, approximation_error h_n⟩
  | succ t ih =>
    rw [Function.iterate_succ_apply']
    obtain ⟨h_x, h_y⟩ := ih (by omega)
    exact error_step (by omega) (agree_run h_odd t (by omega)) h_x h_y

/-- `Phase` after the last step: the values have lost 31 bits between them, or the first is
zero. -/
private theorem phase_final {n L0 : Nat} {X Y : Int} (h_n : 64 < n) (h_L0 : 2 * n ≤ L0 + 31)
    (h_phase : Phase (2 ^ (n - 33)) L0 31 X Y) : X = 0 ∨ len X + len Y + 31 ≤ L0 := by
  have h_2E : (2 : Int) * 2 ^ (n - 33) = 2 ^ (n - 32) := by
    rw [← pow_succ']
    congr 1
    omega
  have h_4E : (2 : Int) * 2 ^ (n - 32) = 2 ^ (n - 31) := by
    rw [← pow_succ']
    congr 1
    omega
  rcases h_phase with ⟨-, -, h⟩ | h_zero |
      ⟨N, V, P, Q, i, j, d, h_slots, h_N, h_V, h_N_bound, h_V_bound, h_count, h_P, h_PQ,
        h_P_len⟩ | ⟨h_X_bound, h_Y_bound⟩
  · exact h
  · exact Or.inl h_zero
  · right
    have h_sum : len X + len Y = len N + len V := by
      rcases h_slots with ⟨rfl, rfl⟩ | ⟨rfl, rfl⟩ <;> omega
    rw [h_sum]
    have h_len_N : len N + i ≤ n - 33 := len_add_le_of_lt_pow h_N.ne h_N_bound
    have h_E1 : (1 : Int) ≤ 2 ^ (n - 33) := one_le_pow₀ (by norm_num)
    have h_pow_j : (1 : Int) ≤ 2 ^ j := one_le_pow₀ (by norm_num)
    have h_V_pos : 0 < V := by omega
    by_cases h_P_big : 2 * 2 ^ (n - 33) ≤ P
    · -- P has at least n - 31 bits, and V has lost j - 1 bits from Q.
      have h_len_P : n - 32 < len P := by
        rw [lt_len_iff, abs_of_nonneg h_P]
        rw [← h_2E]
        exact h_P_big
      have h_Q_pos : 0 < Q := by
        have h_V_le : 2 ^ j * V ≤ Q + (2 ^ (n - 33) - 1) * (2 ^ j - 1) := h_V_bound
        nlinarith
      have h_V_lt : 2 ^ j * V < 2 * Q := by
        have h_extra : 2 ^ j * (2 * 2 ^ (n - 33)) ≤ 2 ^ j * V :=
          mul_le_mul_of_nonneg_left h_V (by positivity)
        nlinarith
      have h_Q_lt : Q < 2 ^ len Q := by
        have := len_le_iff.mp (le_refl (len Q))
        rwa [abs_of_pos h_Q_pos] at this
      have h_len_V : len V + j ≤ len Q + 1 := by
        apply len_add_le_of_lt_pow h_V_pos.ne'
        rw [abs_of_pos h_V_pos, pow_succ]
        linarith
      omega
    · -- P is below 2 E, so Q is below 4 E, and V is at most Q.
      have h_Q_lt : Q < 2 ^ (n - 31) := by linarith
      have h_V_le : V ≤ Q := by
        nlinarith [mul_nonneg (by linarith : (0 : Int) ≤ 2 ^ j - 1)
          (by linarith : (0 : Int) ≤ V - (2 ^ (n - 33) - 1))]
      have h_len_V : len V ≤ n - 31 := by
        rw [len_le_iff, abs_of_pos h_V_pos]
        linarith
      omega
  · right
    have h_len_X : len X ≤ n - 32 := by rw [len_le_iff, ← h_2E]; exact h_X_bound
    have h_len_Y : len Y ≤ n - 32 := by rw [len_le_iff, ← h_2E]; exact h_Y_bound
    omega

private theorem diagonal {p : Int × Int} : ∀ t, (pairStep^[t] (p, p)).1 = (pairStep^[t] (p, p)).2
  | 0 => rfl
  | t + 1 => by
    rw [Function.iterate_succ_apply']
    have h := diagonal (p := p) t
    generalize pairStep^[t] (p, p) = s at h ⊢
    obtain ⟨q, r⟩ := s
    simp only at h
    subst h
    rfl

/-- A round's 31 steps take 31 bits off `a` and `b` between them, unless `a` reaches zero:
`round_shrinks` for the exact values the steps make. -/
theorem run_shrinks {a b : Nat} (h_odd : b % 2 = 1) :
    (pairStep^[31] (start a b)).2.1 = 0 ∨
      len (pairStep^[31] (start a b)).2.1 + len (pairStep^[31] (start a b)).2.2 + 31 ≤
        a.size + b.size := by
  have h_b : (0 : Int) < b := by exact_mod_cast (show 0 < b by omega)
  have h_L0 : a.size + b.size = len (a : Int) + len (b : Int) := by
    rw [len_natCast, len_natCast]
  rw [h_L0]
  by_cases h_n : width a b ≤ 64
  · -- The approximations are a and b.
    have h_start : start a b = (((a : Int), (b : Int)), ((a : Int), (b : Int))) := by
      simp [start, approximation_of_le h_n]
    rw [h_start] at *
    apply shrinks_of_agree (by positivity) h_b (by exact_mod_cast h_odd)
    intro t _
    rw [diagonal t]
  have h_n' : 64 < width a b := by omega
  by_cases h_balanced : min a.size b.size + 32 ≤ width a b
  · exact shrinks_of_agree (by positivity) h_b (by exact_mod_cast h_odd)
      (agree_of_unbalanced h_odd h_n' h_balanced)
  · -- Balanced: a and b have at least n - 31 bits each.
    set n := width a b with h_n_def
    have h_sizes : 2 * n ≤ len (a : Int) + len (b : Int) + 31 := by
      rw [len_natCast, len_natCast]
      have : max a.size b.size = n := rfl
      omega
    have h_E : (2 : Int) ^ (n - 33) = 2 ^ (n - 64) * 2 ^ 31 := by
      rw [← pow_add]
      congr 1
      omega
    have h_phase : ∀ t ≤ 31, Phase (2 ^ (n - 33)) (len (a : Int) + len (b : Int)) t
        (pairStep^[t] (start a b)).2.1 (pairStep^[t] (start a b)).2.2 := by
      intro t h_t
      induction t with
      | zero => exact Or.inl ⟨by simp [start], by simpa [start] using h_b, Or.inr (by simp [start])⟩
      | succ t ih =>
        rw [Function.iterate_succ_apply']
        obtain ⟨h_x, h_y⟩ := error_run h_odd h_n' t (by omega)
        exact phase_step (by omega) (by positivity) h_E (agree_run h_odd t (by omega)) h_x h_y
          (ih (by omega))
    exact phase_final h_n' h_sizes (h_phase 31 le_rfl)

/-! ## The factors

`stepFactors` runs the moves `pairStep` runs, and its factors give the exact values after the
steps: `2 ^ t` times them is `a f0 + b g0` and `a f1 + b g1`. So the division the round makes
by `2 ^ 31` is exact, and its quotients are the exact values `run_shrinks` is about. -/

private theorem approximations_same (p : Int × Int) (r : Int × Int × Int × Int)
    (q : Int × Int) : ∀ t, (factorStep^[t] (p, r)).1 = (pairStep^[t] (p, q)).1
  | 0 => rfl
  | t + 1 => by
    rw [Function.iterate_succ_apply', Function.iterate_succ_apply']
    have h := approximations_same p r q t
    simp only [factorStep, pairStep, h]

/-- `2 ^ t` times the exact values after `t` steps is what the factors make of `a` and `b`. -/
theorem factors_represent {a b : Nat} (h_odd : b % 2 = 1) :
    ∀ t ≤ 31,
      2 ^ t * (pairStep^[t] (start a b)).2.1 =
          a * (factorStep^[t] ((start a b).1, (1, 0, 0, 1))).2.1 +
            b * (factorStep^[t] ((start a b).1, (1, 0, 0, 1))).2.2.1 ∧
      2 ^ t * (pairStep^[t] (start a b)).2.2 =
          a * (factorStep^[t] ((start a b).1, (1, 0, 0, 1))).2.2.2.1 +
            b * (factorStep^[t] ((start a b).1, (1, 0, 0, 1))).2.2.2.2 := by
  intro t h_t
  induction t with
  | zero => simp [start]
  | succ t ih =>
    obtain ⟨h_X, h_Y⟩ := ih (by omega)
    have h_agree := agree_run (a := a) h_odd t (by omega)
    have h_parity := agree_parity (by omega : t < 31) h_agree
    have h_same := approximations_same (start a b).1 (1, 0, 0, 1) (start a b).2 t
    rw [Function.iterate_succ_apply', Function.iterate_succ_apply']
    have h_start : ((start a b).1, (start a b).2) = start a b := rfl
    rw [h_start] at h_same
    generalize pairStep^[t] (start a b) = s at h_X h_Y h_agree h_parity h_same ⊢
    generalize factorStep^[t] ((start a b).1, (1, 0, 0, 1)) = w at h_X h_Y h_same ⊢
    obtain ⟨⟨x, y⟩, ⟨X, Y⟩⟩ := s
    obtain ⟨p, ⟨f0, g0, f1, g1⟩⟩ := w
    simp only at h_same
    subst h_same
    obtain ⟨-, -, -, h_Y_odd, -, -⟩ := h_agree
    simp only at h_X h_Y h_parity h_Y_odd ⊢
    have h_pow : (2 : Int) ^ (t + 1) = 2 ^ t * 2 := pow_succ 2 t
    simp only [pairStep, factorStep, move]
    split_ifs with h_even h_lt
    · simp only [apply, applyFactors]
      have h_two : 2 * (X / 2) = X := by omega
      constructor
      · rw [h_pow, mul_assoc, h_two, h_X]
      · rw [h_pow]; linear_combination 2 * h_Y
    · simp only [apply, applyFactors]
      have h_two : 2 * ((Y - X) / 2) = Y - X := by omega
      constructor
      · rw [h_pow, mul_assoc, h_two]; linear_combination h_Y - h_X
      · rw [h_pow]; linear_combination 2 * h_X
    · simp only [apply, applyFactors]
      have h_two : 2 * ((X - Y) / 2) = X - Y := by omega
      constructor
      · rw [h_pow, mul_assoc, h_two]; linear_combination h_X - h_Y
      · rw [h_pow]; linear_combination 2 * h_Y

/-- The round's two quotients are the exact values after the 31 steps. -/
private theorem round_quotients {a b : Nat} (h_odd : b % 2 = 1) :
    let r := stepFactors (approximation (width a b) a) (approximation (width a b) b)
    (a * r.1 + b * r.2.1) / 2 ^ steps = (pairStep^[31] (start a b)).2.1 ∧
      (a * r.2.2.1 + b * r.2.2.2) / 2 ^ steps = (pairStep^[31] (start a b)).2.2 := by
  obtain ⟨h_X, h_Y⟩ := factors_represent h_odd 31 le_rfl
  simp only [stepFactors, steps]
  have h_first : (start a b).1 =
      (((approximation (width a b) a : Nat) : Int), ((approximation (width a b) b : Nat) : Int)) :=
    rfl
  rw [h_first] at h_X h_Y
  constructor
  · rw [← h_X]
    exact Int.mul_ediv_cancel_left _ (by positivity)
  · rw [← h_Y]
    exact Int.mul_ediv_cancel_left _ (by positivity)

/-! ## What a round keeps -/

/-- A round's `a` and `b` are the sizes of the exact values after its 31 steps. -/
private theorem round_ab {m : Nat} (s : State m) (h_odd : s.b % 2 = 1) :
    (round m s).a = (pairStep^[31] (start s.a s.b)).2.1.natAbs ∧
      (round m s).b = (pairStep^[31] (start s.a s.b)).2.2.natAbs := by
  obtain ⟨h_A, h_B⟩ := round_quotients (a := s.a) h_odd
  exact ⟨by simp only [round, h_A], by simp only [round, h_B]⟩

private theorem gcd_half {Z Y : Int} (h_Z : Z % 2 = 0) (h_Y : Y % 2 = 1) :
    Int.gcd (Z / 2) Y = Int.gcd Z Y := by
  have h_Z2 : Z = 2 * (Z / 2) := by omega
  have h_coprime : Nat.Coprime 2 Y.natAbs := by
    rw [Nat.coprime_two_left]
    have : Odd Y := Int.odd_iff.mpr h_Y
    exact Int.natAbs_odd.mpr this
  conv_rhs => rw [h_Z2]
  unfold Int.gcd
  rw [Int.natAbs_mul]
  exact (Nat.Coprime.gcd_mul_left_cancel _ h_coprime).symm

/-- A step keeps the greatest common divisor of the exact values. -/
private theorem gcd_step {t : Nat} {s : (Int × Int) × (Int × Int)} (h_t : t < 31) (h_agree : Agree t s) :
    Int.gcd (pairStep s).2.1 (pairStep s).2.2 = Int.gcd s.2.1 s.2.2 := by
  have h_parity := agree_parity h_t h_agree
  obtain ⟨⟨x, y⟩, ⟨X, Y⟩⟩ := s
  obtain ⟨-, -, -, h_Y_odd, -, -⟩ := h_agree
  simp only at h_parity h_Y_odd ⊢
  simp only [pairStep, move]
  split_ifs with h_even h_lt
  · simp only [apply]
    exact gcd_half (by omega) h_Y_odd
  · simp only [apply]
    rw [gcd_half (by omega) (by omega), Int.gcd_comm]
    have : Y - X = Y + (-1) * X := by ring
    rw [this, Int.gcd_add_mul_right_right]
  · simp only [apply]
    rw [gcd_half (by omega) h_Y_odd, Int.gcd_comm, Int.gcd_comm X Y]
    have : X - Y = X + (-1) * Y := by ring
    rw [this, Int.gcd_add_mul_right_right]

/-- A round keeps `b` odd. -/
theorem round_b_odd {m : Nat} (s : State m) (h_odd : s.b % 2 = 1) : (round m s).b % 2 = 1 := by
  obtain ⟨-, -, -, h_Y_odd, -, -⟩ := agree_run (a := s.a) h_odd 31 le_rfl
  rw [(round_ab s h_odd).2]
  have : Odd (pairStep^[31] (start s.a s.b)).2.2 := Int.odd_iff.mpr h_Y_odd
  exact Nat.odd_iff.mp (Int.natAbs_odd.mpr this)

/-- A round keeps `gcd a b`. -/
theorem round_gcd {m : Nat} (s : State m) (h_odd : s.b % 2 = 1) :
    Nat.gcd (round m s).a (round m s).b = Nat.gcd s.a s.b := by
  have h_run : ∀ t ≤ 31, Int.gcd (pairStep^[t] (start s.a s.b)).2.1
      (pairStep^[t] (start s.a s.b)).2.2 = Int.gcd s.a s.b := by
    intro t h_t
    induction t with
    | zero => rfl
    | succ t ih =>
      rw [Function.iterate_succ_apply', gcd_step (by omega) (agree_run h_odd t (by omega))]
      exact ih (by omega)
  obtain ⟨h_a, h_b⟩ := round_ab s h_odd
  rw [h_a, h_b]
  have := h_run 31 le_rfl
  unfold Int.gcd at this
  simpa using this

/-- A round takes 31 bits off `a` and `b` between them, unless it leaves `a` zero. -/
theorem round_shrinks {m : Nat} (s : State m) (h_odd : s.b % 2 = 1) :
    (round m s).a = 0 ∨ (round m s).a.size + (round m s).b.size + 31 ≤ s.a.size + s.b.size := by
  obtain ⟨h_a, h_b⟩ := round_ab s h_odd
  rw [h_a, h_b]
  rcases run_shrinks (a := s.a) h_odd with h | h
  · exact Or.inl (by rw [h]; rfl)
  · exact Or.inr h

/-- A round leaves a zero `a` zero. -/
theorem round_zero {m : Nat} (s : State m) (h_odd : s.b % 2 = 1) (h_zero : s.a = 0) :
    (round m s).a = 0 := by
  have h_run : ∀ t ≤ 31, (pairStep^[t] (start s.a s.b)).2.1 = 0 := by
    intro t h_t
    induction t with
    | zero => simp [start, h_zero]
    | succ t ih =>
      have h_agree := agree_run (a := s.a) h_odd t (by omega)
      have h_parity := agree_parity (by omega : t < 31) h_agree
      have h_X := ih (by omega)
      rw [Function.iterate_succ_apply']
      generalize pairStep^[t] (start s.a s.b) = w at h_parity h_X ⊢
      obtain ⟨⟨x, y⟩, ⟨X, Y⟩⟩ := w
      simp only at h_parity h_X ⊢
      subst h_X
      have h_x_even : x % 2 = 0 := by omega
      simp only [pairStep, move, if_pos h_x_even, apply, Int.zero_ediv]
  rw [(round_ab s h_odd).1, h_run 31 le_rfl]
  rfl

private theorem natAbs_eq_sign_mul (A : Int) : ((A.natAbs : Nat) : Int) = signOf A * A := by
  unfold signOf
  split_ifs with h
  · rw [Int.natCast_natAbs, abs_of_neg h]; ring
  · rw [Int.natCast_natAbs, abs_of_nonneg (not_lt.mp h)]; ring

private theorem round_factors {a b : Nat} (h_odd : b % 2 = 1) :
    let r := stepFactors (approximation (width a b) a) (approximation (width a b) b)
    2 ^ steps * (pairStep^[31] (start a b)).2.1 = a * r.1 + b * r.2.1 ∧
      2 ^ steps * (pairStep^[31] (start a b)).2.2 = a * r.2.2.1 + b * r.2.2.2 := by
  obtain ⟨h_X, h_Y⟩ := factors_represent h_odd 31 le_rfl
  have h_first : (start a b).1 =
      (((approximation (width a b) a : Nat) : Int), ((approximation (width a b) b : Nat) : Int)) :=
    rfl
  rw [h_first] at h_X h_Y
  simp only [stepFactors, steps]
  exact ⟨h_X, h_Y⟩

/-- A round keeps `a = u y` and `b = v y` modulo an odd `m`. -/
theorem round_mod {m : Nat} (h_m : m % 2 = 1) {y : ZMod m} (s : State m)
    (h_odd : s.b % 2 = 1) (h_a : (s.a : ZMod m) = s.u * y) (h_b : (s.b : ZMod m) = s.v * y) :
    ((round m s).a : ZMod m) = (round m s).u * y ∧
      ((round m s).b : ZMod m) = (round m s).v * y := by
  obtain ⟨h_X, h_Y⟩ := round_factors (a := s.a) h_odd
  obtain ⟨h_A, h_B⟩ := round_quotients (a := s.a) h_odd
  obtain ⟨h_ra, h_rb⟩ := round_ab s h_odd
  have h_unit : ((2 : ZMod m) ^ steps)⁻¹ * (2 : ZMod m) ^ steps = 1 := by
    have h_coprime : Nat.Coprime (2 ^ steps) m :=
      Nat.Coprime.pow_left _ (Nat.coprime_two_left.mpr (Nat.odd_iff.mpr h_m))
    have := ZMod.coe_mul_inv_eq_one (2 ^ steps) h_coprime
    push_cast at this
    rw [mul_comm]
    exact this
  rw [h_ra, h_rb]
  simp only [round]
  rw [h_A, h_B]
  generalize stepFactors (approximation (width s.a s.b) s.a)
    (approximation (width s.a s.b) s.b) = r at h_X h_Y ⊢
  generalize (pairStep^[31] (start s.a s.b)).2.1 = X at h_X ⊢
  generalize (pairStep^[31] (start s.a s.b)).2.2 = Y at h_Y ⊢
  have h_cast : ∀ Z : Int, ((Z.natAbs : Nat) : ZMod m) = (signOf Z : ZMod m) * (Z : ZMod m) := by
    intro Z
    rw [← Int.cast_natCast, natAbs_eq_sign_mul, Int.cast_mul]
  have h_X_mod : (2 : ZMod m) ^ steps * (X : ZMod m) = (s.u * r.1 + s.v * r.2.1) * y := by
    have := congrArg (fun z : Int => (z : ZMod m)) h_X
    push_cast at this
    rw [this, h_a, h_b]
    ring
  have h_Y_mod : (2 : ZMod m) ^ steps * (Y : ZMod m) = (s.u * r.2.2.1 + s.v * r.2.2.2) * y := by
    have := congrArg (fun z : Int => (z : ZMod m)) h_Y
    push_cast at this
    rw [this, h_a, h_b]
    ring
  constructor
  · rw [h_cast X]
    calc (signOf X : ZMod m) * (X : ZMod m)
        = (signOf X : ZMod m) * (((2 : ZMod m) ^ steps)⁻¹ * (2 : ZMod m) ^ steps * X) := by
          rw [h_unit, one_mul]
      _ = (signOf X : ZMod m) * (s.u * r.1 + s.v * r.2.1) * ((2 : ZMod m) ^ steps)⁻¹ * y := by
          rw [mul_assoc (((2 : ZMod m) ^ steps)⁻¹), h_X_mod]
          ring
  · rw [h_cast Y]
    calc (signOf Y : ZMod m) * (Y : ZMod m)
        = (signOf Y : ZMod m) * (((2 : ZMod m) ^ steps)⁻¹ * (2 : ZMod m) ^ steps * Y) := by
          rw [h_unit, one_mul]
      _ = (signOf Y : ZMod m) * (s.u * r.2.2.1 + s.v * r.2.2.2) * ((2 : ZMod m) ^ steps)⁻¹ *
            y := by
          rw [mul_assoc (((2 : ZMod m) ^ steps)⁻¹), h_Y_mod]
          ring

/-! ## The inverse -/

/-- What `k` rounds from `a = y`, `b = m`, `u = 1` and `v = 0` keep: `b` odd,
`gcd a b = gcd y m`, `a = u y` and `b = v y` modulo `m`, and `31 k` bits taken off `a` and `b`
between them unless `a` is zero. -/
theorem rounds_keep {m y : Nat} (h_m : m % 2 = 1) : ∀ k : Nat,
    ((round m)^[k] ⟨y, m, 1, 0⟩).b % 2 = 1 ∧
      Nat.gcd ((round m)^[k] ⟨y, m, 1, 0⟩).a ((round m)^[k] ⟨y, m, 1, 0⟩).b = Nat.gcd y m ∧
      (((round m)^[k] ⟨y, m, 1, 0⟩).a : ZMod m) = ((round m)^[k] ⟨y, m, 1, 0⟩).u * y ∧
      (((round m)^[k] ⟨y, m, 1, 0⟩).b : ZMod m) = ((round m)^[k] ⟨y, m, 1, 0⟩).v * y ∧
      (((round m)^[k] ⟨y, m, 1, 0⟩).a = 0 ∨
        ((round m)^[k] ⟨y, m, 1, 0⟩).a.size + ((round m)^[k] ⟨y, m, 1, 0⟩).b.size + 31 * k ≤
          y.size + m.size)
  | 0 => ⟨h_m, rfl, by simp, by simp, Or.inr (by simp)⟩
  | k + 1 => by
    obtain ⟨h_odd, h_gcd, h_a, h_b, h_len⟩ := rounds_keep h_m k
    simp only [Function.iterate_succ_apply']
    generalize (round m)^[k] ⟨y, m, 1, 0⟩ = s at h_odd h_gcd h_a h_b h_len ⊢
    obtain ⟨h_a', h_b'⟩ := round_mod h_m s h_odd h_a h_b
    refine ⟨round_b_odd s h_odd, (round_gcd s h_odd).trans h_gcd, h_a', h_b', ?_⟩
    rcases h_len with h_zero | h_len
    · exact Or.inl (round_zero s h_odd h_zero)
    · rcases round_shrinks s h_odd with h | h
      · exact Or.inl h
      · exact Or.inr (by omega)

/-- `rounds` rounds invert every `y` below an odd modulus `m` below `2 ^ 256` and coprime to
it: `p256_wide_inverse`'s answer times `y` is 1 modulo `m`. -/
theorem inverse_mul_self {m y : Nat} (h_m : m % 2 = 1) (h_m_lt : m < 2 ^ 256) (h_y : y < m)
    (h_coprime : Nat.Coprime y m) : inverse m y * y = 1 := by
  obtain ⟨h_odd, h_gcd, -, h_b, h_len⟩ := rounds_keep (y := y) h_m rounds
  have h_zero : ((round m)^[rounds] ⟨y, m, 1, 0⟩).a = 0 := by
    by_contra h_ne
    have h_size := h_len.resolve_left h_ne
    have h_y_size : y.size ≤ 256 := Nat.size_le.mpr (by omega)
    have h_m_size : m.size ≤ 256 := Nat.size_le.mpr h_m_lt
    have h_a_size : 0 < ((round m)^[rounds] ⟨y, m, 1, 0⟩).a.size :=
      Nat.size_pos.mpr (Nat.pos_of_ne_zero h_ne)
    have h_b_size : 0 < ((round m)^[rounds] ⟨y, m, 1, 0⟩).b.size :=
      Nat.size_pos.mpr (by omega)
    simp only [rounds] at h_size
    omega
  rw [h_zero, Nat.gcd_zero_left, h_coprime] at h_gcd
  rw [h_gcd, Nat.cast_one] at h_b
  exact h_b.symm

private theorem factors_of_zero (z : Int) :
    ∀ t, factorStep^[t] ((0, z), (1, 0, 0, 1)) = ((0, z), (1, 0, 0, 2 ^ t))
  | 0 => by simp
  | t + 1 => by
    rw [Function.iterate_succ_apply', factors_of_zero z t]
    simp [factorStep, move, apply, applyFactors, pow_succ, mul_comm]

/-- `rounds` rounds send 0 to 0, as `p256_wide_inverse` does. -/
theorem inverse_zero (m : Nat) : inverse m 0 = 0 := by
  have h : ∀ k, ((round m)^[k] ⟨0, m, 1, 0⟩).a = 0 ∧ ((round m)^[k] ⟨0, m, 1, 0⟩).v = 0 := by
    intro k
    induction k with
    | zero => exact ⟨rfl, rfl⟩
    | succ k ih =>
      rw [Function.iterate_succ_apply']
      generalize (round m)^[k] ⟨0, m, 1, 0⟩ = s at ih ⊢
      obtain ⟨a, b, u, v⟩ := s
      obtain ⟨h_a, h_v⟩ := ih
      simp only at h_a h_v
      subst h_a h_v
      have h_zero : approximation (width 0 b) 0 = 0 := by
        unfold approximation
        split_ifs <;> simp
      have h_r : stepFactors (approximation (width 0 b) 0) (approximation (width 0 b) b) =
          (1, 0, 0, 2 ^ steps) := by
        rw [h_zero]
        exact congrArg Prod.snd (factors_of_zero _ steps)
      simp only [round, h_r]
      simp
  exact (h rounds).2

/-! ## At P-256 -/

/-- `p256_wide_fe_inv`'s binary GCD inverts every element from 1 to `p - 1` of the field
`Spec.P256.p` names, with `p` prime as a hypothesis. -/
theorem inverse_mul_self_p [h_prime : Fact Spec.P256.p.Prime] {y : Nat} (h_pos : 0 < y)
    (h_y : y < Spec.P256.p) : inverse Spec.P256.p y * y = 1 :=
  inverse_mul_self (by decide) (by decide) h_y
    ((Nat.Prime.coprime_iff_not_dvd h_prime.out).mpr (Nat.not_dvd_of_pos_of_lt h_pos h_y)).symm

/-- `p256_wide_scalar_inverse`'s binary GCD inverts every scalar from 1 to `n - 1` modulo the
group order `Spec.P256.n`, with `n` prime as a hypothesis. -/
theorem inverse_mul_self_n [h_prime : Fact Spec.P256.n.Prime] {y : Nat} (h_pos : 0 < y)
    (h_y : y < Spec.P256.n) : inverse Spec.P256.n y * y = 1 :=
  inverse_mul_self (by decide) (by decide) h_y
    ((Nat.Prime.coprime_iff_not_dvd h_prime.out).mpr (Nat.not_dvd_of_pos_of_lt h_pos h_y)).symm

set_option compiler.extract_closed false in
/-- `inverse` against the definition of an inverse at both P-256 moduli: `y` times its inverse is
1 for 1, 2, 3, `m - 1`, `m - 2`, `2 ^ 255`, values of 64 bits and fewer, where the
approximations are exact, and values on either side of word boundaries; and 0 goes to 0. -/
def selftest (_ : Unit) : Bool :=
  let check := fun (m : Nat) =>
    let values := [1, 2, 3, m - 1, m - 2, 2 ^ 255, 2 ^ 64 - 1, 2 ^ 64, 2 ^ 64 + 1, 2 ^ 128 - 1,
      2 ^ 192 + 2 ^ 63, 0x1234567890abcdef, 0x6b8e05f5ee0f8b25101f13b6dc3d514c,
      0x5555666677778888111122223333444409876543210fedcba987654321fedcba]
    values.all (fun y => ((inverse m y * y : ZMod m) == 1)) && (inverse m 0 == 0)
  check Spec.P256.p && check Spec.P256.n

end Spec.P256WideInverse
