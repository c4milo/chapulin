import Mathlib

/-!
# The blinded exponent of the RSA ladder

`rsa_sp1` (rsa_sign.c) runs its ladder over `d + r (65537 d - 1)` in
place of the private exponent `d`, for a fresh 64-bit `r` each signature
(docs/decisions.md 186). This module proves that the power is the same
modulo `n = p q` for every base and every `r`.

The hypotheses are what an RSA key with the public exponent 65537 gives:
`65537 d ≡ 1` modulo `λ(n) = lcm(p - 1, q - 1)`, which is that `p - 1` and
`q - 1` both divide `65537 d - 1`. The proof needs no hypothesis on the
base: a base that shares a factor with `n` holds too, because `d ≥ 1`.

`blinded_exponent` computes the product `r t` by 64 passes over `r`'s bits
from the top down, each `exponent := 2 exponent + bit t` (`blind_pass`).
`passes` models that loop and `passes_eq` proves it writes `r t`. The
`rsa_sign_blind` harness holds `blind_pass` and `scale_minus_one`, the
step that writes `t = 65537 d - 1`, to those formulas at one word.
-/

namespace Spec.RsaBlind

/-- The exponent the ladder walks: `d + r (65537 d - 1)`. -/
def blindedExponent (d r : ℕ) : ℕ := d + r * (65537 * d - 1)

/-- One pass of the C's product: `acc` doubled, plus `t` where bit `j` of
`r` is set, as `blind_pass` runs it. -/
def pass (t r acc j : ℕ) : ℕ := 2 * acc + (r.testBit j).toNat * t

/-- The passes over bits `k - 1` down to `0`, from `acc`, as
`blinded_exponent`'s loop runs them. -/
def passes (t r : ℕ) : ℕ → ℕ → ℕ
  | 0, acc => acc
  | k + 1, acc => passes t r k (pass t r acc k)

/-- The passes over `k` bits write `2^k acc + (r mod 2^k) t`. -/
theorem passes_eq (t r k acc : ℕ) : passes t r k acc = 2 ^ k * acc + r % 2 ^ k * t := by
  induction k generalizing acc with
  | zero => simp [passes, Nat.mod_one]
  | succ k h_induction =>
    have h_mod : r % 2 ^ (k + 1) = 2 ^ k * (r.testBit k).toNat + r % 2 ^ k := by
      rw [Nat.mod_pow_succ, Nat.add_comm, Nat.toNat_testBit]
    rw [passes, h_induction, pass, h_mod, pow_succ]
    ring

/-- The C's whole exponent: 64 passes from zero over `t = 65537 d - 1`,
then `d` added, is `blindedExponent d r` for every 64-bit `r`. -/
theorem blinded_exponent_eq {d r : ℕ} (h_r : r < 2 ^ 64) :
    d + passes (65537 * d - 1) r 64 0 = blindedExponent d r := by
  rw [passes_eq, Nat.mod_eq_of_lt h_r, blindedExponent]
  ring

/-- One prime's half: raising to `d + r t` is raising to `d`, modulo a
prime `p` with `p - 1` dividing `t`. -/
theorem pow_add_mul_modEq {p d m r t : ℕ} (h_prime : p.Prime) (h_d : 1 ≤ d)
    (h_divides : p - 1 ∣ t) : m ^ (d + r * t) ≡ m ^ d [MOD p] := by
  by_cases h_m : p ∣ m
  · have h_left : p ∣ m ^ (d + r * t) := dvd_pow h_m (by omega)
    have h_right : p ∣ m ^ d := dvd_pow h_m (by omega)
    exact (Nat.modEq_zero_iff_dvd.2 h_left).trans (Nat.modEq_zero_iff_dvd.2 h_right).symm
  · have h_coprime : m.Coprime p :=
      Nat.Coprime.symm ((Nat.Prime.coprime_iff_not_dvd h_prime).2 h_m)
    have h_fermat : m ^ (p - 1) ≡ 1 [MOD p] := by
      have h_euler := Nat.ModEq.pow_totient h_coprime
      rwa [Nat.totient_prime h_prime] at h_euler
    obtain ⟨c, rfl⟩ := h_divides
    have h_split : m ^ (d + r * ((p - 1) * c)) = m ^ d * (m ^ (p - 1)) ^ (r * c) := by
      rw [pow_add, ← pow_mul]
      congr 2
      ring
    calc m ^ (d + r * ((p - 1) * c)) = m ^ d * (m ^ (p - 1)) ^ (r * c) := h_split
      _ ≡ m ^ d * 1 ^ (r * c) [MOD p] := (Nat.ModEq.refl _).mul (h_fermat.pow _)
      _ = m ^ d := by simp

/-- The blinding keeps the signature: for distinct primes `p` and `q` and a
private exponent `d` of the public exponent 65537, raising any `m` to the
blinded exponent gives `m ^ d` modulo `p q`, for every `r`. -/
theorem blinded_pow_mod {p q d m r : ℕ} (h_p : p.Prime) (h_q : q.Prime) (h_distinct : p ≠ q)
    (h_d : 1 ≤ d) (h_p_divides : p - 1 ∣ 65537 * d - 1) (h_q_divides : q - 1 ∣ 65537 * d - 1) :
    m ^ blindedExponent d r % (p * q) = m ^ d % (p * q) := by
  have h_coprime : p.Coprime q := (Nat.coprime_primes h_p h_q).2 h_distinct
  exact (Nat.modEq_and_modEq_iff_modEq_mul h_coprime).1
    ⟨pow_add_mul_modEq h_p h_d h_p_divides, pow_add_mul_modEq h_q h_d h_q_divides⟩

end Spec.RsaBlind
