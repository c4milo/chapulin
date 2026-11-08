import Mathlib.Tactic
import Spec.MlDsa

/-!
The compaction `mlds_eta_from_stream` in `mldsa_sign_pack.c` runs for
FIPS 204 Algorithm 31, RejBoundedPoly (docs/decisions.md 176).

RejBoundedPoly keeps each half-byte under 15 and drops each 15. The C
gives each half-byte an entry: a kept one holds its value and its move,
the count of 15s before it, and a dropped one holds nothing. Then pass
`b`, for `b` from 0 to 9, writes each position `p` from two entries: the
one at `p + 2^b` when its move has bit `b`, and the one at `p` when its
move does not. A mask chooses at every position, so no branch reads the
stream.

`final_eq` proves that after enough passes position `p` holds the
`p`-th kept entry, in order, and `etaFromStream_eq` that the C's ten passes
over 481 bytes give `Spec.MlDsa.rejBoundedStream`, RejBoundedPoly's loop.
`pass_never_both` proves that no pass finds both entries chosen, so the
C's OR of the two masked entries is the choice this model makes.

The half-bytes are a function `z` and a count `n`, as the C reads them
from its array. The C's model is `choose`, `pass` and `start`;
`proof/mldsa_sign_samplers_harness.c` holds the C's 16-bit entries to
them.
-/

namespace Spec.MlDsaEta

/-- An entry: a kept value and its move, or nothing. -/
abbrev Entry := Option (Int × Nat)

/-- FIPS 204 Algorithm 15, CoeffFromHalfByte, at eta = 2. -/
def value (z : Nat) : Int := 2 - ((z % 5 : Nat) : Int)

/-- The count of 15s, half-bytes of 15 or more, among the first `i`. The C
counts them in `rejected` as it writes the entries. -/
def rejected (z : Nat → Nat) : Nat → Nat
  | 0 => 0
  | i + 1 => rejected z i + if z i < 15 then 0 else 1

/-- `eta_entry`: half-byte `i`'s entry, and nothing at or past `n`. -/
def start (z : Nat → Nat) (n : Nat) (i : Nat) : Entry :=
  if i < n ∧ z i < 15 then some (value (z i), rejected z i) else none

/-- `eta_choose`: the entry above when its move has bit `b`, else the entry
here when its move does not, else nothing. -/
def choose (b : Nat) (here above : Entry) : Entry :=
  match above with
  | some (v, m) => if m.testBit b then some (v, m) else
      match here with
      | some (w, k) => if k.testBit b then none else some (w, k)
      | none => none
  | none =>
      match here with
      | some (w, k) => if k.testBit b then none else some (w, k)
      | none => none

/-- `eta_pass` for bit `b`. Past the 962 entries `eta_entry` writes, the C
reads 0, an empty entry, from the zero entries its array holds above them. -/
def pass (b : Nat) (s : Nat → Entry) : Nat → Entry :=
  fun p => choose b (s p) (s (p + 2 ^ b))

/-- The passes for bits 0 to `count - 1`, in increasing order. -/
def passes : Nat → (Nat → Entry) → Nat → Entry
  | 0, s => s
  | count + 1, s => pass count (passes count s)

/-- Both entries are chosen at one position: the one above moves and the
one here stays. The C ORs the two masked entries, which is `choose` only
when this never holds. -/
def both (b : Nat) (here above : Entry) : Prop :=
  (∃ v m, above = some (v, m) ∧ m.testBit b) ∧ (∃ w k, here = some (w, k) ∧ ¬k.testBit b)

/-- The kept entries among the first `n`, in order: what RejBoundedPoly's
loop writes. -/
def kept (z : Nat → Nat) (n : Nat) : List (Int × Nat) :=
  (List.range n).filterMap fun i => if z i < 15 then some (value (z i), rejected z i) else none

section Moves

variable (z : Nat → Nat)

theorem rejected_le (i : Nat) : rejected z i ≤ i := by
  induction i with
  | zero => simp [rejected]
  | succ i ih => simp only [rejected]; split_ifs <;> omega

theorem rejected_mono {i j : Nat} (h_le : i ≤ j) : rejected z i ≤ rejected z j := by
  induction j, h_le using Nat.le_induction with
  | base => rfl
  | succ j _ ih => simp only [rejected]; split_ifs <;> omega

/-- Past a kept half-byte `i`, at most `j - i - 1` of the next `j - i` are
15s. -/
theorem rejected_gap {i j : Nat} (h_lt : i < j) (h_kept : z i < 15) :
    rejected z j + i + 1 ≤ rejected z i + j := by
  induction j, h_lt using Nat.le_induction with
  | base => simp [rejected, h_kept]
  | succ j _ ih => simp only [rejected]; split_ifs <;> omega

/-- A kept entry's position after the passes for bits below `b`. -/
def pos (b i : Nat) : Nat := i - rejected z i % 2 ^ b

theorem pos_zero (i : Nat) : pos z 0 i = i := by simp [pos, Nat.mod_one]

/-- Pass `b` moves a kept entry down by `2^b` when its move has bit `b`. -/
theorem pos_succ (b i : Nat) :
    pos z (b + 1) i = pos z b i - (if (rejected z i).testBit b then 2 ^ b else 0) := by
  have h_split : rejected z i % 2 ^ (b + 1)
      = rejected z i % 2 ^ b + 2 ^ b * (rejected z i / 2 ^ b % 2) := Nat.mod_pow_succ
  have h_bit : (rejected z i).testBit b = decide (rejected z i / 2 ^ b % 2 = 1) :=
    Nat.testBit_eq_decide_div_mod_eq
  simp only [pos, h_split, Nat.sub_sub]
  rcases Nat.mod_two_eq_zero_or_one (rejected z i / 2 ^ b) with h | h <;> simp [h_bit, h]

/-- An entry that pass `b` moves sits at least `2^b` up. -/
theorem pos_ge_of_bit {b i : Nat} (h_bit : (rejected z i).testBit b) :
    2 ^ b ≤ pos z b i := by
  have h_split : rejected z i % 2 ^ (b + 1)
      = rejected z i % 2 ^ b + 2 ^ b * (rejected z i / 2 ^ b % 2) := Nat.mod_pow_succ
  have h_one : rejected z i / 2 ^ b % 2 = 1 := by
    simpa [Nat.testBit_eq_decide_div_mod_eq] using h_bit
  have h_le : rejected z i % 2 ^ (b + 1) ≤ i :=
    (Nat.mod_le _ _).trans (rejected_le z i)
  simp only [pos]
  rw [h_split, h_one] at h_le
  omega

/-- No two kept entries share a position after any number of passes. -/
theorem pos_injective {b i j : Nat} (h_lt : i < j) (h_kept : z i < 15)
    (h_pos : pos z b i = pos z b j) : False := by
  have h_gap := rejected_gap z h_lt h_kept
  have h_mono := rejected_mono z h_lt.le
  have h_i := Nat.mod_add_div (rejected z i) (2 ^ b)
  have h_j := Nat.mod_add_div (rejected z j) (2 ^ b)
  have h_mi := Nat.mod_lt (rejected z i) (Nat.two_pow_pos b)
  have h_mj := Nat.mod_lt (rejected z j) (Nat.two_pow_pos b)
  have h_li := (Nat.mod_le (rejected z i) (2 ^ b)).trans (rejected_le z i)
  have h_lj := (Nat.mod_le (rejected z j) (2 ^ b)).trans (rejected_le z j)
  simp only [pos] at h_pos
  rcases Nat.lt_or_ge (rejected z j / 2 ^ b) (rejected z i / 2 ^ b) with h_q | h_q
  · have h_step : 2 ^ b * (rejected z j / 2 ^ b) + 2 ^ b ≤ 2 ^ b * (rejected z i / 2 ^ b) := by
      rw [← Nat.mul_succ]; exact Nat.mul_le_mul_left _ h_q
    omega
  · have h_step : 2 ^ b * (rejected z i / 2 ^ b) ≤ 2 ^ b * (rejected z j / 2 ^ b) :=
      Nat.mul_le_mul_left _ h_q
    omega

end Moves

section Passes

variable (z : Nat → Nat) (n : Nat)

/-- What position `p` holds after the passes for bits below `b`: the kept
entry whose position is `p`, if one is. -/
def ideal (b p : Nat) : Entry :=
  ((List.range n).find? fun i => decide (z i < 15 ∧ pos z b i = p)).map
    fun i => (value (z i), rejected z i)

theorem ideal_of_kept {b p i : Nat} (h_n : i < n) (h_kept : z i < 15) (h_pos : pos z b i = p) :
    ideal z n b p = some (value (z i), rejected z i) := by
  have h_find : (List.range n).find? (fun i => decide (z i < 15 ∧ pos z b i = p)) = some i := by
    rw [List.find?_eq_some_iff_getElem]
    refine ⟨by simp [h_kept, h_pos], i, by simpa using h_n, by simp, ?_⟩
    intro k h_k
    simp only [List.getElem_range, Bool.not_eq_eq_eq_not, Bool.not_true, decide_eq_false_iff_not,
      not_and]
    intro h_kept_k h_pos_k
    exact pos_injective z h_k h_kept_k (h_pos_k.trans h_pos.symm)
  simp only [ideal, h_find, Option.map_some]

theorem ideal_of_none {b p : Nat} (h_none : ∀ i < n, z i < 15 → pos z b i ≠ p) :
    ideal z n b p = none := by
  simp only [ideal, Option.map_eq_none_iff, List.find?_eq_none, List.mem_range,
    decide_eq_true_eq, not_and]
  exact fun i h_n h_kept => h_none i h_n h_kept

/-- What `ideal` holds is a kept entry at its position. -/
theorem ideal_spec {b p : Nat} {e : Int × Nat} (h_e : ideal z n b p = some e) :
    ∃ i < n, z i < 15 ∧ pos z b i = p ∧ e = (value (z i), rejected z i) := by
  simp only [ideal, Option.map_eq_some_iff] at h_e
  obtain ⟨i, h_find, rfl⟩ := h_e
  have h_mem := List.mem_of_find?_eq_some h_find
  have h_true := List.find?_some h_find
  simp only [decide_eq_true_eq] at h_true
  exact ⟨i, List.mem_range.mp h_mem, h_true.1, h_true.2, rfl⟩

theorem start_eq_ideal : start z n = ideal z n 0 := by
  funext p
  by_cases h : p < n ∧ z p < 15
  · rw [ideal_of_kept z n h.1 h.2 (pos_zero z p)]
    simp [start, h]
  · rw [ideal_of_none z n]
    · simp [start, h]
    · intro i h_n h_kept h_pos
      rw [pos_zero] at h_pos
      subst h_pos
      exact h ⟨h_n, h_kept⟩

/-- Pass `b` takes `ideal` for bits below `b` to `ideal` for bits below
`b + 1`. -/
theorem pass_ideal (b : Nat) : pass b (ideal z n b) = ideal z n (b + 1) := by
  funext p
  simp only [pass]
  by_cases h_some : ∃ i < n, z i < 15 ∧ pos z (b + 1) i = p
  · obtain ⟨i, h_n, h_kept, h_pos⟩ := h_some
    rw [ideal_of_kept z n h_n h_kept h_pos]
    rw [pos_succ] at h_pos
    by_cases h_bit : (rejected z i).testBit b
    · have h_ge := pos_ge_of_bit z h_bit
      rw [if_pos h_bit] at h_pos
      rw [ideal_of_kept z n h_n h_kept (show pos z b i = p + 2 ^ b by omega)]
      simp [choose, h_bit]
    · rw [if_neg h_bit, Nat.sub_zero] at h_pos
      rw [ideal_of_kept z n h_n h_kept h_pos]
      cases h_above : ideal z n b (p + 2 ^ b) with
      | none => simp [choose, h_bit]
      | some e =>
          obtain ⟨k, _, h_kept_k, h_pos_k, rfl⟩ := ideal_spec z n h_above
          have h_moved : ¬(rejected z k).testBit b := by
            intro h_bit_k
            have h_ge := pos_ge_of_bit z h_bit_k
            have h_same : pos z (b + 1) k = pos z (b + 1) i := by
              rw [pos_succ, pos_succ, if_pos h_bit_k, if_neg h_bit]; omega
            rcases Nat.lt_trichotomy i k with h_ik | rfl | h_ki
            · exact pos_injective z h_ik h_kept h_same.symm
            · exact h_bit h_bit_k
            · exact pos_injective z h_ki h_kept_k h_same
          simp [choose, h_bit, h_moved]
  · push Not at h_some
    rw [ideal_of_none z n h_some]
    have h_no_move : ∀ e, ideal z n b (p + 2 ^ b) = some e → ¬e.2.testBit b := by
      intro e h_e h_bit
      obtain ⟨k, h_n, h_kept, h_pos, rfl⟩ := ideal_spec z n h_e
      have h_ge := pos_ge_of_bit z h_bit
      refine h_some k h_n h_kept ?_
      rw [pos_succ, if_pos h_bit]; omega
    have h_no_stay : ∀ e, ideal z n b p = some e → e.2.testBit b := by
      intro e h_e
      obtain ⟨k, h_n, h_kept, h_pos, rfl⟩ := ideal_spec z n h_e
      by_contra h_bit
      refine h_some k h_n h_kept ?_
      rw [pos_succ, if_neg h_bit]; omega
    cases h_above : ideal z n b (p + 2 ^ b) with
    | some e =>
        have h_bit := h_no_move e h_above
        cases h_here : ideal z n b p with
        | none => simp [choose, h_bit]
        | some f => simp [choose, h_bit, h_no_stay f h_here]
    | none =>
        cases h_here : ideal z n b p with
        | none => simp [choose]
        | some f => simp [choose, h_no_stay f h_here]

theorem passes_ideal (count : Nat) : passes count (start z n) = ideal z n count := by
  induction count with
  | zero => simp [passes, start_eq_ideal]
  | succ count ih => simp [passes, ih, pass_ideal]

/-- No pass of the run finds both entries chosen at one position. -/
theorem pass_never_both (b p : Nat) :
    ¬both b (passes b (start z n) p) (passes b (start z n) (p + 2 ^ b)) := by
  rw [passes_ideal]
  rintro ⟨⟨v, m, h_above, h_move⟩, ⟨w, k, h_here, h_stay⟩⟩
  obtain ⟨i, _, h_kept_i, h_pos_i, h_e⟩ := ideal_spec z n h_above
  obtain ⟨j, _, h_kept_j, h_pos_j, h_f⟩ := ideal_spec z n h_here
  simp only [Prod.mk.injEq] at h_e h_f
  rw [h_e.2] at h_move
  rw [h_f.2] at h_stay
  have h_ge := pos_ge_of_bit z h_move
  have h_same : pos z (b + 1) i = pos z (b + 1) j := by
    rw [pos_succ, pos_succ, if_pos h_move, if_neg h_stay]; omega
  rcases Nat.lt_trichotomy i j with h_ij | rfl | h_ji
  · exact pos_injective z h_ij h_kept_i h_same
  · exact h_stay h_move
  · exact pos_injective z h_ji h_kept_j h_same.symm

end Passes

section Final

variable (z : Nat → Nat)

theorem kept_succ (n : Nat) :
    kept z (n + 1) = kept z n ++
      (if z n < 15 then [(value (z n), rejected z n)] else []) := by
  simp only [kept, List.range_succ, List.filterMap_append]
  split_ifs <;> simp [*]

theorem kept_length (n : Nat) : (kept z n).length + rejected z n = n := by
  induction n with
  | zero => simp [kept, rejected]
  | succ n ih =>
      rw [kept_succ]
      simp only [rejected]
      split_ifs <;> simp <;> omega

/-- After passes for every bit a move can hold, position `p` holds the
`p`-th kept entry, or nothing past the last one. -/
theorem final_eq {n count : Nat} (h_fits : n ≤ 2 ^ count) (p : Nat) :
    passes count (start z n) p = (kept z n)[p]? := by
  rw [passes_ideal]
  induction n generalizing p with
  | zero =>
      rw [ideal_of_none z 0 (by simp)]
      simp [kept]
  | succ n ih =>
      have h_low : ∀ i ≤ n, pos z count i = i - rejected z i := by
        intro i h_i
        have h_lt : rejected z i < 2 ^ count := by
          have := rejected_le z i; omega
        simp [pos, Nat.mod_eq_of_lt h_lt]
      have h_len := kept_length z n
      have h_prev := ih (by omega)
      rw [kept_succ]
      by_cases h_new : z n < 15 ∧ p = n - rejected z n
      · obtain ⟨h_kept, rfl⟩ := h_new
        rw [ideal_of_kept z (n + 1) (Nat.lt_succ_self n) h_kept (h_low n le_rfl)]
        rw [if_pos h_kept, List.getElem?_append_right (by omega)]
        simp [show n - rejected z n - (kept z n).length = 0 by omega]
      · have h_old : ideal z (n + 1) count p = ideal z n count p := by
          by_cases h_some : ∃ i < n, z i < 15 ∧ pos z count i = p
          · obtain ⟨i, h_i, h_kept, h_pos⟩ := h_some
            rw [ideal_of_kept z (n + 1) (by omega) h_kept h_pos,
              ideal_of_kept z n h_i h_kept h_pos]
          · push Not at h_some
            rw [ideal_of_none z n h_some, ideal_of_none z (n + 1)]
            intro i h_i h_kept h_pos
            rcases Nat.lt_succ_iff_lt_or_eq.mp h_i with h_i | rfl
            · exact h_some i h_i h_kept h_pos
            · exact h_new ⟨h_kept, by rw [← h_pos, h_low i le_rfl]⟩
        rw [h_old, h_prev p]
        by_cases h_p : p < (kept z n).length
        · rw [List.getElem?_append_left h_p]
        · have h_none : (kept z n)[p]? = none := List.getElem?_eq_none (by omega)
          rw [h_none]
          split_ifs with h_kept
          · have h_ne : p ≠ n - rejected z n := fun h => h_new ⟨h_kept, h⟩
            rw [List.getElem?_eq_none (by simp; omega)]
          · simp [List.getElem?_eq_none (by omega : (kept z n).length ≤ p)]

end Final

section Stream

open Spec.MlDsa (etaStreamBytes rejBoundedStream)

/-- Half-byte `i` of the stream, the low half of byte `i / 2` first. -/
def halves (s : ByteArray) (i : Nat) : Nat :=
  if i % 2 = 0 then s[i / 2]!.toNat % 16 else s[i / 2]!.toNat / 16

/-- `mlds_eta_from_stream`: the entries of the 962 half-bytes, ten passes,
then the first 256 positions, an empty one read as -2, and the verdict
from `rejected`. -/
def etaFromStream (s : ByteArray) : Option (Array Int) :=
  let n := 2 * etaStreamBytes
  let final := passes 10 (start (halves s) n)
  if 256 ≤ n - rejected (halves s) n then
    some ((List.range 256).map fun p => ((final p).map Prod.fst).getD (-2)).toArray
  else none

theorem flatMap_pairs (x y : Nat → Nat) (m : Nat) :
    (List.range m).flatMap (fun b => [x b, y b])
      = (List.range (2 * m)).map fun i => if i % 2 = 0 then x (i / 2) else y (i / 2) := by
  induction m with
  | zero => simp
  | succ m ih =>
      rw [List.range_succ, List.flatMap_append, ih, show 2 * (m + 1) = 2 * m + 1 + 1 by ring,
        List.range_succ, List.range_succ]
      simp [Nat.mul_add_div]

/-- The C's model gives RejBoundedPoly's loop on every stream. -/
theorem etaFromStream_eq (s : ByteArray) : etaFromStream s = rejBoundedStream s := by
  set z := halves s
  set n := 2 * etaStreamBytes
  have h_list : (List.range etaStreamBytes).flatMap
      (fun b => [s[b]!.toNat % 16, s[b]!.toNat / 16]) = (List.range n).map z := by
    rw [flatMap_pairs]; rfl
  have h_values : ((List.range n).map z).filterMap
      (fun v => if v < 15 then some ((2 : Int) - ((v % 5 : Nat) : Int)) else none)
      = (kept z n).map Prod.fst := by
    simp only [kept, List.filterMap_map, List.map_filterMap]
    congr 1; funext i; split_ifs with h_kept <;> simp [value, h_kept]
  have h_len := kept_length z n
  simp only [etaFromStream, rejBoundedStream, h_list, h_values, List.length_map]
  rw [show n - rejected z n = (kept z n).length by omega]
  split_ifs with h_enough
  · refine congrArg (fun l : List Int => some l.toArray) ?_
    apply List.ext_getElem (by simp; omega)
    intro p h_p _
    simp only [List.length_map, List.length_range] at h_p
    have h_final : passes 10 (start (halves s) (2 * etaStreamBytes)) p = (kept z n)[p]? :=
      final_eq (halves s) (show 2 * etaStreamBytes ≤ 2 ^ 10 by simp only [etaStreamBytes]; norm_num) p
    have h_in : p < (kept z n).length := by omega
    simp only [List.getElem_map, List.getElem_range, List.getElem_take, h_final,
      List.getElem?_eq_getElem h_in, Option.map_some, Option.getD_some]
  · rfl

end Stream

end Spec.MlDsaEta
