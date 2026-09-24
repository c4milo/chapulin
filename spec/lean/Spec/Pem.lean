import Spec.Bytes

/-!
# RFC 7468 textual encoding, decode side

Written from RFC 7468 §2 (encapsulation boundaries) and §3 (the ABNF),
and RFC 4648 §4 (the base64 alphabet) and §3.5 (canonical padding).

Two rules here are chapulin's profile rather than an RFC requirement,
and are stated in `pem.h`:

* one CERTIFICATE block per input, so nothing but line terminators may
  follow the END boundary;
* a byte cap on the text, derived from the DER cap so that every
  certificate the parser admits fits at every line width of four
  characters or more, CRLF included — the floor `pemMax`'s terminator
  budget is sized for. Narrower wraps spend more bytes on terminators
  than the cap budgets, and a full-cap certificate at width 1 is over
  it: same DER, accepted at one width and over the cap at another.

Two more departures from the RFCs, both narrowing:

* RFC 7468 §5.2 permits explanatory text before the BEGIN boundary.
  This grammar does not, because a provisioning blob carries one block
  and nothing else.
* RFC 7468 §3's ABNF is `eol = CRLF / CR / LF`, so a bare CR ends a
  line there. Here it does not: a terminator is LF or CR then LF. An
  operator's tooling emits one of those, and admitting a third spelling
  would widen the grammar for no deployment that needs it.
-/

namespace Spec.Pem

open Spec.Bytes

/-- RFC 7468 §2: the pre-encapsulation boundary for a certificate. -/
def beginLine : List UInt8 := (ascii "-----BEGIN CERTIFICATE-----").toList
/-- RFC 7468 §2: the post-encapsulation boundary for a certificate. -/
def endLine : List UInt8 := (ascii "-----END CERTIFICATE-----").toList

/-- RFC 4648 §4: `A-Z` → 0..25, `a-z` → 26..51, `0-9` → 52..61,
`+` → 62, `/` → 63. Every other byte is outside the alphabet. -/
def b64Value? (c : UInt8) : Option Nat :=
  if c ≥ 65 ∧ c ≤ 90 then some (c.toNat - 65)
  else if c ≥ 97 ∧ c ≤ 122 then some (c.toNat - 97 + 26)
  else if c ≥ 48 ∧ c ≤ 57 then some (c.toNat - 48 + 52)
  else if c == 43 then some 62
  else if c == 47 then some 63
  else none

/-- One line terminator: LF, or CR then LF. A lone CR ends no line. -/
def eatEol? (cs : List UInt8) : Option (List UInt8) :=
  match cs with
  | 13 :: 10 :: r => some r
  | 10 :: r => some r
  | _ => none

/-- Six bits at a time, emitting a byte whenever eight have arrived.
`acc` holds only the bits not yet emitted, so it stays below `2 ^ nbits`.
Output accumulates in reverse and `b64Decode?` reverses once: appending
to the tail would make a 2048-character body quadratic, and the
differential rows run bodies that long. -/
def b64Fold (st : List UInt8 × Nat × Nat) (v : Nat) : List UInt8 × Nat × Nat :=
  let (out, acc, nbits) := st
  let acc := acc * 64 + v
  let nbits := nbits + 6
  if nbits ≥ 8 then
    (UInt8.ofNat (acc / 2 ^ (nbits - 8)) :: out, acc % 2 ^ (nbits - 8), nbits - 8)
  else
    (out, acc, nbits)

/-- RFC 4648 §4 with §3.5's canonical padding: the characters must close
their last quantum, at most two pads and only at the end, and the bits
the padding stands for must be zero. An empty body decodes to nothing
and is rejected, since a certificate has content. -/
def b64Decode? (cs : List UInt8) : Option ByteArray := do
  let npad := (cs.reverse.takeWhile (· == 61)).length
  guard (npad ≤ 2)
  let body := cs.take (cs.length - npad)
  guard (body.length ≠ 0)
  guard ((body.length + npad) % 4 == 0)
  let vals ← body.mapM b64Value?
  let (out, acc, _) := vals.foldl b64Fold ([], 0, 0)
  guard (acc == 0)
  some (ByteArray.mk out.reverse.toArray)

/-- The text cap. Base64 spends four characters per three bytes; the
budget of two terminator bytes per four characters covers CRLF wrapping
down to four characters a line; 64 bytes cover the two boundary lines
and their terminators. -/
def pemMax (derMax : Nat) : Nat :=
  let body := 4 * ((derMax + 2) / 3)
  body + (body / 4) * 2 + 64

/-- One CERTIFICATE block to the DER it carries. CR and LF are ignored
anywhere in the body, so every armoured text that fits the cap decodes
to the same DER regardless of how it was wrapped. Whether it FITS
depends on the width: below four characters a line the terminators
outgrow `pemMax`'s budget at full cap. -/
def decode? (derMax : Nat) (input : ByteArray) : Option ByteArray := do
  guard (input.size ≤ pemMax derMax)
  let cs := input.toList
  guard (beginLine.isPrefixOf cs)
  let rest ← eatEol? (cs.drop beginLine.length)
  let body := rest.takeWhile (· ≠ 45)
  let after := rest.drop body.length
  guard (endLine.isPrefixOf after)
  let tail := after.drop endLine.length
  guard (tail.all (fun c => c == 13 ∨ c == 10))
  let der ← b64Decode? (body.filter (fun c => c ≠ 13 ∧ c ≠ 10))
  guard (der.size ≤ derMax)
  some der

/-- Armours DER at a given line width, for the selftest and for rows
the differential driver wants stated once. -/
def encode (width : Nat) (der : ByteArray) : ByteArray := Id.run do
  let alphabet := ascii "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
  let mut chars : List UInt8 := []
  let n := der.size
  for i in [0:(n + 2) / 3] do
    let o := i * 3
    let b0 := der[o]!.toNat
    let b1 := if o + 1 < n then der[o + 1]!.toNat else 0
    let b2 := if o + 2 < n then der[o + 2]!.toNat else 0
    let v := b0 * 65536 + b1 * 256 + b2
    chars := chars ++ [alphabet[v / 262144]!, alphabet[(v / 4096) % 64]!,
      if o + 1 < n then alphabet[(v / 64) % 64]! else 61,
      if o + 2 < n then alphabet[v % 64]! else 61]
  let mut out := beginLine ++ [10]
  let w := if width == 0 then chars.length + 1 else width
  let mut col := 0
  for c in chars do
    out := out ++ [c]
    col := col + 1
    if col == w then
      out := out ++ [10]
      col := 0
  if col ≠ 0 then out := out ++ [10]
  return ByteArray.mk (out ++ endLine ++ [10]).toArray

/-- RFC 4648 §10's published vectors, then the properties the C relies
on: every line width decodes alike, and each rejection shape is caught. -/
def selftest : Bool :=
  let cap := 1536
  let rt (s : String) : Bool :=
    match decode? cap (encode 64 (ascii s)) with
    | some d => d.toList == (ascii s).toList
    | none => s == ""
  let vec (s expect : String) : Bool :=
    let armored := encode 0 (ascii s)
    let body := (armored.toList.drop (beginLine.length + 1)).takeWhile (· ≠ 45)
    String.ofList (body.filter (fun c => c ≠ 10) |>.map (fun c => Char.ofNat c.toNat)) == expect
  let der := ascii "any twenty-nine byte string!!"
  let widths := [4, 8, 16, 60, 64, 76, 0]
  let sameEverywhere := widths.all (fun w =>
    match decode? cap (encode w der) with
    | some d => d.toList == der.toList
    | none => false)
  let reject (f : List UInt8 → List UInt8) : Bool :=
    (decode? cap (ByteArray.mk (f (encode 64 der).toList).toArray)).isNone
  vec "f" "Zg==" ∧ vec "fo" "Zm8=" ∧ vec "foo" "Zm9v" ∧ vec "foob" "Zm9vYg==" ∧
    vec "fooba" "Zm9vYmE=" ∧ vec "foobar" "Zm9vYmFy" ∧
    -- The same §10 vectors through decode?, as literal armoured text:
    -- the differential drives decode?, so the known answers must pin
    -- the decoding direction and not only the encoder above.
    (decode? cap (ascii "-----BEGIN CERTIFICATE-----\nZm9vYmE=\n-----END CERTIFICATE-----\n")
      == some (ascii "fooba")) ∧
    (decode? cap (ascii "-----BEGIN CERTIFICATE-----\nZm8=\n-----END CERTIFICATE-----\n")
      == some (ascii "fo")) ∧
    rt "f" ∧ rt "foobar" ∧ sameEverywhere ∧
    reject (fun l => l ++ l) ∧                                  -- a second block
    reject (fun l => l ++ [120]) ∧                              -- trailing junk
    reject (fun l => [110] ++ l) ∧                              -- leading text
    reject (fun l => l.set 8 88) ∧                              -- a broken BEGIN
    reject (fun l => l.set (beginLine.length + 2) 33) ∧         -- outside the alphabet
    reject (fun l => l.set (beginLine.length + 2) 45) ∧         -- base64url dash
    (decode? cap (ByteArray.mk (beginLine ++ [10] ++ endLine ++ [10]).toArray)).isNone


/-!
## Proofs

The public theorems pin the codec. `b64Value?_table`, `b64Value?_lt`,
`b64Value?_inv` and `b64Value?_isSome_iff` fix the alphabet in both
directions: each alphabet character maps to its index and to nothing
else, and only values below 64 come back. `b64Decode?_isSome_iff`
characterizes acceptance: the base64 decoder succeeds on exactly the
texts `B64Grammar` admits. `decode?_size` bounds the output: a DER
that `decode?` returns fits `derMax`. `decode?_encode` is the round
trip: `decode?` returns the exact DER `encode` armoured, at every line
width, not just the widths the selftest runs. `decode?_sound` is the
frame: an input `decode?` accepts is the BEGIN line, a line
terminator, a dash-free body, the END line, and a tail of line
terminators, with the body's base64 the returned DER. `encode_fits`
and `encode_fits_zero` discharge `decode?_encode`'s fits-the-cap
hypothesis: armour at any width of four or more, or as one line, stays
within `pemMax`.

The private lemmas below follow the shape of the definitions: a proof
view of `encode` as list folds, one lemma per layer of `decode?`, and
an induction over three-byte groups for the base64 body.
-/

/-! ### Shared helpers

`ByteArray.toList` is defined by a counting loop, so the kernel cannot
evaluate it on literals. `byteArray_toList_eq` moves every list-level
fact onto `b.data.toList`, which the kernel can evaluate. -/

private theorem guard_pos {p : Prop} [Decidable p] (h : p) :
    (guard p : Option Unit) = some () := by
  unfold guard
  rw [if_pos h]
  rfl

private theorem of_guard_eq_some {p : Prop} [Decidable p] {u : Unit}
    (h : (guard p : Option Unit) = some u) : p := by
  unfold guard at h
  split at h
  · assumption
  · simp at h

private theorem toList_loop_eq (bs : ByteArray) :
    ∀ (d i : Nat) (r : List UInt8), bs.size ≤ i + d →
      ByteArray.toList.loop bs i r = r.reverse ++ bs.data.toList.drop i
  | 0, i, r, h => by
    rw [ByteArray.toList.loop.eq_1, if_neg (by omega),
      List.drop_of_length_le (by simpa using h), List.append_nil]
  | d+1, i, r, h => by
    rw [ByteArray.toList.loop.eq_1]
    by_cases hi : i < bs.size
    · rw [if_pos hi, toList_loop_eq bs d (i+1) _ (by omega)]
      conv => rhs; rw [List.drop_eq_getElem_cons (show i < bs.data.toList.length by simpa using hi)]
      rw [List.reverse_cons, List.append_assoc]
      congr 1
      rw [List.singleton_append]
      congr 1
      show bs.data[i]! = _
      rw [getElem!_pos bs.data i (by simpa using hi)]
      simp
    · rw [if_neg hi, List.drop_of_length_le (by simp; omega), List.append_nil]

private theorem byteArray_toList_eq (b : ByteArray) : b.toList = b.data.toList := by
  rw [ByteArray.toList, toList_loop_eq b b.size 0 [] (by omega)]
  rfl

/-! ### The alphabet table -/

/-- Every character of the RFC 4648 §4 alphabet decodes to its own
index: `b64Value?` of the `i`-th alphabet byte is `some i`. -/
theorem b64Value?_table : ∀ i, i < 64 →
    b64Value? ((ascii "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/")[i]!)
      = some i := by
  decide

/-- `b64Value?` only ever produces six-bit values: `some v` implies
`v < 64`. -/
theorem b64Value?_lt (c : UInt8) (v : Nat) (h : b64Value? c = some v) : v < 64 := by
  unfold b64Value? at h
  split at h
  next hc =>
    obtain ⟨-, h90⟩ := hc
    have h90' := UInt8.le_iff_toNat_le.mp h90
    simp at h90'
    injection h with h
    omega
  next =>
    split at h
    next hc =>
      obtain ⟨-, h122⟩ := hc
      have h122' := UInt8.le_iff_toNat_le.mp h122
      simp at h122'
      injection h with h
      omega
    next =>
      split at h
      next hc =>
        obtain ⟨-, h57⟩ := hc
        have h57' := UInt8.le_iff_toNat_le.mp h57
        simp at h57'
        injection h with h
        omega
      next =>
        split at h
        next => injection h with h; omega
        next =>
          split at h
          next => injection h with h; omega
          next => exact absurd h (by simp)

/-! ### A proof view of `encode`

`encode` is two `for` loops under `Id.run`. `encode_eq` restates it as
list folds: `bodyChars` is the base64 character stream (`charGroup`
per three-byte group), `wrapStep` inserts one LF per full line, and
`wrapped` is the fold's output with the final LF. The two `forIn`
lemmas turn each loop into the fold it computes. -/

private def alphabet : ByteArray :=
  ascii "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

private def charGroup (der : ByteArray) (i : Nat) : List UInt8 :=
  let n := der.size
  let b0 := der[i * 3]!.toNat
  let b1 := if i * 3 + 1 < n then der[i * 3 + 1]!.toNat else 0
  let b2 := if i * 3 + 2 < n then der[i * 3 + 2]!.toNat else 0
  let v := b0 * 65536 + b1 * 256 + b2
  [alphabet[v / 262144]!, alphabet[v / 4096 % 64]!,
   if i * 3 + 1 < n then alphabet[v / 64 % 64]! else 61,
   if i * 3 + 2 < n then alphabet[v % 64]! else 61]

private def bodyChars (der : ByteArray) : List UInt8 :=
  (List.range' 0 ((der.size + 2) / 3)).flatMap (fun i => charGroup der i)

private def wrapStep (w : Nat) (st : List UInt8 × Nat) (c : UInt8) : List UInt8 × Nat :=
  if st.2 + 1 == w then (st.1 ++ [c] ++ [10], 0) else (st.1 ++ [c], st.2 + 1)

private def wrapped (w : Nat) (der : ByteArray) : List UInt8 :=
  let chars := bodyChars der
  let st := chars.foldl (wrapStep (if w == 0 then chars.length + 1 else w)) (beginLine ++ [10], 0)
  if st.2 ≠ 0 then st.1 ++ [10] else st.1

private theorem id_bind_eq {α β : Type} (x : Id α) (f : α → Id β) : x >>= f = f x := rfl

private theorem id_pure_eq {α : Type} (x : α) : (pure x : Id α) = x := rfl

private theorem forIn_range_append (k : Nat) (f : Nat → List UInt8) :
    forIn (m := Id) [0:k] ([] : List UInt8) (fun i s => pure (ForInStep.yield (s ++ f i)))
      = (List.range' 0 k).flatMap f := by
  simp [List.flatMap_def]
  rfl

private theorem forIn_wrap (W : Nat) :
    ∀ (chars : List UInt8) (st : List UInt8 × Nat),
    forIn (m := Id) chars st (fun c s =>
        if (s.2 + 1 == W) = true then pure (ForInStep.yield (s.1 ++ [c] ++ [10], 0))
        else pure (ForInStep.yield (s.1 ++ [c], s.2 + 1)))
      = chars.foldl (wrapStep W) st
  | [], _ => by rfl
  | c :: cs, st => by
    rw [List.forIn_cons, List.foldl_cons]
    by_cases hb : (st.2 + 1 == W) = true
    · have hs : wrapStep W st c = (st.1 ++ [c] ++ [10], 0) := by
        simp only [wrapStep]
        rw [if_pos hb]
      rw [if_pos hb, hs]
      exact forIn_wrap W cs _
    · have hs : wrapStep W st c = (st.1 ++ [c], st.2 + 1) := by
        simp only [wrapStep]
        rw [if_neg hb]
      rw [if_neg hb, hs]
      exact forIn_wrap W cs _

private theorem encode_eq (w : Nat) (der : ByteArray) :
    encode w der = ByteArray.mk ((wrapped w der ++ endLine ++ [10]).toArray) := by
  simp only [encode, forIn_range_append, forIn_wrap]
  simp only [id_bind_eq, id_pure_eq, Id.run, wrapped, bodyChars, charGroup, alphabet]
  split <;> split <;> rfl

/-! ### The wrapping layer, unwound

`decode?` takes everything after the BEGIN line up to the first `-`,
then filters CR and LF out. `wrapped_spec` shows that region is the
character stream plus inserted LFs, whatever the width: the filter
gives back `bodyChars` exactly. -/

private theorem takeWhile_all (p : UInt8 → Bool) :
    ∀ (l : List UInt8), (∀ x ∈ l, p x = true) → l.takeWhile p = l
  | [], _ => rfl
  | c :: cs, h => by
    rw [List.takeWhile_cons, if_pos (h c (by simp)),
      takeWhile_all p cs (fun x hx => h x (by simp [hx]))]

private theorem endLine_head : endLine.head? = some 45 := by
  rw [endLine, byteArray_toList_eq]
  decide

private theorem wrapFold_spec (W : Nat) :
    ∀ (chars pre : List UInt8) (col : Nat),
      (∀ x ∈ chars, x ≠ 13 ∧ x ≠ 10 ∧ x ≠ 45) →
      ∃ mid, (chars.foldl (wrapStep W) (pre, col)).1 = pre ++ mid ∧
        (∀ x ∈ mid, x ≠ 45) ∧
        mid.filter (fun c => c ≠ 13 ∧ c ≠ 10) = chars
  | [], pre, col, _ => ⟨[], by simp, by simp, by simp⟩
  | c :: cs, pre, col, h => by
    obtain ⟨hc13, hc10, hc45⟩ := h c (by simp)
    have htail : ∀ x ∈ cs, x ≠ 13 ∧ x ≠ 10 ∧ x ≠ 45 := fun x hx => h x (by simp [hx])
    rw [List.foldl_cons]
    by_cases hb : (col + 1 == W) = true
    · have hs : wrapStep W (pre, col) c = (pre ++ [c] ++ [10], 0) := by
        simp only [wrapStep]
        rw [if_pos hb]
      obtain ⟨mid, h1, h2, h3⟩ := wrapFold_spec W cs (pre ++ [c] ++ [10]) 0 htail
      refine ⟨c :: 10 :: mid, ?_, ?_, ?_⟩
      · rw [hs, h1]
        simp
      · intro x hx
        rcases List.mem_cons.mp hx with rfl | hx
        · exact hc45
        · rcases List.mem_cons.mp hx with rfl | hx
          · decide
          · exact h2 x hx
      · have hkc : (decide (c ≠ 13 ∧ c ≠ 10)) = true := by simp [hc13, hc10]
        rw [List.filter_cons, List.filter_cons, if_pos hkc, if_neg (by decide), h3]
    · have hs : wrapStep W (pre, col) c = (pre ++ [c], col + 1) := by
        simp only [wrapStep]
        rw [if_neg hb]
      obtain ⟨mid, h1, h2, h3⟩ := wrapFold_spec W cs (pre ++ [c]) (col + 1) htail
      refine ⟨c :: mid, ?_, ?_, ?_⟩
      · rw [hs, h1]
        simp
      · intro x hx
        rcases List.mem_cons.mp hx with rfl | hx
        · exact hc45
        · exact h2 x hx
      · have hkc : (decide (c ≠ 13 ∧ c ≠ 10)) = true := by simp [hc13, hc10]
        rw [List.filter_cons, if_pos hkc, h3]

private theorem wrapped_spec (w : Nat) (der : ByteArray)
    (hchars : ∀ x ∈ bodyChars der, x ≠ 13 ∧ x ≠ 10 ∧ x ≠ 45) :
    ∃ mid, wrapped w der = (beginLine ++ [10]) ++ mid ∧
      (∀ x ∈ mid, x ≠ 45) ∧
      mid.filter (fun c => c ≠ 13 ∧ c ≠ 10) = bodyChars der := by
  obtain ⟨mid, h1, h2, h3⟩ :=
    wrapFold_spec (if w == 0 then (bodyChars der).length + 1 else w)
      (bodyChars der) (beginLine ++ [10]) 0 hchars
  have h10 : (List.filter (fun c => decide (c ≠ 13 ∧ c ≠ 10)) [10] : List UInt8) = [] := by
    decide
  rw [wrapped]
  by_cases hcol : ((bodyChars der).foldl
      (wrapStep (if w == 0 then (bodyChars der).length + 1 else w))
      (beginLine ++ [10], 0)).2 ≠ 0
  · rw [if_pos hcol]
    refine ⟨mid ++ [10], ?_, ?_, ?_⟩
    · rw [h1, List.append_assoc]
    · intro x hx
      rcases List.mem_append.mp hx with hx | hx
      · exact h2 x hx
      · simp at hx
        subst hx
        decide
    · rw [List.filter_append, h3, h10, List.append_nil]
  · rw [if_neg hcol]
    exact ⟨mid, h1, h2, h3⟩

/-! ### Alphabet facts

Every character `encode` emits is an alphabet byte or the pad 61, so
the stream never contains CR, LF, or `-`, and the pads sit only at the
end. -/

private theorem b64Value?_alphabet (i : Nat) (h : i < 64) : b64Value? (alphabet[i]!) = some i :=
  b64Value?_table i h

private theorem alphabet_ne (i : Nat) (h : i < 64) :
    alphabet[i]! ≠ 10 ∧ alphabet[i]! ≠ 13 ∧ alphabet[i]! ≠ 45 ∧ alphabet[i]! ≠ 61 := by
  revert h
  revert i
  decide

private theorem charGroup_mem (der : ByteArray) (i : Nat) :
    ∀ x ∈ charGroup der i, (∃ j, j < 64 ∧ x = alphabet[j]!) ∨ x = 61 := by
  intro x hx
  have hb0 := UInt8.toNat_lt (der[i * 3]!)
  simp only [charGroup] at hx
  by_cases h1 : i * 3 + 1 < der.size
  · have hb1 := UInt8.toNat_lt (der[i * 3 + 1]!)
    by_cases h2 : i * 3 + 2 < der.size
    · have hb2 := UInt8.toNat_lt (der[i * 3 + 2]!)
      rw [if_pos h1, if_pos h2, if_pos h1, if_pos h2] at hx
      simp only [List.mem_cons, List.not_mem_nil, or_false] at hx
      rcases hx with rfl | rfl | rfl | rfl
      · exact Or.inl ⟨_, by omega, rfl⟩
      · exact Or.inl ⟨_, by omega, rfl⟩
      · exact Or.inl ⟨_, by omega, rfl⟩
      · exact Or.inl ⟨_, by omega, rfl⟩
    · rw [if_pos h1, if_neg h2, if_pos h1, if_neg h2] at hx
      simp only [List.mem_cons, List.not_mem_nil, or_false] at hx
      rcases hx with rfl | rfl | rfl | rfl
      · exact Or.inl ⟨_, by omega, rfl⟩
      · exact Or.inl ⟨_, by omega, rfl⟩
      · exact Or.inl ⟨_, by omega, rfl⟩
      · exact Or.inr rfl
  · have h2 : ¬ i * 3 + 2 < der.size := by omega
    rw [if_neg h1, if_neg h2, if_neg h1, if_neg h2] at hx
    simp only [List.mem_cons, List.not_mem_nil, or_false] at hx
    rcases hx with rfl | rfl | rfl | rfl
    · exact Or.inl ⟨_, by omega, rfl⟩
    · exact Or.inl ⟨_, by omega, rfl⟩
    · exact Or.inr rfl
    · exact Or.inr rfl

private theorem bodyChars_clean (der : ByteArray) :
    ∀ x ∈ bodyChars der, x ≠ 13 ∧ x ≠ 10 ∧ x ≠ 45 := by
  intro x hx
  rw [bodyChars] at hx
  obtain ⟨i, -, hxi⟩ := List.mem_flatMap.mp hx
  rcases charGroup_mem der i x hxi with ⟨j, hj, rfl⟩ | rfl
  · obtain ⟨hne10, hne13, hne45, -⟩ := alphabet_ne j hj
    exact ⟨hne13, hne10, hne45⟩
  · refine ⟨by decide, by decide, by decide⟩

/-! ### Full groups through the fold

`groupValues` is the four six-bit values of one full group.
`fold_groupValues` pushes them through `b64Fold`: the accumulator
returns to zero and the three bytes come out in reverse order, so
`fold_full_prefix` extends over any prefix of full groups by
induction. -/

private def groupValues (der : ByteArray) (i : Nat) : List Nat :=
  let v := der[i * 3]!.toNat * 65536 + der[i * 3 + 1]!.toNat * 256 + der[i * 3 + 2]!.toNat
  [v / 262144, v / 4096 % 64, v / 64 % 64, v % 64]

private theorem fold_groupValues (der : ByteArray) (i : Nat) (out : List UInt8) :
    (groupValues der i).foldl b64Fold (out, 0, 0)
      = (der[i * 3 + 2]! :: der[i * 3 + 1]! :: der[i * 3]! :: out, 0, 0) := by
  have hb0 := UInt8.toNat_lt (der[i * 3]!)
  have hb1 := UInt8.toNat_lt (der[i * 3 + 1]!)
  have hb2 := UInt8.toNat_lt (der[i * 3 + 2]!)
  simp [groupValues, b64Fold]
  refine ⟨⟨?_, ?_, ?_⟩, ?_⟩
  · apply UInt8.toNat_inj.mp
    simp [UInt8.toNat_add, UInt8.toNat_mul]
    omega
  · apply UInt8.toNat_inj.mp
    simp
    omega
  · apply UInt8.toNat_inj.mp
    simp
    omega
  · omega

private theorem mapM_charGroup_full (der : ByteArray) (i : Nat) (h : i * 3 + 2 < der.size) :
    (charGroup der i).mapM b64Value? = some (groupValues der i) := by
  have hb0 := UInt8.toNat_lt (der[i * 3]!)
  have hb1 := UInt8.toNat_lt (der[i * 3 + 1]!)
  have hb2 := UInt8.toNat_lt (der[i * 3 + 2]!)
  have h1 : i * 3 + 1 < der.size := by omega
  simp only [charGroup, if_pos h1, if_pos h]
  rw [List.mapM_cons, List.mapM_cons, List.mapM_cons, List.mapM_cons, List.mapM_nil]
  rw [b64Value?_alphabet _ (by omega), b64Value?_alphabet _ (by omega),
    b64Value?_alphabet _ (by omega), b64Value?_alphabet _ (by omega)]
  simp [groupValues]

private theorem mapM_full_prefix (der : ByteArray) :
    ∀ j, j * 3 ≤ der.size →
      ((List.range' 0 j).flatMap (fun i => charGroup der i)).mapM b64Value?
        = some ((List.range' 0 j).flatMap (fun i => groupValues der i))
  | 0, _ => rfl
  | j+1, h => by
    rw [List.range'_1_concat, List.flatMap_append, List.flatMap_append,
      List.mapM_append, mapM_full_prefix der j (by omega)]
    have hlast : ([0 + j] : List Nat).flatMap (fun i => charGroup der i)
        = charGroup der j ++ [] := by
      simp
    rw [hlast, List.mapM_append, mapM_charGroup_full der j (by omega), List.mapM_nil]
    simp

private theorem fold_full_prefix (der : ByteArray) :
    ∀ j, j * 3 ≤ der.size →
      ((List.range' 0 j).flatMap (fun i => groupValues der i)).foldl b64Fold ([], 0, 0)
        = (((List.range' 0 (j * 3)).map (fun t => der[t]!)).reverse, 0, 0)
  | 0, _ => rfl
  | j+1, h => by
    rw [List.range'_1_concat, List.flatMap_append, List.foldl_append,
      fold_full_prefix der j (by omega)]
    have hlast : ([0 + j] : List Nat).flatMap (fun i => groupValues der i)
        = groupValues der j ++ [] := by
      simp
    rw [hlast, List.foldl_append, fold_groupValues der j]
    have hr : List.range' 0 ((j + 1) * 3)
        = List.range' 0 (j * 3) ++ [j * 3, j * 3 + 1, j * 3 + 2] := by
      have h3 : (j + 1) * 3 = j * 3 + 1 + 1 + 1 := by omega
      rw [h3, List.range'_1_concat, List.range'_1_concat, List.range'_1_concat]
      simp
    rw [hr]
    simp

private theorem mk_map_getElem (der : ByteArray) :
    ByteArray.mk (((List.range' 0 der.size).map (fun t => der[t]!)).toArray) = der := by
  apply ByteArray.ext_getElem
  · show (((List.range' 0 der.size).map fun t => der[t]!).toArray).size = der.size
    simp
  · intro i h1 h2
    simp only [ByteArray.getElem_eq_getElem_data, List.getElem_toArray, List.getElem_map,
      List.getElem_range']
    rw [getElem!_pos der (0 + 1 * i) (by omega)]
    congr 1
    omega

/-! ### The last group and its padding

A trailing group of one or two bytes ends in pads. These lemmas give
the exact characters, the padding count `decode?` recovers, the
`take` that strips it, and the fold of the remaining values, for each
of the three residues of the size. -/

private theorem charGroup_length (der : ByteArray) (i : Nat) : (charGroup der i).length = 4 := by
  simp [charGroup]

private theorem flatMap_charGroup_length (der : ByteArray) :
    ∀ j, ((List.range' 0 j).flatMap (fun i => charGroup der i)).length = 4 * j
  | 0 => rfl
  | j+1 => by
    rw [List.range'_1_concat, List.flatMap_append, List.length_append,
      flatMap_charGroup_length der j]
    simp [charGroup_length]
    omega

private theorem charGroup_full (der : ByteArray) (i : Nat) (h : i * 3 + 2 < der.size) :
    charGroup der i =
      [alphabet[(der[i * 3]!.toNat * 65536 + der[i * 3 + 1]!.toNat * 256 + der[i * 3 + 2]!.toNat)
          / 262144]!,
       alphabet[(der[i * 3]!.toNat * 65536 + der[i * 3 + 1]!.toNat * 256 + der[i * 3 + 2]!.toNat)
          / 4096 % 64]!,
       alphabet[(der[i * 3]!.toNat * 65536 + der[i * 3 + 1]!.toNat * 256 + der[i * 3 + 2]!.toNat)
          / 64 % 64]!,
       alphabet[(der[i * 3]!.toNat * 65536 + der[i * 3 + 1]!.toNat * 256 + der[i * 3 + 2]!.toNat)
          % 64]!] := by
  have h1 : i * 3 + 1 < der.size := by omega
  simp only [charGroup, if_pos h1, if_pos h]

private theorem charGroup_last1 (der : ByteArray) (q : Nat) (h : der.size = q * 3 + 1) :
    charGroup der q =
      [alphabet[der[q * 3]!.toNat * 65536 / 262144]!,
       alphabet[der[q * 3]!.toNat * 65536 / 4096 % 64]!, 61, 61] := by
  have h1 : ¬ q * 3 + 1 < der.size := by omega
  have h2 : ¬ q * 3 + 2 < der.size := by omega
  simp only [charGroup, if_neg h1, if_neg h2, Nat.zero_mul, Nat.add_zero]

private theorem charGroup_last2 (der : ByteArray) (q : Nat) (h : der.size = q * 3 + 2) :
    charGroup der q =
      [alphabet[(der[q * 3]!.toNat * 65536 + der[q * 3 + 1]!.toNat * 256) / 262144]!,
       alphabet[(der[q * 3]!.toNat * 65536 + der[q * 3 + 1]!.toNat * 256) / 4096 % 64]!,
       alphabet[(der[q * 3]!.toNat * 65536 + der[q * 3 + 1]!.toNat * 256) / 64 % 64]!, 61] := by
  have h1 : q * 3 + 1 < der.size := by omega
  have h2 : ¬ q * 3 + 2 < der.size := by omega
  simp only [charGroup, if_pos h1, if_neg h2, Nat.add_zero]

private theorem fold_lastGroup1 (der : ByteArray) (q : Nat) (out : List UInt8) :
    ([der[q * 3]!.toNat * 65536 / 262144,
      der[q * 3]!.toNat * 65536 / 4096 % 64] : List Nat).foldl b64Fold (out, 0, 0)
      = (der[q * 3]! :: out, 0, 4) := by
  have hb0 := UInt8.toNat_lt (der[q * 3]!)
  simp [b64Fold]
  constructor
  · apply UInt8.toNat_inj.mp
    simp
    omega
  · omega

private theorem fold_lastGroup2 (der : ByteArray) (q : Nat) (out : List UInt8) :
    ([(der[q * 3]!.toNat * 65536 + der[q * 3 + 1]!.toNat * 256) / 262144,
      (der[q * 3]!.toNat * 65536 + der[q * 3 + 1]!.toNat * 256) / 4096 % 64,
      (der[q * 3]!.toNat * 65536 + der[q * 3 + 1]!.toNat * 256) / 64 % 64] : List Nat).foldl
        b64Fold (out, 0, 0)
      = (der[q * 3 + 1]! :: der[q * 3]! :: out, 0, 2) := by
  have hb0 := UInt8.toNat_lt (der[q * 3]!)
  have hb1 := UInt8.toNat_lt (der[q * 3 + 1]!)
  simp [b64Fold]
  refine ⟨⟨?_, ?_⟩, ?_⟩
  · apply UInt8.toNat_inj.mp
    simp
    omega
  · apply UInt8.toNat_inj.mp
    simp
    omega
  · omega

private theorem guard_true : (guard True : Option Unit) = some () := rfl

private theorem takeWhile61_full (P : List UInt8) (a1 a2 a3 a4 : UInt8) (h : a4 ≠ 61) :
    List.takeWhile (fun x => x == 61) ((P ++ [a1, a2, a3, a4]).reverse) = [] := by
  rw [List.reverse_append, show ([a1, a2, a3, a4] : List UInt8).reverse = a4 :: [a3, a2, a1]
      from rfl,
    List.cons_append, List.takeWhile_cons, if_neg (by simp [h])]

private theorem takeWhile61_pad2 (P : List UInt8) (a1 a2 : UInt8) (h : a2 ≠ 61) :
    List.takeWhile (fun x => x == 61) ((P ++ [a1, a2, 61, 61]).reverse) = [61, 61] := by
  rw [List.reverse_append, show ([a1, a2, 61, 61] : List UInt8).reverse = 61 :: 61 :: [a2, a1]
      from rfl,
    List.cons_append, List.takeWhile_cons]
  rw [if_pos (by decide), List.cons_append, List.takeWhile_cons, if_pos (by decide),
    List.cons_append, List.takeWhile_cons, if_neg (by simp [h])]

private theorem takeWhile61_pad1 (P : List UInt8) (a1 a2 a3 : UInt8) (h : a3 ≠ 61) :
    List.takeWhile (fun x => x == 61) ((P ++ [a1, a2, a3, 61]).reverse) = [61] := by
  rw [List.reverse_append, show ([a1, a2, a3, 61] : List UInt8).reverse = 61 :: [a3, a2, a1]
      from rfl,
    List.cons_append, List.takeWhile_cons, if_pos (by decide),
    List.cons_append, List.takeWhile_cons, if_neg (by simp [h])]

private theorem take_append_two (P : List UInt8) (a1 a2 a3 a4 : UInt8) (m : Nat)
    (hm : m = P.length + 2) :
    List.take m (P ++ [a1, a2, a3, a4]) = P ++ [a1, a2] := by
  subst hm
  rw [List.take_append, List.take_of_length_le (by omega), Nat.add_sub_cancel_left]
  rfl

private theorem take_append_three (P : List UInt8) (a1 a2 a3 a4 : UInt8) (m : Nat)
    (hm : m = P.length + 3) :
    List.take m (P ++ [a1, a2, a3, a4]) = P ++ [a1, a2, a3] := by
  subst hm
  rw [List.take_append, List.take_of_length_le (by omega), Nat.add_sub_cancel_left]
  rfl

private theorem b64Decode?_of_encode (der : ByteArray) (h0 : der.size ≠ 0) :
    b64Decode? (bodyChars der) = some der := by
  have h3 : der.size % 3 = 0 ∨ der.size % 3 = 1 ∨ der.size % 3 = 2 := by omega
  rcases h3 with h3 | h3 | h3
  · -- der.size = (q' + 1) * 3: every group is full, no padding
    obtain ⟨q, hn⟩ : ∃ q, der.size = q * 3 := ⟨der.size / 3, by omega⟩
    obtain ⟨q', rfl⟩ : ∃ q', q = q' + 1 := ⟨q - 1, by omega⟩
    have hb0 := UInt8.toNat_lt (der[q' * 3]!)
    have hb1 := UInt8.toNat_lt (der[q' * 3 + 1]!)
    have hb2 := UInt8.toNat_lt (der[q' * 3 + 2]!)
    have hfull : q' * 3 + 2 < der.size := by omega
    have hk : (der.size + 2) / 3 = q' + 1 := by omega
    have hsplit : bodyChars der
        = (List.range' 0 q').flatMap (fun i => charGroup der i) ++ charGroup der q' := by
      rw [bodyChars, hk, List.range'_1_concat, List.flatMap_append]
      simp
    have htw : List.takeWhile (fun x => x == 61) (bodyChars der).reverse = [] := by
      rw [hsplit, charGroup_full der q' hfull]
      exact takeWhile61_full _ _ _ _ _ (alphabet_ne _ (by omega)).2.2.2
    have hlen : (bodyChars der).length = 4 * (q' + 1) := by
      rw [bodyChars, hk, flatMap_charGroup_length]
    have hmapM : (bodyChars der).mapM b64Value?
        = some ((List.range' 0 (q' + 1)).flatMap (fun i => groupValues der i)) := by
      rw [bodyChars, hk]
      exact mapM_full_prefix der (q' + 1) (by omega)
    simp only [b64Decode?, htw]
    have htk : List.take ((bodyChars der).length - ([] : List UInt8).length) (bodyChars der)
        = bodyChars der := by
      simp
    rw [htk, hmapM]
    simp only [Option.bind_eq_bind, Option.bind_some]
    rw [fold_full_prefix der (q' + 1) (by omega), ← hn]
    simp [guard_true, hlen, mk_map_getElem]
  · -- der.size = q * 3 + 1: the last group carries one byte and two pads
    obtain ⟨q, hn⟩ : ∃ q, der.size = q * 3 + 1 := ⟨der.size / 3, by omega⟩
    have hb0 := UInt8.toNat_lt (der[q * 3]!)
    have hk : (der.size + 2) / 3 = q + 1 := by omega
    have hPlen := flatMap_charGroup_length der q
    have hsplit : bodyChars der
        = (List.range' 0 q).flatMap (fun i => charGroup der i) ++ charGroup der q := by
      rw [bodyChars, hk, List.range'_1_concat, List.flatMap_append]
      simp
    have htw : List.takeWhile (fun x => x == 61) (bodyChars der).reverse = [61, 61] := by
      rw [hsplit, charGroup_last1 der q hn]
      exact takeWhile61_pad2 _ _ _ (alphabet_ne _ (by omega)).2.2.2
    simp only [b64Decode?, htw]
    have htk : List.take ((bodyChars der).length - ([61, 61] : List UInt8).length)
          (bodyChars der)
        = (List.range' 0 q).flatMap (fun i => charGroup der i)
            ++ [alphabet[der[q * 3]!.toNat * 65536 / 262144]!,
                alphabet[der[q * 3]!.toNat * 65536 / 4096 % 64]!] := by
      rw [hsplit, charGroup_last1 der q hn]
      exact take_append_two _ _ _ _ _ _ (by rw [List.length_append, hPlen]; simp)
    rw [htk]
    have hmapM : ((List.range' 0 q).flatMap (fun i => charGroup der i)
          ++ [alphabet[der[q * 3]!.toNat * 65536 / 262144]!,
              alphabet[der[q * 3]!.toNat * 65536 / 4096 % 64]!]).mapM b64Value?
        = some ((List.range' 0 q).flatMap (fun i => groupValues der i)
            ++ [der[q * 3]!.toNat * 65536 / 262144,
                der[q * 3]!.toNat * 65536 / 4096 % 64]) := by
      rw [List.mapM_append, mapM_full_prefix der q (by omega),
        List.mapM_cons, List.mapM_cons, List.mapM_nil,
        b64Value?_alphabet _ (by omega), b64Value?_alphabet _ (by omega)]
      simp
    rw [hmapM]
    simp only [Option.bind_eq_bind, Option.bind_some]
    rw [List.foldl_append, fold_full_prefix der q (by omega), fold_lastGroup1 der q]
    have hfuse : List.map (fun t => der[t]!) (List.range' 0 (q * 3)) ++ [der[q * 3]!]
        = List.map (fun t => der[t]!) (List.range' 0 der.size) := by
      rw [hn, List.range'_1_concat, List.map_append]
      simp
    have hmod : (4 * q + 4) % 4 = 0 := by omega
    simp [guard_true, hPlen, hmod, hfuse, mk_map_getElem]
  · -- der.size = q * 3 + 2: the last group carries two bytes and one pad
    obtain ⟨q, hn⟩ : ∃ q, der.size = q * 3 + 2 := ⟨der.size / 3, by omega⟩
    have hb0 := UInt8.toNat_lt (der[q * 3]!)
    have hb1 := UInt8.toNat_lt (der[q * 3 + 1]!)
    have hk : (der.size + 2) / 3 = q + 1 := by omega
    have hPlen := flatMap_charGroup_length der q
    have hsplit : bodyChars der
        = (List.range' 0 q).flatMap (fun i => charGroup der i) ++ charGroup der q := by
      rw [bodyChars, hk, List.range'_1_concat, List.flatMap_append]
      simp
    have htw : List.takeWhile (fun x => x == 61) (bodyChars der).reverse = [61] := by
      rw [hsplit, charGroup_last2 der q hn]
      exact takeWhile61_pad1 _ _ _ _ (alphabet_ne _ (by omega)).2.2.2
    simp only [b64Decode?, htw]
    have htk : List.take ((bodyChars der).length - ([61] : List UInt8).length)
          (bodyChars der)
        = (List.range' 0 q).flatMap (fun i => charGroup der i)
            ++ [alphabet[(der[q * 3]!.toNat * 65536 + der[q * 3 + 1]!.toNat * 256) / 262144]!,
                alphabet[(der[q * 3]!.toNat * 65536 + der[q * 3 + 1]!.toNat * 256) / 4096 % 64]!,
                alphabet[(der[q * 3]!.toNat * 65536 + der[q * 3 + 1]!.toNat * 256) / 64 % 64]!] := by
      rw [hsplit, charGroup_last2 der q hn]
      exact take_append_three _ _ _ _ _ _ (by rw [List.length_append, hPlen]; simp)
    rw [htk]
    have hmapM : ((List.range' 0 q).flatMap (fun i => charGroup der i)
          ++ [alphabet[(der[q * 3]!.toNat * 65536 + der[q * 3 + 1]!.toNat * 256) / 262144]!,
              alphabet[(der[q * 3]!.toNat * 65536 + der[q * 3 + 1]!.toNat * 256) / 4096 % 64]!,
              alphabet[(der[q * 3]!.toNat * 65536 + der[q * 3 + 1]!.toNat * 256) / 64 % 64]!]).mapM
            b64Value?
        = some ((List.range' 0 q).flatMap (fun i => groupValues der i)
            ++ [(der[q * 3]!.toNat * 65536 + der[q * 3 + 1]!.toNat * 256) / 262144,
                (der[q * 3]!.toNat * 65536 + der[q * 3 + 1]!.toNat * 256) / 4096 % 64,
                (der[q * 3]!.toNat * 65536 + der[q * 3 + 1]!.toNat * 256) / 64 % 64]) := by
      rw [List.mapM_append, mapM_full_prefix der q (by omega),
        List.mapM_cons, List.mapM_cons, List.mapM_cons, List.mapM_nil,
        b64Value?_alphabet _ (by omega), b64Value?_alphabet _ (by omega),
        b64Value?_alphabet _ (by omega)]
      simp
    rw [hmapM]
    simp only [Option.bind_eq_bind, Option.bind_some]
    rw [List.foldl_append, fold_full_prefix der q (by omega), fold_lastGroup2 der q]
    have hfuse : List.map (fun t => der[t]!) (List.range' 0 (q * 3))
          ++ [der[q * 3]!, der[q * 3 + 1]!]
        = List.map (fun t => der[t]!) (List.range' 0 der.size) := by
      rw [hn, show q * 3 + 2 = (q * 3 + 1) + 1 by omega, List.range'_1_concat,
        List.range'_1_concat, List.map_append, List.map_append]
      simp
    have hmod : (4 * q + 4) % 4 = 0 := by omega
    simp [guard_true, hPlen, hmod, hfuse, mk_map_getElem]

/-- Bool view of the inverse direction for one byte value: if it
decodes, it is the alphabet character at its own value. -/
private def invOk (n : Nat) : Bool :=
  match b64Value? (UInt8.ofNat n) with
  | some v =>
    (ascii "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/")[v]! == UInt8.ofNat n
  | none => true

-- Four quarters so each decide fits the default recursion depth:
-- lint-spec bans raising maxRecDepth, and one 256-case decide needs it.
private theorem invOk_q0 : ∀ n, n < 64 → invOk n = true := by decide
private theorem invOk_q1 : ∀ n, n < 64 → invOk (64 + n) = true := by decide
private theorem invOk_q2 : ∀ n, n < 64 → invOk (128 + n) = true := by decide
private theorem invOk_q3 : ∀ n, n < 64 → invOk (192 + n) = true := by decide

private theorem invOk_all : ∀ n, n < 256 → invOk n = true := by
  intro n h
  rcases Nat.lt_or_ge n 64 with h0 | h64
  · exact invOk_q0 n h0
  rcases Nat.lt_or_ge n 128 with h1 | h128
  · have := invOk_q1 (n - 64) (by omega); rwa [Nat.add_sub_cancel' h64] at this
  rcases Nat.lt_or_ge n 192 with h2 | h192
  · have := invOk_q2 (n - 128) (by omega); rwa [Nat.add_sub_cancel' h128] at this
  · have := invOk_q3 (n - 192) (by omega); rwa [Nat.add_sub_cancel' h192] at this

/-- `b64Value?` inverts the table: a byte that decodes to `v` IS the
`v`-th alphabet character. `b64Value?_table` is the other direction;
together they pin the accepted alphabet exactly — the definition's
"every other byte is outside the alphabet" as a theorem rather than a
comment. A widened range in `b64Value?` now fails the build instead of
waiting for a random differential row to sample it. -/
theorem b64Value?_inv (c : UInt8) (v : Nat) (h : b64Value? c = some v) :
    (ascii "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/")[v]! = c := by
  have h_ofNat : UInt8.ofNat c.toNat = c := by simp
  have h_ok := invOk_all c.toNat c.toNat_lt
  rw [invOk, h_ofNat, h] at h_ok
  exact eq_of_beq h_ok

/-- Exact-domain corollary: a byte decodes iff it is an alphabet
character. -/
theorem b64Value?_isSome_iff (c : UInt8) :
    (b64Value? c).isSome = true ↔
      ∃ i, i < 64 ∧
        c = (ascii "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/")[i]! := by
  constructor
  · intro h_some
    obtain ⟨v, hv⟩ := Option.isSome_iff_exists.mp h_some
    exact ⟨v, b64Value?_lt c v hv, (b64Value?_inv c v hv).symm⟩
  · rintro ⟨i, h_lt, rfl⟩
    rw [Option.isSome_iff_exists]
    exact ⟨i, b64Value?_table i h_lt⟩

/-! ### `decode?`: the bound and the round trip -/

/-- `decode?` never yields more than `derMax` bytes: the final guard
bounds the DER before it is returned. -/
theorem decode?_size (derMax : Nat) (input d : ByteArray)
    (h : decode? derMax input = some d) : d.size ≤ derMax := by
  simp only [decode?, Option.bind_eq_bind, Option.bind_eq_some_iff, Option.some.injEq] at h
  obtain ⟨_, -, _, -, _, -, _, -, _, -, der, -, _, hu5, hd⟩ := h
  subst hd
  exact of_guard_eq_some hu5

private theorem eatEol?_lf (r : List UInt8) : eatEol? (10 :: r) = some r := rfl

/-- Armour then decode is the identity. For DER that is non-empty (an
empty body is rejected), within the byte cap, and whose armoured text
fits the text cap, `decode?` undoes `encode` at every line width. -/
theorem decode?_encode (derMax w : Nat) (der : ByteArray)
    (hfit : (encode w der).size ≤ pemMax derMax)
    (hmax : der.size ≤ derMax) (h0 : der.size ≠ 0) :
    decode? derMax (encode w der) = some der := by
  obtain ⟨mid, hmid, hmid45, hmidf⟩ := wrapped_spec w der (bodyChars_clean der)
  have hlist : (encode w der).toList = beginLine ++ 10 :: (mid ++ (endLine ++ [10])) := by
    rw [encode_eq, byteArray_toList_eq]
    show ((wrapped w der ++ endLine ++ [10]).toArray).toList = _
    rw [List.toList_toArray, hmid]
    simp
  obtain ⟨eys, heys⟩ := List.head?_eq_some_iff.mp endLine_head
  have htkw : (mid ++ (endLine ++ [10])).takeWhile (fun c => c ≠ 45) = mid := by
    rw [List.takeWhile_append,
      takeWhile_all _ mid (fun x hx => by simpa using hmid45 x hx)]
    rw [if_pos rfl, heys, List.cons_append, List.takeWhile_cons, if_neg (by simp)]
    simp
  have hall : (([10] : List UInt8).all (fun c => c == 13 ∨ c == 10)) = true := by decide
  simp only [decode?]
  rw [guard_pos hfit]
  simp only [Option.bind_eq_bind, Option.bind_some]
  rw [hlist]
  rw [guard_pos (show beginLine.isPrefixOf (beginLine ++ 10 :: (mid ++ (endLine ++ [10])))
        = true from List.isPrefixOf_iff_prefix.mpr (List.prefix_append _ _))]
  simp only [Option.bind_some]
  rw [List.drop_left, eatEol?_lf]
  simp only [Option.bind_some]
  rw [htkw, List.drop_left]
  rw [guard_pos (show endLine.isPrefixOf (endLine ++ [10]) = true
        from List.isPrefixOf_iff_prefix.mpr (List.prefix_append _ _))]
  simp only [Option.bind_some]
  rw [List.drop_left, guard_pos hall]
  simp only [Option.bind_some]
  rw [hmidf, b64Decode?_of_encode der h0]
  simp only [Option.bind_some]
  rw [guard_pos hmax]
  rfl

/-! ### decode? soundness -/

private theorem eatEol?_shape {cs r : List UInt8} (h : eatEol? cs = some r) :
    ∃ eol, (eol = [10] ∨ eol = [13, 10]) ∧ cs = eol ++ r := by
  unfold eatEol? at h
  split at h
  · exact ⟨[13, 10], Or.inr rfl, by rw [Option.some.inj h]; rfl⟩
  · exact ⟨[10], Or.inl rfl, by rw [Option.some.inj h]; rfl⟩
  · simp at h

private theorem drop_length_of_append {l₁ l₂ l : List UInt8} (h : l₁ ++ l₂ = l) :
    l.drop l₁.length = l₂ := by
  rw [← h, List.drop_left]

/-- Soundness: an input `decode?` accepts has the RFC 7468 frame. The
text is the BEGIN line, one line terminator, a body with no dash, the
END line, and a tail of line terminators only — and the body's base64,
CR and LF removed, is the returned DER. -/
theorem decode?_sound (derMax : Nat) (input der : ByteArray)
    (h : decode? derMax input = some der) :
    ∃ eol body tail,
      input.toList = beginLine ++ eol ++ body ++ endLine ++ tail ∧
      (eol = [10] ∨ eol = [13, 10]) ∧
      (∀ c ∈ body, c ≠ 45) ∧
      (∀ c ∈ tail, c = 13 ∨ c = 10) ∧
      b64Decode? (body.filter (fun c => c ≠ 13 ∧ c ≠ 10)) = some der := by
  simp only [decode?, Option.bind_eq_bind, Option.bind_eq_some_iff, Option.some.injEq] at h
  obtain ⟨_, -, _, hpre, rest, hrest, _, hend, _, hallt, der', hb64, _, -, hd⟩ := h
  subst hd
  obtain ⟨t, ht⟩ := List.isPrefixOf_iff_prefix.mp (of_guard_eq_some hpre)
  rw [drop_length_of_append ht] at hrest
  obtain ⟨eol, heol, ht2⟩ := eatEol?_shape hrest
  have hafter : rest.takeWhile (· ≠ 45) ++ rest.dropWhile (· ≠ 45) = rest :=
    List.takeWhile_append_dropWhile
  have hendp := of_guard_eq_some hend
  have halltp := of_guard_eq_some hallt
  rw [drop_length_of_append hafter] at hendp halltp
  obtain ⟨tl, htl⟩ := List.isPrefixOf_iff_prefix.mp hendp
  rw [drop_length_of_append htl] at halltp
  refine ⟨eol, rest.takeWhile (· ≠ 45), tl, ?_, heol, ?_, ?_, hb64⟩
  · simp only [List.append_assoc]
    rw [htl, hafter, ← ht2, ht]
  · intro c hc
    exact of_decide_eq_true (List.all_eq_true.mp List.all_takeWhile c hc)
  · intro c hc
    simpa using List.all_eq_true.mp halltp c hc

/-! ### encode size bound

`decode?_encode` assumes the armoured text fits the cap; the theorems
here discharge that assumption. `encode_fits` covers every line width
of four characters or more — the floor `pemMax`'s terminator budget is
sized for — and `encode_fits_zero` covers width zero, the single-line
form. The count behind both: `bodyChars` spends four characters per
three-byte group (`flatMap_charGroup_length`), the fold in `wrapped`
adds one LF per full line plus one more for a nonempty last line
(`wrapFold_length`), and the two boundary lines with their LFs cost 54
bytes of `pemMax`'s 64-byte fixed budget. -/

private theorem wrapFold_length (W : Nat) :
    ∀ (chars pre : List UInt8) (col : Nat), col < W →
      (chars.foldl (wrapStep W) (pre, col)).1.length
          = pre.length + chars.length + (col + chars.length) / W ∧
        (chars.foldl (wrapStep W) (pre, col)).2 = (col + chars.length) % W
  | [], pre, col, h => ⟨by simp [Nat.div_eq_of_lt h], by simp [Nat.mod_eq_of_lt h]⟩
  | c :: cs, pre, col, h => by
    rw [List.foldl_cons]
    simp only [wrapStep]
    by_cases hb : (col + 1 == W) = true
    · have hW : col + 1 = W := eq_of_beq hb
      rw [if_pos hb]
      obtain ⟨h1, h2⟩ := wrapFold_length W cs (pre ++ [c] ++ [10]) 0 (by omega)
      have harg : col + (c :: cs).length = cs.length + W := by
        simp only [List.length_cons]
        omega
      refine ⟨?_, ?_⟩
      · rw [h1, harg, Nat.add_div_right cs.length (show 0 < W by omega), Nat.zero_add]
        simp only [List.length_append, List.length_cons, List.length_nil]
        generalize cs.length / W = q
        omega
      · rw [h2, harg, Nat.add_mod_right, Nat.zero_add]
    · have hne : col + 1 ≠ W := by simpa using hb
      rw [if_neg hb]
      obtain ⟨h1, h2⟩ := wrapFold_length W cs (pre ++ [c]) (col + 1) (by omega)
      have harg : col + 1 + cs.length = col + (c :: cs).length := by
        simp only [List.length_cons]
        omega
      refine ⟨?_, ?_⟩
      · rw [h1, harg]
        generalize (col + (c :: cs).length) / W = q
        simp only [List.length_append, List.length_cons, List.length_nil]
        omega
      · rw [h2, harg]

private theorem wrapped_length_le (w : Nat) (der : ByteArray) :
    (wrapped w der).length
      ≤ 29 + (bodyChars der).length
        + (bodyChars der).length / (if w == 0 then (bodyChars der).length + 1 else w) := by
  have hW : 0 < (if w == 0 then (bodyChars der).length + 1 else w) := by
    cases w <;> simp
  obtain ⟨h1, -⟩ := wrapFold_length (if w == 0 then (bodyChars der).length + 1 else w)
    (bodyChars der) (beginLine ++ [10]) 0 hW
  have hbegin : (beginLine ++ [10] : List UInt8).length = 28 := by
    rw [beginLine, byteArray_toList_eq]
    decide
  rw [wrapped]
  by_cases hcol : ((bodyChars der).foldl
      (wrapStep (if w == 0 then (bodyChars der).length + 1 else w))
      (beginLine ++ [10], 0)).2 ≠ 0
  · rw [if_pos hcol, List.length_append, h1, hbegin, Nat.zero_add]
    simp only [List.length_cons, List.length_nil]
    omega
  · rw [if_neg hcol, h1, hbegin, Nat.zero_add]
    omega

private theorem bodyChars_length (der : ByteArray) :
    (bodyChars der).length = 4 * ((der.size + 2) / 3) := by
  rw [bodyChars]
  exact flatMap_charGroup_length der _

private theorem encode_size_eq (w : Nat) (der : ByteArray) :
    (encode w der).size = (wrapped w der).length + 26 := by
  have hend : (endLine : List UInt8).length = 25 := by
    rw [endLine, byteArray_toList_eq]
    decide
  rw [encode_eq]
  show ((wrapped w der ++ endLine ++ [10]).toArray).size = (wrapped w der).length + 26
  simp only [List.size_toArray, List.length_append, List.length_cons, List.length_nil,
    hend]

/-- Armoured output fits the text cap: at every line width of four
characters or more, `encode`'s output is at most `pemMax derMax` bytes
for DER of at most `derMax` bytes. This discharges `decode?_encode`'s
`hfit` hypothesis, so everything the encoder emits at these widths
decodes back. -/
theorem encode_fits (derMax w : Nat) (der : ByteArray)
    (hw : 4 ≤ w) (hmax : der.size ≤ derMax) :
    (encode w der).size ≤ pemMax derMax := by
  have hL := bodyChars_length der
  have hwr := wrapped_length_le w der
  rw [if_neg (by simp; omega)] at hwr
  have hdw : (bodyChars der).length / w ≤ (bodyChars der).length / 4 :=
    Nat.div_le_div_left hw (by omega)
  have hsz := encode_size_eq w der
  have hpem : pemMax derMax
      = 4 * ((derMax + 2) / 3) + 4 * ((derMax + 2) / 3) / 4 * 2 + 64 := rfl
  omega

/-- Width zero armours the body as one line, and that single-line form
also fits the text cap. -/
theorem encode_fits_zero (derMax : Nat) (der : ByteArray)
    (hmax : der.size ≤ derMax) :
    (encode 0 der).size ≤ pemMax derMax := by
  have hL := bodyChars_length der
  have hwr := wrapped_length_le 0 der
  rw [if_pos (show ((0 : Nat) == 0) = true from rfl), Nat.div_eq_of_lt (by omega)] at hwr
  have hsz := encode_size_eq 0 der
  have hpem : pemMax derMax
      = 4 * ((derMax + 2) / 3) + 4 * ((derMax + 2) / 3) / 4 * 2 + 64 := rfl
  omega

/-! ### `b64Decode?` characterization

`B64Grammar` restates acceptance declaratively, without running the
decoder, and `b64Decode?_isSome_iff` proves the decoder succeeds on
exactly the texts the grammar admits. The proof follows the decoder's
own steps: `take_pads` and `trailing_pads_of_append` connect the
trailing-pad count to the body-plus-pads split, `mapM_values`,
`mapM_getLast?` and `mapM_isSome_of_all` handle the alphabet map,
`fold_state` computes `b64Fold`'s final accumulator — the low bits of
the last six-bit value — and `pad_bits_zero_iff` turns that residue
into §3.5's zero-pad-bits condition. -/

/-- RFC 4648 §4 and §3.5 as one predicate: the text splits into a
non-empty body and `npad ≤ 2` trailing pad bytes (61, `=`), the length
counting pads is a multiple of four, every body byte is an alphabet
character, and `4 ^ npad` divides the last body character's value —
§3.5's canonical padding, the bits the pads stand for being zero.
`b64Decode?_isSome_iff` proves `b64Decode?` accepts exactly these
texts. -/
def B64Grammar (cs : List UInt8) : Prop :=
  ∃ body npad,
    cs = body ++ List.replicate npad 61 ∧
    npad ≤ 2 ∧
    body ≠ [] ∧
    (body.length + npad) % 4 = 0 ∧
    (∀ c ∈ body, (b64Value? c).isSome = true) ∧
    (∀ c v, body.getLast? = some c → b64Value? c = some v → 4 ^ npad ∣ v)

/-- The trailing-pad run is a `replicate` of its own length. -/
private theorem takeWhile61_replicate (cs : List UInt8) :
    cs.reverse.takeWhile (· == 61)
      = List.replicate (cs.reverse.takeWhile (· == 61)).length 61 :=
  List.eq_replicate_of_mem fun b hb =>
    eq_of_beq (List.all_eq_true.mp List.all_takeWhile b hb)

/-- Taking an appended list back up to the first part's length gives
the first part. -/
private theorem take_append_exact (B R : List UInt8) (n : Nat) (h : B.length = n) :
    (B ++ R).take n = B := h ▸ List.take_left

/-- The split `b64Decode?` computes: the input is some prefix followed
by its trailing-pad run, and the `take` up to that run is the
prefix. -/
private theorem take_pads (cs : List UInt8) :
    ∃ B, cs = B ++ List.replicate (cs.reverse.takeWhile (· == 61)).length 61 ∧
      cs.take (cs.length - (cs.reverse.takeWhile (· == 61)).length) = B := by
  have hsplit : List.replicate (cs.reverse.takeWhile (· == 61)).length 61
      ++ cs.reverse.dropWhile (· == 61) = cs.reverse := by
    rw [← takeWhile61_replicate, List.takeWhile_append_dropWhile]
  have hlen : (cs.reverse.takeWhile (· == 61)).length
      + (cs.reverse.dropWhile (· == 61)).length = cs.length := by
    simpa using congrArg List.length hsplit
  have hcs : cs = (cs.reverse.dropWhile (· == 61)).reverse
      ++ List.replicate (cs.reverse.takeWhile (· == 61)).length 61 := by
    have h3 := congrArg List.reverse hsplit
    rw [List.reverse_append, List.reverse_replicate, List.reverse_reverse] at h3
    exact h3.symm
  refine ⟨(cs.reverse.dropWhile (· == 61)).reverse, hcs, ?_⟩
  rw [congrArg (List.take (cs.length - (cs.reverse.takeWhile (· == 61)).length)) hcs]
  exact take_append_exact _ _ _ (by rw [List.length_reverse]; omega)

/-- The trailing-pad count of body-plus-pads is the pad count, when
the body does not itself end in a pad. -/
private theorem trailing_pads_of_append (body : List UInt8) (npad : Nat)
    (h61 : ∀ c, body.getLast? = some c → (c == 61) = false) :
    ((body ++ List.replicate npad 61).reverse.takeWhile (· == 61)).length = npad := by
  have hrev : body.reverse.takeWhile (· == 61) = [] := by
    cases hb : body.reverse with
    | nil => rfl
    | cons c cs =>
      rw [List.takeWhile_cons,
        if_neg (by simp [h61 c (by rw [← List.head?_reverse, hb]; rfl)])]
  rw [List.reverse_append, List.reverse_replicate]
  simp [hrev]

/-- What a successful alphabet map says: same length, six-bit values,
and every input character in the alphabet. -/
private theorem mapM_values :
    ∀ (l : List UInt8) (vals : List Nat), l.mapM b64Value? = some vals →
      vals.length = l.length ∧ (∀ v ∈ vals, v < 64) ∧
        ∀ c ∈ l, (b64Value? c).isSome = true
  | [], vals, h => by
    rw [List.mapM_nil] at h
    obtain rfl : ([] : List Nat) = vals := by simpa using h
    exact ⟨rfl, by simp, by simp⟩
  | a :: l, vals, h => by
    rw [List.mapM_cons] at h
    simp only [Option.bind_eq_bind, Option.bind_eq_some_iff, Option.pure_def,
      Option.some.injEq] at h
    obtain ⟨v, hv, vs, hvs, rfl⟩ := h
    obtain ⟨ih_len, ih_lt, ih_some⟩ := mapM_values l vs hvs
    refine ⟨by simp [ih_len], fun x hx => ?_, fun c hc => ?_⟩
    · rcases List.mem_cons.mp hx with rfl | hx2
      · exact b64Value?_lt a x hv
      · exact ih_lt x hx2
    · rcases List.mem_cons.mp hc with rfl | hc2
      · rw [hv]
        rfl
      · exact ih_some c hc2

/-- A successful alphabet map sends the last input character to the
last output value. -/
private theorem mapM_getLast? (l : List UInt8) (vals : List Nat) (c : UInt8)
    (hm : l.mapM b64Value? = some vals) (hc : l.getLast? = some c) :
    ∃ v, b64Value? c = some v ∧ vals.getLast? = some v := by
  obtain ⟨l', rfl⟩ := List.getLast?_eq_some_iff.mp hc
  rw [List.mapM_append, List.mapM_cons, List.mapM_nil] at hm
  simp only [Option.bind_eq_bind, Option.bind_eq_some_iff, Option.pure_def,
    Option.some.injEq] at hm
  obtain ⟨vs, -, w, ⟨v, hv, a, rfl, rfl⟩, rfl⟩ := hm
  exact ⟨v, hv, List.getLast?_concat⟩

/-- The alphabet map succeeds when every character is in the
alphabet. -/
private theorem mapM_isSome_of_all :
    ∀ (l : List UInt8), (∀ c ∈ l, (b64Value? c).isSome = true) →
      ∃ vals, l.mapM b64Value? = some vals
  | [], _ => ⟨[], List.mapM_nil⟩
  | a :: l, h => by
    obtain ⟨v, hv⟩ := Option.isSome_iff_exists.mp (h a (by simp))
    obtain ⟨vs, hvs⟩ := mapM_isSome_of_all l (fun c hc => h c (by simp [hc]))
    exact ⟨v :: vs, by rw [List.mapM_cons, hv, hvs]; rfl⟩

/-- The fold, solved: over six-bit values `b64Fold` advances `nbits`
by six per value modulo eight, and leaves in the accumulator exactly
the low `nbits` bits of the last value (`acc` again when no value
arrived). -/
private theorem fold_state :
    ∀ (vals : List Nat) (out : List UInt8) (acc nbits : Nat),
      (∀ v ∈ vals, v < 64) → nbits % 2 = 0 → nbits ≤ 6 → acc < 2 ^ nbits →
      ∃ out', vals.foldl b64Fold (out, acc, nbits)
        = (out', vals.getLast?.getD acc % 2 ^ ((nbits + 6 * vals.length) % 8),
           (nbits + 6 * vals.length) % 8)
  | [], out, acc, nbits, _, _, hn6, ha => by
    have h8 : (nbits + 6 * ([] : List Nat).length) % 8 = nbits := by
      simp only [List.length_nil]
      omega
    exact ⟨out, by
      rw [List.foldl_nil, h8, List.getLast?_nil, Option.getD_none, Nat.mod_eq_of_lt ha]⟩
  | v :: vs, out, acc, nbits, hv64, hn2, hn6, ha => by
    have hv : v < 64 := hv64 v (by simp)
    have hvs64 : ∀ x ∈ vs, x < 64 := fun x hx => hv64 x (by simp [hx])
    rw [List.foldl_cons]
    simp only [b64Fold]
    by_cases hge : nbits + 6 ≥ 8
    · rw [if_pos hge]
      obtain ⟨out', hfold⟩ :=
        fold_state vs (UInt8.ofNat ((acc * 64 + v) / 2 ^ (nbits + 6 - 8)) :: out)
          ((acc * 64 + v) % 2 ^ (nbits + 6 - 8)) (nbits + 6 - 8) hvs64
          (by omega) (by omega) (Nat.mod_lt _ (Nat.two_pow_pos _))
      have h8 : (nbits + 6 - 8 + 6 * vs.length) % 8
          = (nbits + 6 * (v :: vs).length) % 8 := by
        simp only [List.length_cons]
        omega
      refine ⟨out', ?_⟩
      rw [hfold, h8, List.getLast?_cons]
      cases hvl : vs.getLast? with
      | some w => simp only [Option.getD_some]
      | none =>
        obtain rfl := List.getLast?_eq_none_iff.mp hvl
        simp only [Option.getD_none, Option.getD_some, List.length_cons, List.length_nil]
        have hcases : nbits = 2 ∨ nbits = 4 ∨ nbits = 6 := by omega
        rcases hcases with rfl | rfl | rfl <;> simp <;> omega
    · rw [if_neg hge]
      obtain rfl : nbits = 0 := by omega
      obtain rfl : acc = 0 := by simpa using ha
      simp only [Nat.zero_mul, Nat.zero_add]
      obtain ⟨out', hfold⟩ := fold_state vs out v 6 hvs64 (by omega) (by omega) (by omega)
      have h8 : (6 + 6 * vs.length) % 8 = 6 * (v :: vs).length % 8 := by
        simp only [List.length_cons]
        omega
      exact ⟨out', by rw [hfold, h8, List.getLast?_cons, Option.getD_some]⟩

/-- RFC 4648 §3.5's padding arithmetic: with `npad` pads closing a
quantum of `len` characters, the pending low bits of the last six-bit
value are zero exactly when `4 ^ npad` divides it. -/
private theorem pad_bits_zero_iff (len npad v : Nat) (hnpad : npad ≤ 2)
    (hmod : (len + npad) % 4 = 0) :
    v % 2 ^ (6 * len % 8) = 0 ↔ 4 ^ npad ∣ v := by
  have h3 : npad = 0 ∨ npad = 1 ∨ npad = 2 := by omega
  rcases h3 with rfl | rfl | rfl
  · rw [show 6 * len % 8 = 0 by omega]
    omega
  · rw [show 6 * len % 8 = 2 by omega]
    omega
  · rw [show 6 * len % 8 = 4 by omega]
    omega

/-- `b64Decode?` succeeds on exactly the texts `B64Grammar` admits:
success of the executable decoder is equivalent to the declarative
grammar. -/
theorem b64Decode?_isSome_iff (cs : List UInt8) :
    (b64Decode? cs).isSome = true ↔ B64Grammar cs := by
  constructor
  · intro h
    obtain ⟨d, hd⟩ := Option.isSome_iff_exists.mp h
    simp only [b64Decode?, Option.bind_eq_bind, Option.bind_eq_some_iff] at hd
    obtain ⟨_, hg1, _, hg2, _, hg3, vals, hvals, hmatch⟩ := hd
    have hnpad : (cs.reverse.takeWhile (· == 61)).length ≤ 2 := of_guard_eq_some hg1
    have hne := of_guard_eq_some hg2
    have hmod := of_guard_eq_some hg3
    obtain ⟨B, hB, hBtake⟩ := take_pads cs
    rw [hBtake] at hne hmod hvals
    obtain ⟨hlen, hlt, hsome⟩ := mapM_values B vals hvals
    have hBne : B ≠ [] := fun hnil => hne (by simp [hnil])
    have hmod' : (B.length + (cs.reverse.takeWhile (· == 61)).length) % 4 = 0 := by
      simpa using hmod
    refine ⟨B, (cs.reverse.takeWhile (· == 61)).length, hB, hnpad, hBne, hmod', hsome, ?_⟩
    intro c v hc hv
    obtain ⟨v', hv', hvalsl⟩ := mapM_getLast? B vals c hvals hc
    obtain rfl : v = v' := Option.some.inj (hv.symm.trans hv')
    obtain ⟨out', hfold⟩ := fold_state vals [] 0 0 hlt (by omega) (by omega) (by decide)
    simp only [hfold] at hmatch
    obtain ⟨_, hg4, -⟩ := hmatch
    have hacc := of_guard_eq_some hg4
    rw [hvalsl, Option.getD_some, Nat.zero_add, beq_iff_eq] at hacc
    exact (pad_bits_zero_iff vals.length _ v hnpad (by omega)).mp hacc
  · rintro ⟨body, npad, rfl, hnpad, hne, hmod, hall, hlast⟩
    have h61 : ∀ c, body.getLast? = some c → (c == 61) = false := by
      intro c hc
      rw [beq_eq_false_iff_ne]
      rintro rfl
      have hsome := hall 61 (List.mem_of_getLast? hc)
      simp [b64Value?] at hsome
    have hpadlen : (((body ++ List.replicate npad 61).reverse).takeWhile (· == 61)).length
        = npad := trailing_pads_of_append body npad h61
    have hbody : (body ++ List.replicate npad 61).take
        ((body ++ List.replicate npad 61).length - npad) = body :=
      take_append_exact _ _ _ (by rw [List.length_append, List.length_replicate]; omega)
    have hne' : body.length ≠ 0 := fun h0 => hne (List.length_eq_zero_iff.mp h0)
    obtain ⟨vals, hvals⟩ := mapM_isSome_of_all body hall
    obtain ⟨hlen, hlt, -⟩ := mapM_values body vals hvals
    obtain ⟨clast, hclast⟩ := Option.isSome_iff_exists.mp (List.getLast?_isSome.mpr hne)
    obtain ⟨vlast, hvlast, hvalsl⟩ := mapM_getLast? body vals clast hvals hclast
    obtain ⟨out', hfold⟩ := fold_state vals [] 0 0 hlt (by omega) (by omega) (by decide)
    have hdvd : 4 ^ npad ∣ vlast := hlast clast vlast hclast hvlast
    simp only [b64Decode?]
    rw [hpadlen, hbody, guard_pos hnpad]
    simp only [Option.bind_eq_bind, Option.bind_some]
    rw [guard_pos hne']
    simp only [Option.bind_some]
    rw [guard_pos (show ((body.length + npad) % 4 == 0) = true by simp [hmod])]
    simp only [Option.bind_some]
    rw [hvals]
    simp only [Option.bind_some, hfold, hvalsl, Option.getD_some, Nat.zero_add]
    rw [guard_pos (show (vlast % 2 ^ (6 * vals.length % 8) == 0) = true by
      rw [beq_iff_eq]
      exact (pad_bits_zero_iff vals.length npad vlast hnpad (by omega)).mpr hdvd)]
    rfl

end Spec.Pem
