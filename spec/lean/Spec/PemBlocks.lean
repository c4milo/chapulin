import Spec.Pem

/-!
# PEM blocks of four labels, and runs of CERTIFICATE blocks

Written from RFC 7468 §2 (the encapsulation boundaries, which name a
label), §5 and §10 (the CERTIFICATE and PRIVATE KEY labels), RFC 5915 §4
(the EC PRIVATE KEY label), the EC PARAMETERS label OpenSSL writes above
an EC PRIVATE KEY block, and the two text rules `pem_blocks.h` states for
a certificate chain and a CA bundle, which the owner ruled on 2026-10-13
(docs/decisions.md 131). The base64 body is `Spec.Pem`'s.

`Spec.Pem.decode?` reads the CERTIFICATE label alone. `decodeOne?` here
takes any label, and `decode?_eq_decodeOne?` proves the two the same
function on that label, so every theorem `Spec.Pem` proves of `decode?`
holds of `decodeOne?`'s certificate arm.

`readCertificates?` reads a run of CERTIFICATE blocks under one of two
text rules:

* `TextRule.refused`, a chain: the first block at the first byte, CR and
  LF alone outside the blocks, and the last of them before each next
  BEGIN line an LF;
* `TextRule.skipped`, a bundle. A BEGIN line is a line that starts with
  "-----BEGIN ", the first 11 bytes of RFC 7468 §3's pre-encapsulation
  boundary. Each BEGIN line opens a block, whatever follows the 11 bytes.
  The run reads a CERTIFICATE block there or refuses the text.
  "-----BEGIN " at any other byte of a line refuses the text. The run
  skips every other line as text, before, between and after the blocks.
  Each END line ends its line. Camilo ruled on 2026-10-13 that a BEGIN
  line of any other label refuses a bundle.

The blocks' DER together is at most `roomMax` bytes, the room the
caller's writer has. The count of blocks is the caller's rule
(`Spec.PemFiles`), as it is in C, where `pem_blocks_next` reads one block
a call and the caller counts them.
-/

namespace Spec.PemBlocks

open Spec.Bytes Spec.Pem

/-- RFC 7468 §5: a certificate. -/
def labelCertificate : List UInt8 := (ascii "CERTIFICATE").toList
/-- RFC 7468 §10: a PKCS #8 PrivateKeyInfo. -/
def labelPrivateKey : List UInt8 := (ascii "PRIVATE KEY").toList
/-- RFC 5915 §4: a SEC 1 ECPrivateKey. -/
def labelEcPrivateKey : List UInt8 := (ascii "EC PRIVATE KEY").toList
/-- The ECParameters `openssl ecparam -genkey` writes above an EC PRIVATE
KEY block. -/
def labelEcParameters : List UInt8 := (ascii "EC PARAMETERS").toList

/-- RFC 7468 §3: the 11 bytes that open the pre-encapsulation boundary of
every label, "-----BEGIN ". -/
def beginPrefix : List UInt8 := (ascii "-----BEGIN ").toList

/-- RFC 7468 §2: the pre-encapsulation boundary of a label. -/
def beginOf (label : List UInt8) : List UInt8 :=
  beginPrefix ++ label ++ (ascii "-----").toList

/-- RFC 7468 §2: the post-encapsulation boundary of a label. -/
def endOf (label : List UInt8) : List UInt8 :=
  (ascii "-----END ").toList ++ label ++ (ascii "-----").toList

/-- One block of `label` at the head of `cs`: its BEGIN line, one line
terminator, a base64 body with CR and LF anywhere in it, and its END
line. Returns the DER and the bytes after the END line. The body runs
to the first dash, as `Spec.Pem.decode?`'s does. -/
def readBlock? (label cs : List UInt8) : Option (ByteArray × List UInt8) := do
  guard ((beginOf label).isPrefixOf cs)
  let rest ← eatEol? (cs.drop (beginOf label).length)
  let body := rest.takeWhile (· ≠ 45)
  let after := rest.drop body.length
  guard ((endOf label).isPrefixOf after)
  let der ← b64Decode? (body.filter (fun c => c ≠ 13 ∧ c ≠ 10))
  some (der, after.drop (endOf label).length)

/-- `pem_decode_one` under its caller's caps: the whole input is one
block of `label` followed by CR and LF alone, the input at most
`textMax` bytes and the DER at most `derMax`. -/
def decodeOne? (label : List UInt8) (textMax derMax : Nat) (input : ByteArray) :
    Option ByteArray := do
  guard (input.size ≤ textMax)
  let (der, tail) ← readBlock? label input.toList
  guard (tail.all (fun c => c == 13 ∨ c == 10))
  guard (der.size ≤ derMax)
  some der

/-- `pem_blocks.h`'s two text rules: what may lie outside the blocks. -/
inductive TextRule where
  /-- CR and LF alone: a certificate chain. -/
  | refused
  /-- Every line that holds no "-----BEGIN ": a CA bundle. -/
  | skipped
  deriving DecidableEq

/-- What the text before a block leaves. -/
inductive Next where
  /-- The input ended where the rule lets it. -/
  | ended
  /-- A block opens at the head of these bytes. -/
  | block (rest : List UInt8)
  /-- The text broke the rule. -/
  | refused

/-- A chain's text after a block: CR and LF bytes; before a next block
the last of them is LF, so the BEGIN line starts a line. -/
def strictGap (cs : List UInt8) : Next :=
  let gap := cs.takeWhile (fun c => c == 13 || c == 10)
  let rest := cs.drop gap.length
  if rest.isEmpty then .ended
  else if gap.getLast? == some 10 then .block rest
  else .refused

/-- The end of an END line's line: the input ends there, or LF or CR LF
follows. -/
def lineEnds? (cs : List UInt8) : Option (List UInt8) :=
  if cs.isEmpty then some [] else eatEol? cs

/-- Whether "-----BEGIN " starts at a byte of the first line of `cs`
other than its first byte. "-----BEGIN " holds no LF, so one that starts
inside the line ends inside it too. -/
def beginInsideLine (cs : List UInt8) : Bool :=
  (List.range (cs.takeWhile (· ≠ 10)).length).any
    (fun k => k != 0 && beginPrefix.isPrefixOf (cs.drop k))

/-- A bundle's text from a line start. A line that starts with
"-----BEGIN " opens a block, which the run reads as a CERTIFICATE block or
refuses. A line that holds "-----BEGIN " at another byte refuses the text.
Every other line is skipped through its LF. `fuel` bounds the lines, and
`cs.length + 1` is always enough, since a line skipped is a byte or
more. -/
def skipText : Nat → List UInt8 → Next
  | 0, _ => .refused
  | fuel + 1, cs =>
    if cs.isEmpty then .ended
    else if beginPrefix.isPrefixOf cs then .block cs
    else if beginInsideLine cs then .refused
    else skipText fuel ((cs.dropWhile (· ≠ 10)).drop 1)

/-- The text before a block under `rule`. `first` says no block has been
read: a chain's first block opens at the first byte, and a bundle's first
line starts at the first byte. -/
def nextBlock (rule : TextRule) (first : Bool) (cs : List UInt8) : Next :=
  match rule with
  | .refused => if first then .block cs else strictGap cs
  | .skipped =>
    match (if first then some cs else lineEnds? cs) with
    | none => .refused
    | some rest => skipText (rest.length + 1) rest

/-- The bytes of DER the blocks in `done` hold together. -/
def derTotal (done : List ByteArray) : Nat := (done.map ByteArray.size).sum

/-- The loop over blocks: `done` holds the DER of the blocks read, the
last first. `fuel` bounds the blocks, and `cs.length + 1` is always
enough, since a block is a byte or more. -/
def certificatesLoop (rule : TextRule) (roomMax : Nat) :
    Nat → List UInt8 → List ByteArray → Option (List ByteArray)
  | 0, _, _ => none
  | fuel + 1, cs, done =>
    match nextBlock rule done.isEmpty cs with
    | .refused => none
    | .ended => if done.isEmpty then none else some done.reverse
    | .block rest => do
      let (der, after) ← readBlock? labelCertificate rest
      guard (derTotal done + der.size ≤ roomMax)
      certificatesLoop rule roomMax fuel after (der :: done)

/-- `pem_blocks_next` called until the text ends. A run of no block is
refused, as its callers refuse it: one or more CERTIFICATE blocks under
`rule`, all of their DER together at most `roomMax` bytes. -/
def readCertificates? (rule : TextRule) (roomMax : Nat) (input : ByteArray) :
    Option (List ByteArray) :=
  certificatesLoop rule roomMax (input.size + 1) input.toList []

/-! ## Proofs

`decode?_eq_decodeOne?` ties `Spec.Pem.decode?` to `decodeOne?` on the
CERTIFICATE label at `pemMax`, so the round trip and soundness theorems
`Spec.Pem` proves of the first hold of the second. `readCertificates?_bounds`
is the run's contract: an accepted text holds one or more blocks, all of
their DER together at most `roomMax` bytes.

`skipText_ended_clear` and `skipText_block_clear` state the bundle's text
rule of 2026-10-13 for one stretch of text. The text a bundle skips holds
"-----BEGIN " at no byte. A block opens only at the start of a line where
"-----BEGIN " starts. `readBlock?_begins` reads a block only under its
label's BEGIN line. `readCertificates?_begins` combines these over a whole
bundle. Wherever "-----BEGIN " starts in a bundle that the run accepts, it
starts a line, and CERTIFICATE's BEGIN line starts there. -/

private theorem guard_pos {p : Prop} [Decidable p] (h : p) :
    (guard p : Option Unit) = some () := by
  unfold guard
  rw [if_pos h]
  rfl

private theorem guard_neg {p : Prop} [Decidable p] (h : ¬p) :
    (guard p : Option Unit) = none := by
  unfold guard
  rw [if_neg h]
  rfl

private theorem of_guard_eq_some {p : Prop} [Decidable p] {u : Unit}
    (h : (guard p : Option Unit) = some u) : p := by
  unfold guard at h
  split at h
  · assumption
  · simp at h

private theorem beginOf_certificate : beginOf labelCertificate = beginLine := by
  simp only [beginOf, beginPrefix, labelCertificate, beginLine, byteArray_toList_eq]
  decide

private theorem endOf_certificate : endOf labelCertificate = endLine := by
  simp only [endOf, labelCertificate, endLine, byteArray_toList_eq]
  decide

/-- `Spec.Pem.decode?` is `decodeOne?` on the CERTIFICATE label at
`pemMax`'s text cap: the same verdict and the same DER on every input. -/
theorem decode?_eq_decodeOne? (derMax : Nat) (input : ByteArray) :
    decode? derMax input = decodeOne? labelCertificate (pemMax derMax) derMax input := by
  simp only [decode?, decodeOne?, readBlock?, beginOf_certificate, endOf_certificate,
    Option.bind_eq_bind]
  by_cases h_size : input.size ≤ pemMax derMax
  · rw [guard_pos h_size]
    simp only [Option.bind_some]
    by_cases h_begin : beginLine.isPrefixOf input.toList = true
    · rw [guard_pos h_begin]
      simp only [Option.bind_some]
      cases eatEol? (input.toList.drop beginLine.length) with
      | none => rfl
      | some rest =>
        simp only [Option.bind_some]
        by_cases h_end :
            endLine.isPrefixOf (rest.drop (rest.takeWhile (· ≠ 45)).length) = true
        · rw [guard_pos h_end]
          simp only [Option.bind_some]
          cases b64Decode? ((rest.takeWhile (· ≠ 45)).filter (fun c => c ≠ 13 ∧ c ≠ 10)) with
          | none =>
            by_cases h_tail :
                ((rest.drop (rest.takeWhile (· ≠ 45)).length).drop endLine.length).all
                  (fun c => c == 13 ∨ c == 10) = true
            · rw [guard_pos h_tail]
              rfl
            · rw [guard_neg h_tail]
              rfl
          | some der => rfl
        · rw [guard_neg h_end]
          rfl
    · rw [guard_neg h_begin]
      rfl
  · rw [guard_neg h_size]
    rfl

/-- "-----BEGIN " as its bytes. -/
private theorem beginPrefix_eq :
    beginPrefix = [45, 45, 45, 45, 45, 66, 69, 71, 73, 78, 32] := by
  simp only [beginPrefix, byteArray_toList_eq]
  decide

/-- "-----BEGIN " starts at no end of input and at no LF. -/
private theorem beginPrefix_not_at_lf (cs : List UInt8) (h_lf : cs = [] ∨ cs.head? = some 10) :
    beginPrefix.isPrefixOf cs = false := by
  rcases h_lf with rfl | h_head
  · rw [beginPrefix_eq]; rfl
  · cases cs with
    | nil => simp at h_head
    | cons c t =>
      simp only [List.head?_cons, Option.some.injEq] at h_head
      subst h_head
      rw [beginPrefix_eq]; rfl

/-- A line's bytes before its LF, dropped, leave the LF and what follows
it. -/
private theorem drop_line (cs : List UInt8) :
    cs.drop (cs.takeWhile (· ≠ 10)).length = cs.dropWhile (· ≠ 10) := by
  have h_split := List.takeWhile_append_dropWhile (p := fun c => decide (c ≠ 10)) (l := cs)
  generalize h_line : cs.takeWhile (· ≠ 10) = line at h_split
  calc cs.drop line.length
      = (line ++ cs.dropWhile (· ≠ 10)).drop line.length := by rw [h_split]
    _ = cs.dropWhile (· ≠ 10) := List.drop_left

/-- The byte that ends a line's run of bytes other than LF is an LF, or the
input ends there. -/
private theorem line_end_at (cs : List UInt8) :
    cs.drop (cs.takeWhile (· ≠ 10)).length = [] ∨
      (cs.drop (cs.takeWhile (· ≠ 10)).length).head? = some 10 := by
  rw [drop_line]
  by_cases h_empty : cs.dropWhile (· ≠ 10) = []
  · exact Or.inl h_empty
  · refine Or.inr ?_
    have h_not := List.head_dropWhile_not (fun c => decide (c ≠ 10)) h_empty
    rw [List.head?_eq_some_head h_empty]
    simpa using h_not

/-- `skipText` skips a line when it drops the line's bytes and its LF. -/
private theorem skip_line_eq (cs : List UInt8) :
    (cs.dropWhile (· ≠ 10)).drop 1 = cs.drop ((cs.takeWhile (· ≠ 10)).length + 1) := by
  rw [← drop_line, List.drop_drop]

/-- No "-----BEGIN " starts at a byte of a line that `skipText` skips,
its LF included: not at its first byte, and by `beginInsideLine` not at
another. -/
private theorem first_line_clear (cs : List UInt8)
    (h_head : beginPrefix.isPrefixOf cs = false) (h_inside : beginInsideLine cs = false)
    (k : Nat) (h_k : k ≤ (cs.takeWhile (· ≠ 10)).length) :
    beginPrefix.isPrefixOf (cs.drop k) = false := by
  rcases Nat.lt_or_eq_of_le h_k with h_lt | rfl
  · rcases Nat.eq_zero_or_pos k with rfl | h_pos
    · simpa using h_head
    · have h_none := List.any_eq_false.mp h_inside k (List.mem_range.mpr h_lt)
      cases h_at : beginPrefix.isPrefixOf (cs.drop k) with
      | false => rfl
      | true =>
        exfalso
        apply h_none
        simp [h_at, Nat.pos_iff_ne_zero.mp h_pos]
  · exact beginPrefix_not_at_lf _ (line_end_at cs)

/-- A bundle's text that `skipText` reads to its end holds "-----BEGIN " at
no byte. -/
theorem skipText_ended_clear : ∀ (fuel : Nat) (cs : List UInt8),
    skipText fuel cs = .ended → ∀ k, beginPrefix.isPrefixOf (cs.drop k) = false
  | 0, _, h, _ => by simp [skipText] at h
  | fuel + 1, cs, h, k => by
    unfold skipText at h
    split at h
    · rename_i h_empty
      rw [List.isEmpty_iff.mp h_empty, List.drop_nil]
      exact beginPrefix_not_at_lf [] (Or.inl rfl)
    · split at h
      · cases h
      · split at h
        · cases h
        · rename_i h_head h_inside
          rw [skip_line_eq] at h
          have h_first_line := first_line_clear cs (Bool.eq_false_iff.mpr h_head)
            (Bool.eq_false_iff.mpr h_inside)
          generalize h_m : (cs.takeWhile (· ≠ 10)).length = m at h h_first_line
          by_cases h_k : k ≤ m
          · exact h_first_line k h_k
          · have h_rest := skipText_ended_clear fuel _ h (k - (m + 1))
            rwa [List.drop_drop, show m + 1 + (k - (m + 1)) = k by omega] at h_rest

/-- When `skipText` opens a block at `rest`, "-----BEGIN " starts there, at
the start of a line, and at no byte before it. -/
theorem skipText_block_clear : ∀ (fuel : Nat) (cs rest : List UInt8),
    skipText fuel cs = .block rest →
      ∃ n, rest = cs.drop n ∧ beginPrefix.isPrefixOf rest = true ∧
        (n = 0 ∨ cs[n - 1]? = some 10) ∧ ∀ k < n, beginPrefix.isPrefixOf (cs.drop k) = false
  | 0, _, _, h => by simp [skipText] at h
  | fuel + 1, cs, rest, h => by
    unfold skipText at h
    split at h
    · cases h
    · split at h
      · rename_i h_begin
        cases h
        exact ⟨0, rfl, h_begin, Or.inl rfl, fun k h_k => absurd h_k (Nat.not_lt_zero k)⟩
      · split at h
        · cases h
        · rename_i h_head h_inside
          rw [skip_line_eq] at h
          obtain ⟨n, h_rest, h_opens, h_line, h_clear⟩ := skipText_block_clear fuel _ rest h
          have h_first_line := first_line_clear cs (Bool.eq_false_iff.mpr h_head)
            (Bool.eq_false_iff.mpr h_inside)
          generalize h_m : (cs.takeWhile (· ≠ 10)).length = m at h_rest h_line h_clear h_first_line
          refine ⟨m + 1 + n, ?_, h_opens, Or.inr ?_, ?_⟩
          · rw [h_rest, List.drop_drop]
          · rcases Nat.eq_zero_or_pos n with rfl | h_pos
            · have h_end := line_end_at cs
              rw [h_m] at h_end
              rcases h_end with h_none | h_lf
              · rw [h_rest, List.drop_zero, ← List.drop_drop, h_none, List.drop_nil] at h_opens
                rw [beginPrefix_not_at_lf [] (Or.inl rfl)] at h_opens
                cases h_opens
              · rw [List.head?_drop] at h_lf
                simpa using h_lf
            · have h_lf := h_line.resolve_left (Nat.pos_iff_ne_zero.mp h_pos)
              rw [List.getElem?_drop] at h_lf
              rwa [show m + 1 + n - 1 = m + 1 + (n - 1) by omega]
          · intro k h_k
            by_cases h_first : k ≤ m
            · exact h_first_line k h_first
            · have h_after := h_clear (k - (m + 1)) (by omega)
              rwa [List.drop_drop, show m + 1 + (k - (m + 1)) = k by omega] at h_after

/-- A block of `label` reads only where `label`'s BEGIN line starts. -/
theorem readBlock?_begins (label cs : List UInt8) (block : ByteArray × List UInt8)
    (h : readBlock? label cs = some block) : (beginOf label).isPrefixOf cs = true := by
  simp only [readBlock?, Option.bind_eq_bind, Option.bind_eq_some_iff] at h
  obtain ⟨_, h_guard, -⟩ := h
  exact of_guard_eq_some h_guard

/-- What the loop keeps: the blocks read so far hold at most `roomMax`
bytes of DER together. -/
private theorem certificatesLoop_bounds (rule : TextRule) (roomMax : Nat) :
    ∀ (fuel : Nat) (cs : List UInt8) (done ders : List ByteArray),
      derTotal done ≤ roomMax → certificatesLoop rule roomMax fuel cs done = some ders →
      1 ≤ ders.length ∧ derTotal ders ≤ roomMax
  | 0, _, _, _, _, h => by simp [certificatesLoop] at h
  | fuel + 1, cs, done, ders, h_total, h => by
    unfold certificatesLoop at h
    split at h
    · simp at h
    · split at h
      · simp at h
      · rename_i h_nonempty
        rw [Option.some.injEq] at h
        subst h
        refine ⟨?_, ?_⟩
        · rw [List.length_reverse]
          cases done with
          | nil => simp at h_nonempty
          | cons _ _ => simp
        · simpa [derTotal, List.map_reverse, List.sum_reverse] using h_total
    · simp only [Option.bind_eq_bind, Option.bind_eq_some_iff] at h
      obtain ⟨⟨der, after⟩, -, _, h_fits, h_rest⟩ := h
      have h_fits' := of_guard_eq_some h_fits
      refine certificatesLoop_bounds rule roomMax fuel after (der :: done) ders ?_ h_rest
      simp only [derTotal, List.map_cons, List.sum_cons] at h_fits' ⊢
      omega

/-- A text `readCertificates?` accepts holds one or more blocks, all of
their DER together at most `roomMax` bytes. -/
theorem readCertificates?_bounds (rule : TextRule) (roomMax : Nat) (input : ByteArray)
    (ders : List ByteArray) (h : readCertificates? rule roomMax input = some ders) :
    1 ≤ ders.length ∧ derTotal ders ≤ roomMax :=
  certificatesLoop_bounds rule roomMax _ _ [] ders (by simp [derTotal]) h

/-! ## The bundle's BEGIN lines over a whole run

`readCertificates?_begins` holds Camilo's rule of 2026-10-13 over a whole
bundle. The lemmas before it show that past a block's first byte, no
"-----BEGIN " starts inside the block. -/

/-- "-----BEGIN CERTIFICATE-----" as its bytes. -/
private theorem beginLine_eq : beginLine =
    [45, 45, 45, 45, 45, 66, 69, 71, 73, 78, 32,
      67, 69, 82, 84, 73, 70, 73, 67, 65, 84, 69, 45, 45, 45, 45, 45] := by
  simp only [beginLine, byteArray_toList_eq]
  decide

/-- "-----END CERTIFICATE-----" as its bytes. -/
private theorem endLine_eq : endLine =
    [45, 45, 45, 45, 45, 69, 78, 68, 32,
      67, 69, 82, 84, 73, 70, 73, 67, 65, 84, 69, 45, 45, 45, 45, 45] := by
  simp only [endLine, byteArray_toList_eq]
  decide

/-- "-----BEGIN " starts at no byte but a dash. -/
private theorem begin_not_at (c : UInt8) (rest : List UInt8) (h_c : c ≠ 45) :
    beginPrefix.isPrefixOf (c :: rest) = false := by
  rw [beginPrefix_eq]
  simp [List.isPrefixOf, Ne.symm h_c]

/-- "-----BEGIN " starts at the head of `known ++ rest` only where it starts
at the head of `known`, or where `known` is a part of it. -/
private theorem begin_not_in_append (known rest : List UInt8)
    (h_long : beginPrefix.isPrefixOf known = false)
    (h_short : known.isPrefixOf beginPrefix = false) :
    beginPrefix.isPrefixOf (known ++ rest) = false := by
  cases h_begin : beginPrefix.isPrefixOf (known ++ rest) with
  | false => rfl
  | true =>
    rw [List.isPrefixOf_iff_prefix] at h_begin
    rcases List.prefix_or_prefix_of_prefix h_begin (List.prefix_append known rest) with
      h_in | h_part
    · rw [← List.isPrefixOf_iff_prefix, h_long] at h_in
      cases h_in
    · rw [← List.isPrefixOf_iff_prefix, h_short] at h_part
      cases h_part

/-- Past its first byte, "-----BEGIN " starts nowhere in a BEGIN
CERTIFICATE line and its line terminator, and no byte there starts a
part of it. -/
private theorem beginLine_inner (eol : List UInt8) (h_eol : eol = [10] ∨ eol = [13, 10]) :
    ∀ k < (beginLine ++ eol).length, 0 < k →
      beginPrefix.isPrefixOf ((beginLine ++ eol).drop k) = false ∧
        ((beginLine ++ eol).drop k).isPrefixOf beginPrefix = false := by
  rcases h_eol with rfl | rfl <;> rw [beginLine_eq, beginPrefix_eq] <;> decide

/-- "-----BEGIN " starts nowhere in an END CERTIFICATE line and the byte
after it, an LF or a CR, and no byte there starts a part of it. -/
private theorem endLine_clear (next : UInt8) (h_next : next = 10 ∨ next = 13) :
    ∀ k < endLine.length,
      beginPrefix.isPrefixOf ((endLine ++ [next]).drop k) = false ∧
        ((endLine ++ [next]).drop k).isPrefixOf beginPrefix = false := by
  rcases h_next with rfl | rfl <;> rw [endLine_eq, beginPrefix_eq] <;> decide

/-- "-----BEGIN " starts nowhere in an END CERTIFICATE line that ends the
input. -/
private theorem endLine_alone_clear :
    ∀ k < endLine.length, beginPrefix.isPrefixOf (endLine.drop k) = false := by
  rw [endLine_eq, beginPrefix_eq]
  decide

/-- A CERTIFICATE block that `readBlock?` reads is its BEGIN line, a line
terminator, a body with no dash, its END line, and what follows. -/
private theorem readBlock?_shape (cs after : List UInt8) (der : ByteArray)
    (h : readBlock? labelCertificate cs = some (der, after)) :
    ∃ eol body, (eol = [10] ∨ eol = [13, 10]) ∧ (∀ c ∈ body, c ≠ 45) ∧
      cs = beginLine ++ eol ++ body ++ endLine ++ after := by
  simp only [readBlock?, beginOf_certificate, endOf_certificate, Option.bind_eq_bind,
    Option.bind_eq_some_iff] at h
  obtain ⟨_, h_begin, rest, h_eol, _, h_end, _, -, h_pair⟩ := h
  have h_begins := List.prefix_iff_eq_append.mp
    (List.isPrefixOf_iff_prefix.mp (of_guard_eq_some h_begin))
  have h_ends := List.prefix_iff_eq_append.mp
    (List.isPrefixOf_iff_prefix.mp (of_guard_eq_some h_end))
  have h_after := (Prod.mk.inj (Option.some.inj h_pair)).2
  have h_tail : ∃ eol, (eol = [10] ∨ eol = [13, 10]) ∧
      cs.drop beginLine.length = eol ++ rest := by
    unfold eatEol? at h_eol
    split at h_eol
    · rename_i h_split
      exact ⟨[13, 10], Or.inr rfl, by rw [h_split, Option.some.inj h_eol]; rfl⟩
    · rename_i h_split
      exact ⟨[10], Or.inl rfl, by rw [h_split, Option.some.inj h_eol]; rfl⟩
    · cases h_eol
  obtain ⟨eol, h_eol_bytes, h_tail⟩ := h_tail
  have h_no_dash := List.all_eq_true.mp
    (List.all_takeWhile (p := fun c => decide (c ≠ 45)) (l := rest))
  have h_body := List.prefix_iff_eq_append.mp
    (List.takeWhile_prefix (p := fun c => decide (c ≠ 45)) (l := rest))
  generalize rest.takeWhile (fun c => decide (c ≠ 45)) = body at h_ends h_after h_no_dash h_body
  refine ⟨eol, body, h_eol_bytes, fun c h_c => by simpa using h_no_dash c h_c, ?_⟩
  calc cs = beginLine ++ cs.drop beginLine.length := h_begins.symm
    _ = beginLine ++ (eol ++ (body ++ rest.drop body.length)) := by rw [h_tail, h_body]
    _ = beginLine ++ eol ++ body ++ endLine ++ after := by rw [← h_ends, h_after]; simp

/-- Past a block's first byte, "-----BEGIN " starts nowhere in the block,
when an LF, a CR or the end of the input follows its END line. -/
private theorem block_inner_clear (eol body after : List UInt8)
    (h_eol : eol = [10] ∨ eol = [13, 10]) (h_body : ∀ c ∈ body, c ≠ 45)
    (h_after : after = [] ∨ ∃ c rest, (c = 10 ∨ c = 13) ∧ after = c :: rest) :
    ∀ k, 0 < k → k < (beginLine ++ eol ++ body ++ endLine).length →
      beginPrefix.isPrefixOf ((beginLine ++ eol ++ body ++ endLine ++ after).drop k) =
        false := by
  intro k h_pos h_k
  have h_parts : beginLine ++ eol ++ body ++ endLine ++ after =
      (beginLine ++ eol) ++ (body ++ (endLine ++ after)) := by simp
  rw [h_parts]
  by_cases h_line : k < (beginLine ++ eol).length
  · rw [List.drop_append_of_le_length (Nat.le_of_lt h_line)]
    obtain ⟨h_long, h_short⟩ := beginLine_inner eol h_eol k h_line h_pos
    exact begin_not_in_append _ _ h_long h_short
  rw [List.drop_append, List.drop_eq_nil_of_le (Nat.le_of_not_lt h_line), List.nil_append]
  by_cases h_in_body : k - (beginLine ++ eol).length < body.length
  · rw [List.drop_append_of_le_length (Nat.le_of_lt h_in_body),
      List.drop_eq_getElem_cons h_in_body, List.cons_append]
    exact begin_not_at _ _ (h_body _ (List.getElem_mem h_in_body))
  rw [List.drop_append, List.drop_eq_nil_of_le (Nat.le_of_not_lt h_in_body), List.nil_append]
  have h_in_end : k - (beginLine ++ eol).length - body.length < endLine.length := by
    simp only [List.length_append] at h_k h_line h_in_body ⊢
    omega
  generalize k - (beginLine ++ eol).length - body.length = i at h_in_end
  rcases h_after with rfl | ⟨c, rest, h_c, rfl⟩
  · simpa using endLine_alone_clear i h_in_end
  · obtain ⟨h_long, h_short⟩ := endLine_clear c h_c i h_in_end
    have h_split : endLine ++ c :: rest = (endLine ++ [c]) ++ rest := by simp
    rw [h_split, List.drop_append_of_le_length (by simp; omega)]
    exact begin_not_in_append _ _ h_long h_short

/-- `lineEnds?` reads nothing at the end of the input, or an LF, or CR LF. -/
private theorem lineEnds?_shape (cs rest : List UInt8) (h : lineEnds? cs = some rest) :
    (cs = [] ∧ rest = []) ∨ cs = 10 :: rest ∨ cs = 13 :: 10 :: rest := by
  unfold lineEnds? at h
  split at h
  · rename_i h_empty
    exact Or.inl ⟨List.isEmpty_iff.mp h_empty, (Option.some.inj h).symm ▸ rfl⟩
  · unfold eatEol? at h
    split at h
    · exact Or.inr (Or.inr (by rw [Option.some.inj h]))
    · exact Or.inr (Or.inl (by rw [Option.some.inj h]))
    · cases h

/-- Where a bundle's text starts: at the first byte before the first
block, and after a block past the end of the END line's line. The bytes
before it are an LF, or CR LF, or none. -/
private theorem skipped_start (first : Bool) (cs rest : List UInt8)
    (h : (if first then some cs else lineEnds? cs) = some rest) :
    ∃ e, rest = cs.drop e ∧ (∀ j < e, beginPrefix.isPrefixOf (cs.drop j) = false) ∧
      ((e = 0 ∧ (first = true ∨ cs = [])) ∨ cs[e - 1]? = some 10) := by
  cases first with
  | true =>
    exact ⟨0, (Option.some.inj h).symm, fun j h_j => absurd h_j (Nat.not_lt_zero j),
      Or.inl ⟨rfl, Or.inl rfl⟩⟩
  | false =>
    rcases lineEnds?_shape cs rest h with ⟨rfl, rfl⟩ | rfl | rfl
    · exact ⟨0, rfl, fun j h_j => absurd h_j (Nat.not_lt_zero j), Or.inl ⟨rfl, Or.inr rfl⟩⟩
    · refine ⟨1, rfl, fun j h_j => ?_, Or.inr rfl⟩
      rw [Nat.lt_one_iff.mp h_j]
      exact begin_not_at 10 rest (by decide)
    · refine ⟨2, rfl, fun j h_j => ?_, Or.inr rfl⟩
      rcases j with _ | _ | j
      · exact begin_not_at 13 _ (by decide)
      · exact begin_not_at 10 rest (by decide)
      · omega

/-- After a block, a run that the loop accepts goes on past the end of the
END line's line. -/
private theorem loop_lineEnds (roomMax fuel : Nat) (cs : List UInt8) (der : ByteArray)
    (done ders : List ByteArray)
    (h : certificatesLoop .skipped roomMax fuel cs (der :: done) = some ders) :
    ∃ rest, lineEnds? cs = some rest := by
  cases fuel with
  | zero => simp [certificatesLoop] at h
  | succ fuel =>
    unfold certificatesLoop at h
    cases h_ends : lineEnds? cs with
    | none => simp [nextBlock, h_ends] at h
    | some rest => exact ⟨rest, rfl⟩

/-- The loop's invariant under the bundle's rule: wherever "-----BEGIN "
starts in the text it accepts, it starts a line, and CERTIFICATE's BEGIN
line starts there. Only the first block may open at the first byte. -/
private theorem loop_begins (roomMax : Nat) : ∀ (fuel : Nat) (cs : List UInt8)
    (done ders : List ByteArray), certificatesLoop .skipped roomMax fuel cs done = some ders →
      ∀ k, beginPrefix.isPrefixOf (cs.drop k) = true →
        ((k = 0 ∧ done = []) ∨ cs[k - 1]? = some 10) ∧ beginLine.isPrefixOf (cs.drop k) = true
  | 0, _, _, _, h, _, _ => by simp [certificatesLoop] at h
  | fuel + 1, cs, done, ders, h, k, h_k => by
    unfold certificatesLoop nextBlock at h
    generalize h_start : (if done.isEmpty = true then some cs else lineEnds? cs) = start at h
    cases start with
    | none => simp at h
    | some rest =>
      obtain ⟨e, h_rest, h_before, h_line⟩ := skipped_start _ cs rest h_start
      have h_text_at : ∀ j, e ≤ j → cs.drop j = rest.drop (j - e) := by
        intro j h_j
        rw [h_rest, List.drop_drop, Nat.add_sub_cancel' h_j]
      simp only at h
      generalize h_skip : skipText (rest.length + 1) rest = next at h
      cases next with
      | refused => simp at h
      | ended =>
        exfalso
        by_cases h_early : k < e
        · rw [h_before k h_early] at h_k
          cases h_k
        · rw [h_text_at k (Nat.le_of_not_lt h_early),
            skipText_ended_clear _ rest h_skip (k - e)] at h_k
          cases h_k
      | block opened =>
        simp only [Option.bind_eq_bind, Option.bind_eq_some_iff] at h
        obtain ⟨⟨der, after⟩, h_read, _, -, h_rec⟩ := h
        obtain ⟨n, h_opened, h_opens, h_n_line, h_n_clear⟩ :=
          skipText_block_clear _ rest opened h_skip
        obtain ⟨eol, body, h_eol, h_body, h_shape⟩ := readBlock?_shape opened after der h_read
        obtain ⟨ends, h_ends⟩ := loop_lineEnds roomMax fuel after der done ders h_rec
        have h_after : after = [] ∨ ∃ c rest, (c = 10 ∨ c = 13) ∧ after = c :: rest := by
          rcases lineEnds?_shape after ends h_ends with ⟨rfl, -⟩ | rfl | rfl
          · exact Or.inl rfl
          · exact Or.inr ⟨10, ends, Or.inl rfl, rfl⟩
          · exact Or.inr ⟨13, 10 :: ends, Or.inr rfl, rfl⟩
        generalize h_m : (beginLine ++ eol ++ body ++ endLine).length = m
        have h_block_at : cs.drop (e + n) = opened := by
          rw [h_text_at (e + n) (Nat.le_add_right e n), Nat.add_sub_cancel_left, h_opened]
        have h_after_at : cs.drop (e + n + m) = after := by
          rw [← List.drop_drop, h_block_at, h_shape, ← h_m, List.drop_left]
        rcases Nat.lt_trichotomy k (e + n) with h_lt | rfl | h_gt
        · exfalso
          by_cases h_early : k < e
          · rw [h_before k h_early] at h_k
            cases h_k
          · rw [h_text_at k (Nat.le_of_not_lt h_early), h_n_clear (k - e) (by omega)] at h_k
            cases h_k
        · refine ⟨?_, ?_⟩
          · by_cases h_n0 : n = 0
            · subst h_n0
              rcases h_line with ⟨rfl, h_first | rfl⟩ | h_lf
              · exact Or.inl ⟨rfl, List.isEmpty_iff.mp h_first⟩
              · rw [← h_block_at] at h_opens
                simp [beginPrefix_eq] at h_opens
              · exact Or.inr h_lf
            · right
              have h_lf := h_n_line.resolve_left h_n0
              rw [h_rest, List.getElem?_drop] at h_lf
              rwa [show e + n - 1 = e + (n - 1) by omega]
          · rw [h_block_at, ← beginOf_certificate]
            exact readBlock?_begins _ _ _ h_read
        · by_cases h_inside : k < e + n + m
          · exfalso
            have h_clear := block_inner_clear eol body after h_eol h_body h_after
              (k - (e + n)) (by omega) (by rw [h_m]; omega)
            rw [← h_shape, ← h_block_at, List.drop_drop,
              Nat.add_sub_cancel' (Nat.le_of_lt h_gt)] at h_clear
            rw [h_clear] at h_k
            cases h_k
          · have h_later : cs.drop k = after.drop (k - (e + n + m)) := by
              rw [← h_after_at, List.drop_drop, Nat.add_sub_cancel' (Nat.le_of_not_lt h_inside)]
            rw [h_later] at h_k ⊢
            obtain ⟨h_pos, h_begins⟩ :=
              loop_begins roomMax fuel after (der :: done) ders h_rec _ h_k
            refine ⟨Or.inr ?_, h_begins⟩
            rcases h_pos with ⟨-, h_nil⟩ | h_lf
            · cases h_nil
            · by_cases h_k0 : k - (e + n + m) = 0
              · exfalso
                rw [h_k0, List.drop_zero] at h_k
                rcases h_after with rfl | ⟨c, rest', h_c, rfl⟩
                · simp [beginPrefix_eq] at h_k
                · rw [begin_not_at c rest' (by rcases h_c with rfl | rfl <;> decide)] at h_k
                  cases h_k
              · rw [← h_after_at, List.getElem?_drop] at h_lf
                rwa [show e + n + m + (k - (e + n + m) - 1) = k - 1 by omega] at h_lf

/-- A bundle that `readCertificates?` accepts holds "-----BEGIN " only at
the start of a line, and there CERTIFICATE's BEGIN line starts. So a
BEGIN line of any other label refuses the bundle, and so does
"-----BEGIN " inside a line. -/
theorem readCertificates?_begins (roomMax : Nat) (input : ByteArray) (ders : List ByteArray)
    (h : readCertificates? .skipped roomMax input = some ders) (k : Nat)
    (h_k : beginPrefix.isPrefixOf (input.toList.drop k) = true) :
    (k = 0 ∨ input.toList[k - 1]? = some 10) ∧
      beginLine.isPrefixOf (input.toList.drop k) = true := by
  obtain ⟨h_line, h_begins⟩ := loop_begins roomMax _ _ [] ders h k h_k
  exact ⟨h_line.imp_left And.left, h_begins⟩

end Spec.PemBlocks
