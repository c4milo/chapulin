import Spec.Bytes
import Spec.X509Der

/-!
Hostnames for the web PKI trust mode, written from RFC 6125 §6.4 (name
matching), RFC 5280 §4.2.1.6 (GeneralNames), RFC 1035 §2.3.4 (label
length), RFC 1123 §2.1 (label edges) and RFC 6066 §3 (no IP literal in
server_name) — never from the C sources.

The reference name is checked for shape before anything is matched
against it: 1..253 bytes of `[A-Za-z0-9.-]`, every label 1..63 bytes,
no label that starts or ends with '-', and a last label that is not
all digits. Matching is over the dNSName entries of a GeneralNames,
ASCII case-insensitively; a wildcard is the whole leftmost label of
the presented name and stands for exactly one label of the reference
name, and it needs two labels after it. Line ops:
`webpki_hostname <hex>` → `1`/`0`; `webpki_san <san> <host>` →
`1`/`0`, both bytes as hex.
-/

namespace Spec.WebpkiName

open Spec.Bytes
open Spec.X509 (byteAt? readLen slice)

/-- The dot, '.', 0x2e. -/
def dot : UInt8 := 0x2e

/-- The wildcard, '*', 0x2a. -/
def star : UInt8 := 0x2a

/-- The hyphen, '-', 0x2d. -/
def hyphen : UInt8 := 0x2d

/-- ASCII letters, either case. -/
def isLetter (b : UInt8) : Bool := (0x41 ≤ b && b ≤ 0x5a) || (0x61 ≤ b && b ≤ 0x7a)

/-- ASCII decimal digits. -/
def isDigit (b : UInt8) : Bool := 0x30 ≤ b && b ≤ 0x39

/-- The reference-name alphabet `[A-Za-z0-9.-]`. -/
def isHostByte (b : UInt8) : Bool := isLetter b || isDigit b || b == dot || b == hyphen

/-- Every label 1..63 bytes (RFC 1035 §2.3.4), `run` counting the
current label so far. The 1 refuses an empty label, and with it a
leading dot, a trailing dot and two dots in a row. -/
def labelsOk : List UInt8 → Nat → Bool
  | [], run => 1 ≤ run && run ≤ 63
  | b :: rest, run =>
    if b == dot then (1 ≤ run && run ≤ 63) && labelsOk rest 0 else labelsOk rest (run + 1)

/-- A label neither starts nor ends with '-': RFC 952's label rule as
RFC 1123 §2.1 amends it, where a label starts and ends with a letter or
digit. -/
def labelEdgesOk (label : List UInt8) : Bool :=
  label.head? != some hyphen && label.getLast? != some hyphen

/-- The bytes after the last dot. -/
def lastLabel (h : List UInt8) : List UInt8 := (h.reverse.takeWhile (· != dot)).reverse

/-- The shape check on the reference name. The labels are the byte
runs between dots, `h.splitOn dot`. An all-digit last label is an IPv4
literal's shape, which RFC 6066 §3 forbids in server_name. -/
def hostnameOk (h : List UInt8) : Bool :=
  1 ≤ h.length && h.length ≤ 253 && h.all isHostByte && labelsOk h 0 &&
    (h.splitOn dot).all labelEdgesOk && !(lastLabel h).all isDigit

/-- ASCII case folding: 'A'..'Z' to 'a'..'z', every other byte as is. -/
def lower (b : UInt8) : UInt8 := if 0x41 ≤ b && b ≤ 0x5a then b + 0x20 else b

/-- Equal after folding both sides (RFC 6125 §6.4.1). -/
def foldEq (a b : List UInt8) : Bool := a.map lower == b.map lower

/-- The presented name was "*." then `suffix`. The wildcard stands for
exactly one label, so `host` must be one label, a dot, then bytes
equal to `suffix`; and `suffix` must hold a dot, two labels at least,
so a wildcard directly under a public suffix such as "*.com" matches
nothing (RFC 6125 §6.4.3). -/
def matchWildcard (suffix host : List UInt8) : Bool :=
  suffix.any (· == dot) &&
    match host.dropWhile (· != dot) with
    | _ :: rest => foldEq suffix rest
    | [] => false

/-- One dNSName against the reference name. A '*' anywhere but as the
whole leftmost label is an ordinary byte, and the exact compare then
fails against a reference name that holds none. -/
def matchDnsName (name host : List UInt8) : Bool :=
  match name with
  | a :: b :: suffix => if a == star && b == dot then matchWildcard suffix host else foldEq name host
  | _ => foldEq name host

/-- The nine arms of GeneralName ::= CHOICE (RFC 5280 §4.2.1.6), in
a module with IMPLICIT tags, each as its one DER identifier byte:
context-specific class, the arm number, and the constructed bit
exactly when the arm's type is constructed (X.690 §8.14). otherName
[0], x400Address [3] and ediPartyName [5] are SEQUENCEs; directoryName
[4] is a Name, a CHOICE, and a tagged CHOICE is always explicit;
rfc822Name [1], dNSName [2], uniformResourceIdentifier [6], iPAddress
[7] and registeredID [8] are primitive. No byte here has the low five
bits 0x1f that start the high-tag-number form (X.690 §8.1.2.4). -/
def generalNameTags : List UInt8 := [0xa0, 0x81, 0x82, 0xa3, 0xa4, 0xa5, 0x86, 0x87, 0x88]

/-- The entries of one GeneralNames content, each as its CHOICE tag
and content bytes, read from `off` to the end of `b`; `none` on a
malformed entry: a tag outside `generalNameTags`, or a length that is
not minimal or runs past the end. Each entry is at least two bytes, so
`fuel` at `b.size` never runs out first. -/
def entries : Nat → ByteArray → Nat → List (UInt8 × ByteArray) → Option (List (UInt8 × ByteArray))
  | 0, _, _, _ => none
  | fuel + 1, b, off, acc =>
    if b.size ≤ off then some acc.reverse
    else do
      let tag ← byteAt? b off
      guard (generalNameTags.contains tag)
      let (len, contentOff) ← readLen b (off + 1)
      entries fuel b (contentOff + len) ((tag, slice b contentOff len) :: acc)

/-- GeneralNames ::= SEQUENCE OF GeneralName (RFC 5280 §4.2.1.6), the
whole of `b`: its entries, or `none` when the SEQUENCE header, its
fill or any entry is malformed. -/
def generalNames? (b : ByteArray) : Option (List (UInt8 × ByteArray)) := do
  let tag ← byteAt? b 0
  guard (tag == 0x30)
  let (len, off) ← readLen b 1
  guard (off + len == b.size)
  entries b.size b off []

/-- dNSName is GeneralName's `[2] IMPLICIT IA5String`. -/
def dnsNameTag : UInt8 := 0x82

/-- Whether any dNSName entry of the GeneralNames `san` matches `host`.
Every entry's tag is checked and its length read, so one malformed
entry anywhere refuses the whole GeneralNames, even after a match. -/
def matchSan (san : ByteArray) (host : List UInt8) : Bool :=
  match generalNames? san with
  | some es => es.any (fun e => e.1 == dnsNameTag && matchDnsName e.2.toList host)
  | none => false

/-- Structural checks: the shape rules on the reference name, a hyphen
inside a label and at each of its edges, a 63-byte label on both sides
of the hyphen rule, exact and folded matches, the wildcard on each
side of its rules, a NUL in a presented name, a skipped iPAddress
entry, and the GeneralName tag rule on both sides: [8] and [0]
accepted, [9], a primitive [0], a constructed dNSName, universal tags
and the high-tag-number form refused. -/
def selftest : Bool :=
  let host (s : String) : List UInt8 := (ascii s).toList
  let entry (tag : UInt8) (s : String) : ByteArray :=
    ByteArray.mk #[tag, UInt8.ofNat s.utf8ByteSize] ++ ascii s
  let san (es : List ByteArray) : ByteArray :=
    let body := es.foldl (· ++ ·) ByteArray.empty
    ByteArray.mk #[0x30, UInt8.ofNat body.size] ++ body
  hostnameOk (host "s3.example.test")
    && !hostnameOk (host "example.test.")
    && !hostnameOk (host ".example.test")
    && !hostnameOk (host "a..b")
    && !hostnameOk (host "192.0.2.1")
    && !hostnameOk (host "*.example.test")
    && !hostnameOk []
    && hostnameOk (host "a-b")
    && hostnameOk (host "xn--abc.example")
    && !hostnameOk (host "-")
    && !hostnameOk (host "-a")
    && !hostnameOk (host "a-")
    && !hostnameOk (host "a.-b")
    && !hostnameOk (host "a-.b")
    && !hostnameOk (host "-a.b")
    && !hostnameOk (host "a.b-")
    -- A 63-byte label of 'a', 61 hyphens and 'a', then the same length
    -- ending in a hyphen.
    && hostnameOk (0x61 :: List.replicate 61 hyphen ++ host "a.test")
    && !hostnameOk (0x61 :: List.replicate 62 hyphen ++ host ".test")
    && matchSan (san [entry dnsNameTag "S3.Example.TEST"]) (host "s3.example.test")
    && matchSan (san [entry dnsNameTag "*.example.test"]) (host "s3.example.test")
    && !matchSan (san [entry dnsNameTag "*.example.test"]) (host "example.test")
    && !matchSan (san [entry dnsNameTag "*.example.test"]) (host "a.b.example.test")
    && !matchSan (san [entry dnsNameTag "s3*.example.test"]) (host "s3.example.test")
    && !matchSan (san [entry dnsNameTag "*.com"]) (host "example.com")
    && !matchSan (san [entry dnsNameTag "s3.example.test\x00.evil"]) (host "s3.example.test")
    && matchSan (san [entry 0x87 "\x7f\x00\x00\x01", entry dnsNameTag "s3.example.test"])
        (host "s3.example.test")
    && !matchSan (san [entry 0x81 "s3.example.test"]) (host "s3.example.test")
    && !matchSan (ByteArray.mk #[0x30, 0x02, 0x82]) (host "s3.example.test")
    -- 9f 1f 2b is one high-tag-number header: tag number 31, length 43,
    -- and the 43 bytes hold 30 'A' and then bytes shaped like a dNSName
    -- entry. Read as one tag byte 9f and length 1f, the dNSName would
    -- be an entry of its own and would match.
    && !matchSan (san [ByteArray.mk #[0x9f, 0x1f, 0x2b] ++ ascii "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        entry dnsNameTag "victim.test"]) (host "victim.test")
    && !matchSan (san [entry dnsNameTag "s3.example.test", entry 0x04 "x"]) (host "s3.example.test")
    && !matchSan (san [entry dnsNameTag "s3.example.test", entry 0x00 ""]) (host "s3.example.test")
    && !matchSan (san [entry dnsNameTag "s3.example.test", entry 0x9f "\x01"])
        (host "s3.example.test")
    && !matchSan (san [entry 0xa2 "s3.example.test"]) (host "s3.example.test")
    && matchSan (san [entry 0x88 "\x2b\x06\x01", entry dnsNameTag "s3.example.test"])
        (host "s3.example.test")
    && !matchSan (san [entry 0x89 "", entry dnsNameTag "s3.example.test"]) (host "s3.example.test")
    && matchSan (san [entry 0xa0 "", entry dnsNameTag "s3.example.test"]) (host "s3.example.test")
    && !matchSan (san [entry 0x80 "", entry dnsNameTag "s3.example.test"]) (host "s3.example.test")

/-!
## Proofs

The shape check is the whole defence against a presented name that
holds NUL or '*' (docs/webpki.md, "Hostnames"): it refuses a reference
name that holds either byte, and the matcher then compares
equal-length byte ranges against that name, so a presented byte
matches only a reference byte equal to it up to case. The theorems below say exactly
that: an accepted reference name holds neither byte, every byte of a
matching presented name is a reference byte up to case or one of the
two bytes of the wildcard label, and so a matching presented name
holds no NUL and no '*' but the wildcard's own.
-/

/-- The alphabet has no NUL. -/
private theorem isHostByte_zero : isHostByte 0 = false := by decide

/-- The alphabet has no '*'. -/
private theorem isHostByte_star : isHostByte star = false := by decide

private theorem hostnameOk_bytes (h : List UInt8) (h_ok : hostnameOk h = true) (b : UInt8)
    (h_mem : b ∈ h) : isHostByte b = true := by
  unfold hostnameOk at h_ok
  simp only [Bool.and_eq_true, decide_eq_true_eq] at h_ok
  exact List.all_eq_true.mp h_ok.1.1.1.2 b h_mem

/-- An accepted reference name is 1..253 bytes, DNS's own limit and
the bound the CBMC harness proves the C at. -/
theorem hostnameOk_length (h : List UInt8) (h_ok : hostnameOk h = true) :
    1 ≤ h.length ∧ h.length ≤ 253 := by
  unfold hostnameOk at h_ok
  simp only [Bool.and_eq_true, decide_eq_true_eq] at h_ok
  exact ⟨h_ok.1.1.1.1.1, h_ok.1.1.1.1.2⟩

/-- An accepted reference name holds no NUL. -/
theorem hostnameOk_no_nul (h : List UInt8) (h_ok : hostnameOk h = true) : 0 ∉ h := by
  intro h_mem
  have h_byte := hostnameOk_bytes h h_ok 0 h_mem
  rw [isHostByte_zero] at h_byte
  exact Bool.false_ne_true h_byte

/-- An accepted reference name holds no '*'. -/
theorem hostnameOk_no_star (h : List UInt8) (h_ok : hostnameOk h = true) : star ∉ h := by
  intro h_mem
  have h_byte := hostnameOk_bytes h h_ok star h_mem
  rw [isHostByte_star] at h_byte
  exact Bool.false_ne_true h_byte

/-- A byte of a label of `h` is a byte of `h`, and it is not a dot. -/
private theorem mem_of_mem_splitOn (h label : List UInt8) (h_label : label ∈ h.splitOn dot)
    (b : UInt8) (h_mem : b ∈ label) : b ∈ h ∧ b ≠ dot := by
  induction h generalizing label with
  | nil => simp_all
  | cons x rest ih =>
    rw [List.splitOn_cons_eq_if_modifyHead] at h_label
    split at h_label
    · rcases List.mem_cons.mp h_label with rfl | h_rest
      · exact absurd h_mem List.not_mem_nil
      · obtain ⟨h_in, h_not_dot⟩ := ih label h_rest h_mem
        exact ⟨List.mem_cons_of_mem x h_in, h_not_dot⟩
    · next h_x =>
      obtain ⟨first, others, h_split⟩ := List.exists_cons_of_ne_nil (List.splitOn_ne_nil dot rest)
      rw [h_split, List.modifyHead_cons, List.mem_cons] at h_label
      rcases h_label with rfl | h_other
      · rcases List.mem_cons.mp h_mem with rfl | h_first
        · exact ⟨List.mem_cons_self, fun h_eq => h_x (beq_iff_eq.mpr h_eq)⟩
        · obtain ⟨h_in, h_not_dot⟩ := ih first (h_split ▸ List.mem_cons_self) h_first
          exact ⟨List.mem_cons_of_mem x h_in, h_not_dot⟩
      · obtain ⟨h_in, h_not_dot⟩ := ih label (h_split ▸ List.mem_cons_of_mem first h_other) h_mem
        exact ⟨List.mem_cons_of_mem x h_in, h_not_dot⟩

/-- Every label of an accepted reference name, a byte run between dots,
starts and ends with a letter or a digit and never with '-' (RFC 1123
§2.1). -/
theorem hostnameOk_label_edges (h : List UInt8) (h_ok : hostnameOk h = true) (label : List UInt8)
    (h_label : label ∈ h.splitOn dot) :
    (∀ b, label.head? = some b → (isLetter b || isDigit b) = true) ∧
      ∀ b, label.getLast? = some b → (isLetter b || isDigit b) = true := by
  have h_edges : labelEdgesOk label = true := by
    unfold hostnameOk at h_ok
    simp only [Bool.and_eq_true, decide_eq_true_eq] at h_ok
    exact List.all_eq_true.mp h_ok.1.2 label h_label
  unfold labelEdgesOk at h_edges
  simp only [Bool.and_eq_true, bne_iff_ne, ne_eq] at h_edges
  obtain ⟨h_head, h_last⟩ := h_edges
  have h_edge (b : UInt8) (h_mem : b ∈ label) (h_not_hyphen : b ≠ hyphen) :
      (isLetter b || isDigit b) = true := by
    obtain ⟨h_in, h_not_dot⟩ := mem_of_mem_splitOn h label h_label b h_mem
    simpa [isHostByte, h_not_dot, h_not_hyphen] using hostnameOk_bytes h h_ok b h_in
  refine ⟨fun b h_b => ?_, fun b h_b => ?_⟩
  · exact h_edge b (List.mem_of_mem_head? h_b) (fun h_eq => h_head (h_eq ▸ h_b))
  · exact h_edge b (List.mem_of_getLast? h_b) (fun h_eq => h_last (h_eq ▸ h_b))

/-- `lower` changes only 'A'..'Z', and it maps them to 'a'..'z', so a
byte whose `lower` is below 'a' equals that result: a byte whose
`lower` is NUL or '*' is NUL or '*' itself. -/
private theorem lower_eq_low (c t : UInt8) (h_low : t.toNat < 0x61) (h : lower c = t) : c = t := by
  unfold lower at h
  split at h
  · next h_letter =>
    simp only [Bool.and_eq_true, decide_eq_true_eq] at h_letter
    have h_add := UInt8.toNat_add c 0x20
    rw [h] at h_add
    have h_ge : (0x41 : UInt8).toNat ≤ c.toNat := h_letter.1
    have h_le : c.toNat ≤ (0x5a : UInt8).toNat := h_letter.2
    simp at h_add h_ge h_le
    omega
  · exact h

/-- A byte of a folded-equal name is a byte of the other name, up to
case. -/
private theorem foldEq_mem (a b : List UInt8) (h : foldEq a b = true) (x : UInt8) (h_mem : x ∈ a) :
    ∃ y, y ∈ b ∧ lower y = lower x := by
  unfold foldEq at h
  have h_eq : a.map lower = b.map lower := by simpa using h
  have h_in : lower x ∈ b.map lower := by
    rw [← h_eq]
    exact List.mem_map.mpr ⟨x, h_mem, rfl⟩
  obtain ⟨y, h_y, h_yx⟩ := List.mem_map.mp h_in
  exact ⟨y, h_y, h_yx⟩

/-- A wildcard match compares the suffix against bytes of the
reference name: the bytes after its first dot. -/
private theorem matchWildcard_mem (suffix host : List UInt8) (h : matchWildcard suffix host = true)
    (x : UInt8) (h_mem : x ∈ suffix) : ∃ y, y ∈ host ∧ lower y = lower x := by
  unfold matchWildcard at h
  simp only [Bool.and_eq_true] at h
  obtain ⟨_, h_rest⟩ := h
  split at h_rest
  · next d rest h_drop =>
    obtain ⟨y, h_y, h_yx⟩ := foldEq_mem suffix rest h_rest x h_mem
    have h_sub := List.dropWhile_sublist (l := host) (· != dot)
    rw [h_drop] at h_sub
    exact ⟨y, (List.Sublist.subset h_sub) (List.mem_cons_of_mem d h_y), h_yx⟩
  · exact absurd h_rest Bool.false_ne_true

/-- Every byte of a matching presented name is a byte of the reference
name up to case, or one of the two bytes of the wildcard label "*.".
Nothing else in a presented name takes part in a match. -/
theorem matchDnsName_mem (name host : List UInt8) (h : matchDnsName name host = true) (x : UInt8)
    (h_mem : x ∈ name) : (∃ y, y ∈ host ∧ lower y = lower x) ∨ x = star ∨ x = dot := by
  unfold matchDnsName at h
  split at h
  · next a b suffix =>
    split at h
    · next h_wild =>
      simp only [Bool.and_eq_true, beq_iff_eq] at h_wild
      obtain ⟨rfl, rfl⟩ := h_wild
      simp only [List.mem_cons] at h_mem
      rcases h_mem with rfl | rfl | h_suffix
      · exact Or.inr (Or.inl rfl)
      · exact Or.inr (Or.inr rfl)
      · exact Or.inl (matchWildcard_mem suffix host h x h_suffix)
    · exact Or.inl (foldEq_mem _ host h x h_mem)
  · exact Or.inl (foldEq_mem _ host h x h_mem)

/-- Against an accepted reference name, a matching presented name
holds no NUL: the `evil.example\0s3.amazonaws.com` case from
docs/webpki.md, refused by the shape check on the other side. -/
theorem matchDnsName_no_nul (name host : List UInt8) (h_ok : hostnameOk host = true)
    (h : matchDnsName name host = true) : 0 ∉ name := by
  intro h_mem
  rcases matchDnsName_mem name host h 0 h_mem with ⟨y, h_y, h_fold⟩ | h_star | h_dot
  · have h_zero : y = 0 := lower_eq_low y 0 (by decide) (by rw [h_fold]; rfl)
    rw [h_zero] at h_y
    exact hostnameOk_no_nul host h_ok h_y
  · exact absurd h_star (by decide)
  · exact absurd h_dot (by decide)

/-- Against an accepted reference name, the only '*' a matching
presented name can hold is the wildcard label's own: the name is
"*." then a suffix with no '*' in it. So a wildcard that is only part
of a label, or one anywhere but leftmost, matches nothing. -/
theorem matchDnsName_star (name host : List UInt8) (h_ok : hostnameOk host = true)
    (h : matchDnsName name host = true) (h_star : star ∈ name) :
    ∃ suffix, name = star :: dot :: suffix ∧ star ∉ suffix := by
  have h_no_star : ∀ x ∈ name, (∃ y, y ∈ host ∧ lower y = lower x) → x ≠ star := by
    intro x _ ⟨y, h_y, h_fold⟩ h_x
    rw [h_x] at h_fold
    have h_is_star : y = star := lower_eq_low y star (by decide) (by rw [h_fold]; rfl)
    rw [h_is_star] at h_y
    exact hostnameOk_no_star host h_ok h_y
  unfold matchDnsName at h
  split at h
  · next a b suffix =>
    split at h
    · next h_wild =>
      simp only [Bool.and_eq_true, beq_iff_eq] at h_wild
      obtain ⟨rfl, rfl⟩ := h_wild
      refine ⟨suffix, rfl, fun h_in => ?_⟩
      exact h_no_star star (by simp [h_in]) (matchWildcard_mem suffix host h star h_in) rfl
    · exact absurd rfl (h_no_star star h_star (foldEq_mem _ host h star h_star))
  · exact absurd rfl (h_no_star star h_star (foldEq_mem _ host h star h_star))

/-- A successful `Option` bind ran its continuation on a value the
first computation produced. -/
private theorem exists_of_bind_eq_some {α β : Type} {x : Option α} {f : α → Option β} {b : β}
    (h : x.bind f = some b) : ∃ a, x = some a ∧ f a = some b := by
  cases x with
  | none => simp at h
  | some a => exact ⟨a, rfl, h⟩

private theorem guard_eq_ite (p : Prop) [Decidable p] :
    (guard p : Option Unit) = if p then some () else none := rfl

/-- A `guard` the do-block ran past held. -/
private theorem bind_guard_eq_some {α : Type} {p : Prop} [Decidable p] {f : Unit → Option α}
    {a : α} (h : (guard p : Option Unit).bind f = some a) : p ∧ f () = some a := by
  rw [guard_eq_ite] at h
  by_cases hp : p
  · rw [if_pos hp] at h
    exact ⟨hp, h⟩
  · rw [if_neg hp] at h
    simp at h

/-- Every entry `entries` returns has a tag in `generalNameTags`, when
every entry already in `acc` has one. -/
private theorem entries_tags (fuel : Nat) (b : ByteArray) (off : Nat)
    (acc es : List (UInt8 × ByteArray)) (h_acc : ∀ e ∈ acc, e.1 ∈ generalNameTags)
    (h : entries fuel b off acc = some es) : ∀ e ∈ es, e.1 ∈ generalNameTags := by
  induction fuel generalizing off acc with
  | zero => simp [entries] at h
  | succ fuel ih =>
    unfold entries at h
    split at h
    · simp only [Option.some.injEq] at h
      subst h
      exact fun e h_mem => h_acc e (List.mem_reverse.mp h_mem)
    · obtain ⟨tag, -, h⟩ := exists_of_bind_eq_some h
      obtain ⟨h_tag, h⟩ := bind_guard_eq_some h
      obtain ⟨⟨len, contentOff⟩, -, h⟩ := exists_of_bind_eq_some h
      refine ih _ _ ?_ h
      intro e h_mem
      rcases List.mem_cons.mp h_mem with rfl | h_old
      · exact List.elem_iff.mp h_tag
      · exact h_acc e h_old

/-- Every entry of an accepted GeneralNames has one of GeneralName's
nine tags. A universal tag, a context-specific number above 8, the
wrong constructed bit, or the high-tag-number form refuses the whole
GeneralNames; none of them is skipped as an entry. -/
theorem generalNames?_tags (b : ByteArray) (es : List (UInt8 × ByteArray))
    (h : generalNames? b = some es) : ∀ e ∈ es, e.1 ∈ generalNameTags := by
  unfold generalNames? at h
  obtain ⟨_, -, h⟩ := exists_of_bind_eq_some h
  obtain ⟨-, h⟩ := bind_guard_eq_some h
  obtain ⟨⟨_, off⟩, -, h⟩ := exists_of_bind_eq_some h
  obtain ⟨-, h⟩ := bind_guard_eq_some h
  exact entries_tags _ b off [] es (fun _ h_mem => absurd h_mem List.not_mem_nil) h

/-- A match is a dNSName entry of a well-formed GeneralNames that
`matchDnsName` accepts: no other GeneralName type and no fallback to
the subject common name (RFC 6125 §6.4.4) can produce one. -/
theorem matchSan_sound (san : ByteArray) (host : List UInt8) (h : matchSan san host = true) :
    ∃ es, generalNames? san = some es ∧
      ∃ e, e ∈ es ∧ e.1 = dnsNameTag ∧ matchDnsName e.2.toList host = true := by
  unfold matchSan at h
  split at h
  · next es h_names =>
    obtain ⟨e, h_mem, h_e⟩ := List.any_eq_true.mp h
    simp only [Bool.and_eq_true, beq_iff_eq] at h_e
    exact ⟨es, h_names, e, h_mem, h_e.1, h_e.2⟩
  · exact absurd h Bool.false_ne_true

end Spec.WebpkiName
