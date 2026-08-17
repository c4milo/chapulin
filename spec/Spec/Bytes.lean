/-!
Byte and hex utilities shared by every spec module. The spec is an
executable oracle: clarity beats speed everywhere, and nothing here may
look at the C implementation — modules are written from the RFC text.
-/
namespace Spec.Bytes

def hexDigit? (c : Char) : Option UInt8 :=
  if '0' ≤ c ∧ c ≤ '9' then some (UInt8.ofNat (c.toNat - '0'.toNat))
  else if 'a' ≤ c ∧ c ≤ 'f' then some (UInt8.ofNat (c.toNat - 'a'.toNat + 10))
  else if 'A' ≤ c ∧ c ≤ 'F' then some (UInt8.ofNat (c.toNat - 'A'.toNat + 10))
  else none

def hexToBytes? (s : String) : Option ByteArray := do
  let cs := s.toList
  if cs.length % 2 ≠ 0 then none
  else
    let rec go : List Char → ByteArray → Option ByteArray
      | [], acc => some acc
      | hi :: lo :: rest, acc => do
        let h ← hexDigit? hi
        let l ← hexDigit? lo
        go rest (acc.push (h <<< 4 ||| l))
      | _, _ => none
    go cs (ByteArray.emptyWithCapacity (cs.length / 2))

def bytesToHex (b : ByteArray) : String :=
  let digits := "0123456789abcdef".toList.toArray
  b.foldl (init := "") fun s v =>
    s.push (digits[(v >>> 4).toNat]!) |>.push (digits[(v &&& 0xf).toNat]!)

/-- Big-endian encoding of `n` into `len` bytes (truncates above 2^(8*len)). -/
def natToBytesBE (n len : Nat) : ByteArray := Id.run do
  let mut out := ByteArray.emptyWithCapacity len
  for i in [0:len] do
    out := out.push (UInt8.ofNat (n >>> ((len - 1 - i) * 8) % 256))
  return out

/-- Little-endian encoding of `n` into `len` bytes. -/
def natToBytesLE (n len : Nat) : ByteArray := Id.run do
  let mut out := ByteArray.emptyWithCapacity len
  for i in [0:len] do
    out := out.push (UInt8.ofNat (n >>> (i * 8) % 256))
  return out

/-- Little-endian decoding of the whole array. -/
def bytesToNatLE (b : ByteArray) : Nat :=
  b.data.foldr (init := 0) fun v acc => acc * 256 + v.toNat

/-- Big-endian decoding of the whole array. -/
def bytesToNatBE (b : ByteArray) : Nat :=
  b.foldl (init := 0) fun acc v => acc * 256 + v.toNat

def xorBytes (a b : ByteArray) : ByteArray := Id.run do
  let n := min a.size b.size
  let mut out := ByteArray.emptyWithCapacity n
  for i in [0:n] do
    out := out.push (a[i]! ^^^ b[i]!)
  return out

def ascii (s : String) : ByteArray := s.toUTF8

/-!
Proof toolkit. The spec's loops all follow one shape — `Id.run do` with
a `for` over a range pushing or appending bytes — and `simp [def]`
reduces that shape to a `List.foldl` over `List.range'`. The lemmas
below characterize the two fold bodies the modules use, so size and
element facts about every looped definition come out of one place.
-/

/-- `emptyWithCapacity` is the empty array whatever the capacity hint. -/
theorem emptyWithCapacity_eq (n : Nat) :
    ByteArray.emptyWithCapacity n = ByteArray.empty := rfl

/-- A push-only fold appends the pushed bytes, in order. -/
theorem foldl_push_eq_append {α} (l : List α) (f : α → UInt8) (init : ByteArray) :
    l.foldl (fun out a => out.push (f a)) init = init ++ (l.map f).toByteArray := by
  induction l generalizing init with
  | nil => simp
  | cons x xs ih =>
    simp only [List.foldl_cons, ih, List.map_cons]
    rw [← ByteArray.append_toByteArray_singleton, ByteArray.append_assoc,
      ← List.toByteArray_append]
    rfl

/-- Carry an invariant through a fold. -/
theorem foldl_inv {α β} (l : List α) (f : β → α → β) (P : β → Prop)
    (init : β) (h0 : P init) (hstep : ∀ b a, P b → P (f b a)) :
    P (l.foldl f init) := by
  induction l generalizing init with
  | nil => exact h0
  | cons x xs ih => exact ih (f init x) (hstep init x h0)

/-- Carry a position-indexed invariant through a fold. -/
theorem foldl_inv_idx {α β} (l : List α) (f : β → α → β) (P : Nat → β → Prop)
    (init : β) (h0 : P 0 init) (hstep : ∀ k b a, P k b → P (k + 1) (f b a)) :
    P l.length (l.foldl f init) := by
  induction l generalizing init P with
  | nil => exact h0
  | cons x xs ih =>
    simpa [List.length_cons] using
      ih (fun k b => P (k + 1) b) (f init x) (hstep 0 init x h0)
        (fun k b a hk => hstep (k + 1) b a hk)

/-- An append-only fold of constant-size pieces grows by `c` per element. -/
theorem size_foldl_append_const {α} (l : List α) (g : α → ByteArray) (c : Nat)
    (hg : ∀ a, (g a).size = c) (init : ByteArray) :
    (l.foldl (fun out a => out ++ g a) init).size = init.size + c * l.length := by
  induction l generalizing init with
  | nil => simp
  | cons x xs ih =>
    simp only [List.foldl_cons, ih, ByteArray.size_append, hg, List.length_cons,
      Nat.mul_succ]
    omega

theorem natToBytesBE_size (n len : Nat) : (natToBytesBE n len).size = len := by
  simp [natToBytesBE, foldl_push_eq_append, emptyWithCapacity_eq]

theorem natToBytesLE_size (n len : Nat) : (natToBytesLE n len).size = len := by
  simp [natToBytesLE, foldl_push_eq_append, emptyWithCapacity_eq]

theorem xorBytes_eq (a b : ByteArray) :
    xorBytes a b =
      ((List.range' 0 (min a.size b.size)).map fun i => a[i]! ^^^ b[i]!).toByteArray := by
  simp [xorBytes, foldl_push_eq_append, emptyWithCapacity_eq]

theorem xorBytes_size (a b : ByteArray) : (xorBytes a b).size = min a.size b.size := by
  simp [xorBytes_eq]

theorem getElem_xorBytes (a b : ByteArray) (i : Nat) (h : i < (xorBytes a b).size) :
    (xorBytes a b)[i] = a[i]! ^^^ b[i]! := by
  simp only [xorBytes_eq] at h ⊢
  simp [List.getElem_toByteArray]

theorem uint8_xor_cancel (a b : UInt8) : (a ^^^ b) ^^^ b = a := by
  apply UInt8.toBitVec_inj.1
  simp [BitVec.xor_assoc]

/-- XOR with the same (long enough) pad twice is the identity. -/
theorem xorBytes_xorBytes (a b : ByteArray) (h : a.size ≤ b.size) :
    xorBytes (xorBytes a b) b = a := by
  have hsz : (xorBytes a b).size = a.size := by rw [xorBytes_size]; omega
  apply ByteArray.ext_getElem
  · rw [xorBytes_size, hsz]; omega
  · intro i h1 h2
    rw [getElem_xorBytes]
    rw [getElem!_pos (xorBytes a b) i (by omega), getElem_xorBytes a b i (by omega)]
    rw [getElem!_pos a i h2, uint8_xor_cancel]

/-!
`bytesToHex` injectivity. `Aead.open?` compares tags through
`bytesToHex`, so its rejection theorem needs hex equality to imply byte
equality. The chain: bridge `ByteArray.foldl` to a list fold, read off
the two digits emitted per byte, and recover the byte from them.
-/

private theorem foldl_loop_eq {β} (f : β → UInt8 → β) (as : ByteArray)
    (h : as.size ≤ as.size) :
    ∀ (i j : Nat) (acc : β), j + i ≤ as.size →
      ByteArray.foldlM.loop (m := Id) (fun b a => pure (f b a)) as as.size h i j acc
        = ((as.data.toList.drop j).take i).foldl f acc := by
  intro i
  induction i with
  | zero =>
    intro j acc _
    rw [ByteArray.foldlM.loop]
    split <;> rfl
  | succ i' ih =>
    intro j acc hj
    rw [ByteArray.foldlM.loop]
    split
    · next hlt =>
      have hdrop : as.data.toList.drop j = as[j] :: as.data.toList.drop (j + 1) := by
        rw [List.drop_eq_getElem_cons (by simpa using hlt)]
        simp [ByteArray.getElem_eq_getElem_data]
      rw [hdrop]
      simpa using ih (j + 1) (f acc as[j]) (by omega)
    · next hge =>
      omega

/-- `ByteArray.foldl` over the whole array is the fold over its bytes. -/
theorem byteArray_foldl_eq {β} (f : β → UInt8 → β) (init : β) (b : ByteArray) :
    b.foldl f init = b.data.toList.foldl f init := by
  rw [ByteArray.foldl, ByteArray.foldlM]
  simp only [Nat.le_refl, dite_true]
  rw [Id.run, foldl_loop_eq f b (Nat.le_refl _) (b.size - 0) 0 init (by omega)]
  rw [List.drop_zero, Nat.sub_zero,
    List.take_of_length_le (by simp [ByteArray.size_data])]

/-- The two hex digits `bytesToHex` emits for one byte. -/
private def hexPair (v : UInt8) : List Char :=
  ["0123456789abcdef".toList.toArray[(v >>> 4).toNat]!,
   "0123456789abcdef".toList.toArray[(v &&& 0xf).toNat]!]

private theorem foldl_hexPair (l : List UInt8) (s : String) :
    (l.foldl (fun s v =>
        s.push ("0123456789abcdef".toList.toArray[(v >>> 4).toNat]!)
          |>.push ("0123456789abcdef".toList.toArray[(v &&& 0xf).toNat]!)) s).toList
      = s.toList ++ l.flatMap hexPair := by
  induction l generalizing s with
  | nil => simp
  | cons x xs ih =>
    rw [List.foldl_cons, ih]
    simp [String.toList_push, hexPair]

private theorem bytesToHex_toList (b : ByteArray) :
    (bytesToHex b).toList = b.data.toList.flatMap hexPair := by
  rw [bytesToHex, byteArray_foldl_eq, foldl_hexPair]
  rfl

private theorem hexPair_inj (v w : UInt8) (h : hexPair v = hexPair w) : v = w := by
  have hd : ∀ m : Nat, m < 16 → ∀ n : Nat, n < 16 →
      "0123456789abcdef".toList.toArray[m]! = "0123456789abcdef".toList.toArray[n]! →
      m = n := by decide
  simp only [hexPair, List.cons.injEq, and_true] at h
  have hb : ∀ u : UInt8, (u >>> 4).toNat = u.toNat / 16 ∧ (u &&& 0xf).toNat = u.toNat % 16 := by
    intro u
    constructor
    · rw [UInt8.toNat_shiftRight, Nat.shiftRight_eq_div_pow]
      congr 1
    · rw [UInt8.toNat_and]
      simpa using Nat.and_two_pow_sub_one_eq_mod u.toNat 4
  have hlt : ∀ u : UInt8, u.toNat / 16 < 16 ∧ u.toNat % 16 < 16 := by
    intro u
    have hu := UInt8.toNat_lt u
    omega
  have e1 := hd _ (by rw [(hb v).1]; exact (hlt v).1) _ (by rw [(hb w).1]; exact (hlt w).1) h.1
  have e2 := hd _ (by rw [(hb v).2]; exact (hlt v).2) _ (by rw [(hb w).2]; exact (hlt w).2) h.2
  rw [(hb v).1, (hb w).1] at e1
  rw [(hb v).2, (hb w).2] at e2
  apply UInt8.toNat_inj.mp
  omega

/-- Two-hex-digits-per-byte encodings only collide on equal inputs. -/
private theorem flatMap_hexPair_inj :
    ∀ (l1 l2 : List UInt8), l1.flatMap hexPair = l2.flatMap hexPair → l1 = l2
  | [], [], _ => rfl
  | [], y :: ys, h => by simp [hexPair] at h
  | x :: xs, [], h => by simp [hexPair] at h
  | x :: xs, y :: ys, h => by
    simp only [List.flatMap_cons, hexPair, List.cons_append, List.nil_append,
      List.cons.injEq] at h
    obtain ⟨h1, h2, h3⟩ := h
    have := hexPair_inj x y (by simp only [hexPair, h1, h2])
    have := flatMap_hexPair_inj xs ys h3
    simp_all

/-- `bytesToHex` is injective: distinct byte strings have distinct hex. -/
theorem bytesToHex_inj (a b : ByteArray) (h : bytesToHex a = bytesToHex b) : a = b := by
  have := congrArg String.toList h
  rw [bytesToHex_toList, bytesToHex_toList] at this
  have hdata := flatMap_hexPair_inj _ _ this
  apply ByteArray.ext
  apply Array.toList_inj.mp
  exact hdata

end Spec.Bytes
