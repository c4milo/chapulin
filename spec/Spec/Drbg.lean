import Spec.Bytes
import Spec.ChaCha

/-!
The reference generator (drbg.[ch]): fast key erasure over ChaCha20,
after Bernstein's construction (blog.cr.yp.to/20170723-random.html).
One request under key `k` takes the ChaCha20 keystream with a zero
nonce from counter 0; the first 32 bytes become the next key and the
`n` bytes after them are the output. Defined over the keystream itself
(XOR against zeros), so this spec shares no structure with the C's
block-at-a-time walk.
-/
namespace Spec.Drbg

open Spec.Bytes

/-- The all-zero 12-byte nonce every request draws under, since the
key changes on each one. -/
def zeroNonce : ByteArray :=
  ByteArray.mk (Array.replicate 12 0)

/-- One request: `(next key, output)` for `n` output bytes. -/
def next (k : ByteArray) (n : Nat) : ByteArray × ByteArray :=
  let stream := Spec.ChaCha.xor k zeroNonce 0 (ByteArray.mk (Array.replicate (32 + n) 0))
  (stream.extract 0 32, stream.extract 32 (32 + n))

/-- The construction rekeys: consecutive requests use distinct keys, and
the output never contains the next key's bytes. -/
def selftest : Bool :=
  let k0 := ByteArray.mk (Array.replicate 32 7)
  let (k1, out1) := next k0 40
  let (k2, out2) := next k1 40
  k1 != k0 && k2 != k1 && out1 != out2 && out1.size == 40 && out2.size == 40


/-- The keystream one request draws: 32 bytes for the next key, then
the requested output bytes. -/
def stream (k : ByteArray) (n : Nat) : ByteArray :=
  Spec.ChaCha.xor k zeroNonce 0 (ByteArray.mk (Array.replicate (32 + n) 0))

theorem next_eq (k : ByteArray) (n : Nat) :
    next k n = ((stream k n).extract 0 32, (stream k n).extract 32 (32 + n)) := rfl

theorem stream_size (k : ByteArray) (n : Nat) : (stream k n).size = 32 + n := by
  simp [stream, Spec.ChaCha.xor_size, zeros_size]

theorem stream_getElem! (k : ByteArray) (n i : Nat) (h : i < 32 + n) :
    (stream k n)[i]! = (Spec.ChaCha.block k zeroNonce (UInt32.ofNat (i / 64)))[i % 64]! := by
  rw [stream, Spec.ChaCha.xor_getElem! _ _ _ _ _ (by rw [zeros_size]; exact h)]
  rw [zeros_getElem_zero, uint8_zero_xor]
  simp

theorem next_key_size (k : ByteArray) (n : Nat) : (next k n).1.size = 32 := by
  rw [next_eq]
  simp [ByteArray.size_extract, stream_size]

theorem next_out_size (k : ByteArray) (n : Nat) : (next k n).2.size = n := by
  rw [next_eq]
  simp [ByteArray.size_extract, stream_size]

/-- Key advance: the next key is the first 32 bytes of the ChaCha20
block under the current key at counter 0, whatever `n` was asked for. -/
theorem next_key_eq_block (k : ByteArray) (n : Nat) :
    (next k n).1 = (Spec.ChaCha.block k zeroNonce 0).extract 0 32 := by
  rw [next_eq]
  apply ByteArray.ext_getElem
  · simp [ByteArray.size_extract, stream_size, Spec.ChaCha.block_size]
  · intro i h_lt_key h_lt_block
    rw [← getElem!_pos _ i h_lt_key, ← getElem!_pos _ i h_lt_block]
    have hi : i < 32 := by
      simpa [ByteArray.size_extract, stream_size] using h_lt_key
    rw [getElem!_pos _ i (by simp [ByteArray.size_extract, stream_size]; omega),
        ByteArray.getElem_extract,
        getElem!_pos _ i (by simp [ByteArray.size_extract, Spec.ChaCha.block_size]; omega),
        ByteArray.getElem_extract]
    rw [← getElem!_pos (stream k n) _ (by rw [stream_size]; omega),
        ← getElem!_pos (Spec.ChaCha.block k zeroNonce 0) _
          (by rw [Spec.ChaCha.block_size]; omega)]
    rw [stream_getElem! k n (0 + i) (by omega)]
    have hdiv : (0 + i) / 64 = 0 := by omega
    have hmod : (0 + i) % 64 = 0 + i := by omega
    rw [hdiv, hmod]
    rfl

/-- The next key is a function of the current key alone: the number of
output bytes the request asked for does not change it. -/
theorem next_key_indep (k : ByteArray) (n m : Nat) : (next k n).1 = (next k m).1 := by
  rw [next_key_eq_block, next_key_eq_block]

/-- Byte `j` of the next key is keystream byte `j`. -/
theorem next_key_getElem! (k : ByteArray) (n j : Nat) (h : j < 32) :
    (next k n).1[j]! = (stream k n)[j]! := by
  rw [next_eq]
  rw [getElem!_pos _ j (by simp [ByteArray.size_extract, stream_size]; omega),
      ByteArray.getElem_extract, ← getElem!_pos (stream k n) _ (by rw [stream_size]; omega)]
  simp

/-- Byte `i` of the output is keystream byte `32 + i`. -/
theorem next_out_getElem! (k : ByteArray) (n i : Nat) (h : i < n) :
    (next k n).2[i]! = (stream k n)[32 + i]! := by
  rw [next_eq]
  rw [getElem!_pos _ i (by simp [ByteArray.size_extract, stream_size]; omega),
      ByteArray.getElem_extract, ← getElem!_pos (stream k n) _ (by rw [stream_size]; omega)]

/-- Fast key erasure's premise: the next key and the output never share
a keystream byte. The key comes from positions 0..31, the output from
32 onward, and those positions differ. Stated here rather than left for
a reader to derive from the two index lemmas above. -/
theorem next_key_out_disjoint (k : ByteArray) (n j i : Nat) (hj : j < 32) (hi : i < n) :
    (next k n).1[j]! = (stream k n)[j]!
      ∧ (next k n).2[i]! = (stream k n)[32 + i]!
      ∧ j ≠ 32 + i :=
  ⟨next_key_getElem! k n j hj, next_out_getElem! k n i hi, by omega⟩

/-- Request-size consistency: a shorter request returns a prefix of a
longer one under the same key. Every request is cut from one stream. -/
theorem next_out_prefix (k : ByteArray) (n m : Nat) (h : n ≤ m) :
    (next k n).2 = (next k m).2.extract 0 n := by
  apply ByteArray.ext_getElem
  · rw [ByteArray.size_extract, next_out_size, next_out_size]; omega
  · intro i h_lt_out h_lt_prefix
    have hi : i < n := by rw [next_out_size] at h_lt_out; exact h_lt_out
    rw [← getElem!_pos _ i h_lt_out, ← getElem!_pos _ i h_lt_prefix, next_out_getElem! k n i hi]
    rw [getElem!_pos _ i (by rw [ByteArray.size_extract, next_out_size]; omega),
        ByteArray.getElem_extract,
        ← getElem!_pos ((next k m).2) _ (by rw [next_out_size]; omega),
        next_out_getElem! k m (0 + i) (by omega)]
    rw [stream_getElem! k n (32 + i) (by omega), stream_getElem! k m (32 + (0 + i)) (by omega)]
    simp

/-- A whole generator session from one seed: `ns` is the sequence of
request sizes; the result is the final key and the outputs in order. -/
def gen : ByteArray → List Nat → ByteArray × List ByteArray
  | k, [] => (k, [])
  | k, n :: ns =>
    let k' := (next k n).1
    ((gen k' ns).1, (next k n).2 :: (gen k' ns).2)

/-- Every request in a session gets exactly the bytes it asked for. -/
theorem gen_sizes (k : ByteArray) (ns : List Nat) :
    (gen k ns).2.map ByteArray.size = ns := by
  induction ns generalizing k with
  | nil => rfl
  | cons n ns ih => simp [gen, next_out_size, ih]

/-- The key chain depends on the seed and the number of requests only,
never on how many bytes each request asked for. -/
theorem gen_key_indep_of_sizes (k : ByteArray) :
    ∀ (ns ms : List Nat), ns.length = ms.length → (gen k ns).1 = (gen k ms).1 := by
  intro ns
  induction ns generalizing k with
  | nil => intro ms h; cases ms with
    | nil => rfl
    | cons _ _ => simp at h
  | cons n ns ih =>
    intro ms h
    cases ms with
    | nil => simp at h
    | cons m ms =>
      have hlen : ns.length = ms.length := by simpa using h
      show (gen (next k n).1 ns).1 = (gen (next k m).1 ms).1
      rw [next_key_indep k n m]
      exact ih (next k m).1 ms hlen

end Spec.Drbg
