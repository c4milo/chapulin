import Spec.Hkdf
import Spec.Aead

/-!
TLS 1.3 record protection per RFC 9846 §5.2–5.3, written from the RFC
text as an executable oracle. Fixed profile: TLS_CHACHA20_POLY1305
(32-byte key, 12-byte IV, 16-byte tag).
-/
namespace Spec.Record
open Spec.Bytes

/--
RFC 9846 §7.2: the next generation of a traffic secret,
`HKDF-Expand-Label(secret, "traffic upd", "", Hash.length)`. -/
def nextSecret (secret : ByteArray) : ByteArray :=
  Spec.Hkdf.expandLabel secret "traffic upd" ByteArray.empty 32

/--
RFC 9846 §5.3: the per-record nonce — the 64-bit sequence number in
network (big-endian) byte order, left-padded with zeros to the IV
length, XORed with the write IV.
-/
def nonce (iv : ByteArray) (seq : Nat) : ByteArray :=
  xorBytes iv (ByteArray.mk (Array.replicate (iv.size - 8) 0) ++ natToBytesBE seq 8)

/--
RFC 9846 §5.2: protect one record. Traffic key and IV come from the
traffic secret via HKDF-Expand-Label (§7.3: `"key"`/`"iv"`, empty
context). The inner plaintext is `content ‖ ContentType` (no padding),
the AAD is the 5-byte record header `17 03 03 ‖ len16` where the
length covers the inner plaintext plus the 16-byte tag, and the output
is `header ‖ AEAD-Encrypt(...)`.

Domain: `seq < 2^64 - 1`. RFC 9846 §5.5 requires the sender to stop before
the 64-bit sequence number wraps, so the C refuses `seq = 2^64 - 1` (its
last representable value) rather than reuse a nonce on the next record.
This transform is the pure protection function and does not model that
refusal; the boundary is a unit test, and the differential run keeps
`seq = 2^64 - 1` out of the compared domain.
-/
def «seal» (trafficSecret : ByteArray) (seq : Nat) (ctype : UInt8) (pt : ByteArray) : ByteArray :=
  let key := Spec.Hkdf.expandLabel trafficSecret "key" ByteArray.empty 32
  let iv := Spec.Hkdf.expandLabel trafficSecret "iv" ByteArray.empty 12
  let inner := pt.push ctype
  let header := ByteArray.mk #[0x17, 0x03, 0x03] ++ natToBytesBE (inner.size + 16) 2
  header ++ Spec.Aead.seal key (nonce iv seq) header inner

theorem seal_size (secret : ByteArray) (seq : Nat) (ctype : UInt8) (pt : ByteArray) :
    («seal» secret seq ctype pt).size = pt.size + 22 := by
  have h_prefix_size : (ByteArray.mk #[0x17, 0x03, 0x03]).size = 3 := rfl
  simp [«seal», ByteArray.size_append, Spec.Aead.seal_size, natToBytesBE_size,
    ByteArray.size_push, h_prefix_size]
  omega

/--
Record round-trip. The spec models protection only — deprotection lives
in the C read path — so the theorem states what that path checks:
splitting the sealed record back into the 5-byte header, ciphertext,
and tag, and opening with the §7.3 traffic key/IV and the §5.3 nonce,
recovers the inner plaintext `pt ‖ ctype` for every secret, sequence
number, content type, and plaintext.
-/
theorem aeadOpen_seal (secret : ByteArray) (seq : Nat) (ctype : UInt8) (pt : ByteArray) :
    Spec.Aead.open?
      (Spec.Hkdf.expandLabel secret "key" ByteArray.empty 32)
      (nonce (Spec.Hkdf.expandLabel secret "iv" ByteArray.empty 12) seq)
      ((«seal» secret seq ctype pt).extract 0 5)
      ((«seal» secret seq ctype pt).extract 5 (5 + (pt.size + 1)))
      ((«seal» secret seq ctype pt).extract (5 + (pt.size + 1)) (5 + (pt.size + 1) + 16))
      = some (pt.push ctype) := by
  have hseal : «seal» secret seq ctype pt
      = (ByteArray.mk #[0x17, 0x03, 0x03] ++ natToBytesBE ((pt.push ctype).size + 16) 2)
        ++ Spec.Aead.seal (Spec.Hkdf.expandLabel secret "key" ByteArray.empty 32)
            (nonce (Spec.Hkdf.expandLabel secret "iv" ByteArray.empty 12) seq)
            (ByteArray.mk #[0x17, 0x03, 0x03] ++ natToBytesBE ((pt.push ctype).size + 16) 2)
            (pt.push ctype) := rfl
  rw [hseal]
  generalize Spec.Hkdf.expandLabel secret "key" ByteArray.empty 32 = key
  generalize nonce (Spec.Hkdf.expandLabel secret "iv" ByteArray.empty 12) seq = nn
  have hins : (pt.push ctype).size = pt.size + 1 := ByteArray.size_push ..
  generalize hin : pt.push ctype = inner at hins ⊢
  generalize hH : ByteArray.mk #[0x17, 0x03, 0x03] ++ natToBytesBE (inner.size + 16) 2
    = header at *
  have hhs : header.size = 5 := by
    rw [← hH]
    have h_prefix_size : (ByteArray.mk #[0x17, 0x03, 0x03]).size = 3 := rfl
    simp [ByteArray.size_append, natToBytesBE_size, h_prefix_size]
  rw [show ((header ++ Spec.Aead.seal key nn header inner).extract 0 5)
      = header from ByteArray.extract_append_eq_left hhs.symm]
  rw [show (5 : Nat) + (pt.size + 1) = header.size + inner.size by omega,
    show (5 : Nat) = header.size + 0 by omega,
    ByteArray.extract_append_size_add' rfl]
  rw [show header.size + inner.size + 16 = header.size + (inner.size + 16) by omega,
    ByteArray.extract_append_size_add' rfl]
  simpa [hins] using Spec.Aead.open?_seal key nn header inner

/--
Structural checks: header is `17 03 03`, its length field is
`|pt| + 17` (content type byte plus tag), the record body matches
that length, and the §5.3 nonce construction XORs the sequence number
into the low 8 IV bytes. Record protection has no external
known-answer test; its functional coverage comes from the
differential run against the C implementation.
-/
def selftest : Bool := Id.run do
  let secret := ByteArray.mk (Array.replicate 32 0x0b)
  let pt := ascii "ping"
  let out := «seal» secret 1 0x17 pt
  let len := pt.size + 17
  let headerOk := out.size == 5 + len &&
    out[0]! == 0x17 && out[1]! == 0x03 && out[2]! == 0x03 &&
    out[3]!.toNat * 256 + out[4]!.toNat == len
  -- §5.3 nonce: seq 0 leaves the IV as-is; a seq flips only low bytes.
  let iv := ByteArray.mk #[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11]
  let nonceOk := bytesToHex (nonce iv 0) == bytesToHex iv &&
    bytesToHex (nonce iv 0x0102) == "000102030405060708090b09"
  -- Different sequence numbers must protect to different bodies.
  let seqOk := bytesToHex («seal» secret 0 0x17 pt) != bytesToHex out
  return headerOk && nonceOk && seqOk


theorem nonce_size (iv : ByteArray) (seq : Nat) (h : 8 ≤ iv.size) :
    (nonce iv seq).size = iv.size := by
  have hz : ∀ m : Nat, (ByteArray.mk (Array.replicate m 0)).size = m :=
    fun m => by simp [ByteArray.size]
  rw [nonce, xorBytes_size, ByteArray.size_append, natToBytesBE_size, hz]
  omega

theorem nextSecret_size (s : ByteArray) : (nextSecret s).size = 32 := by
  simp [nextSecret, Spec.Hkdf.expandLabel_size]

-- 4. Record: the nonce is as long as the IV.

theorem pad_getElem! (iv : ByteArray) (seq j : Nat) (hiv : 8 ≤ iv.size) (hj : j < 8) :
    (ByteArray.mk (Array.replicate (iv.size - 8) 0) ++ natToBytesBE seq 8)[iv.size - 8 + j]!
      = (natToBytesBE seq 8)[j]! := by
  have hz := zeros_size (iv.size - 8)
  have hs : (ByteArray.mk (Array.replicate (iv.size - 8) 0) ++ natToBytesBE seq 8).size
      = iv.size := by
    rw [ByteArray.size_append, hz, natToBytesBE_size]; omega
  rw [getElem!_pos _ _ (by rw [hs]; omega),
    ByteArray.getElem_append_right (by rw [hz]; omega),
    ← getElem!_pos (natToBytesBE seq 8) _ (by rw [natToBytesBE_size]; omega)]
  rw [hz]
  congr 1
  omega

theorem nonce_inj (iv : ByteArray) (s1 s2 : Nat) (hiv : 8 ≤ iv.size)
    (h_s1_lt : s1 < 2 ^ 64) (h_s2_lt : s2 < 2 ^ 64)
    (h : nonce iv s1 = nonce iv s2) : s1 = s2 := by
  have hz := zeros_size (iv.size - 8)
  have hpsz : ∀ s : Nat, (ByteArray.mk (Array.replicate (iv.size - 8) 0)
      ++ natToBytesBE s 8).size = iv.size := by
    intro s; rw [ByteArray.size_append, hz, natToBytesBE_size]; omega
  have hnsz : ∀ s : Nat, (nonce iv s).size = iv.size := by
    intro s
    rw [nonce, xorBytes_size, hpsz s]
    omega
  have key : natToBytesBE s1 8 = natToBytesBE s2 8 := by
    apply ByteArray.ext_getElem
    · rw [natToBytesBE_size, natToBytesBE_size]
    · intro j hj1 hj2
      have hj : j < 8 := by rw [natToBytesBE_size] at hj1; exact hj1
      rw [← getElem!_pos _ j hj1, ← getElem!_pos _ j hj2]
      rw [← pad_getElem! iv s1 j hiv hj, ← pad_getElem! iv s2 j hiv hj]
      apply uint8_xor_left_cancel iv[iv.size - 8 + j]!
      have e : ∀ s : Nat, (nonce iv s)[iv.size - 8 + j]!
          = iv[iv.size - 8 + j]! ^^^ (ByteArray.mk (Array.replicate (iv.size - 8) 0)
              ++ natToBytesBE s 8)[iv.size - 8 + j]! := by
        intro s
        rw [nonce,
          getElem!_pos _ _ (by rw [xorBytes_size, hpsz s]; omega),
          getElem_xorBytes _ _ _ (by rw [xorBytes_size, hpsz s]; omega)]
      rw [← e s1, ← e s2, h]
  exact natToBytesBE_inj 8 s1 s2 (by simpa using h_s1_lt) (by simpa using h_s2_lt) key

end Spec.Record
