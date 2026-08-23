import Spec.Hkdf
import Spec.Aead

/-!
TLS 1.3 record protection and deprotection per RFC 9846 §5.1–5.4,
written from the RFC text as an executable oracle. Fixed profile:
TLS_CHACHA20_POLY1305 (32-byte key, 12-byte IV, 16-byte tag).
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
The AEAD layer of the round trip: splitting the sealed record back into
the 5-byte header, ciphertext, and tag, and opening with the §7.3
traffic key/IV and the §5.3 nonce, recovers the inner plaintext
`pt ‖ ctype` for every secret, sequence number, content type, and
plaintext — with no side conditions, because the §5.4 parse of that
inner plaintext has not happened yet. `open?_seal` states the round trip
at the record layer and rests on this.
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
RFC 9846 §5.2: the largest `TLSCiphertext.length` a receiver accepts,
`2^14 + 256` — the §5.1 fragment limit of 2^14 octets, one octet of
inner content type, and the 255 octets §5.2 allows an AEAD to expand
by. A longer record is a "record_overflow".
-/
def maxCiphertext : Nat := 16384 + 256

/--
RFC 9846 §5.4: padding does not raise the ceiling — the full encoded
TLSInnerPlaintext (content, content type, and padding) is at most
`2^14 + 1` octets. The content is what is left once the type octet and
the padding come off, so this also holds §5.1's 2^14-octet limit on the
fragment the record carries.
-/
def maxInner : Nat := 16384 + 1

/--
RFC 9846 §5.4's padding scan as a bounded loop: `scanNonZero b n`
examines octets `n - 1` down to `0` of `b` and returns the index of the
first non-zero one it meets, or `none` when all `n` are zero.
-/
private def scanNonZero (b : ByteArray) : Nat → Option Nat
  | 0 => none
  | n + 1 => if b[n]! == 0 then scanNonZero b n else some n

/--
RFC 9846 §5.4: on a deprotected record the receiver scans the cleartext
from the end toward the beginning until it finds a non-zero octet, and
that octet is the content type. This returns its index: the content is
everything before it, the zeros after it are padding. `none` is the
all-zero cleartext, which §5.4 makes an "unexpected_message" rather
than a record of content type `invalid(0)`. The scan is bounded by
`inner.size`, so it stays inside the cleartext the AEAD returned, as
§5.4 requires.
-/
def contentTypeIndex? (inner : ByteArray) : Option Nat := scanNonZero inner inner.size

/--
RFC 9846 §5.2: deprotect one record — the inverse of `seal`. Given the
traffic secret, the read sequence number, and one whole TLSCiphertext,
it returns the content and the recovered `TLSInnerPlaintext.type`, or
`none` if the record is not acceptable.

Every refusal is a MUST a receiver can decide with nothing but this
record in hand:

* framing — a record shorter than a 5-byte header, a 16-byte tag and
  the one content-type octet cannot be parsed (§5.2);
* `opaque_type` — always `application_data(23)` on a TLSCiphertext
  (§5.2). `legacy_record_version` is deliberately not checked: §5.1
  deprecates the field and says to ignore it, and since the AAD is the
  record header, a wrong version already fails the tag below;
* `length` — it counts exactly the encrypted_record that follows, so a
  record whose body is not that long is malformed (§5.2);
* size limits — `TLSCiphertext.length` at most `2^14 + 256` (§5.2,
  "record_overflow") and the encoded TLSInnerPlaintext at most
  `2^14 + 1` (§5.4). Both are decided on the framing, before the AEAD
  runs;
* the tag — a failed AEAD-Decrypt is a "bad_record_mac" (§5.2);
* the padding strip — an all-zero cleartext carries no content type
  and is an "unexpected_message" (§5.4);
* `change_cipher_spec(20)` — a protected change_cipher_spec record is
  an "unexpected_message" (§5), and no negotiation makes it legal;
* a zero-length content under `handshake(22)` or `alert(21)`, which
  §5.4 makes an "unexpected_message" on receipt. Zero-length
  `application_data(23)` is explicitly allowed there as cover traffic.

Content types outside the four §5.1 defines are *not* refused here:
§5.1 permits new record types negotiated by an extension, so which
recovered types are expected belongs to the layer that knows what was
negotiated (`Spec.Handshake`), not to deprotection.
-/
def open? (trafficSecret : ByteArray) (seq : Nat) (rec : ByteArray) :
    Option (ByteArray × UInt8) :=
  if rec.size < 22 then none else
  let bodySize := rec.size - 5
  let innerSize := bodySize - 16
  if rec[0]! != 0x17 then none else
  if bytesToNatBE (rec.extract 3 5) != bodySize then none else
  if bodySize > maxCiphertext then none else
  if innerSize > maxInner then none else
  let key := Spec.Hkdf.expandLabel trafficSecret "key" ByteArray.empty 32
  let iv := Spec.Hkdf.expandLabel trafficSecret "iv" ByteArray.empty 12
  match Spec.Aead.open? key (nonce iv seq) (rec.extract 0 5)
      (rec.extract 5 (5 + innerSize)) (rec.extract (5 + innerSize) rec.size) with
  | none => none
  | some inner =>
    match contentTypeIndex? inner with
    | none => none
    | some idx =>
      -- The content type is handed back as found. Which types are
      -- meaningful depends on where the connection is — a handshake
      -- flight, application data, a close — so RFC 9846 §5.4's
      -- "unexpected_message" for the rest belongs to the reader above
      -- this layer, not to deprotection.
      some (inner.extract 0 idx, inner[idx]!)

/-- Stripping the content type off `content ‖ ctype` leaves the
content: the §5.4 scan's index is where `seal` put the type octet. -/
private theorem extract_push_left (pt : ByteArray) (ctype : UInt8) :
    (pt.push ctype).extract 0 pt.size = pt := by
  rw [← ByteArray.append_toByteArray_singleton]
  exact ByteArray.extract_append_eq_left rfl

/-- The §5.4 scan stops at the content type `seal` appended: the last
octet of `content ‖ ctype` is `ctype`, non-zero by hypothesis, so no
padding is stripped. -/
private theorem contentTypeIndex?_push (pt : ByteArray) (ctype : UInt8)
    (h_type_nonzero : ctype ≠ 0) : contentTypeIndex? (pt.push ctype) = some pt.size := by
  rw [contentTypeIndex?, ByteArray.size_push, scanNonZero, ByteArray.getElem!_push_eq]
  simp [h_type_nonzero]

/--
Record round trip: opening what `seal` produced returns the content and
the content type it was sealed with, for every traffic secret and
sequence number.

It is not unconditional, and the four side conditions are exactly the
receive-side MUSTs `seal` — the pure protection transform of §5.2 — does
not itself enforce:

* `ctype ≠ 0`: `seal` appends the content type as the last octet of the
  inner plaintext, so a zero one is indistinguishable from padding;
  §5.4 makes that cleartext an "unexpected_message";
* `ctype ≠ 20`: §5 forbids a protected change_cipher_spec record;
* zero-length content only under a type other than `handshake(22)` or
  `alert(21)` (§5.4);
* `|content| ≤ 2^14`: §5.1's fragment limit, equivalently §5.4's
  `2^14 + 1` on the encoded TLSInnerPlaintext once the type octet is
  counted. It is also what keeps the 16-bit length field from wrapping.

This is the completeness direction — every record `seal` mints and the
RFC allows is accepted. `open?_type_sound` is the soundness one.
-/
theorem open?_seal (secret : ByteArray) (seq : Nat) (ctype : UInt8) (pt : ByteArray)
    (h_type_nonzero : ctype ≠ 0) (h_content_fits : pt.size ≤ 16384) :
    open? secret seq («seal» secret seq ctype pt) = some (pt, ctype) := by
  have h_size : («seal» secret seq ctype pt).size = pt.size + 22 := seal_size ..
  have h_assoc : «seal» secret seq ctype pt
      = ByteArray.mk #[0x17, 0x03, 0x03]
        ++ (natToBytesBE ((pt.push ctype).size + 16) 2
          ++ Spec.Aead.seal (Spec.Hkdf.expandLabel secret "key" ByteArray.empty 32)
              (nonce (Spec.Hkdf.expandLabel secret "iv" ByteArray.empty 12) seq)
              (ByteArray.mk #[0x17, 0x03, 0x03] ++ natToBytesBE ((pt.push ctype).size + 16) 2)
              (pt.push ctype)) := by
    rw [«seal»]
    exact ByteArray.append_assoc
  have h_prefix_size : (3 : Nat) = (ByteArray.mk #[(0x17 : UInt8), 0x03, 0x03]).size := rfl
  have h_outer_type : («seal» secret seq ctype pt)[0]! = 0x17 := by
    rw [h_assoc, getElem!_pos _ 0 (by rw [← h_assoc, h_size]; omega),
      ByteArray.getElem_append_left (by omega)]
    rfl
  have h_len_field : («seal» secret seq ctype pt).extract 3 5
      = natToBytesBE ((pt.push ctype).size + 16) 2 := by
    rw [h_assoc]
    show (ByteArray.mk #[0x17, 0x03, 0x03] ++ _).extract (3 + 0) (3 + 2) = _
    rw [ByteArray.extract_append_size_add' h_prefix_size]
    exact ByteArray.extract_append_eq_left (natToBytesBE_size _ 2).symm
  have h_len_value : bytesToNatBE ((«seal» secret seq ctype pt).extract 3 5)
      = pt.size + 17 := by
    rw [h_len_field, bytesToNatBE_natToBytesBE, ByteArray.size_push]
    exact Nat.mod_eq_of_lt (by rw [show 2 ^ (8 * 2) = 65536 from rfl]; omega)
  simp only [open?, h_size, h_outer_type, h_len_value]
  rw [if_neg (show ¬ (pt.size + 22 < 22) from by omega),
    show pt.size + 22 - 5 = pt.size + 17 from by omega,
    show pt.size + 17 - 16 = pt.size + 1 from by omega,
    if_neg (show ¬ (((23 : UInt8) != 23) = true) from by decide),
    if_neg (show ¬ ((pt.size + 17 != pt.size + 17) = true) from by simp),
    if_neg (show ¬ (pt.size + 17 > maxCiphertext) from by rw [maxCiphertext]; omega),
    if_neg (show ¬ (pt.size + 1 > maxInner) from by rw [maxInner]; omega),
    show pt.size + 22 = 5 + (pt.size + 1) + 16 from by omega,
    aeadOpen_seal secret seq ctype pt]
  simp only [contentTypeIndex?_push pt ctype h_type_nonzero, ByteArray.getElem!_push_eq,
    extract_push_left]

/-- The §5.4 scan returns only indices of non-zero octets, so an index
it reports really is a content type and not a padding octet. -/
private theorem scanNonZero_ne_zero (b : ByteArray) :
    ∀ n idx : Nat, scanNonZero b n = some idx → b[idx]! ≠ 0 := by
  intro n
  induction n with
  | zero => intro idx h_scan; simp [scanNonZero] at h_scan
  | succ n ih =>
    intro idx h_scan
    rw [scanNonZero] at h_scan
    split at h_scan
    · exact ih idx h_scan
    · next h_octet_nonzero =>
      obtain rfl : idx = n := by simpa using h_scan.symm
      simpa using h_octet_nonzero

/--
RFC 9846 §5.4: the content type is the last non-zero octet of the
deprotected cleartext, so an accepted record never carries
`invalid(0)` — an all-zero cleartext is refused instead. Which of the
remaining types is legal where is the reader's business, not this
layer's, so nothing stronger is claimed here.
-/
theorem open?_type_sound (secret : ByteArray) (seq : Nat) (rec : ByteArray)
    (content : ByteArray) (ctype : UInt8)
    (h_accepted : open? secret seq rec = some (content, ctype)) :
    ctype ≠ 0 := by
  rw [open?] at h_accepted
  repeat split at h_accepted
  all_goals simp_all
  obtain ⟨-, -, -, -, h_deprotected⟩ := h_accepted
  split at h_deprotected
  · simp at h_deprotected
  · rename_i inner _
    split at h_deprotected
    · simp at h_deprotected
    · rename_i idx h_scan_found
      have h_type_nonzero := scanNonZero_ne_zero inner inner.size idx h_scan_found
      simp_all

/--
Structural checks: header is `17 03 03`, its length field is
`|pt| + 17` (content type byte plus tag), the record body matches
that length, and the §5.3 nonce construction XORs the sequence number
into the low 8 IV bytes. Deprotection is checked against protection —
the round trip, the §5.4 padding strip, and one case per refusal
`open?` owes the RFC. Record protection has no external
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
  -- Deprotection returns the content and the content type it was sealed with.
  let opens (rec : ByteArray) (seq : Nat) (content : ByteArray) (ctype : UInt8) : Bool :=
    match open? secret seq rec with
    | some (got, gotType) => bytesToHex got == bytesToHex content && gotType == ctype
    | none => false
  let rejects (rec : ByteArray) (seq : Nat) : Bool := (open? secret seq rec).isNone
  let roundTripOk := opens out 1 pt 0x17 &&
    opens («seal» secret 3 0x16 (ascii "hs")) 3 (ascii "hs") 0x16 &&
    -- §5.4: zero-length application_data is legal cover traffic.
    opens («seal» secret 0 0x17 ByteArray.empty) 0 ByteArray.empty 0x17
  -- §5.4: padding is zeros appended after the content type; the scan from
  -- the end strips them and still recovers handshake(22).
  let key := Spec.Hkdf.expandLabel secret "key" ByteArray.empty 32
  let ivKey := Spec.Hkdf.expandLabel secret "iv" ByteArray.empty 12
  let inner := (pt.push 0x16) ++ ByteArray.mk (Array.replicate 5 0)
  let paddedHeader := ByteArray.mk #[0x17, 0x03, 0x03] ++ natToBytesBE (inner.size + 16) 2
  let padded := paddedHeader ++ Spec.Aead.seal key (nonce ivKey 7) paddedHeader inner
  let padOk := opens padded 7 pt 0x16
  -- §5.4: an all-zero cleartext has no content type at all.
  let allZeroOk := rejects («seal» secret 1 0x00 ByteArray.empty) 1
  -- §5.2 bad_record_mac: a flipped ciphertext byte, and the wrong sequence
  -- number (a different §5.3 nonce), must both fail the tag.
  let tampered := out.extract 0 5 ++ ByteArray.mk #[out[5]! ^^^ 0x01] ++ out.extract 6 out.size
  let tagOk := rejects tampered 1 && rejects out 2
  -- §5.2 framing: one call carries exactly one record, so a body that is
  -- shorter or longer than the length field claims is refused. (A mangled
  -- header is also a bad_record_mac, since the header is the AAD — these
  -- cases pin the verdict, not which check reaches it first.)
  let truncOk := rejects (out.extract 0 (out.size - 1)) 1 &&
    rejects (out.push 0x00) 1
  -- §5.2: the outer type of a TLSCiphertext is application_data.
  let outerTypeOk := rejects (ByteArray.mk #[0x16] ++ out.extract 1 out.size) 1
  -- Deprotection hands the content type back as found: a protected
  -- change_cipher_spec and a zero-length handshake or alert all open
  -- here, and the reader above this layer answers §5.4's
  -- "unexpected_message" for them. Only `invalid(0)` has no content
  -- type at all, which allZeroOk covers.
  let innerTypeOk := opens («seal» secret 1 0x14 pt) 1 pt 0x14 &&
    opens («seal» secret 1 0x16 ByteArray.empty) 1 ByteArray.empty 0x16 &&
    opens («seal» secret 1 0x15 ByteArray.empty) 1 ByteArray.empty 0x15
  -- §5.2 record_overflow (2^14 + 256) and §5.4's inner limit (2^14 + 1).
  -- Both are decided on the framing before the AEAD runs, so the case
  -- below pins the two constants and the refusal; it cannot tell them
  -- apart from a tag failure, since a record that large with a valid tag
  -- costs a 16 KiB keystream. The differential run carries that.
  let oversized := ByteArray.mk #[0x17, 0x03, 0x03] ++
    natToBytesBE (maxCiphertext + 1) 2 ++ ByteArray.mk (Array.replicate (maxCiphertext + 1) 0)
  let sizeOk := maxCiphertext == 16640 && maxInner == 16385 && rejects oversized 0
  return headerOk && nonceOk && seqOk && roundTripOk && padOk && allZeroOk &&
    tagOk && truncOk && outerTypeOk && innerTypeOk && sizeOk


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
