import Spec.Bytes
import Spec.Hkdf

/-!
AES-128, the forward cipher of FIPS 197, and the Initial keys RFC 9001
§5.2 derives for it, written from the standards as an executable oracle.

The S-box is computed, not tabulated: FIPS 197 §5.1.1 defines it as the
affine transform of the multiplicative inverse in GF(2^8), and this
module says that, where `quic_aes.c` ships the 256-byte table the
definition produces. The differential compares the two.

Only the forward cipher exists here, for the reason `quic_aes.h` gives:
GCM uses CIPH_K alone and the RFC 9001 §5.4.3 mask is one forward block,
so nothing in this tree decrypts an AES block.
-/
namespace Spec.Aes
open Spec.Bytes

/-- Rotate a byte left by `n` bits, the operation FIPS 197 §5.1.1's
affine transform indexes with. -/
def rotl (b : UInt8) (n : UInt8) : UInt8 := (b <<< n) ||| (b >>> (8 - n))

/-- FIPS 197 §4.2: multiplication by x in GF(2^8). The left shift drops
bit 7, and the field polynomial x^8+x^4+x^3+x+1 reduces the result. -/
def xtime (b : UInt8) : UInt8 :=
  if b &&& 0x80 == 0 then b <<< 1 else (b <<< 1) ^^^ 0x1b

/-- FIPS 197 §4.2.1: the product of two field elements, as the sum of
the doublings of `a` that the bits of `b` select. -/
def gmul (a b : UInt8) : UInt8 := Id.run do
  let mut doubling := a
  let mut acc : UInt8 := 0
  for i in [0:8] do
    if (b >>> UInt8.ofNat i) &&& 1 == 1 then
      acc := acc ^^^ doubling
    doubling := xtime doubling
  return acc

/-- FIPS 197 §5.1.1: the multiplicative inverse in GF(2^8), with 0 mapped
to 0. Searched rather than computed: the inverse of `b` is the one
element whose product with `b` is 1, and saying that is shorter than any
way of finding it. -/
def inv (b : UInt8) : UInt8 :=
  UInt8.ofNat (((List.range 256).find? fun x => gmul b (UInt8.ofNat x) == 1).getD 0)

/-- FIPS 197 §5.1.1, equation (5.1): the affine transform over GF(2).
Bit i of the result sums bits i, i+4, i+5, i+6 and i+7 of the input and
bit i of 0x63, which is the byte rotated left by 0, 4, 3, 2 and 1. -/
def affine (b : UInt8) : UInt8 :=
  b ^^^ rotl b 1 ^^^ rotl b 2 ^^^ rotl b 3 ^^^ rotl b 4 ^^^ 0x63

/-- FIPS 197 §5.1.1: the S-box, the affine transform of the inverse. -/
def sbox (b : UInt8) : UInt8 := affine (inv b)

/-- FIPS 197 §5.1.1, SubBytes: the S-box on every byte of the state. -/
def subBytes (s : ByteArray) : ByteArray := ByteArray.mk (s.data.map sbox)

/-- FIPS 197 §5.1.2, ShiftRows: row r of the state moves left by r
columns. Byte i of the state is row i % 4 of column i / 4 (§3.4). -/
def shiftRows (s : ByteArray) : ByteArray :=
  (List.range 16).foldl (fun out i =>
    out.set! i s[(i % 4) + 4 * ((i / 4 + i % 4) % 4)]!) s

/-- FIPS 197 §5.1.3, MixColumns: each column is multiplied by the fixed
polynomial of equation (5.6), whose rows are 2 3 1 1 rotated. -/
def mixColumns (s : ByteArray) : ByteArray :=
  (List.range 16).foldl (fun out i =>
    let base := 4 * (i / 4)
    let a := s[base + (i + 0) % 4]!
    let b := s[base + (i + 1) % 4]!
    let c := s[base + (i + 2) % 4]!
    let d := s[base + (i + 3) % 4]!
    out.set! i (gmul 2 a ^^^ gmul 3 b ^^^ c ^^^ d)) s

/-- FIPS 197 §5.1.4, AddRoundKey: the state exclusive-ored with one round
key. -/
def addRoundKey (s roundKey : ByteArray) : ByteArray := xorBytes s roundKey

/-- FIPS 197 §5.2: the round constant of word `4 * i`, x^(i-1) in
GF(2^8). -/
def roundConstant : Nat → UInt8
  | 0 => 1
  | n + 1 => xtime (roundConstant n)

/-- The 4-byte word `j` of an expansion, read byte by byte so that the
word is four bytes whatever the array holds. -/
def wordAt (w : ByteArray) (j : Nat) : ByteArray :=
  ByteArray.mk #[w[4 * j]!, w[4 * j + 1]!, w[4 * j + 2]!, w[4 * j + 3]!]

/-- Round key `r` of an expansion, read byte by byte so that it is 16
bytes whatever the array holds. -/
def roundKeyAt (w : ByteArray) (r : Nat) : ByteArray :=
  ByteArray.mk (Array.ofFn (n := 16) fun j => w[16 * r + j.val]!)

/-- FIPS 197 §5.2: one word of the expansion appended to what is built.
Word `i` is word `i - 4` exclusive-ored with word `i - 1`, and every
fourth word takes RotWord, SubWord and the round constant first. -/
def expandWord (w : ByteArray) (i : Nat) : ByteArray :=
  let p := wordAt w (i - 1)
  let t := if i % 4 == 0 then
      ByteArray.mk #[sbox p[1]! ^^^ roundConstant (i / 4 - 1), sbox p[2]!, sbox p[3]!, sbox p[0]!]
    else p
  w ++ xorBytes (wordAt w (i - 4)) t

/-- FIPS 197 §5.2, Key Expansion for Nk = 4: the 16 key bytes are the
first round key, and the 40 words after them are `expandWord`'s. The
result is 11 round keys. -/
def keySchedule (key : ByteArray) : ByteArray := (List.range' 4 40).foldl expandWord key

/-- FIPS 197 §5.1: one full round — SubBytes, ShiftRows, MixColumns,
AddRoundKey. -/
def cipherRound (w : ByteArray) (s : ByteArray) (round : Nat) : ByteArray :=
  addRoundKey (mixColumns (shiftRows (subBytes s))) (roundKeyAt w round)

/-- FIPS 197 §5.1: the forward cipher CIPH_K under a 128-bit key — one
AddRoundKey, nine full rounds, and a last round without MixColumns. -/
def encryptBlock (key block : ByteArray) : ByteArray :=
  let w := keySchedule key
  let last := (List.range' 1 9).foldl (cipherRound w) (addRoundKey block (roundKeyAt w 0))
  addRoundKey (shiftRows (subBytes last)) (roundKeyAt w 10)

/-- RFC 9001 §5.2's printed salt, 0x38762cf7f55934b34d179ae6a4c80cadccbb7f0a. -/
def initialSalt : ByteArray :=
  ByteArray.mk #[0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17,
                 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a]

/-- RFC 9001 §5.8's printed Retry integrity tag key,
0xbe0c690b9f66575a1d766b54e368c84e. -/
def retryKey : ByteArray :=
  ByteArray.mk #[0xbe, 0x0c, 0x69, 0x0b, 0x9f, 0x66, 0x57, 0x5a, 0x1d, 0x76,
                 0x6b, 0x54, 0xe3, 0x68, 0xc8, 0x4e]

/-- RFC 9001 §5.2: the secret one direction protects Initial packets
with. `client` picks the label "client in", which the client uses for
what it sends; "server in" is what it reads. -/
def initialSecret (dcid : ByteArray) (client : Bool) : ByteArray :=
  Spec.Hkdf.expandLabel (Spec.Hkdf.extract initialSalt dcid)
    (if client then "client in" else "server in") ByteArray.empty 32

/-- RFC 9001 §5.1: the packet protection key, the packet protection IV
and the header protection key of one direction of the Initial level,
each an HKDF-Expand-Label over that direction's secret with an empty
context. -/
def initialKeys (dcid : ByteArray) (client : Bool) : ByteArray × ByteArray × ByteArray :=
  let secret := initialSecret dcid client
  (Spec.Hkdf.expandLabel secret "quic key" ByteArray.empty 16,
   Spec.Hkdf.expandLabel secret "quic iv" ByteArray.empty 12,
   Spec.Hkdf.expandLabel secret "quic hp" ByteArray.empty 16)

/-- A word read byte by byte is four bytes, whatever the array holds. -/
theorem wordAt_size (w : ByteArray) (j : Nat) : (wordAt w j).size = 4 := rfl

/-- A round key read byte by byte is 16 bytes, whatever the array
holds. -/
theorem roundKeyAt_size (w : ByteArray) (r : Nat) : (roundKeyAt w r).size = 16 := by
  show (Array.ofFn (n := 16) fun j => w[16 * r + j.val]!).size = 16
  simp

/-- One expansion step appends one 4-byte word. -/
theorem expandWord_size (w : ByteArray) (i : Nat) : (expandWord w i).size = w.size + 4 := by
  simp only [expandWord]
  split <;> simp [ByteArray.size_append, xorBytes_size, wordAt_size] <;> rfl

/-- The key expansion emits 11 round keys of 16 bytes (FIPS 197 §5.2:
Nb(Nr+1) words, for a 16-byte key). -/
theorem keySchedule_size (key : ByteArray) (h_key : key.size = 16) :
    (keySchedule key).size = 176 := by
  have h_fold := foldl_inv_idx (List.range' 4 40) expandWord
    (fun k w => w.size = 16 + 4 * k) key (by simpa using h_key)
    (fun k w i h_step => by simp [expandWord_size, h_step]; omega)
  simp only [List.length_range'] at h_fold
  exact h_fold

/-- Adding a round key twice is the identity: AddRoundKey is an XOR
(FIPS 197 §5.1.4), so no round key loses state. -/
theorem addRoundKey_addRoundKey (s roundKey : ByteArray) (h_fits : s.size ≤ roundKey.size) :
    addRoundKey (addRoundKey s roundKey) roundKey = s := by
  simpa [addRoundKey] using xorBytes_xorBytes s roundKey h_fits

/-- SubBytes rewrites bytes in place, so the state keeps its size. -/
theorem subBytes_size (s : ByteArray) : (subBytes s).size = s.size := by
  show (s.data.map sbox).size = s.data.size
  simp

/-- ShiftRows moves bytes inside the state, so the state keeps its size. -/
theorem shiftRows_size (s : ByteArray) : (shiftRows s).size = s.size := by
  have h_fold := foldl_inv (List.range 16)
    (fun (out : ByteArray) i => out.set! i s[(i % 4) + 4 * ((i / 4 + i % 4) % 4)]!)
    (fun out => out.size = s.size) s rfl (by intro out i h_step; simpa using h_step)
  simpa [shiftRows] using h_fold

/-- MixColumns rewrites bytes in place, so the state keeps its size. -/
theorem mixColumns_size (s : ByteArray) : (mixColumns s).size = s.size := by
  have h_fold := foldl_inv (List.range 16)
    (fun (out : ByteArray) i =>
      out.set! i (gmul 2 s[4 * (i / 4) + (i + 0) % 4]! ^^^ gmul 3 s[4 * (i / 4) + (i + 1) % 4]! ^^^
        s[4 * (i / 4) + (i + 2) % 4]! ^^^ s[4 * (i / 4) + (i + 3) % 4]!))
    (fun out => out.size = s.size) s rfl (by intro out i h_step; simpa using h_step)
  simpa [mixColumns] using h_fold

/-- One full round keeps a 16-byte state 16 bytes. -/
theorem cipherRound_size (w s : ByteArray) (round : Nat) (h_state : s.size = 16) :
    (cipherRound w s round).size = 16 := by
  simp [cipherRound, addRoundKey, xorBytes_size, mixColumns_size, shiftRows_size,
    subBytes_size, roundKeyAt_size, h_state]

/-- The forward cipher answers one block (FIPS 197 §5.1: CIPH_K maps a
128-bit block to a 128-bit block). -/
theorem encryptBlock_size (key block : ByteArray) (h_block : block.size = 16) :
    (encryptBlock key block).size = 16 := by
  have h_first : (addRoundKey block (roundKeyAt (keySchedule key) 0)).size = 16 := by
    simp [addRoundKey, xorBytes_size, roundKeyAt_size, h_block]
  have h_fold := foldl_inv (List.range' 1 9) (cipherRound (keySchedule key))
    (fun s => s.size = 16) _ h_first
    (fun s round h_step => cipherRound_size _ s round h_step)
  show (addRoundKey (shiftRows (subBytes (List.foldl (cipherRound (keySchedule key))
    (addRoundKey block (roundKeyAt (keySchedule key) 0)) (List.range' 1 9))))
      (roundKeyAt (keySchedule key) 10)).size = 16
  rw [addRoundKey, xorBytes_size, shiftRows_size, subBytes_size, roundKeyAt_size, h_fold]
  simp

set_option compiler.extract_closed false in
/-- Test vectors: FIPS 197 Appendix C.1 for the block cipher, the §5.1.1
worked S-box entry, and RFC 9001 Appendix A.1 for the client's Initial
keys. -/
def selftest (_ : Unit) : Bool :=
  -- A malformed literal falls back to a 1-byte sentinel, which fails the
  -- length-sensitive checks instead of testing the empty string.
  let hx (s : String) : ByteArray := (hexToBytes? s).getD (ByteArray.mk #[0])
  let block := encryptBlock (hx "000102030405060708090a0b0c0d0e0f")
    (hx "00112233445566778899aabbccddeeff")
  let (key, iv, hp) := initialKeys (hx "8394c8f03e515708") true
  bytesToHex block == "69c4e0d86a7b0430d8cdb78070b4c55a"
    && bytesToHex (ByteArray.mk #[sbox 0x53]) == "ed"
    && bytesToHex key == "1f369613dd76d5467730efcbe3b1a22d"
    && bytesToHex iv == "fa044b2f42a3fd3b46fb255c"
    && bytesToHex hp == "9f50449e04a0e810283a1e9933adedd2"

end Spec.Aes
