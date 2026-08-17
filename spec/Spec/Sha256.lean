import Spec.Bytes

/-!
SHA-256, written from FIPS 180-4 (Secure Hash Standard) only.

`UInt32` arithmetic is exactly the standard's word arithmetic: FIPS
180-4 §3.2 defines `+` on 32-bit words as addition modulo 2^32, and the
logical operations are bitwise on 32-bit words, so `UInt32` matches the
spec definitionally.
-/

namespace Spec.Sha256
open Spec.Bytes

/-- FIPS 180-4 §3.2: `ROTR^n(x)`, rotate right by `n` (used with 1 ≤ n ≤ 31,
so both shift amounts stay in range). -/
def rotr (n : Nat) (x : UInt32) : UInt32 :=
  (x >>> UInt32.ofNat n) ||| (x <<< UInt32.ofNat (32 - n))

/-- FIPS 180-4 §4.1.2 (4.2): `Ch(x,y,z) = (x ∧ y) ⊕ (¬x ∧ z)`. -/
def ch (x y z : UInt32) : UInt32 := (x &&& y) ^^^ (~~~x &&& z)

/-- FIPS 180-4 §4.1.2 (4.3): `Maj(x,y,z) = (x ∧ y) ⊕ (x ∧ z) ⊕ (y ∧ z)`. -/
def maj (x y z : UInt32) : UInt32 := (x &&& y) ^^^ (x &&& z) ^^^ (y &&& z)

/-- FIPS 180-4 §4.1.2 (4.4): `Σ₀(x) = ROTR²(x) ⊕ ROTR¹³(x) ⊕ ROTR²²(x)`. -/
def bigSigma0 (x : UInt32) : UInt32 := rotr 2 x ^^^ rotr 13 x ^^^ rotr 22 x

/-- FIPS 180-4 §4.1.2 (4.5): `Σ₁(x) = ROTR⁶(x) ⊕ ROTR¹¹(x) ⊕ ROTR²⁵(x)`. -/
def bigSigma1 (x : UInt32) : UInt32 := rotr 6 x ^^^ rotr 11 x ^^^ rotr 25 x

/-- FIPS 180-4 §4.1.2 (4.6): `σ₀(x) = ROTR⁷(x) ⊕ ROTR¹⁸(x) ⊕ SHR³(x)`. -/
def smallSigma0 (x : UInt32) : UInt32 := rotr 7 x ^^^ rotr 18 x ^^^ (x >>> 3)

/-- FIPS 180-4 §4.1.2 (4.7): `σ₁(x) = ROTR¹⁷(x) ⊕ ROTR¹⁹(x) ⊕ SHR¹⁰(x)`. -/
def smallSigma1 (x : UInt32) : UInt32 := rotr 17 x ^^^ rotr 19 x ^^^ (x >>> 10)

/-- FIPS 180-4 §4.3.2: the sixty-four constant words K₀…K₆₃ (first 32 bits
of the fractional parts of the cube roots of the first 64 primes). -/
def K : Array UInt32 := #[
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
  0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
  0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
  0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
  0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
  0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
  0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
  0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
  0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2]

/-- FIPS 180-4 §5.3.3: the initial hash value H⁽⁰⁾ (first 32 bits of the
fractional parts of the square roots of the first 8 primes). -/
def H0 : Array UInt32 := #[
  0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
  0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]

/-- FIPS 180-4 §5.1.1: append the bit `1`, then k zero bits with
`l + 1 + k ≡ 448 (mod 512)`, then the message bit length as a 64-bit
big-endian integer. In bytes: `0x80`, zero bytes to 56 mod 64, 8-byte
length. -/
def pad (msg : ByteArray) : ByteArray :=
  let zeroCount := (120 - (msg.size + 1) % 64) % 64
  msg ++ ByteArray.mk #[0x80]
      ++ ByteArray.mk (Array.replicate zeroCount 0)
      ++ natToBytesBE (msg.size * 8) 8

/-- FIPS 180-4 §5.2.1 and §6.2.2 step 1: parse the 64-byte block at
`off` into sixteen big-endian 32-bit words W₀…W₁₅. -/
def blockWords (padded : ByteArray) (off : Nat) : Array UInt32 := Id.run do
  let mut w : Array UInt32 := Array.mkEmpty 16
  for i in [0:16] do
    let j := off + 4 * i
    w := w.push (UInt32.ofNat (bytesToNatBE (padded.extract j (j + 4))))
  return w

/-- FIPS 180-4 §6.2.2: one application of the compression function —
extend W to 64 words (step 1), run the 64 working-variable rounds
(steps 2–3), and add the result into the intermediate hash (step 4). -/
def compress (h : Array UInt32) (w0 : Array UInt32) : Array UInt32 := Id.run do
  let mut w := w0
  for t in [16:64] do
    w := w.push (smallSigma1 w[t-2]! + w[t-7]! + smallSigma0 w[t-15]! + w[t-16]!)
  let mut a := h[0]!
  let mut b := h[1]!
  let mut c := h[2]!
  let mut d := h[3]!
  let mut e := h[4]!
  let mut f := h[5]!
  let mut g := h[6]!
  let mut hh := h[7]!
  for t in [0:64] do
    let t1 := hh + bigSigma1 e + ch e f g + K[t]! + w[t]!
    let t2 := bigSigma0 a + maj a b c
    hh := g
    g := f
    f := e
    e := d + t1
    d := c
    c := b
    b := a
    a := t1 + t2
  return #[h[0]! + a, h[1]! + b, h[2]! + c, h[3]! + d,
           h[4]! + e, h[5]! + f, h[6]! + g, h[7]! + hh]

/-- FIPS 180-4 §6.2: SHA-256 of an arbitrary byte string — pad (§5.1.1),
parse into 512-bit blocks (§5.2.1), iterate the compression function
from H⁽⁰⁾, and emit H⁽ᴺ⁾ as 32 big-endian bytes. -/
def sha256 (msg : ByteArray) : ByteArray := Id.run do
  let padded := pad msg
  let mut h := H0
  for i in [0:padded.size / 64] do
    h := compress h (blockWords padded (i * 64))
  let mut out := ByteArray.emptyWithCapacity 32
  for word in h do
    out := out ++ natToBytesBE word.toNat 4
  return out

/-- The compression function always returns eight words (FIPS 180-4
§6.2.2 step 4). -/
theorem compress_size (h w : Array UInt32) : (compress h w).size = 8 := by
  simp [compress]

/-- The digest is always 32 bytes: eight 32-bit words serialized as
four big-endian bytes each. Size lemmas like this one are the base the
HKDF and key-schedule length proofs build on. -/
theorem sha256_size (msg : ByteArray) : (sha256 msg).size = 32 := by
  have hh : (List.foldl
      (fun b a => compress b (blockWords (pad msg) (a * 64)))
      H0 (List.range' 0 ((pad msg).size / 64))).size = 8 :=
    foldl_inv _ _ (fun h => h.size = 8) H0 rfl (fun b a _ => compress_size b _)
  simp [sha256, emptyWithCapacity_eq]
  rw [← Array.foldl_toList,
    size_foldl_append_const (g := fun a : UInt32 => natToBytesBE a.toNat 4) _ 4
      (fun a => natToBytesBE_size a.toNat 4)]
  simp [Array.length_toList, hh]

/-- FIPS 180-4 / NIST example vectors: SHA-256("abc") and the two-block
message (FIPS 180-4 appendix examples, also NIST CAVP), plus SHA-256 of
the empty string. -/
def selftest : Bool :=
  let vec (msg want : String) : Bool := bytesToHex (sha256 (ascii msg)) == want
  vec "abc"
      "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
  && vec "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
      "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
  && vec ""
      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

end Spec.Sha256
