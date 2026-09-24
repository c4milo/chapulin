import Spec.Bytes

/-!
SHA-512 and SHA-384, written from FIPS 180-4 (Secure Hash Standard) only.

`UInt64` arithmetic is exactly the standard's word arithmetic: FIPS
180-4 §3.2 defines `+` on 64-bit words as addition modulo 2^64, and the
logical operations are bitwise on 64-bit words, so `UInt64` matches the
spec definitionally. SHA-384 is SHA-512 started from its own initial
value with the first 384 bits of the result kept (§5.3.4 and §6.5), so
one `digest` carries both and the two differ in two arguments.
-/

namespace Spec.Sha512
open Spec.Bytes

/-- FIPS 180-4 §3.2: `ROTR^n(x)`, rotate right by `n` (used with 1 ≤ n ≤ 63,
so both shift amounts stay in range). -/
def rotr (n : Nat) (x : UInt64) : UInt64 :=
  (x >>> UInt64.ofNat n) ||| (x <<< UInt64.ofNat (64 - n))

/-- FIPS 180-4 §4.1.3 (4.8): `Ch(x,y,z) = (x ∧ y) ⊕ (¬x ∧ z)`. -/
def ch (x y z : UInt64) : UInt64 := (x &&& y) ^^^ (~~~x &&& z)

/-- FIPS 180-4 §4.1.3 (4.9): `Maj(x,y,z) = (x ∧ y) ⊕ (x ∧ z) ⊕ (y ∧ z)`. -/
def maj (x y z : UInt64) : UInt64 := (x &&& y) ^^^ (x &&& z) ^^^ (y &&& z)

/-- FIPS 180-4 §4.1.3 (4.10): `Σ₀(x) = ROTR²⁸(x) ⊕ ROTR³⁴(x) ⊕ ROTR³⁹(x)`. -/
def bigSigma0 (x : UInt64) : UInt64 := rotr 28 x ^^^ rotr 34 x ^^^ rotr 39 x

/-- FIPS 180-4 §4.1.3 (4.11): `Σ₁(x) = ROTR¹⁴(x) ⊕ ROTR¹⁸(x) ⊕ ROTR⁴¹(x)`. -/
def bigSigma1 (x : UInt64) : UInt64 := rotr 14 x ^^^ rotr 18 x ^^^ rotr 41 x

/-- FIPS 180-4 §4.1.3 (4.12): `σ₀(x) = ROTR¹(x) ⊕ ROTR⁸(x) ⊕ SHR⁷(x)`. -/
def smallSigma0 (x : UInt64) : UInt64 := rotr 1 x ^^^ rotr 8 x ^^^ (x >>> 7)

/-- FIPS 180-4 §4.1.3 (4.13): `σ₁(x) = ROTR¹⁹(x) ⊕ ROTR⁶¹(x) ⊕ SHR⁶(x)`. -/
def smallSigma1 (x : UInt64) : UInt64 := rotr 19 x ^^^ rotr 61 x ^^^ (x >>> 6)

/-- FIPS 180-4 §4.2.3: the eighty constant words K₀…K₇₉ (first 64 bits of
the fractional parts of the cube roots of the first 80 primes). -/
def K : Array UInt64 := #[
  0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
  0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
  0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
  0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
  0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
  0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
  0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
  0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
  0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
  0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
  0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
  0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
  0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
  0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
  0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
  0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
  0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
  0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
  0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
  0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817]

/-- FIPS 180-4 §5.3.5: the SHA-512 initial hash value H⁽⁰⁾ (first 64 bits
of the fractional parts of the square roots of the first 8 primes). -/
def H0_512 : Array UInt64 := #[
  0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
  0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179]

/-- FIPS 180-4 §5.3.4: the SHA-384 initial hash value H⁽⁰⁾ (the same bits
of the ninth through sixteenth primes). -/
def H0_384 : Array UInt64 := #[
  0xcbbb9d5dc1059ed8, 0x629a292a367cd507, 0x9159015a3070dd17, 0x152fecd8f70e5939,
  0x67332667ffc00b31, 0x8eb44a8768581511, 0xdb0c2e0d64f98fa7, 0x47b5481dbefa4fa4]

/-- FIPS 180-4 §5.1.2: append the bit `1`, then k zero bits with
`l + 1 + k ≡ 896 (mod 1024)`, then the message bit length as a 128-bit
big-endian integer. In bytes: `0x80`, zero bytes to 112 mod 128, 16-byte
length. -/
def pad (msg : ByteArray) : ByteArray :=
  let zeroCount := (240 - (msg.size + 1) % 128) % 128
  msg ++ ByteArray.mk #[0x80]
      ++ ByteArray.mk (Array.replicate zeroCount 0)
      ++ natToBytesBE (msg.size * 8) 16

/-- FIPS 180-4 §5.2.2 and §6.4.2 step 1: parse the 128-byte block at
`off` into sixteen big-endian 64-bit words W₀…W₁₅. -/
def blockWords (padded : ByteArray) (off : Nat) : Array UInt64 := Id.run do
  let mut w : Array UInt64 := Array.mkEmpty 16
  for i in [0:16] do
    let j := off + 8 * i
    w := w.push (UInt64.ofNat (bytesToNatBE (padded.extract j (j + 8))))
  return w

/-- FIPS 180-4 §6.4.2: one application of the compression function —
extend W to 80 words (step 1), run the 80 working-variable rounds
(steps 2–3), and add the result into the intermediate hash (step 4). -/
def compress (h : Array UInt64) (w0 : Array UInt64) : Array UInt64 := Id.run do
  let mut w := w0
  for t in [16:80] do
    w := w.push (smallSigma1 w[t-2]! + w[t-7]! + smallSigma0 w[t-15]! + w[t-16]!)
  let mut a := h[0]!
  let mut b := h[1]!
  let mut c := h[2]!
  let mut d := h[3]!
  let mut e := h[4]!
  let mut f := h[5]!
  let mut g := h[6]!
  let mut hh := h[7]!
  for t in [0:80] do
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

/-- The shared body of §6.4 and §6.5: pad (§5.1.2), parse into 1024-bit
blocks (§5.2.2), iterate the compression function from `h0`, and emit the
first `words` words of H⁽ᴺ⁾ as 8 big-endian bytes each. SHA-512 keeps all
eight; SHA-384 keeps six. -/
def digest (h0 : Array UInt64) (words : Nat) (msg : ByteArray) : ByteArray := Id.run do
  let padded := pad msg
  let mut h := h0
  for i in [0:padded.size / 128] do
    h := compress h (blockWords padded (i * 128))
  let kept := (h.extract 0 words).toList
  return kept.foldl (fun out word => out ++ natToBytesBE word.toNat 8) ByteArray.empty

/-- FIPS 180-4 §6.4: SHA-512 of an arbitrary byte string, 64 bytes out. -/
def sha512 (msg : ByteArray) : ByteArray := digest H0_512 8 msg

/-- FIPS 180-4 §6.5: SHA-384 of an arbitrary byte string, the first 48
bytes of the SHA-512 computation started from `H0_384`. -/
def sha384 (msg : ByteArray) : ByteArray := digest H0_384 6 msg

/-- The compression function always returns eight words (FIPS 180-4
§6.4.2 step 4). -/
theorem compress_size (h w : Array UInt64) : (compress h w).size = 8 := by
  simp [compress]

/-- `digest` emits eight bytes per kept word: with an eight-word initial
value and at most eight words kept, the output is `8 * words` bytes. Both
public size lemmas are instances of this one. -/
private theorem digest_size (h0 : Array UInt64) (words : Nat) (msg : ByteArray)
    (h_eight : h0.size = 8) (h_words : words ≤ 8) :
    (digest h0 words msg).size = 8 * words := by
  have h_fold : (List.foldl
      (fun b a => compress b (blockWords (pad msg) (a * 128)))
      h0 (List.range' 0 ((pad msg).size / 128))).size = 8 :=
    foldl_inv _ _ (fun h => h.size = 8) h0 h_eight (fun b a _ => compress_size b _)
  simp [digest]
  rw [size_foldl_append_const (g := fun a : UInt64 => natToBytesBE a.toNat 8) _ 8
      (fun a => natToBytesBE_size a.toNat 8)]
  simp [Array.length_toList, h_fold]
  omega

/-- The SHA-512 digest is always 64 bytes: eight 64-bit words serialized
as eight big-endian bytes each. -/
theorem sha512_size (msg : ByteArray) : (sha512 msg).size = 64 :=
  digest_size H0_512 8 msg rfl (by decide)

/-- The SHA-384 digest is always 48 bytes: the first six words of the
eight, serialized the same way (FIPS 180-4 §6.5 step 3). -/
theorem sha384_size (msg : ByteArray) : (sha384 msg).size = 48 :=
  digest_size H0_384 6 msg rfl (by decide)

/-- Padding always produces a whole number of 128-byte blocks
(FIPS 180-4 §5.1.2). -/
theorem pad_blocks (msg : ByteArray) : (pad msg).size % 128 = 0 := by
  have h_pad_byte_size : (ByteArray.mk #[0x80]).size = 1 := rfl
  rw [pad]
  simp only [ByteArray.size_append, natToBytesBE_size, zeros_size, h_pad_byte_size]
  omega

/-- Padding keeps the message as a prefix: the bytes before the `0x80`
are the message itself. -/
theorem pad_prefix (msg : ByteArray) : (pad msg).extract 0 msg.size = msg := by
  rw [pad, ByteArray.append_assoc, ByteArray.append_assoc]
  exact ByteArray.extract_append_eq_left rfl

/-- FIPS 180-4 appendix C and D examples: "abc" and the 896-bit two-block
message for each hash, plus the empty string. -/
def selftest : Bool :=
  let vec512 (msg want : String) : Bool := bytesToHex (sha512 (ascii msg)) == want
  let vec384 (msg want : String) : Bool := bytesToHex (sha384 (ascii msg)) == want
  let twoBlock := "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnop"
    ++ "jklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"
  vec512 "abc"
      ("ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
        ++ "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f")
  && vec512 twoBlock
      ("8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018"
        ++ "501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909")
  && vec512 ""
      ("cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce"
        ++ "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e")
  && vec384 "abc"
      ("cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed"
        ++ "8086072ba1e7cc2358baeca134c825a7")
  && vec384 twoBlock
      ("09330c33f71147e83d192fc782cd1b4753111b173b3b05d22fa08086e3b0f712"
        ++ "fcc7c71a557e2db966c3e9fa91746039")
  && vec384 ""
      ("38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da"
        ++ "274edebfe76f65fbd51ad2f14898b95b")

end Spec.Sha512
