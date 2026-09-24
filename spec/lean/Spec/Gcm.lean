import Spec.Bytes
import Spec.Aes

/-!
AEAD_AES_128_GCM, AEAD_AES_256_GCM and the GHASH under them, NIST SP
800-38D, written from the standard as an executable oracle. The two
AEADs differ in the forward cipher alone, and `Spec.Aes.cipher` picks
that by the key's length, so every definition below serves both.

A block is a 128-bit value here, where `quic_gcm.c` carries 16 bytes.
SP 800-38D numbers the bits of a block from the leftmost, so the
standard's bit 0 is the most significant bit of the value, and the
conversion in both directions is `natToBytesBE` and `bytesToNatBE`. The
differential compares the bytes, so the two representations meet where
they are compared and nowhere else.

Only the 96-bit IV exists here, for the reason `quic_gcm.h` gives: SP
800-38D §7.1 takes the first counter block straight from a 96-bit IV,
QUIC produces no other length, and the C has no second arm to model.

The forward cipher comes from `Spec.Aes.cipher`, so this module states
GCM and restates nothing about AES.
-/
namespace Spec.Gcm
open Spec.Bytes

/-- SP 800-38D §6.3: the field polynomial's reduction term R, the block
`11100001 || 0^120` read as a 128-bit value. -/
def reductionTerm : Nat := 0xe1 <<< 120

/-- SP 800-38D §6.3, Algorithm 1: the product of two blocks in
GF(2^128). Bit i of `x`, counted from the standard's leftmost bit, adds
the running multiple to the product; the multiple moves right one bit
each step and takes R back when the bit that moved out was set. -/
def mulBlocks (x y : Nat) : Nat := Id.run do
  let mut product := 0
  let mut multiple := y
  for i in [0:128] do
    if (x >>> (127 - i)) % 2 == 1 then
      product := product ^^^ multiple
    let wrapped := multiple % 2 == 1
    multiple := multiple >>> 1
    if wrapped then
      multiple := multiple ^^^ reductionTerm
  return product

/-- The 16 bytes at block `i` of an array, read byte by byte so that the
block is 16 bytes whatever the array holds. A block past the end reads
as zeros, which is the padding SP 800-38D §6.4 appends. -/
def blockAt (b : ByteArray) (i : Nat) : ByteArray :=
  ByteArray.mk (Array.ofFn (n := 16) fun j => b[16 * i + j.val]?.getD 0)

/-- SP 800-38D §6.4: a byte string as its blocks, the last one padded
with zeros on the right. -/
def blocksOf (b : ByteArray) : List Nat :=
  (List.range ((b.size + 15) / 16)).map fun i => bytesToNatBE (blockAt b i)

/-- SP 800-38D §6.4: GHASH_H over a list of blocks. Each block is added
to the accumulator and the sum is multiplied by the hash subkey. -/
def ghashBlocks (subkey : Nat) (blocks : List Nat) : Nat :=
  blocks.foldl (fun acc x => mulBlocks (acc ^^^ x) subkey) 0

/-- SP 800-38D §7.1 step 1: the hash subkey is the forward cipher of a
block of zeros. -/
def hashSubkey (key : ByteArray) : Nat :=
  bytesToNatBE (Spec.Aes.cipher key (natToBytesBE 0 16))

/-- SP 800-38D §6.4's last block: the two lengths in bits, the
associated data's in the high 64 bits and the ciphertext's in the low
64. -/
def lengthBlock (aad ct : ByteArray) : Nat :=
  (8 * aad.size) * 2 ^ 64 + 8 * ct.size

/-- SP 800-38D §6.4 as GCM calls it: GHASH over the associated data, the
ciphertext and the block of lengths, each padded to a block. -/
def ghash (key aad ct : ByteArray) : ByteArray :=
  natToBytesBE
    (ghashBlocks (hashSubkey key) (blocksOf aad ++ blocksOf ct ++ [lengthBlock aad ct])) 16

/-- SP 800-38D §6.2, inc32: the rightmost 32 bits of the block increase
by one, modulo 2^32, and the 96 bits before them stay. -/
def inc32 (block : Nat) : Nat :=
  block / 2 ^ 32 * 2 ^ 32 + (block % 2 ^ 32 + 1) % 2 ^ 32

/-- `inc32` applied `n` times. -/
def inc32Iter (block : Nat) : Nat → Nat
  | 0 => block
  | n + 1 => inc32 (inc32Iter block n)

/-- SP 800-38D §7.1 step 2: for a 96-bit IV the first counter block is
the IV followed by 31 zero bits and a one. -/
def firstCounter (iv : ByteArray) : Nat := bytesToNatBE iv * 2 ^ 32 + 1

/-- SP 800-38D §6.5, GCTR over the blocks after the first counter block:
the data exclusive-ored with the forward cipher of each counter, the
counter increasing before every block. Enough keystream is built to
cover the data and `xorBytes` cuts it to the data's length, which is
§6.5's truncation of the last block. -/
def gctr (key : ByteArray) (first : Nat) (data : ByteArray) : ByteArray :=
  let keystream := (List.range ((data.size + 15) / 16)).foldl (fun out i =>
    out ++ Spec.Aes.cipher key (natToBytesBE (inc32Iter first (i + 1)) 16)) ByteArray.empty
  xorBytes data keystream

/-- SP 800-38D §7.1 step 6: the tag is GHASH exclusive-ored with the
forward cipher of the first counter block. -/
def tagOf (key iv aad ct : ByteArray) : ByteArray :=
  xorBytes (ghash key aad ct) (Spec.Aes.cipher key (natToBytesBE (firstCounter iv) 16))

/-- SP 800-38D §7.1, GCM-AE: the ciphertext and the tag. -/
def encrypt (key iv aad pt : ByteArray) : ByteArray × ByteArray :=
  let ct := gctr key (firstCounter iv) pt
  (ct, tagOf key iv aad ct)

/-- SP 800-38D §7.2, GCM-AD: the plaintext when the tag matches, and
nothing when it does not. The comparison is on the bytes, and `none` is
the specification's FAIL. -/
def decrypt? (key iv aad ct tag : ByteArray) : Option ByteArray :=
  if bytesToHex (tagOf key iv aad ct) == bytesToHex tag then
    some (gctr key (firstCounter iv) ct)
  else
    none

/-- RFC 9001 §5.8's printed Retry key and nonce (`rfc9001.txt:1499-1502`),
the one AES key in QUIC that no derivation produces. -/
def retryNonce : ByteArray :=
  ByteArray.mk #[0x46, 0x15, 0x99, 0xd3, 0x5d, 0x63, 0x2b, 0xf2, 0x23, 0x98, 0x25, 0xbb]

/-- GHASH answers one block (SP 800-38D §6.4: GHASH maps to a 128-bit
block). -/
theorem ghash_size (key aad ct : ByteArray) : (ghash key aad ct).size = 16 :=
  natToBytesBE_size _ _

/-- A block read byte by byte is 16 bytes, whatever the array holds. -/
theorem blockAt_size (b : ByteArray) (i : Nat) : (blockAt b i).size = 16 := by
  show (Array.ofFn (n := 16) fun j => b[16 * i + j.val]?.getD 0).size = 16
  simp

/-- The keystream GCTR builds covers the data, so §6.5's truncation
never shortens the answer below the input. -/
theorem gctr_size (key : ByteArray) (first : Nat) (data : ByteArray) :
    (gctr key first data).size = data.size := by
  have h_stream : ∀ n : Nat, ((List.range n).foldl (fun out i =>
      out ++ Spec.Aes.cipher key (natToBytesBE (inc32Iter first (i + 1)) 16))
      ByteArray.empty).size = 16 * n := by
    intro n
    have := size_foldl_append_const (List.range n)
      (fun i => Spec.Aes.cipher key (natToBytesBE (inc32Iter first (i + 1)) 16)) 16
      (fun i => Spec.Aes.cipher_size key _ (natToBytesBE_size _ _)) ByteArray.empty
    simpa [List.length_range, Nat.mul_comm] using this
  simp only [gctr, xorBytes_size, h_stream]
  omega

/-- The tag is one block (SP 800-38D §7.1 fixes it at 128 bits here). -/
theorem tagOf_size (key iv aad ct : ByteArray) (h_key : ∀ b : ByteArray, b.size = 16 →
    (Spec.Aes.cipher key b).size = 16) : (tagOf key iv aad ct).size = 16 := by
  simp [tagOf, xorBytes_size, ghash_size, h_key _ (natToBytesBE_size _ _)]

/-- Sealing does not change the length: SP 800-38D §7.1 writes one
ciphertext byte per plaintext byte, and the tag is separate. -/
theorem encrypt_ct_size (key iv aad pt : ByteArray) : (encrypt key iv aad pt).1.size = pt.size :=
  gctr_size key _ pt

/-- Opening a ciphertext whose tag matches runs the same GCTR that
sealed it, so `decrypt?` is `some` exactly when the tags agree. -/
theorem decrypt?_isSome (key iv aad ct tag : ByteArray) :
    (decrypt? key iv aad ct tag).isSome = (bytesToHex (tagOf key iv aad ct) == bytesToHex tag) := by
  simp only [decrypt?]
  split <;> simp_all

set_option compiler.extract_closed false in
/-- Test vectors: NIST SP 800-38D's AES-128 cases 1 to 4, its AES-256
cases 13 to 16, and the RFC 9001 Appendix A.4 Retry integrity tag, which
is this AEAD over an empty plaintext with the Retry Pseudo-Packet as
associated data (§5.8). -/
def selftest (_ : Unit) : Bool :=
  -- A malformed literal falls back to a 1-byte sentinel, which fails the
  -- length-sensitive checks instead of testing the empty string.
  let hx (s : String) : ByteArray := (hexToBytes? s).getD (ByteArray.mk #[0])
  let zeroKey := hx "00000000000000000000000000000000"
  let zeroIv := hx "000000000000000000000000"
  let key3 := hx "feffe9928665731c6d6a8f9467308308"
  let iv3 := hx "cafebabefacedbaddecaf888"
  let pt3 := hx ("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72" ++
                 "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255")
  let aad4 := hx "feedfacedeadbeeffeedfacedeadbeefabaddad2"
  let pt4 := hx ("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72" ++
                 "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39")
  -- RFC 9001 Appendix A.4's Retry Pseudo-Packet: the original
  -- Destination Connection ID's length, that connection ID, and the
  -- Retry packet up to its tag.
  let pseudo := hx "088394c8f03e515708ff000000010008f067a5502a4262b5746f6b656e"
  let (ct1, tag1) := encrypt zeroKey zeroIv ByteArray.empty ByteArray.empty
  let (ct2, tag2) := encrypt zeroKey zeroIv ByteArray.empty (hx "00000000000000000000000000000000")
  let (ct3, tag3) := encrypt key3 iv3 ByteArray.empty pt3
  let (ct4, tag4) := encrypt key3 iv3 aad4 pt4
  let (_, retryTag) := encrypt Spec.Aes.retryKey retryNonce pseudo ByteArray.empty
  let zeroKey256 := hx "0000000000000000000000000000000000000000000000000000000000000000"
  let key15 := hx "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308"
  let (ct13, tag13) := encrypt zeroKey256 zeroIv ByteArray.empty ByteArray.empty
  let (ct14, tag14) :=
    encrypt zeroKey256 zeroIv ByteArray.empty (hx "00000000000000000000000000000000")
  let (ct15, tag15) := encrypt key15 iv3 ByteArray.empty pt3
  let (ct16, tag16) := encrypt key15 iv3 aad4 pt4
  bytesToHex ct1 == "" && bytesToHex tag1 == "58e2fccefa7e3061367f1d57a4e7455a"
    && bytesToHex ct2 == "0388dace60b6a392f328c2b971b2fe78"
    && bytesToHex tag2 == "ab6e47d42cec13bdf53a67b21257bddf"
    && bytesToHex ct3 == ("42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e" ++
                          "21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f5985")
    && bytesToHex tag3 == "4d5c2af327cd64a62cf35abd2ba6fab4"
    && bytesToHex ct4 == ("42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e" ++
                          "21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091")
    && bytesToHex tag4 == "5bc94fbc3221a5db94fae95ae7121a47"
    && bytesToHex retryTag == "04a265ba2eff4d829058fb3f0f2496ba"
    && decrypt? key3 iv3 aad4 ct4 tag4 == some pt4
    && decrypt? key3 iv3 aad4 ct4 tag3 == none
    && bytesToHex (ghash zeroKey ByteArray.empty ByteArray.empty)
         == "00000000000000000000000000000000"
    && bytesToHex ct13 == "" && bytesToHex tag13 == "530f8afbc74536b9a963b4f1c4cb738b"
    && bytesToHex ct14 == "cea7403d4d606b6e074ec5d3baf39d18"
    && bytesToHex tag14 == "d0d1c8a799996bf0265b98b5d48ab919"
    && bytesToHex ct15 == ("522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa" ++
                           "8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662898015ad")
    && bytesToHex tag15 == "b094dac5d93471bdec1a502270e3cc6c"
    && bytesToHex ct16 == ("522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa" ++
                           "8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662")
    && bytesToHex tag16 == "76fc6ece0f4e1768cddf8853bb2d551b"
    && decrypt? key15 iv3 aad4 ct16 tag16 == some pt4

end Spec.Gcm
