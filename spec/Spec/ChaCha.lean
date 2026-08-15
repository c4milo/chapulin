import Spec.Bytes

/-!
ChaCha20 per RFC 8439 §2.1–2.4, written from the RFC text as an
executable oracle. State is sixteen 32-bit words; all word arithmetic
wraps mod 2^32 (native `UInt32`).
-/
namespace Spec.ChaCha
open Spec.Bytes

/-- RFC 8439 §2.1: rotate a 32-bit word left by `c` bits (the `<<<` op). -/
def rotl (x : UInt32) (c : UInt32) : UInt32 :=
  (x <<< c) ||| (x >>> (32 - c))

/-- RFC 8439 §2.1: the quarter round on state words `a b c d`. -/
def quarterRound (s : Array UInt32) (a b c d : Nat) : Array UInt32 := Id.run do
  let mut x := s
  x := x.set! a (x[a]! + x[b]!); x := x.set! d (rotl (x[d]! ^^^ x[a]!) 16)
  x := x.set! c (x[c]! + x[d]!); x := x.set! b (rotl (x[b]! ^^^ x[c]!) 12)
  x := x.set! a (x[a]! + x[b]!); x := x.set! d (rotl (x[d]! ^^^ x[a]!) 8)
  x := x.set! c (x[c]! + x[d]!); x := x.set! b (rotl (x[b]! ^^^ x[c]!) 7)
  return x

/-- Little-endian 32-bit word `i` of a byte string (RFC 8439 §2.3). -/
def word (b : ByteArray) (i : Nat) : UInt32 :=
  UInt32.ofNat (bytesToNatLE (b.extract (4 * i) (4 * i + 4)))

/--
RFC 8439 §2.3: initial state — constants "expand 32-byte k", the
256-bit key as 8 LE words, the 32-bit block counter, the 96-bit nonce
as 3 LE words.
-/
def initState (key nonce : ByteArray) (counter : UInt32) : Array UInt32 :=
  #[0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,
    word key 0, word key 1, word key 2, word key 3,
    word key 4, word key 5, word key 6, word key 7,
    counter, word nonce 0, word nonce 1, word nonce 2]

/-- RFC 8439 §2.3: one double round — four column then four diagonal
quarter rounds. -/
def doubleRound (s : Array UInt32) : Array UInt32 :=
  let s := quarterRound s 0 4  8 12
  let s := quarterRound s 1 5  9 13
  let s := quarterRound s 2 6 10 14
  let s := quarterRound s 3 7 11 15
  let s := quarterRound s 0 5 10 15
  let s := quarterRound s 1 6 11 12
  let s := quarterRound s 2 7  8 13
  quarterRound s 3 4  9 14

/--
RFC 8439 §2.3: the ChaCha20 block function — 20 rounds (10 double
rounds) over the initial state, add the initial state word-wise, and
serialize the 16 words little-endian into 64 keystream bytes.
-/
def block (key nonce : ByteArray) (counter : UInt32) : ByteArray := Id.run do
  let init := initState key nonce counter
  let mut s := init
  for _ in [0:10] do
    s := doubleRound s
  let mut out := ByteArray.emptyWithCapacity 64
  for i in [0:16] do
    out := out ++ natToBytesLE (s[i]! + init[i]!).toNat 4
  return out

/--
RFC 8439 §2.4: ChaCha20 as a stream cipher — XOR `data` with the
concatenated keystream blocks for counters `counter`, `counter+1`, …;
the last block is truncated to the remaining length.
-/
def xor (key nonce : ByteArray) (counter : UInt32) (data : ByteArray) : ByteArray := Id.run do
  let mut out := ByteArray.emptyWithCapacity data.size
  for j in [0:(data.size + 63) / 64] do
    let ks := block key nonce (counter + UInt32.ofNat j)
    let chunk := data.extract (64 * j) (min (64 * j + 64) data.size)
    out := out ++ xorBytes chunk ks
  return out

/-- Test vectors: RFC 8439 §2.3.2 (block keystream) and §2.4.2
(encryption). -/
def selftest : Bool := Id.run do
  -- A malformed literal falls back to a 1-byte sentinel and breaks the
  -- length-sensitive checks instead of testing the empty string.
  let hx (s : String) : ByteArray := (hexToBytes? s).getD (ByteArray.mk #[0])
  -- §2.3.2: key 00..1f, nonce 000000090000004a00000000, counter 1.
  let key := hx "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
  let ks := block key (hx "000000090000004a00000000") 1
  let ksOk := bytesToHex ks ==
    "10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4e" ++
    "d2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e"
  -- §2.4.2: same key, nonce 000000000000004a00000000, counter 1.
  let pt := ascii ("Ladies and Gentlemen of the class of '99: If I could offer you " ++
    "only one tip for the future, sunscreen would be it.")
  let ct := xor key (hx "000000000000004a00000000") 1 pt
  let ctOk := bytesToHex ct ==
    "6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0b" ++
    "f91b65c5524733ab8f593dabcd62b3571639d624e65152ab8f530c359f0861d8" ++
    "07ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab7793736" ++
    "5af90bbf74a35be6b40b8eedf2785e42874d"
  -- Decryption is the same XOR (RFC 8439 §2.4).
  let rtOk := bytesToHex (xor key (hx "000000000000004a00000000") 1 ct) == bytesToHex pt
  return ksOk && ctOk && rtOk

end Spec.ChaCha

