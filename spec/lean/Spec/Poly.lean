import Spec.Bytes

/-!
Poly1305 per RFC 8439 §2.5, written from the RFC text as an executable
oracle. The accumulator is a plain `Nat` reduced mod `p = 2^130 - 5`
after every block — definitional, no limb tricks.
-/
namespace Spec.Poly
open Spec.Bytes

/-- The Poly1305 prime, RFC 8439 §2.5: `p = 2^130 - 5`. -/
def p : Nat := 2 ^ 130 - 5

/--
RFC 8439 §2.5.1: clamp `r` — clear the top four bits of bytes 3, 7,
11, 15 and the bottom two bits of bytes 4, 8, 12, expressed as one
little-endian mask.
-/
def clamp (r : Nat) : Nat := r &&& 0x0ffffffc0ffffffc0ffffffc0fffffff

/--
RFC 8439 §2.5: Poly1305. `r` is the clamped LE first half of the key,
`s` the LE second half. Each 16-byte (or shorter, final) chunk gets a
0x01 byte appended — as a number, add `2^(8*len)` to its LE value —
then `acc = (r * (acc + n)) mod p`. The tag is the low 128 bits of
`acc + s`, little-endian.
-/
def mac (key msg : ByteArray) : ByteArray := Id.run do
  let r := clamp (bytesToNatLE (key.extract 0 16))
  let s := bytesToNatLE (key.extract 16 32)
  let mut acc := 0
  for i in [0:(msg.size + 15) / 16] do
    let chunk := msg.extract (16 * i) (min (16 * i + 16) msg.size)
    let n := bytesToNatLE chunk + 2 ^ (8 * chunk.size)
    acc := (r * (acc + n)) % p
  return natToBytesLE ((acc + s) % 2 ^ 128) 16

/-- The tag is always 16 bytes (RFC 8439 §2.5: the low 128 bits of
`acc + s`). -/
theorem mac_size (key msg : ByteArray) : (mac key msg).size = 16 := by
  simp [mac, Spec.Bytes.natToBytesLE_size]

/-- Test vector: RFC 8439 §2.5.2. -/
def selftest : Bool :=
  -- A malformed literal falls back to a 1-byte sentinel and breaks the
  -- length-sensitive checks instead of testing the empty string.
  let hx (s : String) : ByteArray := (hexToBytes? s).getD (ByteArray.mk #[0])
  let key := hx "85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b"
  let tag := mac key (ascii "Cryptographic Forum Research Group")
  bytesToHex tag == "a8061dc1305136c6c22b8baf0c0127a9"

end Spec.Poly

