import Spec.Bytes

/-!
X25519 Diffie-Hellman scalar multiplication, RFC 7748 §5.

Everything is plain `Nat` arithmetic with an explicit `% p` after every
field operation, `p = 2^255 - 19` (§4.1). The ladder is the exact
pseudocode of §5: conditional swap driven by the running ladder bit,
working variables `x_2/z_2/x_3/z_3`, and `a24 = 121665`. Inversion is
Fermat's little theorem, `z^(p-2)`, via square-and-multiply that reduces
mod `p` at every step (no unreduced giant powers).
-/

namespace Spec.X25519

open Spec.Bytes

/-- Field prime `p = 2^255 - 19` (RFC 7748 §4.1). -/
def p : Nat := 2 ^ 255 - 19

/-- `a24 = (486662 - 2) / 4 = 121665` (RFC 7748 §5). -/
def a24 : Nat := 121665

/-- Square-and-multiply `b^e mod m`, reducing after every multiplication
so intermediates never exceed `m^2`. -/
def powMod (b e m : Nat) : Nat :=
  go (b % m) e (1 % m)
where
  go (b e acc : Nat) : Nat :=
    if _h : e = 0 then acc
    else go (b * b % m) (e / 2) (if e % 2 = 1 then acc * b % m else acc)
  termination_by e
  decreasing_by omega

/-- Field inversion by Fermat's little theorem: `z^(p-2) mod p`
(RFC 7748 §5 finishes the ladder with `x_2 * (z_2^(p - 2))`). -/
def finv (z : Nat) : Nat := powMod z (p - 2) p

/-- RFC 7748 §5 `decodeUCoordinate` for bits = 255: mask the most
significant bit of the final byte (`u_list[31] &= 0x7f`), then decode
little-endian. -/
def decodeUCoordinate (b : ByteArray) : Nat :=
  bytesToNatLE (b.set! 31 (b[31]! &&& 0x7f))

/-- RFC 7748 §5 `decodeScalar25519`: clamp with
`k[0] &= 248; k[31] &= 127; k[31] |= 64`, then decode little-endian. -/
def decodeScalar (b : ByteArray) : Nat :=
  let b := b.set! 0 (b[0]! &&& 248)
  let b := b.set! 31 ((b[31]! &&& 127) ||| 64)
  bytesToNatLE b

/-- RFC 7748 §5 `encodeUCoordinate`: reduce mod `p`, emit 32 bytes
little-endian. -/
def encodeUCoordinate (u : Nat) : ByteArray :=
  natToBytesLE (u % p) 32

/-- The Montgomery ladder of RFC 7748 §5 on decoded scalar `k` and
u-coordinate `u`: 255 iterations (`t = 254` down to `0`), conditional
swap on `swap ^= k_t`, then the §5 formulas
`A, AA, B, BB, E, C, D, DA, CB` and the updates
`x_3 = (DA + CB)^2`, `z_3 = x_1 * (DA - CB)^2`,
`x_2 = AA * BB`, `z_2 = E * (AA + a24 * E)`.
Returns the affine result `x_2 * z_2^(p-2) mod p`. Subtraction in GF(p)
is `(x + p - y) % p`; both operands are already reduced, so the `Nat`
difference never underflows. -/
def ladder (k u : Nat) : Nat := Id.run do
  let x1 := u % p
  let mut x2 : Nat := 1
  let mut z2 : Nat := 0
  let mut x3 := x1
  let mut z3 : Nat := 1
  let mut swap : Nat := 0
  for i in [0:255] do
    let t := 254 - i
    let kt := (k >>> t) &&& 1
    swap := swap ^^^ kt
    if swap = 1 then
      let tx := x2; x2 := x3; x3 := tx
      let tz := z2; z2 := z3; z3 := tz
    swap := kt
    let a  := (x2 + z2) % p
    let aa := a * a % p
    let bs := (x2 + p - z2) % p
    let bb := bs * bs % p
    let e  := (aa + p - bb) % p
    let c  := (x3 + z3) % p
    let d  := (x3 + p - z3) % p
    let da := d * a % p
    let cb := c * bs % p
    let s  := (da + cb) % p
    x3 := s * s % p
    let t2 := (da + p - cb) % p
    z3 := x1 * (t2 * t2 % p) % p
    x2 := aa * bb % p
    z2 := e * ((aa + a24 * e % p) % p) % p
  -- Final conditional swap (§5, after the loop body).
  if swap = 1 then
    let tx := x2; x2 := x3; x3 := tx
    let tz := z2; z2 := z3; z3 := tz
  return x2 * finv z2 % p

/-- X25519 (RFC 7748 §5): decode scalar and u-coordinate, run the
Montgomery ladder, encode the result. -/
def scalarMult (scalar point : ByteArray) : ByteArray :=
  encodeUCoordinate (ladder (decodeScalar scalar) (decodeUCoordinate point))

/-- X25519 with the base point `u = 9` (RFC 7748 §4.1, §6.1). -/
def base (scalar : ByteArray) : ByteArray :=
  scalarMult scalar (encodeUCoordinate 9)

/-- RFC 7748 test vectors: the two §5.2 single vectors, one iteration of
the §5.2 iteration test, and the §6.1 Diffie-Hellman public keys and
shared secret. -/
def selftest : Bool :=
  let hx := fun s => (hexToBytes? s).getD ByteArray.empty
  let sm := fun (k u r : String) => bytesToHex (scalarMult (hx k) (hx u)) == r
  -- §5.2 vector 1
  sm "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4"
     "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c"
     "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552" &&
  -- §5.2 vector 2 (u has the top bit set, exercising the mask)
  sm "4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d"
     "e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493"
     "95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957" &&
  -- §5.2 iteration test, one iteration (k = u = 9)
  sm "0900000000000000000000000000000000000000000000000000000000000000"
     "0900000000000000000000000000000000000000000000000000000000000000"
     "422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079" &&
  -- §6.1: public keys from the private keys, and the shared secret K
  let alicePriv := hx "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"
  let bobPriv := hx "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb"
  let alicePub := "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"
  let bobPub := "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"
  let shared := "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"
  bytesToHex (base alicePriv) == alicePub &&
  bytesToHex (base bobPriv) == bobPub &&
  bytesToHex (scalarMult alicePriv (hx bobPub)) == shared &&
  bytesToHex (scalarMult bobPriv (hx alicePub)) == shared

end Spec.X25519
