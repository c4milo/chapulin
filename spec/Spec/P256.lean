import Spec.Bytes

/-!
ECDSA over NIST P-256 (secp256r1), FIPS 186-4 §6 with the domain
parameters of FIPS 186-4 §D.1.2.3 (same values as SEC 2 v2 §2.4.2).

Everything is plain `Nat` arithmetic with an explicit `% p` (or `% n`)
after every operation; points are affine `Option (Nat × Nat)` with
`none` for the point at infinity; inversion is Fermat's little theorem.
Subtraction in GF(p) is `(x + p - y) % p` on reduced operands, so the
`Nat` difference never underflows.

Signing lives here so the oracle can mint signatures the C verifier
must accept; the C side never signs.
-/

namespace Spec.P256

open Spec.Bytes

/-- Field prime `p = 2^256 - 2^224 + 2^192 + 2^96 - 1` (FIPS 186-4 §D.1.2.3). -/
def p : Nat := 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff

/-- Curve `y^2 = x^3 + ax + b` with `a ≡ -3 (mod p)` (FIPS 186-4 §D.1.2.3). -/
def a : Nat := p - 3

/-- Coefficient `b` (FIPS 186-4 §D.1.2.3). -/
def b : Nat := 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b

/-- Group order `n`; the cofactor is 1 (FIPS 186-4 §D.1.2.3). -/
def n : Nat := 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551

/-- Base point x-coordinate `G_x` (FIPS 186-4 §D.1.2.3). -/
def gx : Nat := 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296

/-- Base point y-coordinate `G_y` (FIPS 186-4 §D.1.2.3). -/
def gy : Nat := 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5

/-- Affine point; `none` is the point at infinity. -/
abbrev Point := Option (Nat × Nat)

/-- The base point `G`. -/
def g : Point := some (gx, gy)

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

/-- Inversion mod a prime `m` by Fermat's little theorem: `x^(m-2) mod m`. -/
def inv (x m : Nat) : Nat := powMod x (m - 2) m

/-- Curve membership: reduced coordinates with
`y^2 ≡ x^3 + ax + b (mod p)`. With cofactor 1 this is the whole
public-key validation (SEC 1 v2 §3.2.2.1; the order check is redundant). -/
def onCurve (x y : Nat) : Bool :=
  x < p && y < p && y * y % p == ((x * x % p * x % p + a * x % p) + b) % p

/-- Affine group law (SEC 1 v2 §2.2.1). `P + (-P) = O` covers doubling a
point with `y = 0`; otherwise the chord (or tangent, for `P = Q`) slope
`lam` gives `x3 = lam^2 - x1 - x2` and `y3 = lam(x1 - x3) - y1`. -/
def add : Point → Point → Point
  | none, q => q
  | pt, none => pt
  | some (x1, y1), some (x2, y2) =>
    if x1 == x2 && (y1 + y2) % p == 0 then none
    else
      let lam :=
        if x1 == x2 then (3 * (x1 * x1 % p) + a) % p * inv (2 * y1 % p) p % p
        else (y2 + p - y1) % p * inv ((x2 + p - x1) % p) p % p
      let x3 := (lam * lam % p + (p - x1) + (p - x2)) % p
      let y3 := (lam * ((x1 + p - x3) % p) % p + (p - y1)) % p
      some (x3, y3)

/-- Scalar multiplication by double-and-add over the bits of `k`. -/
def smul (k : Nat) (pt : Point) : Point :=
  go k pt none
where
  go (k : Nat) (q acc : Point) : Point :=
    if _h : k = 0 then acc
    else go (k / 2) (add q q) (if k % 2 = 1 then add acc q else acc)
  termination_by k
  decreasing_by omega

/-- Public key `Q = d·G` encoded as X‖Y, 32 bytes each big-endian
(SEC 1 v2 §2.3.3 uncompressed, without the 0x04 tag); `none` unless
`d ∈ [1, n-1]` (FIPS 186-4 §B.4). -/
def pubKey? (d : Nat) : Option ByteArray :=
  if d == 0 || d ≥ n then none
  else match smul d g with
    | none => none
    | some (x, y) => some (natToBytesBE x 32 ++ natToBytesBE y 32)

/-- ECDSA signing (FIPS 186-4 §6.4) with `d`, `k`, and the
hash-as-integer `z` given explicitly: `r = (k·G).x mod n` and
`s = k^-1 (z + r·d) mod n`. With SHA-256 and the 256-bit `n`, `z` is the
whole digest, no truncation. `none` when `d` or `k` is outside
`[1, n-1]` or `r`/`s` degenerates to 0. -/
def ecdsaSign (d k z : Nat) : Option (Nat × Nat) :=
  if d == 0 || d ≥ n || k == 0 || k ≥ n then none
  else match smul k g with
    | none => none
    | some (x, _) =>
      let r := x % n
      let s := inv k n * ((z % n + r * d) % n) % n
      if r == 0 || s == 0 then none else some (r, s)

/-- ECDSA verification (FIPS 186-4 §6.4 / SEC 1 v2 §4.1.4): `pub` is
X‖Y (64 bytes), `hash` the 32-byte digest, `r`/`s` the signature
integers. Requires `r, s ∈ [1, n-1]` and the public point on the curve,
then accepts iff `r ≡ (u1·G + u2·Q).x (mod n)` for `u1 = z·s^-1 mod n`,
`u2 = r·s^-1 mod n`. -/
def ecdsaVerify (pub hash : ByteArray) (r s : Nat) : Bool :=
  if pub.size != 64 || hash.size != 32 then false
  else
    let qx := bytesToNatBE (pub.extract 0 32)
    let qy := bytesToNatBE (pub.extract 32 64)
    if !onCurve qx qy then false
    else if r == 0 || r ≥ n || s == 0 || s ≥ n then false
    else
      let w := inv s n
      let u1 := bytesToNatBE hash * w % n
      let u2 := r * w % n
      match add (smul u1 g) (smul u2 (some (qx, qy))) with
      | none => false
      | some (x, _) => x % n == r

/-- The RFC 6979 §A.2.5 P-256/SHA-256 "sample" vector (deterministic
`k`; signature independently checked against openssl): key generation,
signing, verification, tamper rejection, and a sign-then-verify round
trip on unrelated inputs. -/
def selftest : Bool :=
  let hx := fun s => (hexToBytes? s).getD ByteArray.empty
  let d := 0xc9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721
  let k := 0xa6e3c57dd01abe90086538398355dd4c3b17aa873382b0f24d6129493d8aad60
  -- SHA-256("sample")
  let h := hx "af2bdbe1aa9b6ec1e2ade1d694f41fc71a831d0268e9891562113d8a62add1bf"
  let pub := hx ("60fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6" ++
                 "7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299")
  let r := 0xefd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716
  let s := 0xf7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8
  (match pubKey? d with
   | some q => bytesToHex q == bytesToHex pub
   | none => false) &&
  ecdsaSign d k (bytesToNatBE h) == some (r, s) &&
  ecdsaVerify pub h r s &&
  !ecdsaVerify pub (h.set! 0 (h[0]! ^^^ 1)) r s &&
  !ecdsaVerify pub h s r &&
  -- Round trip on unrelated inputs: sign with fresh d/k, verify with
  -- the derived public key, reject a one-byte hash flip.
  (let d2 := 0x1b8e05f5ee0f8b25101f13b6dc3d514cbbbf6bc7e2b1c9f2f6a2e15c7a3d4e51
   let k2 := 0x7f1c6a9de4b8b0a4c2d9e3f1a0b5c6d7e8f90123456789abcdef012345678901
   let h2 := hx "6cd2f8a17f5b3e9d0c4a2b1e8f7d6c5b4a392817065f4e3d2c1b0a9988776655"
   match ecdsaSign d2 k2 (bytesToNatBE h2), pubKey? d2 with
   | some (r2, s2), some q2 =>
     ecdsaVerify q2 h2 r2 s2 && !ecdsaVerify q2 (h2.set! 5 (h2[5]! ^^^ 0x40)) r2 s2
   | _, _ => false)

end Spec.P256
