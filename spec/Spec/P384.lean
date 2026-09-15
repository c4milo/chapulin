import Spec.Bytes

/-!
ECDSA over NIST P-384 (secp384r1), FIPS 186-4 §6 with the domain
parameters of FIPS 186-4 §D.1.2.4 (same values as SEC 2 v2 §2.5.1).

This is `Spec/P256.lean` at the P-384 parameters: plain `Nat`
arithmetic with an explicit `% p` (or `% n`) after every operation,
affine `Option (Nat × Nat)` points with `none` for the point at
infinity, Fermat inversion, and `(x + p - y) % p` for subtraction on
reduced operands so the `Nat` difference never underflows.

The hash is exactly 48 bytes here, the length of SHA-384. A caller
holding a digest of another length truncates or left-pads it first
(FIPS 186-4 §6.4); that step lives with the caller, not in the curve.

Signing lives here so the oracle can mint signatures the C verifier
must accept; the C side never signs. The arithmetic theorems P-256
lacks are absent here for the same reason — the dependency-free build
carries no number theory (spec/CONTRACT.md) — and arrive with mathlib.
-/

namespace Spec.P384

open Spec.Bytes

/-- Field prime `p = 2^384 - 2^128 - 2^96 + 2^32 - 1` (FIPS 186-4 §D.1.2.4). -/
def p : Nat :=
  0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff

/-- Curve `y^2 = x^3 + ax + b` with `a ≡ -3 (mod p)` (FIPS 186-4 §D.1.2.4). -/
def a : Nat := p - 3

/-- Coefficient `b` (FIPS 186-4 §D.1.2.4). -/
def b : Nat :=
  0xb3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef

/-- Group order `n`; the cofactor is 1 (FIPS 186-4 §D.1.2.4). -/
def n : Nat :=
  0xffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973

/-- Base point x-coordinate `G_x` (FIPS 186-4 §D.1.2.4). -/
def gx : Nat :=
  0xaa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7

/-- Base point y-coordinate `G_y` (FIPS 186-4 §D.1.2.4). -/
def gy : Nat :=
  0x3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f

/-- Bytes in one coordinate or scalar. -/
def coordLen : Nat := 48

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

/-- Public key `Q = d·G` encoded as X‖Y, 48 bytes each big-endian
(SEC 1 v2 §2.3.3 uncompressed, without the 0x04 tag); `none` unless
`d ∈ [1, n-1]` (FIPS 186-4 §B.4). -/
def pubKey? (d : Nat) : Option ByteArray :=
  if d == 0 || d ≥ n then none
  else match smul d g with
    | none => none
    | some (x, y) => some (natToBytesBE x coordLen ++ natToBytesBE y coordLen)

/-- ECDSA signing (FIPS 186-4 §6.4) with `d`, `k`, and the
hash-as-integer `z` given explicitly: `r = (k·G).x mod n` and
`s = k^-1 (z + r·d) mod n`. With SHA-384 and the 384-bit `n`, `z` is the
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
X‖Y (96 bytes), `hash` the 48-byte digest, `r`/`s` the signature
integers. Requires `r, s ∈ [1, n-1]` and the public point on the curve,
then accepts iff `r ≡ (u1·G + u2·Q).x (mod n)` for `u1 = z·s^-1 mod n`,
`u2 = r·s^-1 mod n`. -/
def ecdsaVerify (pub hash : ByteArray) (r s : Nat) : Bool :=
  if pub.size != 2 * coordLen || hash.size != coordLen then false
  else
    let qx := bytesToNatBE (pub.extract 0 coordLen)
    let qy := bytesToNatBE (pub.extract coordLen (2 * coordLen))
    if !onCurve qx qy then false
    else if r == 0 || r ≥ n || s == 0 || s ≥ n then false
    else
      let w := inv s n
      let u1 := bytesToNatBE hash * w % n
      let u2 := r * w % n
      match add (smul u1 g) (smul u2 (some (qx, qy))) with
      | none => false
      | some (x, _) => x % n == r

/-- The RFC 6979 §A.2.6 P-384/SHA-384 "sample" and "test" vectors (the
RFC's private key, digests, and signatures; `k` recovered from them as
`s^-1 (z + r·d) mod n` and checked against `r`): key generation,
deterministic signing, verification of both, tamper rejection, and a
sign-then-verify round trip on unrelated inputs. -/
def selftest : Bool :=
  -- A malformed literal falls back to a 1-byte sentinel and breaks the
  -- length-sensitive checks instead of testing the empty string.
  let hx := fun s => (hexToBytes? s).getD (ByteArray.mk #[0])
  let d := 0x6b9d3dad2e1b8c1c05b19875b6659f4de23c3b667bf297ba9aa47740787137d896d5724e4c70a825f872c9ea60d2edf5
  let pub := hx ("ec3a4e415b4e19a4568618029f427fa5da9a8bc4ae92e02e06aae5286b300c64def8f0ea9055866064a254515480bc13" ++
                 "8015d9b72d7d57244ea8ef9ac0c621896708a59367f9dfb9f54ca84b3f1c9db1288b231c3ae0d4fe7344fd2533264720")
  -- "sample": SHA-384 of the message, the RFC's r and s, and the k they came from.
  let hSample := hx "9a9083505bc92276aec4be312696ef7bf3bf603f4bbd381196a029f340585312313bca4a9b5b890efee42c77b1ee25fe"
  let kSample := 0x94ed910d1a099dad3254e9242ae85abde4ba15168eaf0ca87a555fd56d10fbca2907e3e83ba95368623b8c4686915cf9
  let rSample := 0x94edbb92a5ecb8aad4736e56c691916b3f88140666ce9fa73d64c4ea95ad133c81a648152e44acf96e36dd1e80fabe46
  let sSample := 0x99ef4aeb15f178cea1fe40db2603138f130e740a19624526203b6351d0a3a94fa329c145786e679e7b82c71a38628ac8
  -- "test".
  let hTest := hx "768412320f7b0aa5812fce428dc4706b3cae50e02a64caa16a782249bfe8efc4b7ef1ccb126255d196047dfedf17a0a9"
  let kTest := 0x015ee46a5bf88773ed9123a5ab0807962d193719503c527b031b4c2d225092ada71f4a459bc0da98adb95837db8312ea
  let rTest := 0x8203b63d3c853e8d77227fb377bcf7b7b772e97892a80f36ab775d509d7a5feb0542a7f0812998da8f1dd3ca3cf023db
  let sTest := 0xddd0760448d42d8a43af45af836fce4de8be06b485e9b61b827c2f13173923e06a739f040649a667bf3b828246baa5a5
  (match pubKey? d with
   | some q => bytesToHex q == bytesToHex pub
   | none => false) &&
  ecdsaSign d kSample (bytesToNatBE hSample) == some (rSample, sSample) &&
  ecdsaSign d kTest (bytesToNatBE hTest) == some (rTest, sTest) &&
  ecdsaVerify pub hSample rSample sSample &&
  ecdsaVerify pub hTest rTest sTest &&
  !ecdsaVerify pub (hSample.set! 0 (hSample[0]! ^^^ 1)) rSample sSample &&
  !ecdsaVerify pub hSample sSample rSample &&
  !ecdsaVerify pub hTest rSample sSample &&
  -- Round trip on unrelated inputs: sign with fresh d/k, verify with
  -- the derived public key, reject a one-byte hash flip.
  (let d2 := 0x1b8e05f5ee0f8b25101f13b6dc3d514cbbbf6bc7e2b1c9f2f6a2e15c7a3d4e51a0b1c2d3e4f5061728394a5b6c7d8e9f
   let k2 := 0x7f1c6a9de4b8b0a4c2d9e3f1a0b5c6d7e8f90123456789abcdef0123456789010fedcba9876543210011223344556677
   let h2 := hx "6cd2f8a17f5b3e9d0c4a2b1e8f7d6c5b4a392817065f4e3d2c1b0a99887766554433221100ffeeddccbbaa9988776655"
   match ecdsaSign d2 k2 (bytesToNatBE h2), pubKey? d2 with
   | some (r2, s2), some q2 =>
     ecdsaVerify q2 h2 r2 s2 && !ecdsaVerify q2 (h2.set! 5 (h2[5]! ^^^ 0x40)) r2 s2
   | _, _ => false)

end Spec.P384
