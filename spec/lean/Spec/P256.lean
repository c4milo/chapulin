import Spec.Weierstrass

/-!
ECDSA over NIST P-256 (secp256r1), FIPS 186-4 §6 with the domain
parameters of FIPS 186-4 §D.1.2.3 (same values as SEC 2 v2 §2.4.2).

The arithmetic is `Spec/Weierstrass.lean` at these parameters: plain
`Nat` arithmetic with an explicit `% p` (or `% n`) after every
operation, affine `Option (Nat × Nat)` points with `none` for the point
at infinity, and Fermat inversion. Every public name here is that
module's definition applied to `curve`, so the theorems below are its
theorems at these constants; `decide` discharges the decidable facts
about them — `2 < p`, the discriminant, `G` on the curve, `p` below
`2^256`. What stays a hypothesis is what no tactic certifies: `p` and
`n` prime, and `n • G = 0`.

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

/-- The domain parameters as `Spec/Weierstrass.lean` takes them; a
coordinate or scalar is 32 bytes. -/
abbrev curve : Spec.Weierstrass.Curve :=
  { p := p, b := b, n := n, gx := gx, gy := gy, coordLen := 32 }

/-- The base point `G`. -/
def g : Point := some (gx, gy)

/-- Square-and-multiply `b^e mod m`, reducing after every multiplication
so intermediates never exceed `m^2`. -/
def powMod (b e m : Nat) : Nat := Spec.Weierstrass.powMod b e m

/-- Inversion mod a prime `m` by Fermat's little theorem: `x^(m-2) mod m`. -/
def inv (x m : Nat) : Nat := Spec.Weierstrass.inv x m

/-- Curve membership: reduced coordinates with
`y^2 ≡ x^3 + ax + b (mod p)`. With cofactor 1 this is the whole
public-key validation (SEC 1 v2 §3.2.2.1; the order check is redundant). -/
def onCurve (x y : Nat) : Bool := curve.onCurve x y

/-- Affine group law (SEC 1 v2 §2.2.1). -/
def add : Point → Point → Point := curve.add

/-- Scalar multiplication by double-and-add over the bits of `k`. -/
def smul (k : Nat) (pt : Point) : Point := curve.smul k pt

/-- Public key `Q = d·G` encoded as X‖Y, 32 bytes each big-endian
(SEC 1 v2 §2.3.3 uncompressed, without the 0x04 tag); `none` unless
`d ∈ [1, n-1]` (FIPS 186-4 §B.4). -/
def pubKey? (d : Nat) : Option ByteArray := curve.pubKey? d

/-- ECDSA signing (FIPS 186-4 §6.4) with `d`, `k`, and the
hash-as-integer `z` given explicitly: `r = (k·G).x mod n` and
`s = k^-1 (z + r·d) mod n`. With SHA-256 and the 256-bit `n`, `z` is the
whole digest, no truncation. `none` when `d` or `k` is outside
`[1, n-1]` or `r`/`s` degenerates to 0. -/
def ecdsaSign (d k z : Nat) : Option (Nat × Nat) := curve.ecdsaSign d k z

/-- ECDSA verification (FIPS 186-4 §6.4 / SEC 1 v2 §4.1.4): `pub` is
X‖Y (64 bytes), `hash` the 32-byte digest, `r`/`s` the signature
integers. Requires `r, s ∈ [1, n-1]` and the public point on the curve,
then accepts iff `r ≡ (u1·G + u2·Q).x (mod n)` for `u1 = z·s^-1 mod n`,
`u2 = r·s^-1 mod n`. -/
def ecdsaVerify (pub hash : ByteArray) (r s : Nat) : Bool :=
  curve.ecdsaVerify pub hash r s

/-! ## Proven properties

The decidable facts about the constants, checked by the kernel. -/

/-- The hypothesis every `Spec/Weierstrass.lean` theorem about the curve
takes: it makes the reduced `p - 3` cast to `-3`. -/
private theorem two_lt_p : 2 < p := by decide

/-- The curve is nonsingular: `4a^3 + 27b^2 ≢ 0 (mod p)` (SEC 1 v2
§3.1.1.2.1). -/
private theorem discriminant_ne_zero : (4 * a ^ 3 + 27 * b ^ 2) % p ≠ 0 := by decide

/-- The base point is on the curve (SEC 1 v2 §3.1.1.2.1). -/
private theorem g_onCurve : onCurve gx gy = true := by decide

-- `+kernel`: the elaborator refuses to fold an exponent above 256 and
-- warns; the kernel folds it. Stated through `curve` so the use site
-- unifies without folding it again. P-256's exponent is exactly 256;
-- the form matches P-384's so the two files differ only in their
-- constants.
private theorem p_lt_two_pow : curve.p < 2 ^ (8 * curve.coordLen) := by decide +kernel

/-- `powMod` is modular exponentiation, with no hypothesis on `m`. -/
theorem powMod_eq (b e m : Nat) : powMod b e m = b ^ e % m :=
  Spec.Weierstrass.powMod_eq b e m

/-- Fermat inversion inverts: for a prime `m` and `x` not a multiple of
`m`, `x * inv x m ≡ 1 (mod m)`. -/
theorem inv_mul {x m : Nat} [Fact m.Prime] (h_nonzero : x % m ≠ 0) : x * inv x m % m = 1 :=
  Spec.Weierstrass.inv_mul h_nonzero

/-- Membership is Mathlib's Weierstrass equation on the reduced
coordinates, for the curve `curve.weierstrass` with `a₄ = -3`, `a₆ = b`. -/
theorem onCurve_iff [Fact p.Prime] {x y : Nat} (h_x_lt : x < p) (h_y_lt : y < p) :
    onCurve x y = true ↔ curve.weierstrass.Equation x y :=
  curve.onCurve_iff two_lt_p h_x_lt h_y_lt

/-- `add` computes Mathlib's group law on points read through `ofPoint`,
the point at infinity included (SEC 1 v2 §2.2.1). -/
theorem add_ofPoint [Fact p.Prime] (P Q : curve.weierstrass.Point) :
    add (curve.ofPoint P) (curve.ofPoint Q) = curve.ofPoint (P + Q) :=
  curve.add_ofPoint two_lt_p P Q

/-- Closure: the sum of two points on the curve is on the curve, whenever
the sum is affine. -/
theorem onCurve_add [Fact p.Prime] {x₁ y₁ x₂ y₂ x₃ y₃ : Nat} (h_on₁ : onCurve x₁ y₁ = true)
    (h_on₂ : onCurve x₂ y₂ = true) (h_sum : add (some (x₁, y₁)) (some (x₂, y₂)) = some (x₃, y₃)) :
    onCurve x₃ y₃ = true :=
  curve.onCurve_add two_lt_p discriminant_ne_zero h_on₁ h_on₂ h_sum

/-- `smul` computes Mathlib's `nsmul`. -/
theorem smul_ofPoint [Fact p.Prime] (k : Nat) (P : curve.weierstrass.Point) :
    smul k (curve.ofPoint P) = curve.ofPoint (k • P) :=
  curve.smul_ofPoint two_lt_p k P

/-- The base point `G` as a Mathlib point. -/
def basePoint [Fact p.Prime] : curve.weierstrass.Point :=
  curve.basePoint two_lt_p discriminant_ne_zero g_onCurve

/-- Sign-then-verify round trip (FIPS 186-4 §6.4): a signature
`ecdsaSign` mints for `d` verifies under `pubKey? d`. `n` prime and
`n • G = 0` are the group facts the algorithm requires, taken as
hypotheses. This is completeness — the oracle's signatures are ones the
C must accept — not soundness of the verifier. -/
theorem ecdsaVerify_ecdsaSign [Fact p.Prime] [Fact n.Prime] (h_order : n • basePoint = 0)
    {d k r s : Nat} {pub hash : ByteArray}
    (h_sign : ecdsaSign d k (bytesToNatBE hash) = some (r, s)) (h_pub : pubKey? d = some pub)
    (h_hash : hash.size = 32) : ecdsaVerify pub hash r s = true :=
  curve.ecdsaVerify_ecdsaSign two_lt_p discriminant_ne_zero g_onCurve p_lt_two_pow h_order
    h_sign h_pub h_hash

set_option compiler.extract_closed false in
/-- The RFC 6979 §A.2.5 P-256/SHA-256 "sample" vector (deterministic
`k`; signature independently checked against openssl): key generation,
signing, verification, tamper rejection, and a sign-then-verify round
trip on unrelated inputs. -/
def selftest (_ : Unit) : Bool :=
  -- A malformed literal falls back to a 1-byte sentinel and breaks the
  -- length-sensitive checks instead of testing the empty string.
  let hx := fun s => (hexToBytes? s).getD (ByteArray.mk #[0])
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
