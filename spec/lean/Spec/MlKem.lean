import Spec.Bytes
import Spec.Sha3

/-!
ML-KEM-768, written from FIPS 203 (Module-Lattice-Based Key-Encapsulation
Mechanism Standard) only.

This is the differential oracle for the C ML-KEM port: it computes
byte-identical ML-KEM-768 output. Definitional style throughout —
coefficients are plain `Nat` reduced mod `q = 3329`, a polynomial is an
`Array Nat` of length 256, and a vector is an `Array` of three
polynomials. The no-division rule of the C build does not apply here; the
spec uses `Nat` `%` and `/` freely, as FIPS 203 §2.3 permits for a
reference description.

Parameter set (FIPS 203 §8, Table 2, ML-KEM-768): `k = 3`, `q = 3329`,
`n = 256`, `eta1 = eta2 = 2`, `du = 10`, `dv = 4`. Key sizes: encapsulation
key 1184 bytes, decapsulation key 2400 bytes, ciphertext 1088 bytes,
shared secret 32 bytes.

The hash and XOF functions are FIPS 203 §4.1: G = SHA3-512, H = SHA3-256,
J = SHAKE256 (32-byte output), XOF = SHAKE128, PRF = SHAKE256. They come
from `Spec.Sha3` as one-shots.
-/

namespace Spec.MlKem
open Spec.Bytes
open Spec.Sha3

/-- FIPS 203 §8, Table 2: the field modulus `q = 3329`. -/
def q : Nat := 3329

/-- FIPS 203 §8, Table 2: the module rank `k = 3` for ML-KEM-768. -/
def k : Nat := 3

/-- FIPS 203 §8, Table 2: the CBD parameter `eta1 = 2` (secret and error
noise in key generation). -/
def eta1 : Nat := 2

/-- FIPS 203 §8, Table 2: the CBD parameter `eta2 = 2` (error noise in
encryption). -/
def eta2 : Nat := 2

/-- FIPS 203 §8, Table 2: the ciphertext compression parameter `du = 10`. -/
def du : Nat := 10

/-- FIPS 203 §8, Table 2: the ciphertext compression parameter `dv = 4`. -/
def dv : Nat := 4

/-- The SHAKE128 output length, in bytes, that `sampleNTT` draws from for
rejection sampling. FIPS 203 §4.2.2 squeezes the XOF lazily; a spec draws
a fixed prefix instead. `168 * 12 = 2016` bytes is 672 three-byte chunks,
each yielding up to two candidates accepted with probability `q/4096`, so
the expected yield is about 1092 coefficients against the 256 needed —
the probability of drawing too few is negligible, and the prefix is
identical to the reference's lazy stream. -/
def xofLen : Nat := 168 * 12

/-- FIPS 203 §4.3, Appendix A: the NTT twiddle factors
`zeta^BitRev7(i) mod q` for `i = 0..127`, with `zeta = 17`. Index 0 is
unused by the transform (its value 1 is `17^0`). Verified by recomputation
against `17^BitRev7(i) mod 3329`. -/
def ZETAS : Array Nat := #[
  1, 1729, 2580, 3289, 2642, 630, 1897, 848,
  1062, 1919, 193, 797, 2786, 3260, 569, 1746,
  296, 2447, 1339, 1476, 3046, 56, 2240, 1333,
  1426, 2094, 535, 2882, 2393, 2879, 1974, 821,
  289, 331, 3253, 1756, 1197, 2304, 2277, 2055,
  650, 1977, 2513, 632, 2865, 33, 1320, 1915,
  2319, 1435, 807, 452, 1438, 2868, 1534, 2402,
  2647, 2617, 1481, 648, 2474, 3110, 1227, 910,
  17, 2761, 583, 2649, 1637, 723, 2288, 1100,
  1409, 2662, 3281, 233, 756, 2156, 3015, 3050,
  1703, 1651, 2789, 1789, 1847, 952, 1461, 2687,
  939, 2308, 2437, 2388, 733, 2337, 268, 641,
  1584, 2298, 2037, 3220, 375, 2549, 2090, 1645,
  1063, 319, 2773, 757, 2099, 561, 2466, 2594,
  2804, 1092, 403, 1026, 1143, 2150, 2775, 886,
  1722, 1212, 1874, 1029, 2110, 2935, 885, 2154]

/-- FIPS 203 §4.3.1, Appendix A: the base-case multiplication factors
`zeta^(2*BitRev7(i)+1) mod q` for `i = 0..127`, used by `MultiplyNTTs` to
multiply the degree-1 residues modulo `X^2 - zeta^(2*BitRev7(i)+1)`.
Verified by recomputation against `17^(2*BitRev7(i)+1) mod 3329`. -/
def GAMMAS : Array Nat := #[
  17, 3312, 2761, 568, 583, 2746, 2649, 680,
  1637, 1692, 723, 2606, 2288, 1041, 1100, 2229,
  1409, 1920, 2662, 667, 3281, 48, 233, 3096,
  756, 2573, 2156, 1173, 3015, 314, 3050, 279,
  1703, 1626, 1651, 1678, 2789, 540, 1789, 1540,
  1847, 1482, 952, 2377, 1461, 1868, 2687, 642,
  939, 2390, 2308, 1021, 2437, 892, 2388, 941,
  733, 2596, 2337, 992, 268, 3061, 641, 2688,
  1584, 1745, 2298, 1031, 2037, 1292, 3220, 109,
  375, 2954, 2549, 780, 2090, 1239, 1645, 1684,
  1063, 2266, 319, 3010, 2773, 556, 757, 2572,
  2099, 1230, 561, 2768, 2466, 863, 2594, 735,
  2804, 525, 1092, 2237, 403, 2926, 1026, 2303,
  1143, 2186, 2150, 1179, 2775, 554, 886, 2443,
  1722, 1607, 1212, 2117, 1874, 1455, 1029, 2300,
  2110, 1219, 2935, 394, 885, 2444, 2154, 1175]

/-! ## Compression and encoding (FIPS 203 §4.2.1) -/

/-- FIPS 203 §4.2.1, Equation (4.7): `Compress_d(x) = round((2^d/q)*x) mod
2^d`, with round-half-up. Written as
`floor((2^(d+1)*x + q) / (2q)) mod 2^d` over `Nat`; ties occur only at
`x = 0`, which rounds to 0 under any convention. -/
def compress (d x : Nat) : Nat := ((x <<< (d + 1)) + q) / (2 * q) % 2 ^ d

/-- FIPS 203 §4.2.1, Equation (4.8): `Decompress_d(y) = round((q/2^d)*y)`,
round-half-up. Written as `floor((2*q*y + 2^d) / 2^(d+1))` over `Nat`. -/
def decompress (d y : Nat) : Nat := (2 * q * y + 2 ^ d) / 2 ^ (d + 1)

/-- FIPS 203 §4.2.1: bit `idx % d` of coefficient `idx / d` of `F`, taken
after reducing that coefficient modulo `m`. This is one bit of the
concatenated bit stream `ByteEncode_d` packs, LSB first. -/
def encBit (F : Array Nat) (m d idx : Nat) : Nat :=
  ((F[idx / d]! % m) >>> (idx % d)) % 2

/-- FIPS 203 §4.2.1: byte `i` of `ByteEncode_d`'s output — the eight bits
`8*i .. 8*i+7` of the stream, packed LSB first. -/
def encByte (F : Array Nat) (m d i : Nat) : UInt8 :=
  UInt8.ofNat ((List.range 8).foldl (fun acc j => acc + encBit F m d (8 * i + j) * 2 ^ j) 0)

/-- FIPS 203 §4.2.1, Algorithm 5 (ByteEncode_d): serialize a 256-coefficient
polynomial `F` as `32*d` bytes. Each coefficient contributes `d` bits, LSB
first; the reduction modulus is `2^d` for `d < 12` and `q` for `d = 12`.
Built with `Array.ofFn` so the output length is `32*d` by construction. -/
def byteEncode (F : Array Nat) (d : Nat) : ByteArray :=
  let m := if d < 12 then 2 ^ d else q
  ByteArray.mk (Array.ofFn (n := 32 * d) fun i => encByte F m d i.val)

/-- FIPS 203 §4.2.1: bit `idx` of byte string `B`, read LSB first — the
inverse indexing of `encBit`. -/
def decBit (B : ByteArray) (idx : Nat) : Nat := (B[idx / 8]!.toNat >>> (idx % 8)) % 2

/-- FIPS 203 §4.2.1, Algorithm 6 (ByteDecode_d): parse `32*d` bytes back
into a 256-coefficient polynomial. Coefficient `i` reads bits
`i*d .. i*d+d-1` LSB first and reduces modulo `2^d` (`d < 12`) or `q`
(`d = 12`). -/
def byteDecode (B : ByteArray) (d : Nat) : Array Nat :=
  let m := if d < 12 then 2 ^ d else q
  Array.ofFn (n := 256) fun i =>
    ((List.range d).foldl (fun acc j => acc + decBit B (i.val * d + j) * 2 ^ j) 0) % m

/-- Apply `Compress_d` to every coefficient of a polynomial. -/
def polyCompress (d : Nat) (p : Array Nat) : Array Nat := p.map (compress d)

/-- Apply `Decompress_d` to every coefficient of a polynomial. -/
def polyDecompress (d : Nat) (p : Array Nat) : Array Nat := p.map (decompress d)

/-- Concatenate `ByteEncode_d` of the three polynomials of a rank-3 vector.
The output length is `3 * 32 * d` bytes. -/
def encode3 (v : Array (Array Nat)) (d : Nat) : ByteArray :=
  byteEncode v[0]! d ++ byteEncode v[1]! d ++ byteEncode v[2]! d

/-! ## Polynomial arithmetic mod q -/

/-- Coefficient-wise sum of two polynomials, reduced mod `q`. -/
def polyAdd (a b : Array Nat) : Array Nat :=
  Array.ofFn (n := 256) fun i => (a[i.val]! + b[i.val]!) % q

/-- Coefficient-wise difference of two polynomials, reduced mod `q` (both
inputs are already reduced, so `+ q -` avoids `Nat` underflow). -/
def polySub (a b : Array Nat) : Array Nat :=
  Array.ofFn (n := 256) fun i => (a[i.val]! + q - b[i.val]!) % q

/-! ## NTT (FIPS 203 §4.3) -/

/-- FIPS 203 §4.3, Algorithm 9 (NTT): the forward number-theoretic
transform. Seven layers of decimation with `len` halving from 128 to 2;
the twiddle index runs 1..127 across all butterfly groups. -/
def ntt (f : Array Nat) : Array Nat := Id.run do
  let mut fh := f
  let mut zi := 1
  for lenExp in [0:7] do
    let length := 128 >>> lenExp
    for g in [0 : 128 / length] do
      let start := g * (2 * length)
      let z := ZETAS[zi]!
      zi := zi + 1
      for jj in [start : start + length] do
        let t := (z * fh[jj + length]!) % q
        fh := fh.set! (jj + length) ((fh[jj]! + q - t) % q)
        fh := fh.set! jj ((fh[jj]! + t) % q)
  return fh

/-- FIPS 203 §4.3, Algorithm 10 (NTT^{-1}): the inverse transform. `len`
doubles from 2 to 128, the twiddle index runs 127..1, and a final scaling
by `128^{-1} = 3303 mod q` completes the inversion. -/
def invNtt (f : Array Nat) : Array Nat := Id.run do
  let mut fh := f
  let mut zi := 127
  for lenExp in [0:7] do
    let length := 2 <<< lenExp
    for g in [0 : 128 / length] do
      let start := g * (2 * length)
      let z := ZETAS[zi]!
      zi := zi - 1
      for jj in [start : start + length] do
        let t := fh[jj]!
        fh := fh.set! jj ((t + fh[jj + length]!) % q)
        fh := fh.set! (jj + length) ((z * (fh[jj + length]! + q - t)) % q)
  return fh.map (fun x => (x * 3303) % q)

/-- FIPS 203 §4.3.1, Algorithm 11 (MultiplyNTTs) with Algorithm 12
(BaseCaseMultiply): multiply two NTT-domain polynomials as 128 products of
degree-1 residues, each modulo `X^2 - GAMMAS[i]`. -/
def mulNtt (a b : Array Nat) : Array Nat := Id.run do
  let mut c := Array.replicate 256 0
  for i in [0:128] do
    let a0 := a[2 * i]!
    let a1 := a[2 * i + 1]!
    let b0 := b[2 * i]!
    let b1 := b[2 * i + 1]!
    let g := GAMMAS[i]!
    c := c.set! (2 * i) ((a0 * b0 + a1 * b1 * g) % q)
    c := c.set! (2 * i + 1) ((a0 * b1 + a1 * b0) % q)
  return c

/-! ## Sampling (FIPS 203 §4.2.2) -/

/-- FIPS 203 §4.2.2, Algorithm 7 (SampleNTT), rejection loop: read the byte
stream three at a time, form two 12-bit candidates, and keep those below
`q` until 256 coefficients are filled. -/
def rejSample (stream : ByteArray) : Array Nat := Id.run do
  let mut a := Array.replicate 256 0
  let mut j := 0
  let mut pos := 0
  for _ in [0 : stream.size / 3] do
    let c0 := stream[pos]!.toNat
    let c1 := stream[pos + 1]!.toNat
    let c2 := stream[pos + 2]!.toNat
    pos := pos + 3
    let d1 := c0 + 256 * (c1 % 16)
    let d2 := c1 / 16 + 16 * c2
    if d1 < q ∧ j < 256 then
      a := a.set! j d1
      j := j + 1
    if d2 < q ∧ j < 256 then
      a := a.set! j d2
      j := j + 1
  return a

/-- FIPS 203 §4.2.2, Algorithm 7 (SampleNTT): sample a uniform NTT-domain
polynomial from `rho` and two index bytes, via XOF = SHAKE128. -/
def sampleNTT (rho : ByteArray) (b0 b1 : Nat) : Array Nat :=
  rejSample (shake128 (rho ++ ByteArray.mk #[UInt8.ofNat b0, UInt8.ofNat b1]) xofLen)

/-- FIPS 203 §4.2.2, Algorithm 8 (SamplePolyCBD_eta): the centered binomial
distribution. Coefficient `i` is the difference of two `eta`-bit population
counts read from the PRF output stream, reduced mod `q`. -/
def samplePolyCBD (eta : Nat) (B : ByteArray) : Array Nat :=
  Array.ofFn (n := 256) fun i =>
    let x := (List.range eta).foldl (fun acc jj => acc + decBit B (2 * i.val * eta + jj)) 0
    let y := (List.range eta).foldl (fun acc jj => acc + decBit B (2 * i.val * eta + eta + jj)) 0
    (x + q - y) % q

/-- FIPS 203 §4.1: PRF_eta(s, b) = SHAKE256(s ‖ b, 64*eta). -/
def prf (eta : Nat) (s : ByteArray) (b : Nat) : ByteArray :=
  shake256 (s ++ ByteArray.mk #[UInt8.ofNat b]) (64 * eta)

/-! ## Hashes (FIPS 203 §4.1) -/

/-- FIPS 203 §4.1: G = SHA3-512, split into two 32-byte halves. -/
def hashG (b : ByteArray) : ByteArray × ByteArray :=
  let h := sha3_512 b
  (h.extract 0 32, h.extract 32 64)

/-- FIPS 203 §4.1: H = SHA3-256. -/
def hashH (b : ByteArray) : ByteArray := sha3_256 b

/-- FIPS 203 §4.1: J = SHAKE256 with 32-byte output. -/
def hashJ (b : ByteArray) : ByteArray := shake256 b 32

/-! ## K-PKE (FIPS 203 §5) -/

/-- FIPS 203 §5.1, Algorithm 13 (K-PKE.KeyGen): derive `(rho, sigma)` from
`d`, sample the matrix `A` (with `A[i][j]` from XOF over `rho ‖ j ‖ i`),
the secret `s` and error `e`, and form `t = A s + e` in the NTT domain.
Returns `(ek_PKE, dk_PKE)` where `ek_PKE = ByteEncode_12(t) ‖ rho` and
`dk_PKE = ByteEncode_12(s)`. -/
def pkeKeygen (d : ByteArray) : ByteArray × ByteArray :=
  let rs := hashG (d ++ ByteArray.mk #[UInt8.ofNat k])
  let rho := rs.1
  let sigma := rs.2
  let s := Array.ofFn (n := 3) fun i => ntt (samplePolyCBD eta1 (prf eta1 sigma i.val))
  let e := Array.ofFn (n := 3) fun i => ntt (samplePolyCBD eta1 (prf eta1 sigma (3 + i.val)))
  let th := Array.ofFn (n := 3) fun i =>
    polyAdd e[i.val]!
      ((List.range 3).foldl
        (fun acc j => polyAdd acc (mulNtt (sampleNTT rho j i.val) s[j]!))
        (Array.replicate 256 0))
  (encode3 th 12 ++ rho, encode3 s 12)

/-- FIPS 203 §5.2, Algorithm 14 (K-PKE.Encrypt): decode `t` and `rho` from
`ek`, regenerate the transposed matrix (`A^T[i][j]` from XOF over
`rho ‖ i ‖ j`), sample `y`, `e1`, `e2` from `r`, and form
`u = NTT^{-1}(A^T y) + e1` and `v = NTT^{-1}(t^T y) + e2 + Decompress_1(m)`.
Returns `ByteEncode_du(Compress_du(u)) ‖ ByteEncode_dv(Compress_dv(v))`. -/
def pkeEncrypt (ek m r : ByteArray) : ByteArray :=
  let th := Array.ofFn (n := 3) fun i => byteDecode (ek.extract (384 * i.val) (384 * i.val + 384)) 12
  let rho := ek.extract (384 * 3) (384 * 3 + 32)
  let y := Array.ofFn (n := 3) fun i => ntt (samplePolyCBD eta1 (prf eta1 r i.val))
  let e1 := Array.ofFn (n := 3) fun i => samplePolyCBD eta2 (prf eta2 r (3 + i.val))
  let e2 := samplePolyCBD eta2 (prf eta2 r 6)
  let u := Array.ofFn (n := 3) fun i =>
    polyAdd
      (invNtt ((List.range 3).foldl
        (fun acc j => polyAdd acc (mulNtt (sampleNTT rho i.val j) y[j]!))
        (Array.replicate 256 0)))
      e1[i.val]!
  let mu := polyDecompress 1 (byteDecode m 1)
  let vacc := (List.range 3).foldl
    (fun acc i => polyAdd acc (mulNtt th[i]! y[i]!)) (Array.replicate 256 0)
  let v := polyAdd (polyAdd (invNtt vacc) e2) mu
  encode3 (u.map (polyCompress du)) du ++ byteEncode (polyCompress dv v) dv

/-- FIPS 203 §5.3, Algorithm 15 (K-PKE.Decrypt): decode and decompress
`u` and `v` from the ciphertext, decode `s` from `dk`, and recover the
message `m = ByteEncode_1(Compress_1(v - NTT^{-1}(s^T NTT(u))))`. -/
def pkeDecrypt (dk c : ByteArray) : ByteArray :=
  let u := Array.ofFn (n := 3) fun i =>
    polyDecompress du (byteDecode (c.extract (320 * i.val) (320 * i.val + 320)) du)
  let v := polyDecompress dv (byteDecode (c.extract (320 * 3) (320 * 3 + 128)) dv)
  let s := Array.ofFn (n := 3) fun i => byteDecode (dk.extract (384 * i.val) (384 * i.val + 384)) 12
  let w := polySub v
    (invNtt ((List.range 3).foldl
      (fun acc i => polyAdd acc (mulNtt s[i]! (ntt u[i]!))) (Array.replicate 256 0)))
  byteEncode (polyCompress 1 w) 1

/-! ## ML-KEM (FIPS 203 §6) -/

/-- FIPS 203 §6.1, Algorithm 16 (ML-KEM.KeyGen_internal): the encapsulation
key is `ek_PKE`; the decapsulation key bundles
`dk_PKE ‖ ek ‖ H(ek) ‖ z`. -/
def keygen (d z : ByteArray) : ByteArray × ByteArray :=
  let kp := pkeKeygen d
  (kp.1, kp.2 ++ kp.1 ++ hashH kp.1 ++ z)

/-- FIPS 203 §6.2, Algorithm 17 (ML-KEM.Encaps_internal): derive
`(K, r) = G(m ‖ H(ek))`, encrypt `m` under randomness `r`, and return the
ciphertext paired with the shared secret `K`. -/
def encapsInternal (ek m : ByteArray) : ByteArray × ByteArray :=
  let kr := hashG (m ++ hashH ek)
  (pkeEncrypt ek m kr.2, kr.1)

/-- FIPS 203 §6.3, Algorithm 18 (ML-KEM.Decaps_internal): decrypt to `m'`,
re-derive `(K', r')`, re-encrypt, and return `K'` when the re-encryption
reproduces the ciphertext, otherwise the implicit-reject secret
`J(z ‖ c)`. -/
def decapsInternal (dk c : ByteArray) : ByteArray :=
  let dkPke := dk.extract 0 1152
  let ekPke := dk.extract 1152 2336
  let h := dk.extract 2336 2368
  let z := dk.extract 2368 2400
  let m' := pkeDecrypt dkPke c
  let kr := hashG (m' ++ h)
  let kbar := hashJ (z ++ c)
  let c' := pkeEncrypt ekPke m' kr.2
  if bytesToHex c == bytesToHex c' then kr.1 else kbar

/-- FIPS 203 §7.2, Algorithm 20 (ML-KEM.Encaps) input validation: `ek` has
the right length and each of its three encoded polynomials survives a
`ByteDecode_12`/`ByteEncode_12` round trip, i.e. every 12-bit value is
below `q`. -/
def modulusOk (ek : ByteArray) : Bool :=
  ek.size == 1184 &&
    (List.range 3).all fun i =>
      bytesToHex (byteEncode (byteDecode (ek.extract (384 * i) (384 * i + 384)) 12) 12)
        == bytesToHex (ek.extract (384 * i) (384 * i + 384))

/-- ML-KEM-768 encapsulation (FIPS 203 §7.2): `none` when `ek` fails the
modulus check, otherwise `some (ciphertext, shared secret)` with a
1088-byte ciphertext and 32-byte secret. -/
def encaps (ek m : ByteArray) : Option (ByteArray × ByteArray) :=
  if modulusOk ek then some (encapsInternal ek m) else none

/-- ML-KEM-768 decapsulation (FIPS 203 §7.3): the 32-byte shared secret,
with implicit reject built in. -/
def decaps (dk ct : ByteArray) : ByteArray := decapsInternal dk ct

/-! ## Size theorems

The output-length proofs rest on the ByteEncode boundary: `byteEncode F d`
is `32*d` bytes whatever the coefficients, because it is built with
`Array.ofFn (n := 32*d)`. Every ciphertext and key length then follows
from the encode steps and the fixed hash lengths, never from the NTT or
sampling internals. -/

/-- `ByteEncode_d` always emits `32*d` bytes (FIPS 203 §4.2.1). -/
theorem byteEncode_size (F : Array Nat) (d : Nat) : (byteEncode F d).size = 32 * d := by
  simp [byteEncode, ByteArray.size, Array.size_ofFn]

/-- Encoding a rank-3 vector emits `96*d` bytes. -/
theorem encode3_size (v : Array (Array Nat)) (d : Nat) : (encode3 v d).size = 96 * d := by
  simp only [encode3, ByteArray.size_append, byteEncode_size]
  omega

private theorem hashH_size (b : ByteArray) : (hashH b).size = 32 := sha3_256_size b

private theorem hashG_fst_size (x : ByteArray) : (hashG x).1.size = 32 := by
  simp only [hashG]
  rw [ByteArray.size_extract, sha3_512_size]; omega

private theorem hashJ_size (x : ByteArray) : (hashJ x).size = 32 := shake256_size x 32

private theorem pkeKeygen_fst_size (d : ByteArray) : (pkeKeygen d).1.size = 1184 := by
  simp only [pkeKeygen, hashG, ByteArray.size_append, encode3_size, ByteArray.size_extract,
    sha3_512_size]
  omega

private theorem pkeKeygen_snd_size (d : ByteArray) : (pkeKeygen d).2.size = 1152 := by
  simp only [pkeKeygen, encode3_size]

private theorem pkeEncrypt_size (ek m r : ByteArray) : (pkeEncrypt ek m r).size = 1088 := by
  simp only [pkeEncrypt, ByteArray.size_append, encode3_size, byteEncode_size, du, dv]

/-- The encapsulation key is always 1184 bytes (FIPS 203 §6.1). -/
theorem keygen_ek_size (d z : ByteArray) : (keygen d z).1.size = 1184 := by
  simp only [keygen]
  exact pkeKeygen_fst_size d

/-- The decapsulation key is always 2400 bytes given a 32-byte `z`
(FIPS 203 §6.1). -/
theorem keygen_dk_size (d z : ByteArray) (hz : z.size = 32) : (keygen d z).2.size = 2400 := by
  simp only [keygen, ByteArray.size_append]
  rw [pkeKeygen_snd_size, pkeKeygen_fst_size, hashH_size, hz]

/-- A ciphertext returned by `encaps` is always 1088 bytes (FIPS 203 §6.2). -/
theorem encaps_ct_size (ek m ct ss : ByteArray) (h : encaps ek m = some (ct, ss)) :
    ct.size = 1088 := by
  simp only [encaps] at h
  split at h
  · have he : encapsInternal ek m = (ct, ss) := Option.some.inj h
    have hct : ct = (encapsInternal ek m).1 := by rw [he]
    rw [hct]
    simp only [encapsInternal]
    exact pkeEncrypt_size ek m _
  · simp at h

/-- The shared secret from `decaps` is always 32 bytes, on both the normal
and the implicit-reject branch (FIPS 203 §6.3). -/
theorem decaps_size (dk ct : ByteArray) : (decaps dk ct).size = 32 := by
  simp only [decaps, decapsInternal]
  split
  · exact hashG_fst_size _
  · exact hashJ_size _

/-! ## Self-test

FIPS 203 has no small published vectors, so the self-test pins one full
known-answer vector generated by kyber-py (seed index 0 of the
differential's KAT set, test/gen_mlkem_vectors.py): the exact key,
ciphertext and shared secret bytes, plus one implicit-reject case with a
single flipped ciphertext byte.
-/

/-- The seed-0 known-answer vector and one implicit-reject case, checked
byte-for-byte. Returns `true` iff key generation, encapsulation, the honest
decapsulation and the reject decapsulation all reproduce the reference. -/
def selftest : Bool :=
  let d := "aeed86158e34d8e1f0a0b5eea10f6c10e8d5827ad42f444abb29c79510103184"
  let z := "e3ee0a22d4686b6c8cb995e25893cdf12a974dc71a3672a706118f53a813dec7"
  let m := "a877c13d2d9b9ce9cb3a5708c8912103f0b052869c2aaccc34ea8268ed16c0b7"
  let ctBad := "b08b39282e5a03ff2e7799ea53af55e83b982447f6838ff0ddbe4d5790fcb2dc835b53fa718c06057f73a9ef1681c0d1cf255aa38add2f3b5b3c814570ed2a04d306fb3bcce47cb2b0c017be1ce58aa27349ca05b7cb236b7987431335eb64e290e111c7c2975b3daac76ec2f2b99f7d7e49867b0ae44953c00c7648962b58ee801d670b0a2705ad3f8bd5fed955b0a03c696fdab2fc97deeedee444cd80fe6025b65aa6940c70c9162f21f651c038537ad5caeced6efb2536945556b15356585d28acc8235a54c6e3fe0414b6f5dc95e0798d69c8eb501bab7196c5f1a02819f2f145454c0465d6beadba554fe70d023b96c322ec83b5db015fe801336ff2c6ca7ecff627d282c79c25cfaa2bd5cd0faecfc3ddec74bb0f9755a08974a33bfae0dcb9298363fc9fbd5b51fd2c6eb26d781e7010736e5935d39e5e1c3c415bb1eb77f63ee780b6a9e0b9ee2c3aee7f58388e564d4f2c235009d4d9ddbeb7b0dba86dd6863379e9ce639b7ca6c4ece99febc15e86b8d1dc6d18f7717e01dac12e01d14269930616af0819b5fe87b021da196f9543e3d0a0b0c9c699d83ac7b0cc3663cff513b8966b2a8d1c577147871a2b20a8404ab58d01cca84f6bb0dbc73fcca1501420808205081997ec2c6d2b5a3563133507ac1427edfc4bef24e7eef75f96115a2a4c14e2c670f13c31d7a3e0fa67b39e8c3724529e78608580b78919a2a9e4c55f3b810d5c7c47ef78d112d3736dae653d6357d0b144b1bdb437b6f4e58af2a0b8bd8eaf3eeaa30c1445792565c778cf0e853326a56b0c780e60b581d361428c180b4b87dea416c370d8da1b4ed7c8b928c8ac8ce48208a65b12b753551b2d47d665e207ee5f14cc19f1c43307d2962c33f0f8984afd419bd1c0354c7b344c53eb26fb40d12da0353e1bd3f6e0e3a1b6b9b0acf872f89080f7c879d1651e139b52f98edc97a0288c77b138db89c25a6ba3cfadf5bccff7224b57b2a9dc3c12572091fd99116880017e936d9210182f48ad7cf34badfbee65e5bddf27040721cddb4e53768b4bc1c7fa493aca5a2e29c5f8ef8308cf9e8ae317fd34357c8dfc0b4812cfa768afa326cff2e70deb0bcdaca45dbf554584f743236937b97f3592437cbdf79202f3bb3cd4f542b19dcfc4756ce840dc0686ed067a842ab4866e960d6ea13edeee36780b3a827dbdfbb0eb088fe3ca01816d827dfe1999f26ac45e8475610e788b6dab7f9bcf37ba539e3268a1d8e1fb9e7af4ae5b25c76c91117eebbeef61dd55b223287e729d0dc95148db8e9c3e7924de0d029efe1fa4e568c8afb7baea8142965500afb323742049e4661054a60ef817084ca8e28e7003bbd0d86142ce9ea6dc7ea0c2c6e5d9c87e600bd2f0ae2ce8237c5f6a4e0643a22f1a546f4afdf277bb092279e8782830ef1b53330044207133d84045354d15a44823ba9d374ddd2846a2c34f467b5d780016fb0e98a79cb758571fbc977cad3f69886c8ebd449d4df49e589421bc22c00e3e64d418c225be0e6e239ded60fc"
  let ekWant := "d0a7c53fa0a9c5137554f39f1708555172b13494856a295179356dc52a310ac4900f83bedb3098cb8b90cf2abf4326af669c477f5820a1464f6503cdbbbc4504e686919b53589615fc3c373e56665e53548ad2049830b224958116c6c962b74b58f9bd2e6650818b0e4ab061e207baa07c7ef4a778b46ac4f94ca63232cf96975183eacc332518329066f45652d7bb7871355376d4695c234fb0a54c4488619bba8cdddc380db33f8d78c179f823eeb4525355c648260ff322505183325165a392d64dfa68ad2f293be324286eb21c8dc6820f988da9963c34c60439328418023eb4fa830e0a936f62b1bd392bd7797e60e7601318c2e6632fcc7ccc1cd464e3f4aaa0f73fb6507472c0af1b6018a12806a120a7b40b6f74e5b542715e748020aff96c4d23c7b349528f20456002bc1b5a4179142d96ca28d5b3a08075831e4b3906881a53eb80534274be396621e518c0d5c96301309e15aed87414a7142c074b1ece998644a424c4e1c55a75b984862cceb42460d5b7084c6e7949a3986703cf258c79f81cad475ff506b22856183131a5d0d92461552fd8435334b35a76b558abc492e20b9e5728b534909a6d218d94b480ccd8c96bf081bdf5290e7602f38a0f534ca49ef16f10e44303c7686f8aaf5a6babdeeaa8b6c0925d3b8567c0636acb378420cf3968191b599c804880da7cc0f8312f77c80beee5837205933f8b3dba507847b79671073c9592229b173d14f8ca194c8e36a5a4a96c315f68a42b766527f3ad33747c5e7544c0d096e716616242ba64455d21138075bc4d8c87b3f3a162ac364f001da010d830ed27ae52b90d5ff920b88571fb280f1baa2032552db5aaafd810065d638e83362d40300ae9890cb8ec5c76c327cc794401a731c7c868e5205b31c00d2b5c856811b47e61876501b5984981d2b077a91565148789a32b44ed9b8d85e69638dc0be05129f2c417c7447a1f671b1782b39d3a8c2e9c39433abfe687b27ad9127454bbc540cb5522bf47236c4ebb6943bac6b631c3333a644d4920039129f625a1bc1019784674b2362aafd94e12507f96a702168988aa3385622741c0f8bebbb15583b6ad250564f37bad17f718b30c357215558526992c99273fd75837b082579a586a252d888a0895ec7c6e6554e28543ffec5feb4390cdac75f6bb4caa91a43482159bb5824099972ce7b830f73e998194ed52be73392381957fa69ac28f3447daf42994d8ba5a36c52f384587cb4ac834b64b0410042c48576c14ee30b639410c33d35d876a7ecb3acf80d0c7e281a783a54e96466521103b94e956f8f97e7ce93c70c531d3847ae813bc7547a76f88be6cb35e3c14b0d90174c46b36803244a5252cf1a2ae37f65629c153f8d99059a1150aa4813ca8425066777d1495d183881d644fb7248fb0f86459e185a04877e058126009b5bd29917317a5bd556d38094ce6f1c8b04cad82f13a78933bed7772f8e450cd2a400cf8569ef906ccfb88dfc4cf5fa15ecd28b342c41146a4891f0c4ce8a3b17bdb1edfdc181a163ed3a02222607e4020cdd6c229933570f2eacc8b66618d48b550971388021b2c72363a49a23d37cdab4ac1950cb3e3817c3aec40f357a6173b11632e7a3fb97e339036f0a96fa8ca031ae1f6943cf0e2d117574a774483"
  let dkWant := "f13b3be8e4b271b0a38bb17c21a66bf798c2db630e3248bea2a214ba1aa65227bfc2b89eb81cb974d6aaec4229ccc3cbf5365547e684208a7122dace97000dfcf969f13642d865283c9571fbec7049e1cc3c246aa0577683026923a534f7ca7495f52e402c9e11222a53e0301a1158b3fc85b1e5abff287558261a40f2b309f208b8c174c46416723354a847bee83159c42448e820c8bbc433eed9b887d193aeb8c3905575d9d596e182a8ee565072493f9833788bf62c29513c07b59fc1391dcc3c409fc15e877ba7cbd349f1290c0d9683b3507f8a5b51f1a7c138ec0699316dde462f9e9368614976c07bbcfe2585508c676565ae98d385f878c0e4e2abd1510b23e2b2d9b5c2e877021487cd12621799fb5b0817113742cc5063c9260c458bc4429a4054c72c59f334bc6858156bf53aa43b983ab659383b0ef1ba2f9ff80835d40aac957c71750daf7b24d4c32c8ff2b6034132dc3ac6c0abbef8dc2f6665adc21ba92de3197bf542132581fbb5a4d5c40c86ab003b2a5d4fa52ac4f742395b7e6aec88c56221cc66632e92888ac217ea3cab6e6449b00285854c68fb112a8990315dfb535094cf96da9ca5764f632456cc97b9c519a03df777d27ac8af57c27c178cfac1b009b800faa44e7ee07ad6e151ca57644e5b771b10754adacc72242eddd64c5e1401737b7e9fc1114be165427c6415cc51b4bc41d30611c759cc3f09682e1862db131169bc99d440b4a0b58c6b6c17abd96816c082f26cccfe83588ee4a5def3cc023c7c402159e34880a2e26f0957072ecb524d63c13a60832deb3da5f12761b632e640c7457b19ccc25c51c19c13d43754483169eca972a4626b6ccb6b4326eeb39e4248c59ed7585ae184f9d17adbe83f44106dc3408c1724c8444b111e047849c0a0eb7a0cce3681d37752cf00b3892a4c364411f36cc3cdb6549ac00d0d2063a91503656bb0d34299d8d74fa47709b195bc5896b6d3d3a9075b286338ae3267a5cb249727e61bf1d71584c4bd9b6b6594e27be76993112a06349a7be389480a43043ac9c7e1940ab08587e88c20c76241dd7a854a86794d1cb868f06179e55ca61120652c6d45e58764abb89efc9e60f312d59b27257b638ba081d47397d7cb76b8f3047df7ad8102ceaeca3ab006b9655c984a07a9cf5c70cb3c6a190b5be4e367e649a8ac184e9df65a9a547623932ffea009cfc1698dbb457e125678d3ac3681b3ba500a6a77825d7c122150c10ed984855939bf1741833a9793c835fbb4673f170ac80a4e6f88ad1af57b5716963409d04802affd00bdc68143d4b981439b5e5293cc3eb43c1fc4818bba63236c3c0f5b19580283176951943471931900566462f33920ce6a45d188b120f67766763411db694dac1a25398396c325170b2f161c110e5c6131260d04b503dd810563440dc1d3b2a6416439702e9b2bc4a4c00ddccc551689cf37cc7a1c061317f23ff55607e557024926c2409619cc2a0fff4c0b6c2a87e8c8b3cfd48f97d6a96b3b66038078bcea7450272360b9bf979cb3fbe45db9e9a5f1998318026a26a09f778a78c7944fdf69705297320e68151eb1740b10cfbc9630fc4819d167a89d025b7d4a74af1a64d0a7c53fa0a9c5137554f39f1708555172b13494856a295179356dc52a310ac4900f83bedb3098cb8b90cf2abf4326af669c477f5820a1464f6503cdbbbc4504e686919b53589615fc3c373e56665e53548ad2049830b224958116c6c962b74b58f9bd2e6650818b0e4ab061e207baa07c7ef4a778b46ac4f94ca63232cf96975183eacc332518329066f45652d7bb7871355376d4695c234fb0a54c4488619bba8cdddc380db33f8d78c179f823eeb4525355c648260ff322505183325165a392d64dfa68ad2f293be324286eb21c8dc6820f988da9963c34c60439328418023eb4fa830e0a936f62b1bd392bd7797e60e7601318c2e6632fcc7ccc1cd464e3f4aaa0f73fb6507472c0af1b6018a12806a120a7b40b6f74e5b542715e748020aff96c4d23c7b349528f20456002bc1b5a4179142d96ca28d5b3a08075831e4b3906881a53eb80534274be396621e518c0d5c96301309e15aed87414a7142c074b1ece998644a424c4e1c55a75b984862cceb42460d5b7084c6e7949a3986703cf258c79f81cad475ff506b22856183131a5d0d92461552fd8435334b35a76b558abc492e20b9e5728b534909a6d218d94b480ccd8c96bf081bdf5290e7602f38a0f534ca49ef16f10e44303c7686f8aaf5a6babdeeaa8b6c0925d3b8567c0636acb378420cf3968191b599c804880da7cc0f8312f77c80beee5837205933f8b3dba507847b79671073c9592229b173d14f8ca194c8e36a5a4a96c315f68a42b766527f3ad33747c5e7544c0d096e716616242ba64455d21138075bc4d8c87b3f3a162ac364f001da010d830ed27ae52b90d5ff920b88571fb280f1baa2032552db5aaafd810065d638e83362d40300ae9890cb8ec5c76c327cc794401a731c7c868e5205b31c00d2b5c856811b47e61876501b5984981d2b077a91565148789a32b44ed9b8d85e69638dc0be05129f2c417c7447a1f671b1782b39d3a8c2e9c39433abfe687b27ad9127454bbc540cb5522bf47236c4ebb6943bac6b631c3333a644d4920039129f625a1bc1019784674b2362aafd94e12507f96a702168988aa3385622741c0f8bebbb15583b6ad250564f37bad17f718b30c357215558526992c99273fd75837b082579a586a252d888a0895ec7c6e6554e28543ffec5feb4390cdac75f6bb4caa91a43482159bb5824099972ce7b830f73e998194ed52be73392381957fa69ac28f3447daf42994d8ba5a36c52f384587cb4ac834b64b0410042c48576c14ee30b639410c33d35d876a7ecb3acf80d0c7e281a783a54e96466521103b94e956f8f97e7ce93c70c531d3847ae813bc7547a76f88be6cb35e3c14b0d90174c46b36803244a5252cf1a2ae37f65629c153f8d99059a1150aa4813ca8425066777d1495d183881d644fb7248fb0f86459e185a04877e058126009b5bd29917317a5bd556d38094ce6f1c8b04cad82f13a78933bed7772f8e450cd2a400cf8569ef906ccfb88dfc4cf5fa15ecd28b342c41146a4891f0c4ce8a3b17bdb1edfdc181a163ed3a02222607e4020cdd6c229933570f2eacc8b66618d48b550971388021b2c72363a49a23d37cdab4ac1950cb3e3817c3aec40f357a6173b11632e7a3fb97e339036f0a96fa8ca031ae1f6943cf0e2d117574a7744837f70bb76f4fd7890c29191cd04f4fb60348a6f4c175e955763c8b1bceef4c5b6e3ee0a22d4686b6c8cb995e25893cdf12a974dc71a3672a706118f53a813dec7"
  let ctWant := "b08b39282e5b03ff2e7799ea53af55e83b982447f6838ff0ddbe4d5790fcb2dc835b53fa718c06057f73a9ef1681c0d1cf255aa38add2f3b5b3c814570ed2a04d306fb3bcce47cb2b0c017be1ce58aa27349ca05b7cb236b7987431335eb64e290e111c7c2975b3daac76ec2f2b99f7d7e49867b0ae44953c00c7648962b58ee801d670b0a2705ad3f8bd5fed955b0a03c696fdab2fc97deeedee444cd80fe6025b65aa6940c70c9162f21f651c038537ad5caeced6efb2536945556b15356585d28acc8235a54c6e3fe0414b6f5dc95e0798d69c8eb501bab7196c5f1a02819f2f145454c0465d6beadba554fe70d023b96c322ec83b5db015fe801336ff2c6ca7ecff627d282c79c25cfaa2bd5cd0faecfc3ddec74bb0f9755a08974a33bfae0dcb9298363fc9fbd5b51fd2c6eb26d781e7010736e5935d39e5e1c3c415bb1eb77f63ee780b6a9e0b9ee2c3aee7f58388e564d4f2c235009d4d9ddbeb7b0dba86dd6863379e9ce639b7ca6c4ece99febc15e86b8d1dc6d18f7717e01dac12e01d14269930616af0819b5fe87b021da196f9543e3d0a0b0c9c699d83ac7b0cc3663cff513b8966b2a8d1c577147871a2b20a8404ab58d01cca84f6bb0dbc73fcca1501420808205081997ec2c6d2b5a3563133507ac1427edfc4bef24e7eef75f96115a2a4c14e2c670f13c31d7a3e0fa67b39e8c3724529e78608580b78919a2a9e4c55f3b810d5c7c47ef78d112d3736dae653d6357d0b144b1bdb437b6f4e58af2a0b8bd8eaf3eeaa30c1445792565c778cf0e853326a56b0c780e60b581d361428c180b4b87dea416c370d8da1b4ed7c8b928c8ac8ce48208a65b12b753551b2d47d665e207ee5f14cc19f1c43307d2962c33f0f8984afd419bd1c0354c7b344c53eb26fb40d12da0353e1bd3f6e0e3a1b6b9b0acf872f89080f7c879d1651e139b52f98edc97a0288c77b138db89c25a6ba3cfadf5bccff7224b57b2a9dc3c12572091fd99116880017e936d9210182f48ad7cf34badfbee65e5bddf27040721cddb4e53768b4bc1c7fa493aca5a2e29c5f8ef8308cf9e8ae317fd34357c8dfc0b4812cfa768afa326cff2e70deb0bcdaca45dbf554584f743236937b97f3592437cbdf79202f3bb3cd4f542b19dcfc4756ce840dc0686ed067a842ab4866e960d6ea13edeee36780b3a827dbdfbb0eb088fe3ca01816d827dfe1999f26ac45e8475610e788b6dab7f9bcf37ba539e3268a1d8e1fb9e7af4ae5b25c76c91117eebbeef61dd55b223287e729d0dc95148db8e9c3e7924de0d029efe1fa4e568c8afb7baea8142965500afb323742049e4661054a60ef817084ca8e28e7003bbd0d86142ce9ea6dc7ea0c2c6e5d9c87e600bd2f0ae2ce8237c5f6a4e0643a22f1a546f4afdf277bb092279e8782830ef1b53330044207133d84045354d15a44823ba9d374ddd2846a2c34f467b5d780016fb0e98a79cb758571fbc977cad3f69886c8ebd449d4df49e589421bc22c00e3e64d418c225be0e6e239ded60fc"
  let ssWant := "b100ca39eaf924878e62dd8fe70b6ba78d95e2d53217ba55c07d904c25d73850"
  let ssBadWant := "52de31ee3b664156045c759ebf4b675ece3fa2c229d1c54555d06933b34c6d59"
  match hexToBytes? d, hexToBytes? z, hexToBytes? m, hexToBytes? ctBad with
  | some db, some zb, some mb, some ctb =>
    let (ek, dk) := keygen db zb
    let ekOk := bytesToHex ek == ekWant
    let dkOk := bytesToHex dk == dkWant
    let encOk :=
      match encaps ek mb with
      | some (ct, ss) =>
        bytesToHex ct == ctWant && bytesToHex ss == ssWant
          && bytesToHex (decaps dk ct) == ssWant
      | none => false
    let rejectOk := bytesToHex (decaps dk ctb) == ssBadWant
    ekOk && dkOk && encOk && rejectOk
  | _, _, _, _ => false

end Spec.MlKem
