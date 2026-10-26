import Mathlib.Tactic.SplitIfs
import Spec.Bytes
import Spec.Sha3

/-!
ML-DSA-87 verification, written from FIPS 204 (Module-Lattice-Based
Digital Signature Standard) only.

This is the differential oracle for `mldsa.c` and `mldsa_poly.c`
(docs/decisions.md 154). Definitional style: a coefficient is a `Nat`
reduced mod `q = 8380417`, a polynomial is an `Array Nat` of 256
coefficients, and Decompose runs over `Int` with `%` and `/`, as FIPS 204
§7.4 writes it.

Parameters (FIPS 204 §4, Table 1, ML-DSA-87): `k = 8`, `l = 7`,
`eta = 2`, `tau = 60`, `beta = 120`, `gamma1 = 2^19`,
`gamma2 = (q - 1) / 32`, `omega = 75`, `lambda = 256`, `d = 13`. A public
key is 2592 bytes and a signature 4627 bytes (Table 2).

The hash functions are FIPS 204 §3.7: H is SHAKE256 and G is SHAKE128,
from `Spec.Sha3` as one-shots. FIPS 204 squeezes them lazily. This model
reads a fixed prefix instead, as `Spec.MlKem` does, and the prefix is the
bound at which `mldsa_poly.c` stops: 6 blocks of SHAKE128 for an entry of
A, and 272 bytes of SHAKE256 for the challenge. An input whose sampling
needs more fails here as it fails in the C. FIPS 204 Appendix C lets an
implementation bound these loops, and docs/decisions.md 154 states the
probability that a bound is reached.
-/

namespace Spec.MlDsa
open Spec.Bytes
open Spec.Sha3

/-- FIPS 204 §4, Table 1: the field modulus `q = 2^23 - 2^13 + 1`. -/
def q : Nat := 8380417

/-- FIPS 204 Table 1: the rows of A at ML-DSA-87. -/
def k : Nat := 8

/-- FIPS 204 Table 1: the columns of A at ML-DSA-87. -/
def l : Nat := 7

/-- FIPS 204 Table 1: the nonzero coefficients of the challenge c. -/
def tau : Nat := 60

/-- FIPS 204 Table 1: `beta = tau * eta`. -/
def beta : Nat := 120

/-- FIPS 204 Table 1: the coefficient range of y and z, `2^19`. -/
def gamma1 : Nat := 2 ^ 19

/-- FIPS 204 Table 1: the low-order rounding range, `(q - 1) / 32`. -/
def gamma2 : Nat := (q - 1) / 32

/-- FIPS 204 Table 1: the most ones the hint h holds. -/
def omega : Nat := 75

/-- FIPS 204 Table 1: the bits dropped from t, `d = 13`. -/
def dropped : Nat := 13

/-- The bytes of the challenge seed c-tilde, `lambda / 4` with `lambda = 256`. -/
def ctildeLen : Nat := 64

/-- FIPS 204 Algorithm 22, pkEncode: rho, then k polynomials of t1 at 10 bits. -/
def pkLen : Nat := 32 + k * (32 * 10)

/-- FIPS 204 Algorithm 26, sigEncode: c-tilde, l polynomials of z at 20
bits, then omega + k bytes of hints. -/
def sigLen : Nat := ctildeLen + l * (32 * 20) + omega + k

/-- The SHAKE128 blocks this model reads for one entry of A. -/
def sampleBlocks : Nat := 6

/-- The SHAKE256 bytes this model reads for the challenge c. -/
def ballBytes : Nat := 272

/-! ## The NTT (FIPS 204 §7.5) -/

/-- `BitRev8(i)`: the eight low bits of `i` in the other order. -/
def bitRev8 (i : Nat) : Nat := (List.range 8).foldl (fun acc b => acc * 2 + (i >>> b) % 2) 0

/-- FIPS 204 Appendix B: `zetas[i] = 1753^BitRev8(i) mod q`, with 1753 the
primitive 512th root of unity mod q. -/
def zetas : Array Nat := Array.ofFn (n := 256) fun i => 1753 ^ bitRev8 i.val % q

/-- FIPS 204 Algorithm 41, NTT: eight layers, the span halving from 128 to
1, the twiddle index running from 1 to 255. -/
def ntt (w : Array Nat) : Array Nat := Id.run do
  let mut a := w
  let mut m := 0
  for e in [0:8] do
    let len := 128 >>> e
    for g in [0 : 128 / len] do
      let start := g * (2 * len)
      m := m + 1
      let z := zetas[m]!
      for j in [start : start + len] do
        let t := z * a[j + len]! % q
        a := a.set! (j + len) ((a[j]! + q - t) % q)
        a := a.set! j ((a[j]! + t) % q)
  return a

/-- FIPS 204 Algorithm 42, NTT^-1: eight layers, the span doubling from 1
to 128, the twiddle index running down from 255 with the twiddle negated,
then the scale `f = 256^-1 mod q = 8347681`. -/
def invNtt (w : Array Nat) : Array Nat := Id.run do
  let mut a := w
  let mut m := 256
  for e in [0:8] do
    let len := 1 <<< e
    for g in [0 : 128 / len] do
      let start := g * (2 * len)
      m := m - 1
      let z := q - zetas[m]!
      for j in [start : start + len] do
        let t := a[j]!
        a := a.set! j ((t + a[j + len]!) % q)
        a := a.set! (j + len) (z * ((t + q - a[j + len]!) % q) % q)
  return a.map fun x => x * 8347681 % q

/-- FIPS 204 Algorithm 45, MultiplyNTT: the coefficient-wise product. -/
def multiplyNtt (a b : Array Nat) : Array Nat :=
  Array.ofFn (n := 256) fun i => a[i.val]! * b[i.val]! % q

/-- The coefficient-wise sum mod q. -/
def polyAdd (a b : Array Nat) : Array Nat :=
  Array.ofFn (n := 256) fun i => (a[i.val]! + b[i.val]!) % q

/-- The coefficient-wise difference mod q, for reduced inputs. -/
def polySub (a b : Array Nat) : Array Nat :=
  Array.ofFn (n := 256) fun i => (a[i.val]! + q - b[i.val]!) % q

/-! ## Sampling (FIPS 204 §7.3) -/

/-- FIPS 204 Algorithm 30, RejNTTPoly, over `sampleBlocks` blocks of
SHAKE128(seed). Each three bytes give `b0 + 256 b1 + 65536 (b2 mod 128)`
(Algorithm 14, CoeffFromThreeBytes), kept when it is under q. `none` when
fewer than 256 are kept. -/
def rejNttPoly (seed : ByteArray) : Option (Array Nat) :=
  let s := shake128 seed (168 * sampleBlocks)
  let kept := (List.range (56 * sampleBlocks)).filterMap fun g =>
    let v := s[3 * g]!.toNat + 256 * s[3 * g + 1]!.toNat + 65536 * (s[3 * g + 2]!.toNat % 128)
    if v < q then some v else none
  if 256 ≤ kept.length then some (kept.take 256).toArray else none

/-- FIPS 204 Algorithm 29, SampleInBall, over `ballBytes` bytes of
SHAKE256(c-tilde): 64 sign bits from the first 8 bytes, then for i from
196 to 255 the first later byte j with `j ≤ i` moves `c[j]` to `c[i]` and
puts `(-1)^h[i + tau - 256]` at `c[j]`. A coefficient of -1 is `q - 1`.
`none` when the bytes run out first. -/
def sampleInBall (ctilde : ByteArray) : Option (Array Nat) := Id.run do
  let s := shake256 ctilde ballBytes
  let signs := (List.range 8).foldl (fun acc b => acc + s[b]!.toNat * 256 ^ b) 0
  let mut c : Array Nat := Array.replicate 256 0
  let mut i := 256 - tau
  for pos in [8 : ballBytes] do
    if i < 256 then
      let j := s[pos]!.toNat
      if j ≤ i then
        let sign := if (signs >>> (i + tau - 256)) % 2 == 1 then q - 1 else 1
        c := c.set! i c[j]!
        c := c.set! j sign
        i := i + 1
  if i == 256 then return some c else return none

/-! ## Decoding (FIPS 204 §7.1 and §7.2) -/

/-- Bit `idx` of `B`, the low bit of each byte first (FIPS 204 Algorithm 9,
BytesToBits). -/
def bitAt (B : ByteArray) (idx : Nat) : Nat := (B[idx / 8]!.toNat >>> (idx % 8)) % 2

/-- FIPS 204 Algorithm 18, SimpleBitUnpack: 256 values of `width` bits each. -/
def unpackBits (B : ByteArray) (width : Nat) : Array Nat :=
  Array.ofFn (n := 256) fun i =>
    (List.range width).foldl (fun acc b => acc + bitAt B (i.val * width + b) * 2 ^ b) 0

/-- FIPS 204 Algorithm 19, BitUnpack with `a = gamma1 - 1` and
`b = gamma1`: each coefficient of z is `gamma1` minus its 20-bit value. -/
def unpackZ (B : ByteArray) : Array Int :=
  (unpackBits B 20).map fun (v : Nat) => (gamma1 : Int) - (v : Int)

/-- FIPS 204 Algorithm 21, HintBitUnpack: `none` when an end is below the
end before it or past omega, when a row's positions do not increase, or
when a byte after the last row's end is not 0. -/
def hintBitUnpack (y : ByteArray) : Option (Array (Array Bool)) := Id.run do
  let mut h : Array (Array Bool) := Array.replicate k (Array.replicate 256 false)
  let mut index := 0
  for i in [0:k] do
    let stop := y[omega + i]!.toNat
    if stop < index || stop > omega then return none
    for pos in [index : stop] do
      if pos > index && y[pos - 1]! ≥ y[pos]! then return none
      h := h.set! i (h[i]!.set! y[pos]!.toNat true)
    index := stop
  for pos in [index : omega] do
    if y[pos]! != 0 then return none
  return some h

/-! ## Rounding (FIPS 204 §7.4) -/

/-- `r mod± alpha`: the representative in `(-alpha/2, alpha/2]`, for an even
alpha. -/
def modPm (r alpha : Int) : Int :=
  let r0 := r % alpha
  if r0 > alpha / 2 then r0 - alpha else r0

/-- FIPS 204 Algorithm 36, Decompose: `(r1, r0)` with
`r = r1 * 2 gamma2 + r0`, and at `r - r0 = q - 1` the pair `(0, r0 - 1)`. -/
def decompose (r : Nat) : Int × Int :=
  let rp : Int := (r % q : Nat)
  let alpha : Int := 2 * (gamma2 : Int)
  let r0 := modPm rp alpha
  let top := decide (rp - r0 = (q : Int) - 1)
  (if top then 0 else (rp - r0) / alpha, if top then r0 - 1 else r0)

/-- FIPS 204 Algorithm 40, UseHint, with `m = (q - 1) / (2 gamma2) = 16`. -/
def useHint (h : Bool) (r : Nat) : Nat :=
  let p := decompose r
  let v := if h && p.2 > 0 then (p.1 + 1) % 16 else if h then (p.1 - 1) % 16 else p.1
  v.toNat

/-- FIPS 204 Algorithm 28, w1Encode, for one polynomial: SimpleBitPack at
4 bits, coefficient `2i` in the low half of byte `i`. -/
def w1Encode (w1 : Array Nat) : ByteArray :=
  ByteArray.mk (Array.ofFn (n := 128) fun i =>
    UInt8.ofNat (w1[2 * i.val]! % 16 + 16 * (w1[2 * i.val + 1]! % 16)))

/-! ## Verification (FIPS 204 §5.3 and §6.3) -/

/-- The polynomial with every coefficient 0. -/
def zero : Array Nat := Array.replicate 256 0

/-- One row of w1Encode(w1') (FIPS 204 Algorithm 8, steps 9 and 10):
`A[i] o NTT(z) - NTT(c) o NTT(t1[i] * 2^d)`, back through NTT^-1, under
UseHint with row i's hints. `none` when an entry of A runs past its
bound. -/
def row (pk : ByteArray) (zHat : List (Array Nat)) (cHat : Array Nat) (h : Array (Array Bool))
    (i : Nat) : Option ByteArray := do
  let rho := pk.extract 0 32
  let entries ← (List.range l).mapM fun j =>
    rejNttPoly (rho ++ ByteArray.mk #[UInt8.ofNat j, UInt8.ofNat i])
  let az := (entries.zip zHat).foldl (fun acc (a, zh) => polyAdd acc (multiplyNtt a zh)) zero
  let t1 := unpackBits (pk.extract (32 + 320 * i) (32 + 320 * (i + 1))) 10
  let ct1 := multiplyNtt cHat (ntt (t1.map fun v => v * 2 ^ dropped % q))
  let w := invNtt (polySub az ct1)
  return w1Encode (Array.ofFn (n := 256) fun c => useHint h[i]![c.val]! w[c.val]!)

/-- FIPS 204 Algorithm 8, ML-DSA.Verify_internal, up to the challenge it
recomputes: `c-tilde' = H(mu || w1Encode(w1'), 64)`. `none` when the sizes
are wrong, when HintBitUnpack fails, when z is not under `gamma1 - beta`,
or when a sampling bound is reached. -/
def challenge (pk mu sig : ByteArray) : Option ByteArray := do
  guard (pk.size == pkLen && sig.size == sigLen && mu.size == 64)
  let h ← hintBitUnpack (sig.extract (sigLen - (omega + k)) sigLen)
  let zs := (List.range l).map fun j => unpackZ (sig.extract (64 + 640 * j) (64 + 640 * (j + 1)))
  guard (zs.all fun z => z.all fun c => c.natAbs < gamma1 - beta)
  let c ← sampleInBall (sig.extract 0 ctildeLen)
  let cHat := ntt c
  let zHat := zs.map fun z => ntt (z.map fun v => (v % (q : Int)).toNat)
  let rows ← (List.range k).mapM (row pk zHat cHat h)
  return shake256 (rows.foldl (· ++ ·) mu) 64

/-- FIPS 204 Algorithm 3 step 5 and Algorithm 8 steps 6 and 7: `mu` is
H(H(pk, 64) || 0 || |ctx| || ctx || M, 64), pure ML-DSA's domain byte 0
first. -/
def mu (pk msg ctx : ByteArray) : ByteArray :=
  shake256 (shake256 pk 64 ++ ByteArray.mk #[0, UInt8.ofNat ctx.size] ++ ctx ++ msg) 64

/-- FIPS 204 Algorithm 3, ML-DSA.Verify: false for a context over 255
bytes or a key or signature of the wrong length, else whether the
challenge recomputed is the signature's c-tilde. -/
def verify (pk msg ctx sig : ByteArray) : Bool :=
  if pk.size != pkLen || sig.size != sigLen || 255 < ctx.size then false
  else
    match challenge pk (mu pk msg ctx) sig with
    | some c => c.data == (sig.extract 0 ctildeLen).data
    | none => false

/-! ## Signing (FIPS 204 §5.1, §5.2, §6.1 and §6.2)

The model of `mldsa_signer.c` (docs/decisions.md 159). It reads fixed
prefixes of the XOFs, as verification does: 481 bytes of SHAKE256 for a
polynomial of s1 or s2, FIPS 204 Appendix C Table 3's limit, and the
verifier's prefixes for A and c. The rejection loop runs at most 814
rounds, Table 3's limit for ML-DSA.Sign_internal. A bound reached gives
`none`, as it gives 0 in the C. -/

/-- FIPS 204 Table 1: the range of s1 and s2 at ML-DSA-87. -/
def eta : Nat := 2

/-- FIPS 204 Table 2: the secret key, `rho ‖ K ‖ tr ‖ s1 ‖ s2 ‖ t0`. -/
def skLen : Nat := 32 + 32 + 64 + 32 * 3 * l + 32 * 3 * k + 32 * 13 * k

/-- FIPS 204 Appendix C Table 3: the SHAKE256 bytes RejBoundedPoly reads. -/
def etaStreamBytes : Nat := 481

/-- FIPS 204 Appendix C Table 3: the rounds ML-DSA.Sign_internal runs. -/
def signRounds : Nat := 814

/-- A coefficient `v` as its residue in `[0, q)`. -/
def toZq (v : Int) : Nat := (v % (q : Int)).toNat

/-- A residue as its representative in `[-(q - 1) / 2, (q - 1) / 2]`. -/
def centered (x : Nat) : Int := if x > (q - 1) / 2 then (x : Int) - q else x

/-- FIPS 204 Algorithm 16, SimpleBitPack: 256 values of `width` bits, the
low bit of each value first, eight bits a byte. -/
def packBits (values : Array Nat) (width : Nat) : ByteArray :=
  ByteArray.mk (Array.ofFn (n := 32 * width) fun byte =>
    UInt8.ofNat ((List.range 8).foldl (fun acc b =>
      let index := byte.val * 8 + b
      acc + (values[index / width]! >>> (index % width)) % 2 * 2 ^ b) 0))

/-- FIPS 204 Algorithm 17, BitPack with `b` the offset: each value is
`b - v`, as skEncode and sigEncode write s1, s2, t0 and z. -/
def packOffset (values : Array Int) (offset : Int) (width : Nat) : ByteArray :=
  packBits (values.map fun v => (offset - v).toNat) width

/-- FIPS 204 Algorithm 19, BitUnpack with `b` the offset. -/
def unpackOffset (B : ByteArray) (offset : Int) (width : Nat) : Array Int :=
  (unpackBits B width).map fun (v : Nat) => offset - (v : Int)

/-- FIPS 204 Algorithm 31, RejBoundedPoly, at eta = 2, over
`etaStreamBytes` bytes of SHAKE256(seed): each half-byte z under 15 gives
`2 - (z mod 5)` (Algorithm 15, CoeffFromHalfByte), the low half first. -/
def rejBoundedPoly (seed : ByteArray) : Option (Array Int) :=
  let s := shake256 seed etaStreamBytes
  let halves := (List.range etaStreamBytes).flatMap fun b => [s[b]!.toNat % 16, s[b]!.toNat / 16]
  let kept := halves.filterMap fun z =>
    if z < 15 then some ((2 : Int) - ((z % 5 : Nat) : Int)) else none
  if 256 ≤ kept.length then some (kept.take 256).toArray else none

/-- FIPS 204 Algorithm 35, Power2Round: `(r1, r0)` with
`r = r1 * 2^13 + r0` and `r0 = r mod± 2^13`. -/
def power2Round (r : Nat) : Nat × Int :=
  let rp : Int := (r % q : Nat)
  let r0 := modPm rp (2 ^ dropped)
  (((rp - r0) / 2 ^ dropped).toNat, r0)

/-- Row i of A, sampled from rho (FIPS 204 Algorithm 32, ExpandA). -/
def matrixRow (rho : ByteArray) (i : Nat) : Option (List (Array Nat)) :=
  (List.range l).mapM fun j => rejNttPoly (rho ++ ByteArray.mk #[UInt8.ofNat j, UInt8.ofNat i])

/-- `NTT^-1(sum over j of a[j] o v[j])`. -/
def rowTimes (a : List (Array Nat)) (vHat : List (Array Nat)) : Array Nat :=
  invNtt ((a.zip vHat).foldl (fun acc (e, vh) => polyAdd acc (multiplyNtt e vh)) zero)

/-- The two-byte little-endian nonce FIPS 204 appends in ExpandS and
ExpandMask. -/
def nonce (n : Nat) : ByteArray := ByteArray.mk #[UInt8.ofNat (n % 256), UInt8.ofNat (n / 256)]

/-- FIPS 204 Algorithm 6, ML-DSA.KeyGen_internal: `(sk, pk)` from the seed
xi. `none` when a sampler reaches its bound. -/
def keyGen (xi : ByteArray) : Option (ByteArray × ByteArray) := do
  let e := shake256 (xi ++ ByteArray.mk #[UInt8.ofNat k, UInt8.ofNat l]) 128
  let rho := e.extract 0 32
  let rhoP := e.extract 32 96
  let s1 ← (List.range l).mapM fun r => rejBoundedPoly (rhoP ++ nonce r)
  let s2 ← (List.range k).mapM fun r => rejBoundedPoly (rhoP ++ nonce (l + r))
  let s1Hat := s1.map fun s => ntt (s.map toZq)
  let t ← (List.range k).mapM fun i => do
    let a ← matrixRow rho i
    return polyAdd (rowTimes a s1Hat) (s2[i]!.map toZq)
  let halves := t.map fun ti => ti.map power2Round
  let pk := halves.foldl (fun acc h => acc ++ packBits (h.map (·.1)) 10) rho
  let sk := rho ++ e.extract 96 128 ++ shake256 pk 64 ++
    (s1 ++ s2).foldl (fun acc s => acc ++ packOffset s eta 3) ByteArray.empty ++
    halves.foldl (fun acc h => acc ++ packOffset (h.map (·.2)) (2 ^ 12) 13) ByteArray.empty
  return (sk, pk)

/-- FIPS 204 Algorithm 39, MakeHint(z, r): whether adding z moves the high
bits of r. -/
def makeHint (z : Int) (r : Int) : Bool :=
  (decompose (toZq r)).1 != (decompose (toZq (r + z))).1

/-- FIPS 204 Algorithm 20, HintBitPack: the positions of each row's hints,
then the running count at the end of each row. -/
def hintBitPack (h : List (Array Bool)) : ByteArray :=
  let rows := h.map fun row => (List.range 256).filter fun c => row[c]!
  let positions := rows.flatten
  let ends := (List.range k).map fun i => ((rows.take (i + 1)).map List.length).sum
  ByteArray.mk ((positions ++ List.replicate (omega - positions.length) 0 ++ ends).map
    UInt8.ofNat).toArray

/-- The largest absolute value among the coefficients of a vector. -/
def infNorm (v : List (Array Int)) : Nat :=
  v.foldl (fun acc p => p.foldl (fun m c => max m c.natAbs) acc) 0

/-- The parts of skDecode (FIPS 204 Algorithm 25) that a round reads, in
the NTT domain, with K and the matrix A. -/
structure SignKey where
  /-- K, the key of rho''. -/
  key : ByteArray
  /-- A, row by row. -/
  a : List (List (Array Nat))
  /-- NTT(s1). -/
  s1Hat : List (Array Nat)
  /-- NTT(s2). -/
  s2Hat : List (Array Nat)
  /-- NTT(t0). -/
  t0Hat : List (Array Nat)

/-- One round of FIPS 204 Algorithm 7 at kappa: `some (some sig)` when it
passes, `some none` when a check rejects it, and `none` when SampleInBall
reaches its bound. -/
def signRound (sk : SignKey) (mu rho2 : ByteArray) (kappa : Nat) :
    Option (Option ByteArray) := do
  let y := (List.range l).map fun j =>
    unpackOffset (shake256 (rho2 ++ nonce (kappa + j)) 640) gamma1 20
  let yHat := y.map fun p => ntt (p.map toZq)
  let w := sk.a.map fun row => rowTimes row yHat
  let w1 := w.map fun wi => w1Encode (wi.map fun c => (decompose c).1.toNat)
  let ctilde := shake256 (w1.foldl (· ++ ·) mu) 64
  let c ← sampleInBall ctilde
  let cHat := ntt c
  let times (sHat : Array Nat) : Array Int := (invNtt (multiplyNtt cHat sHat)).map centered
  let z := (y.zip sk.s1Hat).map fun (yj, s) => (yj.zip (times s)).map fun (a, b) => a + b
  let r := (w.zip sk.s2Hat).map fun (wi, s) =>
    (wi.zip (times s)).map fun (a, b) => (a : Int) - b
  let r0 := r.map fun ri => ri.map fun v => (decompose (toZq v)).2
  let ct0 := sk.t0Hat.map times
  let h := (ct0.zip r).map fun (ci, ri) =>
    (ci.zip ri).map fun (cv, rv) => makeHint (-cv) (rv + cv)
  let hints := (h.map fun row => (row.toList.filter id).length).sum
  if gamma1 - beta ≤ infNorm z || gamma2 - beta ≤ infNorm r0 || gamma2 ≤ infNorm ct0 ||
      omega < hints then
    return none
  return some (ctilde ++ z.foldl (fun acc p => acc ++ packOffset p gamma1 20) ByteArray.empty ++
    hintBitPack h)

/-- skDecode (FIPS 204 Algorithm 25) to the parts a round reads. `none`
for a key of another length, a coefficient of s1 or s2 outside
`[-eta, eta]`, which FIPS 204 §7.2 says skDecode may give for a key from
an untrusted source, or an entry of A past its bound. -/
def signKey (sk : ByteArray) : Option SignKey := do
  guard (sk.size == skLen)
  let part (start len : Nat) := sk.extract start (start + len)
  let s := (List.range (l + k)).map fun r => unpackOffset (part (128 + 96 * r) 96) eta 3
  guard (s.all fun p => p.all fun c => c.natAbs ≤ eta)
  let t0 := (List.range k).map fun i =>
    unpackOffset (part (128 + 96 * (l + k) + 416 * i) 416) (2 ^ 12) 13
  let a ← (List.range k).mapM (matrixRow (sk.extract 0 32))
  let hat (p : Array Int) := ntt (p.map toZq)
  return { key := sk.extract 32 64, a := a, s1Hat := (s.take l).map hat,
           s2Hat := (s.drop l).map hat, t0Hat := t0.map hat }

/-- The rejection loop from round `round` on, with `rounds` rounds left. -/
def signLoop (sk : SignKey) (mu rho2 : ByteArray) : Nat → Nat → Option ByteArray
  | 0, _ => none
  | rounds + 1, round =>
    match signRound sk mu rho2 (round * l) with
    | none => none
    | some (some sig) => some sig
    | some none => signLoop sk mu rho2 rounds (round + 1)

/-- FIPS 204 Algorithm 7, ML-DSA.Sign_internal, from mu, at most
`signRounds` rounds. -/
def signMu (sk mu rnd : ByteArray) : Option ByteArray := do
  let key ← signKey sk
  signLoop key mu (shake256 (key.key ++ rnd ++ mu) 64) signRounds 0

/-- FIPS 204 Algorithm 2, ML-DSA.Sign, pure ML-DSA: `none` for a context
over 255 bytes or a key of another length, else Sign_internal over
`M' = 0 ‖ |ctx| ‖ ctx ‖ M`, with mu from the key's tr. -/
def sign (sk msg ctx rnd : ByteArray) : Option ByteArray :=
  if 255 < ctx.size || sk.size != skLen then none
  else
    signMu sk (shake256 (sk.extract 64 128 ++ ByteArray.mk #[0, UInt8.ofNat ctx.size] ++ ctx ++
      msg) 64) rnd

/-! ## Theorems -/

/-- FIPS 204 Table 2 at ML-DSA-87: a 2592-byte key and a 4627-byte
signature. -/
theorem sizes_87 : pkLen = 2592 ∧ sigLen = 4627 := by decide

/-- A key of another length never verifies (FIPS 204 Algorithm 3). -/
theorem verify_false_of_pk_size (pk msg ctx sig : ByteArray) (h_size : pk.size ≠ pkLen) :
    verify pk msg ctx sig = false := by
  simp [verify, h_size]

/-- A context over 255 bytes never verifies (FIPS 204 Algorithm 3 step 1). -/
theorem verify_false_of_long_context (pk msg ctx sig : ByteArray) (h_long : 255 < ctx.size) :
    verify pk msg ctx sig = false := by
  simp [verify, h_long]

/-- Soundness of the comparison: a signature verifies only when the
challenge recomputed from its key, its mu and its hints is its c-tilde. -/
theorem challenge_of_verify (pk msg ctx sig : ByteArray)
    (h_verified : verify pk msg ctx sig = true) :
    ∃ c, challenge pk (mu pk msg ctx) sig = some c ∧
      c.data = (sig.extract 0 ctildeLen).data := by
  unfold verify at h_verified
  split at h_verified
  · contradiction
  · split at h_verified
    · rename_i c h_challenge
      exact ⟨c, h_challenge, by simpa using h_verified⟩
    · contradiction

/-- `mod±` at `2 gamma2 = 523776` leaves a multiple of 523776 and a
representative in `(-gamma2, gamma2]`. -/
private theorem modPm_bounds (r : Int) :
    (r - modPm r 523776) % 523776 = 0 ∧ -261888 < modPm r 523776 ∧ modPm r 523776 ≤ 261888 := by
  simp only [modPm]
  split_ifs <;> omega

/-- Decompose's high part is in 0..15: `r - r0` is a multiple of `2 gamma2`
below `q - 1 + gamma2`, and at `q - 1` itself Decompose gives 0. -/
private theorem decompose_fst_bounds (r : Nat) : 0 ≤ (decompose r).1 ∧ (decompose r).1 < 16 := by
  have h_alpha : 2 * ((gamma2 : Nat) : Int) = 523776 := by decide
  have h_top_value : (q : Int) - 1 = 8380416 := by decide
  simp only [decompose, h_alpha, h_top_value]
  obtain ⟨h_multiple, h_low, h_high⟩ := modPm_bounds ((r % q : Nat) : Int)
  have h_reduced : 0 ≤ ((r % q : Nat) : Int) ∧ ((r % q : Nat) : Int) < 8380417 := by
    simp only [q]; omega
  generalize modPm ((r % q : Nat) : Int) 523776 = r0 at *
  generalize ((r % q : Nat) : Int) = rp at *
  by_cases h_top : rp - r0 = 8380416
  · simp only [h_top, decide_true, if_true]
    omega
  · simp only [h_top, decide_false, Bool.false_eq_true, if_false]
    omega

/-- UseHint's value is a 4-bit `w1` coefficient, so w1Encode loses no bit
(FIPS 204 Algorithm 40, `m = 16`). -/
theorem useHint_lt (h : Bool) (r : Nat) : useHint h r < 16 := by
  obtain ⟨h_low, h_high⟩ := decompose_fst_bounds r
  cases h <;> simp only [useHint] <;> split_ifs <;> omega

/-- One row of w1Encode is 128 bytes, so the eight rows the challenge hashes
are 1024. -/
theorem w1Encode_size (w1 : Array Nat) : (w1Encode w1).size = 128 := by
  simp [w1Encode, ByteArray.size]

/-- FIPS 204 Table 2 at ML-DSA-87: a 4896-byte secret key. -/
theorem skLen_87 : skLen = 4896 := by decide

/-- A context over 255 bytes is never signed (FIPS 204 Algorithm 2 step 1). -/
theorem sign_none_of_long_context (sk msg ctx rnd : ByteArray) (h_long : 255 < ctx.size) :
    sign sk msg ctx rnd = none := by
  simp [sign, h_long]

/-- A key of another length is never used (FIPS 204 Table 2). -/
theorem sign_none_of_sk_size (sk msg ctx rnd : ByteArray) (h_size : sk.size ≠ skLen) :
    sign sk msg ctx rnd = none := by
  simp [sign, h_size]

/-- Power2Round splits r into `r1 * 2^13 + r0` with `r0` in
`(-2^12, 2^12]` (FIPS 204 Algorithm 35). -/
theorem power2Round_spec (r : Nat) (h_reduced : r < q) :
    ((power2Round r).1 : Int) * 2 ^ dropped + (power2Round r).2 = r ∧
      -4096 < (power2Round r).2 ∧ (power2Round r).2 ≤ 4096 := by
  have h_mod : r % q = r := Nat.mod_eq_of_lt h_reduced
  simp only [power2Round, h_mod, modPm, dropped]
  split_ifs <;> omega

/-- `packBits` writes 32 bytes for each bit of width: 96 for s1 and s2,
320 for t1, 416 for t0 and 640 for z. -/
theorem packBits_size (values : Array Nat) (width : Nat) :
    (packBits values width).size = 32 * width := by
  simp [packBits, ByteArray.size]

/-! ## Self-test

Wycheproof's first ML-DSA-87 verify case (mldsa_87_verify_test.json,
tcId 1): its key, the message "Hello world" and its signature must verify,
and with one bit of c-tilde flipped must not. Then the first four zetas
of FIPS 204 Appendix B, and a key whose t1 is 0: with z = 0 and no hint,
w1 is 0, so `c-tilde = H(mu || 0^1024, 64)` verifies.
-/

set_option compiler.extract_closed false in
/-- The checks the section note above names. -/
def selftest (_ : Unit) : Bool :=
  let pkHex := String.join [
    "17a508179b35057099111733da28fd1a2265de7d8ab22d5279f13bca84cc42a5b8c9644c121e7e1b81723c52",
    "95be288fb6c36bfa188b6e08d913a152350947fa2c8ccc3fd01b319f65a2058a1dff54133946cfeb408d0b6d",
    "fde6bbebd7e0591cfe83b8b5452ceef6c855f7d33e06a0d269345089ed0d3ad67d84d8a4a34d16836004cff1",
    "25469e8c3387abd788b620e30c1fc23909117a0e34c42a6631d9791347b1b2a3c9ab3082416211afb7bc3f6c",
    "e630a7019af19f736cdfacb1e7db66b65ef56844d2a2b0753d09283a7a0b66f77596384e95f7ceddd1c4ba20",
    "edc11f1eaab695bb963f6eda1c383754aa372a0d7729bfa6e0f142131c2367ba3f89ce3de6c357f9a7225b7c",
    "b85f6b3e8a3a122e8501fd1446b8152a415c19dda1d2e4590cd994f6664b4d1abd7381468c3a085abe2741a0",
    "cfbb81880664b271677245c4a471bf8bb8e0192eb32e4fb5e8560f3c50d6b19a353e486d0fcc2a35ac046286",
    "e707e095f61786d92212686a65d39b6863e0f8cec1e1997f2f845e4878ca9df650c746765296790863e51d01",
    "2d32dffcbd746aa2276d04c0a57cd1b3d6ed06c0d66a0897aae5c49c97b6f19ae829baaafbfed28a52c05963",
    "c6eea9eff69528294207f8cda75280f7c486e6848791c8e37015479f2e13c28a9fe654dbde11689875203aae",
    "c51be3da7cab1cf31e4ec476c0c830cbdd04ac02167c0a6fbfdd6548b1fa525d235c7e3fca8d63e6427503b0",
    "a45c0bfddb428b837c32e8755441077bfe1c0142bac357b012a46545bf4148d465472dcf89c9d73b62357087",
    "e229f53a450d3cce41c8ee21a9d54b61e34a794f5b1406a70724ab0c3712c49df231ef30a956075e907c51b6",
    "3dd1f9453dbe60e25b0f3cc0354dfd7c9119313919e77cb2c92f544d3e5302b8827603e936b567e99bfe9904",
    "932585a9f01a5a1b5bce07565f1d84c6b1c5c86259e1fefcff18cd06861122be6836be21e40be4eaf6bcabee",
    "8f634f95520aa914bb51c54dbd67d1b9dc5e38831e786c283979a963a3206b98e339edec4128b0502d4d4781",
    "3869713e431a529a03c7f54b50123680f2b7f256f5d2b40642203259b9e85c62253d5670ce372193f28b5aa4",
    "8ddd643c54756a2cff808c109f74772961d8db6bb8a17547c8f29c7f5ff3ea06740b867d84917e07f3978ad0",
    "281a20689eef58467e768b6178a9b36a567289fd39762bb3e4254031b2798a4550857f6af369d484392cddd7",
    "b48eaa2942e2cbfe754d5ee2da2b7fa71222e4a525ff5224d551a778ebd828e4e0499adc74ff0d59a5abc78a",
    "d6a8abafeedb3c99045a14423507f85597b1a7f540982f7d72ea13449110b442d54b78029b4c7fe3b49396dc",
    "6c3b7d58792538fa907963de10a4b724548142541cdf1512e0f7ff1b10a93de63541b8cc3268b4de20ed2673",
    "9ee8973b6507ebe48965602c35fa3f7d4278146b598d7d7044e16e97e9351f7c51ac25573b7232ae2432638e",
    "9166190e7f7a7dcb5096ecb5d10017cdea2a82b4f56c7385041c6919a7e36e11beac77ec3f25df44e7b596c1",
    "542c1e376de3667c0e903fe25b57c338e9d93c5570c484f0ddab4f57d38f292b23599d9efc7a9fd9e078aadd",
    "ca0acb1a196d6c45d3c8be6f39e8cdbe3299e370b262e0bf6fb5f005cae2b12879289d00bd8039de6a571c31",
    "0d87557f5c9a4f64a0bde7177a8464722a04bf87fa2cb0e312d4fa6e536c61d65dc2c1baf144b0d1d1d75f4c",
    "860626ff773933efa9941d105c53a1d92c4f7c7bba4aa969590acef1e50901870f59715ac14d9846d83871a7",
    "7367be57c63f88bc2c02eabafe678f44925a3e605979282fcd3f284736a1d346c033cb782dd615e886683fc3",
    "7cd87a91422857774c63c6659096eba393c56225ed8c3485b4f89ecb07d53526281a6426ae7d67cda52fec5a",
    "c32320caae9b96000bcbe9e8782be88cb1ca6dcaffb74ef04c77e03a994bea2c89e4fcfa44cd0c9f4e30705a",
    "8b7b20df8c76b05a4479400e07db03d243e9fe4c90d34e9245f1e574be9a388f5355482077e4e98b919de024",
    "e666fdd7d51ed2a0d58a823e7497eb07303cf1d6d5f10a536be980220de5856727e5c13981839cfa19740988",
    "e7771a2b984f53ae3a5916ed881a4a90fe524f0bb3778355882864f8961fade32e656fcf9f524e748c8196a1",
    "f1bbc57bf8da7b36de9b0080f0c7bb8487a2b7bb7a81a8ff43a2539b367c9a48c70041520f05ca3dae316dbb",
    "e3118218216f52b7bcdba7557c4c9d861803a5e2ee01d3682e1261d7cae0a99fb8de909eb2bc1e112aa43cc2",
    "fa9c76a222bd85faaaba5d9ec2198ac45a295181a324a0592632b89e2752582cd5e01e1a610e7563faee10b7",
    "6d853109e257e7c0c248a9fb7933f514b07b4f4e3a4a3d2cd22e8cc45ebda3bef5948aa050f01eff85ae98d1",
    "9f69c51e67ff89f2df0c5268acfdd325e84591317e05cab4f9e6358f249c4ddf4019fbc8f511549a733898a5",
    "0efa9e0793083de0b15b5bf78d9f63d8df830d42df2fefa27b89e0ede2a702eb9467118fc0ed44edc63ad1b1",
    "935877c34843fea06fdf388bbf83e501723a13cc6cc2efbb9691fe28fc1d45270591e5bdf7aa1c82673544ee",
    "29d9e6c9da3328f21e9729bffd7f4e56de585909679a74037105fdac3f51ae35f69d9763d2e4cfeb1d4a8fdc",
    "e99bf1aa21f866a9f523b2a9549e12258a4d19900cf5db37b67da19b23563bd1d701c6106fccb28e4689c62e",
    "1a6cf1abd763d7239c2258b765610d4478be9f1650cb8d18923592ad0024076e52f9bd0a3894fe97bc0a1646",
    "b4c37f62c27f32d0df270260f47c49a5caf110e4cf80168a7d54b1c70bed9bd5d9a143ce869a05cd44ee266a",
    "ecd6bfedb39be79e7c7d5c11a99575ebc0f389cc55a4fe1469a2d61b70bfe4b74e3e27521a037d2b9f4fdb37",
    "7231e2ceb214ba90f6953865c683215203ce963875c6524c01b789e0389a9f0c386eb236f0dfba6c95df4f28",
    "ccc7ae7cd473f9dcd20817cccdd211bcbc78b064e936e4ba2813df531128428ddf410e6ca07044aeb4cfcc0a",
    "16c995ec51c8af16a541ce18dbeb69a26635632dcc24ee52a5eedce38c502cd0e356ec31341c893f92e6063c",
    "3a160a53d34b85e92357a8ebaaad8f206771be43ee48cc409825a7094bda529ee18776d9e67f1fa1c1419514",
    "309d70ba2443be2f63b6943478d6c0f56dd058731e53de4c30bfc7d915e9284a56248e81944392881666680d",
    "4991f04269ec9a83b24b458ed59a6c274de452ab3013c103a4920543e6a7d22dadfd764f6ea39d49b910ee0d",
    "c216e547aa5fb4382a72a568ebe83ec00416fb5830dc21c24ae72416602870cb52c3a8a1c4c12a4b287b9b80",
    "0d31c287ca161f404a9e598a5358d28b3aae43e534846bcd0d7a9c7652ae01e6698c79e315aca8198f36de45",
    "af7084b1cb21ca2ba0ee3a547a7343a10ef9e3fd17b0a4060badd1409a0562cba25b84fd578268fac53cfbca",
    "08e6cf6e5419f57262eb5813c1d1324e0df1d483ade08d8f6c62498e262485ac7c2872b11b42e5c1b797fc12",
    "e838b38a711d364d45cd1ed35f7faffdf4b0fb0eaa312fc3d5af77909b0649cbbacea10c9831273922b5b051",
    "72face9ce6cf324edf6e2f5f5fa0a9f0463eee938b30adf3e55664f94d274cd87dea901a7e08e805"]
  let sigHex := String.join [
    "ba4275ff54c22d2d09ea1937a0667362acd44925c6d6965fad350b111d1cbcce68ddbd0e576d1a8810eb4e71",
    "623781f32f747d44c8e693749df191682f588906949d97617a4b0ec54ad966818dee88b95f0f28ca24bfc5bf",
    "e0c316140b0662c43093ae48b899cc71e5739e9d67095ed987a79b6a0e7aac960c3c4125f0e92bc9435d10bf",
    "ffae34bb3af05e977ebe0bafcbeb2381c5afe3379667b4c201aebf162dbd0a4bd1baa88fb2f88fa970499a84",
    "8737d3cf94cc8ce278880a169cad91f304e4e8f1091d4cf39d9a3ab9f88dcc6f3bc4df311a5be0cba290365b",
    "3e879527e2a77f0cb6eccc9d85a5e592fb00f3a2e925a26d295a6b82746d7f534c83c35bc4826ee4910216b9",
    "a2867032698996fb0e1669b539ccd2ec74d181f4844e8f4d28f9c174316c12dadb54cb1dde7338238a20731c",
    "2565bb959f8e3086273ed03abc7ac515728750633083c0b397b29d385d13f5afd2529b32f00dce66c9dc8ea9",
    "3d99c8b61c5e0ab2fc70de2a8dabdcaf290d53e8fca7561bda8c516ad475e4ec6c7cd2603aa3c8a71d9fa5dc",
    "7efc33cf318bebc1f1594e6ea25c69b8f9ce34a65b8ab0ae8dd3538bd267d86c584b8f354d7e4776ed4dd59a",
    "73f9e70a1df572f033b69b3eafa5a901e02515472e37258608875ca469de07db71cd6b8dc7edeb3d866ed2d2",
    "19e44fcb133a066e89d8e3013569ca6f1fee7bf4ae56a6d32a5f3e5a530819c31aadabc8a88503edbea9cdfa",
    "3171762e1e8bcebaf9bb6af7e540102d5fc810bbcf1e02ae564e04d9dc55dab0a9392d6c95a317730d979395",
    "4da2cb16544d15403d0db01e85881e2d4f1b9b98458e1af0985f98b014f08f200558f2fed7a70c352a27423b",
    "edeebb3775c0a1ede9d461d2aea303c09c8b1f73fc37a5b3a01fb24a131574f7eac90c78baa38cebe81e2335",
    "dafda20299f76d6a0ba77d2954d11381674f4069f45e133886d64222d92583d5908e3ab6eb6a72cfb41f7dc3",
    "e71c1383888f61624bdcaf12fb716de98232ee329af1dd045f30d377234db7bfd11ddab0b3108329e16ce568",
    "c8bada39a98df5a5f72a72f063fa4253313a806013f61ce5adbe54cf42180ebf6e496bd4b42aeacf069aaa8e",
    "1c231fd037b394d78a69d1742b45bc5784ab8593a198077423c4c357d734f9899cfe9b3b62b6b9c3f4d781b8",
    "484a3fd0eea7e8d6945f4ba2b046fee079b7f032bebbc402918daa2aa1c9433dc3bcfbd7f49a5d7a293833c2",
    "1c1bade3e8a7ec3c83d485529de51b5993cdffe23b770e25acab0ab9fb3059f14952d9464ebfa36a6274d8da",
    "317a7b07c2afe38ba28ca942cf7bfaee4020e59911c047b2aa24d1787baae1bc3546364b782358676d75c769",
    "8769f1d4a0d5dccade7fcf80e308437f7fc24fdfbf72625abf1b0f534da62cf860da1efd986950e3e19a0859",
    "99f4d008fce38459c673befcdf2287c1766e106beb4f3175e97812da141330dcb2beb3265e38c8423c19dd50",
    "a655c9e8dc969f6367f3383b644d53a26875d53cea26de429266b506e70e7e6832886ed06d81738b0b482bd2",
    "3bda396eb674ddfdb64803d6c4fae2f040170b5a28923279838b7b876220d02dc7478666f7c3287b1ba4a2f8",
    "228e8c491a55ba459805c601b986caea27ee9436f63383351c74d673643b15f6007fc6dc49e337a65a8a96ec",
    "d7eef4ad730bf3dc1972fc396703ee26af1156dc4beb46c47d99bb69ebdaf81c2d738d0f70e57a2c7162f5a5",
    "5242255675f22082aa43f5b3dd862b535b2a15bb815b4e9faf16a302552cd6098d40930dfad7a7c609d6aead",
    "e814242a8bf0721c1c26d0d3daa7a638880a6411c6538d80c259d31b639aadaea49563a8d7f5ddb64291d6b0",
    "86c80d72bfe7d26802cbd20fd6ba5495011e42da1c82483cbe8e37838e73c48f79f65b205476bee600399fed",
    "a6aaaa939eee12cb34be4e6bdbd18032c85b54a2713551de677a16ca0142ff97b77bc963e8f3c57d91df9b49",
    "474b01ca514641842893abc3181caee3f49b635d17daf41bcc4aeb1116ec4b3e78ff1480cf3a5d9c6a154384",
    "b88516834d19196976e2ba97cee91f7a0d73f7f8146e58dc0fc8f510511d39d82a7ba531a4abcce6b624035d",
    "753a37c5980343cfc7724cf83efb0c33fc4abb5b002241bf57a46b67cb5a4cbd637b2f19bc93b368d97e13c6",
    "a62c8443c8222e0a90c3ed1972cc739b824fdf729ed8eca02ad96bd78bf6d2b3d2853e24fa93199ff4163517",
    "6b31aab2207013d0a9317fa49668dfeb672b8129e6175a2998642ab8e74f0823e3b5480ae80180ca395f5348",
    "744a3c7b344891f008aab65914760b5fe852615ad6425216b1c5e777db1a46517cd01a77b277cfa2c6f250c2",
    "d68c495fef28feee6e0716817d6b30716f5ca48001805042133eca17a41c2219784ce0f12858ccfd371c77b9",
    "0966ea04c3996851edf31aef962946628007de5531b06fddf3449f6c552eaf6e16b3e9160e265900b8c8e414",
    "732505e02660e123d45a3d6f1b15e56fd759d38e821e27e84967e95c4b0d2a48e008897e655d1b65b76299f1",
    "e3074209abe44b37f8786b02df23aa4dcebe512e6312f1a3d6d781d749635247aca897626f5ee688f517df6c",
    "fe947ddead820f07fed4bcbe7f1bee3f19117b5666dc123d528f2bf03db346d6afb53804b0681aea98a9479f",
    "c6de5ae974d2c0d2055f07ba8a1d2d8b6a7e08a6805bd8634cc190c4988b502f475c36d78c7b3dda0057c818",
    "835bbf21c5a7c13bb6fd91cd3cfd76abe4c2ff908a08a3000b9021500ff94b297cec0fb3e51b1cae7026ab43",
    "47bfd5b6a641a3d347f45a2a2aacd22e521e00da0c3986c67672c5d7d7e61e7edafc15d42aa42cb37fa8621f",
    "79e9096b092efe853ab318b3e4bbd90f20165a1be1d3aa5b3de43751b65abbd952599869778393c4351ab8f5",
    "34fd49e16547df01c40bfaf56de60b4fb0019bc34177cc8e2236d219fb3c0b84dedae6b88e134280eabd1823",
    "420cd1afe6d929774967fd7d885fbad33d89ed9dc5e0eb978eab5d96c50bed5887aa8277880c7b06bf2780ce",
    "e82ce639a1e3344c88a25102edcc17a4cb48989c4ad6a998726ede31deb0b98107f40858bad7864983f6ecdf",
    "0c9761a42751b19d5360daa7fddbbd2e2292638b95c763ca1e747eedef0dd387e9d9ec9e5afee207d8c45703",
    "c5befc2de3878d313655ce85ad984250cdf054360f33d41dc193060d42cf9528b1fb91d6ca3395199e25a1a7",
    "739eba9a6a4ac2c417ae615940b3eb1b746dd0ecc7b2f7acdff887110115629f70877dafcd7a6625fa1b9e25",
    "6bc8fe1d66005dbcf12fde0a5fcda5d4f23d58ece91d60eb91274df8d9d17d4a39e63533acf1b317db979b04",
    "ca3ab9a0bcba652d0010ca3fcd33ed8f8a62faf42f78b37912d3adb410f20bf16b31359cacc25fb783083a3f",
    "065f0a2dd6fe58b8f594e11a87bf0f4c5f5493f334c18b03ebdefebce50228937ec13a8c221b617450486291",
    "071f3c14f64f66c927dd4bd623c214ac35433b8a6875cdf00916476eac0f196858aa1484bc1cd45b726d33a9",
    "65619829b8deaa9d9fa0c3c210f23967ce26a4bdd939cff8aa662f70fb0af97ee44bcb9e2755000a195741d8",
    "919e4dcb1a5caae21009f686fa1489c72f16f9fee76b5410ece7f406947f4a19f394a5121da79f3216777b0f",
    "ee5423328156ecf0b4548dbd5b3f7b526d6b9cfd57576f67dd521c314c2d37474ed0cf732c3b073a101c735a",
    "4c4e6b33c9aaa12c91d147ad1075a20287d36c388657614a9c648d8e49cce8cfa282b2a2e8e9da6e4444e4b6",
    "aed1bd0ada5009a335cd0500bdae9a01b97f7e8cfe8372398e750de92ee4a524393a19826d19de5e762fb53a",
    "88b9b4657e9c6d7d01a4124e3e39532f614aec5cb88d982b78b2ff568017c92f6a1ce5298b5f323b5ee61695",
    "038ef0c3a7a339cfac31cf7875a4563046a40e7b35cef1d37d811b342fcbb5373122415befc23cb656a619f7",
    "c262c443403b23ba20e341a079918dec6f4f801b92781179ad7ac1951f39ddb0b1f1fb95b28c0f4593a04486",
    "f0e0e86bb3b014674879aad10f41e0bad34d40bc817b6fd43c1dde8547882d82e5111e208107e9c9736d16ca",
    "77ac7453d7b6c7976a7dd6a4c6c0252185bc9948660a07b66151b09b980d8572ae829ab2f6d900cc63066c4e",
    "cb3a0317e8a9acaa8e22a216721f3d69c67843df2fbedd88bc424f761cdf420de4ff2c55b6925b1826c1c413",
    "4090d2aae82a7f64a8d428efe1b21097a6fdbc9b8a31c4d46c7b32d478bf5b9181bef8af4d3486958d7c198c",
    "46a5ad771090bb64e7fc2bd7677ae7618b861c83c13177075063517eff40cfd52ae56650e9e7035f783bfe89",
    "20c754e98470b327909ac2a407e07864710544b8adbc075502c75b5f0fdbca0cde5d94b013141c96b55ae1b6",
    "0ab63f9e792641690af41b05a78233935fd7f82852ebb2602a10459a709256c41d108c2aeb71925089cc79b1",
    "21eabd5edc54f3f7c8929685b88ab29700c7fb2f247cd7962c8ce6dc9f79f9358d6a7989d24ccc17d0dbaa0b",
    "7fbe73479164181ae7d6b6a02678cce46f74ea2bd387ecb73041817b429a0220e1c3635fe492f5f3a8e2b65c",
    "086fe24c375563d7220856dd8f970716d548492964a156554dc88810c3c4f81dcc3ae80243e19679a3be9c9b",
    "1b8c707b416e9166c54a568bb9d84728c1a283d9231a12b13688ce2362901342652d66bf44cec223f561d273",
    "5d977c6adcf57e9066220d0770fc77fdf6ff367a2f36ae20062887beb88d1b453f267aef9bc763ab716bacb9",
    "214c38b95f4f2f3f6c236aa71aef83c1ae4b26133678884476c1d7c6d3e7b99f13e028ac6cebddfae4793f9a",
    "e975f3d66b725b500e7c7d2f664eaa0c358deb91cb2d6173394b306749d2bfb2684b985769bdb682e922b755",
    "55d38dad1899057a64ef6ea361e4712244d02d0dfec8c3d40770122770c2538d6a14a8462ef18eb705c16e5b",
    "a30aa5366447c94869060e4df155f7d01ffda04c1ced0ad5fbe5fdd85856e1e49320319687d31a6e4c714547",
    "9f45f43a9b8e9ffe4cbacfad4a21e5445e119df2996cce8b11d0f224efb4f18b544d456e2fb1d96fcd99fc31",
    "9dbd86720621ac25b490f3611f7e5655bb3940a503c07dbf41f4b87593595a66008808744668371a54ce1b9d",
    "fdaa16f90415e57470bc23898d13d8351ba34369e96347da13d012b4eab32ada90668654c5ed2b433716b1b4",
    "170f640cf4b40659efcf4150237bbc25f72b248be85cd482b55ce2f5f73e8f02efd2465805b37d12487465ec",
    "1085bc6602b71862771af13e13baece4916b1ddef9ce016c92db9fb9e82aee5e1c4e22c45090ad1c19801ce1",
    "c541ff3902baea7a12dbcac6ec2d128ac7acb203463921ca6ce1d182d60d553ddecc4a3175eec2e924e9191e",
    "0d69aa49ca0b653495b8c62b802e443e669220f2a4047a56ed5cb7431a3387a435070795e6e63d242a74555e",
    "97371989c6d0040748e89ac316618d5d6eb7bff8d91e953afbe00464df4e4f6380c273b7ac5934cacb6c3be4",
    "da6649c8a5ea12bdf9afa1ec1e5053db7668c10ae2df75c4b3b14525369bf33741525a7630158aca3d3c7da5",
    "c1d71d3f63c0c2948a43236968d623c6c163eb757f0c78d6ae682ff4e4b673be07193e8d6c106c92851b393f",
    "0523491d5152e06de675fa22ae7bded329836a8ca0b955a59cb575395952c6ea0cb1644f2cada196b96b44ee",
    "12115ff9668e32886103d8f8109fac4a2287738ee1d2d4c1c19dab94eaa2757ea32016df60d7286099eb010b",
    "a570b5791ce4c54d860b15d56c53a5ddb543b0b602b3a87ca5213aa9647e51b1cb1736697506081240f4f716",
    "3a646f2be30e62c617d7572d820a113f96320834a2f43842160511923bd1ef4f723a2ab9b242fffe97cf0199",
    "c9f2ebca266a63beea0af279f2d18651b2ea9789d03025857c8aefc5f8bc6ee92ab7c6ffed2606f9c7ef25cb",
    "6c96140256a08cc58218869c52f3e5074fe5ace87a86057cc29fc845ff275f1b2dbc5991cbebe4c556b29ce3",
    "da3415958f0c9c68a5c664a1da60365ce56b9a4df24ec5d69c6f5a2e685885f6973c0ccd4caf7e000346bdea",
    "502b1418c8819e05bb7bee31bbd235819b49c892f7dadade576cb8ca68bda916a598c32ec03cceba2d01a796",
    "0f38680facccdaaf05e254dd8c3631a7222d1561c998c54b16f17a425f3247232dca035d545202e1b1803402",
    "19ce31c66987bc86f983240e7fd2c926e8af77e6ea9f4139ff1edc0c323b67ceadead8f64a8004164d942f6a",
    "a65a28544d7205d41aafe62c5bfc6fd9fc322e2a8b620532d00d1add7a0d25a9dbaff90e19de14ac2ca97e83",
    "a2d77e63888ba0f7eaf9b18a7f2e5f148d16887580e55e894ae79024385f439acd071494e6469b77d07e7635",
    "53652a470f3b4bd8bb7968052f3a969dacced51572bd125870849ce3e55359b2e17eabc3153b5f62868ea0ca",
    "1f40738488dbe0020c103f53678b9eb1c1000000000000000000000000000000000000000000000000000007",
    "0a111518202731"]
  let zetasOk := (List.range 4).map (fun i => zetas[i + 1]!) == [4808194, 3765607, 3761513, 5178923]
  match hexToBytes? pkHex, hexToBytes? sigHex, hexToBytes? "48656c6c6f20776f726c64" with
  | some pk, some sig, some msg =>
    let flipped := sig.set! 0 (sig[0]! ^^^ 1)
    let zeroKey := ByteArray.mk (Array.ofFn (n := 2592) fun i =>
      if i.val < 32 then UInt8.ofNat (i.val + 1) else 0)
    let zBytes := ByteArray.mk (Array.ofFn (n := 4480) fun i =>
      if i.val % 5 == 2 then 0x08 else if i.val % 5 == 4 then 0x80 else 0)
    let w1 := ByteArray.mk (Array.replicate 1024 0)
    let cTilde := shake256 (mu zeroKey msg ByteArray.empty ++ w1) 64
    let zeroSig := cTilde ++ zBytes ++ ByteArray.mk (Array.replicate 83 0)
    zetasOk && verify pk msg ByteArray.empty sig && !verify pk msg ByteArray.empty flipped
      && verify zeroKey msg ByteArray.empty zeroSig
  | _, _, _ => false

end Spec.MlDsa
