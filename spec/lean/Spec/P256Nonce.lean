import Spec.Bytes
import Spec.Hkdf
import Spec.P256

/-!
The ECDSA P-256 nonce `p256_sign.c` derives (docs/decisions.md 147 and
153). It is RFC 6979 §3.2 over HMAC-SHA-256, or the hedged form of
draft-irtf-cfrg-det-sigs-with-noise-05 §4, whose steps d and f put fresh
bytes Z and zero bytes around the private key. Written from the two texts,
with HMAC from `Spec.Hkdf`.

`Spec.P256.ecdsaSign` takes the nonce as an input, so it states nothing of
the derivation. `sign?` composes the two, and the differential compares
it with the signature the C writes, byte for byte, in both forms.

The C makes four candidates and takes the first in [1, n-1]; `nonce?` is
that rule. RFC 6979 makes candidates until one is in range, so the two
agree unless the first four all fail, which is below 2^-128.
-/
namespace Spec.P256Nonce

open Spec.Bytes
open Spec.Hkdf (hmac zeros)

/-- RFC 6979 §2.3.4, bits2octets(h1), for P-256 with SHA-256: qlen and
hlen are both 256, so it is the hash as an integer, reduced mod n, in 32
bytes. -/
def zOctets (hash : ByteArray) : ByteArray :=
  natToBytesBE (bytesToNatBE hash % Spec.P256.n) 32

/-- The zero bytes that take `len` bytes to the next multiple of the
SHA-256 block, 64 bytes: the draft's "smallest possible multiples of the
block size". -/
def padTo (len : Nat) : Nat := (64 - len % 64) % 64

/-- The bytes after V and the separator in steps d and f. With no noise it
is RFC 6979's int2octets(x) ‖ bits2octets(h1). With noise Z it is the
draft's Z ‖ 000… ‖ int2octets(x) ‖ 000… ‖ bits2octets(h1), where the
first zeros take V ‖ 0x00 ‖ Z to a whole number of blocks, and the second
take int2octets(x) to one. -/
def tail (d : Nat) (hash : ByteArray) : Option ByteArray → ByteArray
  | none => natToBytesBE d 32 ++ zOctets hash
  | some z =>
    z ++ zeros (padTo (32 + 1 + z.size)) ++ natToBytesBE d 32 ++ zeros (padTo 32) ++
      zOctets hash

/-- RFC 6979 §3.2 steps b through g, over a tail: the (K, V) the
candidates start from. -/
def init (t : ByteArray) : ByteArray × ByteArray :=
  let v₀ := ByteArray.mk (Array.replicate 32 1)
  let k₁ := hmac (zeros 32) (v₀ ++ ByteArray.mk #[0] ++ t)
  let v₁ := hmac k₁ v₀
  let k₂ := hmac k₁ (v₁ ++ ByteArray.mk #[1] ++ t)
  (k₂, hmac k₂ v₁)

/-- RFC 6979 §3.2 step h: the first `count` candidates, in range or not.
qlen is one HMAC output here, so each candidate is one V. Step h.3's update
runs after every candidate. -/
def candidates : Nat → ByteArray × ByteArray → List Nat
  | 0, _ => []
  | c + 1, (k, v) =>
    let v' := hmac k v
    let k' := hmac k (v' ++ ByteArray.mk #[0])
    bytesToNatBE v' :: candidates c (k', hmac k' v')

/-- The nonce: the first of four candidates in [1, n-1], as the C takes
it, or `none`. -/
def nonce? (d : Nat) (hash : ByteArray) (noise : Option ByteArray) : Option Nat :=
  (candidates 4 (init (tail d hash noise))).find? (fun t => 0 < t && t < Spec.P256.n)

/-- The signature `p256_sign` writes (no noise) or `p256_sign_hedged` writes
(noise Z): ECDSA over the derived nonce. -/
def sign? (d : Nat) (hash : ByteArray) (noise : Option ByteArray) : Option (Nat × Nat) := do
  let k ← nonce? d hash noise
  Spec.P256.ecdsaSign d k (bytesToNatBE hash)

/-! ## Proven properties -/

theorem zOctets_size (hash : ByteArray) : (zOctets hash).size = 32 :=
  natToBytesBE_size _ _

/-- RFC 6979's tail is 64 bytes. -/
theorem tail_none_size (d : Nat) (hash : ByteArray) : (tail d hash none).size = 64 := by
  simp [tail, ByteArray.size_append, natToBytesBE_size, zOctets_size]

/-- The hedged tail with 32 bytes of noise is 191 bytes: 32 of noise, 63
zeros, 32 of key, 32 zeros and 32 of hash. -/
theorem tail_some_size (d : Nat) (hash z : ByteArray) (hz : z.size = 32) :
    (tail d hash (some z)).size = 191 := by
  simp [tail, ByteArray.size_append, natToBytesBE_size, zOctets_size, zeros, zeros_size, hz,
    padTo]

/-- The private key starts a SHA-256 block of the step d and f input:
V and the separator are 33 bytes, so 33 + 32 bytes of noise and its zeros
end at 128. -/
theorem key_starts_block (z : ByteArray) (hz : z.size = 32) :
    (32 + 1 + z.size + padTo (32 + 1 + z.size)) % 64 = 0 := by
  simp [hz, padTo]

/-- The draft's separation from RFC 6979: no hedged tail is an RFC 6979
tail, for any key, hash or noise of 32 bytes, because the two lengths
differ. So the HMAC input of step d is never the same in the two forms. -/
theorem tail_some_ne_none (d d' : Nat) (hash hash' z : ByteArray) (hz : z.size = 32) :
    tail d hash (some z) ≠ tail d' hash' none := by
  intro h
  have := congrArg ByteArray.size h
  rw [tail_some_size d hash z hz, tail_none_size] at this
  omega

/-- A nonce is in [1, n-1]: the range `p256_sign.c` requires before it
multiplies. -/
theorem nonce?_range {d k : Nat} {hash : ByteArray} {noise : Option ByteArray}
    (h : nonce? d hash noise = some k) : 0 < k ∧ k < Spec.P256.n := by
  have := List.find?_some h
  simpa using this

set_option compiler.extract_closed false in
/-- RFC 6979 §A.2.5's P-256/SHA-256 nonces for "sample" and "test", and one
hedged answer over the same key: noise 0x01 to 0x20 for "sample". The
hedged answer comes from `test/gen_p256_sign_vectors.py`, which computes
it with Python's integers and `hmac` module and not from this file. -/
def selftest (_ : Unit) : Bool :=
  let d := 0xc9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721
  let sample := Spec.Sha256.sha256 (ascii "sample")
  let test := Spec.Sha256.sha256 (ascii "test")
  let noise := ByteArray.mk ((List.range 32).map (fun i => (i + 1).toUInt8)).toArray
  nonce? d sample none ==
      some 0xa6e3c57dd01abe90086538398355dd4c3b17aa873382b0f24d6129493d8aad60 &&
    nonce? d test none ==
      some 0xd16b6ae827f17175e040871a1c7ec3500192c4c92677336ec2537acaee0008e0 &&
    nonce? d sample (some noise) ==
      some 0x8bcee63c9559529dc95dae6e88b84b7c043b19d464a9821b2bae1ad97094b29e &&
    sign? d sample (some noise) ==
      some (0x8f921763c1baa901677fce6df8f6459a7e4d16d80ebd445ef9777c2f1e0517a4,
        0x81d38968695b0309dfe50026d2456411d823e07e22e536d67236d5d5d08444dd)

end Spec.P256Nonce
