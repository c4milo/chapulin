import Spec.Bytes
import Spec.Rsa

/-!
RSASSA-PKCS1-v1_5 with SHA-256 or SHA-384, written from PKCS #1 v2.2
(RFC 8017) only. This is the signature a public CA writes on a
certificate; CertificateVerify stays RSASSA-PSS (`Spec/Rsa.lean`).

The RSA primitives are `Spec.Rsa`'s `rsavp1` and `rsasp1`; I2OSP/OS2IP
are the big-endian byte codings in `Spec/Bytes.lean`. EMSA-PKCS1-v1_5
(§9.2) is an encoding with no mask and no salt: the verifier rebuilds
the whole encoded message from the digest and compares it to the
recovered one — encode-and-compare, the shape the C follows, so no
parser of the recovered bytes exists to be lenient.

The digest's length alone selects the DigestInfo: 32 bytes is SHA-256,
48 is SHA-384, and any other length encodes nothing. Signing lives here
so the oracle can mint signatures the C verifier must accept; the C side
only ever verifies.

The modulus is any `Nat`, as in `Spec/Rsa.lean`; the C admits 256 to
`CH_RSA_MODULUS_MAX` bytes (512 under `CH_TRUST_WEBPKI`, the build this
verifier ships in), and the differential (`test/diff_rsa_pkcs1.h`)
samples 2048, 3072 and 4096-bit moduli at both digest lengths.
-/

namespace Spec.RsaPkcs1

open Spec.Bytes

/-- RFC 8017 §9.2 note 1: the DER DigestInfo prefix for SHA-256 —
`SEQUENCE { SEQUENCE { id-sha256, NULL }, OCTET STRING (32) }` with the
digest as the OCTET STRING's content, 19 bytes. -/
def digestInfoSha256 : ByteArray := ByteArray.mk #[
  0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
  0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20]

/-- RFC 8017 §9.2 note 1: the same prefix for SHA-384, 19 bytes. -/
def digestInfoSha384 : ByteArray := ByteArray.mk #[
  0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
  0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30]

/-- The DigestInfo a digest length selects: SHA-256 for 32 bytes, SHA-384
for 48, and nothing for any other length. -/
def digestInfo? (digestLen : Nat) : Option ByteArray :=
  if digestLen == 32 then some digestInfoSha256
  else if digestLen == 48 then some digestInfoSha384
  else none

/-- The three fixed bytes of the encoded message besides PS: `0x00`,
`0x01`, and the `0x00` separator (§9.2 step 5). -/
def overhead : Nat := 3

/-- The shortest padding string §9.2 step 3 admits: eight `0xff` bytes. -/
def psMin : Nat := 8

/-- EMSA-PKCS1-v1_5-ENCODE (§9.2): `0x00 ‖ 0x01 ‖ PS ‖ 0x00 ‖ T` with
`T = DigestInfo ‖ digest` and `PS` a run of `0xff` at least `psMin`
long; `none` when `emLen` is too short (step 3) or the digest length
names no hash. -/
def encode? (digest : ByteArray) (emLen : Nat) : Option ByteArray :=
  match digestInfo? digest.size with
  | none => none
  | some info =>
    let t := info ++ digest
    if emLen < t.size + overhead + psMin then none
    else
      let ps := ByteArray.mk (Array.replicate (emLen - t.size - overhead) 0xff)
      some (ByteArray.mk #[0x00, 0x01] ++ ps ++ ByteArray.mk #[0x00] ++ t)

/-- RSASSA-PKCS1-V1_5-VERIFY (§8.2.2) with modulus `n`, public exponent
`e`, the message digest, and the signature octets: the signature is
exactly `k` octets (step 1), its integer is below `n` (RSAVP1 step 1),
and RSAVP1 of it, written as `k` octets, equals the digest's encoding
(steps 2–4). -/
def pkcs1Verify (n e : Nat) (digest sig : ByteArray) : Bool :=
  let k := (Spec.Rsa.bitLen n + 7) / 8
  if sig.size != k then false
  else
    let s := bytesToNatBE sig
    if s ≥ n then false
    else
      match encode? digest k with
      | none => false
      | some em => bytesToHex (natToBytesBE (Spec.Rsa.rsavp1 n e s) k) == bytesToHex em

/-- RSASSA-PKCS1-V1_5-SIGN (§8.2.1) with private exponent `d`, so the
oracle can mint signatures the C verifier must accept; `none` when the
modulus is too short for the encoding. -/
def pkcs1Sign (n d : Nat) (digest : ByteArray) : Option ByteArray :=
  let k := (Spec.Rsa.bitLen n + 7) / 8
  match encode? digest k with
  | none => none
  | some em => some (natToBytesBE (Spec.Rsa.rsasp1 n d (bytesToNatBE em)) k)

/-- The encoding is exactly `emLen` octets whenever it exists
(§9.2 step 5): two fixed bytes, the padding, the separator, and `T`. -/
theorem encode_size (digest : ByteArray) (emLen : Nat) (em : ByteArray)
    (h_encode : encode? digest emLen = some em) : em.size = emLen := by
  unfold encode? at h_encode
  cases h_info : digestInfo? digest.size with
  | none => rw [h_info] at h_encode; simp at h_encode
  | some info =>
    rw [h_info] at h_encode
    simp only [] at h_encode
    split at h_encode
    · simp at h_encode
    · rename_i h_fits
      simp only [Option.some.injEq] at h_encode
      subst h_encode
      have h_two : (ByteArray.mk #[0x00, 0x01]).size = 2 := rfl
      have h_one : (ByteArray.mk #[0x00]).size = 1 := rfl
      have h_ps : ∀ m : Nat, (ByteArray.mk (Array.replicate m (0xff : UInt8))).size = m :=
        fun m => by simp [ByteArray.size]
      rw [ByteArray.size_append, ByteArray.size_append, ByteArray.size_append, h_two, h_ps, h_one]
      simp only [overhead, psMin] at h_fits ⊢
      omega

/-- A signature of the wrong length never verifies (§8.2.2 step 1). -/
theorem pkcs1Verify_sig_size (n e : Nat) (digest sig : ByteArray)
    (h_len : sig.size ≠ (Spec.Rsa.bitLen n + 7) / 8) :
    pkcs1Verify n e digest sig = false := by
  unfold pkcs1Verify; simp [h_len]

/-- A signature the signer produced is exactly `k` octets
(§8.2.1 step 3). -/
theorem pkcs1Sign_size (n d : Nat) (digest sig : ByteArray)
    (h_sign : pkcs1Sign n d digest = some sig) :
    sig.size = (Spec.Rsa.bitLen n + 7) / 8 := by
  simp only [pkcs1Sign] at h_sign
  cases h_encode : encode? digest ((Spec.Rsa.bitLen n + 7) / 8) with
  | none => rw [h_encode] at h_sign; simp at h_sign
  | some em =>
    rw [h_encode] at h_sign; simp at h_sign; subst h_sign; exact natToBytesBE_size _ _

/-- A digest whose length names no hash never verifies: there is no
DigestInfo to encode against. -/
theorem pkcs1Verify_digest_len (n e : Nat) (digest sig : ByteArray)
    (h_none : digestInfo? digest.size = none) :
    pkcs1Verify n e digest sig = false := by
  unfold pkcs1Verify encode?; simp [h_none]

set_option compiler.extract_closed false in
/-- Sign-then-verify round trips over the 2048-bit key `Spec/Rsa.lean`'s
selftest carries, with a SHA-256-length and a SHA-384-length digest; a
one-byte flip of either digest is rejected, a signature verified against
the other digest length is rejected, and a 20-byte digest signs nothing.
Then an OpenSSL-minted RSA-2048/SHA-256 signature — the bytes
`test/rsa_pkcs1_vectors.h` carries, from `openssl dgst -sha256 -sign` —
verifies and rejects a flipped digest. -/
def selftest (_ : Unit) : Bool :=
  -- A malformed literal falls back to a 1-byte sentinel and breaks the
  -- length-sensitive checks instead of testing the empty string.
  let hx := fun s => (hexToBytes? s).getD (ByteArray.mk #[0])
  let n := 0xa59931eebcc909b93406f4c6999c3b86e086bea972203cb921e806c42c0d73b87b9db6647e15753e232c1f8b8fdfac6210e9866b5eec09ffd62eacfc16b67bcd736d90dae48435130a247e054a4bf821b1c0ccd673ec3240f8686b46e22689c0ab86fd2329a8e10a0fcea94df123459a3ae4d2de6aad52b850c2955e38155be708e9f6dafdc9934e661503bc69463f962aa1f0dabb8427ce065a0f2e6e2bf7650ba0e9c4532d03fb50e5c45447090f00b1e99dd44ba351fb3c78dc2cbf7860e3285789f39a758eb8c314c493d5baf351ba82c3381e4c940574b37f891e63ed5daae377df24ab67d717d5621aa7dc87046359d5b61910ad63d01e56d9bec95a7b
  let e := 65537
  let d := 0x2bd7f91bebd8d05dbc1421679990ff43b11b8bcc621e7de548405dd63f919a335c6b3fb8b0972ed0f25002d419160fd67102db277f5cc032ffbaa0eb277a4e21f1af2f1c7d4731a42659ce11c97f7ea531224a39773cb07b7a296f49b7a39b722b17d4daa3f3860d7b6cec6f69ea3c49ded0e9b1a08dde2a559b871f887ac337653e73889f8e67b4792ef87e7d53270abcb193e68d576ed631b3756b5f9468c27b006fe67380f3078143774a0567cf1160581bb562768f1e1e1c5371d62ee56d6df2e444f8f516acc5b3330a49d66b6081fc1f1d77ffa212223123208e5a773ece826038c46a425d04787317ff2cb895b4b6710234434263f83f9aa2764c3071
  let h256 := hx "af96472d3b9a625e8ede207d21da78af279fb5ffc7692c73c20813e2d71a15cd"
  let h384 := hx ("9a9083505bc92276aec4be312696ef7bf3bf603f4bbd381196a029f340585312" ++
                  "313bca4a9b5b890efee42c77b1ee25fe")
  let flip := fun (b : ByteArray) => b.set! 0 (b[0]! ^^^ 1)
  (match pkcs1Sign n d h256, pkcs1Sign n d h384 with
   | some s256, some s384 =>
     pkcs1Verify n e h256 s256 && pkcs1Verify n e h384 s384 &&
     !pkcs1Verify n e (flip h256) s256 && !pkcs1Verify n e (flip h384) s384 &&
     !pkcs1Verify n e h384 s256 && !pkcs1Verify n e h256 s384 &&
     !pkcs1Verify n e h256 (s256.extract 0 255)
   | _, _ => false) &&
  pkcs1Sign n d (hx "0102030405060708090a0b0c0d0e0f1011121314") == none &&
  -- The OpenSSL-minted vector, independently re-verified in Python as
  -- sig^65537 mod n against the v1.5 encoding before it was embedded.
  (let n2 := 0x9a3d639cab8cd64c94713bc43dfa21319a75ee87549b0512cb647dfded714f3b3babcd4efcb91adde9985126a0e703c2b1dc570ac6c05498d3b7759bd1cbf067716b384c6af35c55c88f3a14e44b73a80efc7e9e6aa420f0a9687439ed4f9ef38ffe8d62c818d5dfb4815d88a8e7f6c770e18514fa19dacaa064c3408055e720ef65f3a32e0bbbd8d7b0080f66cbef60e57585dd89d86ebe1f997db85b09018cd965a4d33ede2b19acb0a67bd35a186669e28275b21128b395508bc73f7d3986fdebb7a0e32a20f71df50d6c925e2546227a91b22e12c600ccb75fd67d833a53d10467482c73d836738d5ad4f603cf657ca8d8c3b556fe5cccb36a4d103e70bb
   let digest2 := hx "795f893e2fa54bf999dd32687958488cec39d31a2f59996d294d9f2a3bd48c43"
   let sig2 := hx ("1f7a67a8961666d616597f4d5bd35e544a9af1e88731174ecbeae27e8466b12e" ++
                   "a6bcd77552298f3d789c52e135261c088dbc70f410b63d8f90f67ba10d9ee436" ++
                   "f8d07f4a0a5434594ec5ec890b69a4a48eeb4e995bc0fad0b10e34cdb1c79be0" ++
                   "eaefa7f90a1588ef2c39a6ea01ef6b859c3a8982225d4d26d9defdce276aefb9" ++
                   "5654378431f0cacc3530998d2cb39c236faf4d582c64cdebc974118c6896540b" ++
                   "9096827c35b416a554736866476fd90838e4b352549cd7b5997f1f56963f3a52" ++
                   "d2eb97f864358f787ba95c74465424b1596701a4c1a57c9690ff7de0bc674aa2" ++
                   "13507dfe5f789b5984e15f0b601cb5139bf2d6c3504a13ad3043231e79c01f7a")
   pkcs1Verify n2 e digest2 sig2 && !pkcs1Verify n2 e (flip digest2) sig2)

end Spec.RsaPkcs1
