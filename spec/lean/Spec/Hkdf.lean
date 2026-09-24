import Spec.Sha256
import Spec.Sha512

/-!
HMAC (RFC 2104), HKDF (RFC 5869), and the TLS 1.3 key-schedule pieces built
on them (RFC 9846 §7.1), over SHA-256 and SHA-384. Written from the RFC
text only.

Every definition takes the hash as a `Hash`: its block size, its output
length and the function. RFC 9846 §7.1 makes the cipher suite's hash the
one Transcript-Hash and HKDF use, so SHA-256 serves
TLS_CHACHA20_POLY1305_SHA256 and TLS_AES_128_GCM_SHA256 and SHA-384 serves
TLS_AES_256_GCM_SHA384. The names without `With` are SHA-256's, which the
other modules read.
-/

namespace Spec.Hkdf
open Spec.Bytes
open Spec.Sha256 (sha256)

/-- A hash as RFC 2104 and RFC 5869 use it. -/
structure Hash where
  /-- RFC 2104 §2: B, the input block size in bytes. -/
  blockSize : Nat
  /-- RFC 5869 §2: HashLen, the output size in bytes. -/
  hashLen : Nat
  /-- The hash function. -/
  digest : ByteArray → ByteArray

/-- SHA-256: B = 64 and HashLen = 32 (FIPS 180-4 §1). -/
def sha256H : Hash := ⟨64, 32, sha256⟩

/-- SHA-384: B = 128 and HashLen = 48 (FIPS 180-4 §1; SHA-384 takes
SHA-512's block). -/
def sha384H : Hash := ⟨128, 48, Spec.Sha512.sha384⟩

/-- RFC 2104 §2: B for SHA-256. -/
def blockSize : Nat := sha256H.blockSize

/-- RFC 5869 §2: HashLen for SHA-256. -/
def hashLen : Nat := sha256H.hashLen

/-- `n` zero bytes. -/
def zeros (n : Nat) : ByteArray := ByteArray.mk (Array.replicate n 0)

/-- RFC 2104 §2: `HMAC(K, text) = H(K ⊕ opad ‖ H(K ⊕ ipad ‖ text))` with
ipad = 0x36 and opad = 0x5c repeated B times. Keys longer than B are first
hashed; shorter keys are zero-padded to B bytes. -/
def hmacWith (h : Hash) (key msg : ByteArray) : ByteArray :=
  let k0 := if key.size > h.blockSize then h.digest key else key
  let k := k0 ++ zeros (h.blockSize - k0.size)
  let ipad := ByteArray.mk (Array.replicate h.blockSize 0x36)
  let opad := ByteArray.mk (Array.replicate h.blockSize 0x5c)
  h.digest (xorBytes k opad ++ h.digest (xorBytes k ipad ++ msg))

/-- RFC 5869 §2.2: `HKDF-Extract(salt, IKM) = HMAC-Hash(salt, IKM)`, PRK is
HashLen bytes. (The §2.2 default of a HashLen-zero salt is the caller's
choice; note HMAC zero-pads keys, so an empty salt is equivalent.) -/
def extractWith (h : Hash) (salt ikm : ByteArray) : ByteArray :=
  hmacWith h salt ikm

/-- RFC 5869 §2.3: `HKDF-Expand(PRK, info, L)` — `N = ceil(L/HashLen)`,
`T(0) = empty`, `T(i) = HMAC-Hash(PRK, T(i-1) ‖ info ‖ i)` for a single
octet counter `i`, output the first L bytes of `T(1) ‖ … ‖ T(N)`.
§2.3 limits `L` to `255 * HashLen`, the most the single-octet counter can
emit; the dispatcher enforces the bound. -/
def expandWith (h : Hash) (prk info : ByteArray) (len : Nat) : ByteArray := Id.run do
  let n := (len + h.hashLen - 1) / h.hashLen
  let mut t := ByteArray.empty
  let mut okm := ByteArray.empty
  for i in [1:n+1] do
    t := hmacWith h prk (t ++ info ++ ByteArray.mk #[UInt8.ofNat i])
    okm := okm ++ t
  return okm.extract 0 len

/-- RFC 9846 §7.1: `HKDF-Expand-Label(Secret, Label, Context, Length)` =
`HKDF-Expand(Secret, HkdfLabel, Length)` where HkdfLabel is

    struct {
        uint16 length = Length;
        opaque label<7..255> = "tls13 " + Label;
        opaque context<0..255> = Context;
    } HkdfLabel;

i.e. a 2-byte big-endian length, then the 1-byte-length-prefixed label
with the "tls13 " prefix, then the 1-byte-length-prefixed context. -/
def expandLabelWith (h : Hash) (secret : ByteArray) (label : String) (ctx : ByteArray)
    (len : Nat) : ByteArray :=
  let lab := ascii ("tls13 " ++ label)
  let info := natToBytesBE len 2
      ++ natToBytesBE lab.size 1 ++ lab
      ++ natToBytesBE ctx.size 1 ++ ctx
  expandWith h secret info len

/-- RFC 9846 §7.1: `Derive-Secret(Secret, Label, Messages) =
HKDF-Expand-Label(Secret, Label, Transcript-Hash(Messages), Hash.length)`.
The caller supplies the transcript hash directly. -/
def deriveSecretWith (h : Hash) (secret : ByteArray) (label : String)
    (transcriptHash : ByteArray) : ByteArray :=
  expandLabelWith h secret label transcriptHash h.hashLen

/-- `Transcript-Hash("")` — the hash of the empty transcript, used where
RFC 9846 §7.1 writes `Derive-Secret(., "derived", "")`. -/
def emptyHashWith (h : Hash) : ByteArray := h.digest ByteArray.empty

/-- RFC 9846 §7.1 key schedule with a PSK, ECDHE, and no early data:

    Early Secret     = HKDF-Extract(salt = 0, IKM = PSK)
    Handshake Secret = HKDF-Extract(Derive-Secret(Early, "derived", ""), ECDHE)
    cHs / sHs        = Derive-Secret(Handshake, "c hs traffic" / "s hs traffic",
                                     ClientHello..ServerHello)   [helloHash]
    Master Secret    = HKDF-Extract(Derive-Secret(Handshake, "derived", ""), 0)
    cAp / sAp        = Derive-Secret(Master, "c ap traffic" / "s ap traffic",
                                     ClientHello..server Finished) [finHash]

where `0` is a string of Hash.length zero bytes. Returns
`(cHs, sHs, cAp, sAp)`. -/
def scheduleWith (h : Hash) (psk ecdhe helloHash finHash : ByteArray) :
    ByteArray × ByteArray × ByteArray × ByteArray :=
  let early := extractWith h (zeros h.hashLen) psk
  let hs := extractWith h (deriveSecretWith h early "derived" (emptyHashWith h)) ecdhe
  let cHs := deriveSecretWith h hs "c hs traffic" helloHash
  let sHs := deriveSecretWith h hs "s hs traffic" helloHash
  let master := extractWith h (deriveSecretWith h hs "derived" (emptyHashWith h))
    (zeros h.hashLen)
  let cAp := deriveSecretWith h master "c ap traffic" finHash
  let sAp := deriveSecretWith h master "s ap traffic" finHash
  (cHs, sHs, cAp, sAp)

/-- HMAC-SHA-256. -/
def hmac : ByteArray → ByteArray → ByteArray := hmacWith sha256H

/-- HKDF-Extract over SHA-256. -/
def extract : ByteArray → ByteArray → ByteArray := extractWith sha256H

/-- HKDF-Expand over SHA-256. -/
def expand : ByteArray → ByteArray → Nat → ByteArray := expandWith sha256H

/-- HKDF-Expand-Label over SHA-256. -/
def expandLabel : ByteArray → String → ByteArray → Nat → ByteArray := expandLabelWith sha256H

/-- Derive-Secret over SHA-256. -/
def deriveSecret : ByteArray → String → ByteArray → ByteArray := deriveSecretWith sha256H

/-- SHA-256 of the empty string. -/
def emptyHash : ByteArray := emptyHashWith sha256H

/-- The key schedule over SHA-256. -/
def schedule : ByteArray → ByteArray → ByteArray → ByteArray →
    ByteArray × ByteArray × ByteArray × ByteArray := scheduleWith sha256H

/-!
Proven properties: output lengths. RFC 5869 §2.3 defines the OKM as
"the first L octets of T"; these lemmas discharge that clause for every
input and both hashes, so the key schedule always hands the record layer
exactly the keys and IVs it asks for.
-/

/-- SHA-256's digest is its HashLen. -/
theorem sha256H_digest_size (m : ByteArray) : (sha256H.digest m).size = sha256H.hashLen :=
  Spec.Sha256.sha256_size m

/-- SHA-384's digest is its HashLen. -/
theorem sha384H_digest_size (m : ByteArray) : (sha384H.digest m).size = sha384H.hashLen :=
  Spec.Sha512.sha384_size m

/-- HMAC answers one hash output (RFC 2104 §2: the outer hash's). -/
theorem hmacWith_size (h : Hash) (h_digest : ∀ m, (h.digest m).size = h.hashLen)
    (key msg : ByteArray) : (hmacWith h key msg).size = h.hashLen :=
  h_digest _

/-- HashLen times the block count HKDF-Expand computes covers the output
it keeps. -/
theorem blocks_cover (d len : Nat) (h_pos : 0 < d) : len ≤ d * ((len + d - 1) / d) := by
  have h_div := Nat.div_add_mod (len + d - 1) d
  have h_mod := Nat.mod_lt (len + d - 1) h_pos
  omega

/-- `HKDF-Expand(prk, info, len)` returns exactly `len` bytes: the loop
emits `HashLen * ceil(len/HashLen) ≥ len` bytes and the final extract
keeps `len`. -/
theorem expandWith_size (h : Hash) (h_digest : ∀ m, (h.digest m).size = h.hashLen)
    (h_pos : 0 < h.hashLen) (prk info : ByteArray) (len : Nat) :
    (expandWith h prk info len).size = len := by
  have h_fold := foldl_inv_idx (List.range' 1 ((len + h.hashLen - 1) / h.hashLen))
    (fun (b : ByteArray × ByteArray) (a : Nat) =>
      (hmacWith h prk (b.fst ++ info ++ ByteArray.mk #[UInt8.ofNat a]),
       b.snd ++ hmacWith h prk (b.fst ++ info ++ ByteArray.mk #[UInt8.ofNat a])))
    (fun k s => s.snd.size = h.hashLen * k)
    (ByteArray.empty, ByteArray.empty)
    (by simp)
    (fun k b a h_step => by
      simp [ByteArray.size_append, hmacWith_size h h_digest, h_step, Nat.mul_succ])
  simp only [List.length_range'] at h_fold
  have h_cover := blocks_cover h.hashLen len h_pos
  simp [expandWith, h_fold]
  omega

/-- HKDF-Expand-Label returns exactly `len` bytes, under either hash. -/
theorem expandLabelWith_size (h : Hash) (h_digest : ∀ m, (h.digest m).size = h.hashLen)
    (h_pos : 0 < h.hashLen) (secret : ByteArray) (label : String) (ctx : ByteArray)
    (len : Nat) : (expandLabelWith h secret label ctx len).size = len := by
  simp [expandLabelWith, expandWith_size h h_digest h_pos]

theorem hmac_size (key msg : ByteArray) : (hmac key msg).size = 32 :=
  hmacWith_size sha256H sha256H_digest_size key msg

/-- `HKDF-Expand(prk, info, len)` over SHA-256 returns exactly `len`
bytes. -/
theorem expand_size (prk info : ByteArray) (len : Nat) :
    (expand prk info len).size = len :=
  expandWith_size sha256H sha256H_digest_size (by decide) prk info len

theorem expandLabel_size (secret : ByteArray) (label : String) (ctx : ByteArray)
    (len : Nat) : (expandLabel secret label ctx len).size = len :=
  expandLabelWith_size sha256H sha256H_digest_size (by decide) secret label ctx len

set_option compiler.extract_closed false in
/-- Official vectors: HMAC-SHA-256 RFC 4231 test cases 1 and 2; HKDF
RFC 5869 test case 1 (PRK and 42-byte OKM); the RFC 8448 §3 Early Secret
and "derived" secret (an all-zero PSK trace, exercising `expandLabel` with
the empty-transcript hash); a structural check that `expandLabel` builds
exactly the §7.1 HkdfLabel encoding; a wiring check that `schedule`
equals the step-by-step §7.1 derivation; the four RFC 8448 §3 traffic
secrets, which pin every `schedule` label and step to the published
trace; HMAC-SHA-384 RFC 4231 test cases 1 and 2; and a
TLS_AES_256_GCM_SHA384 handshake's early secret, handshake secret and two
handshake traffic secrets, from The Illustrated TLS 1.3 Connection
(tls13.xargs.org), since no RFC prints a SHA-384 trace. -/
def selftest (_ : Unit) : Bool :=
  let hex := bytesToHex
  -- A malformed literal falls back to a 1-byte sentinel and breaks the
  -- length-sensitive checks instead of testing the empty string.
  let hx (s : String) : ByteArray := (hexToBytes? s).getD (ByteArray.mk #[0])
  -- RFC 4231 §4.2 test case 1: key = 0x0b × 20, data = "Hi There".
  let t1 :=
    hex (hmac (ByteArray.mk (Array.replicate 20 0x0b)) (ascii "Hi There"))
      == "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
  -- RFC 4231 §4.3 test case 2: key = "Jefe".
  let t2 :=
    hex (hmac (ascii "Jefe") (ascii "what do ya want for nothing?"))
      == "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
  -- RFC 5869 appendix A.1 test case 1.
  let ikm := ByteArray.mk (Array.replicate 22 0x0b)
  let salt := hx "000102030405060708090a0b0c"
  let info := hx "f0f1f2f3f4f5f6f7f8f9"
  let prk := extract salt ikm
  let t3 :=
    hex prk == "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"
  let t4 :=
    hex (expand prk info 42)
      == "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
  -- RFC 8448 §3: Early Secret = HKDF-Extract(0, 0-PSK) and
  -- Derive-Secret(Early, "derived", "").
  let early := extract (zeros hashLen) (zeros hashLen)
  let t5 :=
    hex early == "33ad0a1c607ec03b09e6cd9893680ce210adf300aa1f2660e1b22e10f170f92a"
  let t6 :=
    hex (deriveSecret early "derived" emptyHash)
      == "6f2615a108c702c5678f54fc9dbab69716c076189c48250cebeac3576c3611ba"
  -- Structural: expandLabel(secret, "key", Hash(""), 16) must equal a raw
  -- expand over the hand-assembled HkdfLabel bytes
  -- (uint16 16, 9-byte "tls13 key", 32-byte context).
  let lab := ascii "tls13 key"
  let rawInfo := ByteArray.mk #[0x00, 0x10, 0x09] ++ lab
      ++ ByteArray.mk #[0x20] ++ emptyHash
  let t7 := hex (expandLabel prk "key" emptyHash 16) == hex (expand prk rawInfo 16)
  -- Wiring: schedule must equal the step-by-step §7.1 derivation.
  let psk := ByteArray.mk (Array.replicate 32 0x01)
  let ecdhe := ByteArray.mk (Array.replicate 32 0x02)
  let helloHash := sha256 (ascii "hello transcript")
  let finHash := sha256 (ascii "finished transcript")
  let (cHs, sHs, cAp, sAp) := schedule psk ecdhe helloHash finHash
  let early' := extract (zeros hashLen) psk
  let hs' := extract (deriveSecret early' "derived" emptyHash) ecdhe
  let master' := extract (deriveSecret hs' "derived" emptyHash) (zeros hashLen)
  let t8 := hex cHs == hex (expandLabel hs' "c hs traffic" helloHash hashLen)
        && hex sHs == hex (expandLabel hs' "s hs traffic" helloHash hashLen)
        && hex cAp == hex (expandLabel master' "c ap traffic" finHash hashLen)
        && hex sAp == hex (expandLabel master' "s ap traffic" finHash hashLen)
  -- RFC 8448 §3, simple 1-RTT trace: `schedule` over the trace's zero PSK,
  -- x25519 shared secret (the "handshake" extract IKM), and the two
  -- transcript hashes the trace feeds Derive-Secret must reproduce all
  -- four published traffic secrets.
  let ecdhe8448 := hx "8bd4054fb55b9d63fdfbacf9f04b9f0d35e6d63f537563efd46272900f89492d"
  let hello8448 := hx "860c06edc07858ee8e78f0e7428c58edd6b43f2ca3e6e95f02ed063cf0e1cad8"
  let fin8448 := hx "9608102a0f1ccc6db6250b7b7e417b1a000eaada3daae4777a7686c9ff83df13"
  let (cHs8, sHs8, cAp8, sAp8) := schedule (zeros hashLen) ecdhe8448 hello8448 fin8448
  let t9 := hex cHs8 == "b3eddb126e067f35a780b3abf45e2d8f3b1a950738f52e9600746a0e27a55a21"
        && hex sHs8 == "b67b7d690cc16c4e75e54213cb2d37b4e9c912bcded9105d42befd59d391ad38"
        && hex cAp8 == "9e40646ce79a7f9dc05af8889bce6552875afa0b06df0087f792ebb7c17504a5"
        && hex sAp8 == "a11af9f05531f856ad47116b45a950328204b4f44bfb6b3a4b4f1f3fcb631643"
  -- RFC 4231 §4.2 and §4.3 over SHA-384.
  let t10 :=
    hex (hmacWith sha384H (ByteArray.mk (Array.replicate 20 0x0b)) (ascii "Hi There"))
      == "afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59c" ++
         "faea9ea9076ede7f4af152e8b2fa9cb6"
    && hex (hmacWith sha384H (ascii "Jefe") (ascii "what do ya want for nothing?"))
      == "af45d2e376484031617f78d2b58a6b1b9c7ef464f5a01b47e42ec3736322445e" ++
         "8e2240ca5e69e2c78b3239ecfab21649"
  -- The Illustrated TLS 1.3 Connection under TLS_AES_256_GCM_SHA384: the
  -- early secret of no PSK, the handshake secret from its x25519 shared
  -- secret, and the two handshake traffic secrets over its
  -- ClientHello..ServerHello hash.
  let early384 := extractWith sha384H (zeros 48) (zeros 48)
  let shared := hx "df4a291baa1eb7cfa6934b29b474baad2697e29f1f920dcc77c8a0a088447624"
  let hello384 := hx ("e05f64fcd082bdb0dce473adf669c2769f257a1c75a51b7887468b5e0e7a7de4" ++
                      "f4d34555112077f16e079019d5a845bd")
  let hs384 := extractWith sha384H
    (deriveSecretWith sha384H early384 "derived" (emptyHashWith sha384H)) shared
  let (cHs384, sHs384, _, _) := scheduleWith sha384H (zeros 48) shared hello384 hello384
  let t11 := hex early384 == "7ee8206f5570023e6dc7519eb1073bc4e791ad37b5c382aa10ba18e2357e7169" ++
                             "71f9362f2c2fe2a76bfd78dfec4ea9b5"
    && hex hs384 == "bdbbe8757494bef20de932598294ea65b5e6bf6dc5c02a960a2de2eaa9b07c92" ++
                    "9078d2caa0936231c38d1725f179d299"
    && hex cHs384 == "db89d2d6df0e84fed74a2288f8fd4d0959f790ff23946cdf4c26d85e51bebd42" ++
                     "ae184501972f8d30c4a3e4a3693d0ef0"
    && hex sHs384 == "23323da031634b241dd37d61032b62a4f450584d1f7f47983ba2f7cc0cdcc39a" ++
                     "68f481f2b019f9403a3051908a5d1622"
  t1 && t2 && t3 && t4 && t5 && t6 && t7 && t8 && t9 && t10 && t11


theorem schedule_eq (psk ecdhe helloHash finHash : ByteArray) :
    schedule psk ecdhe helloHash finHash =
      (expandLabel
         (extract (deriveSecret
           (extract (zeros 32) psk) "derived" emptyHash) ecdhe)
         "c hs traffic" helloHash 32,
       expandLabel
         (extract (deriveSecret
           (extract (zeros 32) psk) "derived" emptyHash) ecdhe)
         "s hs traffic" helloHash 32,
       expandLabel
         (extract (deriveSecret
           (extract (deriveSecret
             (extract (zeros 32) psk) "derived" emptyHash) ecdhe)
             "derived" emptyHash) (zeros 32))
         "c ap traffic" finHash 32,
       expandLabel
         (extract (deriveSecret
           (extract (deriveSecret
             (extract (zeros 32) psk) "derived" emptyHash) ecdhe)
             "derived" emptyHash) (zeros 32))
         "s ap traffic" finHash 32) := rfl

-- 2. Hkdf: every schedule output is one hash output long, under either
-- hash.

theorem scheduleWith_sizes (h : Hash) (h_digest : ∀ m, (h.digest m).size = h.hashLen)
    (h_pos : 0 < h.hashLen) (psk ecdhe hh fh : ByteArray) :
    let (a, b, c, d) := scheduleWith h psk ecdhe hh fh
    a.size = h.hashLen ∧ b.size = h.hashLen ∧ c.size = h.hashLen ∧ d.size = h.hashLen := by
  simp [scheduleWith, deriveSecretWith, expandLabelWith_size h h_digest h_pos]

theorem schedule_sizes (psk ecdhe hh fh : ByteArray) :
    let (a, b, c, d) := schedule psk ecdhe hh fh
    a.size = 32 ∧ b.size = 32 ∧ c.size = 32 ∧ d.size = 32 :=
  scheduleWith_sizes sha256H sha256H_digest_size (by decide) psk ecdhe hh fh

-- 3. Record: nextSecret is 32 bytes.

end Spec.Hkdf
