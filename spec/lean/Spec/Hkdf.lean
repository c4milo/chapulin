import Spec.Sha256

/-!
HMAC-SHA-256 (RFC 2104), HKDF (RFC 5869), and the TLS 1.3 key-schedule
pieces built on them (RFC 9846 §7.1). Written from the RFC text only.
-/

namespace Spec.Hkdf
open Spec.Bytes
open Spec.Sha256 (sha256)

/-- RFC 2104 §2: B, the hash's input block size in bytes (64 for SHA-256). -/
def blockSize : Nat := 64

/-- RFC 5869 §2: HashLen, the hash output size in bytes (32 for SHA-256). -/
def hashLen : Nat := 32

/-- `n` zero bytes. -/
def zeros (n : Nat) : ByteArray := ByteArray.mk (Array.replicate n 0)

/-- RFC 2104 §2: `HMAC(K, text) = H(K ⊕ opad ‖ H(K ⊕ ipad ‖ text))` with
ipad = 0x36 and opad = 0x5c repeated B times. Keys longer than B are first
hashed; shorter keys are zero-padded to B bytes. -/
def hmac (key msg : ByteArray) : ByteArray :=
  let k0 := if key.size > blockSize then sha256 key else key
  let k := k0 ++ zeros (blockSize - k0.size)
  let ipad := ByteArray.mk (Array.replicate blockSize 0x36)
  let opad := ByteArray.mk (Array.replicate blockSize 0x5c)
  sha256 (xorBytes k opad ++ sha256 (xorBytes k ipad ++ msg))

/-- RFC 5869 §2.2: `HKDF-Extract(salt, IKM) = HMAC-Hash(salt, IKM)`, PRK is
HashLen bytes. (The §2.2 default of a HashLen-zero salt is the caller's
choice; note HMAC zero-pads keys, so an empty salt is equivalent.) -/
def extract (salt ikm : ByteArray) : ByteArray :=
  hmac salt ikm

/-- RFC 5869 §2.3: `HKDF-Expand(PRK, info, L)` — `N = ceil(L/HashLen)`,
`T(0) = empty`, `T(i) = HMAC-Hash(PRK, T(i-1) ‖ info ‖ i)` for a single
octet counter `i`, output the first L bytes of `T(1) ‖ … ‖ T(N)`.
§2.3 limits `L` to `255 * HashLen` (8160 bytes for SHA-256), the most
the single-octet counter can emit; the dispatcher enforces the bound. -/
def expand (prk info : ByteArray) (len : Nat) : ByteArray := Id.run do
  let n := (len + hashLen - 1) / hashLen
  let mut t := ByteArray.empty
  let mut okm := ByteArray.empty
  for i in [1:n+1] do
    t := hmac prk (t ++ info ++ ByteArray.mk #[UInt8.ofNat i])
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
def expandLabel (secret : ByteArray) (label : String) (ctx : ByteArray)
    (len : Nat) : ByteArray :=
  let lab := ascii ("tls13 " ++ label)
  let info := natToBytesBE len 2
      ++ natToBytesBE lab.size 1 ++ lab
      ++ natToBytesBE ctx.size 1 ++ ctx
  expand secret info len

/-- RFC 9846 §7.1: `Derive-Secret(Secret, Label, Messages) =
HKDF-Expand-Label(Secret, Label, Transcript-Hash(Messages), Hash.length)`.
The caller supplies the transcript hash directly. -/
def deriveSecret (secret : ByteArray) (label : String)
    (transcriptHash : ByteArray) : ByteArray :=
  expandLabel secret label transcriptHash hashLen

/-- `Transcript-Hash("")` — the hash of the empty transcript, used where
RFC 9846 §7.1 writes `Derive-Secret(., "derived", "")`. -/
def emptyHash : ByteArray := sha256 ByteArray.empty

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
def schedule (psk ecdhe helloHash finHash : ByteArray) :
    ByteArray × ByteArray × ByteArray × ByteArray :=
  let early := extract (zeros hashLen) psk
  let hs := extract (deriveSecret early "derived" emptyHash) ecdhe
  let cHs := deriveSecret hs "c hs traffic" helloHash
  let sHs := deriveSecret hs "s hs traffic" helloHash
  let master := extract (deriveSecret hs "derived" emptyHash) (zeros hashLen)
  let cAp := deriveSecret master "c ap traffic" finHash
  let sAp := deriveSecret master "s ap traffic" finHash
  (cHs, sHs, cAp, sAp)

/-!
Proven properties: output lengths. RFC 5869 §2.3 defines the OKM as
"the first L octets of T"; these lemmas discharge that clause for every
input, so the key schedule always hands the record layer exactly the
32-byte keys and 12-byte IVs it asks for.
-/

theorem hmac_size (key msg : ByteArray) : (hmac key msg).size = 32 := by
  simp [hmac, Spec.Sha256.sha256_size]

/-- `HKDF-Expand(prk, info, len)` returns exactly `len` bytes: the loop
emits `32 * ceil(len/32) ≥ len` bytes and the final extract keeps
`len`. -/
theorem expand_size (prk info : ByteArray) (len : Nat) :
    (expand prk info len).size = len := by
  have h := foldl_inv_idx (List.range' 1 ((len + hashLen - 1) / hashLen))
    (fun (b : ByteArray × ByteArray) (a : Nat) =>
      (hmac prk (b.fst ++ info ++ ByteArray.mk #[UInt8.ofNat a]),
       b.snd ++ hmac prk (b.fst ++ info ++ ByteArray.mk #[UInt8.ofNat a])))
    (fun k s => s.snd.size = 32 * k)
    (ByteArray.empty, ByteArray.empty)
    (by simp)
    (fun k b a hk => by simp [ByteArray.size_append, hmac_size, hk, Nat.mul_succ])
  simp only [List.length_range'] at h
  simp [expand, h]
  simp only [hashLen] at *
  omega

theorem expandLabel_size (secret : ByteArray) (label : String) (ctx : ByteArray)
    (len : Nat) : (expandLabel secret label ctx len).size = len := by
  simp [expandLabel, expand_size]

/-- Official vectors: HMAC-SHA-256 RFC 4231 test cases 1 and 2; HKDF
RFC 5869 test case 1 (PRK and 42-byte OKM); the RFC 8448 §3 Early Secret
and "derived" secret (an all-zero PSK trace, exercising `expandLabel` with
the empty-transcript hash); a structural check that `expandLabel` builds
exactly the §7.1 HkdfLabel encoding; a wiring check that `schedule`
equals the step-by-step §7.1 derivation; and the four RFC 8448 §3
traffic secrets, which pin every `schedule` label and step to the
published trace. -/
def selftest : Bool :=
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
  t1 && t2 && t3 && t4 && t5 && t6 && t7 && t8 && t9


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

-- 2. Hkdf: every schedule output is 32 bytes.

theorem schedule_sizes (psk ecdhe hh fh : ByteArray) :
    let (a, b, c, d) := schedule psk ecdhe hh fh
    a.size = 32 ∧ b.size = 32 ∧ c.size = 32 ∧ d.size = 32 := by
  simp [schedule, deriveSecret, expandLabel_size, hashLen]

-- 3. Record: nextSecret is 32 bytes.

end Spec.Hkdf
