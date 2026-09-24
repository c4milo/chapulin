import Spec.Bytes

/-!
SHA-3 and SHAKE, written from FIPS 202 (SHA-3 Standard) only.

The state is §3.1's 5×5×64 bit array, held as 25 `UInt64` lanes indexed
`x + 5*y`; `UInt64` arithmetic is exactly the standard's lane arithmetic
(XOR, AND, complement, rotation on 64-bit words). Bytes enter and leave
lanes little-endian per §3.1.2. The sponge (§4) works on a 200-byte
state string and converts to lanes only around the permutation.
-/

namespace Spec.Sha3
open Spec.Bytes

/-- FIPS 202 §3.2.5: the round constants RC[0..23] for iota. -/
def RC : Array UInt64 := #[
  0x0000000000000001, 0x0000000000008082, 0x800000000000808a, 0x8000000080008000,
  0x000000000000808b, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
  0x000000000000008a, 0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
  0x000000008000808b, 0x800000000000008b, 0x8000000000008089, 0x8000000000008003,
  0x8000000000008002, 0x8000000000000080, 0x000000000000800a, 0x800000008000000a,
  0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008]

/-- FIPS 202 §3.2.2: the rho rotation offset of lane (x, y), indexed
`x + 5*y`. -/
def rhoOffset : Array Nat := #[
  0, 1, 62, 28, 27,
  36, 44, 6, 55, 20,
  3, 10, 43, 25, 39,
  41, 45, 15, 21, 8,
  18, 2, 61, 56, 14]

/-- Rotate a 64-bit lane left by `r` bits. `r` may be 0 (lane (0,0) in
rho), so the right shift is reduced mod 64 to stay in range. -/
def rotl (x : UInt64) (r : Nat) : UInt64 :=
  (x <<< UInt64.ofNat r) ||| (x >>> UInt64.ofNat ((64 - r) % 64))

/-- One Keccak round: theta (§3.2.1), rho and pi (§3.2.2–3.2.3), chi
(§3.2.4), iota (§3.2.5). Each step is a fresh 25-lane array indexed by
destination, so rho-and-pi uses the standard's own inverse form
`A′[x, y] = rot(A[(x + 3y) mod 5, x])`. -/
def round (a : Array UInt64) (rc : UInt64) : Array UInt64 :=
  let c := Array.ofFn (n := 5) fun x =>
    a[x.val]! ^^^ a[x.val + 5]! ^^^ a[x.val + 10]! ^^^ a[x.val + 15]! ^^^ a[x.val + 20]!
  let d := Array.ofFn (n := 5) fun x =>
    c[(x.val + 4) % 5]! ^^^ rotl c[(x.val + 1) % 5]! 1
  let afterTheta := Array.ofFn (n := 25) fun i => a[i.val]! ^^^ d[i.val % 5]!
  let b := Array.ofFn (n := 25) fun j =>
    let x := j.val % 5
    let y := j.val / 5
    let src := (x + 3 * y) % 5 + 5 * x
    rotl afterTheta[src]! rhoOffset[src]!
  Array.ofFn (n := 25) fun i =>
    let x := i.val % 5
    let y := i.val / 5
    let v := b[5 * y + x]! ^^^ (~~~b[5 * y + (x + 1) % 5]! &&& b[5 * y + (x + 2) % 5]!)
    if i.val == 0 then v ^^^ rc else v

/-- FIPS 202 §3.3: Keccak-f[1600], the 24 rounds in order. -/
def keccakF (a : Array UInt64) : Array UInt64 :=
  RC.foldl round a

/-- §3.1.2: the 200 state bytes as 25 little-endian lanes. -/
def lanesOfBytes (s : ByteArray) : Array UInt64 :=
  Array.ofFn (n := 25) fun i =>
    UInt64.ofNat (bytesToNatLE (s.extract (8 * i.val) (8 * i.val + 8)))

/-- §3.1.3: 25 lanes back to 200 state bytes, little-endian. -/
def bytesOfLanes (lanes : Array UInt64) : ByteArray :=
  lanes.foldl (fun acc v => acc ++ natToBytesLE v.toNat 8) ByteArray.empty

/-- The permutation on the state string: to lanes, Keccak-f[1600], back
to bytes. -/
def permute (state : ByteArray) : ByteArray :=
  bytesOfLanes (keccakF (lanesOfBytes state))

/-- XOR a block into the front of the state, leaving the capacity bytes
behind it unchanged (they are XORed with zero). -/
def xorInto (state block : ByteArray) : ByteArray :=
  xorBytes state (block ++ ByteArray.mk (Array.replicate (state.size - block.size) 0))

/-- FIPS 202 §B.2, the byte-level pad10*1 with the domain bits packed
in: when one byte of the block remains the domain bits and both pad
bits share it, otherwise the domain byte, zeros, and the final 0x80. -/
def pad (rate : Nat) (domain : UInt8) (msg : ByteArray) : ByteArray :=
  if rate - msg.size % rate == 1 then
    msg ++ ByteArray.mk #[domain ||| 0x80]
  else
    msg ++ ByteArray.mk #[domain]
        ++ ByteArray.mk (Array.replicate (rate - msg.size % rate - 2) 0)
        ++ ByteArray.mk #[0x80]

/-- §4 sponge, absorbing: XOR each rate-sized block of the padded
message into the state and permute. -/
def absorb (rate : Nat) (padded : ByteArray) : ByteArray :=
  (List.range (padded.size / rate)).foldl
    (fun state i => permute (xorInto state (padded.extract (i * rate) (i * rate + rate))))
    (ByteArray.mk (Array.replicate 200 0))

/-- §4 sponge, squeezing one block: the front `rate` bytes of the state,
then the next block from the permuted state. -/
def squeezeBlocks (rate : Nat) (state : ByteArray) : Nat → ByteArray
  | 0 => ByteArray.empty
  | k + 1 => state.extract 0 rate ++ squeezeBlocks rate (permute state) k

/-- §4 sponge, squeezing: enough whole blocks, truncated to the
requested length. -/
def squeeze (rate : Nat) (state : ByteArray) (outLen : Nat) : ByteArray :=
  (squeezeBlocks rate state ((outLen + rate - 1) / rate)).extract 0 outLen

/-- §5: KECCAK[c] applied to a message under one domain byte — pad,
absorb, squeeze. -/
def keccak (rate : Nat) (domain : UInt8) (msg : ByteArray) (outLen : Nat) : ByteArray :=
  squeeze rate (absorb rate (pad rate domain msg)) outLen

/-- FIPS 202 §6.1: SHA3-256, rate 136, domain bits 01. -/
def sha3_256 (msg : ByteArray) : ByteArray := keccak 136 0x06 msg 32

/-- FIPS 202 §6.1: SHA3-512, rate 72, domain bits 01. -/
def sha3_512 (msg : ByteArray) : ByteArray := keccak 72 0x06 msg 64

/-- FIPS 202 §6.2: SHAKE128, rate 168, domain bits 1111. -/
def shake128 (msg : ByteArray) (outLen : Nat) : ByteArray := keccak 168 0x1f msg outLen

/-- FIPS 202 §6.2: SHAKE256, rate 136, domain bits 1111. -/
def shake256 (msg : ByteArray) (outLen : Nat) : ByteArray := keccak 136 0x1f msg outLen

private theorem round_size (a : Array UInt64) (rc : UInt64) : (round a rc).size = 25 := by
  simp [round]

private theorem lanesOfBytes_size (s : ByteArray) : (lanesOfBytes s).size = 25 := by
  simp [lanesOfBytes]

private theorem keccakF_size (a : Array UInt64) (h : a.size = 25) : (keccakF a).size = 25 := by
  rw [keccakF, ← Array.foldl_toList]
  exact foldl_inv _ _ (fun x => x.size = 25) a h (fun b rc _ => round_size b rc)

private theorem bytesOfLanes_size (lanes : Array UInt64) :
    (bytesOfLanes lanes).size = 8 * lanes.size := by
  rw [bytesOfLanes, ← Array.foldl_toList,
    size_foldl_append_const _ (fun v : UInt64 => natToBytesLE v.toNat 8) 8
      (fun v => natToBytesLE_size v.toNat 8)]
  simp

private theorem permute_size (state : ByteArray) : (permute state).size = 200 := by
  rw [permute, bytesOfLanes_size, keccakF_size _ (lanesOfBytes_size state)]

private theorem xorInto_size (state block : ByteArray) :
    (xorInto state block).size = state.size := by
  rw [xorInto, xorBytes_size, ByteArray.size_append, zeros_size]
  omega

/-- Absorbing always yields the 200-byte state string, whatever the
rate and message. -/
theorem absorb_size (rate : Nat) (padded : ByteArray) : (absorb rate padded).size = 200 := by
  rw [absorb]
  exact foldl_inv _ _ (fun s : ByteArray => s.size = 200) _ (zeros_size 200)
    (fun b i _ => permute_size _)

/-- Each squeezed block is one rate's worth of bytes. -/
private theorem squeezeBlocks_size (rate : Nat) (h_cap : rate ≤ 200) :
    ∀ (k : Nat) (state : ByteArray), state.size = 200 →
      (squeezeBlocks rate state k).size = rate * k
  | 0, _, _ => by simp [squeezeBlocks]
  | k + 1, state, h => by
    rw [squeezeBlocks, ByteArray.size_append, ByteArray.size_extract,
      squeezeBlocks_size rate h_cap k _ (permute_size state), h, Nat.mul_succ]
    omega

/-- Squeezing a 200-byte state at a real rate yields exactly the
requested number of bytes. -/
theorem squeeze_size (rate : Nat) (state : ByteArray) (outLen : Nat)
    (h_rate : 0 < rate) (h_cap : rate ≤ 200) (h_state : state.size = 200) :
    (squeeze rate state outLen).size = outLen := by
  have hd := Nat.div_add_mod (outLen + rate - 1) rate
  have hm := Nat.mod_lt (outLen + rate - 1) h_rate
  rw [squeeze, ByteArray.size_extract,
    squeezeBlocks_size rate h_cap _ state h_state]
  omega

/-- The digest is always 32 bytes (FIPS 202 §6.1). -/
theorem sha3_256_size (msg : ByteArray) : (sha3_256 msg).size = 32 :=
  squeeze_size 136 _ 32 (by omega) (by omega) (absorb_size 136 _)

/-- The digest is always 64 bytes (FIPS 202 §6.1). -/
theorem sha3_512_size (msg : ByteArray) : (sha3_512 msg).size = 64 :=
  squeeze_size 72 _ 64 (by omega) (by omega) (absorb_size 72 _)

/-- The XOF returns exactly the requested length (FIPS 202 §6.2). -/
theorem shake128_size (msg : ByteArray) (outLen : Nat) : (shake128 msg outLen).size = outLen :=
  squeeze_size 168 _ outLen (by omega) (by omega) (absorb_size 168 _)

/-- The XOF returns exactly the requested length (FIPS 202 §6.2). -/
theorem shake256_size (msg : ByteArray) (outLen : Nat) : (shake256 msg outLen).size = outLen :=
  squeeze_size 136 _ outLen (by omega) (by omega) (absorb_size 136 _)

/-- Padding fills the message to a whole number of rate-sized blocks
(FIPS 202 §B.2). -/
theorem pad_blocks (rate : Nat) (domain : UInt8) (msg : ByteArray) (h : 0 < rate) :
    (pad rate domain msg).size % rate = 0 := by
  have hd := Nat.div_add_mod msg.size rate
  have hm := Nat.mod_lt msg.size h
  rw [pad]
  split
  · rename_i hone
    simp only [beq_iff_eq] at hone
    obtain ⟨k, hk⟩ : ∃ k, (msg ++ ByteArray.mk #[domain ||| 0x80]).size = rate * k :=
      ⟨msg.size / rate + 1, by
        have h1 : (ByteArray.mk #[domain ||| 0x80]).size = 1 := rfl
        rw [ByteArray.size_append, h1, Nat.mul_succ]
        omega⟩
    rw [hk, Nat.mul_mod_right]
  · rename_i hmore
    simp only [beq_iff_eq] at hmore
    obtain ⟨k, hk⟩ : ∃ k,
        (msg ++ ByteArray.mk #[domain]
            ++ ByteArray.mk (Array.replicate (rate - msg.size % rate - 2) 0)
            ++ ByteArray.mk #[0x80]).size = rate * k :=
      ⟨msg.size / rate + 1, by
        have h1 : (ByteArray.mk #[domain]).size = 1 := rfl
        have h2 : (ByteArray.mk #[(0x80 : UInt8)]).size = 1 := rfl
        rw [ByteArray.size_append, ByteArray.size_append, ByteArray.size_append,
          h1, h2, zeros_size, Nat.mul_succ]
        omega⟩
    rw [hk, Nat.mul_mod_right]

/-- Padding keeps the message as a prefix. -/
theorem pad_prefix (rate : Nat) (domain : UInt8) (msg : ByteArray) :
    (pad rate domain msg).extract 0 msg.size = msg := by
  rw [pad]
  split
  · exact ByteArray.extract_append_eq_left rfl
  · rw [ByteArray.append_assoc, ByteArray.append_assoc]
    exact ByteArray.extract_append_eq_left rfl

/-- NIST FIPS 202 example values: the empty message and "abc" for the
fixed-length digests; the empty message and the 1600-bit message of
repeated 0xa3 for the XOFs, first 32 output bytes. -/
def selftest : Bool :=
  let a3 := ByteArray.mk (Array.replicate 200 0xa3)
  bytesToHex (sha3_256 (ascii "")) ==
      "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
  && bytesToHex (sha3_256 (ascii "abc")) ==
      "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"
  && bytesToHex (sha3_512 (ascii "")) ==
      "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"
  && bytesToHex (sha3_512 (ascii "abc")) ==
      "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0"
  && bytesToHex (shake128 (ascii "") 32) ==
      "7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26"
  && bytesToHex (shake256 (ascii "") 32) ==
      "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f"
  && bytesToHex (shake128 a3 32) ==
      "131ab8d2b594946b9c81333f9bb6e0ce75c3b93104fa3469d3917457385da037"
  && bytesToHex (shake256 a3 32) ==
      "cd8a920ed141aa0407a22d59288652e9d9f1a7ee0c1e7c1ca699424da84a904d"

end Spec.Sha3
