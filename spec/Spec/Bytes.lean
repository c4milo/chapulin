/-!
Byte and hex utilities shared by every spec module. The spec is an
executable oracle: clarity beats speed everywhere, and nothing here may
look at the C implementation — modules are written from the RFC text.
-/
namespace Spec.Bytes

def hexDigit? (c : Char) : Option UInt8 :=
  if '0' ≤ c ∧ c ≤ '9' then some (UInt8.ofNat (c.toNat - '0'.toNat))
  else if 'a' ≤ c ∧ c ≤ 'f' then some (UInt8.ofNat (c.toNat - 'a'.toNat + 10))
  else if 'A' ≤ c ∧ c ≤ 'F' then some (UInt8.ofNat (c.toNat - 'A'.toNat + 10))
  else none

def hexToBytes? (s : String) : Option ByteArray := do
  let cs := s.toList
  if cs.length % 2 ≠ 0 then none
  else
    let rec go : List Char → ByteArray → Option ByteArray
      | [], acc => some acc
      | hi :: lo :: rest, acc => do
        let h ← hexDigit? hi
        let l ← hexDigit? lo
        go rest (acc.push (h <<< 4 ||| l))
      | _, _ => none
    go cs (ByteArray.emptyWithCapacity (cs.length / 2))

def bytesToHex (b : ByteArray) : String :=
  let digits := "0123456789abcdef".toList.toArray
  b.foldl (init := "") fun s v =>
    s.push (digits[(v >>> 4).toNat]!) |>.push (digits[(v &&& 0xf).toNat]!)

/-- Big-endian encoding of `n` into `len` bytes (truncates above 2^(8*len)). -/
def natToBytesBE (n len : Nat) : ByteArray := Id.run do
  let mut out := ByteArray.emptyWithCapacity len
  for i in [0:len] do
    out := out.push (UInt8.ofNat (n >>> ((len - 1 - i) * 8) % 256))
  return out

/-- Little-endian encoding of `n` into `len` bytes. -/
def natToBytesLE (n len : Nat) : ByteArray := Id.run do
  let mut out := ByteArray.emptyWithCapacity len
  for i in [0:len] do
    out := out.push (UInt8.ofNat (n >>> (i * 8) % 256))
  return out

/-- Little-endian decoding of the whole array. -/
def bytesToNatLE (b : ByteArray) : Nat :=
  b.data.foldr (init := 0) fun v acc => acc * 256 + v.toNat

/-- Big-endian decoding of the whole array. -/
def bytesToNatBE (b : ByteArray) : Nat :=
  b.foldl (init := 0) fun acc v => acc * 256 + v.toNat

def xorBytes (a b : ByteArray) : ByteArray := Id.run do
  let n := min a.size b.size
  let mut out := ByteArray.emptyWithCapacity n
  for i in [0:n] do
    out := out.push (a[i]! ^^^ b[i]!)
  return out

def ascii (s : String) : ByteArray := s.toUTF8

end Spec.Bytes
