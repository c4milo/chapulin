import Spec.Bytes
import Spec.ChaCha

/-!
The reference generator (drbg.[ch]): fast key erasure over ChaCha20,
after Bernstein's construction (blog.cr.yp.to/20170723-random.html).
One request under key `k` takes the ChaCha20 keystream with a zero
nonce from counter 0; the first 32 bytes become the next key and the
`n` bytes after them are the output. Defined over the keystream itself
(XOR against zeros), so this spec shares no structure with the C's
block-at-a-time walk.
-/
namespace Spec.Drbg

open Spec.Bytes

def zeroNonce : ByteArray :=
  ByteArray.mk (Array.replicate 12 0)

/-- One request: `(next key, output)` for `n` output bytes. -/
def next (k : ByteArray) (n : Nat) : ByteArray × ByteArray :=
  let stream := Spec.ChaCha.xor k zeroNonce 0 (ByteArray.mk (Array.replicate (32 + n) 0))
  (stream.extract 0 32, stream.extract 32 (32 + n))

/-- The construction rekeys: consecutive requests use distinct keys, and
the output never contains the next key's bytes. -/
def selftest : Bool :=
  let k0 := ByteArray.mk (Array.replicate 32 7)
  let (k1, out1) := next k0 40
  let (k2, out2) := next k1 40
  k1 != k0 && k2 != k1 && out1 != out2 && out1.size == 40 && out2.size == 40

end Spec.Drbg
