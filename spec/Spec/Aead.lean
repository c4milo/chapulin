import Spec.ChaCha
import Spec.Poly

/-!
AEAD_CHACHA20_POLY1305 per RFC 8439 §2.6–2.8, written from the RFC
text as an executable oracle.
-/
namespace Spec.Aead
open Spec.Bytes

/-- RFC 8439 §2.8: zero padding up to the next 16-byte multiple
(empty when already aligned). -/
def pad16 (b : ByteArray) : ByteArray :=
  if b.size % 16 == 0 then ByteArray.empty
  else ByteArray.mk (Array.replicate (16 - b.size % 16) 0)

/-- RFC 8439 §2.6: the one-time Poly1305 key is the first 32 bytes of
the ChaCha20 block with counter 0. -/
def polyKey (key nonce : ByteArray) : ByteArray :=
  (ChaCha.block key nonce 0).extract 0 32

/-- RFC 8439 §2.8: the MAC covers
`aad ‖ pad16(aad) ‖ ct ‖ pad16(ct) ‖ le64(|aad|) ‖ le64(|ct|)`. -/
def macData (aad ct : ByteArray) : ByteArray :=
  aad ++ pad16 aad ++ ct ++ pad16 ct ++
    natToBytesLE aad.size 8 ++ natToBytesLE ct.size 8

/-- RFC 8439 §2.8: encrypt with ChaCha20 starting at block counter 1,
tag with Poly1305 under the one-time key; output is `ct ‖ tag`. -/
def «seal» (key nonce aad pt : ByteArray) : ByteArray :=
  let ct := ChaCha.xor key nonce 1 pt
  ct ++ Poly.mac (polyKey key nonce) (macData aad ct)

/-- RFC 8439 §2.8 decryption: recompute the tag over the ciphertext;
on match decrypt (the same keystream XOR), otherwise `none`. -/
def open? (key nonce aad ct tag : ByteArray) : Option ByteArray :=
  let expect := Poly.mac (polyKey key nonce) (macData aad ct)
  if bytesToHex expect == bytesToHex tag then
    some (ChaCha.xor key nonce 1 ct)
  else
    none

/-- Test vectors: RFC 8439 §2.8.2 (ciphertext and tag), a round-trip
through `open?`, and a rejected forgery (one flipped tag byte). -/
def selftest : Bool := Id.run do
  -- A malformed literal falls back to a 1-byte sentinel and breaks the
  -- length-sensitive checks instead of testing the empty string.
  let hx (s : String) : ByteArray := (hexToBytes? s).getD (ByteArray.mk #[0])
  let key := hx "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"
  let nonce := hx "070000004041424344454647"
  let aad := hx "50515253c0c1c2c3c4c5c6c7"
  let pt := ascii ("Ladies and Gentlemen of the class of '99: If I could offer you " ++
    "only one tip for the future, sunscreen would be it.")
  let expectCt :=
    "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6" ++
    "3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36" ++
    "92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc" ++
    "3ff4def08e4b7a9de576d26586cec64b6116"
  let expectTag := "1ae10b594f09e26a7e902ecbd0600691"
  let out := «seal» key nonce aad pt
  let ct := out.extract 0 (out.size - 16)
  let tag := out.extract (out.size - 16) out.size
  let sealOk := bytesToHex ct == expectCt && bytesToHex tag == expectTag
  -- Verified open round-trips to the plaintext.
  let openOk := match open? key nonce aad ct tag with
    | some d => bytesToHex d == bytesToHex pt
    | none => false
  -- A forged tag (first byte flipped) must fail.
  let badTag := ByteArray.mk #[tag[0]! ^^^ 0x01] ++ tag.extract 1 16
  let forgeOk := (open? key nonce aad ct badTag).isNone
  return sealOk && openOk && forgeOk

end Spec.Aead

