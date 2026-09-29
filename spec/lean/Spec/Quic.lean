import Spec.Bytes
import Spec.Hkdf
import Spec.Gcm

/-!
QUIC packet protection keys, written from RFC 9001 and RFC 9369 as an
executable oracle: the Initial keys a Destination Connection ID derives
(RFC 9001 §5.2), the packet protection key, IV and header protection key
a traffic secret derives (§5.1), the next secret of a key update (§6.1)
and the Retry Integrity Tag (§5.8), each in QUIC version 1 and in QUIC
version 2.

RFC 9369 §3.3 changes four inputs between the two versions and nothing
else: the Initial salt, the four HKDF labels, and the Retry key and
nonce. So every definition below takes the version and reads those four
from it, and none restates HKDF or GCM: `Spec.Hkdf` and `Spec.Gcm` do.
Every secret here is a SHA-256 one, the hash of
TLS_CHACHA20_POLY1305_SHA256 and of the Initial level.
-/
namespace Spec.Quic
open Spec.Bytes

/-- The two QUIC versions: RFC 9000's version 1 and RFC 9369's version 2. -/
inductive Version where
  /-- RFC 9000 and RFC 9001. -/
  | v1
  /-- RFC 9369. -/
  | v2
deriving DecidableEq, Repr

/-- The Version field of a long header: 0x00000001 for version 1 (RFC 9000
§15) and 0x6b3343cf for version 2 (RFC 9369 §3.1). -/
def Version.field : Version → Nat
  | .v1 => 0x00000001
  | .v2 => 0x6b3343cf

/-- The version a Version field names, and nothing for a field neither RFC
defines. -/
def Version.ofField? (field : Nat) : Option Version :=
  if field == Version.field .v1 then some .v1
  else if field == Version.field .v2 then some .v2
  else none

/-- The Initial salt: RFC 9001 §5.2's for version 1 and RFC 9369 §3.3.1's
for version 2. -/
def initialSalt : Version → ByteArray
  | .v1 => ByteArray.mk #[0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17,
                          0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a]
  | .v2 => ByteArray.mk #[0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93,
                          0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb, 0xf9, 0xbd, 0x2e, 0xd9]

/-- The four HKDF labels one version derives its keys under: the packet
protection key, the IV and the header protection key of RFC 9001 §5.1,
and the key update label of §6.1. -/
structure Labels where
  /-- The packet protection key's label. -/
  key : String
  /-- The packet protection IV's label. -/
  iv : String
  /-- The header protection key's label. -/
  hp : String
  /-- The key update's label. -/
  ku : String

/-- RFC 9001 §5.1 and §6.1's labels for version 1, and RFC 9369 §3.3.2's
for version 2. -/
def labels : Version → Labels
  | .v1 => ⟨"quic key", "quic iv", "quic hp", "quic ku"⟩
  | .v2 => ⟨"quicv2 key", "quicv2 iv", "quicv2 hp", "quicv2 ku"⟩

/-- The Retry Integrity Tag key: RFC 9001 §5.8 prints
0xbe0c690b9f66575a1d766b54e368c84e for version 1, and RFC 9369 §3.3.3
prints 0x8fb4b01b56ac48e260fbcbcead7ccc92 for version 2. -/
def retryKey : Version → ByteArray
  | .v1 => ByteArray.mk #[0xbe, 0x0c, 0x69, 0x0b, 0x9f, 0x66, 0x57, 0x5a, 0x1d, 0x76,
                          0x6b, 0x54, 0xe3, 0x68, 0xc8, 0x4e]
  | .v2 => ByteArray.mk #[0x8f, 0xb4, 0xb0, 0x1b, 0x56, 0xac, 0x48, 0xe2, 0x60, 0xfb,
                          0xcb, 0xce, 0xad, 0x7c, 0xcc, 0x92]

/-- The Retry Integrity Tag nonce: RFC 9001 §5.8 prints
0x461599d35d632bf2239825bb for version 1, and RFC 9369 §3.3.3 prints
0xd86969bc2d7c6d9990efb04a for version 2. -/
def retryNonce : Version → ByteArray
  | .v1 => ByteArray.mk #[0x46, 0x15, 0x99, 0xd3, 0x5d, 0x63, 0x2b, 0xf2, 0x23, 0x98,
                          0x25, 0xbb]
  | .v2 => ByteArray.mk #[0xd8, 0x69, 0x69, 0xbc, 0x2d, 0x7c, 0x6d, 0x99, 0x90, 0xef,
                          0xb0, 0x4a]

/-- RFC 9001 §5.1: the packet protection key, the packet protection IV and
the header protection key of one direction, each an HKDF-Expand-Label
over that direction's traffic secret with an empty context, under the
version's labels. The two keys are `keyLen` bytes, the AEAD's key length,
and the IV is 12 bytes. -/
def packetKeys (version : Version) (secret : ByteArray) (keyLen : Nat) :
    ByteArray × ByteArray × ByteArray :=
  let names := labels version
  (Spec.Hkdf.expandLabel secret names.key ByteArray.empty keyLen,
   Spec.Hkdf.expandLabel secret names.iv ByteArray.empty 12,
   Spec.Hkdf.expandLabel secret names.hp ByteArray.empty keyLen)

/-- RFC 9001 §6.1: the next traffic secret of a key update,
`HKDF-Expand-Label(secret, ku, "", Hash.length)` under the version's key
update label. The packet protection key and IV of the next phase are
`packetKeys` over it; the header protection key is not updated. -/
def nextSecret (version : Version) (secret : ByteArray) : ByteArray :=
  Spec.Hkdf.expandLabel secret (labels version).ku ByteArray.empty 32

/-- RFC 9001 §5.2: the secret one endpoint protects its Initial packets
with, from the version's salt and the Destination Connection ID the
client chose. `client` picks the label "client in"; "server in" is the
server's. RFC 9369 keeps both labels. -/
def initialSecret (version : Version) (dcid : ByteArray) (client : Bool) : ByteArray :=
  Spec.Hkdf.expandLabel (Spec.Hkdf.extract (initialSalt version) dcid)
    (if client then "client in" else "server in") ByteArray.empty 32

/-- RFC 9001 §5.2: one endpoint's Initial keys, which are §5.1's keys over
its Initial secret for AEAD_AES_128_GCM, whose key is 16 bytes. -/
def initialKeys (version : Version) (dcid : ByteArray) (client : Bool) :
    ByteArray × ByteArray × ByteArray :=
  packetKeys version (initialSecret version dcid client) 16

/-- RFC 9001 §5.8: the Retry Integrity Tag, the tag of AEAD_AES_128_GCM
over an empty plaintext with the Retry Pseudo-Packet as associated data,
under the version's printed key and nonce. -/
def retryTag (version : Version) (pseudo : ByteArray) : ByteArray :=
  (Spec.Gcm.encrypt (retryKey version) (retryNonce version) pseudo ByteArray.empty).2

/-- Reading a version's own Version field answers that version. -/
theorem ofField?_field (version : Version) : Version.ofField? version.field = some version := by
  cases version <;> decide

/-- The three keys have the lengths RFC 9001 §5.1 asks for. -/
theorem packetKeys_size (version : Version) (secret : ByteArray) (keyLen : Nat) :
    (packetKeys version secret keyLen).1.size = keyLen ∧
      (packetKeys version secret keyLen).2.1.size = 12 ∧
      (packetKeys version secret keyLen).2.2.size = keyLen := by
  simp [packetKeys, Spec.Hkdf.expandLabel_size]

/-- A key update's next secret is a SHA-256 secret again. -/
theorem nextSecret_size (version : Version) (secret : ByteArray) :
    (nextSecret version secret).size = 32 := by
  simp [nextSecret, Spec.Hkdf.expandLabel_size]

/-- The two versions share no label: RFC 9001 §9.6 asks a new version for
new labels, so a key one version derives is never the key the other
derives from the same secret under the same label. -/
theorem labels_disjoint :
    (labels .v1).key ≠ (labels .v2).key ∧ (labels .v1).iv ≠ (labels .v2).iv ∧
      (labels .v1).hp ≠ (labels .v2).hp ∧ (labels .v1).ku ≠ (labels .v2).ku := by
  decide

set_option compiler.extract_closed false in
/-- Test vectors: RFC 9001 Appendix A.1's client keys, A.4's Retry tag and
A.5's four values, and RFC 9369 Appendix A.1's client and server keys,
A.4's Retry tag and A.5's four values. The Retry key and nonce of each
version are also derived again from the secret its RFC prints, under its
key and iv labels (RFC 9001 §5.8, RFC 9369 §3.3.3). -/
def selftest (_ : Unit) : Bool :=
  -- A malformed literal falls back to a 1-byte sentinel, which fails the
  -- length-sensitive checks instead of testing the empty string.
  let hx (s : String) : ByteArray := (hexToBytes? s).getD (ByteArray.mk #[0])
  let dcid := hx "8394c8f03e515708"
  let (key1, iv1, hp1) := initialKeys .v1 dcid true
  let (key2c, iv2c, hp2c) := initialKeys .v2 dcid true
  let (key2s, iv2s, hp2s) := initialKeys .v2 dcid false
  -- RFC 9001 A.4 and RFC 9369 A.4: the pseudo-packet is the original
  -- Destination Connection ID's length, that ID, and the Retry packet up
  -- to its tag.
  let pseudo1 := hx "088394c8f03e515708ff000000010008f067a5502a4262b5746f6b656e"
  let pseudo2 := hx "088394c8f03e515708cf6b3343cf0008f067a5502a4262b5746f6b656e"
  -- RFC 9001 A.5 and RFC 9369 A.5 derive from one application secret.
  let secret := hx "9ac312a7f877468ebe69422748ad00a15443f18203a07d6060f688f30f21632b"
  let (akey1, aiv1, ahp1) := packetKeys .v1 secret 32
  let (akey2, aiv2, ahp2) := packetKeys .v2 secret 32
  let retry1 := hx "d9c9943e6101fd200021506bcc02814c73030f25c79d71ce876eca876e6fca8e"
  let retry2 := hx "c4dd2484d681aefa4ff4d69c2c20299984a765a5d3c31982f38fc74162155e9f"
  bytesToHex key1 == "1f369613dd76d5467730efcbe3b1a22d"
    && bytesToHex iv1 == "fa044b2f42a3fd3b46fb255c"
    && bytesToHex hp1 == "9f50449e04a0e810283a1e9933adedd2"
    && bytesToHex key2c == "8b1a0bc121284290a29e0971b5cd045d"
    && bytesToHex iv2c == "91f73e2351d8fa91660e909f"
    && bytesToHex hp2c == "45b95e15235d6f45a6b19cbcb0294ba9"
    && bytesToHex key2s == "82db637861d55e1d011f19ea71d5d2a7"
    && bytesToHex iv2s == "dd13c276499c0249d3310652"
    && bytesToHex hp2s == "edf6d05c83121201b436e16877593c3a"
    && bytesToHex (retryTag .v1 pseudo1) == "04a265ba2eff4d829058fb3f0f2496ba"
    && bytesToHex (retryTag .v2 pseudo2) == "c8646ce8bfe33952d955543665dcc7b6"
    && bytesToHex akey1 == "c6d98ff3441c3fe1b2182094f69caa2ed4b716b65488960a7a984979fb23e1c8"
    && bytesToHex aiv1 == "e0459b3474bdd0e44a41c144"
    && bytesToHex ahp1 == "25a282b9e82f06f21f488917a4fc8f1b73573685608597d0efcb076b0ab7a7a4"
    && bytesToHex (nextSecret .v1 secret)
         == "1223504755036d556342ee9361d253421a826c9ecdf3c7148684b36b714881f9"
    && bytesToHex akey2 == "3bfcddd72bcf02541d7fa0dd1f5f9eeea817e09a6963a0e6c7df0f9a1bab90f2"
    && bytesToHex aiv2 == "a6b5bc6ab7dafce30ffff5dd"
    && bytesToHex ahp2 == "d659760d2ba434a226fd37b35c69e2da8211d10c4f12538787d65645d5d1b8e2"
    && bytesToHex (nextSecret .v2 secret)
         == "c69374c49e3d2a9466fa689e49d476db5d0dfbc87d32ceeaa6343fd0ae4c7d88"
    && Spec.Hkdf.expandLabel retry1 (labels .v1).key ByteArray.empty 16 == retryKey .v1
    && Spec.Hkdf.expandLabel retry1 (labels .v1).iv ByteArray.empty 12 == retryNonce .v1
    && Spec.Hkdf.expandLabel retry2 (labels .v2).key ByteArray.empty 16 == retryKey .v2
    && Spec.Hkdf.expandLabel retry2 (labels .v2).iv ByteArray.empty 12 == retryNonce .v2

end Spec.Quic
