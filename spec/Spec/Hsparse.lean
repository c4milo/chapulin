import Spec.Bytes
import Spec.Sha256

/-!
The server-to-client handshake message grammar of RFC 9846 §4, written
from the RFC text as an executable oracle. Four messages reach this
client after its ClientHello: ServerHello (§4.1.3, which §4.1.4 also
uses for a HelloRetryRequest), EncryptedExtensions (§4.3.1),
Certificate (§4.4.2), and CertificateVerify (§4.4.3).

Each parser takes one complete Handshake structure — `msg_type`, the
`uint24 length`, and the body those two frame (§4) — and either
returns the fields the client needs or names the alert the message
earns. Every function is written twice over: first the byte layout the
RFC's `struct` gives, then the narrowing the profile in `CLAUDE.md`
imposes on it. Each check's doc comment says which of the two it is.

The profile: TLS 1.3 only, TLS_CHACHA20_POLY1305_SHA256, one
key-exchange group per build (`Kex`: x25519, or the X25519MLKEM768
hybrid), two auth modes (ECDHE-PSK or a pinned server key checked
through CertificateVerify), no 0-RTT, no compression, no renegotiation,
no RFC 7250 raw public keys, and `record_size_limit` (RFC 8449) always
offered. The client offers exactly one of everything, so most of the
RFC's negotiation choices collapse to a byte compare against a
constant.

Where the RFC fixes the alert, `Alert` names it. Where the RFC states
a MUST but names no alert, the verdict is `Alert.unspecified` and the
doc comment says so, rather than inventing one: a guessed alert would
report a disagreement that is not a bug.
-/
namespace Spec.Hsparse

open Spec.Bytes

/-! ## Alerts -/

/--
The alerts RFC 9846 §6.2 fixes for the refusals in this file, plus one
marker for the refusals it leaves open.
-/
inductive Alert
  /-- unexpected_message(10): the wrong handshake message arrived. -/
  | unexpectedMessage
  /-- decode_error(50): a field was out of the specified range, or the
  length of the message was incorrect (§6.2). -/
  | decodeError
  /-- illegal_parameter(47): a field was syntactically correct but its
  value is not acceptable, or is inconsistent with another field. -/
  | illegalParameter
  /-- unsupported_extension(110): the message carried an extension
  response the client never requested (§4.2). -/
  | unsupportedExtension
  /-- missing_extension(109): an extension §9.2 requires for the
  features in play is absent. -/
  | missingExtension
  /-- The RFC states the MUST but fixes no alert, so the choice is the
  implementation's. The model refuses and says nothing more; a guessed
  alert would turn a free choice into a differential mismatch. -/
  | unspecified
deriving BEq, DecidableEq

/-! ## Message and extension code points -/

/-- HandshakeType server_hello(2) (RFC 9846 §4). A HelloRetryRequest
uses this same type; §4.1.4 tells the two apart by the Random. -/
def serverHelloType : Nat := 2

/-- HandshakeType encrypted_extensions(8) (RFC 9846 §4). -/
def encryptedExtensionsType : Nat := 8

/-- HandshakeType certificate(11) (RFC 9846 §4). -/
def certificateType : Nat := 11

/-- HandshakeType certificate_verify(15) (RFC 9846 §4). -/
def certificateVerifyType : Nat := 15

/-- ExtensionType server_name(0) (RFC 6066 §3). -/
def extServerName : Nat := 0

/-- ExtensionType supported_groups(10) (RFC 9846 §4.2.7). -/
def extSupportedGroups : Nat := 10

/-- ExtensionType record_size_limit(28) (RFC 8449 §4). -/
def extRecordSizeLimit : Nat := 28

/-- ExtensionType pre_shared_key(41) (RFC 9846 §4.2.11). -/
def extPreSharedKey : Nat := 41

/-- ExtensionType early_data(42) (RFC 9846 §4.2.10). -/
def extEarlyData : Nat := 42

/-- ExtensionType supported_versions(43) (RFC 9846 §4.2.1). -/
def extSupportedVersions : Nat := 43

/-- ExtensionType cookie(44) (RFC 9846 §4.2.2). -/
def extCookie : Nat := 44

/-- ExtensionType key_share(51) (RFC 9846 §4.2.8). -/
def extKeyShare : Nat := 51

/--
Every ExtensionType RFC 9846 §4.2 defines, together with RFC 8449's
record_size_limit(28) and RFC 7250's certificate-type pair (19, 20).
"Recognized" in §4.2's sense is a property of the implementation, and
for this client it is exactly this list: the code points the profile
knows about, whether or not it offers them.
-/
def knownExtension (t : Nat) : Bool :=
  [0, 1, 5, 10, 13, 14, 15, 16, 18, 19, 20, 21, 28, 35,
    41, 42, 43, 44, 45, 47, 48, 49, 50, 51].contains t

/-! ## Profile constants -/

/-- CipherSuite TLS_CHACHA20_POLY1305_SHA256 = `{0x13,0x03}`
(RFC 9846 appendix B.4). The profile offers this one and no other. -/
def cipherSuite : Nat := 0x1303

/-- NamedGroup x25519(0x001D) (RFC 9846 §4.2.7): the KEX=x25519
build's one group. `Kex` below names both builds' groups. -/
def x25519Group : Nat := 0x001d

/-- ProtocolVersion 0x0304, the value a TLS 1.3 server puts in the
ServerHello's supported_versions (RFC 9846 §4.2.1). -/
def tls13Version : Nat := 0x0304

/-- ProtocolVersion 0x0303 ("TLS 1.2"), the value §4.1.3 freezes into
the ServerHello's `legacy_version` field. The real version moves to
supported_versions; this one is a constant on the wire. -/
def legacyVersion : Nat := 0x0303

/-- The x25519 public value is 32 bytes (RFC 9846 §4.2.8.2, RFC 7748
§5). -/
def x25519KeySize : Nat := 32

/--
The one NamedGroup the build offers. `CLAUDE.md` fixes it at build time
through the Makefile's KEX variable, the way PIN fixes `Scheme`, so
exactly one of these is live in a library object. The client offers its
build's group and no other, so a ServerHello selecting anything else is
a group the client did not offer (RFC 9846 §4.2.8).
-/
inductive Kex
  /-- x25519(0x001D) (RFC 9846 §4.2.7). -/
  | x25519
  /-- X25519MLKEM768(0x11EC), the ML-KEM-768 + x25519 hybrid
  (RFC 10024). -/
  | pq
deriving BEq

/-- The build's NamedGroup code point (RFC 9846 §4.2.7 for x25519,
RFC 10024 for X25519MLKEM768). -/
def Kex.code : Kex → Nat
  | .x25519 => x25519Group
  | .pq => 0x11ec

/--
The octet count of the build's server key_exchange value (RFC 9846
§4.2.8): the 32-octet x25519 public value (§4.2.8.2), or RFC 10024's
hybrid share — the 1088-octet ML-KEM-768 ciphertext then the 32-octet
x25519 public value, ML-KEM first despite the group's name.
-/
def Kex.serverShareSize : Kex → Nat
  | .x25519 => x25519KeySize
  | .pq => 1088 + 32

/-- The line protocol's key-exchange token, spelled as the Makefile's
KEX variable spells the build. -/
def kexOf? : String → Option Kex
  | "x25519" => some .x25519
  | "pq" => some .pq
  | _ => none

/--
RFC 9846 §4.1.4: the Random of a HelloRetryRequest is this fixed
value, the SHA-256 of the string "HelloRetryRequest". A ServerHello
carrying it is a HelloRetryRequest and nothing else; `selftest` pins
both the literal and the hash identity.
-/
def helloRetryRequestRandom : ByteArray :=
  (hexToBytes? ("cf21ad74e59a6111be1d8c021e65b891" ++ "c2a211167abb8c5e079e09e2c8a8339c")).getD
    (ByteArray.mk #[0])

/-! ## Readers over the RFC's vector notation -/

/--
Byte-string equality through the hex rendering, which
`Spec.Bytes.bytesToHex_inj` makes faithful. ByteArray carries no
`LawfulBEq` instance, so a proof cannot read `=` back out of `==`;
`Spec.Aead` compares tags the same way.
-/
def bytesEq (a b : ByteArray) : Bool := bytesToHex a == bytesToHex b

/-- Byte equality implies hex equality, so `bytesEq` is a faithful
equality test in both directions. -/
theorem eq_of_bytesEq {a b : ByteArray} (h_hex_eq : bytesEq a b = true) : a = b :=
  bytesToHex_inj a b (eq_of_beq h_hex_eq)

/-- A refusal with the alert it earns; `p` is the condition the RFC
requires to hold. -/
def ensure (p : Prop) [Decidable p] (alert : Alert) : Except Alert Unit :=
  if p then .ok () else .error alert

/-- The octet at `off`. Reading past the end of a message is
"the length of the message was incorrect", a decode_error (§6.2). -/
def u8At (b : ByteArray) (off : Nat) : Except Alert Nat :=
  if h : off < b.size then .ok b[off].toNat else .error .decodeError

/-- A `uint16` at `off`, network byte order (RFC 9846 §3.3). -/
def u16At (b : ByteArray) (off : Nat) : Except Alert Nat := do
  return (← u8At b off) * 256 + (← u8At b (off + 1))

/-- A `uint24` at `off`, network byte order (RFC 9846 §3.3). -/
def u24At (b : ByteArray) (off : Nat) : Except Alert Nat := do
  return (← u16At b off) * 256 + (← u8At b (off + 2))

/-- `len` octets at `off`, or decode_error when the message stops
short of them. -/
def bytesAt (b : ByteArray) (off len : Nat) : Except Alert ByteArray :=
  if off + len ≤ b.size then .ok (b.extract off (off + len)) else .error .decodeError

/-- An `opaque x<0..2^8-1>` vector at `off` (RFC 9846 §3.4): the
length octet and the octets it counts, with the offset just past
them. -/
def vec8At (b : ByteArray) (off : Nat) : Except Alert (ByteArray × Nat) := do
  let n ← u8At b off
  return (← bytesAt b (off + 1) n, off + 1 + n)

/-- An `opaque x<0..2^16-1>` vector at `off` (RFC 9846 §3.4). -/
def vec16At (b : ByteArray) (off : Nat) : Except Alert (ByteArray × Nat) := do
  let n ← u16At b off
  return (← bytesAt b (off + 2) n, off + 2 + n)

/-- An `opaque x<0..2^24-1>` vector at `off` (RFC 9846 §3.4). -/
def vec24At (b : ByteArray) (off : Nat) : Except Alert (ByteArray × Nat) := do
  let n ← u24At b off
  return (← bytesAt b (off + 3) n, off + 3 + n)

/--
RFC 9846 §4: `struct { HandshakeType msg_type; uint24 length; body }`.
The body is the `length` octets that follow, and the message holds
exactly one of them — a length that does not account for every octet
handed in is a decode_error (§6.2), and a `msg_type` other than the
one asked for is the wrong message for this parser,
unexpected_message (§6.2).
-/
def messageBody (msg : ByteArray) (msgType : Nat) : Except Alert ByteArray := do
  let t ← u8At msg 0
  ensure (t = msgType) .unexpectedMessage
  let len ← u24At msg 1
  ensure (msg.size = 4 + len) .decodeError
  bytesAt msg 4 len

/-! ## The extension block -/

/--
RFC 9846 §4.2: `struct { ExtensionType extension_type; opaque
extension_data<0..2^16-1>; } Extension`, repeated until the block ends.
`fuel` bounds the walk; every extension costs at least four octets, so
the block's own size is fuel enough.
-/
def extensionsAt (b : ByteArray) :
    Nat → Nat → List (Nat × ByteArray) → Except Alert (List (Nat × ByteArray))
  | 0, off, acc => if off = b.size then .ok acc.reverse else .error .decodeError
  | fuel + 1, off, acc =>
    if off = b.size then .ok acc.reverse
    else do
      let t ← u16At b off
      let (data, off') ← vec16At b (off + 2)
      extensionsAt b fuel off' ((t, data) :: acc)

/-- Whether a list of extension types repeats one. -/
def hasDuplicate : List Nat → Bool
  | [] => false
  | t :: rest => rest.contains t || hasDuplicate rest

/--
The whole extension block as `(type, data)` pairs, in the order they
appear. The block must end exactly where its length says (§4.2's
vector framing, decode_error), and RFC 9846 §4.2 allows at most one
extension of each type: "an endpoint that receives multiple extensions
of the same type MUST abort the handshake with an illegal_parameter
alert".
-/
def extensionList (b : ByteArray) : Except Alert (List (Nat × ByteArray)) := do
  let exts ← extensionsAt b b.size 0 []
  ensure (hasDuplicate (exts.map Prod.fst) = false) .illegalParameter
  return exts

/-- The data of the extension with this type, if the block carries
it. -/
def extensionData? (exts : List (Nat × ByteArray)) (t : Nat) : Option ByteArray :=
  (exts.find? (fun e => e.1 == t)).map (fun e => e.2)

/-- An extension the message cannot do without, with the alert its
absence earns. -/
def requiredExtension (exts : List (Nat × ByteArray)) (t : Nat) (alert : Alert) :
    Except Alert ByteArray :=
  match extensionData? exts t with
  | some data => .ok data
  | none => .error alert

/--
RFC 9846 §4.2 gives two rules for an extension that has no business in
the message carrying it: an extension "which it recognizes and which is
not specified for the message in which it appears" is an
illegal_parameter, and a response the endpoint "did not send the
corresponding extension request" for is an unsupported_extension. Which
one fires therefore turns on `knownExtension`, this client's table of
recognized code points.
-/
def wrongMessageAlert (t : Nat) : Alert :=
  if knownExtension t then .illegalParameter else .unsupportedExtension

/-- Every extension in the block must be one the message admits; the
first that is not decides the alert. -/
def ensureAllowed (allowed : List Nat) (alertFor : Nat → Alert)
    (exts : List (Nat × ByteArray)) : Except Alert Unit :=
  match exts.find? (fun e => !allowed.contains e.1) with
  | some (t, _) => .error (alertFor t)
  | none => .ok ()

/-! ## ServerHello and HelloRetryRequest (RFC 9846 §4.1.3, §4.1.4) -/

/-- The ServerHello fields that precede the extension block, plus the
block itself. §4.1.4 gives a HelloRetryRequest this same layout, so
both are read through here first. -/
structure ServerHelloPrefix where
  /-- Random: 32 octets (§4.1.3). -/
  random : ByteArray
  /-- legacy_session_id_echo<0..32> (§4.1.3). -/
  sessionIdEcho : ByteArray
  /-- extensions<6..2^16-1>, already split into typed pairs. -/
  extensions : List (Nat × ByteArray)

/-- What an accepted ServerHello hands the client (RFC 9846 §4.1.3). -/
structure ServerHello where
  /-- The echoed legacy_session_id, for the caller to compare against
  the one it sent (§4.1.3). -/
  sessionIdEcho : ByteArray
  /-- The server's key_exchange value from key_share (§4.2.8): the
  x25519 public value, or the hybrid build's ML-KEM-768 ciphertext
  then x25519 public value (RFC 10024). -/
  keyExchange : ByteArray
  /-- pre_shared_key's selected_identity, absent when the server did
  not accept a PSK (§4.2.11). -/
  selectedIdentity : Option Nat

/-- What an accepted HelloRetryRequest hands the client
(RFC 9846 §4.1.4). -/
structure HelloRetryRequest where
  /-- The echoed legacy_session_id (§4.1.3). -/
  sessionIdEcho : ByteArray
  /-- The cookie the second ClientHello must carry back (§4.2.2). -/
  cookie : ByteArray

/-- A ServerHello is one of two messages, and RFC 9846 §4.1.4 makes
the Random the only thing that tells them apart. -/
inductive ServerHelloKind
  /-- The server's half of the key exchange (§4.1.3). -/
  | serverHello (fields : ServerHello)
  /-- A retry request: same format, special Random (§4.1.4). -/
  | helloRetryRequest (fields : HelloRetryRequest)

/-- The extension types RFC 9846 §4.2 specifies for a ServerHello.
Nothing else may appear in one. -/
def serverHelloExtensions : List Nat := [extPreSharedKey, extSupportedVersions, extKeyShare]

/-- The extension types RFC 9846 §4.2 specifies for a
HelloRetryRequest. -/
def helloRetryRequestExtensions : List Nat :=
  [extSupportedVersions, extCookie, extKeyShare]

/--
RFC 9846 §4.1.3, read down the struct:

* `legacy_version` is 0x0303 exactly. §4.1.3 freezes the field at that
  value and §4.2.1's real version moves to supported_versions, so
  any other legacy_version is an illegal_parameter;
* `random` is 32 octets, handed on for the §4.1.4 comparison;
* `legacy_session_id_echo<0..32>`: a longer echo is a field out of the
  specified range, decode_error (§6.2). Whether it matches the
  ClientHello's is the caller's check — §4.1.3 makes a mismatch an
  illegal_parameter, but this parser sees one message and not the
  ClientHello that preceded it, so the echo travels out in the fields;
* `cipher_suite`: profile — the client offers
  TLS_CHACHA20_POLY1305_SHA256 alone, and §4.1.3 makes a suite that
  was not offered an illegal_parameter;
* `legacy_compression_method`: profile — no compression, and §4.1.3
  fixes the value at 0 with an illegal_parameter for anything else;
* `extensions<6..2^16-1>`: the block ends the message, and a block
  under six octets cannot hold even one extension, so it is out of the
  specified range (§6.2).
-/
def serverHelloPrefix (msg : ByteArray) : Except Alert ServerHelloPrefix := do
  let body ← messageBody msg serverHelloType
  -- §4.1.3: legacy_version "MUST be set to 0x0303"; a client that sees
  -- any other value MUST abort with illegal_parameter.
  let legacy ← u16At body 0
  ensure (legacy = legacyVersion) .illegalParameter
  let random ← bytesAt body 2 32
  let (sessionIdEcho, off) ← vec8At body 34
  ensure (sessionIdEcho.size ≤ 32) .decodeError
  -- §4.1.3: legacy_session_id_echo is "the contents of the client's
  -- legacy_session_id field", and a client that receives any other
  -- value MUST abort with illegal_parameter. This profile needs no
  -- middlebox compatibility, so hsmsg.c sends the field empty and the
  -- only echo that can match is the empty one. Like the cipher suite
  -- and the group, the offer is a constant, so the check belongs here
  -- rather than with the caller.
  ensure (sessionIdEcho.size = 0) .illegalParameter
  let suite ← u16At body off
  ensure (suite = cipherSuite) .illegalParameter
  let compression ← u8At body (off + 2)
  ensure (compression = 0) .illegalParameter
  let (extBytes, off') ← vec16At body (off + 3)
  ensure (off' = body.size) .decodeError
  ensure (6 ≤ extBytes.size) .decodeError
  let extensions ← extensionList extBytes
  return { random, sessionIdEcho, extensions }

/--
RFC 9846 §4.2.1: in a ServerHello or HelloRetryRequest the
supported_versions extension_data is one `ProtocolVersion
selected_version`, not a list, so any length but two is out of the
specified range (§6.2). §9.2 makes the extension required in both
messages, and its absence a missing_extension. A version "not offered
by the client or ... prior to TLS 1.3" is an illegal_parameter
(§4.2.1); the profile offers TLS 1.3 alone, so 0x0304 is the only
value that passes.
-/
def checkSelectedVersion (exts : List (Nat × ByteArray)) : Except Alert Unit := do
  let data ← requiredExtension exts extSupportedVersions .missingExtension
  ensure (data.size = 2) .decodeError
  ensure (bytesToNatBE data = tls13Version) .illegalParameter

/--
RFC 9846 §4.2.11: pre_shared_key in a ServerHello is `uint16
selected_identity`, two octets and no more, present only when the
server accepted the PSK. Profile: the client offers exactly one
identity, so the only index in range is 0, and §4.2.11 makes an
out-of-range selected_identity an illegal_parameter. Whether the
extension may appear at all is `serverHelloFields`' business: it turns
on what the ClientHello offered, which this reader is not told.
-/
def readSelectedIdentity? (exts : List (Nat × ByteArray)) : Except Alert (Option Nat) :=
  match extensionData? exts extPreSharedKey with
  | none => .ok none
  | some data => do
    ensure (data.size = 2) .decodeError
    let identity ← u16At data 0
    ensure (identity = 0) .illegalParameter
    return some identity

/--
RFC 9846 §4.2.8: key_share in a ServerHello is `KeyShareServerHello`,
one `KeyShareEntry` — `NamedGroup group` then `opaque
key_exchange<1..2^16-1>` — filling the extension exactly. §9.2 requires
the extension "for DHE or ECDHE key exchange", which both of the
profile's auth modes use (the PSK mode is psk_dhe_ke), so its absence
is a missing_extension.

Profile: the build's `Kex` group is the only one offered, and a group
the client did not offer is an illegal_parameter (§4.2.8); the
key_exchange value is `kex.serverShareSize` octets — 32 for an x25519
public value (§4.2.8.2), 1120 for the hybrid's ciphertext-then-public
share (RFC 10024) — so any other length is out of the specified range.
Whether the x25519 value is a low-order point is not decided here:
§7.4.2 puts that check on the computed shared secret, after the key
exchange this parser only feeds.
-/
def readKeyShare (kex : Kex) (exts : List (Nat × ByteArray)) : Except Alert ByteArray := do
  let share ← requiredExtension exts extKeyShare .missingExtension
  let group ← u16At share 0
  ensure (group = kex.code) .illegalParameter
  let (keyExchange, off) ← vec16At share 2
  ensure (off = share.size) .decodeError
  ensure (keyExchange.size = kex.serverShareSize) .decodeError
  return keyExchange

/--
The ServerHello branch (RFC 9846 §4.1.3): only the three extensions
§4.2 specifies for a ServerHello may appear, a pre_shared_key response
only when the ClientHello offered one, the key share is read and
narrowed to the build's one group, and the PSK identity comes back
when the server accepted one.
-/
def serverHelloFields (kex : Kex) (pskOffered : Bool) (p : ServerHelloPrefix) :
    Except Alert ServerHello := do
  ensureAllowed serverHelloExtensions wrongMessageAlert p.extensions
  -- RFC 9846 §4.2: a server MUST NOT send an extension response the
  -- client did not request, and a client that receives one MUST abort
  -- with unsupported_extension. `pre_shared_key` is the one response
  -- whose admissibility depends on what the ClientHello offered, so it
  -- is the one the profile cannot settle from the message alone.
  ensure (pskOffered || (extensionData? p.extensions extPreSharedKey).isNone) .unsupportedExtension
  let keyExchange ← readKeyShare kex p.extensions
  let selectedIdentity ← readSelectedIdentity? p.extensions
  return { sessionIdEcho := p.sessionIdEcho, keyExchange, selectedIdentity }

/--
The HelloRetryRequest branch (RFC 9846 §4.1.4).

* only the three §4.2 HelloRetryRequest extensions may appear;
* key_share here is `NamedGroup selected_group`, two octets and no
  key (§4.2.8) — and the profile rejects every one of them. The client
  offers a key share for its build's one group and for nothing else,
  so a retry selecting that group "would not result in any change in
  the ClientHello", which §4.1.4 makes an illegal_parameter, and a
  retry selecting any other group asks for one the client did not
  offer, which §4.2.8 makes an illegal_parameter too;
* cookie is therefore required: it is the only change a retry can ask
  this client for, and a retry that asks for no change is §4.1.4's
  illegal_parameter. It is not a §9.2 required extension, so its
  absence is not a missing_extension;
* `struct { opaque cookie<1..2^16-1>; }` (§4.2.2) fills the extension
  exactly, and an empty cookie is out of the specified range.
-/
def helloRetryRequestFields (p : ServerHelloPrefix) : Except Alert HelloRetryRequest := do
  ensureAllowed helloRetryRequestExtensions wrongMessageAlert p.extensions
  ensure ((extensionData? p.extensions extKeyShare).isNone = true) .illegalParameter
  let data ← requiredExtension p.extensions extCookie .illegalParameter
  let (cookie, off) ← vec16At data 0
  ensure (off = data.size) .decodeError
  ensure (cookie.size ≠ 0) .decodeError
  return { sessionIdEcho := p.sessionIdEcho, cookie }

/--
RFC 9846 §4.1.3 and §4.1.4: one message type, two meanings. The shared
prefix is read first, then §4.2.1's "clients MUST check for this
extension prior to processing the rest of the ServerHello" puts the
selected version next, and only then does the Random decide which
message this is.

The §4.1.3 downgrade sentinels are deliberately absent: the RFC scopes
that check to "TLS 1.3 clients receiving a ServerHello indicating TLS
1.2 or below", and `checkSelectedVersion` has already refused every
such message, so no accepted message can reach the check.
-/
def parseServerHello (kex : Kex) (pskOffered : Bool) (msg : ByteArray) :
    Except Alert ServerHelloKind := do
  let p ← serverHelloPrefix msg
  checkSelectedVersion p.extensions
  if bytesEq p.random helloRetryRequestRandom then
    return .helloRetryRequest (← helloRetryRequestFields p)
  else
    return .serverHello (← serverHelloFields kex pskOffered p)

/-! ## EncryptedExtensions (RFC 9846 §4.3.1) -/

/-- What an accepted EncryptedExtensions hands the client. -/
structure EncryptedExtensions where
  /-- RFC 8449 §4's RecordSizeLimit, when the server answered the
  client's own; absent when it did not. -/
  recordSizeLimit : Option Nat

/--
The extension types this profile admits in EncryptedExtensions: the
server_name acknowledgement (RFC 6066 §3), supported_groups
(RFC 9846 §4.2.7), and record_size_limit (RFC 8449 §4), which
`CLAUDE.md` says the client always sends.
-/
def encryptedExtensionsAllowed : List Nat :=
  [extSupportedGroups, extRecordSizeLimit]

/--
Extension types RFC 9846 §4.2 permits in EncryptedExtensions that this
client never requests: server_name(0) — the profile sends no SNI, so a
server_name acknowledgement is a response to a request that never went
out — max_fragment_length(1), use_srtp(14),
heartbeat(15), application_layer_protocol_negotiation(16), the RFC 7250
certificate-type pair (19, 20), and early_data(42) — the profile has no
0-RTT and no raw public keys. §4.2 makes an unrequested response an
unsupported_extension, which is a different refusal from §4.3.1's
illegal_parameter for an extension that has no business in this message
at all.
-/
def encryptedExtensionsUnrequested : List Nat :=
  [extServerName, 1, 14, 15, 16, 19, 20, extEarlyData]

/-- The alert an extension that does not belong in EncryptedExtensions
earns: unsupported_extension when the RFC allows it here but the client
never asked for it (§4.2), and otherwise §4.3.1's illegal_parameter for
a forbidden extension, through `wrongMessageAlert`. -/
def encryptedExtensionsAlert (t : Nat) : Alert :=
  if encryptedExtensionsUnrequested.contains t then .unsupportedExtension
  else wrongMessageAlert t

/--
RFC 8449 §4: `uint16 RecordSizeLimit`, two octets and no more, so any
other length is out of the specified range (§6.2). A value below 64 is
a fatal error with an illegal_parameter alert. A value above the
protocol's own limit is deliberately *not* refused: RFC 8449 says an
endpoint "MUST NOT send records larger than the protocol-defined
limit" whatever the peer asked for, which caps the sender rather than
rejecting the message.
-/
def readRecordSizeLimit (data : ByteArray) : Except Alert Nat := do
  ensure (data.size = 2) .decodeError
  let limit ← u16At data 0
  ensure (64 ≤ limit) .illegalParameter
  return limit

/-- RFC 8449 §4's limit when the server answered the client's own
extension, and `none` when it did not. -/
def readRecordSizeLimit? (exts : List (Nat × ByteArray)) : Except Alert (Option Nat) :=
  match extensionData? exts extRecordSizeLimit with
  | none => .ok none
  | some data => do return some (← readRecordSizeLimit data)

/-- RFC 9846 §4.2.7: supported_groups carries `NamedGroup
named_group_list<2..2^16-2>`, an even number of octets and at least
one group, filling the extension exactly. The groups themselves go
unread: §4.2.7 tells the client not to act on them during this
handshake. -/
def checkSupportedGroups (exts : List (Nat × ByteArray)) : Except Alert Unit :=
  match extensionData? exts extSupportedGroups with
  | none => .ok ()
  | some data => do
    let (groups, off) ← vec16At data 0
    ensure (off = data.size) .decodeError
    ensure (2 ≤ groups.size ∧ groups.size % 2 = 0) .decodeError

/--
RFC 9846 §4.3.1: `struct { Extension extensions<0..2^16-1>; }`, and
"the client MUST check EncryptedExtensions for the presence of any
forbidden extensions and if any are found MUST abort the handshake
with an illegal_parameter alert".

The block may be empty. The profile admits two extensions here:
supported_groups, a `NamedGroup named_group_list<2..2^16-2>` whose
contents §4.2.7 tells the client not to act on during the handshake —
so the framing is checked and the groups go unread — and
record_size_limit, the only one whose value the client needs. This
client sends no server_name, so a server_name acknowledgement is an
unrequested response and earns §4.2's unsupported_extension.
-/
def parseEncryptedExtensions (msg : ByteArray) : Except Alert EncryptedExtensions := do
  let body ← messageBody msg encryptedExtensionsType
  let (extBytes, off) ← vec16At body 0
  ensure (off = body.size) .decodeError
  let exts ← extensionList extBytes
  ensureAllowed encryptedExtensionsAllowed encryptedExtensionsAlert exts
  checkSupportedGroups exts
  let recordSizeLimit ← readRecordSizeLimit? exts
  return { recordSizeLimit }

/-! ## Certificate (RFC 9846 §4.4.2) -/

/-- What an accepted Certificate hands the client. -/
structure Certificate where
  /-- How many CertificateEntry structures the list held. -/
  entryCount : Nat
  /-- The first entry's cert_data: the end-entity certificate
  (§4.4.2, "the sender's certificate MUST come first"). -/
  leafCert : ByteArray

/--
The CertificateEntry list (RFC 9846 §4.4.2), walked entry by entry:
`opaque cert_data<1..2^24-1>` then `Extension extensions<0..2^16-1>`.
An empty cert_data is out of the specified range (§6.2).

Profile: the per-entry extensions must be empty. §4.4.2 admits the
OCSP status_request and signed_certificate_timestamp responses there,
and §4.2 makes any response the client did not request an
unsupported_extension — this client requests neither. The entry's
opaque is cert_data and never an ASN1_subjectPublicKeyInfo, because
that choice is made by a server_certificate_type the profile refuses in
EncryptedExtensions: no RFC 7250 raw public keys.

`fuel` bounds the walk; every entry costs at least six octets, so the
list's own size is fuel enough.
-/
def entriesAt (b : ByteArray) : Nat → Nat → List ByteArray → Except Alert (List ByteArray)
  | 0, off, acc => if off = b.size then .ok acc.reverse else .error .decodeError
  | fuel + 1, off, acc =>
    if off = b.size then .ok acc.reverse
    else do
      let (cert, off1) ← vec24At b off
      ensure (cert.size ≠ 0) .decodeError
      let (exts, off2) ← vec16At b off1
      ensure (exts.size = 0) .unsupportedExtension
      entriesAt b fuel off2 (cert :: acc)

/--
RFC 9846 §4.4.2: `struct { opaque certificate_request_context<0..2^8-1>;
CertificateEntry certificate_list<0..2^24-1>; }`.

* certificate_request_context "SHALL be zero length" in the case of
  server authentication, which is the only case this client sees. The
  RFC states the requirement and names no alert for breaking it, so
  the refusal is `unspecified`;
* the list ends the message;
* §4.4.2.4: "If the server supplies an empty Certificate message, the
  client MUST abort the handshake with a decode_error alert."

Which chains are acceptable is not decided here. In the CA trust mode
that belongs to `Spec.X509.parse`, which reads this same
CertificateEntry list; in the pinned mode nothing reads the
certificates at all — they are hashed into the transcript and the
pinned key answers CertificateVerify.
-/
def parseCertificate (msg : ByteArray) : Except Alert Certificate := do
  let body ← messageBody msg certificateType
  let (context, off) ← vec8At body 0
  ensure (context.size = 0) .unspecified
  let (list, off') ← vec24At body off
  ensure (off' = body.size) .decodeError
  ensure (list.size ≠ 0) .decodeError
  let certs ← entriesAt list list.size 0 []
  match certs with
  | [] => .error .decodeError
  | leaf :: rest => return { entryCount := rest.length + 1, leafCert := leaf }

/-! ## CertificateVerify (RFC 9846 §4.4.3) -/

/--
The one SignatureScheme the build pins. `CLAUDE.md` fixes it at build
time through the Makefile's PIN variable, so exactly one of these is
live in a library object.
-/
inductive Scheme
  /-- rsa_pss_rsae_sha256(0x0804), RSA-PSS up to 3072 bits. -/
  | rsa
  /-- ecdsa_secp256r1_sha256(0x0403), ECDSA over NIST P-256. -/
  | p256
deriving BEq

/-- The SignatureScheme code point (RFC 9846 §4.2.3). -/
def Scheme.code : Scheme → Nat
  | .rsa => 0x0804
  | .p256 => 0x0403

/-- The line protocol's scheme token, spelled as `Spec.X509.algOf?`
spells the matching certificate algorithm. -/
def schemeOf? : String → Option Scheme
  | "rsa" => some .rsa
  | "p256" => some .p256
  | _ => none

/-- What an accepted CertificateVerify hands the client. -/
structure CertificateVerify where
  /-- The SignatureScheme the server signed under (§4.4.3). -/
  algorithm : Nat
  /-- The signature octets, for the verifier that runs next. -/
  signature : ByteArray

/--
RFC 9846 §4.4.3: the octets the CertificateVerify signature covers —
64 octets of 0x20, the context string "TLS 1.3, server
CertificateVerify", a single zero octet, and the transcript hash. The
client builds this and hands it, not the transcript hash alone, to the
pinned key's verifier.
-/
def verifyContent (transcriptHash : ByteArray) : ByteArray :=
  ByteArray.mk (Array.replicate 64 0x20) ++ ascii "TLS 1.3, server CertificateVerify"
    ++ ByteArray.mk #[0] ++ transcriptHash

/--
RFC 9846 §4.4.3: `struct { SignatureScheme algorithm; opaque
signature<0..2^16-1>; }`, filling the message exactly.

* `algorithm`: profile — the build pins one scheme, so it is the only
  code point that passes. §4.4.3 requires the algorithm be one the
  client offered but names no alert for one that is not, so the
  refusal is `unspecified`;
* `signature`: `opaque signature<0..2^16-1>`, exact-fill. §4.4.3 sets
  no length rule of its own — what lengths a scheme admits is the
  verifier's business, so no bound is imposed here. Whether the
  signature verifies is not decided here either; §4.4.3 makes that
  failure a decrypt_error, and it belongs to `Spec.Rsa.pssVerify` or
  `Spec.P256.ecdsaVerify` over `verifyContent`.
-/
def parseCertificateVerify (scheme : Scheme) (msg : ByteArray) :
    Except Alert CertificateVerify := do
  let body ← messageBody msg certificateVerifyType
  let algorithm ← u16At body 0
  ensure (algorithm = scheme.code) .unspecified
  let (signature, off) ← vec16At body 2
  ensure (off = body.size) .decodeError
  -- §4.4.3 frames the signature as `opaque signature<0..2^16-1>` and
  -- says nothing about its length: what lengths are admissible is the
  -- signature algorithm's business, settled when the signature is
  -- verified. hsparse.c leaves it there too.
  return { algorithm, signature }

/-! ## Encoders, for the selftest and for minting differential inputs -/

/-- A `uint16` in network byte order (RFC 9846 §3.3). -/
def u16 (n : Nat) : ByteArray := natToBytesBE n 2

/-- A `uint24` in network byte order (RFC 9846 §3.3). -/
def u24 (n : Nat) : ByteArray := natToBytesBE n 3

/-- An `opaque x<0..2^8-1>` vector: the length octet and its contents
(RFC 9846 §3.4). -/
def vec8 (b : ByteArray) : ByteArray := ByteArray.mk #[UInt8.ofNat b.size] ++ b

/-- An `opaque x<0..2^16-1>` vector (RFC 9846 §3.4). -/
def vec16 (b : ByteArray) : ByteArray := u16 b.size ++ b

/-- An `opaque x<0..2^24-1>` vector (RFC 9846 §3.4). -/
def vec24 (b : ByteArray) : ByteArray := u24 b.size ++ b

/-- One Extension: type and its data vector (RFC 9846 §4.2). -/
def extension (t : Nat) (data : ByteArray) : ByteArray := u16 t ++ vec16 data

/-- One Handshake structure: msg_type, uint24 length, body
(RFC 9846 §4). -/
def message (msgType : Nat) (body : ByteArray) : ByteArray :=
  ByteArray.mk #[UInt8.ofNat msgType] ++ vec24 body

/-- A ServerHello body around a caller-supplied Random and extension
block (RFC 9846 §4.1.3), with the profile's cipher suite and no
compression. -/
def serverHelloBody (random sessionId exts : ByteArray) : ByteArray :=
  u16 legacyVersion ++ random ++ vec8 sessionId ++ u16 cipherSuite ++ ByteArray.mk #[0] ++ vec16 exts

/-- One CertificateEntry: cert_data and its extension vector
(RFC 9846 §4.4.2). -/
def certificateEntry (cert exts : ByteArray) : ByteArray := vec24 cert ++ vec16 exts

/-! ## Selftest -/

/--
Structural checks: the message grammar has no third-party vectors, so
the selftest builds one on-profile message of each kind, checks the
fields come back, and then walks one case per refusal the RFC and the
profile owe. The §4.1.4 Random is pinned twice over — against the
literal §4.1.3 prints and against its stated derivation, the SHA-256 of
"HelloRetryRequest". The ServerHello rows run under both `Kex` values:
one accepted message per build, the cross-group refusal each way, the
hybrid share length at its boundary, and the retry branch under the
hybrid build. Functional coverage against the C comes from the
differential run.
-/
def selftest : Bool := Id.run do
  let random := ByteArray.mk (Array.replicate 32 0x5a)
  -- hsmsg.c offers an empty legacy_session_id, so the echo is empty.
  let sessionId := ByteArray.mk #[]
  let share := ByteArray.mk (Array.replicate 32 0x77)
  let versionExt := extension extSupportedVersions (u16 tls13Version)
  let keyShareExt := extension extKeyShare (u16 x25519Group ++ vec16 share)
  let hex := bytesToHex
  -- The §4.1.4 Random, from the §4.1.3 literal and from its derivation.
  let hrrRandomOk := hex helloRetryRequestRandom ==
      "cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c" &&
    hex (Spec.Sha256.sha256 (ascii "HelloRetryRequest")) == hex helloRetryRequestRandom
  -- ServerHello: the profile's own message, and the fields it yields.
  let serverHelloOf (exts : ByteArray) : ByteArray :=
    message serverHelloType (serverHelloBody random sessionId exts)
  let good := serverHelloOf (versionExt ++ keyShareExt)
  let acceptsShareUnder (kex : Kex) (msg : ByteArray) (want : ByteArray)
      (identity : Option Nat) : Bool :=
    match parseServerHello kex true msg with
    | .ok (.serverHello fields) =>
      hex fields.sessionIdEcho == hex sessionId && hex fields.keyExchange == hex want &&
        fields.selectedIdentity == identity
    | _ => false
  let acceptsShare (msg : ByteArray) (identity : Option Nat) : Bool :=
    acceptsShareUnder .x25519 msg share identity
  let rejectsUnder (kex : Kex) (msg : ByteArray) : Bool :=
    (parseServerHello kex true msg).toOption.isNone
  let rejects (msg : ByteArray) : Bool := rejectsUnder .x25519 msg
  let serverHelloOk := acceptsShare good none &&
    -- §4.1.3: legacy_version is frozen at 0x0303.
    rejects (message serverHelloType (ByteArray.mk #[0x03, 0x04] ++ random ++ vec8 sessionId ++
      u16 cipherSuite ++ ByteArray.mk #[0] ++ vec16 (versionExt ++ keyShareExt))) &&
    -- §4.1.3: any echo but the empty one we offered is illegal_parameter.
    rejects (message serverHelloType (serverHelloBody random
      (ByteArray.mk (Array.replicate 32 0xa5)) (versionExt ++ keyShareExt))) &&
    -- §4.2.11: the one identity the profile offers is index 0.
    acceptsShare (serverHelloOf (versionExt ++ keyShareExt ++
      extension extPreSharedKey (u16 0))) (some 0) &&
    rejects (serverHelloOf (versionExt ++ keyShareExt ++
      extension extPreSharedKey (u16 1))) &&
    -- §4: the length field counts the body, and one call carries one message.
    rejects (good ++ ByteArray.mk #[0]) &&
    rejects (good.extract 0 (good.size - 1)) &&
    rejects (ByteArray.mk #[UInt8.ofNat certificateType] ++ good.extract 1 good.size) &&
    -- §9.2 and §4.2.1: supported_versions is required and pins 0x0304.
    rejects (serverHelloOf keyShareExt) &&
    rejects (serverHelloOf (extension extSupportedVersions (u16 0x0303) ++ keyShareExt)) &&
    rejects (serverHelloOf (extension extSupportedVersions (u16 tls13Version ++ u16 0) ++
      keyShareExt)) &&
    -- §9.2 and §4.2.8: key_share is required, x25519 only, 32 octets only.
    rejects (serverHelloOf (versionExt ++ extension extCookie (vec16 (ascii "c")))) &&
    rejects (serverHelloOf (versionExt ++
      extension extKeyShare (u16 0x0017 ++ vec16 share))) &&
    rejects (serverHelloOf (versionExt ++
      extension extKeyShare (u16 x25519Group ++ vec16 (share.extract 0 31)))) &&
    -- §4.2: one extension of each type, and only the three §4.2 admits here.
    rejects (serverHelloOf (versionExt ++ versionExt ++ keyShareExt)) &&
    rejects (serverHelloOf (versionExt ++ keyShareExt ++
      extension extServerName ByteArray.empty)) &&
    rejects (serverHelloOf (versionExt ++ keyShareExt ++
      extension 0xfeed ByteArray.empty))
  -- §4.1.3: the profile's cipher suite, no compression, a 32-octet echo.
  let handBuilt (suite : Nat) (compression : Nat) (sid : ByteArray) : ByteArray :=
    message serverHelloType (u16 0x0303 ++ random ++ vec8 sid ++ u16 suite ++
      ByteArray.mk #[UInt8.ofNat compression] ++ vec16 (versionExt ++ keyShareExt))
  let profileOk := acceptsShare (handBuilt cipherSuite 0 sessionId) none &&
    rejects (handBuilt 0x1301 0 sessionId) &&
    rejects (handBuilt cipherSuite 1 sessionId) &&
    rejects (handBuilt cipherSuite 0 (ByteArray.mk (Array.replicate 33 0xa5)))
  -- §4.1.4: the same format under the special Random is a retry request.
  let cookie := ascii "retry me"
  let cookieExt := extension extCookie (vec16 cookie)
  let hrrOf (exts : ByteArray) : ByteArray :=
    message serverHelloType (serverHelloBody helloRetryRequestRandom sessionId exts)
  let hrrOk :=
    (match parseServerHello .x25519 true (hrrOf (versionExt ++ cookieExt)) with
     | .ok (.helloRetryRequest fields) =>
       hex fields.cookie == hex cookie && hex fields.sessionIdEcho == hex sessionId
     | _ => false) &&
    -- A retry with no cookie asks for no change; a retry with a key_share
    -- asks for a group the client either already sent or never offered.
    rejects (hrrOf (versionExt ++ extension extKeyShare (u16 x25519Group))) &&
    rejects (hrrOf (versionExt ++ cookieExt ++
      extension extKeyShare (u16 x25519Group))) &&
    rejects (hrrOf (versionExt ++ extension extCookie (vec16 ByteArray.empty))) &&
    -- The Random decides, and only the whole 32 octets do.
    rejects (hrrOf (versionExt ++ keyShareExt)) &&
    acceptsShare (message serverHelloType (serverHelloBody
      (helloRetryRequestRandom.extract 0 31 ++ ByteArray.mk #[0]) sessionId
      (versionExt ++ keyShareExt))) none
  -- The KEX builds (§4.2.8, RFC 10024): each build accepts its own
  -- group's share at its own length and refuses the other build's.
  let hybridShare := ByteArray.mk (Array.replicate 1120 0x88)
  let pqShareExtOf (keyExchange : ByteArray) : ByteArray :=
    extension extKeyShare (u16 Kex.pq.code ++ vec16 keyExchange)
  let kexOk :=
    acceptsShareUnder .pq (serverHelloOf (versionExt ++ pqShareExtOf hybridShare))
      hybridShare none &&
    -- Cross-group, each way: the x25519 share under the hybrid build,
    -- the hybrid share under the x25519 build.
    rejectsUnder .pq good &&
    rejectsUnder .x25519 (serverHelloOf (versionExt ++ pqShareExtOf hybridShare)) &&
    -- Boundary: 1120 octets is the one valid hybrid length; both
    -- neighbors fail.
    rejectsUnder .pq (serverHelloOf (versionExt ++
      pqShareExtOf (hybridShare.extract 0 1119))) &&
    rejectsUnder .pq (serverHelloOf (versionExt ++
      pqShareExtOf (hybridShare ++ ByteArray.mk #[0]))) &&
    -- The retry branch under the hybrid build: the same cookie retry
    -- is accepted, and a retry selecting the hybrid group is refused.
    (match parseServerHello .pq true (hrrOf (versionExt ++ cookieExt)) with
     | .ok (.helloRetryRequest fields) => hex fields.cookie == hex cookie
     | _ => false) &&
    rejectsUnder .pq (hrrOf (versionExt ++ cookieExt ++
      extension extKeyShare (u16 Kex.pq.code)))
  -- §4.3.1 and RFC 8449 §4.
  let encryptedExtensionsOf (exts : ByteArray) : ByteArray :=
    message encryptedExtensionsType (vec16 exts)
  let limitOf (msg : ByteArray) : Option (Option Nat) :=
    (parseEncryptedExtensions msg).toOption.map (fun fields => fields.recordSizeLimit)
  let encryptedExtensionsOk :=
    limitOf (encryptedExtensionsOf ByteArray.empty) == some none &&
    limitOf (encryptedExtensionsOf (extension extRecordSizeLimit (u16 16385))) ==
      some (some 16385) &&
    limitOf (encryptedExtensionsOf (extension extRecordSizeLimit (u16 64))) ==
      some (some 64) &&
    -- RFC 8449 §4: below 64 is fatal; above the protocol limit is not.
    limitOf (encryptedExtensionsOf (extension extRecordSizeLimit (u16 63))) == none &&
    limitOf (encryptedExtensionsOf (extension extRecordSizeLimit (u16 65535))) ==
      some (some 65535) &&
    limitOf (encryptedExtensionsOf (extension extRecordSizeLimit (ByteArray.mk #[64]))) ==
      none &&
    -- The profile has no 0-RTT, so early_data is a response it never asked for.
    limitOf (encryptedExtensionsOf (extension extEarlyData ByteArray.empty)) == none &&
    limitOf (encryptedExtensionsOf (extension extKeyShare (u16 x25519Group))) == none &&
    -- §4.2: this client sends no server_name, so its acknowledgement,
    -- empty or not, is an unrequested response the client refuses.
    limitOf (encryptedExtensionsOf (extension extServerName ByteArray.empty)) == none &&
    limitOf (encryptedExtensionsOf (extension extServerName (ascii "x"))) == none &&
    limitOf (encryptedExtensionsOf (extension extSupportedGroups
      (vec16 (u16 x25519Group)))) == some none &&
    limitOf (encryptedExtensionsOf (extension extSupportedGroups
      (vec16 (ByteArray.mk #[0x00])))) == none &&
    limitOf (message certificateType (vec16 ByteArray.empty)) == none
  -- §4.4.2: the context is empty, the list is not, entries carry no extensions.
  let leaf := ByteArray.mk (Array.replicate 40 0xc1)
  let intermediate := ByteArray.mk (Array.replicate 24 0xc2)
  let certificateOf (context list : ByteArray) : ByteArray :=
    message certificateType (vec8 context ++ vec24 list)
  let entryOf (cert : ByteArray) : ByteArray := certificateEntry cert ByteArray.empty
  let parsedCert (msg : ByteArray) : Option (Nat × String) :=
    (parseCertificate msg).toOption.map (fun fields => (fields.entryCount, hex fields.leafCert))
  let certificateOk :=
    parsedCert (certificateOf ByteArray.empty (entryOf leaf)) == some (1, hex leaf) &&
    parsedCert (certificateOf ByteArray.empty (entryOf leaf ++ entryOf intermediate)) ==
      some (2, hex leaf) &&
    parsedCert (certificateOf (ascii "ctx") (entryOf leaf)) == none &&
    parsedCert (certificateOf ByteArray.empty ByteArray.empty) == none &&
    parsedCert (certificateOf ByteArray.empty (certificateEntry leaf
      (extension 5 ByteArray.empty))) == none &&
    parsedCert (certificateOf ByteArray.empty (entryOf ByteArray.empty)) == none &&
    parsedCert (certificateOf ByteArray.empty (entryOf leaf) ++ ByteArray.mk #[0]) == none &&
    parsedCert (message certificateType (vec8 ByteArray.empty ++ vec24 (entryOf leaf) ++
      ByteArray.mk #[0])) == none
  -- §4.4.3: one pinned scheme, one signature, exact-fill. The
  -- signature's own length is the verifier's business, not this
  -- parser's, so no length but a framing error is refused here.
  let rsaSig := ByteArray.mk (Array.replicate 256 0x33)
  let ecdsaSig := ByteArray.mk (Array.replicate 70 0x44)
  let verifyOf (algorithm : Nat) (sig : ByteArray) : ByteArray :=
    message certificateVerifyType (u16 algorithm ++ vec16 sig)
  let verifies (scheme : Scheme) (msg : ByteArray) (sig : ByteArray) : Bool :=
    match parseCertificateVerify scheme msg with
    | .ok fields => fields.algorithm == scheme.code && hex fields.signature == hex sig
    | .error _ => false
  let refuses (scheme : Scheme) (msg : ByteArray) : Bool :=
    (parseCertificateVerify scheme msg).toOption.isNone
  let certificateVerifyOk :=
    verifies .rsa (verifyOf Scheme.rsa.code rsaSig) rsaSig &&
    verifies .p256 (verifyOf Scheme.p256.code ecdsaSig) ecdsaSig &&
    refuses .rsa (verifyOf Scheme.p256.code rsaSig) &&
    refuses .p256 (verifyOf Scheme.rsa.code ecdsaSig) &&
    verifies .rsa (verifyOf Scheme.rsa.code (ByteArray.mk (Array.replicate 39 0x33)))
      (ByteArray.mk (Array.replicate 39 0x33)) &&
    refuses .rsa (verifyOf Scheme.rsa.code rsaSig ++ ByteArray.mk #[0])
  -- §4.4.3: the signed content is 64 spaces, the context string, a zero, the hash.
  let transcript := Spec.Sha256.sha256 (ascii "transcript")
  let content := verifyContent transcript
  let verifyContentOk := content.size == 130 &&
    hex (content.extract 0 64) == hex (ByteArray.mk (Array.replicate 64 0x20)) &&
    hex (content.extract 64 97) == hex (ascii "TLS 1.3, server CertificateVerify") &&
    content[97]! == 0 && hex (content.extract 98 130) == hex transcript
  return hrrRandomOk && serverHelloOk && profileOk && hrrOk && kexOk &&
    encryptedExtensionsOk && certificateOk && certificateVerifyOk && verifyContentOk

/-! ## Soundness -/

/-- A successful `Except` bind ran its continuation on a value the
first computation actually produced. -/
private theorem exists_of_bind_eq_ok {α β : Type} {x : Except Alert α}
    {f : α → Except Alert β} {b : β} (h_bound : x.bind f = .ok b) :
    ∃ a, x = .ok a ∧ f a = .ok b := by
  cases x with
  | error e => simp [Except.bind] at h_bound
  | ok a => exact ⟨a, rfl, h_bound⟩

/-- A condition the do-block ran past held. -/
private theorem of_ensure_bind {β : Type} {p : Prop} [Decidable p] {alert : Alert}
    {f : Unit → Except Alert β} {b : β} (h_bound : (ensure p alert).bind f = .ok b) :
    p ∧ f () = .ok b := by
  rw [ensure] at h_bound
  cases Decidable.em p with
  | inl h_holds => exact ⟨h_holds, by rwa [if_pos h_holds] at h_bound⟩
  | inr h_fails => rw [if_neg h_fails] at h_bound; simp [Except.bind] at h_bound

/-- The value a do-block returned is the value it accepted. -/
private theorem eq_of_pure_eq_ok {α : Type} {x y : α}
    (h_returned : (pure x : Except Alert α) = .ok y) : x = y := Except.ok.inj h_returned

/-- `bytesAt` returns the byte range it was asked for. -/
private theorem bytesAt_eq {b out : ByteArray} {off len : Nat}
    (h_read : bytesAt b off len = .ok out) : out = b.extract off (off + len) := by
  rw [bytesAt] at h_read
  split at h_read
  · exact (Except.ok.inj h_read).symm
  · simp at h_read

/--
Framing soundness (RFC 9846 §4). An accepted body is exactly the
octets after the four-octet header, and the header's `uint24 length`
counts every one of them — so the message holds one Handshake
structure and nothing else.
-/
theorem messageBody_sound (msg body : ByteArray) (msgType : Nat)
    (h_framed : messageBody msg msgType = .ok body) :
    body = msg.extract 4 msg.size ∧ msg.size = 4 + body.size := by
  rw [messageBody] at h_framed
  obtain ⟨_, -, h_framed⟩ := exists_of_bind_eq_ok h_framed
  obtain ⟨-, h_framed⟩ := of_ensure_bind h_framed
  obtain ⟨len, -, h_framed⟩ := exists_of_bind_eq_ok h_framed
  obtain ⟨h_len_counts, h_framed⟩ := of_ensure_bind h_framed
  have h_body := bytesAt_eq h_framed
  have h_size : body.size = len := by
    rw [h_body, ByteArray.size_extract]
    omega
  refine ⟨?_, by omega⟩
  rw [h_body, h_len_counts]

/--
An accepted CertificateEntry list yields only nonempty certificates:
`opaque cert_data<1..2^24-1>` admits no empty entry (RFC 9846 §4.4.2).
-/
private theorem entriesAt_nonempty (b : ByteArray) : ∀ (fuel off : Nat)
    (acc certs : List ByteArray), (∀ c ∈ acc, c.size ≠ 0) →
    entriesAt b fuel off acc = .ok certs → ∀ c ∈ certs, c.size ≠ 0 := by
  intro fuel
  induction fuel with
  | zero =>
    intro off acc certs h_acc h_walk
    rw [entriesAt] at h_walk
    split at h_walk
    · obtain rfl := Except.ok.inj h_walk
      intro c h_mem
      exact h_acc c (List.mem_reverse.mp h_mem)
    · simp at h_walk
  | succ fuel ih =>
    intro off acc certs h_acc h_walk
    rw [entriesAt] at h_walk
    split at h_walk
    · obtain rfl := Except.ok.inj h_walk
      intro c h_mem
      exact h_acc c (List.mem_reverse.mp h_mem)
    · obtain ⟨⟨cert, off1⟩, -, h_walk⟩ := exists_of_bind_eq_ok h_walk
      obtain ⟨h_cert_nonempty, h_walk⟩ := of_ensure_bind h_walk
      obtain ⟨⟨exts, off2⟩, -, h_walk⟩ := exists_of_bind_eq_ok h_walk
      obtain ⟨-, h_walk⟩ := of_ensure_bind h_walk
      refine ih off2 (cert :: acc) certs ?_ h_walk
      intro c h_mem
      cases h_mem with
      | head => exact h_cert_nonempty
      | tail _ h_in_acc => exact h_acc c h_in_acc

/--
Certificate soundness (RFC 9846 §4.4.2, §4.4.2.4). An accepted message
reports at least one entry and a nonempty leaf certificate: the empty
certificate list §4.4.2.4 refuses cannot come back as an accepted one,
and neither can an entry whose `cert_data<1..2^24-1>` is empty.
-/
theorem parseCertificate_sound (msg : ByteArray) (fields : Certificate)
    (h_accepted : parseCertificate msg = .ok fields) :
    1 ≤ fields.entryCount ∧ fields.leafCert.size ≠ 0 := by
  rw [parseCertificate] at h_accepted
  obtain ⟨_, -, h_accepted⟩ := exists_of_bind_eq_ok h_accepted
  obtain ⟨⟨_, _⟩, -, h_accepted⟩ := exists_of_bind_eq_ok h_accepted
  obtain ⟨-, h_accepted⟩ := of_ensure_bind h_accepted
  obtain ⟨⟨list, _⟩, -, h_accepted⟩ := exists_of_bind_eq_ok h_accepted
  obtain ⟨-, h_accepted⟩ := of_ensure_bind h_accepted
  obtain ⟨-, h_accepted⟩ := of_ensure_bind h_accepted
  obtain ⟨certs, h_walk, h_accepted⟩ := exists_of_bind_eq_ok h_accepted
  have h_nonempty := entriesAt_nonempty list list.size 0 [] certs (by simp) h_walk
  cases certs with
  | nil => simp at h_accepted
  | cons leaf rest =>
    obtain rfl := eq_of_pure_eq_ok h_accepted
    exact ⟨Nat.le_add_left 1 rest.length, h_nonempty leaf (by simp)⟩

/--
The shared ServerHello prefix (RFC 9846 §4.1.3): whatever the message
turns out to be, its Random is the 32 octets at offset 2 of the body
and its session id echo is empty — the only echo that can match the
empty legacy_session_id this profile offers (§4.1.3).
-/
private theorem serverHelloPrefix_sound (msg : ByteArray) (p : ServerHelloPrefix)
    (h_prefix : serverHelloPrefix msg = .ok p) :
    ∃ body, messageBody msg serverHelloType = .ok body ∧
      p.random = body.extract 2 34 ∧ p.sessionIdEcho.size = 0 := by
  rw [serverHelloPrefix] at h_prefix
  obtain ⟨body, h_framed, h_prefix⟩ := exists_of_bind_eq_ok h_prefix
  obtain ⟨_, -, h_prefix⟩ := exists_of_bind_eq_ok h_prefix
  obtain ⟨-, h_prefix⟩ := of_ensure_bind h_prefix
  obtain ⟨_, h_random_read, h_prefix⟩ := exists_of_bind_eq_ok h_prefix
  obtain ⟨⟨_, _⟩, -, h_prefix⟩ := exists_of_bind_eq_ok h_prefix
  obtain ⟨-, h_prefix⟩ := of_ensure_bind h_prefix
  obtain ⟨h_echo_empty, h_prefix⟩ := of_ensure_bind h_prefix
  obtain ⟨_, -, h_prefix⟩ := exists_of_bind_eq_ok h_prefix
  obtain ⟨-, h_prefix⟩ := of_ensure_bind h_prefix
  obtain ⟨_, -, h_prefix⟩ := exists_of_bind_eq_ok h_prefix
  obtain ⟨-, h_prefix⟩ := of_ensure_bind h_prefix
  obtain ⟨⟨_, _⟩, -, h_prefix⟩ := exists_of_bind_eq_ok h_prefix
  obtain ⟨-, h_prefix⟩ := of_ensure_bind h_prefix
  obtain ⟨-, h_prefix⟩ := of_ensure_bind h_prefix
  obtain ⟨_, -, h_prefix⟩ := exists_of_bind_eq_ok h_prefix
  obtain rfl := eq_of_pure_eq_ok h_prefix
  exact ⟨body, h_framed, bytesAt_eq h_random_read, h_echo_empty⟩

/--
The ServerHello branch's own fields (RFC 9846 §4.1.3, §4.2.8, §4.2.11):
the echo is the empty one the profile offers, the key_exchange is
exactly the `kex.serverShareSize` octets the build's group's share
occupies, and a PSK identity, when there is one, is the single index
the profile's one offered identity puts in range.
-/
private theorem serverHelloFields_sound (kex : Kex) (pskOffered : Bool) (p : ServerHelloPrefix)
    (fields : ServerHello) (h_fields : serverHelloFields kex pskOffered p = .ok fields) :
    fields.sessionIdEcho = p.sessionIdEcho ∧ fields.keyExchange.size = kex.serverShareSize ∧
      ∀ identity, fields.selectedIdentity = some identity → identity = 0 := by
  rw [serverHelloFields] at h_fields
  obtain ⟨_, -, h_fields⟩ := exists_of_bind_eq_ok h_fields
  obtain ⟨-, h_fields⟩ := of_ensure_bind h_fields
  obtain ⟨key, h_share, h_fields⟩ := exists_of_bind_eq_ok h_fields
  obtain ⟨identity, h_identity, h_fields⟩ := exists_of_bind_eq_ok h_fields
  obtain rfl := eq_of_pure_eq_ok h_fields
  refine ⟨rfl, ?_, ?_⟩
  · rw [readKeyShare] at h_share
    obtain ⟨_, -, h_share⟩ := exists_of_bind_eq_ok h_share
    obtain ⟨_, -, h_share⟩ := exists_of_bind_eq_ok h_share
    obtain ⟨-, h_share⟩ := of_ensure_bind h_share
    obtain ⟨⟨_, _⟩, -, h_share⟩ := exists_of_bind_eq_ok h_share
    obtain ⟨-, h_share⟩ := of_ensure_bind h_share
    obtain ⟨h_key_size, h_share⟩ := of_ensure_bind h_share
    obtain rfl := eq_of_pure_eq_ok h_share
    exact h_key_size
  · intro i h_some
    have h_identity_eq : identity = some i := h_some
    subst h_identity_eq
    rw [readSelectedIdentity?] at h_identity
    split at h_identity
    · simp at h_identity
    · obtain ⟨-, h_identity⟩ := of_ensure_bind h_identity
      obtain ⟨_, -, h_identity⟩ := exists_of_bind_eq_ok h_identity
      obtain ⟨h_zero, h_identity⟩ := of_ensure_bind h_identity
      have h_index := Option.some.inj (eq_of_pure_eq_ok h_identity)
      omega

/--
ServerHello soundness (RFC 9846 §4.1.3, §4.2.8, §4.2.11). An accepted
ServerHello reports a session id echo inside the `<0..32>` its vector
allows, a key_exchange of exactly the `kex.serverShareSize` octets the
build's group's share occupies — 32 for x25519, 1120 for the hybrid —
and, when the server accepted a PSK, the only identity index the
profile's single offered identity puts in range.
-/
theorem parseServerHello_sound (kex : Kex) (pskOffered : Bool) (msg : ByteArray)
    (fields : ServerHello)
    (h_accepted : parseServerHello kex pskOffered msg = .ok (.serverHello fields)) :
    fields.sessionIdEcho.size = 0 ∧ fields.keyExchange.size = kex.serverShareSize ∧
      ∀ identity, fields.selectedIdentity = some identity → identity = 0 := by
  rw [parseServerHello] at h_accepted
  obtain ⟨p, h_prefix, h_accepted⟩ := exists_of_bind_eq_ok h_accepted
  obtain ⟨_, -, h_accepted⟩ := exists_of_bind_eq_ok h_accepted
  obtain ⟨_, -, -, h_echo_empty⟩ := serverHelloPrefix_sound msg p h_prefix
  split at h_accepted
  · obtain ⟨_, -, h_accepted⟩ := exists_of_bind_eq_ok h_accepted
    exact ServerHelloKind.noConfusion (eq_of_pure_eq_ok h_accepted)
  · obtain ⟨read, h_read, h_accepted⟩ := exists_of_bind_eq_ok h_accepted
    obtain rfl := ServerHelloKind.serverHello.inj (eq_of_pure_eq_ok h_accepted)
    obtain ⟨h_echo, h_key_size, h_identity⟩ :=
      serverHelloFields_sound kex pskOffered p read h_read
    exact ⟨by rw [h_echo]; exact h_echo_empty, h_key_size, h_identity⟩

/--
The §4.1.4 discrimination, stated both ways: an accepted result is a
HelloRetryRequest exactly when the 32 octets of the message's Random
field are §4.1.4's fixed value. Nothing else in the message moves the
verdict from one kind to the other.
-/
theorem parseServerHello_random (kex : Kex) (pskOffered : Bool) (msg : ByteArray)
    (kind : ServerHelloKind)
    (h_accepted : parseServerHello kex pskOffered msg = .ok kind) :
    ∃ body, messageBody msg serverHelloType = .ok body ∧
      (∀ fields, kind = .helloRetryRequest fields →
        body.extract 2 34 = helloRetryRequestRandom) ∧
      (∀ fields, kind = .serverHello fields →
        body.extract 2 34 ≠ helloRetryRequestRandom) := by
  rw [parseServerHello] at h_accepted
  obtain ⟨p, h_prefix, h_accepted⟩ := exists_of_bind_eq_ok h_accepted
  obtain ⟨_, -, h_accepted⟩ := exists_of_bind_eq_ok h_accepted
  obtain ⟨body, h_framed, h_random_eq, -⟩ := serverHelloPrefix_sound msg p h_prefix
  refine ⟨body, h_framed, ?_, ?_⟩
  · intro fields h_kind
    split at h_accepted
    · next h_matches => rw [← h_random_eq]; exact eq_of_bytesEq h_matches
    · obtain ⟨_, -, h_accepted⟩ := exists_of_bind_eq_ok h_accepted
      obtain rfl := eq_of_pure_eq_ok h_accepted
      exact ServerHelloKind.noConfusion h_kind
  · intro fields h_kind
    split at h_accepted
    · obtain ⟨_, -, h_accepted⟩ := exists_of_bind_eq_ok h_accepted
      obtain rfl := eq_of_pure_eq_ok h_accepted
      exact ServerHelloKind.noConfusion h_kind
    · next h_differs =>
      rw [← h_random_eq]
      intro h_eq
      rw [h_eq] at h_differs
      simp [bytesEq] at h_differs

/--
RFC 8449 §4: an accepted record_size_limit is at least 64. The client
sizes its record buffer against this number, and the RFC makes a
smaller one a fatal error rather than a value to clamp.
-/
theorem parseEncryptedExtensions_limit_ge_64 (msg : ByteArray)
    (fields : EncryptedExtensions) (limit : Nat)
    (h_accepted : parseEncryptedExtensions msg = .ok fields)
    (h_limit : fields.recordSizeLimit = some limit) : 64 ≤ limit := by
  rw [parseEncryptedExtensions] at h_accepted
  obtain ⟨_, -, h_accepted⟩ := exists_of_bind_eq_ok h_accepted
  obtain ⟨⟨_, _⟩, -, h_accepted⟩ := exists_of_bind_eq_ok h_accepted
  obtain ⟨-, h_accepted⟩ := of_ensure_bind h_accepted
  obtain ⟨_, -, h_accepted⟩ := exists_of_bind_eq_ok h_accepted
  obtain ⟨_, -, h_accepted⟩ := exists_of_bind_eq_ok h_accepted
  obtain ⟨_, -, h_accepted⟩ := exists_of_bind_eq_ok h_accepted
  obtain ⟨read, h_read, h_accepted⟩ := exists_of_bind_eq_ok h_accepted
  obtain rfl := eq_of_pure_eq_ok h_accepted
  have h_read_eq : read = some limit := h_limit
  subst h_read_eq
  rw [readRecordSizeLimit?] at h_read
  split at h_read
  · simp at h_read
  · obtain ⟨value, h_value, h_read⟩ := exists_of_bind_eq_ok h_read
    rw [readRecordSizeLimit] at h_value
    obtain ⟨-, h_value⟩ := of_ensure_bind h_value
    obtain ⟨_, -, h_value⟩ := exists_of_bind_eq_ok h_value
    obtain ⟨h_at_least_64, h_value⟩ := of_ensure_bind h_value
    obtain rfl := eq_of_pure_eq_ok h_value
    have h_out := Option.some.inj (eq_of_pure_eq_ok h_read)
    omega

/--
CertificateVerify soundness (RFC 9846 §4.4.3). An accepted message
reports the build's own SignatureScheme and no other code point: the
one algorithm the ClientHello offered is the one the parser admits.
-/
theorem parseCertificateVerify_sound (scheme : Scheme) (msg : ByteArray)
    (fields : CertificateVerify)
    (h_accepted : parseCertificateVerify scheme msg = .ok fields) :
    fields.algorithm = scheme.code := by
  rw [parseCertificateVerify] at h_accepted
  obtain ⟨_, -, h_accepted⟩ := exists_of_bind_eq_ok h_accepted
  obtain ⟨_, -, h_accepted⟩ := exists_of_bind_eq_ok h_accepted
  obtain ⟨h_pinned, h_accepted⟩ := of_ensure_bind h_accepted
  obtain ⟨⟨_, _⟩, -, h_accepted⟩ := exists_of_bind_eq_ok h_accepted
  obtain ⟨-, h_accepted⟩ := of_ensure_bind h_accepted
  obtain rfl := eq_of_pure_eq_ok h_accepted
  exact h_pinned

end Spec.Hsparse
