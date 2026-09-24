import Spec.Bytes
import Spec.Sha256

/-!
The server-to-client handshake message grammar of RFC 9846 §4, written
from the RFC text as an executable oracle. Four messages reach this
client after its ClientHello: ServerHello (§4.2.3, which §4.2.4 also
uses for a HelloRetryRequest), EncryptedExtensions (§4.4.1),
Certificate (§4.5.1), and CertificateVerify (§4.5.2).

Each parser takes one complete Handshake structure — `msg_type`, the
`uint24 length`, and the body those two frame (§4) — and either
returns the fields the client needs or names the alert the message
earns. Every function is written twice over: first the byte layout the
RFC's `struct` gives, then the narrowing the profile in `CLAUDE.md`
imposes on it. Each check's doc comment says which of the two it is.

The profile: TLS 1.3 only, TLS_CHACHA20_POLY1305_SHA256, one
key-exchange group per build (`Kex`: x25519, or the X25519MLKEM768
hybrid), two auth modes (ECDHE-PSK or a server key checked through
CertificateVerify), no 0-RTT, no compression, no renegotiation, and
`record_size_limit` (RFC 8449) always offered. The client offers
exactly one of everything, so most of the RFC's negotiation choices
collapse to a byte compare against a constant. The TRUST=webpki build
is the one exception, and six parameters carry it: its ClientHello
sends server_name when it has a hostname (`parseEncryptedExtensions`'s
`serverNameSent`), it may offer several application protocols
(`parseEncryptedExtensions`'s `alpnOffered`), with SPKI pins it offers
RFC 7250 raw public keys and may offer X.509 beside them
(`parseEncryptedExtensions`'s `certTypesOffered`), it
offers five signature schemes instead of one (`SignatureOffer`), it
lists two groups, X25519MLKEM768 then x25519, with a key share for each
(`Kex.twoGroups`), and under
SUITE=aesgcm it offers two cipher suites, TLS_CHACHA20_POLY1305_SHA256
then TLS_AES_128_GCM_SHA256 (`SuiteOffer.chachaAndAes`).

Where the RFC fixes the alert, `Alert` names it. Where the RFC states
a MUST but names no alert, the verdict is `Alert.unspecified` and the
doc comment says so, rather than inventing one: a guessed alert would
report a disagreement that is not a bug.
-/
namespace Spec.HandshakeParser

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
  response the client never requested (§4.3). -/
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
uses this same type; §4.2.4 tells the two apart by the Random. -/
def serverHelloType : Nat := 2

/-- HandshakeType encrypted_extensions(8) (RFC 9846 §4). -/
def encryptedExtensionsType : Nat := 8

/-- HandshakeType certificate(11) (RFC 9846 §4). -/
def certificateType : Nat := 11

/-- HandshakeType certificate_verify(15) (RFC 9846 §4). -/
def certificateVerifyType : Nat := 15

/-- ExtensionType server_name(0) (RFC 6066 §3). -/
def extServerName : Nat := 0

/-- ExtensionType supported_groups(10) (RFC 9846 §4.3.7). -/
def extSupportedGroups : Nat := 10

/-- ExtensionType application_layer_protocol_negotiation(16)
(RFC 7301 §3.1). -/
def extAlpn : Nat := 16

/-- ExtensionType server_certificate_type(20) (RFC 7250 §3,
RFC 9846 §4.3). -/
def extServerCertificateType : Nat := 20

/-- ExtensionType record_size_limit(28) (RFC 8449 §4). -/
def extRecordSizeLimit : Nat := 28

/-- ExtensionType pre_shared_key(41) (RFC 9846 §4.3.11). -/
def extPreSharedKey : Nat := 41

/-- ExtensionType early_data(42) (RFC 9846 §4.3.10). -/
def extEarlyData : Nat := 42

/-- ExtensionType supported_versions(43) (RFC 9846 §4.3.1). -/
def extSupportedVersions : Nat := 43

/-- ExtensionType cookie(44) (RFC 9846 §4.3.2). -/
def extCookie : Nat := 44

/-- ExtensionType key_share(51) (RFC 9846 §4.3.8). -/
def extKeyShare : Nat := 51

/--
Every ExtensionType RFC 9846 §4.3 defines, together with RFC 8449's
record_size_limit(28) and RFC 7250's certificate-type pair (19, 20).
"Recognized" in §4.3's sense is a property of the implementation, and
for this client it is exactly this list: the code points the profile
knows about, whether or not it offers them.
-/
def knownExtension (t : Nat) : Bool :=
  [0, 1, 5, 10, 13, 14, 15, 16, 18, 19, 20, 21, 28, 35,
    41, 42, 43, 44, 45, 47, 48, 49, 50, 51].contains t

/-! ## Profile constants -/

/-- CipherSuite TLS_CHACHA20_POLY1305_SHA256 = `{0x13,0x03}`
(RFC 9846 appendix B.4). Every client build offers it, and offers it
first. -/
def chacha20Poly1305Sha256 : Nat := 0x1303

/-- CipherSuite TLS_AES_128_GCM_SHA256 = `{0x13,0x01}` (RFC 9846
appendix B.4). The SUITE=aesgcm TRUST=webpki client offers it second,
after TLS_CHACHA20_POLY1305_SHA256; no other client build offers it. -/
def aes128GcmSha256 : Nat := 0x1301

/--
The cipher suites the build's ClientHello offers in cipher_suites (RFC
9846 §4.2.2). The Makefile's SUITE and TRUST variables fix them at build
time, so exactly one of these is live in a library object.
-/
inductive SuiteOffer
  /-- Every client build but the one below: TLS_CHACHA20_POLY1305_SHA256
  alone. -/
  | chacha
  /-- The SUITE=aesgcm TRUST=webpki client: TLS_CHACHA20_POLY1305_SHA256
  then TLS_AES_128_GCM_SHA256 (docs/decisions.md entry 45). -/
  | chachaAndAes
deriving BEq

/-- The CipherSuite code points the build's ClientHello lists in
cipher_suites (RFC 9846 §4.2.2), in the order it lists them. -/
def SuiteOffer.cipherSuites : SuiteOffer → List Nat
  | .chacha => [chacha20Poly1305Sha256]
  | .chachaAndAes => [chacha20Poly1305Sha256, aes128GcmSha256]

/-- The line protocol's cipher-suite token, spelled as the Makefile's
SUITE variable spells its values: `chacha` for every client build but
one, and `aesgcm` for the SUITE=aesgcm TRUST=webpki client. -/
def suiteOf? : String → Option SuiteOffer
  | "chacha" => some .chacha
  | "aesgcm" => some .chachaAndAes
  | _ => none

/-- NamedGroup x25519(0x001D) (RFC 9846 §4.3.7): the KEX=x25519
build's one group. `Kex.supportedGroups` below lists each build's
groups. -/
def x25519Group : Nat := 0x001d

/-- NamedGroup X25519MLKEM768(0x11EC), the ML-KEM-768 + x25519 hybrid
(RFC 10024): the group the KEX=pq builds and the TRUST=webpki build send
a key share for. -/
def hybridGroup : Nat := 0x11ec

/-- ProtocolVersion 0x0304, the value a TLS 1.3 server puts in the
ServerHello's supported_versions (RFC 9846 §4.3.1). -/
def tls13Version : Nat := 0x0304

/-- ProtocolVersion 0x0303 ("TLS 1.2"), the value §4.2.3 freezes into
the ServerHello's `legacy_version` field. The real version moves to
supported_versions; this one is a constant on the wire. -/
def legacyVersion : Nat := 0x0303

/-- The x25519 public value is 32 bytes (RFC 9846 §4.3.8.2, RFC 7748
§5). -/
def x25519KeySize : Nat := 32

/--
The key-exchange groups the build offers, fixed at build time: the
Makefile's KEX variable picks one of the first two for a raw or ca
build, and every TRUST=webpki build is the third, so exactly one of
these is live in a library object. The ClientHello lists
`Kex.supportedGroups` in supported_groups (RFC 9846 §4.3.7) and sends a
key share for each of `Kex.keyShareGroups` (§4.3.8).
-/
inductive Kex
  /-- KEX=x25519: x25519(0x001D) alone (RFC 9846 §4.3.7). -/
  | x25519
  /-- KEX=pq: X25519MLKEM768(0x11EC) alone, the ML-KEM-768 + x25519
  hybrid (RFC 10024). -/
  | pq
  /-- The TRUST=webpki build: it lists X25519MLKEM768 then x25519 and
  sends a key share for each (docs/decisions.md entry 53), so a server
  selects either one without a HelloRetryRequest. -/
  | twoGroups
deriving BEq

/-- The NamedGroups the build's ClientHello lists in supported_groups
(RFC 9846 §4.3.7), in the order it lists them. -/
def Kex.supportedGroups : Kex → List Nat
  | .x25519 => [x25519Group]
  | .pq => [hybridGroup]
  | .twoGroups => [hybridGroup, x25519Group]

/-- The NamedGroups of the key shares the build's ClientHello sends, in
the order it sends them (RFC 9846 §4.3.8): one per listed group, so the
same list as `Kex.supportedGroups`. -/
def Kex.keyShareGroups : Kex → List Nat
  | .x25519 => [x25519Group]
  | .pq => [hybridGroup]
  | .twoGroups => [hybridGroup, x25519Group]

/--
The NamedGroups a HelloRetryRequest's key_share may select. RFC 9846
§4.3.8 requires the selected_group to be one the ClientHello listed in
supported_groups and not one it already sent a key share for, and makes
either failure an illegal_parameter. These are the supported groups the
build sent no share for, and every build shares every group it lists,
so the list is empty in every build (`Kex.retryGroups_eq_nil`).
-/
def Kex.retryGroups (kex : Kex) : List Nat :=
  kex.supportedGroups.filter (· ∉ kex.keyShareGroups)

/-- No build leaves a listed group without a key share, so no build has
a group a HelloRetryRequest may select. -/
theorem Kex.retryGroups_eq_nil (kex : Kex) : kex.retryGroups = [] := by
  cases kex <;> decide

/--
The octet count of a server key_exchange value in `group` (RFC 9846
§4.3.8): the 32-octet x25519 public value (§4.3.8.2), or RFC 10024's
hybrid share — the 1088-octet ML-KEM-768 ciphertext then the 32-octet
x25519 public value, ML-KEM first despite the group's name. Every other
group gets 0. No build lists one, and `readKeyShare` refuses a group
outside the build's list before it compares a size, so that 0 is never
compared.
-/
def serverShareSize (group : Nat) : Nat :=
  if group = x25519Group then x25519KeySize
  else if group = hybridGroup then 1088 + 32
  else 0

/-- The line protocol's key-exchange token: `x25519` and `pq` as the
Makefile's KEX variable spells the one-group builds, and `two-groups`
for the TRUST=webpki build. -/
def kexOf? : String → Option Kex
  | "x25519" => some .x25519
  | "pq" => some .pq
  | "two-groups" => some .twoGroups
  | _ => none

/--
RFC 9846 §4.2.4: the Random of a HelloRetryRequest is this fixed
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
RFC 9846 §4.3: `struct { ExtensionType extension_type; opaque
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
appear. The block must end exactly where its length says (§4.3's
vector framing, decode_error), and RFC 9846 §4.3 allows at most one
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
RFC 9846 §4.3 gives two rules for an extension that has no business in
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

/-! ## ServerHello and HelloRetryRequest (RFC 9846 §4.2.3, §4.2.4) -/

/-- The ServerHello fields that precede the extension block, plus the
block itself. §4.2.4 gives a HelloRetryRequest this same layout, so
both are read through here first. -/
structure ServerHelloPrefix where
  /-- Random: 32 octets (§4.2.3). -/
  random : ByteArray
  /-- legacy_session_id_echo<0..32> (§4.2.3). -/
  sessionIdEcho : ByteArray
  /-- cipher_suite (§4.2.3), one the build offers. -/
  cipherSuite : Nat
  /-- extensions<6..2^16-1>, already split into typed pairs. -/
  extensions : List (Nat × ByteArray)

/-- What an accepted ServerHello hands the client (RFC 9846 §4.2.3). -/
structure ServerHello where
  /-- The echoed legacy_session_id, for the caller to compare against
  the one it sent (§4.2.3). -/
  sessionIdEcho : ByteArray
  /-- The CipherSuite the message carried in cipher_suite (§4.2.3).
  `serverHelloPrefix` accepts only a suite in `SuiteOffer.cipherSuites`,
  and `parseServerHello_sound` states the membership. After a
  HelloRetryRequest the caller compares it with the retry's suite
  (§4.2.4). -/
  cipherSuite : Nat
  /-- The NamedGroup the key_share selected (§4.3.8). `readKeyShare`
  accepts only a group in `Kex.supportedGroups`, but the value here is
  read from the message, as the C reads `ch_tls.group` from the wire,
  so `parseServerHello_sound` states the membership instead of assuming
  it. -/
  group : Nat
  /-- The server's key_exchange value from key_share (§4.3.8): the
  x25519 public value, or the ML-KEM-768 ciphertext then x25519 public
  value of X25519MLKEM768 (RFC 10024). -/
  keyExchange : ByteArray
  /-- pre_shared_key's selected_identity, absent when the server did
  not accept a PSK (§4.3.11). -/
  selectedIdentity : Option Nat

/-- What an accepted HelloRetryRequest hands the client
(RFC 9846 §4.2.4). -/
structure HelloRetryRequest where
  /-- The echoed legacy_session_id (§4.2.3). -/
  sessionIdEcho : ByteArray
  /-- The CipherSuite the retry carried in cipher_suite, one the build
  offers. §4.2.4 requires the ServerHello that follows to carry the
  same suite, and the caller checks that. -/
  cipherSuite : Nat
  /-- The cookie the second ClientHello must carry back (§4.3.2), or
  none when the retry carries no cookie extension. -/
  cookie : Option ByteArray
  /-- key_share's selected_group (§4.3.8): the group the second
  ClientHello must send a key share for, or none when the retry carries
  no key_share extension. -/
  selectedGroup : Option Nat

/-- A ServerHello is one of two messages, and RFC 9846 §4.2.4 makes
the Random the only thing that tells them apart. -/
inductive ServerHelloKind
  /-- The server's half of the key exchange (§4.2.3). -/
  | serverHello (fields : ServerHello)
  /-- A retry request: same format, special Random (§4.2.4). -/
  | helloRetryRequest (fields : HelloRetryRequest)

/-- The extension types RFC 9846 §4.3 specifies for a ServerHello.
Nothing else may appear in one. -/
def serverHelloExtensions : List Nat := [extPreSharedKey, extSupportedVersions, extKeyShare]

/-- The extension types RFC 9846 §4.3 specifies for a
HelloRetryRequest. -/
def helloRetryRequestExtensions : List Nat :=
  [extSupportedVersions, extCookie, extKeyShare]

/--
RFC 9846 §4.2.3, read down the struct:

* `legacy_version` is 0x0303 exactly. §4.2.3 freezes the field at that
  value and §4.3.1's real version moves to supported_versions, so
  any other legacy_version is an illegal_parameter;
* `random` is 32 octets, handed on for the §4.2.4 comparison;
* `legacy_session_id_echo<0..32>`: a longer echo is a field out of the
  specified range, decode_error (§6.2). Whether it matches the
  ClientHello's is the caller's check — §4.2.3 makes a mismatch an
  illegal_parameter, but this parser sees one message and not the
  ClientHello that preceded it, so the echo travels out in the fields;
* `cipher_suite`: profile — one of `suiteOffer.cipherSuites`, since
  §4.2.3 makes a suite that was not offered an illegal_parameter, and
  §4.2.4 repeats the rule for a HelloRetryRequest. Every client build
  offers TLS_CHACHA20_POLY1305_SHA256, and the SUITE=aesgcm TRUST=webpki
  client also offers TLS_AES_128_GCM_SHA256. §4.2.4 also requires a
  ServerHello after a HelloRetryRequest to carry the retry's suite. That
  turns on whether a retry happened, which one message cannot show, so
  the suite travels out in the fields and the caller checks it;
* `legacy_compression_method`: profile — no compression, and §4.2.3
  fixes the value at 0 with an illegal_parameter for anything else;
* `extensions<6..2^16-1>`: the block ends the message, and a block
  under six octets cannot hold even one extension, so it is out of the
  specified range (§6.2).
-/
def serverHelloPrefix (suiteOffer : SuiteOffer) (msg : ByteArray) :
    Except Alert ServerHelloPrefix := do
  let body ← messageBody msg serverHelloType
  -- §4.2.3: legacy_version "MUST be set to 0x0303"; a client that sees
  -- any other value MUST abort with illegal_parameter.
  let legacy ← u16At body 0
  ensure (legacy = legacyVersion) .illegalParameter
  let random ← bytesAt body 2 32
  let (sessionIdEcho, off) ← vec8At body 34
  ensure (sessionIdEcho.size ≤ 32) .decodeError
  -- §4.2.3: legacy_session_id_echo is "the contents of the client's
  -- legacy_session_id field", and a client that receives any other
  -- value MUST abort with illegal_parameter. This profile needs no
  -- middlebox compatibility, so handshake_message.c sends the field empty and the
  -- only echo that can match is the empty one. Like the cipher suites
  -- and the groups, the offer is fixed when the library is built, so
  -- the check belongs here rather than with the caller.
  ensure (sessionIdEcho.size = 0) .illegalParameter
  let cipherSuite ← u16At body off
  ensure (cipherSuite ∈ suiteOffer.cipherSuites) .illegalParameter
  let compression ← u8At body (off + 2)
  ensure (compression = 0) .illegalParameter
  let (extBytes, off') ← vec16At body (off + 3)
  ensure (off' = body.size) .decodeError
  ensure (6 ≤ extBytes.size) .decodeError
  let extensions ← extensionList extBytes
  return { random, sessionIdEcho, cipherSuite, extensions }

/--
RFC 9846 §4.3.1: in a ServerHello or HelloRetryRequest the
supported_versions extension_data is one `ProtocolVersion
selected_version`, not a list, so any length but two is out of the
specified range (§6.2). §9.2 makes the extension required in both
messages, and its absence a missing_extension. A version "not offered
by the client or ... prior to TLS 1.3" is an illegal_parameter
(§4.3.1); the profile offers TLS 1.3 alone, so 0x0304 is the only
value that passes.
-/
def checkSelectedVersion (exts : List (Nat × ByteArray)) : Except Alert Unit := do
  let data ← requiredExtension exts extSupportedVersions .missingExtension
  ensure (data.size = 2) .decodeError
  ensure (bytesToNatBE data = tls13Version) .illegalParameter

/--
RFC 9846 §4.3.11: pre_shared_key in a ServerHello is `uint16
selected_identity`, two octets and no more, present only when the
server accepted the PSK. Profile: the client offers exactly one
identity, so the only index in range is 0, and §4.3.11 makes an
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
RFC 9846 §4.3.8: key_share in a ServerHello is `KeyShareServerHello`,
one `KeyShareEntry` — `NamedGroup group` then `opaque
key_exchange<1..2^16-1>` — filling the extension exactly. §9.2 requires
the extension "for DHE or ECDHE key exchange", which both of the
profile's auth modes use (the PSK mode is psk_dhe_ke), so its absence
is a missing_extension.

Profile: the group is one of `kex.supportedGroups`, since a group the
client did not offer is an illegal_parameter (§4.3.8); the key_exchange
value is `serverShareSize group` octets — 32 for an x25519 public value
(§4.3.8.2), 1120 for the hybrid's ciphertext-then-public share (RFC
10024) — so any other length is out of the specified range. Whether the
x25519 value is a low-order point is not decided here: §7.4.2 puts that
check on the computed shared secret, after the key exchange this parser
only feeds.

In the two-group build either supported group passes here, because
the ClientHello sent a share for each (§4.3.8), and a retry never moves
the shares, because no build has a group a retry may select
(`Kex.retryGroups_eq_nil`).

Returns the group with the value. The check above admits only a
supported group, but the reader returns the value the message carried,
as `parse_key_share` writes `server_hello_info.group` from the wire.
-/
def readKeyShare (kex : Kex) (exts : List (Nat × ByteArray)) :
    Except Alert (Nat × ByteArray) := do
  let share ← requiredExtension exts extKeyShare .missingExtension
  let group ← u16At share 0
  ensure (group ∈ kex.supportedGroups) .illegalParameter
  let (keyExchange, off) ← vec16At share 2
  ensure (off = share.size) .decodeError
  ensure (keyExchange.size = serverShareSize group) .decodeError
  return (group, keyExchange)

/--
The ServerHello branch (RFC 9846 §4.2.3): only the three extensions
§4.3 specifies for a ServerHello may appear, a pre_shared_key response
only when the ClientHello offered one, the key share is read and
narrowed to the build's supported groups, and the PSK identity comes
back when the server accepted one.
-/
def serverHelloFields (kex : Kex) (pskOffered : Bool) (p : ServerHelloPrefix) :
    Except Alert ServerHello := do
  ensureAllowed serverHelloExtensions wrongMessageAlert p.extensions
  -- RFC 9846 §4.3: a server MUST NOT send an extension response the
  -- client did not request, and a client that receives one MUST abort
  -- with unsupported_extension. `pre_shared_key` is the one response
  -- whose admissibility depends on what the ClientHello offered, so it
  -- is the one the profile cannot settle from the message alone.
  ensure (pskOffered || (extensionData? p.extensions extPreSharedKey).isNone) .unsupportedExtension
  let (group, keyExchange) ← readKeyShare kex p.extensions
  let selectedIdentity ← readSelectedIdentity? p.extensions
  return { sessionIdEcho := p.sessionIdEcho, cipherSuite := p.cipherSuite, group, keyExchange,
           selectedIdentity }

/--
RFC 9846 §4.3.8: key_share in a HelloRetryRequest is
`KeyShareHelloRetryRequest`, one `NamedGroup selected_group` and no
key, so any length but two is out of the specified range (§6.2). The
group must be one of `kex.retryGroups`: §4.3.8 makes a group the
ClientHello did not list in supported_groups, or one it already sent a
key share for, an illegal_parameter. A retry naming the group the
client already sent a share for would also change nothing in the
second ClientHello, which §4.2.4 refuses with the same alert.
-/
def readSelectedGroup? (kex : Kex) (exts : List (Nat × ByteArray)) :
    Except Alert (Option Nat) :=
  match extensionData? exts extKeyShare with
  | none => .ok none
  | some data => do
    ensure (data.size = 2) .decodeError
    let group ← u16At data 0
    ensure (group ∈ kex.retryGroups) .illegalParameter
    return some group

/-- RFC 9846 §4.3.2: `struct { opaque cookie<1..2^16-1>; } Cookie`
fills the extension exactly, so a vector that does not end where the
extension ends, or an empty cookie, is out of the specified range
(§6.2). -/
def readCookie? (exts : List (Nat × ByteArray)) : Except Alert (Option ByteArray) :=
  match extensionData? exts extCookie with
  | none => .ok none
  | some data => do
    let (cookie, off) ← vec16At data 0
    ensure (off = data.size) .decodeError
    ensure (cookie.size ≠ 0) .decodeError
    return some cookie

/--
The HelloRetryRequest branch (RFC 9846 §4.2.4).

* only the three §4.3 HelloRetryRequest extensions may appear;
* key_share, when present, names a group from `kex.retryGroups`
  (`readSelectedGroup?`). No build has one, so every key_share is
  refused;
* cookie, when present, is one non-empty cookie (`readCookie?`);
* at least one of the two is present. A cookie and a selected group
  are the only changes a retry can ask this client for, and §4.2.4
  makes a retry that "would not result in any change in the
  ClientHello" an illegal_parameter. So every build requires the
  cookie. Neither is a §9.2 required extension, so a retry with neither
  is not a missing_extension.
-/
def helloRetryRequestFields (kex : Kex) (p : ServerHelloPrefix) :
    Except Alert HelloRetryRequest := do
  ensureAllowed helloRetryRequestExtensions wrongMessageAlert p.extensions
  let selectedGroup ← readSelectedGroup? kex p.extensions
  let cookie ← readCookie? p.extensions
  ensure (cookie.isSome ∨ selectedGroup.isSome) .illegalParameter
  return { sessionIdEcho := p.sessionIdEcho, cipherSuite := p.cipherSuite, cookie, selectedGroup }

/--
RFC 9846 §4.2.3 and §4.2.4: one message type, two meanings. The shared
prefix is read first, then §4.3.1's "clients MUST check for this
extension prior to processing the rest of the ServerHello" puts the
selected version next, and only then does the Random decide which
message this is.

The §4.2.3 downgrade sentinels are deliberately absent: the RFC scopes
that check to "TLS 1.3 clients receiving a ServerHello indicating TLS
1.2 or below", and `checkSelectedVersion` has already refused every
such message, so no accepted message can reach the check.
-/
def parseServerHello (kex : Kex) (suiteOffer : SuiteOffer) (pskOffered : Bool) (msg : ByteArray) :
    Except Alert ServerHelloKind := do
  let p ← serverHelloPrefix suiteOffer msg
  checkSelectedVersion p.extensions
  if bytesEq p.random helloRetryRequestRandom then
    return .helloRetryRequest (← helloRetryRequestFields kex p)
  else
    return .serverHello (← serverHelloFields kex pskOffered p)

/-! ## EncryptedExtensions (RFC 9846 §4.4.1) -/

/-- What an accepted EncryptedExtensions hands the client. -/
structure EncryptedExtensions where
  /-- RFC 8449 §4's RecordSizeLimit, when the server answered the
  client's own; absent when it did not. -/
  recordSizeLimit : Option Nat
  /-- The index in `alpnOffered` of the protocol RFC 7301 §3.2's ALPN
  extension selected; absent when the server sent no such extension. -/
  alpnSelected : Option Nat
  /-- The CertificateType RFC 7250 §4.2's server_certificate_type
  selected from `certTypesOffered`; absent when the server sent no such
  extension, and the Certificate message then carries X.509
  certificates (RFC 9846 §4.5.1). -/
  serverCertType : Option Nat

/--
The extension types this profile admits in EncryptedExtensions:
supported_groups (RFC 9846 §4.3.7) and record_size_limit (RFC 8449 §4),
which `CLAUDE.md` says the client always sends, the server_name
acknowledgement (RFC 6066 §3) when `serverNameSent` says the ClientHello
carried server_name, the ALPN selection (RFC 7301 §3.2) when
`alpnOffered` holds the protocols the ClientHello offered, and the
server_certificate_type selection (RFC 7250 §4.2) when
`certTypesOffered` holds the certificate types it offered. The
TRUST=webpki build may send all three; the raw and ca builds send none.
-/
def encryptedExtensionsAllowed (serverNameSent : Bool) (alpnOffered : List ByteArray)
    (certTypesOffered : List Nat) : List Nat :=
  (if serverNameSent then [extServerName] else []) ++
    (if alpnOffered.isEmpty then [] else [extAlpn]) ++
    (if certTypesOffered.isEmpty then [] else [extServerCertificateType]) ++
    [extSupportedGroups, extRecordSizeLimit]

/--
Extension types RFC 9846 §4.3 permits in EncryptedExtensions that this
client never requests: server_name(0) when `serverNameSent` is false —
the ClientHello carried no SNI, so a server_name acknowledgement is a
response to a request that never went out —
application_layer_protocol_negotiation(16) when `alpnOffered` is empty
and server_certificate_type(20) when `certTypesOffered` is empty, for
the same reason, max_fragment_length(1), use_srtp(14), heartbeat(15),
client_certificate_type(19), and early_data(42) — the profile has no
0-RTT and no client certificate. §4.3 makes an unrequested response an
unsupported_extension, which is a different refusal from §4.4.1's
illegal_parameter for an extension that has no business in this
message at all.
-/
def encryptedExtensionsUnrequested (serverNameSent : Bool) (alpnOffered : List ByteArray)
    (certTypesOffered : List Nat) : List Nat :=
  (if serverNameSent then [] else [extServerName]) ++
    (if alpnOffered.isEmpty then [extAlpn] else []) ++
    (if certTypesOffered.isEmpty then [extServerCertificateType] else []) ++
    [1, 14, 15, 19, extEarlyData]

/-- The alert an extension that does not belong in EncryptedExtensions
earns: unsupported_extension when the RFC allows it here but the client
never asked for it (§4.3), and otherwise §4.4.1's illegal_parameter for
a forbidden extension, through `wrongMessageAlert`. -/
def encryptedExtensionsAlert (serverNameSent : Bool) (alpnOffered : List ByteArray)
    (certTypesOffered : List Nat) (t : Nat) : Alert :=
  if (encryptedExtensionsUnrequested serverNameSent alpnOffered certTypesOffered).contains t then
    .unsupportedExtension
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

/-- RFC 9846 §4.3.7: supported_groups carries `NamedGroup
named_group_list<2..2^16-2>`, an even number of octets and at least
one group, filling the extension exactly. The groups themselves go
unread: §4.3.7 tells the client not to act on them during this
handshake. -/
def checkSupportedGroups (exts : List (Nat × ByteArray)) : Except Alert Unit :=
  match extensionData? exts extSupportedGroups with
  | none => .ok ()
  | some data => do
    let (groups, off) ← vec16At data 0
    ensure (off = data.size) .decodeError
    ensure (2 ≤ groups.size ∧ groups.size % 2 = 0) .decodeError

/-- RFC 6066 §3: a server that acknowledges server_name sends the
extension with its extension_data empty. Data there gives the extension
a body of the wrong length for its structure, which RFC 9846 §6 makes a
decode_error, as `readRecordSizeLimit` does for a record_size_limit of
the wrong length. -/
def checkServerNameAck (exts : List (Nat × ByteArray)) : Except Alert Unit :=
  match extensionData? exts extServerName with
  | none => .ok ()
  | some data => ensure (data.size = 0) .decodeError

/-- The position of the first offered protocol equal to `name`, or
`none` when the offer holds no such protocol. Written by recursion
rather than through `List.findIdx?` so `offeredIndex?_lt_length` below
follows by induction, and over `bytesEq` because `ByteArray` carries no
`LawfulBEq` instance. -/
def offeredIndex? (offered : List ByteArray) (name : ByteArray) : Option Nat :=
  match offered with
  | [] => none
  | candidate :: rest =>
    if bytesEq candidate name then some 0 else (offeredIndex? rest name).map (· + 1)

/-- An index `offeredIndex?` returns is a position the offer holds. -/
theorem offeredIndex?_lt_length (offered : List ByteArray) (name : ByteArray) (i : Nat)
    (h_found : offeredIndex? offered name = some i) : i < offered.length := by
  induction offered generalizing i with
  | nil => simp [offeredIndex?] at h_found
  | cons candidate rest ih =>
    rw [offeredIndex?] at h_found
    split at h_found
    · simp only [Option.some.injEq] at h_found
      simp [← h_found]
    · match h_rest : offeredIndex? rest name with
      | none => rw [h_rest] at h_found; simp at h_found
      | some j =>
        rw [h_rest] at h_found
        simp only [Option.map_some, Option.some.injEq] at h_found
        have := ih j h_rest
        simp [← h_found]
        omega

/--
RFC 7301 §3.2: the server's extension_data is the client's structure
"except that the 'ProtocolNameList' MUST contain exactly one
'ProtocolName'", and §3.1 makes a ProtocolName
`opaque ProtocolName<1..2^8-1>`. A body that is not one whole name of at
least one octet has a length RFC 9846 §6 calls a decode_error, as
`readRecordSizeLimit` does.

A name outside the client's own offer is a different fault: the body is
well formed and its value is not acceptable, §6.2's illegal_parameter.
§3.2 gives the server no way to select outside the offer — a server that
shares no protocol with the client sends a no_application_protocol alert
instead — so the client has no reason to accept one.
-/
def readAlpn (alpnOffered : List ByteArray) (data : ByteArray) : Except Alert Nat := do
  let (list, off) ← vec16At data 0
  ensure (off = data.size) .decodeError
  let (name, off') ← vec8At list 0
  ensure (off' = list.size) .decodeError
  ensure (1 ≤ name.size) .decodeError
  match offeredIndex? alpnOffered name with
  | some i => pure i
  | none => .error .illegalParameter

/--
RFC 7301 §3.1: the client's own `ProtocolNameList`, one
`opaque ProtocolName<1..2^8-1>` after another until the list ends.
`fuel` bounds the walk; every name costs at least two octets, so the
list's own size is fuel enough. The differential driver reads the offer
back out of the ClientHello the C client built, so both sides take one
description of it.
-/
def protocolNamesAt (b : ByteArray) : Nat → Nat → List ByteArray → Option (List ByteArray)
  | 0, off, acc => if off = b.size then some acc.reverse else none
  | fuel + 1, off, acc =>
    if off = b.size then some acc.reverse
    else match vec8At b off with
      | .ok (name, off') => if name.size = 0 then none
                            else protocolNamesAt b fuel off' (name :: acc)
      | .error _ => none

/-- The whole `ProtocolNameList`, or `none` when the bytes are not one
list of non-empty names. -/
def protocolNames? (b : ByteArray) : Option (List ByteArray) :=
  protocolNamesAt b b.size 0 []

/-- RFC 7301 §3.2's selection when the server sent the extension, and
`none` when it did not: §3.2 lets a server that does not support ALPN
leave it out, so its absence is not a refusal. -/
def readAlpn? (alpnOffered : List ByteArray) (exts : List (Nat × ByteArray)) :
    Except Alert (Option Nat) :=
  match extensionData? exts extAlpn with
  | none => .ok none
  | some data => do return some (← readAlpn alpnOffered data)

/--
RFC 7250 §3: the server's ServerCertTypeExtension is one
`CertificateType server_certificate_type`, a single octet, and §4.2
permits only a single value there. Any other length does not decode as
that struct, a decode_error (RFC 9846 §6).

A type the ClientHello did not offer is a different fault: the octet
decodes and its value is not acceptable, §6.2's illegal_parameter.
RFC 7250 §4.2 has a server with no type in common with the client end
the handshake with unsupported_certificate instead of selecting one, so
the client has no reason to accept a type outside its offer.
-/
def readServerCertType (certTypesOffered : List Nat) (data : ByteArray) : Except Alert Nat := do
  ensure (data.size = 1) .decodeError
  let certType ← u8At data 0
  ensure (certType ∈ certTypesOffered) .illegalParameter
  return certType

/-- RFC 7250 §4.2's selection when the server sent server_certificate_type,
and `none` when it did not: a server that does not support the extension
leaves it out, and its Certificate message then carries X.509
certificates (RFC 9846 §4.5.1), so absence is not a refusal. -/
def readServerCertType? (certTypesOffered : List Nat) (exts : List (Nat × ByteArray)) :
    Except Alert (Option Nat) :=
  match extensionData? exts extServerCertificateType with
  | none => .ok none
  | some data => do return some (← readServerCertType certTypesOffered data)

/--
RFC 9846 §4.4.1: `struct { Extension extensions<0..2^16-1>; }`, and
"the client MUST check EncryptedExtensions for the presence of any
forbidden extensions and if any are found MUST abort the handshake
with an illegal_parameter alert".

The block may be empty. The profile admits two extensions here:
supported_groups, a `NamedGroup named_group_list<2..2^16-2>` whose
contents §4.3.7 tells the client not to act on during the handshake —
so the framing is checked and the groups go unread — and
record_size_limit, the only one whose value the client needs.

`serverNameSent` says whether the ClientHello carried server_name. When
it did not, a server_name acknowledgement is an unrequested response and
earns §4.3's unsupported_extension. When it did, the acknowledgement is a
third admitted extension, once like every extension (§4.3), with the
empty extension_data RFC 6066 §3 gives it.

`alpnOffered` is the list of protocols the ClientHello offered, in the
order it offered them, and it is empty when the hello sent no ALPN
extension. An empty offer makes an ALPN selection an unrequested
response too; a non-empty one makes it a fourth admitted extension,
read by `readAlpn`.

`certTypesOffered` is the list of CertificateType values the
ClientHello's server_certificate_type offered (RFC 7250 §4.1), and it is
empty when the hello sent no such extension. An empty offer makes a
server_certificate_type an unrequested response; a non-empty one makes
it a fifth admitted extension, read by `readServerCertType`.
-/
def parseEncryptedExtensions (serverNameSent : Bool) (alpnOffered : List ByteArray)
    (certTypesOffered : List Nat) (msg : ByteArray) : Except Alert EncryptedExtensions := do
  let body ← messageBody msg encryptedExtensionsType
  let (extBytes, off) ← vec16At body 0
  ensure (off = body.size) .decodeError
  let exts ← extensionList extBytes
  ensureAllowed (encryptedExtensionsAllowed serverNameSent alpnOffered certTypesOffered)
    (encryptedExtensionsAlert serverNameSent alpnOffered certTypesOffered) exts
  checkSupportedGroups exts
  checkServerNameAck exts
  let alpnSelected ← readAlpn? alpnOffered exts
  let serverCertType ← readServerCertType? certTypesOffered exts
  let recordSizeLimit ← readRecordSizeLimit? exts
  return { recordSizeLimit, alpnSelected, serverCertType }

/-! ## Certificate (RFC 9846 §4.5.1) -/

/-- What an accepted Certificate hands the client. -/
structure Certificate where
  /-- How many CertificateEntry structures the list held. -/
  entryCount : Nat
  /-- The first entry's cert_data: the end-entity certificate
  (§4.5.1, "the sender's certificate MUST come first"). -/
  leafCert : ByteArray

/--
The CertificateEntry list (RFC 9846 §4.5.1), walked entry by entry:
`opaque cert_data<1..2^24-1>` then `Extension extensions<0..2^16-1>`.
An empty cert_data is out of the specified range (§6.2).

Profile: the per-entry extensions must be empty. §4.5.1 admits the
OCSP status_request and signed_certificate_timestamp responses there,
and §4.3 makes any response the client did not request an
unsupported_extension — this client requests neither. Which opaque an
entry holds is the certificate type EncryptedExtensions negotiated: a
DER X.509 certificate in cert_data by default, and, when the
TRUST=webpki build's server_certificate_type selected RawPublicKey, an
ASN1_subjectPublicKeyInfo (RFC 7250 §3). Both are
`opaque <1..2^24-1>` followed by the same extensions vector, so the
framing read here is the same for both, and the bytes go unread.

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
RFC 9846 §4.5.1: `struct { opaque certificate_request_context<0..2^8-1>;
CertificateEntry certificate_list<0..2^24-1>; }`.

* certificate_request_context "SHALL be zero length" in the case of
  server authentication, which is the only case this client sees. The
  RFC states the requirement and names no alert for breaking it, so
  the refusal is `unspecified`;
* the list ends the message;
* §4.5.1.3: "If the server supplies an empty Certificate message, the
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

/-! ## CertificateVerify (RFC 9846 §4.5.2) -/

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

/-- The SignatureScheme code point (RFC 9846 §4.3.3). -/
def Scheme.code : Scheme → Nat
  | .rsa => 0x0804
  | .p256 => 0x0403

/--
What a build's ClientHello offers in signature_algorithms (RFC 9846
§4.3.3), which fixes what CertificateVerify may carry. A raw or ca build
pins one `Scheme` and offers it alone. A TRUST=webpki build cannot know
which algorithm family signed the chain the server will send, so it
offers five.
-/
inductive SignatureOffer
  /-- The raw and ca builds: the one scheme the Makefile's PIN pins. -/
  | pinned (scheme : Scheme)
  /-- The TRUST=webpki build. -/
  | webpki

/-- The SignatureScheme code points the offer lists, in the order the
ClientHello sends them. The webpki list is rsa_pss_rsae_sha256,
ecdsa_secp256r1_sha256 and ecdsa_secp384r1_sha384, one for each leaf key
family, then rsa_pkcs1_sha256 and rsa_pkcs1_sha384 for the certificate
signatures a public CA writes. -/
def SignatureOffer.codes : SignatureOffer → List Nat
  | .pinned scheme => [scheme.code]
  | .webpki => [0x0804, 0x0403, 0x0503, 0x0401, 0x0501]

/-- The RSASSA-PKCS1-v1_5 SignatureScheme code points RFC 9846 §4.3.3
lists: rsa_pkcs1_sha256, rsa_pkcs1_sha384 and rsa_pkcs1_sha512. §4.3.3
requires RSASSA-PSS for an RSA CertificateVerify whether or not these
appear in signature_algorithms. -/
def rsaPkcs1Schemes : List Nat := [0x0401, 0x0501, 0x0601]

/-- The SignatureScheme code points a CertificateVerify may carry under
the offer: the offered codes that §4.5.2 permits there. A pinned build's
is its one scheme. The webpki build's are rsa_pss_rsae_sha256,
ecdsa_secp256r1_sha256 and ecdsa_secp384r1_sha384, one per leaf key
family; the two RSASSA-PKCS1-v1_5 schemes it offered are for certificate
signatures only. `certificateVerifyCodes_permitted` proves each code is
offered and none is in `rsaPkcs1Schemes`. -/
def SignatureOffer.certificateVerifyCodes : SignatureOffer → List Nat
  | .pinned scheme => [scheme.code]
  | .webpki => [0x0804, 0x0403, 0x0503]

/-- The line protocol's offer token: `rsa` and `p256` are the pinned
builds, spelled as `Spec.X509.algOf?` spells the matching certificate
algorithm, and `webpki` is the TRUST=webpki build. -/
def offerOf? : String → Option SignatureOffer
  | "rsa" => some (.pinned .rsa)
  | "p256" => some (.pinned .p256)
  | "webpki" => some .webpki
  | _ => none

/-- What an accepted CertificateVerify hands the client. -/
structure CertificateVerify where
  /-- The SignatureScheme the server signed under (§4.5.2). -/
  algorithm : Nat
  /-- The signature octets, for the verifier that runs next. -/
  signature : ByteArray

/--
RFC 9846 §4.5.2: the octets the CertificateVerify signature covers —
64 octets of 0x20, the context string "TLS 1.3, server
CertificateVerify", a single zero octet, and the transcript hash. The
client builds this and hands it, not the transcript hash alone, to the
pinned key's verifier.
-/
def verifyContent (transcriptHash : ByteArray) : ByteArray :=
  ByteArray.mk (Array.replicate 64 0x20) ++ ascii "TLS 1.3, server CertificateVerify"
    ++ ByteArray.mk #[0] ++ transcriptHash

/--
RFC 9846 §4.5.2: `struct { SignatureScheme algorithm; opaque
signature<0..2^16-1>; }`, filling the message exactly.

* `algorithm`: one of `SignatureOffer.certificateVerifyCodes` — a
  pinned build's one scheme, or the webpki build's three. §4.5.2
  requires an offered scheme and forbids RSASSA-PKCS1-v1_5 here even
  when offered, and the list keeps both rules. §4.5.2 names no alert
  for a scheme outside it, so every such scheme gets one verdict,
  `unspecified`;
* `signature`: `opaque signature<0..2^16-1>`, exact-fill. §4.5.2 sets
  no length rule of its own — what lengths a scheme admits is the
  verifier's business, so no bound is imposed here. Whether the
  signature verifies is not decided here either; §4.5.2 makes that
  failure a decrypt_error, and it belongs to `Spec.Rsa.pssVerify` or
  `Spec.P256.ecdsaVerify` over `verifyContent`.
-/
def parseCertificateVerify (offer : SignatureOffer) (msg : ByteArray) :
    Except Alert CertificateVerify := do
  let body ← messageBody msg certificateVerifyType
  let algorithm ← u16At body 0
  ensure (offer.certificateVerifyCodes.contains algorithm = true) .unspecified
  let (signature, off) ← vec16At body 2
  ensure (off = body.size) .decodeError
  -- §4.5.2 frames the signature as `opaque signature<0..2^16-1>` and
  -- says nothing about its length: what lengths are admissible is the
  -- signature algorithm's business, settled when the signature is
  -- verified. handshake_parser.c leaves it there too.
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

/-- One Extension: type and its data vector (RFC 9846 §4.3). -/
def extension (t : Nat) (data : ByteArray) : ByteArray := u16 t ++ vec16 data

/-- One Handshake structure: msg_type, uint24 length, body
(RFC 9846 §4). -/
def message (msgType : Nat) (body : ByteArray) : ByteArray :=
  ByteArray.mk #[UInt8.ofNat msgType] ++ vec24 body

/-- A ServerHello body around a caller-supplied Random and extension
block (RFC 9846 §4.2.3), with TLS_CHACHA20_POLY1305_SHA256, the suite
every client build offers, and no compression. -/
def serverHelloBody (random sessionId exts : ByteArray) : ByteArray :=
  u16 legacyVersion ++ random ++ vec8 sessionId ++ u16 chacha20Poly1305Sha256 ++
    ByteArray.mk #[0] ++ vec16 exts

/-- One CertificateEntry: cert_data and its extension vector
(RFC 9846 §4.5.1). -/
def certificateEntry (cert exts : ByteArray) : ByteArray := vec24 cert ++ vec16 exts

/-! ## Selftest -/

set_option compiler.extract_closed false in
/--
Structural checks: the message grammar has no third-party vectors, so
the selftest builds one on-profile message of each kind, checks the
fields come back, and then walks one case per refusal the RFC and the
profile owe. The §4.2.4 Random is pinned twice over — against the
literal §4.2.3 prints and against its stated derivation, the SHA-256 of
"HelloRetryRequest". The ServerHello rows run under all three `Kex`
values: one accepted message per group a build lists, the cross-group
refusal each way, the hybrid share length at its boundary, and the
retry branch under each build — which groups a retry may name, and
that it must ask for a change. The cipher_suite rows run under both
`SuiteOffer` values: each offered suite passes in a ServerHello and in
a retry and comes back in the fields, and suites the build did not
offer are refused.
Functional coverage against the C comes from the differential run.
-/
def selftest (_ : Unit) : Bool := Id.run do
  let random := ByteArray.mk (Array.replicate 32 0x5a)
  -- handshake_message.c offers an empty legacy_session_id, so the echo is empty.
  let sessionId := ByteArray.mk #[]
  let share := ByteArray.mk (Array.replicate 32 0x77)
  let versionExt := extension extSupportedVersions (u16 tls13Version)
  let keyShareExt := extension extKeyShare (u16 x25519Group ++ vec16 share)
  let hex := bytesToHex
  -- The §4.2.4 Random, from the §4.2.3 literal and from its derivation.
  let hrrRandomOk := hex helloRetryRequestRandom ==
      "cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c" &&
    hex (Spec.Sha256.sha256 (ascii "HelloRetryRequest")) == hex helloRetryRequestRandom
  -- ServerHello: the profile's own message, and the fields it yields.
  let serverHelloOf (exts : ByteArray) : ByteArray :=
    message serverHelloType (serverHelloBody random sessionId exts)
  let good := serverHelloOf (versionExt ++ keyShareExt)
  let acceptsShareUnder (kex : Kex) (msg : ByteArray) (group : Nat) (want : ByteArray)
      (identity : Option Nat) : Bool :=
    match parseServerHello kex .chacha true msg with
    | .ok (.serverHello fields) =>
      hex fields.sessionIdEcho == hex sessionId && fields.group == group &&
        hex fields.keyExchange == hex want && fields.selectedIdentity == identity
    | _ => false
  let acceptsShare (msg : ByteArray) (identity : Option Nat) : Bool :=
    acceptsShareUnder .x25519 msg x25519Group share identity
  let rejectsUnder (kex : Kex) (msg : ByteArray) : Bool :=
    (parseServerHello kex .chacha true msg).toOption.isNone
  let rejects (msg : ByteArray) : Bool := rejectsUnder .x25519 msg
  let refusesWithUnder (kex : Kex) (msg : ByteArray) (alert : Alert) : Bool :=
    match parseServerHello kex .chacha true msg with
    | .error refused => refused == alert
    | .ok _ => false
  let serverHelloOk := acceptsShare good none &&
    -- §4.2.3: legacy_version is frozen at 0x0303.
    rejects (message serverHelloType (ByteArray.mk #[0x03, 0x04] ++ random ++ vec8 sessionId ++
      u16 chacha20Poly1305Sha256 ++ ByteArray.mk #[0] ++ vec16 (versionExt ++ keyShareExt))) &&
    -- §4.2.3: any echo but the empty one we offered is illegal_parameter.
    rejects (message serverHelloType (serverHelloBody random
      (ByteArray.mk (Array.replicate 32 0xa5)) (versionExt ++ keyShareExt))) &&
    -- §4.3.11: the one identity the profile offers is index 0.
    acceptsShare (serverHelloOf (versionExt ++ keyShareExt ++
      extension extPreSharedKey (u16 0))) (some 0) &&
    rejects (serverHelloOf (versionExt ++ keyShareExt ++
      extension extPreSharedKey (u16 1))) &&
    -- §4: the length field counts the body, and one call carries one message.
    rejects (good ++ ByteArray.mk #[0]) &&
    rejects (good.extract 0 (good.size - 1)) &&
    rejects (ByteArray.mk #[UInt8.ofNat certificateType] ++ good.extract 1 good.size) &&
    -- §9.2 and §4.3.1: supported_versions is required and pins 0x0304.
    rejects (serverHelloOf keyShareExt) &&
    rejects (serverHelloOf (extension extSupportedVersions (u16 0x0303) ++ keyShareExt)) &&
    rejects (serverHelloOf (extension extSupportedVersions (u16 tls13Version ++ u16 0) ++
      keyShareExt)) &&
    -- §9.2 and §4.3.8: key_share is required, x25519 only, 32 octets only.
    rejects (serverHelloOf (versionExt ++ extension extCookie (vec16 (ascii "c")))) &&
    rejects (serverHelloOf (versionExt ++
      extension extKeyShare (u16 0x0017 ++ vec16 share))) &&
    rejects (serverHelloOf (versionExt ++
      extension extKeyShare (u16 x25519Group ++ vec16 (share.extract 0 31)))) &&
    -- §4.3: one extension of each type, and only the three §4.3 admits here.
    rejects (serverHelloOf (versionExt ++ versionExt ++ keyShareExt)) &&
    rejects (serverHelloOf (versionExt ++ keyShareExt ++
      extension extServerName ByteArray.empty)) &&
    rejects (serverHelloOf (versionExt ++ keyShareExt ++
      extension 0xfeed ByteArray.empty))
  -- §4.2.3: an offered cipher suite, no compression, a 32-octet echo.
  let handBuilt (suite : Nat) (compression : Nat) (sid : ByteArray) : ByteArray :=
    message serverHelloType (u16 0x0303 ++ random ++ vec8 sid ++ u16 suite ++
      ByteArray.mk #[UInt8.ofNat compression] ++ vec16 (versionExt ++ keyShareExt))
  let profileOk := acceptsShare (handBuilt chacha20Poly1305Sha256 0 sessionId) none &&
    rejects (handBuilt 0x1301 0 sessionId) &&
    rejects (handBuilt chacha20Poly1305Sha256 1 sessionId) &&
    rejects (handBuilt chacha20Poly1305Sha256 0 (ByteArray.mk (Array.replicate 33 0xa5)))
  -- §4.2.4: the same format under the special Random is a retry request.
  let cookie := ascii "retry me"
  let cookieExt := extension extCookie (vec16 cookie)
  let hrrOf (exts : ByteArray) : ByteArray :=
    message serverHelloType (serverHelloBody helloRetryRequestRandom sessionId exts)
  let retriesUnder (kex : Kex) (msg : ByteArray) (wantCookie : Option ByteArray)
      (wantGroup : Option Nat) : Bool :=
    match parseServerHello kex .chacha true msg with
    | .ok (.helloRetryRequest fields) =>
      hex fields.sessionIdEcho == hex sessionId &&
        fields.cookie.map hex == wantCookie.map hex && fields.selectedGroup == wantGroup
    | _ => false
  -- KeyShareHelloRetryRequest (§4.3.8): the selected group alone.
  let retryShareExt (group : Nat) : ByteArray := extension extKeyShare (u16 group)
  let hrrOk :=
    retriesUnder .x25519 (hrrOf (versionExt ++ cookieExt)) (some cookie) none &&
    -- A retry with neither a cookie nor a key_share asks for no change;
    -- a retry with a key_share asks for a group the client either
    -- already sent or never offered.
    refusesWithUnder .x25519 (hrrOf versionExt) .illegalParameter &&
    rejects (hrrOf (versionExt ++ retryShareExt x25519Group)) &&
    rejects (hrrOf (versionExt ++ cookieExt ++ retryShareExt x25519Group)) &&
    rejects (hrrOf (versionExt ++ extension extCookie (vec16 ByteArray.empty))) &&
    -- The Random decides, and only the whole 32 octets do.
    rejects (hrrOf (versionExt ++ keyShareExt)) &&
    acceptsShare (message serverHelloType (serverHelloBody
      (helloRetryRequestRandom.extract 0 31 ++ ByteArray.mk #[0]) sessionId
      (versionExt ++ keyShareExt))) none
  -- The one-group KEX builds (§4.3.8, RFC 10024): each accepts its own
  -- group's share at its own length and refuses the other build's.
  let hybridShare := ByteArray.mk (Array.replicate 1120 0x88)
  let pqShareExtOf (keyExchange : ByteArray) : ByteArray :=
    extension extKeyShare (u16 hybridGroup ++ vec16 keyExchange)
  let kexOk :=
    acceptsShareUnder .pq (serverHelloOf (versionExt ++ pqShareExtOf hybridShare))
      hybridGroup hybridShare none &&
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
    -- is accepted, and a retry selecting either group is refused — the
    -- hybrid already has a share, and x25519 was never listed.
    retriesUnder .pq (hrrOf (versionExt ++ cookieExt)) (some cookie) none &&
    rejectsUnder .pq (hrrOf (versionExt ++ cookieExt ++ retryShareExt hybridGroup)) &&
    rejectsUnder .pq (hrrOf (versionExt ++ cookieExt ++ retryShareExt x25519Group)) &&
    rejectsUnder .pq (hrrOf (versionExt ++ retryShareExt x25519Group))
  -- The two-group build (docs/decisions.md entry 53) lists
  -- X25519MLKEM768 then x25519 and sends a share for each. Its
  -- ServerHello may select either group, each at its own share length,
  -- and its retry may name neither: both already have a share.
  let twoGroupsOk :=
    Kex.twoGroups.retryGroups == [] &&
    Kex.pq.retryGroups == [] && Kex.x25519.retryGroups == [] &&
    acceptsShareUnder .twoGroups (serverHelloOf (versionExt ++ pqShareExtOf hybridShare))
      hybridGroup hybridShare none &&
    acceptsShareUnder .twoGroups good x25519Group share none &&
    -- The size follows the selected group: each group refuses the
    -- other's share length.
    refusesWithUnder .twoGroups (serverHelloOf (versionExt ++
      extension extKeyShare (u16 x25519Group ++ vec16 hybridShare))) .decodeError &&
    refusesWithUnder .twoGroups (serverHelloOf (versionExt ++ pqShareExtOf share))
      .decodeError &&
    -- secp256r1(0x0017), a group the build never listed.
    refusesWithUnder .twoGroups (serverHelloOf (versionExt ++
      extension extKeyShare (u16 0x0017 ++ vec16 share))) .illegalParameter &&
    -- A retry carries the cookie alone. Both listed groups already have
    -- a share, so a retry naming either is refused, with a cookie or
    -- without one, and 0x0017 was never listed.
    retriesUnder .twoGroups (hrrOf (versionExt ++ cookieExt)) (some cookie) none &&
    refusesWithUnder .twoGroups (hrrOf (versionExt ++ retryShareExt x25519Group))
      .illegalParameter &&
    refusesWithUnder .twoGroups (hrrOf (versionExt ++ cookieExt ++ retryShareExt x25519Group))
      .illegalParameter &&
    refusesWithUnder .twoGroups (hrrOf (versionExt ++ retryShareExt hybridGroup))
      .illegalParameter &&
    refusesWithUnder .twoGroups (hrrOf (versionExt ++ retryShareExt 0x0017))
      .illegalParameter &&
    -- KeyShareHelloRetryRequest is two octets exactly.
    refusesWithUnder .twoGroups (hrrOf (versionExt ++
      extension extKeyShare (u16 x25519Group ++ ByteArray.mk #[0]))) .decodeError &&
    -- A retry that asks for no change.
    refusesWithUnder .twoGroups (hrrOf versionExt) .illegalParameter
  -- The SUITE=aesgcm TRUST=webpki client (docs/decisions.md entry 45)
  -- offers TLS_CHACHA20_POLY1305_SHA256 then TLS_AES_128_GCM_SHA256. A
  -- ServerHello or a retry may carry either and reports which (§4.2.3,
  -- §4.2.4); a suite the client did not offer is an illegal_parameter.
  let withSuite (random : ByteArray) (suite : Nat) (exts : ByteArray) : ByteArray :=
    message serverHelloType (u16 legacyVersion ++ random ++ vec8 sessionId ++ u16 suite ++
      ByteArray.mk #[0] ++ vec16 exts)
  let helloWithSuite (suite : Nat) : ByteArray :=
    withSuite random suite (versionExt ++ keyShareExt)
  let retryWithSuite (suite : Nat) : ByteArray :=
    withSuite helloRetryRequestRandom suite (versionExt ++ cookieExt)
  let helloSuite (suiteOffer : SuiteOffer) (msg : ByteArray) : Option Nat :=
    match parseServerHello .x25519 suiteOffer true msg with
    | .ok (.serverHello fields) => some fields.cipherSuite
    | _ => none
  let retrySuite (suiteOffer : SuiteOffer) (msg : ByteArray) : Option Nat :=
    match parseServerHello .x25519 suiteOffer true msg with
    | .ok (.helloRetryRequest fields) => some fields.cipherSuite
    | _ => none
  let refusesSuite (suiteOffer : SuiteOffer) (msg : ByteArray) : Bool :=
    match parseServerHello .x25519 suiteOffer true msg with
    | .error .illegalParameter => true
    | _ => false
  let suiteOk :=
    helloSuite .chacha good == some chacha20Poly1305Sha256 &&
    helloSuite .chachaAndAes (helloWithSuite aes128GcmSha256) == some aes128GcmSha256 &&
    helloSuite .chachaAndAes (helloWithSuite chacha20Poly1305Sha256) ==
      some chacha20Poly1305Sha256 &&
    -- TLS_AES_256_GCM_SHA384(0x1302) and TLS_AES_128_CCM_SHA256(0x1304):
    -- RFC 9846 appendix B.4 defines both, and no client build offers
    -- either.
    refusesSuite .chachaAndAes (helloWithSuite 0x1302) &&
    refusesSuite .chachaAndAes (helloWithSuite 0x1304) &&
    retrySuite .chachaAndAes (retryWithSuite aes128GcmSha256) == some aes128GcmSha256 &&
    retrySuite .chachaAndAes (retryWithSuite chacha20Poly1305Sha256) ==
      some chacha20Poly1305Sha256 &&
    -- The one-suite offer refuses TLS_AES_128_GCM_SHA256 in either message.
    refusesSuite .chacha (helloWithSuite aes128GcmSha256) &&
    refusesSuite .chacha (retryWithSuite aes128GcmSha256)
  -- §4.4.1 and RFC 8449 §4.
  let encryptedExtensionsOf (exts : ByteArray) : ByteArray :=
    message encryptedExtensionsType (vec16 exts)
  let limitSent (serverNameSent : Bool) (msg : ByteArray) : Option (Option Nat) :=
    (parseEncryptedExtensions serverNameSent [] [] msg).toOption.map
      (fun fields => fields.recordSizeLimit)
  let limitOf := limitSent false
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
    -- §4.3: this client sends no server_name, so its acknowledgement,
    -- empty or not, is an unrequested response the client refuses.
    limitOf (encryptedExtensionsOf (extension extServerName ByteArray.empty)) == none &&
    limitOf (encryptedExtensionsOf (extension extServerName (ascii "x"))) == none &&
    (match parseEncryptedExtensions false [] []
        (encryptedExtensionsOf (extension extServerName (ascii "x"))) with
     | .error .unsupportedExtension => true
     | _ => false) &&
    -- RFC 6066 §3: a ClientHello that sent server_name admits its empty
    -- acknowledgement, once, beside the other two. Data in it is a body
    -- of the wrong length, a decode_error (RFC 9846 §6).
    limitSent true (encryptedExtensionsOf (extension extServerName ByteArray.empty)) ==
      some none &&
    (match parseEncryptedExtensions true [] []
        (encryptedExtensionsOf (extension extServerName (ascii "x"))) with
     | .error .decodeError => true
     | _ => false) &&
    limitSent true (encryptedExtensionsOf (extension extRecordSizeLimit (u16 64) ++
      extension extServerName ByteArray.empty)) == some (some 64) &&
    limitSent true (encryptedExtensionsOf (extension extServerName (ascii "x"))) == none &&
    limitSent true (encryptedExtensionsOf (extension extServerName ByteArray.empty ++
      extension extServerName ByteArray.empty)) == none &&
    limitSent true (encryptedExtensionsOf (extension extEarlyData ByteArray.empty)) == none &&
    limitOf (encryptedExtensionsOf (extension extSupportedGroups
      (vec16 (u16 x25519Group)))) == some none &&
    limitOf (encryptedExtensionsOf (extension extSupportedGroups
      (vec16 (ByteArray.mk #[0x00])))) == none &&
    limitOf (message certificateType (vec16 ByteArray.empty)) == none
  -- RFC 7301 §3.2: a ClientHello that offered protocols admits one
  -- selection, reported as an index into its own offer.
  let h2 := ascii "h2"
  let http11 := ascii "http/1.1"
  let offer := [h2, http11]
  let alpnExt (name : ByteArray) : ByteArray := extension extAlpn (vec16 (vec8 name))
  let alpnOf (msg : ByteArray) : Option (Option Nat) :=
    (parseEncryptedExtensions true offer [] msg).toOption.map (fun fields => fields.alpnSelected)
  let refusesWith (offered : List ByteArray) (msg : ByteArray) (alert : Alert) : Bool :=
    match parseEncryptedExtensions true offered [] msg with
    | .error a => a == alert
    | .ok _ => false
  let alpnOk :=
    alpnOf (encryptedExtensionsOf (alpnExt h2)) == some (some 0) &&
    alpnOf (encryptedExtensionsOf (alpnExt http11)) == some (some 1) &&
    -- §3.2 lets a server that does not support ALPN send no extension.
    alpnOf (encryptedExtensionsOf ByteArray.empty) == some none &&
    -- A protocol the client never offered, and a prefix of one it did.
    alpnOf (encryptedExtensionsOf (alpnExt (ascii "h3"))) == none &&
    alpnOf (encryptedExtensionsOf (alpnExt (ascii "h"))) == none &&
    refusesWith offer (encryptedExtensionsOf (alpnExt (ascii "h3"))) .illegalParameter &&
    -- §3.2: exactly one ProtocolName, and §3.1 gives it at least one
    -- octet. Two names, an empty name and a trailing octet are each a
    -- body of the wrong length.
    alpnOf (encryptedExtensionsOf (extension extAlpn (vec16 (vec8 h2 ++ vec8 http11)))) == none &&
    alpnOf (encryptedExtensionsOf (extension extAlpn (vec16 (vec8 ByteArray.empty)))) == none &&
    refusesWith offer (encryptedExtensionsOf (extension extAlpn (vec16 (vec8 ByteArray.empty))))
      .decodeError &&
    alpnOf (encryptedExtensionsOf
      (extension extAlpn (vec16 (vec8 h2) ++ ByteArray.mk #[0]))) == none &&
    -- One selection only (§4.3), and only for a client that offered
    -- protocols: with no offer the extension is an unrequested response.
    alpnOf (encryptedExtensionsOf (alpnExt h2 ++ alpnExt h2)) == none &&
    refusesWith [] (encryptedExtensionsOf (alpnExt h2)) .unsupportedExtension &&
    -- The selection sits beside the other three admitted extensions.
    (parseEncryptedExtensions true offer [] (encryptedExtensionsOf
      (extension extRecordSizeLimit (u16 64) ++ extension extServerName ByteArray.empty ++
        alpnExt h2))).toOption.map (fun f => (f.recordSizeLimit, f.alpnSelected)) ==
      some (some 64, some 0)
  -- RFC 7250 §4.2: a ClientHello that offered certificate types admits
  -- one selection from its offer, one octet long.
  let rawKey := 2
  let x509 := 0
  let certTypeExt (data : ByteArray) : ByteArray := extension extServerCertificateType data
  let certTypeOf (offered : List Nat) (msg : ByteArray) : Option (Option Nat) :=
    (parseEncryptedExtensions true [] offered msg).toOption.map (fun f => f.serverCertType)
  let certTypeRefusal (offered : List Nat) (msg : ByteArray) : Option Alert :=
    match parseEncryptedExtensions true [] offered msg with
    | .error a => some a
    | .ok _ => none
  let oneOctet (n : Nat) : ByteArray := ByteArray.mk #[UInt8.ofNat n]
  let certTypeOk :=
    certTypeOf [rawKey] (encryptedExtensionsOf (certTypeExt (oneOctet rawKey))) ==
      some (some rawKey) &&
    certTypeOf [rawKey, x509] (encryptedExtensionsOf (certTypeExt (oneOctet x509))) ==
      some (some x509) &&
    -- A server that sends none leaves the X.509 default to the client.
    certTypeOf [rawKey, x509] (encryptedExtensionsOf ByteArray.empty) == some none &&
    -- A type outside the offer is illegal_parameter; no offer at all
    -- makes the extension unrequested.
    certTypeRefusal [rawKey] (encryptedExtensionsOf (certTypeExt (oneOctet x509))) ==
      some .illegalParameter &&
    certTypeRefusal [rawKey, x509] (encryptedExtensionsOf (certTypeExt (oneOctet 1))) ==
      some .illegalParameter &&
    certTypeRefusal [] (encryptedExtensionsOf (certTypeExt (oneOctet rawKey))) ==
      some .unsupportedExtension &&
    -- One octet exactly: zero and two are decode_error.
    certTypeRefusal [rawKey] (encryptedExtensionsOf (certTypeExt ByteArray.empty)) ==
      some .decodeError &&
    certTypeRefusal [rawKey] (encryptedExtensionsOf
      (certTypeExt (oneOctet rawKey ++ oneOctet 0))) == some .decodeError &&
    certTypeOf [rawKey] (encryptedExtensionsOf
      (certTypeExt (oneOctet rawKey) ++ certTypeExt (oneOctet rawKey))) == none &&
    -- The empty server_name acknowledgement passes when the ClientHello
    -- sent server_name. One without a hostname sent none, so there the
    -- same acknowledgement is unrequested.
    certTypeRefusal [rawKey] (encryptedExtensionsOf (extension extServerName ByteArray.empty)) ==
      none &&
    (match parseEncryptedExtensions false [] [rawKey]
        (encryptedExtensionsOf (extension extServerName ByteArray.empty)) with
     | .error .unsupportedExtension => true
     | _ => false)
  -- §4.5.1: the context is empty, the list is not, entries carry no extensions.
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
  -- §4.5.2: one pinned scheme, one signature, exact-fill. The
  -- signature's own length is the verifier's business, not this
  -- parser's, so no length but a framing error is refused here.
  let rsaSig := ByteArray.mk (Array.replicate 256 0x33)
  let ecdsaSig := ByteArray.mk (Array.replicate 70 0x44)
  let verifyOf (algorithm : Nat) (sig : ByteArray) : ByteArray :=
    message certificateVerifyType (u16 algorithm ++ vec16 sig)
  let verifiesUnder (offer : SignatureOffer) (algorithm : Nat) (sig : ByteArray) : Bool :=
    match parseCertificateVerify offer (verifyOf algorithm sig) with
    | .ok fields => fields.algorithm == algorithm && hex fields.signature == hex sig
    | .error _ => false
  let verifies (scheme : Scheme) (msg : ByteArray) (sig : ByteArray) : Bool :=
    match parseCertificateVerify (.pinned scheme) msg with
    | .ok fields => fields.algorithm == scheme.code && hex fields.signature == hex sig
    | .error _ => false
  let refusesUnder (offer : SignatureOffer) (msg : ByteArray) : Bool :=
    (parseCertificateVerify offer msg).toOption.isNone
  let refuses (scheme : Scheme) (msg : ByteArray) : Bool := refusesUnder (.pinned scheme) msg
  let certificateVerifyOk :=
    verifies .rsa (verifyOf Scheme.rsa.code rsaSig) rsaSig &&
    verifies .p256 (verifyOf Scheme.p256.code ecdsaSig) ecdsaSig &&
    refuses .rsa (verifyOf Scheme.p256.code rsaSig) &&
    refuses .p256 (verifyOf Scheme.rsa.code ecdsaSig) &&
    verifies .rsa (verifyOf Scheme.rsa.code (ByteArray.mk (Array.replicate 39 0x33)))
      (ByteArray.mk (Array.replicate 39 0x33)) &&
    refuses .rsa (verifyOf Scheme.rsa.code rsaSig ++ ByteArray.mk #[0]) &&
    -- The webpki offer: the three leaf-key schemes pass, the two
    -- RSASSA-PKCS1-v1_5 schemes it offered are refused here (§4.3.3), and
    -- so are schemes it never offered, rsa_pkcs1_sha512 and
    -- rsa_pss_rsae_sha384.
    verifiesUnder .webpki 0x0804 rsaSig && verifiesUnder .webpki 0x0403 ecdsaSig &&
    verifiesUnder .webpki 0x0503 ecdsaSig &&
    refusesUnder .webpki (verifyOf 0x0401 rsaSig) &&
    refusesUnder .webpki (verifyOf 0x0501 rsaSig) &&
    refusesUnder .webpki (verifyOf 0x0601 rsaSig) &&
    refusesUnder .webpki (verifyOf 0x0805 rsaSig) &&
    refusesUnder .webpki (verifyOf 0x0804 rsaSig ++ ByteArray.mk #[0]) &&
    refuses .rsa (verifyOf 0x0503 ecdsaSig)
  -- §4.5.2: the signed content is 64 spaces, the context string, a zero, the hash.
  let transcript := Spec.Sha256.sha256 (ascii "transcript")
  let content := verifyContent transcript
  let verifyContentOk := content.size == 130 &&
    hex (content.extract 0 64) == hex (ByteArray.mk (Array.replicate 64 0x20)) &&
    hex (content.extract 64 97) == hex (ascii "TLS 1.3, server CertificateVerify") &&
    content[97]! == 0 && hex (content.extract 98 130) == hex transcript
  return hrrRandomOk && serverHelloOk && profileOk && hrrOk && kexOk && twoGroupsOk && suiteOk &&
    encryptedExtensionsOk && alpnOk && certTypeOk && certificateOk && certificateVerifyOk &&
    verifyContentOk

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
`opaque cert_data<1..2^24-1>` admits no empty entry (RFC 9846 §4.5.1).
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
Certificate soundness (RFC 9846 §4.5.1, §4.5.1.3). An accepted message
reports at least one entry and a nonempty leaf certificate: the empty
certificate list §4.5.1.3 refuses cannot come back as an accepted one,
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
The shared ServerHello prefix (RFC 9846 §4.2.3): whatever the message
turns out to be, its Random is the 32 octets at offset 2 of the body,
its session id echo is empty — the only echo that can match the empty
legacy_session_id this profile offers (§4.2.3) — and its cipher suite is
one the build offers.
-/
private theorem serverHelloPrefix_sound (suiteOffer : SuiteOffer) (msg : ByteArray)
    (p : ServerHelloPrefix) (h_prefix : serverHelloPrefix suiteOffer msg = .ok p) :
    ∃ body, messageBody msg serverHelloType = .ok body ∧
      p.random = body.extract 2 34 ∧ p.sessionIdEcho.size = 0 ∧
      p.cipherSuite ∈ suiteOffer.cipherSuites := by
  rw [serverHelloPrefix] at h_prefix
  obtain ⟨body, h_framed, h_prefix⟩ := exists_of_bind_eq_ok h_prefix
  obtain ⟨_, -, h_prefix⟩ := exists_of_bind_eq_ok h_prefix
  obtain ⟨-, h_prefix⟩ := of_ensure_bind h_prefix
  obtain ⟨_, h_random_read, h_prefix⟩ := exists_of_bind_eq_ok h_prefix
  obtain ⟨⟨_, _⟩, -, h_prefix⟩ := exists_of_bind_eq_ok h_prefix
  obtain ⟨-, h_prefix⟩ := of_ensure_bind h_prefix
  obtain ⟨h_echo_empty, h_prefix⟩ := of_ensure_bind h_prefix
  obtain ⟨_, -, h_prefix⟩ := exists_of_bind_eq_ok h_prefix
  obtain ⟨h_suite_offered, h_prefix⟩ := of_ensure_bind h_prefix
  obtain ⟨_, -, h_prefix⟩ := exists_of_bind_eq_ok h_prefix
  obtain ⟨-, h_prefix⟩ := of_ensure_bind h_prefix
  obtain ⟨⟨_, _⟩, -, h_prefix⟩ := exists_of_bind_eq_ok h_prefix
  obtain ⟨-, h_prefix⟩ := of_ensure_bind h_prefix
  obtain ⟨-, h_prefix⟩ := of_ensure_bind h_prefix
  obtain ⟨_, -, h_prefix⟩ := exists_of_bind_eq_ok h_prefix
  obtain rfl := eq_of_pure_eq_ok h_prefix
  exact ⟨body, h_framed, bytesAt_eq h_random_read, h_echo_empty, h_suite_offered⟩

/--
The ServerHello branch's own fields (RFC 9846 §4.2.3, §4.3.8, §4.3.11):
the echo and the cipher suite are the prefix's, the group is one the
build lists in supported_groups, the key_exchange is exactly the
`serverShareSize` octets a share in that group occupies, and a PSK
identity, when there is one, is the single index the profile's one
offered identity puts in range.
-/
private theorem serverHelloFields_sound (kex : Kex) (pskOffered : Bool) (p : ServerHelloPrefix)
    (fields : ServerHello) (h_fields : serverHelloFields kex pskOffered p = .ok fields) :
    fields.sessionIdEcho = p.sessionIdEcho ∧ fields.cipherSuite = p.cipherSuite ∧
      fields.group ∈ kex.supportedGroups ∧
      fields.keyExchange.size = serverShareSize fields.group ∧
      ∀ identity, fields.selectedIdentity = some identity → identity = 0 := by
  rw [serverHelloFields] at h_fields
  obtain ⟨_, -, h_fields⟩ := exists_of_bind_eq_ok h_fields
  obtain ⟨-, h_fields⟩ := of_ensure_bind h_fields
  obtain ⟨⟨group, key⟩, h_share, h_fields⟩ := exists_of_bind_eq_ok h_fields
  obtain ⟨identity, h_identity, h_fields⟩ := exists_of_bind_eq_ok h_fields
  obtain rfl := eq_of_pure_eq_ok h_fields
  rw [readKeyShare] at h_share
  obtain ⟨_, -, h_share⟩ := exists_of_bind_eq_ok h_share
  obtain ⟨_, -, h_share⟩ := exists_of_bind_eq_ok h_share
  obtain ⟨h_group, h_share⟩ := of_ensure_bind h_share
  obtain ⟨⟨_, _⟩, -, h_share⟩ := exists_of_bind_eq_ok h_share
  obtain ⟨-, h_share⟩ := of_ensure_bind h_share
  obtain ⟨h_key_size, h_share⟩ := of_ensure_bind h_share
  obtain ⟨rfl, rfl⟩ := Prod.mk.inj (eq_of_pure_eq_ok h_share)
  refine ⟨rfl, rfl, h_group, h_key_size, ?_⟩
  · rintro i rfl
    rw [readSelectedIdentity?] at h_identity
    split at h_identity
    · simp at h_identity
    · obtain ⟨-, h_identity⟩ := of_ensure_bind h_identity
      obtain ⟨_, -, h_identity⟩ := exists_of_bind_eq_ok h_identity
      obtain ⟨h_zero, h_identity⟩ := of_ensure_bind h_identity
      have h_index := Option.some.inj (eq_of_pure_eq_ok h_identity)
      omega

/--
ServerHello soundness (RFC 9846 §4.2.3, §4.3.8, §4.3.11). An accepted
ServerHello reports an empty session id echo, the one the profile
offers; a cipher suite the build offers, which is
TLS_CHACHA20_POLY1305_SHA256 in every client build but the SUITE=aesgcm
TRUST=webpki one; a group the build lists in supported_groups; a
key_exchange of exactly the `serverShareSize` octets a share in that
group occupies — 32 for x25519, 1120 for the hybrid; and, when the
server accepted a PSK, the only identity index the profile's single
offered identity puts in range. The x25519 and pq builds list one group, so there the
group is that one and the size is fixed: a KEX=pq build accepts no
group but X25519MLKEM768. The two-group build accepts either of its
two, because it sent a share for each, and a caller that wants the
hybrid alone sets `ch_cfg.require_pq`, which the handshake checks above
this parser.
-/
theorem parseServerHello_sound (kex : Kex) (suiteOffer : SuiteOffer) (pskOffered : Bool)
    (msg : ByteArray) (fields : ServerHello)
    (h_accepted : parseServerHello kex suiteOffer pskOffered msg = .ok (.serverHello fields)) :
    fields.sessionIdEcho.size = 0 ∧ fields.cipherSuite ∈ suiteOffer.cipherSuites ∧
      fields.group ∈ kex.supportedGroups ∧
      fields.keyExchange.size = serverShareSize fields.group ∧
      ∀ identity, fields.selectedIdentity = some identity → identity = 0 := by
  rw [parseServerHello] at h_accepted
  obtain ⟨p, h_prefix, h_accepted⟩ := exists_of_bind_eq_ok h_accepted
  obtain ⟨_, -, h_accepted⟩ := exists_of_bind_eq_ok h_accepted
  obtain ⟨_, -, -, h_echo_empty, h_suite_offered⟩ :=
    serverHelloPrefix_sound suiteOffer msg p h_prefix
  split at h_accepted
  · obtain ⟨_, -, h_accepted⟩ := exists_of_bind_eq_ok h_accepted
    exact ServerHelloKind.noConfusion (eq_of_pure_eq_ok h_accepted)
  · obtain ⟨read, h_read, h_accepted⟩ := exists_of_bind_eq_ok h_accepted
    obtain rfl := ServerHelloKind.serverHello.inj (eq_of_pure_eq_ok h_accepted)
    obtain ⟨h_echo, h_suite, h_group, h_key_size, h_identity⟩ :=
      serverHelloFields_sound kex pskOffered p read h_read
    exact ⟨h_echo ▸ h_echo_empty, h_suite ▸ h_suite_offered, h_group, h_key_size, h_identity⟩

/--
HelloRetryRequest soundness (RFC 9846 §4.2.3, §4.2.4, §4.3.8). An
accepted retry carries a cipher suite the build offers, which is
TLS_CHACHA20_POLY1305_SHA256 in every client build but the SUITE=aesgcm
TRUST=webpki one. It asks for a change — it carries a cookie or a
selected group — and a selected group is one of `kex.retryGroups`:
listed in the ClientHello's supported_groups and not a group it sent a
key share for. No build has a retry group (`Kex.retryGroups_eq_nil`),
so `parseServerHello_helloRetryRequest_cookie` below reads the
statement down to what it means here: an accepted retry never selects a
group and always carries a cookie.
-/
theorem parseServerHello_helloRetryRequest_sound (kex : Kex) (suiteOffer : SuiteOffer)
    (pskOffered : Bool) (msg : ByteArray) (fields : HelloRetryRequest)
    (h_accepted :
      parseServerHello kex suiteOffer pskOffered msg = .ok (.helloRetryRequest fields)) :
    fields.cipherSuite ∈ suiteOffer.cipherSuites ∧
      (fields.cookie.isSome ∨ fields.selectedGroup.isSome) ∧
      ∀ group, fields.selectedGroup = some group → group ∈ kex.retryGroups := by
  rw [parseServerHello] at h_accepted
  obtain ⟨p, h_prefix, h_accepted⟩ := exists_of_bind_eq_ok h_accepted
  obtain ⟨_, -, h_accepted⟩ := exists_of_bind_eq_ok h_accepted
  obtain ⟨_, -, -, -, h_suite_offered⟩ := serverHelloPrefix_sound suiteOffer msg p h_prefix
  split at h_accepted
  · obtain ⟨read, h_read, h_accepted⟩ := exists_of_bind_eq_ok h_accepted
    obtain rfl := ServerHelloKind.helloRetryRequest.inj (eq_of_pure_eq_ok h_accepted)
    rw [helloRetryRequestFields] at h_read
    obtain ⟨_, -, h_read⟩ := exists_of_bind_eq_ok h_read
    obtain ⟨selected, h_selected, h_read⟩ := exists_of_bind_eq_ok h_read
    obtain ⟨_, -, h_read⟩ := exists_of_bind_eq_ok h_read
    obtain ⟨h_asks_change, h_read⟩ := of_ensure_bind h_read
    obtain rfl := eq_of_pure_eq_ok h_read
    refine ⟨h_suite_offered, h_asks_change, ?_⟩
    rintro group rfl
    rw [readSelectedGroup?] at h_selected
    split at h_selected
    · simp at h_selected
    · obtain ⟨-, h_selected⟩ := of_ensure_bind h_selected
      obtain ⟨_, -, h_selected⟩ := exists_of_bind_eq_ok h_selected
      obtain ⟨h_retry_group, h_selected⟩ := of_ensure_bind h_selected
      exact Option.some.inj (eq_of_pure_eq_ok h_selected) ▸ h_retry_group
  · obtain ⟨_, -, h_accepted⟩ := exists_of_bind_eq_ok h_accepted
    exact ServerHelloKind.noConfusion (eq_of_pure_eq_ok h_accepted)

/--
In every build an accepted HelloRetryRequest selects no group and
carries a cookie (RFC 9846 §4.2.4, §4.3.8). Every group a build lists
already has a key share in its ClientHello (`Kex.retryGroups_eq_nil`),
so a cookie is the one change a retry can ask this client for.
-/
theorem parseServerHello_helloRetryRequest_cookie (kex : Kex) (suiteOffer : SuiteOffer)
    (pskOffered : Bool) (msg : ByteArray) (fields : HelloRetryRequest)
    (h_accepted :
      parseServerHello kex suiteOffer pskOffered msg = .ok (.helloRetryRequest fields)) :
    fields.selectedGroup = none ∧ fields.cookie.isSome := by
  obtain ⟨-, h_asks_change, h_retry_group⟩ :=
    parseServerHello_helloRetryRequest_sound kex suiteOffer pskOffered msg fields h_accepted
  have h_no_group : fields.selectedGroup = none := by
    cases h_selected : fields.selectedGroup with
    | none => rfl
    | some group =>
      have h_member := h_retry_group group h_selected
      rw [Kex.retryGroups_eq_nil] at h_member
      exact absurd h_member (List.not_mem_nil)
  refine ⟨h_no_group, ?_⟩
  rw [h_no_group] at h_asks_change
  simpa using h_asks_change

/--
The §4.2.4 discrimination, stated both ways: an accepted result is a
HelloRetryRequest exactly when the 32 octets of the message's Random
field are §4.2.4's fixed value. Nothing else in the message moves the
verdict from one kind to the other.
-/
theorem parseServerHello_random (kex : Kex) (suiteOffer : SuiteOffer) (pskOffered : Bool)
    (msg : ByteArray) (kind : ServerHelloKind)
    (h_accepted : parseServerHello kex suiteOffer pskOffered msg = .ok kind) :
    ∃ body, messageBody msg serverHelloType = .ok body ∧
      (∀ fields, kind = .helloRetryRequest fields →
        body.extract 2 34 = helloRetryRequestRandom) ∧
      (∀ fields, kind = .serverHello fields →
        body.extract 2 34 ≠ helloRetryRequestRandom) := by
  rw [parseServerHello] at h_accepted
  obtain ⟨p, h_prefix, h_accepted⟩ := exists_of_bind_eq_ok h_accepted
  obtain ⟨_, -, h_accepted⟩ := exists_of_bind_eq_ok h_accepted
  obtain ⟨body, h_framed, h_random_eq, -, -⟩ := serverHelloPrefix_sound suiteOffer msg p h_prefix
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
theorem parseEncryptedExtensions_limit_ge_64 (serverNameSent : Bool)
    (alpnOffered : List ByteArray) (certTypesOffered : List Nat) (msg : ByteArray)
    (fields : EncryptedExtensions) (limit : Nat)
    (h_accepted :
      parseEncryptedExtensions serverNameSent alpnOffered certTypesOffered msg = .ok fields)
    (h_limit : fields.recordSizeLimit = some limit) : 64 ≤ limit := by
  rw [parseEncryptedExtensions] at h_accepted
  obtain ⟨_, -, h_accepted⟩ := exists_of_bind_eq_ok h_accepted
  obtain ⟨⟨_, _⟩, -, h_accepted⟩ := exists_of_bind_eq_ok h_accepted
  obtain ⟨-, h_accepted⟩ := of_ensure_bind h_accepted
  obtain ⟨_, -, h_accepted⟩ := exists_of_bind_eq_ok h_accepted
  obtain ⟨_, -, h_accepted⟩ := exists_of_bind_eq_ok h_accepted
  obtain ⟨_, -, h_accepted⟩ := exists_of_bind_eq_ok h_accepted
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
RFC 7301 §3.2: an accepted ALPN selection names a protocol the
ClientHello offered. The client reports the selection as an index into
its own offer (`ch_tls.alpn_selected`), so the index has to be one that
list holds — a server cannot make the client read past the array it
configured.
-/
theorem parseEncryptedExtensions_alpn_offered (serverNameSent : Bool)
    (alpnOffered : List ByteArray) (certTypesOffered : List Nat) (msg : ByteArray)
    (fields : EncryptedExtensions) (i : Nat)
    (h_accepted :
      parseEncryptedExtensions serverNameSent alpnOffered certTypesOffered msg = .ok fields)
    (h_selected : fields.alpnSelected = some i) : i < alpnOffered.length := by
  rw [parseEncryptedExtensions] at h_accepted
  obtain ⟨_, -, h_accepted⟩ := exists_of_bind_eq_ok h_accepted
  obtain ⟨⟨_, _⟩, -, h_accepted⟩ := exists_of_bind_eq_ok h_accepted
  obtain ⟨-, h_accepted⟩ := of_ensure_bind h_accepted
  obtain ⟨_, -, h_accepted⟩ := exists_of_bind_eq_ok h_accepted
  obtain ⟨_, -, h_accepted⟩ := exists_of_bind_eq_ok h_accepted
  obtain ⟨_, -, h_accepted⟩ := exists_of_bind_eq_ok h_accepted
  obtain ⟨_, -, h_accepted⟩ := exists_of_bind_eq_ok h_accepted
  obtain ⟨selected, h_read, h_accepted⟩ := exists_of_bind_eq_ok h_accepted
  obtain ⟨_, -, h_accepted⟩ := exists_of_bind_eq_ok h_accepted
  obtain ⟨_, -, h_accepted⟩ := exists_of_bind_eq_ok h_accepted
  obtain rfl := eq_of_pure_eq_ok h_accepted
  have h_eq : selected = some i := h_selected
  subst h_eq
  rw [readAlpn?] at h_read
  split at h_read
  · simp at h_read
  · obtain ⟨index, h_index, h_read⟩ := exists_of_bind_eq_ok h_read
    have h_index_eq : index = i := Option.some.inj (eq_of_pure_eq_ok h_read)
    subst h_index_eq
    rw [readAlpn] at h_index
    obtain ⟨⟨_, _⟩, -, h_index⟩ := exists_of_bind_eq_ok h_index
    obtain ⟨-, h_index⟩ := of_ensure_bind h_index
    obtain ⟨⟨_, _⟩, -, h_index⟩ := exists_of_bind_eq_ok h_index
    obtain ⟨-, h_index⟩ := of_ensure_bind h_index
    obtain ⟨-, h_index⟩ := of_ensure_bind h_index
    split at h_index
    · next found =>
      exact offeredIndex?_lt_length _ _ _ (by rw [found]; exact congrArg _ (eq_of_pure_eq_ok h_index))
    · simp at h_index

/--
RFC 7250 §4.2: an accepted server_certificate_type names a type the
ClientHello offered. The client reads the Certificate message under
this type (`ch_tls.server_cert_type`), so a server cannot make it read
a raw public key it never offered to accept, or a chain it offered no
anchor for.
-/
theorem parseEncryptedExtensions_certType_offered (serverNameSent : Bool)
    (alpnOffered : List ByteArray) (certTypesOffered : List Nat) (msg : ByteArray)
    (fields : EncryptedExtensions) (certType : Nat)
    (h_accepted :
      parseEncryptedExtensions serverNameSent alpnOffered certTypesOffered msg = .ok fields)
    (h_selected : fields.serverCertType = some certType) : certType ∈ certTypesOffered := by
  rw [parseEncryptedExtensions] at h_accepted
  obtain ⟨_, -, h_accepted⟩ := exists_of_bind_eq_ok h_accepted
  obtain ⟨⟨_, _⟩, -, h_accepted⟩ := exists_of_bind_eq_ok h_accepted
  obtain ⟨-, h_accepted⟩ := of_ensure_bind h_accepted
  obtain ⟨_, -, h_accepted⟩ := exists_of_bind_eq_ok h_accepted
  obtain ⟨_, -, h_accepted⟩ := exists_of_bind_eq_ok h_accepted
  obtain ⟨_, -, h_accepted⟩ := exists_of_bind_eq_ok h_accepted
  obtain ⟨_, -, h_accepted⟩ := exists_of_bind_eq_ok h_accepted
  obtain ⟨_, -, h_accepted⟩ := exists_of_bind_eq_ok h_accepted
  obtain ⟨selected, h_read, h_accepted⟩ := exists_of_bind_eq_ok h_accepted
  obtain ⟨_, -, h_accepted⟩ := exists_of_bind_eq_ok h_accepted
  obtain rfl := eq_of_pure_eq_ok h_accepted
  have h_eq : selected = some certType := h_selected
  subst h_eq
  rw [readServerCertType?] at h_read
  split at h_read
  · simp at h_read
  · obtain ⟨read, h_value, h_read⟩ := exists_of_bind_eq_ok h_read
    have h_read_eq : read = certType := Option.some.inj (eq_of_pure_eq_ok h_read)
    rw [readServerCertType] at h_value
    obtain ⟨-, h_value⟩ := of_ensure_bind h_value
    obtain ⟨octet, -, h_value⟩ := exists_of_bind_eq_ok h_value
    obtain ⟨h_offered, h_value⟩ := of_ensure_bind h_value
    have h_octet : octet = read := eq_of_pure_eq_ok h_value
    rw [← h_read_eq, ← h_octet]
    exact h_offered

/-- Every code in `certificateVerifyCodes` is one the offer lists and none
is an RSASSA-PKCS1-v1_5 scheme: the list keeps both §4.5.2 rules. -/
private theorem certificateVerifyCodes_permitted (offer : SignatureOffer) (code : Nat)
    (h_listed : offer.certificateVerifyCodes.contains code = true) :
    offer.codes.contains code = true ∧ rsaPkcs1Schemes.contains code = false := by
  cases offer with
  | pinned scheme =>
    cases scheme <;>
      simp [SignatureOffer.certificateVerifyCodes, SignatureOffer.codes, Scheme.code,
        rsaPkcs1Schemes] at h_listed ⊢ <;> omega
  | webpki =>
    simp [SignatureOffer.certificateVerifyCodes, SignatureOffer.codes, rsaPkcs1Schemes]
      at h_listed ⊢
    omega

/--
CertificateVerify soundness (RFC 9846 §4.5.2). An accepted message
reports an algorithm the ClientHello offered, and never an
RSASSA-PKCS1-v1_5 scheme, whatever the offer listed.
-/
theorem parseCertificateVerify_sound (offer : SignatureOffer) (msg : ByteArray)
    (fields : CertificateVerify)
    (h_accepted : parseCertificateVerify offer msg = .ok fields) :
    offer.codes.contains fields.algorithm = true ∧
      rsaPkcs1Schemes.contains fields.algorithm = false := by
  rw [parseCertificateVerify] at h_accepted
  obtain ⟨_, -, h_accepted⟩ := exists_of_bind_eq_ok h_accepted
  obtain ⟨_, -, h_accepted⟩ := exists_of_bind_eq_ok h_accepted
  obtain ⟨h_listed, h_accepted⟩ := of_ensure_bind h_accepted
  obtain ⟨⟨_, _⟩, -, h_accepted⟩ := exists_of_bind_eq_ok h_accepted
  obtain ⟨-, h_accepted⟩ := of_ensure_bind h_accepted
  obtain rfl := eq_of_pure_eq_ok h_accepted
  exact certificateVerifyCodes_permitted offer _ h_listed

/--
A pinned build's CertificateVerify reports the build's own
SignatureScheme and no other code point: the one algorithm the
ClientHello offered is the one the parser admits.
-/
theorem parseCertificateVerify_pinned (scheme : Scheme) (msg : ByteArray)
    (fields : CertificateVerify)
    (h_accepted : parseCertificateVerify (.pinned scheme) msg = .ok fields) :
    fields.algorithm = scheme.code := by
  have h_offered := (parseCertificateVerify_sound (.pinned scheme) msg fields h_accepted).1
  simpa [SignatureOffer.codes] using h_offered

/--
A webpki build's CertificateVerify reports one of the three schemes a
leaf key signs with — rsa_pss_rsae_sha256, ecdsa_secp256r1_sha256 or
ecdsa_secp384r1_sha384 — so the two PKCS#1 v1.5 schemes the ClientHello
offered for certificate signatures never authenticate the handshake.
-/
theorem parseCertificateVerify_webpki (msg : ByteArray) (fields : CertificateVerify)
    (h_accepted : parseCertificateVerify .webpki msg = .ok fields) :
    fields.algorithm = 0x0804 ∨ fields.algorithm = 0x0403 ∨ fields.algorithm = 0x0503 := by
  obtain ⟨h_offered, h_not_pkcs1⟩ := parseCertificateVerify_sound .webpki msg fields h_accepted
  simp [SignatureOffer.codes, rsaPkcs1Schemes] at h_offered h_not_pkcs1
  omega

end Spec.HandshakeParser
