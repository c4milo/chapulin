/-!
TLS 1.3 handshake message ordering per RFC 8446 §4, written from the
RFC text as an executable oracle. The model tracks only the order of
server-to-client messages after the ClientHello; each message body is
assumed valid (a valid ServerHello selects our profile, a Finished
carries a good MAC, and so on — body checks are the other modules'
job). Fixed profile: at most one HelloRetryRequest round, no client
certificate, and two auth modes — PSK, where the server sends no
certificate flight, and a pinned server key, where Certificate,
CertificateVerify, and Finished are mandatory in that order.
-/
namespace Spec.Handshake

/--
Auth mode. Under `psk` the server authenticates via the pre-shared
key, so RFC 8446 §2.2 forbids the certificate flight. Under `pinned`
the server authenticates via certificate, so §4.4 makes Certificate,
CertificateVerify, and Finished mandatory, in that order.
-/
inductive Mode
  | psk
  | pinned

/--
One server-to-client message after the ClientHello, one constructor
per line-protocol letter. Order is the model; bodies are assumed
valid.
-/
inductive Msg
  | serverHello         -- S, §4.1.3
  | helloRetryRequest   -- H, §4.1.4
  | encryptedExtensions -- E, §4.3.1
  | certificate         -- C, §4.4.2
  | certificateRequest  -- R, §4.3.2
  | certificateVerify   -- V, §4.4.3
  | finished            -- F, §4.4.4
  | newSessionTicket    -- N, §4.6.1
  | keyUpdate           -- K, §4.6.3
  | appData             -- A, §5.1
  | closeNotify         -- L, §6.1

/--
Client progress through the server's flight. RFC 8446 §4 fixes the
message order and makes an out-of-order message fatal
(unexpected_message), so each state expects exactly the next legal
messages.
-/
inductive State
  | start     -- ClientHello sent; expect ServerHello or HelloRetryRequest
  | retried   -- HelloRetryRequest taken; expect the retry ServerHello
  | gotSH     -- ServerHello taken; expect EncryptedExtensions
  | awaitCert -- pinned only: expect Certificate
  | awaitCV   -- Certificate taken; expect CertificateVerify
  | awaitFin  -- expect Finished
  | connected -- handshake complete; only post-handshake traffic is legal
  | closed    -- close_notify taken; nothing more is legal

/--
Feed one message to the client. `none` is a fatal error: a handshake
message out of the §4 order, a certificate-flight message under PSK
(§2.2), a CertificateRequest (the client offers no certificate and
fails closed instead of answering §4.4.2 with an empty Certificate),
post-handshake traffic before the handshake completes (§4.6.1, §4.6.3,
§5.1), or anything after close_notify (§6.1).
-/
def step (mode : Mode) : State → Msg → Option State
  -- §4.1.3/§4.1.4: ServerHello or HelloRetryRequest answers the
  -- ClientHello.
  | .start, .serverHello => some .gotSH
  | .start, .helloRetryRequest => some .retried
  -- §4.1.4: only a ServerHello may follow a HelloRetryRequest; a second
  -- HelloRetryRequest aborts with unexpected_message.
  | .retried, .serverHello => some .gotSH
  -- §4.3.1: EncryptedExtensions comes immediately after the ServerHello.
  -- §2.2: under PSK the server sends no certificate flight, so Finished
  -- is next; §4.4.2 puts Certificate next in pinned mode.
  | .gotSH, .encryptedExtensions =>
    some (match mode with | .psk => .awaitFin | .pinned => .awaitCert)
  | .awaitCert, .certificate => some .awaitCV
  -- §4.4.3: CertificateVerify comes immediately after Certificate.
  | .awaitCV, .certificateVerify => some .awaitFin
  -- §4.4.4: Finished ends the server's flight; §4.4.4 also makes it the
  -- gate for application data, so this is where the client connects.
  | .awaitFin, .finished => some .connected
  -- §4.6.1/§4.6.3/§5.1: tickets, key updates, and application data are
  -- legal only after the handshake completes.
  | .connected, .newSessionTicket => some .connected
  | .connected, .keyUpdate => some .connected
  | .connected, .appData => some .connected
  -- §6.1: close_notify ends the connection.
  | .connected, .closeNotify => some .closed
  | _, _ => none

/--
Run a whole sequence from the fresh-ClientHello state. Accept iff
every message is legal in order and the client completes the handshake
(§4.4.4), optionally followed by a clean close. An error-free but
unfinished prefix rejects: the client never connected.
-/
def accepts (mode : Mode) (msgs : List Msg) : Bool :=
  match msgs.foldlM (step mode) State.start with
  | some .connected | some .closed => true
  | _ => false

/-- Line-protocol letter for one message. -/
def msgOfChar? : Char → Option Msg
  | 'S' => some .serverHello
  | 'H' => some .helloRetryRequest
  | 'E' => some .encryptedExtensions
  | 'C' => some .certificate
  | 'R' => some .certificateRequest
  | 'V' => some .certificateVerify
  | 'F' => some .finished
  | 'N' => some .newSessionTicket
  | 'K' => some .keyUpdate
  | 'A' => some .appData
  | 'L' => some .closeNotify
  | _ => none

/-- Parse a letter string; `none` on any letter outside the alphabet. -/
def seq? (s : String) : Option (List Msg) :=
  s.toList.mapM msgOfChar?

/--
Hand-checked orderings. The accepting rows are the legal §4 shapes for
each mode — with and without a HelloRetryRequest round and with
post-handshake tails. Each rejecting row cites the RFC text it
violates.
-/
def selftest : Bool :=
  let check := fun ((mode, letters, want) : Mode × String × Bool) =>
    match seq? letters with
    | some msgs => accepts mode msgs == want
    | none => false
  let vectors : List (Mode × String × Bool) := [
    -- Legal shapes: §2.2 PSK flight, §4.4 certificate flight, one
    -- §4.1.4 retry round, §4.6/§5.1/§6.1 tails.
    (.psk, "SEF", true),
    (.psk, "HSEF", true),
    (.psk, "SEFL", true),
    (.psk, "SEFNKA", true),
    (.psk, "HSEFNKAL", true),
    (.pinned, "SECVF", true),
    (.pinned, "HSECVF", true),
    (.pinned, "SECVFA", true),
    (.pinned, "HSECVFNKAL", true),
    -- §4.4.4: no Finished, so the handshake never completes; error-free
    -- prefixes reject too.
    (.pinned, "SECV", false),
    (.psk, "SE", false),
    (.psk, "H", false),
    -- §2.2: under PSK the server MUST NOT send the certificate flight.
    (.psk, "SECVF", false),
    (.psk, "SEVF", false),
    -- §4.3.2: the client offers no certificate; the profile treats a
    -- CertificateRequest as fatal.
    (.pinned, "SERCVF", false),
    -- §4.1.4: a second HelloRetryRequest aborts with unexpected_message.
    (.psk, "HHSEF", false),
    (.pinned, "HHSECVF", false),
    -- §4.6.1/§4.6.3/§5.1: no tickets, key updates, or application data
    -- before the handshake completes.
    (.psk, "NSEF", false),
    (.psk, "SENF", false),
    (.psk, "SEKF", false),
    (.psk, "SEAF", false),
    (.pinned, "SECVAF", false),
    -- §4.4.3: CertificateVerify comes immediately after Certificate.
    (.pinned, "SEVCF", false),
    -- §4.3.1: EncryptedExtensions comes immediately after the ServerHello.
    (.psk, "SF", false),
    (.pinned, "SCVF", false),
    -- §4: a handshake message out of order is fatal; a second
    -- ServerHello after completion is out of order.
    (.psk, "SEFS", false),
    -- §6.1: close_notify before completion kills the connection short of
    -- connected; nothing may follow a close_notify.
    (.psk, "SEL", false),
    (.psk, "SEFLA", false)]
  vectors.all check

end Spec.Handshake
