/-!
TLS 1.3 handshake message ordering per RFC 9846 §4, written from the
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
key, so RFC 9846 §2.2 forbids the certificate flight. Under `pinned`
the server authenticates via certificate, so §4.5 makes Certificate,
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
  | serverHello         -- S, §4.2.3
  | helloRetryRequest   -- H, §4.2.4
  | encryptedExtensions -- E, §4.4.1
  | certificate         -- C, §4.5.1
  | certificateRequest  -- R, §4.4.2
  | certificateVerify   -- V, §4.5.2
  | finished            -- F, §4.5.3
  | newSessionTicket    -- N, §4.7.1
  | keyUpdate           -- K, §4.7.3
  | appData             -- A, §5.1
  | closeNotify         -- L, §6.1

/--
Client progress through the server's flight. RFC 9846 §4 fixes the
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
fails closed instead of answering §4.5.1 with an empty Certificate),
post-handshake traffic before the handshake completes (§4.7.1, §4.7.3,
§5.1), or anything after close_notify (§6.1).
-/
def step (mode : Mode) : State → Msg → Option State
  -- §4.2.3/§4.2.4: ServerHello or HelloRetryRequest answers the
  -- ClientHello.
  | .start, .serverHello => some .gotSH
  | .start, .helloRetryRequest => some .retried
  -- §4.2.4: only a ServerHello may follow a HelloRetryRequest; a second
  -- HelloRetryRequest aborts with unexpected_message.
  | .retried, .serverHello => some .gotSH
  -- §4.4.1: EncryptedExtensions comes immediately after the ServerHello.
  -- §2.2: under PSK the server sends no certificate flight, so Finished
  -- is next; §4.5.1 puts Certificate next in pinned mode.
  | .gotSH, .encryptedExtensions =>
    some (match mode with | .psk => .awaitFin | .pinned => .awaitCert)
  | .awaitCert, .certificate => some .awaitCV
  -- §4.5.2: CertificateVerify comes immediately after Certificate.
  | .awaitCV, .certificateVerify => some .awaitFin
  -- §4.5.3: Finished ends the server's flight; §4.5.3 also makes it the
  -- gate for application data, so this is where the client connects.
  | .awaitFin, .finished => some .connected
  -- §4.7.1/§4.7.3/§5.1: tickets, key updates, and application data are
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
(§4.5.3), optionally followed by a clean close. An error-free but
unfinished prefix rejects: the client never connected.
-/
def accepts (mode : Mode) (msgs : List Msg) : Bool :=
  match msgs.foldlM (step mode) State.start with
  | some .connected | some .closed => true
  | _ => false

/-!
Proven safety invariants. Each one quantifies over every trace, so the
differential run's agreement with the C state machine transfers a
theorem, not a sample: an accepting C trace (over the compared domain)
has exactly one Finished, no Certificate under PSK, exactly one
Certificate then CertificateVerify then Finished under a pinned key,
and at most one HelloRetryRequest.
-/

deriving instance DecidableEq for Msg
deriving instance DecidableEq for State

/-- `accepts` in terms of the fold it runs. -/
private theorem accepts_iff (mode : Mode) (msgs : List Msg) :
    accepts mode msgs = true ↔
      ∃ t, msgs.foldlM (step mode) State.start = some t ∧
        (t = State.connected ∨ t = State.closed) := by
  unfold accepts
  cases h : msgs.foldlM (step mode) State.start with
  | none => simp
  | some t => cases t <;> simp

/-- Walk a per-step exact count through a whole successful fold. -/
private theorem foldlM_count (mode : Mode) (cnt : State → Nat) (tgt : Msg)
    (hstep : ∀ s s' m, step mode s m = some s' →
      cnt s' = cnt s + (if m = tgt then 1 else 0)) :
    ∀ (msgs : List Msg) (s t : State), msgs.foldlM (step mode) s = some t →
      cnt t = cnt s + msgs.count tgt := by
  intro msgs
  induction msgs with
  | nil =>
    intro s t h
    simp only [List.foldlM_nil] at h
    cases h
    simp
  | cons x xs ih =>
    intro s t h
    simp only [List.foldlM_cons] at h
    cases hx : step mode s x with
    | none => rw [hx] at h; simp at h
    | some s1 =>
      rw [hx] at h
      simp at h
      rw [ih s1 t h, hstep s s1 x hx, List.count_cons]
      simp only [beq_iff_eq]
      omega

/-- Walk a per-step count bound through a whole successful fold. -/
private theorem foldlM_count_le (mode : Mode) (bnd : State → Nat) (tgt : Msg)
    (hstep : ∀ s s' m, step mode s m = some s' →
      bnd s + (if m = tgt then 1 else 0) ≤ bnd s') :
    ∀ (msgs : List Msg) (s t : State), msgs.foldlM (step mode) s = some t →
      msgs.count tgt + bnd s ≤ bnd t := by
  intro msgs
  induction msgs with
  | nil =>
    intro s t h
    simp only [List.foldlM_nil] at h
    cases h
    simp
  | cons x xs ih =>
    intro s t h
    simp only [List.foldlM_cons] at h
    cases hx : step mode s x with
    | none => rw [hx] at h; simp at h
    | some s1 =>
      rw [hx] at h
      simp at h
      have h1 := ih s1 t h
      have h2 := hstep s s1 x hx
      rw [List.count_cons]
      simp only [beq_iff_eq] at *
      omega

/-- 1 once the server's Finished was taken, else 0. -/
private def finSeen : State → Nat
  | .connected | .closed => 1
  | _ => 0

private theorem step_finSeen (mode : Mode) (s s' : State) (m : Msg)
    (h : step mode s m = some s') :
    finSeen s' = finSeen s + (if m = Msg.finished then 1 else 0) := by
  cases mode <;> cases s <;> cases m <;> simp [step] at h <;> cases h <;>
    simp [finSeen]

/-- Every accepting trace contains the server Finished exactly once
(RFC 9846 §4.5.3: it ends the server's flight and gates the
connection). -/
theorem count_finished_of_accepts (mode : Mode) (msgs : List Msg)
    (h : accepts mode msgs = true) : msgs.count .finished = 1 := by
  obtain ⟨t, hfold, ht⟩ := (accepts_iff mode msgs).mp h
  have := foldlM_count mode finSeen .finished (step_finSeen mode) msgs .start t hfold
  rcases ht with rfl | rfl <;> (simp [finSeen] at this; omega)

/-- No accepting trace omits the server Finished. -/
theorem finished_mem_of_accepts (mode : Mode) (msgs : List Msg)
    (h : accepts mode msgs = true) : Msg.finished ∈ msgs := by
  have := count_finished_of_accepts mode msgs h
  exact List.count_pos_iff.mp (by omega)

/-- Under PSK the certificate-flight states are unreachable, so a
successful step never consumes a Certificate (RFC 9846 §2.2). -/
private theorem step_psk_no_cert (s s' : State) (m : Msg)
    (hs : s ≠ State.awaitCert ∧ s ≠ State.awaitCV)
    (h : step Mode.psk s m = some s') :
    (s' ≠ State.awaitCert ∧ s' ≠ State.awaitCV) ∧ m ≠ Msg.certificate := by
  cases s <;> cases m <;> simp [step] at h <;> cases h <;> simp_all

/-- PSK-mode error-free traces never contain Certificate (§2.2: the
server MUST NOT send the certificate flight when authenticating by
PSK). Stated over any successful fold, so it covers accepting traces
and every prefix of them. -/
private theorem foldlM_psk_no_cert :
    ∀ (msgs : List Msg) (s t : State),
      (s ≠ State.awaitCert ∧ s ≠ State.awaitCV) →
      msgs.foldlM (step Mode.psk) s = some t →
      Msg.certificate ∉ msgs := by
  intro msgs
  induction msgs with
  | nil => simp
  | cons x xs ih =>
    intro s t hs h
    simp only [List.foldlM_cons] at h
    cases hx : step Mode.psk s x with
    | none => rw [hx] at h; simp at h
    | some s1 =>
      rw [hx] at h
      simp at h
      have ⟨hs1, hxc⟩ := step_psk_no_cert s s1 x hs hx
      simp only [List.mem_cons, not_or]
      exact ⟨fun he => hxc he.symm, ih s1 t hs1 h⟩

/-- PSK-mode accepting traces never contain Certificate. -/
theorem psk_no_certificate (msgs : List Msg) (h : accepts .psk msgs = true) :
    Msg.certificate ∉ msgs := by
  obtain ⟨t, hfold, _⟩ := (accepts_iff .psk msgs).mp h
  exact foldlM_psk_no_cert msgs .start t (by simp) hfold

/-- 1 once the pinned-mode flight passed Certificate, else 0. -/
private def certSeen : State → Nat
  | .awaitCV | .awaitFin | .connected | .closed => 1
  | _ => 0

private theorem step_certSeen (s s' : State) (m : Msg)
    (h : step Mode.pinned s m = some s') :
    certSeen s' = certSeen s + (if m = Msg.certificate then 1 else 0) := by
  cases s <;> cases m <;> simp [step] at h <;> cases h <;> simp [certSeen]

/-- 1 once the pinned-mode flight passed CertificateVerify, else 0. -/
private def cvSeen : State → Nat
  | .awaitFin | .connected | .closed => 1
  | _ => 0

private theorem step_cvSeen (s s' : State) (m : Msg)
    (h : step Mode.pinned s m = some s') :
    cvSeen s' = cvSeen s + (if m = Msg.certificateVerify then 1 else 0) := by
  cases s <;> cases m <;> simp [step] at h <;> cases h <;> simp [cvSeen]

/-- Pinned-mode accepting traces contain exactly one Certificate
(RFC 9846 §4.5.1). -/
theorem pinned_one_certificate (msgs : List Msg)
    (h : accepts .pinned msgs = true) : msgs.count .certificate = 1 := by
  obtain ⟨t, hfold, ht⟩ := (accepts_iff .pinned msgs).mp h
  have := foldlM_count .pinned certSeen .certificate step_certSeen msgs .start t hfold
  rcases ht with rfl | rfl <;> (simp [certSeen] at this; omega)

/-- Pinned-mode accepting traces contain exactly one CertificateVerify
(RFC 9846 §4.5.2). -/
theorem pinned_one_certificateVerify (msgs : List Msg)
    (h : accepts .pinned msgs = true) : msgs.count .certificateVerify = 1 := by
  obtain ⟨t, hfold, ht⟩ := (accepts_iff .pinned msgs).mp h
  have := foldlM_count .pinned cvSeen .certificateVerify step_cvSeen msgs .start t hfold
  rcases ht with rfl | rfl <;> (simp [cvSeen] at this; omega)

/--
Pinned-mode message order (RFC 9846 §4.5): in an accepting trace, every
prefix that contains CertificateVerify already contains Certificate,
and every prefix that contains Finished already contains
CertificateVerify. With the three counts pinned to one, this places the
unique Certificate before the unique CertificateVerify before the
unique Finished.
-/
theorem pinned_cert_order (msgs : List Msg) (h : accepts .pinned msgs = true)
    (l r : List Msg) (hsplit : msgs = l ++ r) :
    (Msg.certificateVerify ∈ l → Msg.certificate ∈ l) ∧
    (Msg.finished ∈ l → Msg.certificateVerify ∈ l) := by
  obtain ⟨t, hfold, _⟩ := (accepts_iff .pinned msgs).mp h
  rw [hsplit, List.foldlM_append] at hfold
  cases hs : l.foldlM (step .pinned) State.start with
  | none => rw [hs] at hfold; simp at hfold
  | some s =>
    have hc := foldlM_count .pinned certSeen .certificate step_certSeen l .start s hs
    have hv := foldlM_count .pinned cvSeen .certificateVerify step_cvSeen l .start s hs
    have hf := foldlM_count .pinned finSeen .finished (step_finSeen .pinned) l .start s hs
    refine ⟨fun hmem => ?_, fun hmem => ?_⟩
    · have hvpos : 0 < l.count Msg.certificateVerify := List.count_pos_iff.mpr hmem
      refine List.count_pos_iff.mp ?_
      cases s <;> simp [certSeen, cvSeen] at hc hv <;> omega
    · have hfpos : 0 < l.count Msg.finished := List.count_pos_iff.mpr hmem
      refine List.count_pos_iff.mp ?_
      cases s <;> simp [cvSeen, finSeen] at hv hf <;> omega

/-- 0 HelloRetryRequests consumed at `start`, at most 1 anywhere else. -/
private def hrrBound : State → Nat
  | .start => 0
  | _ => 1

private theorem step_hrrBound (mode : Mode) (s s' : State) (m : Msg)
    (h : step mode s m = some s') :
    hrrBound s + (if m = Msg.helloRetryRequest then 1 else 0) ≤ hrrBound s' := by
  cases mode <;> cases s <;> cases m <;> simp [step] at h <;> cases h <;>
    simp [hrrBound]

/-- No accepting trace contains two HelloRetryRequests (RFC 9846
§4.2.4: a second HelloRetryRequest aborts the handshake). -/
theorem hrr_at_most_one (mode : Mode) (msgs : List Msg)
    (h : accepts mode msgs = true) : msgs.count .helloRetryRequest ≤ 1 := by
  obtain ⟨t, hfold, ht⟩ := (accepts_iff mode msgs).mp h
  have := foldlM_count_le mode hrrBound .helloRetryRequest (step_hrrBound mode)
    msgs .start t hfold
  rcases ht with rfl | rfl <;> (simp [hrrBound] at this; omega)

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
    -- Legal shapes: §2.2 PSK flight, §4.5 certificate flight, one
    -- §4.2.4 retry round, §4.7/§5.1/§6.1 tails.
    (.psk, "SEF", true),
    (.psk, "HSEF", true),
    (.psk, "SEFL", true),
    (.psk, "SEFNKA", true),
    (.psk, "HSEFNKAL", true),
    (.pinned, "SECVF", true),
    (.pinned, "HSECVF", true),
    (.pinned, "SECVFA", true),
    (.pinned, "HSECVFNKAL", true),
    -- §4.5.3: no Finished, so the handshake never completes; error-free
    -- prefixes reject too.
    (.pinned, "SECV", false),
    (.psk, "SE", false),
    (.psk, "H", false),
    -- §2.2: under PSK the server MUST NOT send the certificate flight.
    (.psk, "SECVF", false),
    (.psk, "SEVF", false),
    -- §4.4.2: the client offers no certificate; the profile treats a
    -- CertificateRequest as fatal.
    (.pinned, "SERCVF", false),
    -- §4.2.4: a second HelloRetryRequest aborts with unexpected_message.
    (.psk, "HHSEF", false),
    (.pinned, "HHSECVF", false),
    -- §4.7.1/§4.7.3/§5.1: no tickets, key updates, or application data
    -- before the handshake completes.
    (.psk, "NSEF", false),
    (.psk, "SENF", false),
    (.psk, "SEKF", false),
    (.psk, "SEAF", false),
    (.pinned, "SECVAF", false),
    -- §4.5.2: CertificateVerify comes immediately after Certificate.
    (.pinned, "SEVCF", false),
    -- §4.4.1: EncryptedExtensions comes immediately after the ServerHello.
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
