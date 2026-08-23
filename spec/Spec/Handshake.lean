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
    cases h_head_step : step mode s x with
    | none => rw [h_head_step] at h; simp at h
    | some s1 =>
      rw [h_head_step] at h
      simp at h
      rw [ih s1 t h, hstep s s1 x h_head_step, List.count_cons]
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
    cases h_head_step : step mode s x with
    | none => rw [h_head_step] at h; simp at h
    | some s1 =>
      rw [h_head_step] at h
      simp at h
      have h_tail_le := ih s1 t h
      have h_head_le := hstep s s1 x h_head_step
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
    cases h_head_step : step Mode.psk s x with
    | none => rw [h_head_step] at h; simp at h
    | some s1 =>
      rw [h_head_step] at h
      simp at h
      have ⟨hs1, hxc⟩ := step_psk_no_cert s s1 x hs h_head_step
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

/--
True for the three messages RFC 9846 allows only after the handshake
completes: NewSessionTicket (§4.7.1), KeyUpdate (§4.7.3), and
application data (§5.1).
-/
def isPostHandshake : Msg → Bool
  | .newSessionTicket | .keyUpdate | .appData => true
  | _ => false

/-- A post-handshake message steps only from `connected`, the state the
client reaches by taking the Finished. -/
private theorem step_postHandshake (mode : Mode) (s s' : State) (m : Msg)
    (hph : isPostHandshake m = true) (h : step mode s m = some s') :
    finSeen s = 1 := by
  cases mode <;> cases m <;> simp [isPostHandshake] at hph <;>
    cases s <;> simp [step] at h <;> simp [finSeen]

/-- A successful fold that starts before the Finished and takes no
Finished takes no post-handshake message either. -/
private theorem foldlM_no_post_handshake (mode : Mode) :
    ∀ (msgs : List Msg) (s t : State), finSeen s = 0 →
      msgs.foldlM (step mode) s = some t → Msg.finished ∉ msgs →
      ∀ m ∈ msgs, isPostHandshake m = false := by
  intro msgs
  induction msgs with
  | nil => simp
  | cons x xs ih =>
    intro s t hs h hfin
    simp only [List.foldlM_cons] at h
    cases h_head_step : step mode s x with
    | none => rw [h_head_step] at h; simp at h
    | some s1 =>
      rw [h_head_step] at h
      simp at h
      simp only [List.mem_cons, not_or] at hfin
      have hxf : x ≠ Msg.finished := fun he => hfin.1 he.symm
      have hs1 : finSeen s1 = 0 := by
        have h_fin_step := step_finSeen mode s s1 x h_head_step
        rw [hs, if_neg hxf] at h_fin_step
        simpa using h_fin_step
      intro m hm
      rcases List.mem_cons.mp hm with rfl | hm
      · cases hpm : isPostHandshake m with
        | false => rfl
        | true =>
          have := step_postHandshake mode s s1 m hpm h_head_step
          omega
      · exact ih s1 t hs1 h hfin.2 m hm

/--
No post-handshake message appears before the server Finished (RFC 9846
§4.7.1, §4.7.3, and §5.1 make tickets, key updates, and application
data legal only once the handshake completes). In an accepting trace,
every prefix that contains a NewSessionTicket, a KeyUpdate, or
application data already contains the Finished.
-/
theorem no_post_handshake_before_finished (mode : Mode) (msgs : List Msg)
    (h : accepts mode msgs = true) (l r : List Msg) (hsplit : msgs = l ++ r)
    (m : Msg) (hph : isPostHandshake m = true) (hmem : m ∈ l) :
    Msg.finished ∈ l := by
  obtain ⟨t, hfold, _⟩ := (accepts_iff mode msgs).mp h
  rw [hsplit, List.foldlM_append] at hfold
  cases hs : l.foldlM (step mode) State.start with
  | none => rw [hs] at hfold; simp at hfold
  | some s =>
    cases Decidable.em (Msg.finished ∈ l) with
    | inl hfin => exact hfin
    | inr hfin =>
      have := foldlM_no_post_handshake mode l .start s rfl hs hfin m hmem
      simp [this] at hph

/-- Under PSK the certificate-flight states are unreachable, so a
successful step never consumes a CertificateVerify (RFC 9846 §2.2). -/
private theorem step_psk_no_cv (s s' : State) (m : Msg)
    (hs : s ≠ State.awaitCert ∧ s ≠ State.awaitCV)
    (h : step Mode.psk s m = some s') :
    (s' ≠ State.awaitCert ∧ s' ≠ State.awaitCV) ∧ m ≠ Msg.certificateVerify := by
  cases s <;> cases m <;> simp [step] at h <;> cases h <;> simp_all

/-- PSK-mode error-free traces never contain CertificateVerify (§2.2:
the server MUST NOT send the certificate flight when authenticating by
PSK). Stated over any successful fold, so it covers accepting traces
and every prefix of them. -/
private theorem foldlM_psk_no_cv :
    ∀ (msgs : List Msg) (s t : State),
      (s ≠ State.awaitCert ∧ s ≠ State.awaitCV) →
      msgs.foldlM (step Mode.psk) s = some t →
      Msg.certificateVerify ∉ msgs := by
  intro msgs
  induction msgs with
  | nil => simp
  | cons x xs ih =>
    intro s t hs h
    simp only [List.foldlM_cons] at h
    cases h_head_step : step Mode.psk s x with
    | none => rw [h_head_step] at h; simp at h
    | some s1 =>
      rw [h_head_step] at h
      simp at h
      have ⟨hs1, hxc⟩ := step_psk_no_cv s s1 x hs h_head_step
      simp only [List.mem_cons, not_or]
      exact ⟨fun he => hxc he.symm, ih s1 t hs1 h⟩

/-- PSK-mode accepting traces never contain CertificateVerify. -/
theorem psk_no_certificateVerify (msgs : List Msg) (h : accepts .psk msgs = true) :
    Msg.certificateVerify ∉ msgs := by
  obtain ⟨t, hfold, _⟩ := (accepts_iff .psk msgs).mp h
  exact foldlM_psk_no_cv msgs .start t (by simp) hfold

/-- CertificateRequests consumed so far. `step` rejects that message in
every state, so this stays 0 in every reachable state. -/
private def certReqSeen : State → Nat
  | _ => 0

private theorem step_certReqSeen (mode : Mode) (s s' : State) (m : Msg)
    (h : step mode s m = some s') :
    certReqSeen s' = certReqSeen s + (if m = Msg.certificateRequest then 1 else 0) := by
  cases mode <;> cases s <;> cases m <;> simp [step] at h <;> cases h <;>
    simp [certReqSeen]

/-- No accepting trace contains a CertificateRequest (RFC 9846 §4.4.2).
The client offers no certificate, so it fails closed instead of
answering with an empty Certificate: `step` returns `none` for
CertificateRequest in every state and both modes. -/
theorem no_certificateRequest_of_accepts (mode : Mode) (msgs : List Msg)
    (h : accepts mode msgs = true) : msgs.count .certificateRequest = 0 := by
  obtain ⟨t, hfold, ht⟩ := (accepts_iff mode msgs).mp h
  have := foldlM_count mode certReqSeen .certificateRequest (step_certReqSeen mode)
    msgs .start t hfold
  rcases ht with rfl | rfl <;> (simp [certReqSeen] at this; omega)

/-- 1 once EncryptedExtensions was taken, else 0. -/
private def eeSeen : State → Nat
  | .start | .retried | .gotSH => 0
  | _ => 1

private theorem step_eeSeen (mode : Mode) (s s' : State) (m : Msg)
    (h : step mode s m = some s') :
    eeSeen s' = eeSeen s + (if m = Msg.encryptedExtensions then 1 else 0) := by
  cases mode <;> cases s <;> cases m <;> simp [step] at h <;> cases h <;>
    simp [eeSeen]

/-- Every accepting trace contains EncryptedExtensions exactly once
(RFC 9846 §4.4.1: it follows the ServerHello immediately, and the
handshake carries no second one). -/
theorem count_encryptedExtensions_of_accepts (mode : Mode) (msgs : List Msg)
    (h : accepts mode msgs = true) : msgs.count .encryptedExtensions = 1 := by
  obtain ⟨t, hfold, ht⟩ := (accepts_iff mode msgs).mp h
  have := foldlM_count mode eeSeen .encryptedExtensions (step_eeSeen mode)
    msgs .start t hfold
  rcases ht with rfl | rfl <;> (simp [eeSeen] at this; omega)

/-- 1 once a ServerHello was taken, else 0. A HelloRetryRequest moves
`start` to `retried`, which still counts 0, so the retry round does not
change the total. -/
private def shSeen : State → Nat
  | .start | .retried => 0
  | _ => 1

private theorem step_shSeen (mode : Mode) (s s' : State) (m : Msg)
    (h : step mode s m = some s') :
    shSeen s' = shSeen s + (if m = Msg.serverHello then 1 else 0) := by
  cases mode <;> cases s <;> cases m <;> simp [step] at h <;> cases h <;>
    simp [shSeen]

/-- Every accepting trace contains exactly one ServerHello (RFC 9846
§4.2.3). The count is one whether or not the server sent a
HelloRetryRequest: §4.2.4 lets the retry round precede the ServerHello,
never replace it. -/
theorem count_serverHello_of_accepts (mode : Mode) (msgs : List Msg)
    (h : accepts mode msgs = true) : msgs.count .serverHello = 1 := by
  obtain ⟨t, hfold, ht⟩ := (accepts_iff mode msgs).mp h
  have := foldlM_count mode shSeen .serverHello (step_shSeen mode) msgs .start t hfold
  rcases ht with rfl | rfl <;> (simp [shSeen] at this; omega)

/-- 1 once close_notify was taken, else 0. -/
private def closeSeen : State → Nat
  | .closed => 1
  | _ => 0

private theorem step_closeSeen (mode : Mode) (s s' : State) (m : Msg)
    (h : step mode s m = some s') :
    closeSeen s' = closeSeen s + (if m = Msg.closeNotify then 1 else 0) := by
  cases mode <;> cases s <;> cases m <;> simp [step] at h <;> cases h <;>
    simp [closeSeen]

/-- No accepting trace contains two close_notify messages (RFC 9846
§6.1: close_notify moves the client to the closed state, where every
message is fatal). -/
theorem closeNotify_at_most_one (mode : Mode) (msgs : List Msg)
    (h : accepts mode msgs = true) : msgs.count .closeNotify ≤ 1 := by
  obtain ⟨t, hfold, ht⟩ := (accepts_iff mode msgs).mp h
  have := foldlM_count mode closeSeen .closeNotify (step_closeSeen mode)
    msgs .start t hfold
  rcases ht with rfl | rfl <;> (simp [closeSeen] at this; omega)

/-- Every message is fatal in the closed state (RFC 9846 §6.1). -/
private theorem step_closed_none (mode : Mode) (m : Msg) :
    step mode State.closed m = none := by
  cases mode <;> cases m <;> rfl

/-- An error-free run that starts closed takes no message. -/
private theorem foldlM_closed_nil (mode : Mode) :
    ∀ (msgs : List Msg) (t : State),
      msgs.foldlM (step mode) State.closed = some t → msgs = [] := by
  intro msgs t h
  cases msgs with
  | nil => rfl
  | cons x xs => simp [List.foldlM_cons, step_closed_none] at h

/--
close_notify comes last (RFC 9846 §6.1: it ends the connection, and
every message after it is fatal). In an accepting trace split as
`l ++ r`, if `l` contains close_notify then `r` is empty. Together with
`closeNotify_at_most_one` this puts the one close_notify an accepting
trace may carry at the end of the trace.
-/
theorem closeNotify_last (mode : Mode) (msgs : List Msg)
    (h : accepts mode msgs = true) (l r : List Msg) (hsplit : msgs = l ++ r)
    (hmem : Msg.closeNotify ∈ l) : r = [] := by
  obtain ⟨t, hfold, _⟩ := (accepts_iff mode msgs).mp h
  rw [hsplit, List.foldlM_append] at hfold
  cases hs : l.foldlM (step mode) State.start with
  | none => rw [hs] at hfold; simp at hfold
  | some s =>
    rw [hs] at hfold
    have hc := foldlM_count mode closeSeen .closeNotify (step_closeSeen mode)
      l .start s hs
    have hpos : 0 < l.count Msg.closeNotify := List.count_pos_iff.mpr hmem
    have hsc : s = State.closed := by
      cases s <;> simp [closeSeen] at hc ⊢ <;> omega
    subst hsc
    exact foldlM_closed_nil mode r t hfold

/--
A post-handshake message keeps the client connected (RFC 9846 §4.7.1,
§4.7.3, §5.1: tickets, key updates, and application data carry no state
change beyond their own effect), so a whole run of them leaves the
state at `connected`.
-/
theorem connected_stable (mode : Mode) (post : List Msg)
    (h : ∀ x ∈ post, isPostHandshake x = true) :
    post.foldlM (step mode) State.connected = some State.connected := by
  revert h
  induction post with
  | nil => intro _; rfl
  | cons x xs ih =>
    intro h
    have h_head_post : isPostHandshake x = true := h x (by simp)
    have hstep : step mode State.connected x = some State.connected := by
      cases x <;> simp [isPostHandshake] at h_head_post <;> rfl
    rw [List.foldlM_cons, hstep]
    simpa using ih (fun y h_mem => h y (by simp [h_mem]))

/-- Longest flight, in messages, that reaches `connected`: four under
PSK (HelloRetryRequest, ServerHello, EncryptedExtensions, Finished) and
six under a pinned key, which adds Certificate and CertificateVerify
(RFC 9846 §2.2, §4.2.4, §4.5). -/
def flightBound : Mode → Nat
  | .psk => 4
  | .pinned => 6

/-- Messages taken to arrive at a state, at most. `start` is the
fresh-ClientHello state, so it costs nothing; each further state costs
one more message than the state before it in the §4 order. -/
private def flightRank : Mode → State → Nat
  | _, .start => 0
  | _, .retried => 1
  | _, .gotSH => 2
  | .psk, .awaitCert => 1
  | .psk, .awaitCV => 2
  | .psk, .awaitFin => 3
  | .psk, .connected => 4
  | .psk, .closed => 5
  | .pinned, .awaitCert => 3
  | .pinned, .awaitCV => 4
  | .pinned, .awaitFin => 5
  | .pinned, .connected => 6
  | .pinned, .closed => 7

/-- Every step before the handshake completes costs at least one rank,
so the rank counts the messages spent so far. The `connected` state is
the exception: §4.7 traffic returns to it without advancing. -/
private theorem step_flightRank (mode : Mode) (s s' : State) (m : Msg)
    (hs : s ≠ State.connected) (h : step mode s m = some s') :
    flightRank mode s + 1 ≤ flightRank mode s' := by
  cases mode <;> cases s <;> simp at hs <;> cases m <;> simp [step] at h <;>
    cases h <;> simp [flightRank]

/-- Only close_notify from `connected` reaches the closed state
(RFC 9846 §6.1). -/
private theorem step_closed_source (mode : Mode) (s : State) (m : Msg)
    (h : step mode s m = some State.closed) : s = State.connected := by
  cases mode <;> cases s <;> cases m <;> simp [step] at h <;> rfl

/-- From `connected` a successful step either takes a post-handshake
message and stays, or takes close_notify and closes (RFC 9846 §4.7,
§5.1, §6.1). -/
private theorem step_connected_cases (mode : Mode) (m : Msg) (s' : State)
    (h : step mode State.connected m = some s') :
    (isPostHandshake m = true ∧ s' = State.connected) ∨
      (m = Msg.closeNotify ∧ s' = State.closed) := by
  cases mode <;> cases m <;> simp [step] at h <;> cases h <;>
    simp [isPostHandshake]

/-- An error-free run that starts connected is post-handshake traffic
followed by at most one close_notify. -/
private theorem foldlM_from_connected (mode : Mode) :
    ∀ (msgs : List Msg) (t : State),
      msgs.foldlM (step mode) State.connected = some t →
      ∃ ph tail, msgs = ph ++ tail ∧ (∀ x ∈ ph, isPostHandshake x = true) ∧
        (tail = [] ∨ tail = [Msg.closeNotify]) := by
  intro msgs
  induction msgs with
  | nil => intro _ _; exact ⟨[], [], rfl, by simp, Or.inl rfl⟩
  | cons x xs ih =>
    intro t h
    simp only [List.foldlM_cons] at h
    cases h_head_step : step mode State.connected x with
    | none => rw [h_head_step] at h; simp at h
    | some s1 =>
      rw [h_head_step] at h
      simp at h
      rcases step_connected_cases mode x s1 h_head_step with ⟨hph, rfl⟩ | ⟨rfl, rfl⟩
      · obtain ⟨ph, tail, hsplit, hph', htail⟩ := ih t h
        refine ⟨x :: ph, tail, by rw [hsplit]; rfl, ?_, htail⟩
        intro y h_mem
        rcases List.mem_cons.mp h_mem with rfl | h_mem
        · exact hph
        · exact hph' y h_mem
      · have hnil : xs = [] := foldlM_closed_nil mode xs t h
        subst hnil
        exact ⟨[], [Msg.closeNotify], rfl, by simp, Or.inr rfl⟩

/-- Every error-free run that ends connected or closed splits at the
point the client connects: a flight that reaches `connected`, bounded
in length by the rank it climbs, and a remainder. -/
private theorem foldlM_flight (mode : Mode) :
    ∀ (msgs : List Msg) (s t : State), s ≠ State.closed →
      msgs.foldlM (step mode) s = some t →
      (t = State.connected ∨ t = State.closed) →
      ∃ pre rest, msgs = pre ++ rest ∧
        pre.foldlM (step mode) s = some State.connected ∧
        flightRank mode s + pre.length ≤ flightRank mode State.connected := by
  intro msgs
  induction msgs with
  | nil =>
    intro s t hs h ht
    simp only [List.foldlM_nil] at h
    cases h
    rcases ht with rfl | rfl
    · exact ⟨[], [], rfl, rfl, by simp⟩
    · exact absurd rfl hs
  | cons x xs ih =>
    intro s t hs h ht
    cases Decidable.em (s = State.connected) with
    | inl hc =>
      subst hc
      exact ⟨[], x :: xs, rfl, rfl, by simp⟩
    | inr hc =>
      simp only [List.foldlM_cons] at h
      cases h_head_step : step mode s x with
      | none => rw [h_head_step] at h; simp at h
      | some s1 =>
        rw [h_head_step] at h
        simp at h
        have hs1 : s1 ≠ State.closed := by
          intro he
          subst he
          exact hc (step_closed_source mode s x h_head_step)
        obtain ⟨pre, rest, hsplit, hpre, hlen⟩ := ih s1 t hs1 h ht
        refine ⟨x :: pre, rest, by rw [hsplit]; rfl, ?_, ?_⟩
        · rw [List.foldlM_cons, h_head_step]
          simpa using hpre
        · have hr := step_flightRank mode s s1 x hc h_head_step
          simp only [List.length_cons]
          omega

/--
Flight decomposition. Every accepting trace splits into three parts:
the flight that completes the handshake, post-handshake traffic, and at
most one close_notify. The flight ends at `connected`, so it is the
whole handshake (RFC 9846 §4), and it is at most `flightBound mode`
messages long. What follows the flight is only §4.7/§5.1 traffic and
the §6.1 close_notify, which `connected_stable` and `step` show cannot
change whether the trace accepts, so enumerating flights up to
`flightBound mode` covers every accepting trace.
-/
theorem accepts_decompose (mode : Mode) (msgs : List Msg)
    (h : accepts mode msgs = true) :
    ∃ pre ph tail, msgs = pre ++ ph ++ tail ∧
      pre.length ≤ flightBound mode ∧
      pre.foldlM (step mode) State.start = some State.connected ∧
      (∀ x ∈ ph, isPostHandshake x = true) ∧
      (tail = [] ∨ tail = [Msg.closeNotify]) := by
  obtain ⟨t, hfold, ht⟩ := (accepts_iff mode msgs).mp h
  obtain ⟨pre, rest, hsplit, hpre, hlen⟩ :=
    foldlM_flight mode msgs State.start t (by simp) hfold ht
  have hrest : rest.foldlM (step mode) State.connected = some t := by
    rw [hsplit, List.foldlM_append, hpre] at hfold
    simpa using hfold
  obtain ⟨ph, tail, hsplit2, hph, htail⟩ := foldlM_from_connected mode rest t hrest
  refine ⟨pre, ph, tail, ?_, ?_, hpre, hph, htail⟩
  · rw [hsplit, hsplit2, List.append_assoc]
  · have hstart : flightRank mode State.start = 0 := by cases mode <;> rfl
    have hconn : flightRank mode State.connected = flightBound mode := by
      cases mode <;> rfl
    omega

/--
The converse of `accepts_decompose`: any flight that reaches
`connected`, followed by post-handshake traffic and at most one
close_notify, accepts. With the decomposition this makes the flights of
at most `flightBound mode` messages an exact account of what accepts.
-/
theorem accepts_of_flight (mode : Mode) (pre ph tail : List Msg)
    (hpre : pre.foldlM (step mode) State.start = some State.connected)
    (hph : ∀ x ∈ ph, isPostHandshake x = true)
    (htail : tail = [] ∨ tail = [Msg.closeNotify]) :
    accepts mode (pre ++ ph ++ tail) = true := by
  have hfold : (pre ++ ph).foldlM (step mode) State.start = some State.connected := by
    rw [List.foldlM_append, hpre]
    simpa using connected_stable mode ph hph
  rcases htail with rfl | rfl
  · rw [List.append_nil]
    unfold accepts
    rw [hfold]
  · have hclose : (pre ++ ph ++ [Msg.closeNotify]).foldlM (step mode) State.start
        = some State.closed := by
      rw [List.foldlM_append, hfold]
      rfl
    unfold accepts
    rw [hclose]

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
