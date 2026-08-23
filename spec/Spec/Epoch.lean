/-!
The monotonic revocation epoch (docs/ca.md): the ordering and bound
rule `handshake.c` applies to a CA-mode leaf certificate's epoch
number.

The CA writes every server certificate's notBefore as one of a
restricted set of dates and adds one step to revoke.
`Spec.X509.readTimeEpoch` reads that date back as the number
`yy*336 + (mm-1)*28 + (dd-1)`, 0..16799. A device stores the highest
number it has accepted and judges each new certificate against it:
below the stored epoch means a retired certificate, too far above it
means a mis-issued one or an attempt to strand the device.

Two C functions apply the rule, and this module models both plus the
order they run in: `epoch_check` refuses, `epoch_commit` performs the
one assignment. Three things the C does stay outside the model.
Neither function runs when `cfg.epoch_load` is `NULL`, so the model
covers a device with the callbacks configured. `epoch_check` also
records `epoch_status` and `epoch_seen`, which report the verdict
rather than decide it. And `epoch_commit` may run only after the
server Finished, which the C states as
`CH_ASSERT(h->server_finished_ok)` and which message order, not epoch
arithmetic, decides — `Spec.Handshake` is where that lives.

`bound` is cfg.h's `CH_EPOCH_BOUND`, a build constant whose default is
64 and whose `_Static_assert` admits 1..16798. It stays a parameter
here instead of a definition, so every theorem below holds for every
build's value and none of them needs that range.

Unlike every other module in `spec/`, this one is not a differential
oracle. `epoch_check` and `epoch_commit` are `static` in
`handshake.c`, so no driver can call them and nothing compares these
definitions against the C. The theorems are about the model alone; see
CONTRACT.md.
-/
namespace Spec.Epoch

/--
The largest revocation-epoch number, cfg.h's `CH_EPOCH_MAX`. The
allowed dates end at 2049-12-28, so the largest number is
`49*336 + 11*28 + 27 = 16799`, and `Spec.X509.readTimeEpoch`
returns nothing above it.
-/
def maxEpoch : Nat := 16799

/--
`epoch_check`: the ordering and bound rule over one leaf certificate.
`cert` is what the certificate reader returned for the leaf's
notBefore — `some e` when the date is epoch-shaped (`leaf.epoch_ok`
set, number `leaf.epoch`), `none` for any other valid date. The check
accepts iff the number is at or above the stored epoch and at most
`bound` steps above it. The C tells its two refusals apart by alert —
below the stored epoch is `certificate_revoked`, off-shape or too far
ahead is `bad_certificate` — and both fail the handshake closed, so
acceptance is the whole rule (docs/ca.md, INV-21).
-/
def check (bound stored : Nat) (cert : Option Nat) : Bool :=
  match cert with
  | none => false
  | some e => stored ≤ e && e ≤ stored + bound

/--
`epoch_commit`: raise the stored epoch to the certificate's number,
and only ever upward. `bound` is absent from this signature because it
is absent from the C function: the jump bound sits entirely
in `check`, which is why a commit is safe only where a check already
accepted (`commit_takes_any_epoch`).
-/
def commit (stored : Nat) (cert : Option Nat) : Nat :=
  match cert with
  | none => stored
  | some e => if stored < e then e else stored

/--
One CA-mode handshake against one certificate. `epoch_check` runs in
`server_auth` on the chain verdict and fails the handshake closed when
it rejects; `epoch_commit` runs in `run` after `expect_finished`, so
it sees only certificates the check accepted. The model holds the two
calls together because their order is what bounds the result.
-/
def step (bound stored : Nat) (cert : Option Nat) : Nat :=
  if check bound stored cert then commit stored cert else stored

/--
The stored epoch after a device runs one handshake per certificate, in
the order given, starting from `stored`. This is `ch_tls.epoch` across
sessions: `epoch_store` persists it, so each handshake starts from
what the last one left.
-/
def storedAfter (bound stored : Nat) (certs : List (Option Nat)) : Nat :=
  certs.foldl (step bound) stored

/--
How many of `certs` the check accepted, each judged against the stored
epoch as it stood when that certificate arrived. `storedAfter_le`
multiplies `bound` by this count.
-/
def acceptedCount (bound : Nat) : Nat → List (Option Nat) → Nat
  | _, [] => 0
  | stored, cert :: rest =>
    (if check bound stored cert then 1 else 0)
      + acceptedCount bound (step bound stored cert) rest

/--
The stored epoch never decreases across a commit: `epoch_commit` takes
a strictly higher number or leaves the stored epoch alone, for every
certificate, accepted or not. This is INV-21's monotonicity half.
-/
theorem commit_ge (stored : Nat) (cert : Option Nat) : stored ≤ commit stored cert := by
  cases cert with
  | none => exact Nat.le_refl stored
  | some e =>
    simp only [commit]
    split <;> omega

/--
The jump bound: a certificate the check accepted raises the stored
epoch by at most `bound` steps. With `commit_ge`, a commit that
changes the stored epoch at all lands in `(stored, stored + bound]`,
so no single certificate — however far in the future its date — pushes
a device past what the CA will ever issue (docs/ca.md, "The jump bound").
-/
theorem commit_le_of_check (bound stored : Nat) (cert : Option Nat)
    (h_accepted : check bound stored cert = true) :
    commit stored cert ≤ stored + bound := by
  cases cert with
  | none => simp [check] at h_accepted
  | some e =>
    obtain ⟨h_at_least, h_within⟩ : stored ≤ e ∧ e ≤ stored + bound := by
      simpa [check] using h_accepted
    simp only [commit]
    split <;> omega

/--
The jump bound lives in `check`, not in `epoch_commit`. For every
`bound` and every stored epoch, a certificate dated `bound + 1` steps
ahead is one the check refuses and the commit would take. So a commit
is safe only where a refused certificate cannot reach it, and moving
one is safe exactly as far as it stays behind the check's own
early return.

The repo's recorded violation does stay behind it — it inserts the
commit after `epoch_check`'s `if (rc != CH_OK) return rc`, so the
bound survives and what that mutation breaks is the separate temporal
rule `CH_ASSERT(h->server_finished_ok)` states. This theorem does not
speak to that one.
-/
theorem commit_takes_any_epoch (bound stored : Nat) :
    check bound stored (some (stored + bound + 1)) = false ∧
      commit stored (some (stored + bound + 1)) = stored + bound + 1 := by
  have h_over : ¬ (stored + bound + 1 ≤ stored + bound) := by omega
  refine ⟨by simp [check, h_over], ?_⟩
  simp only [commit]
  split
  · rfl
  · omega

/-- A certificate the check refused leaves the stored epoch as it was.
One unfolding of `step`, stated because the run-level theorems rest on
it. -/
private theorem step_eq_of_reject (bound stored : Nat) (cert : Option Nat)
    (h_rejected : check bound stored cert = false) :
    step bound stored cert = stored := by
  simp [step, h_rejected]

/-- Per handshake, the stored epoch never decreases. -/
private theorem step_ge (bound stored : Nat) (cert : Option Nat) :
    stored ≤ step bound stored cert := by
  unfold step
  split
  · exact commit_ge stored cert
  · exact Nat.le_refl stored

/-- Per handshake, the stored epoch rises by at most `bound`, and by
nothing at all when the check refused. -/
private theorem step_le (bound stored : Nat) (cert : Option Nat) :
    step bound stored cert ≤ stored + (if check bound stored cert then bound else 0) := by
  unfold step
  split
  · rename_i h_check
    exact commit_le_of_check bound stored cert h_check
  · omega

/-- Unfold one certificate from a run. -/
private theorem storedAfter_cons (bound stored : Nat) (cert : Option Nat)
    (rest : List (Option Nat)) :
    storedAfter bound stored (cert :: rest)
      = storedAfter bound (step bound stored cert) rest := rfl

/--
Replaying an accepted certificate is a no-op: a second handshake
against the same certificate ends where the first one left the stored
epoch. Once a certificate has been committed the rule reports
`CH_EPOCH_MATCHED` for it and `epoch_commit` returns without storing,
so a copied certificate cannot ratchet a device up one step at a time.
-/
theorem step_idem (bound stored : Nat) (cert : Option Nat) :
    step bound (step bound stored cert) cert = step bound stored cert := by
  cases h_check : check bound stored cert with
  | false =>
    rw [step_eq_of_reject bound stored cert h_check]
    exact step_eq_of_reject bound stored cert h_check
  | true =>
    cases cert with
    | none => simp [check] at h_check
    | some e =>
      obtain ⟨h_at_least, h_within⟩ : stored ≤ e ∧ e ≤ stored + bound := by
        simpa [check] using h_check
      have h_after_commit : step bound stored (some e) = e := by
        simp only [step, h_check, if_true, commit]
        split <;> omega
      have h_recheck_accepts : check bound e (some e) = true := by
        simp only [check, Bool.and_eq_true, decide_eq_true_eq]
        omega
      rw [h_after_commit]
      simp only [step, h_recheck_accepts, if_true, commit]
      split <;> omega

/--
Across a whole run of handshakes the stored epoch never decreases: no
certificate a device sees, accepted or refused, moves it down. This is
INV-21's monotonicity claim at the level INV-21 states it, across
sessions rather than within one.
-/
theorem storedAfter_ge (bound : Nat) (certs : List (Option Nat)) (stored : Nat) :
    stored ≤ storedAfter bound stored certs := by
  induction certs generalizing stored with
  | nil => exact Nat.le_refl stored
  | cons cert rest ih =>
    have h_head : stored ≤ step bound stored cert := step_ge bound stored cert
    have h_tail : step bound stored cert ≤ storedAfter bound (step bound stored cert) rest :=
      ih (step bound stored cert)
    have h_cons := storedAfter_cons bound stored cert rest
    omega

/--
The jump bound over a whole run: the stored epoch rises by at
most `bound` steps per certificate the check accepted. A device that
completes `n` CA handshakes ends no higher than `stored + bound * n`,
whatever dates those certificates carried and in whatever order they
arrived. A single-step statement cannot say this: it is the run, not
one handshake, that decides how far a device can be pushed, and one
far-future date buys the same `bound` steps as any other accepted
certificate.
-/
theorem storedAfter_le (bound : Nat) (certs : List (Option Nat)) (stored : Nat) :
    storedAfter bound stored certs ≤ stored + bound * acceptedCount bound stored certs := by
  induction certs generalizing stored with
  | nil => simp [storedAfter, acceptedCount]
  | cons cert rest ih =>
    have h_tail := ih (step bound stored cert)
    have h_head := step_le bound stored cert
    calc storedAfter bound stored (cert :: rest)
        = storedAfter bound (step bound stored cert) rest :=
          storedAfter_cons bound stored cert rest
      _ ≤ step bound stored cert
            + bound * acceptedCount bound (step bound stored cert) rest := h_tail
      _ ≤ stored + (if check bound stored cert then bound else 0)
            + bound * acceptedCount bound (step bound stored cert) rest :=
          Nat.add_le_add_right h_head _
      _ = stored + bound * acceptedCount bound stored (cert :: rest) := by
          simp only [acceptedCount, Nat.mul_add]
          cases check bound stored cert <;> simp [Nat.add_assoc]

/--
Refused certificates change nothing: a run in which the check accepted
no certificate ends on the exact stored epoch it started from, for any
number of certificates and any dates they carry. Read the other way:
if a device's stored epoch moved, the check accepted at least one
certificate in that run, and each acceptance cost the peer a
CertificateVerify under a CA-signed key.
-/
theorem storedAfter_eq_of_none_accepted (bound stored : Nat) (certs : List (Option Nat))
    (h_none_accepted : acceptedCount bound stored certs = 0) :
    storedAfter bound stored certs = stored := by
  have h_le := storedAfter_le bound certs stored
  have h_ge := storedAfter_ge bound certs stored
  rw [h_none_accepted, Nat.mul_zero] at h_le
  omega

/-- Per handshake, a stored epoch in the reader's range stays in it. -/
private theorem step_le_maxEpoch (bound stored : Nat) (cert : Option Nat)
    (h_stored : stored ≤ maxEpoch) (h_cert : ∀ e, cert = some e → e ≤ maxEpoch) :
    step bound stored cert ≤ maxEpoch := by
  unfold step
  split
  · cases cert with
    | none => simpa [commit] using h_stored
    | some e =>
      have h_in_range := h_cert e rfl
      simp only [commit]
      split <;> omega
  · exact h_stored

/--
The stored epoch stays inside the reader's range. A device provisioned
at or below `maxEpoch` that only ever sees certificates whose epoch
number `Spec.X509.readTimeEpoch` put in range keeps a stored epoch
of at most `maxEpoch`, for any number of handshakes. That is the other
half of what keeps `stored + CH_EPOCH_BOUND` inside the `uint32` the C
compares in: the x509der harness bounds the number the reader
produces, and this bounds the number the device keeps.
-/
theorem storedAfter_le_maxEpoch (bound : Nat) :
    ∀ (certs : List (Option Nat)) (stored : Nat), stored ≤ maxEpoch →
      (∀ e, some e ∈ certs → e ≤ maxEpoch) →
        storedAfter bound stored certs ≤ maxEpoch := by
  intro certs
  induction certs with
  | nil =>
    intro stored h_stored _
    simpa [storedAfter] using h_stored
  | cons cert rest ih =>
    intro stored h_stored h_certs
    have h_head : ∀ e, cert = some e → e ≤ maxEpoch := by
      intro e h_is_epoch
      exact h_certs e (by simp [h_is_epoch])
    have h_tail : ∀ e, some e ∈ rest → e ≤ maxEpoch := by
      intro e h_mem
      exact h_certs e (List.mem_cons_of_mem cert h_mem)
    rw [storedAfter_cons]
    exact ih (step bound stored cert) (step_le_maxEpoch bound stored cert h_stored h_head) h_tail

end Spec.Epoch
