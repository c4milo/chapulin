-- Run by make lint-spec, never part of the library build: prints the
-- axioms each load-bearing theorem depends on, and the gate asserts
-- nothing appears beyond Lean's three standard ones (propext,
-- Classical.choice, Quot.sound). A stray axiom in a proof is exactly
-- what this catches; the hygiene grep catches the declaration itself.
import Spec.Aead
import Spec.Record
import Spec.Handshake
import Spec.Drbg

#print axioms Spec.Aead.open?_seal
#print axioms Spec.Aead.open?_ne_tag
#print axioms Spec.Record.aeadOpen_seal
#print axioms Spec.Handshake.psk_no_certificate
#print axioms Spec.Handshake.hrr_at_most_one
#print axioms Spec.Handshake.count_finished_of_accepts
#print axioms Spec.Drbg.next_key_out_disjoint
#print axioms Spec.Drbg.next_key_indep
#print axioms Spec.Record.nonce_inj
#print axioms Spec.Bytes.natToBytesBE_inj
