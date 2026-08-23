-- Run by make lint-spec, never part of the library build: prints the
-- axioms each load-bearing theorem depends on, and the gate asserts
-- nothing appears beyond Lean's three standard ones (propext,
-- Classical.choice, Quot.sound). A stray axiom in a proof is exactly
-- what this catches; the hygiene grep catches the declaration itself.
import Spec.Aead
import Spec.Record
import Spec.Handshake
import Spec.Drbg
import Spec.X509
import Spec.X25519
import Spec.Hsparse
import Spec.Epoch

#print axioms Spec.Aead.open?_seal
#print axioms Spec.Aead.open?_ne_tag
#print axioms Spec.Record.aeadOpen_seal
#print axioms Spec.Record.open?_seal
#print axioms Spec.Record.open?_type_sound
#print axioms Spec.Handshake.psk_no_certificate
#print axioms Spec.Handshake.hrr_at_most_one
#print axioms Spec.Handshake.count_finished_of_accepts
#print axioms Spec.Drbg.next_key_out_disjoint
#print axioms Spec.Drbg.next_key_indep
#print axioms Spec.Record.nonce_inj
#print axioms Spec.Bytes.natToBytesBE_inj
#print axioms Spec.Handshake.no_post_handshake_before_finished
#print axioms Spec.Handshake.psk_no_certificateVerify
#print axioms Spec.Handshake.closeNotify_last
#print axioms Spec.Handshake.connected_stable
#print axioms Spec.Handshake.accepts_decompose
#print axioms Spec.X509.parse_sound
#print axioms Spec.X509.parse_key_signed
#print axioms Spec.X25519.decodeScalar_mul_eight
#print axioms Spec.X25519.decodeScalar_range
#print axioms Spec.Hsparse.messageBody_sound
#print axioms Spec.Hsparse.parseServerHello_sound
#print axioms Spec.Hsparse.parseServerHello_random
#print axioms Spec.Hsparse.parseCertificate_sound
#print axioms Spec.Hsparse.parseCertificateVerify_sound
#print axioms Spec.Hsparse.parseEncryptedExtensions_limit_ge_64
#print axioms Spec.Epoch.commit_ge
#print axioms Spec.Epoch.commit_le_of_check
#print axioms Spec.Epoch.commit_takes_any_epoch
#print axioms Spec.Epoch.step_idem
#print axioms Spec.Epoch.storedAfter_ge
#print axioms Spec.Epoch.storedAfter_le
#print axioms Spec.Epoch.storedAfter_eq_of_none_accepted
#print axioms Spec.Epoch.storedAfter_le_maxEpoch
