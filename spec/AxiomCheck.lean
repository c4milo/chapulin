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
#print axioms Spec.Handshake.accepts_of_flight
#print axioms Spec.Handshake.closeNotify_at_most_one
#print axioms Spec.Handshake.count_encryptedExtensions_of_accepts
#print axioms Spec.Handshake.count_serverHello_of_accepts
#print axioms Spec.Handshake.finished_mem_of_accepts
#print axioms Spec.Handshake.no_certificateRequest_of_accepts
#print axioms Spec.Handshake.pinned_cert_order
#print axioms Spec.Handshake.pinned_one_certificate
#print axioms Spec.Handshake.pinned_one_certificateVerify
#print axioms Spec.X509.entryAt?_sound
#print axioms Spec.X509.readCertificate_hash
-- X509Der.lean declares namespace Spec.X509, so its theorems list here.
#print axioms Spec.X509.readLen_encodeLen
#print axioms Spec.X509.readLen_canonical
#print axioms Spec.X509.readTlv_tlv
#print axioms Spec.X509.readTlv_tlv_ne
#print axioms Spec.X509.readTlv_canonical
#print axioms Spec.X509.bytesToNatBE_lt
#print axioms Spec.X509.natToBytesBE_bytesToNatBE
#print axioms Spec.X509.bytesToNatBE_ge
#print axioms Spec.X509.natBytesMin_size
#print axioms Spec.X509.bytesToNatBE_natBytesMin
#print axioms Spec.X509.natBytesMin_bytesToNatBE
#print axioms Spec.X509.natBytesMin_head_ne_zero
#print axioms Spec.X509.readDerInt_derIntNat
#print axioms Spec.X509.derIntNat_bytesToNatBE
#print axioms Spec.X509.readDerInt_canonical
#print axioms Spec.X509.oidMinimal_empty
#print axioms Spec.X509.oidMinimal_last
#print axioms Spec.X509.oidMinimal_head_ne_pad
#print axioms Spec.X509.oidMinimal_no_pad
#print axioms Spec.Aead.seal_size
#print axioms Spec.Aead.pad16_aligned
#print axioms Spec.Bytes.emptyWithCapacity_eq
#print axioms Spec.Bytes.foldl_push_eq_append
#print axioms Spec.Bytes.foldl_inv
#print axioms Spec.Bytes.foldl_inv_idx
#print axioms Spec.Bytes.size_foldl_append_const
#print axioms Spec.Bytes.natToBytesBE_size
#print axioms Spec.Bytes.natToBytesLE_size
#print axioms Spec.Bytes.xorBytes_eq
#print axioms Spec.Bytes.xorBytes_size
#print axioms Spec.Bytes.getElem_xorBytes
#print axioms Spec.Bytes.uint8_xor_cancel
#print axioms Spec.Bytes.xorBytes_xorBytes
#print axioms Spec.Bytes.byteArray_foldl_eq
#print axioms Spec.Bytes.bytesToHex_inj
#print axioms Spec.Bytes.natToBytesBE_eq
#print axioms Spec.Bytes.natToBytesBE_zero
#print axioms Spec.Bytes.natToBytesBE_succ
#print axioms Spec.Bytes.bytesToNatBE_append_byte
#print axioms Spec.Bytes.bytesToNatBE_natToBytesBE
#print axioms Spec.Bytes.zeros_size
#print axioms Spec.Bytes.uint8_zero_xor
#print axioms Spec.Bytes.uint8_xor_left_cancel
#print axioms Spec.Bytes.zeros_getElem_zero
#print axioms Spec.ChaCha.block_size
#print axioms Spec.ChaCha.xor_size
#print axioms Spec.ChaCha.xor_getElem!
#print axioms Spec.ChaCha.xor_xor
#print axioms Spec.ChaCha.xor_prefix
#print axioms Spec.Drbg.next_eq
#print axioms Spec.Drbg.stream_size
#print axioms Spec.Drbg.stream_getElem!
#print axioms Spec.Drbg.next_key_size
#print axioms Spec.Drbg.next_out_size
#print axioms Spec.Drbg.next_key_eq_block
#print axioms Spec.Drbg.next_key_getElem!
#print axioms Spec.Drbg.next_out_getElem!
#print axioms Spec.Drbg.next_out_prefix
#print axioms Spec.Drbg.gen_sizes
#print axioms Spec.Drbg.gen_key_indep_of_sizes
#print axioms Spec.Hkdf.hmac_size
#print axioms Spec.Hkdf.expand_size
#print axioms Spec.Hkdf.expandLabel_size
#print axioms Spec.Hkdf.schedule_eq
#print axioms Spec.Hkdf.schedule_sizes
#print axioms Spec.Hsparse.eq_of_bytesEq
#print axioms Spec.Poly.mac_size
#print axioms Spec.Record.seal_size
#print axioms Spec.Record.nonce_size
#print axioms Spec.Record.nextSecret_size
#print axioms Spec.Record.pad_getElem!
#print axioms Spec.Rsa.pssSign_size
#print axioms Spec.Rsa.pssVerify_size
#print axioms Spec.Rsa.pssVerify_hash_size
#print axioms Spec.Rsa.pssSign_hash_size
#print axioms Spec.Sha256.compress_size
#print axioms Spec.Sha256.sha256_size
#print axioms Spec.Sha256.pad_blocks
#print axioms Spec.Sha256.pad_prefix
