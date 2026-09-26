// Contract stubs for the eight calls quic_initial.c makes, so
// quic_initial_harness proves the Initial path's own framing -- the
// length refusals, the offsets it computes and the order of the three
// steps -- rather than re-deriving AES-128, AEAD_AES_128_GCM and the
// header protection pair inside one formula.
//
// Why this exists: the same reason proof/gcm_stubs.h exists. The
// cipher proves on its own in 23 s (proof/run.sh's aes line) and
// the AEAD in 269 s, 48 s and 260 s (the three gcm lines). A
// concrete composition here would carry all four of those formulas plus
// this one, over a packet whose length is symbolic.
//
// WHAT THESE MODEL, and therefore what the harness still proves:
//
//   aes_public_key_initial   CH_EINVAL above CH_QUIC_DCID_MAX, without
//                            reading the connection ID, CH_EINVAL for an
//                            endpoint that is neither name aes.h
//                            gives, and otherwise a whole key of
//                            unconstrained bytes. It records the endpoint
//                            it was handed, refusal included, so main()
//                            can compare the seal's against the open's.
//   aes_encrypt_block_hp     AES_BLOCK unconstrained bytes.
//   gcm_seal                 n ciphertext bytes and GCM_TAG tag bytes.
//   gcm_open                 1 or 0, with the n plaintext bytes written
//                            only on 1. That is the all-or-nothing rule
//                            gcm_refusal proves of the real call.
//   quic_header_protect      byte 0 and QUIC_PN_MAX_LEN bytes at pn_off.
//   quic_header_unprotect    the same writes, and a length of 1 to
//                            QUIC_PN_MAX_LEN, which is what quic_packet.h
//                            promises its caller and what puts the
//                            plaintext inside the packet.
//   quic_pn_read             a value below 2^32, the range an encoded
//                            packet number of up to four bytes has.
//   quic_pn_decode           a value below 2^62, RFC 9000 §17.1's range.
//
// Each one asserts the contract its own header states for a caller:
// every buffer readable or writable at the length passed, and the level
// one of the three. So a quic_initial.c that computed an offset outside
// the packet fails a stub's assert rather than passing quietly.
//
// WHAT THIS NO LONGER PROVES: that those eight meet their contracts.
// aes_harness proves the first two, the three gcm launch
// lines prove the AEAD, and quic_packet.c's own harness proves the four
// packet-protection entries.
#ifndef CH_QUIC_INITIAL_STUBS_H
#define CH_QUIC_INITIAL_STUBS_H

#include "aes_public_key.h"
#include "gcm.h"
#include "quic_packet.h"

uint64_t nondet_u64(void);

// The endpoint the last call asked for. main() reads it after the seal
// and again after the open and compares the two, so a build whose two
// directions derived one endpoint's key fails the harness rather than
// only the vector test. The stub writes it before it checks any length,
// so a refusing call records it too.
uint8_t stub_last_endpoint;

int aes_public_key_initial(aes_public_key *k, const uint8_t *dcid, size_t dcid_len,
                           uint8_t endpoint) {
    stub_last_endpoint = endpoint;
    __CPROVER_assert(__CPROVER_w_ok(k, sizeof *k), "aes_public_key_initial: key writable");
    if (dcid_len > CH_QUIC_DCID_MAX) {
        // The header promises this refusal reads no connection ID byte,
        // so the assert below sits after it rather than before it.
        return CH_EINVAL;
    }
    // A third endpoint is a refusal, not a precondition. aes.c
    // returns CH_EINVAL for one, and quic_initial.c's peer_endpoint hands
    // an unnamed value straight through rather than mapping it, so the
    // harness reaches this arm with an endpoint that is neither name. A
    // stub that asserted the value away would prove the seal and the open
    // only for the two callers that never need checking.
    if (endpoint != CH_QUIC_ENDPOINT_CLIENT && endpoint != CH_QUIC_ENDPOINT_SERVER) {
        return CH_EINVAL;
    }
    __CPROVER_assert(dcid_len == 0 || __CPROVER_r_ok(dcid, dcid_len),
                     "aes_public_key_initial: dcid readable");
    fill_nondet(k->key.round_keys, sizeof k->key.round_keys);
    fill_nondet(k->iv, sizeof k->iv);
    fill_nondet(k->hp.round_keys, sizeof k->hp.round_keys);
    return CH_OK;
}

void aes_encrypt_block_hp(const aes_public_key *k, const uint8_t sample[AES_BLOCK],
                          uint8_t out[AES_BLOCK]) {
    __CPROVER_assert(__CPROVER_r_ok(k, sizeof *k), "aes_encrypt_block_hp: key readable");
    __CPROVER_assert(__CPROVER_r_ok(sample, AES_BLOCK), "aes_encrypt_block_hp: sample readable");
    __CPROVER_assert(__CPROVER_w_ok(out, AES_BLOCK), "aes_encrypt_block_hp: output writable");
    fill_nondet(out, AES_BLOCK);
}

void gcm_seal(const aes_public_key *k, const uint8_t nonce[AES_IV], const uint8_t *aad,
              size_t aad_len, const uint8_t *pt, size_t n, uint8_t *ct, uint8_t tag[GCM_TAG]) {
    __CPROVER_assert(__CPROVER_r_ok(k, sizeof *k), "gcm_seal: key readable");
    __CPROVER_assert(__CPROVER_r_ok(nonce, AES_IV), "gcm_seal: nonce readable");
    __CPROVER_assert(aad_len == 0 || __CPROVER_r_ok(aad, aad_len), "gcm_seal: aad readable");
    __CPROVER_assert(n == 0 || __CPROVER_r_ok(pt, n), "gcm_seal: plaintext readable");
    __CPROVER_assert(n == 0 || __CPROVER_w_ok(ct, n), "gcm_seal: ciphertext writable");
    __CPROVER_assert(__CPROVER_w_ok(tag, GCM_TAG), "gcm_seal: tag writable");
    fill_nondet(ct, n);
    fill_nondet(tag, GCM_TAG);
}

int gcm_open(const aes_public_key *k, const uint8_t nonce[AES_IV], const uint8_t *aad,
             size_t aad_len, const uint8_t *ct, size_t n, const uint8_t tag[GCM_TAG], uint8_t *pt) {
    __CPROVER_assert(__CPROVER_r_ok(k, sizeof *k), "gcm_open: key readable");
    __CPROVER_assert(__CPROVER_r_ok(nonce, AES_IV), "gcm_open: nonce readable");
    __CPROVER_assert(aad_len == 0 || __CPROVER_r_ok(aad, aad_len), "gcm_open: aad readable");
    __CPROVER_assert(n == 0 || __CPROVER_r_ok(ct, n), "gcm_open: ciphertext readable");
    __CPROVER_assert(__CPROVER_r_ok(tag, GCM_TAG), "gcm_open: tag readable");
    __CPROVER_assert(n == 0 || __CPROVER_w_ok(pt, n), "gcm_open: plaintext writable");
    if (nondet_u8() == 0) {
        return 0; // the tag did not match, and no plaintext byte is written
    }
    fill_nondet(pt, n);
    return 1;
}

// The level a QUIC packet call takes. Both entries below check it,
// because level picks the width of the first masked byte.
static int stub_level_ok(uint8_t level) {
    return level == CH_LEVEL_INITIAL || level == CH_LEVEL_HANDSHAKE ||
           level == CH_LEVEL_APPLICATION;
}

void quic_header_protect(uint8_t *pkt, size_t pn_off, size_t pn_len, uint8_t level,
                         const uint8_t mask[QUIC_HP_MASK_LEN]) {
    __CPROVER_assert(__CPROVER_w_ok(pkt, pn_off + QUIC_PN_MAX_LEN),
                     "quic_header_protect: byte 0 and the packet number field writable");
    __CPROVER_assert(pn_len >= 1 && pn_len <= QUIC_PN_MAX_LEN,
                     "quic_header_protect: pn_len is 1 to QUIC_PN_MAX_LEN");
    __CPROVER_assert(stub_level_ok(level), "quic_header_protect: level is one of the three");
    __CPROVER_assert(__CPROVER_r_ok(mask, QUIC_HP_MASK_LEN), "quic_header_protect: mask readable");
    pkt[0] = nondet_u8();
    fill_nondet(&pkt[pn_off], QUIC_PN_MAX_LEN);
}

size_t quic_header_unprotect(uint8_t *pkt, size_t pn_off, uint8_t level,
                             const uint8_t mask[QUIC_HP_MASK_LEN]) {
    __CPROVER_assert(__CPROVER_w_ok(pkt, pn_off + QUIC_PN_MAX_LEN),
                     "quic_header_unprotect: byte 0 and the packet number field writable");
    __CPROVER_assert(stub_level_ok(level), "quic_header_unprotect: level is one of the three");
    __CPROVER_assert(__CPROVER_r_ok(mask, QUIC_HP_MASK_LEN),
                     "quic_header_unprotect: mask readable");
    pkt[0] = nondet_u8();
    fill_nondet(&pkt[pn_off], QUIC_PN_MAX_LEN);
    size_t pn_len = nondet_size_t();
    __CPROVER_assume(pn_len >= 1 && pn_len <= QUIC_PN_MAX_LEN);
    return pn_len;
}

uint64_t quic_pn_read(const uint8_t *pkt, size_t pn_off, size_t pn_len) {
    __CPROVER_assert(__CPROVER_r_ok(pkt, pn_off + QUIC_PN_MAX_LEN),
                     "quic_pn_read: the packet number field readable");
    __CPROVER_assert(pn_len >= 1 && pn_len <= QUIC_PN_MAX_LEN,
                     "quic_pn_read: pn_len is 1 to QUIC_PN_MAX_LEN");
    uint64_t truncated_pn = nondet_u64();
    __CPROVER_assume(truncated_pn <= UINT32_MAX);
    return truncated_pn;
}

uint64_t quic_pn_decode(uint64_t largest_pn, uint64_t truncated_pn, size_t pn_len) {
    __CPROVER_assert(pn_len >= 1 && pn_len <= QUIC_PN_MAX_LEN,
                     "quic_pn_decode: pn_len is 1 to QUIC_PN_MAX_LEN");
    __CPROVER_assert(truncated_pn <= UINT32_MAX, "quic_pn_decode: truncated_pn is what a field of "
                                                 "up to four bytes encodes");
    __CPROVER_assert(largest_pn < (UINT64_C(1) << 62), "quic_pn_decode: largest_pn is in range");
    uint64_t recovered_pn = nondet_u64();
    __CPROVER_assume(recovered_pn < (UINT64_C(1) << 62));
    return recovered_pn;
}

#endif
