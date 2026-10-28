// Proves: srv_ticket_harness.c's properties for a PROFILE=cnsa2 server's
// tickets (docs/decisions.md 162), which srv_ticket.c seals and opens under
// AES-256-GCM on a key it expands on its own frame, with version byte 3.
// The launch line passes the profile server's defines.
//
// The three AES calls are contract stubs, as srv_ticket_harness.c stubs the
// ChaCha20-Poly1305 AEAD: each asserts the buffers the real function reads
// and writes at the lengths it uses, and havocs its outputs.
// aes_traffic_key_init asserts the 32-byte key, the one length the profile
// passes. aes256_harness.c, aes_traffic_harness.c and the gcm harnesses
// prove the real ones.
#include <string.h>

#include "harness.h"

#include "aes_traffic_key.h"
#include "gcm.h"

int nondet_int(void);

void aes_traffic_key_init(aes_traffic_key *k, const uint8_t *key, size_t key_len) {
    __CPROVER_assert(__CPROVER_w_ok(k, sizeof *k), "aes_traffic_key_init: key schedule writable");
    __CPROVER_assert(key_len == 32, "aes_traffic_key_init: the profile's key is AES-256's");
    __CPROVER_assert(__CPROVER_r_ok(key, key_len), "aes_traffic_key_init: key readable");
    fill_nondet((uint8_t *)k, sizeof *k);
}

void gcm_traffic_seal(const aes_traffic_key *k, const uint8_t nonce[AES_IV], const uint8_t *aad,
                      size_t aad_len, const uint8_t *pt, size_t n, uint8_t *ct,
                      uint8_t tag[GCM_TAG]) {
    __CPROVER_assert(__CPROVER_r_ok(k, sizeof *k), "gcm_traffic_seal: key readable");
    __CPROVER_assert(__CPROVER_r_ok(nonce, AES_IV), "gcm_traffic_seal: nonce readable");
    __CPROVER_assert(aad_len == 0 || __CPROVER_r_ok(aad, aad_len),
                     "gcm_traffic_seal: aad readable");
    __CPROVER_assert(n == 0 || __CPROVER_r_ok(pt, n), "gcm_traffic_seal: plaintext readable");
    __CPROVER_assert(n == 0 || __CPROVER_w_ok(ct, n), "gcm_traffic_seal: ciphertext writable");
    __CPROVER_assert(__CPROVER_w_ok(tag, GCM_TAG), "gcm_traffic_seal: tag writable");
    fill_nondet(ct, n);
    fill_nondet(tag, GCM_TAG);
}

int gcm_traffic_open(const aes_traffic_key *k, const uint8_t nonce[AES_IV], const uint8_t *aad,
                     size_t aad_len, const uint8_t *ct, size_t n, const uint8_t tag[GCM_TAG],
                     uint8_t *pt) {
    __CPROVER_assert(__CPROVER_r_ok(k, sizeof *k), "gcm_traffic_open: key readable");
    __CPROVER_assert(__CPROVER_r_ok(nonce, AES_IV), "gcm_traffic_open: nonce readable");
    __CPROVER_assert(aad_len == 0 || __CPROVER_r_ok(aad, aad_len),
                     "gcm_traffic_open: aad readable");
    __CPROVER_assert(n == 0 || __CPROVER_r_ok(ct, n), "gcm_traffic_open: ciphertext readable");
    __CPROVER_assert(__CPROVER_r_ok(tag, GCM_TAG), "gcm_traffic_open: tag readable");
    __CPROVER_assert(n == 0 || __CPROVER_w_ok(pt, n), "gcm_traffic_open: plaintext writable");
    // A mismatch leaves zeros at pt (gcm.h).
    if (nondet_int()) {
        fill_nondet(pt, n);
        return 1;
    }
    memset(pt, 0, n);
    return 0;
}

#include "srv_ticket_harness.c"
