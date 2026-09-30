// The entries bench/record.c times that the library does not export: the
// stages its sources keep static, and the library's own code with one
// callee replaced by a stub. Five stage sources each compile one library
// source under renamed external names and add the entries below, the way
// bench/aead_gcm.c adds one to gcm.c, and bench/record_stub.c defines the
// stubs. The bench also links the library's own objects, so the
// whole seal and open it times are the library's code. None of this is
// library code.
#ifndef CH_BENCH_RECORD_STAGES_H
#define CH_BENCH_RECORD_STAGES_H

#include <stddef.h>
#include <stdint.h>

#include "aead.h"
#include "aes.h"
#include "gcm.h"
#include "record.h"

// bench/record_gcm.c. counter_mode and compute_tag as gcm_traffic_seal
// calls them: from the counter block after the one nonce names, and with
// the first counter block for the tag's mask.
void bench_gcm_counter_mode(const aes_traffic_key *k, const uint8_t nonce[AES_IV],
                            const uint8_t *in, size_t n, uint8_t *out);
void bench_gcm_compute_tag(const aes_traffic_key *k, const uint8_t nonce[AES_IV],
                           const uint8_t *aad, size_t aad_len, const uint8_t *ct, size_t n,
                           uint8_t tag[GCM_TAG]);

// bench/record_gcm_stub.c. The same counter_mode, compiled with its
// forward cipher replaced by bench_stub_encrypt_schedule: the counter
// increments, the calls and the keystream exclusive-or, and no AES round.
void bench_gcm_counter_mode_without_aes(const aes_traffic_key *k, const uint8_t nonce[AES_IV],
                                        const uint8_t *in, size_t n, uint8_t *out);

// bench/record_chacha.c. chacha20.c's block function, called as often
// and with the same counter as chacha20_xor calls it over n bytes, with
// each block written to out and no exclusive-or.
void bench_chacha20_blocks(const uint8_t key[CHACHA20_KEY], const uint8_t nonce[CHACHA20_NONCE],
                           uint32_t counter, size_t n, uint8_t out[CHACHA20_BLOCK]);

// bench/record_chacha_vector.c, in the CHACHA=vector builds alone.
// chacha20_vector.c's four_blocks, called as often and with the same
// counter as chacha20_vector_xor calls it over n bytes, with each group of
// four blocks written to out and no exclusive-or.
void bench_chacha20_vector_blocks(const uint8_t key[CHACHA20_KEY],
                                  const uint8_t nonce[CHACHA20_NONCE], uint32_t counter, size_t n,
                                  uint8_t out[4 * CHACHA20_BLOCK]);

// bench/record_aead.c. aead.c's mac: the one-time key block, Poly1305 over
// the associated data and the ciphertext, and the tag.
void bench_aead_mac(const uint8_t key[AEAD_KEY], const uint8_t nonce[AEAD_NONCE],
                    const uint8_t *aad, size_t aad_len, const uint8_t *ct, size_t n,
                    uint8_t tag[AEAD_TAG]);

// bench/record_layer.c. rec_seal and rec_open compiled with every AEAD call
// replaced by the stubs below: the framing, the copy, the nonce, the AES
// key expansion and its wipe, and no AEAD.
int bench_rec_seal_without_aead(rec_dir *d, uint8_t type, const uint8_t *pt, size_t n, uint8_t *out,
                                size_t cap, size_t *out_len);
int bench_rec_open_without_aead(rec_dir *d, const uint8_t *rec, size_t n, uint8_t *pt, size_t cap,
                                size_t *pt_len, uint8_t *type);

// bench/record_stub.c. The stubs, in a source of their own so that every
// call to one stays a call, as the call to the function it replaces is.
// The cipher copies in to out and runs no round. The two seals write
// nothing, and the two opens write nothing and report a match.
void bench_stub_encrypt_schedule(const aes_key_schedule *s, const uint8_t in[AES_BLOCK],
                                 uint8_t out[AES_BLOCK]);
void bench_stub_gcm_traffic_seal(const aes_traffic_key *k, const uint8_t nonce[AES_IV],
                                 const uint8_t *aad, size_t aad_len, const uint8_t *pt, size_t n,
                                 uint8_t *ct, uint8_t tag[GCM_TAG]);
int bench_stub_gcm_traffic_open(const aes_traffic_key *k, const uint8_t nonce[AES_IV],
                                const uint8_t *aad, size_t aad_len, const uint8_t *ct, size_t n,
                                const uint8_t tag[GCM_TAG], uint8_t *pt);
void bench_stub_aead_seal(const uint8_t key[AEAD_KEY], const uint8_t nonce[AEAD_NONCE],
                          const uint8_t *aad, size_t aad_len, const uint8_t *pt, size_t n,
                          uint8_t *ct, uint8_t tag[AEAD_TAG]);
int bench_stub_aead_open(const uint8_t key[AEAD_KEY], const uint8_t nonce[AEAD_NONCE],
                         const uint8_t *aad, size_t aad_len, const uint8_t *ct, size_t n,
                         const uint8_t tag[AEAD_TAG], uint8_t *pt);

#endif
