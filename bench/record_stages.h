// The entries bench/record.c times that the library does not export: the
// stages its sources keep static, and the library's own code with one
// callee replaced by a stub. Four stage sources each compile one library
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
#include "gcm_hw.h"
#include "gcm_vaes.h"
#include "record.h"
#include "widemul.h"

// The ch_cfg.cpu value every row runs under. The bench's object is a host
// object, which holds every path, and a session's value picks among them
// (cpu_cfg.h, docs/decisions.md 89). bench/record.sh builds the bench once
// for each value it times and passes the value on the compile line, as a
// number such as 0x7, and the rows hand it to the calls a session hands
// its own to: the record directions, the AEAD entries and the AES traffic
// key.
#ifndef BENCH_CPU
#error "bench/record.sh passes -DBENCH_CPU, the ch_cfg.cpu value the rows run under"
#endif

// The answer BENCH_CPU gives the calls that take one (widemul.h).
#define BENCH_WIDEMUL widemul_of_cpu(BENCH_CPU)

// The three entries gcm.c hands a key's whole blocks to under BENCH_CPU, for
// the rows that time one alone: gcm_vaes.c's kernels where the value names
// VAES beside the AES bit on x86-64, as gcm_use_vaes picks them, and
// gcm_hw.c's 128-bit loops under every other value.
#if defined(__x86_64__) && ((BENCH_CPU) & CH_CPU_VAES) != 0 &&                                     \
    ((BENCH_CPU) & CH_CPU_CONSTANT_TIME_AES) != 0
#define BENCH_ON_VAES 1
#define bench_gcm_counter_blocks gcm_counter_blocks_vaes
#define bench_gcm_seal_passes gcm_seal_passes_vaes
#define bench_gcm_open_passes gcm_open_passes_vaes
#else
#define bench_gcm_counter_blocks gcm_counter_blocks_hw
#define bench_gcm_seal_passes gcm_seal_passes_hw
#define bench_gcm_open_passes gcm_open_passes_hw
#endif

// Whether the ChaCha20 rows run chacha20_avx2.c's kernel under BENCH_CPU, as
// chacha20.c's use_avx2 picks it.
#if defined(__x86_64__) && ((BENCH_CPU) & CH_CPU_AVX2) != 0
#define BENCH_ON_AVX2 1
#endif

// bench/record_gcm.c. counter_mode and compute_tag as gcm_traffic_seal
// calls them: from the counter block after the one nonce names, and with
// the first counter block for the tag's mask.
void bench_gcm_counter_mode(const aes_traffic_key *k, const uint8_t nonce[AES_IV],
                            const uint8_t *in, size_t n, uint8_t *out);
void bench_gcm_compute_tag(const aes_traffic_key *k, const uint8_t nonce[AES_IV],
                           const uint8_t *aad, size_t aad_len, const uint8_t *ct, size_t n,
                           uint8_t tag[GCM_TAG]);

// bench/record_chacha_vector.c. The passes of the ChaCha20 path BENCH_CPU
// names, chacha20_vector.c's or the AVX2 kernel's, run as often and with
// the same counters as the path's xor runs them over n bytes, with each
// pass's keystream written to out and no exclusive-or. A pass is eight
// blocks on NEON and on AVX2 and four on SSE2, so out holds the larger.
#define BENCH_CHACHA20_VECTOR_PASS_MAX (8 * CHACHA20_BLOCK)
void bench_chacha20_vector_blocks(const uint8_t key[CHACHA20_KEY],
                                  const uint8_t nonce[CHACHA20_NONCE], uint32_t counter, size_t n,
                                  uint8_t out[BENCH_CHACHA20_VECTOR_PASS_MAX]);

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
// The two seals write nothing, and the two opens write nothing and report
// a match.
void bench_stub_gcm_traffic_seal(const aes_traffic_key *k, const uint8_t nonce[AES_IV],
                                 const uint8_t *aad, size_t aad_len, const uint8_t *pt, size_t n,
                                 uint8_t *ct, uint8_t tag[GCM_TAG]);
int bench_stub_gcm_traffic_open(const aes_traffic_key *k, const uint8_t nonce[AES_IV],
                                const uint8_t *aad, size_t aad_len, const uint8_t *ct, size_t n,
                                const uint8_t tag[GCM_TAG], uint8_t *pt);
void bench_stub_aead_seal_cpu(uint32_t cpu, const uint8_t key[AEAD_KEY],
                              const uint8_t nonce[AEAD_NONCE], const uint8_t *aad, size_t aad_len,
                              const uint8_t *pt, size_t n, uint8_t *ct, uint8_t tag[AEAD_TAG]);
int bench_stub_aead_open_cpu(uint32_t cpu, const uint8_t key[AEAD_KEY],
                             const uint8_t nonce[AEAD_NONCE], const uint8_t *aad, size_t aad_len,
                             const uint8_t *ct, size_t n, const uint8_t tag[AEAD_TAG], uint8_t *pt);

#endif
