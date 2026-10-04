// The stubs bench/record_layer.c calls in place of the library's AEADs,
// for bench/record.c only. They sit in a source of their own so that each
// call to one stays a call, as the call to the function it replaces is.
// record_stages.h states what each one does.
#include "record_stages.h"

void bench_stub_gcm_traffic_seal(const aes_traffic_key *k, const uint8_t nonce[AES_IV],
                                 const uint8_t *aad, size_t aad_len, const uint8_t *pt, size_t n,
                                 uint8_t *ct, uint8_t tag[GCM_TAG]) {
    (void)k;
    (void)nonce;
    (void)aad;
    (void)aad_len;
    (void)pt;
    (void)n;
    (void)ct;
    (void)tag;
}

int bench_stub_gcm_traffic_open(const aes_traffic_key *k, const uint8_t nonce[AES_IV],
                                const uint8_t *aad, size_t aad_len, const uint8_t *ct, size_t n,
                                const uint8_t tag[GCM_TAG], uint8_t *pt) {
    (void)k;
    (void)nonce;
    (void)aad;
    (void)aad_len;
    (void)ct;
    (void)n;
    (void)tag;
    (void)pt;
    return 1;
}

void bench_stub_aead_seal_cpu(uint32_t cpu, const uint8_t key[AEAD_KEY],
                              const uint8_t nonce[AEAD_NONCE], const uint8_t *aad, size_t aad_len,
                              const uint8_t *pt, size_t n, uint8_t *ct, uint8_t tag[AEAD_TAG]) {
    (void)cpu;
    (void)key;
    (void)nonce;
    (void)aad;
    (void)aad_len;
    (void)pt;
    (void)n;
    (void)ct;
    (void)tag;
}

int bench_stub_aead_open_cpu(uint32_t cpu, const uint8_t key[AEAD_KEY],
                             const uint8_t nonce[AEAD_NONCE], const uint8_t *aad, size_t aad_len,
                             const uint8_t *ct, size_t n, const uint8_t tag[AEAD_TAG],
                             uint8_t *pt) {
    (void)cpu;
    (void)key;
    (void)nonce;
    (void)aad;
    (void)aad_len;
    (void)ct;
    (void)n;
    (void)tag;
    (void)pt;
    return 1;
}
