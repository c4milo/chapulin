// aead.c compiled with one more entry, for bench/record.c only. mac is
// static in aead.c, so this file includes the source. The bench also links
// the library's own aead.o, so this file first renames the two external
// names aead.c defines, and nothing calls the renamed functions. The
// include names the parent directory because a quoted include looks in
// bench/ first, and bench/aead.c is the AEAD bench.
#define aead_seal bench_aead_copy_seal
#define aead_open bench_aead_copy_open
#define aead_seal_cpu bench_aead_copy_seal_cpu
#define aead_open_cpu bench_aead_copy_open_cpu

#include "../aead.c"

#include "record_stages.h"

void bench_aead_mac(const uint8_t key[AEAD_KEY], const uint8_t nonce[AEAD_NONCE],
                    const uint8_t *aad, size_t aad_len, const uint8_t *ct, size_t n,
                    uint8_t tag[AEAD_TAG]) {
    mac(BENCH_CPU, BENCH_WIDEMUL, key, nonce, aad, aad_len, ct, n, tag);
}
