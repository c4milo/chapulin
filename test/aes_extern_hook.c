// The ch_aes_block every AES=extern test binary links: quic_aes_soft.c's
// FIPS 197 cipher under second names, for AES-128 and AES-256, standing
// where a part's AES peripheral stands in an image. aes_block.h states
// the contract, and this hook checks the part of it a caller can get
// wrong: a key_len that is neither AES_128_KEY nor AES_256_KEY aborts
// the binary, so a test that passes never handed the hook another
// length.
//
// It expands the key on every call, which a peripheral with a key
// register does not, because the test binaries time nothing. The keys
// they pass are test keys, which is why the schedule on this frame is
// not wiped.
//
// The #defines rename the four entries before aes_block.h is read, so
// that header declares them under the names quic_aes_soft.c then
// defines, the way test/aes_equiv_soft.c renames them. CH_AES_256_TEST
// turns on the AES-256 pair in a binary without the suite define, the
// QUIC AES=extern vectors, before aes.h decides whether CH_AES_256 is
// set.
//
// aes_block.h is read while CH_AES_EXTERN is still defined, so the
// definition below takes the library's own declaration of the hook and
// the compiler checks the signature. Then the two defines that stop
// quic_aes_soft.c are dropped for the one file included after them.
// That file refuses -DCH_SUITE_AES_GCM, because a library object must
// never pair its S-box with a traffic key, and compiles its body only
// when neither CH_AES_HW nor CH_AES_EXTERN is defined. In this
// translation unit it is test code, and it holds the key a peripheral
// would hold. A TCP suite binary defines no transport, and the file's
// body sits behind the transport or the suite define, so the QUIC
// define is set here for that file alone; it reads nothing else under
// it.
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

#ifndef CH_AES_256_TEST
#define CH_AES_256_TEST 1
#endif
#define aes_expand_round_keys reference_expand_round_keys
#define aes_cipher_block reference_cipher_block
#define aes_expand_round_keys_256 reference_expand_round_keys_256
#define aes_cipher_block_256 reference_cipher_block_256

#include "aes_block.h"

#ifndef CH_AES_EXTERN
#error "test/aes_extern_hook.c belongs in an AES=extern binary: build it with -DCH_AES_EXTERN"
#endif

void ch_aes_block(const uint8_t *key, size_t key_len, const uint8_t in[AES_BLOCK],
                  uint8_t out[AES_BLOCK]) {
    uint8_t round_keys[AES_256_ROUND_KEYS * AES_BLOCK];
    if (key_len == AES_128_KEY) {
        reference_expand_round_keys(key, round_keys);
        reference_cipher_block(round_keys, in, out);
        return;
    }
    if (key_len == AES_256_KEY) {
        reference_expand_round_keys_256(key, round_keys);
        reference_cipher_block_256(round_keys, in, out);
        return;
    }
    abort();
}

#undef CH_AES_EXTERN
#undef CH_SUITE_AES_GCM
#ifndef CH_TRANSPORT_QUIC_NONBLOCKING
#define CH_TRANSPORT_QUIC_NONBLOCKING 1
#endif

#include "quic_aes_soft.c"
