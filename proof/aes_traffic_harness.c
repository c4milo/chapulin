// Proves: aes_traffic_key_init, the one constructor of the traffic key a
// -DCH_SUITE_AES_GCM build hands AES, is memory-safe and UB-free for both
// key lengths its contract admits, never reaches its CH_ASSERT on either,
// and writes the round count that names the cipher the key needs; and
// aes_encrypt_schedule runs that key through the cipher the round count
// names.
//
// A suite build takes AES=hw, whose key expansion and cipher are the AES
// instructions, or AES=extern, whose cipher is the image's hook, and
// CBMC can read neither. So the four block entries are contract stubs
// below: each asserts the buffers aes_block.h says it reads and writes,
// and havocs what it writes. What this proves is aes.c's own framing
// over them. The instructions are held to FIPS 197 by
// test/aes_equiv_test.c, which compares them with quic_aes_soft.c's
// reference, and proof/aes256_harness.c proves that reference.
// proof/aes_extern_harness.c proves aes_extern.c's four entries over a
// stub of the hook.
//
// Each stub records whether it ran, so the harness asserts that a 16-byte
// key reached the AES-128 schedule and a 32-byte key the AES-256 one, and
// that the dispatch ran the cipher the count names. A constructor that
// wrote AES_256_ROUNDS beside an AES-128 schedule would send an
// eleven-round-key schedule through fourteen rounds, and these are the
// assertions that fail on it.
#include "harness.h"

#include "aes_stubs.h"

#include "aes.c"

static int ran_expand_128;
static int ran_expand_256;
static int ran_cipher_128;
static int ran_cipher_256;

void aes_expand_round_keys(const uint8_t key[AES_128_KEY],
                           uint8_t round_keys[AES_ROUND_KEYS * AES_BLOCK]) {
    __CPROVER_assert(__CPROVER_r_ok(key, AES_128_KEY), "expand: key readable");
    __CPROVER_assert(__CPROVER_w_ok(round_keys, AES_ROUND_KEYS * AES_BLOCK),
                     "expand: round keys writable");
    fill_nondet(round_keys, AES_ROUND_KEYS * AES_BLOCK);
    ran_expand_128 = 1;
}

void aes_expand_round_keys_256(const uint8_t key[AES_256_KEY],
                               uint8_t round_keys[AES_256_ROUND_KEYS * AES_BLOCK]) {
    __CPROVER_assert(__CPROVER_r_ok(key, AES_256_KEY), "expand 256: key readable");
    __CPROVER_assert(__CPROVER_w_ok(round_keys, AES_256_ROUND_KEYS * AES_BLOCK),
                     "expand 256: round keys writable");
    fill_nondet(round_keys, AES_256_ROUND_KEYS * AES_BLOCK);
    ran_expand_256 = 1;
}

void aes_cipher_block(const uint8_t round_keys[AES_ROUND_KEYS * AES_BLOCK],
                      const uint8_t in[AES_BLOCK], uint8_t out[AES_BLOCK]) {
    __CPROVER_assert(__CPROVER_r_ok(round_keys, AES_ROUND_KEYS * AES_BLOCK),
                     "cipher: round keys readable");
    __CPROVER_assert(__CPROVER_r_ok(in, AES_BLOCK), "cipher: input readable");
    __CPROVER_assert(__CPROVER_w_ok(out, AES_BLOCK), "cipher: output writable");
    fill_nondet(out, AES_BLOCK);
    ran_cipher_128 = 1;
}

void aes_cipher_block_256(const uint8_t round_keys[AES_256_ROUND_KEYS * AES_BLOCK],
                          const uint8_t in[AES_BLOCK], uint8_t out[AES_BLOCK]) {
    __CPROVER_assert(__CPROVER_r_ok(round_keys, AES_256_ROUND_KEYS * AES_BLOCK),
                     "cipher 256: round keys readable");
    __CPROVER_assert(__CPROVER_r_ok(in, AES_BLOCK), "cipher 256: input readable");
    __CPROVER_assert(__CPROVER_w_ok(out, AES_BLOCK), "cipher 256: output writable");
    fill_nondet(out, AES_BLOCK);
    ran_cipher_256 = 1;
}

int main(void) {
    uint8_t key[AES_256_KEY];
    uint8_t in[AES_BLOCK];
    uint8_t out[AES_BLOCK];
    fill_nondet(key, sizeof key);
    fill_nondet(in, sizeof in);

    // One of the two lengths the contract admits, chosen by the solver.
    size_t key_len = (nondet_u8() & 1U) ? AES_128_KEY : AES_256_KEY;
    aes_traffic_key k;
    aes_traffic_key_init(&k, key, key_len);
    if (key_len == AES_256_KEY) {
        __CPROVER_assert(ran_expand_256 && !ran_expand_128, "a 32-byte key takes AES-256");
        __CPROVER_assert(k.key.rounds == AES_256_ROUNDS, "a 32-byte key records 14 rounds");
    } else {
        __CPROVER_assert(ran_expand_128 && !ran_expand_256, "a 16-byte key takes AES-128");
        __CPROVER_assert(k.key.rounds == AES_128_ROUNDS, "a 16-byte key records 10 rounds");
    }

    aes_encrypt_schedule(&k.key, in, out);
    if (key_len == AES_256_KEY) {
        __CPROVER_assert(ran_cipher_256 && !ran_cipher_128, "the dispatch runs AES-256");
    } else {
        __CPROVER_assert(ran_cipher_128 && !ran_cipher_256, "the dispatch runs AES-128");
    }
    return 0;
}
