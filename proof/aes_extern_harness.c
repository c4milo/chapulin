// Proves: aes_extern.c's four entries, the AES=extern implementation a
// -DCH_SUITE_AES_GCM build compiles, are memory-safe and UB-free over
// unconstrained inputs, and pass the image's ch_aes_block what
// aes_block.h says it gets: a key_len of AES_128_KEY or AES_256_KEY, a
// key readable at that length, a readable input block and a writable
// output block. Each cipher entry calls the hook once, with the key
// length its name says and the round-key bytes as the key.
//
// ch_aes_block is the image's, so this tree holds no body for it and
// CBMC has nothing to read. The stub below is its contract: it asserts
// what the entries must pass, havocs the output block, and records the
// key pointer and length it was given. That the peripheral computes AES,
// and in what time, is the image's to answer for (aes_block.h);
// test/aes_extern_hook.c stands in for it in the test binaries.
//
// Each expansion is driven into a buffer exactly as long as aes_block.h
// declares, eleven blocks for AES-128 and fifteen for AES-256, so a
// store past either is a bounds failure here. After each one the harness
// asserts the layout aes_extern.c states at an unconstrained index: the
// key in the first key-length bytes and zeros after them. The index
// stands for every position at once, so no loop reads the buffer back.
//
// Aliasing: gcm.c reuses its counter block as the cipher's output, so
// both ciphers are also called with in == out.
#include "harness.h"

#include "aes_extern.c"

static const uint8_t *hook_key;
static size_t hook_key_len;
static int hook_calls;

void ch_aes_block(const uint8_t *key, size_t key_len, const uint8_t in[AES_BLOCK],
                  uint8_t out[AES_BLOCK]) {
    __CPROVER_assert(key_len == AES_128_KEY || key_len == AES_256_KEY,
                     "hook: key_len is AES_128_KEY or AES_256_KEY");
    __CPROVER_assert(__CPROVER_r_ok(key, key_len), "hook: key readable at key_len");
    __CPROVER_assert(__CPROVER_r_ok(in, AES_BLOCK), "hook: input readable");
    __CPROVER_assert(__CPROVER_w_ok(out, AES_BLOCK), "hook: output writable");
    fill_nondet(out, AES_BLOCK);
    hook_key = key;
    hook_key_len = key_len;
    hook_calls++;
}

int main(void) {
    uint8_t key[AES_256_KEY];
    uint8_t in[AES_BLOCK];
    uint8_t out[AES_BLOCK];
    uint8_t round_keys[AES_ROUND_KEYS * AES_BLOCK];
    uint8_t round_keys_256[AES_256_ROUND_KEYS * AES_BLOCK];

    // AES-128: the expansion over any key into any prior bytes, then the
    // layout at every index.
    fill_nondet(key, sizeof key);
    fill_nondet(round_keys, sizeof round_keys);
    aes_expand_round_keys(key, round_keys);
    size_t at = nondet_size_t();
    __CPROVER_assume(at < sizeof round_keys);
    __CPROVER_assert(round_keys[at] == (at < AES_128_KEY ? key[at] : 0),
                     "expand: the 16 key bytes, then zeros");

    // The cipher over any round keys and any block, into a distinct
    // buffer and in place.
    fill_nondet(round_keys, sizeof round_keys);
    fill_nondet(in, sizeof in);
    hook_calls = 0;
    aes_cipher_block(round_keys, in, out);
    __CPROVER_assert(hook_calls == 1, "cipher: one hook call");
    __CPROVER_assert(hook_key == round_keys, "cipher: the stored key is the key");
    __CPROVER_assert(hook_key_len == AES_128_KEY, "cipher: a 16-byte key");
    fill_nondet(out, sizeof out);
    aes_cipher_block(round_keys, out, out);

    // AES-256, the same four checks.
    fill_nondet(key, sizeof key);
    fill_nondet(round_keys_256, sizeof round_keys_256);
    aes_expand_round_keys_256(key, round_keys_256);
    at = nondet_size_t();
    __CPROVER_assume(at < sizeof round_keys_256);
    __CPROVER_assert(round_keys_256[at] == (at < AES_256_KEY ? key[at] : 0),
                     "expand 256: the 32 key bytes, then zeros");

    fill_nondet(round_keys_256, sizeof round_keys_256);
    fill_nondet(in, sizeof in);
    hook_calls = 0;
    aes_cipher_block_256(round_keys_256, in, out);
    __CPROVER_assert(hook_calls == 1, "cipher 256: one hook call");
    __CPROVER_assert(hook_key == round_keys_256, "cipher 256: the stored key is the key");
    __CPROVER_assert(hook_key_len == AES_256_KEY, "cipher 256: a 32-byte key");
    fill_nondet(out, sizeof out);
    aes_cipher_block_256(round_keys_256, out, out);
    return 0;
}
