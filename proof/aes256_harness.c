// Proves: the AES-256 key schedule and forward cipher of FIPS 197 in
// quic_aes_soft.c, and aes.c's aes_encrypt_schedule choosing between
// AES-128 and AES-256 by the schedule's round count, are memory-safe and
// UB-free over unconstrained inputs at the module's real bound: a 32-byte
// key, fifteen round keys and one block.
//
// The software AES-256 is a reference, compiled here and in the test
// binaries under -DCH_AES_256_TEST and in no library object. It is what
// test/aes_equiv_test.c holds aes_hw.c's AES-256 to, and the
// instructions are what TLS_AES_256_GCM_SHA384 runs on, so this proof
// reaches the path a library object runs only through that equivalence.
// docs/quic.md, "What the AES axis proves", states the split.
//
// The round count is havocked before the dispatch, so both arms of
// aes_encrypt_schedule run: every value other than AES_256_ROUNDS takes
// the AES-128 cipher, which reads the first eleven of the fifteen round
// keys the schedule holds.
//
// Aliasing: gcm.c reuses its counter block as the cipher's output,
// so both ciphers are also called with in == out.
//
// HKDF is the contract stub proof/aes_stubs.h holds, for the
// Initial constructor aes.c compiles beside the dispatch.
#define CH_AES_256_TEST 1

#include "harness.h"

#include "aes_stubs.h"

#include "aes.c"
#include "quic_aes_soft.c"

int main(void) {
    uint8_t key[AES_256_KEY];
    uint8_t round_keys[AES_256_ROUND_KEYS * AES_BLOCK];
    uint8_t in[AES_BLOCK];
    uint8_t out[AES_BLOCK];

    // The schedule over any key.
    fill_nondet(key, sizeof key);
    aes_expand_round_keys_256(key, round_keys);

    // The cipher over any round keys, not only the ones the schedule
    // wrote, and any block.
    fill_nondet(round_keys, sizeof round_keys);
    fill_nondet(in, sizeof in);
    aes_cipher_block_256(round_keys, in, out);
    fill_nondet(out, sizeof out);
    aes_cipher_block_256(round_keys, out, out);

    // The dispatch over a schedule whose round keys and round count are
    // both havocked, through the entry gcm.c calls.
    aes_key_schedule schedule;
    fill_nondet(schedule.round_keys, sizeof schedule.round_keys);
    schedule.rounds = nondet_u8();
    fill_nondet(in, sizeof in);
    aes_encrypt_schedule(&schedule, in, out);
    fill_nondet(out, sizeof out);
    aes_encrypt_schedule(&schedule, out, out);
    return 0;
}
