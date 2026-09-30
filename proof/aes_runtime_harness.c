// Proves: in an AES=runtime QUIC suite object, which holds aes_hw.c's AES
// instructions and quic_aes_soft.c's table beside them, aes.c puts each key
// on the cipher docs/decisions.md 81 names, and does so memory-safely and
// free of UB over unconstrained inputs:
//
//   - an Initial key expands and runs on the instructions only when the
//     caller's answer is CH_AES_INSTRUCTIONS_PRESENT, and on the table for
//     every other byte, and both of its schedules record which;
//   - the Retry key expands and runs on the table whatever the answer;
//   - the table runs no traffic key of either length;
//   - counter mode over whole blocks, which gcm.c hands only a schedule
//     the instructions run, runs on the instructions for an Initial key
//     under the answer present and for a traffic key of either length,
//     and its CH_ASSERT holds for both.
//
// The answer is any byte rather than one of the two cfg.h names. Every init
// call refuses the others, and this proves the constructor would still keep
// such a value off the instructions.
//
// CBMC can read neither cipher whole here: the instructions have no C
// body, and proof/aes_harness.c proves the table itself. So all eight entries
// are contract stubs below. Each asserts the buffers aes_block.h says it
// reads and writes, havocs what it writes, and asserts that the key in hand
// may run on it. HKDF is proof/aes_stubs.h's stub.
#include "harness.h"

#include "aes_stubs.h"

#include "aes.c"

// Whether the key the harness runs now may take the instructions, and
// whether it is a traffic key, which may never take the table.
static int instructions_allowed;
static int traffic_key;

static void ran_on_instructions(void) {
    __CPROVER_assert(instructions_allowed, "only the answer present or a traffic key runs the "
                                           "instructions");
}

static void ran_on_table(void) {
    __CPROVER_assert(!traffic_key, "the table runs no traffic key");
}

void aes_expand_round_keys(const uint8_t key[AES_128_KEY],
                           uint8_t round_keys[AES_ROUND_KEYS * AES_BLOCK]) {
    __CPROVER_assert(__CPROVER_r_ok(key, AES_128_KEY), "expand: key readable");
    __CPROVER_assert(__CPROVER_w_ok(round_keys, AES_ROUND_KEYS * AES_BLOCK),
                     "expand: round keys writable");
    fill_nondet(round_keys, AES_ROUND_KEYS * AES_BLOCK);
    ran_on_instructions();
}

void aes_cipher_block(const uint8_t round_keys[AES_ROUND_KEYS * AES_BLOCK],
                      const uint8_t in[AES_BLOCK], uint8_t out[AES_BLOCK]) {
    __CPROVER_assert(__CPROVER_r_ok(round_keys, AES_ROUND_KEYS * AES_BLOCK),
                     "cipher: round keys readable");
    __CPROVER_assert(__CPROVER_r_ok(in, AES_BLOCK), "cipher: input readable");
    __CPROVER_assert(__CPROVER_w_ok(out, AES_BLOCK), "cipher: output writable");
    fill_nondet(out, AES_BLOCK);
    ran_on_instructions();
}

void aes_expand_round_keys_256(const uint8_t key[AES_256_KEY],
                               uint8_t round_keys[AES_256_ROUND_KEYS * AES_BLOCK]) {
    __CPROVER_assert(__CPROVER_r_ok(key, AES_256_KEY), "expand 256: key readable");
    __CPROVER_assert(__CPROVER_w_ok(round_keys, AES_256_ROUND_KEYS * AES_BLOCK),
                     "expand 256: round keys writable");
    fill_nondet(round_keys, AES_256_ROUND_KEYS * AES_BLOCK);
    ran_on_instructions();
}

void aes_cipher_block_256(const uint8_t round_keys[AES_256_ROUND_KEYS * AES_BLOCK],
                          const uint8_t in[AES_BLOCK], uint8_t out[AES_BLOCK]) {
    __CPROVER_assert(__CPROVER_r_ok(round_keys, AES_256_ROUND_KEYS * AES_BLOCK),
                     "cipher 256: round keys readable");
    __CPROVER_assert(__CPROVER_r_ok(in, AES_BLOCK), "cipher 256: input readable");
    __CPROVER_assert(__CPROVER_w_ok(out, AES_BLOCK), "cipher 256: output writable");
    fill_nondet(out, AES_BLOCK);
    ran_on_instructions();
}

// The whole-block counter mode the harness hands at most two blocks.
#define COUNTER_BLOCKS_MAX 2

static void counter_blocks_contract(uint8_t counter[AES_BLOCK], const uint8_t *in, size_t blocks,
                                    uint8_t *out) {
    __CPROVER_assert(blocks <= COUNTER_BLOCKS_MAX, "counter: the harness's bound");
    __CPROVER_assert(__CPROVER_rw_ok(counter, AES_BLOCK), "counter: counter readable and writable");
    __CPROVER_assert(__CPROVER_r_ok(in, blocks * AES_BLOCK), "counter: input readable");
    __CPROVER_assert(__CPROVER_w_ok(out, blocks * AES_BLOCK), "counter: output writable");
    fill_nondet(counter, AES_BLOCK);
    fill_nondet(out, blocks * AES_BLOCK);
    ran_on_instructions();
}

void aes_counter_blocks(const uint8_t round_keys[AES_ROUND_KEYS * AES_BLOCK],
                        uint8_t counter[AES_BLOCK], const uint8_t *in, size_t blocks,
                        uint8_t *out) {
    __CPROVER_assert(__CPROVER_r_ok(round_keys, AES_ROUND_KEYS * AES_BLOCK),
                     "counter: round keys readable");
    counter_blocks_contract(counter, in, blocks, out);
}

void aes_counter_blocks_256(const uint8_t round_keys[AES_256_ROUND_KEYS * AES_BLOCK],
                            uint8_t counter[AES_BLOCK], const uint8_t *in, size_t blocks,
                            uint8_t *out) {
    __CPROVER_assert(__CPROVER_r_ok(round_keys, AES_256_ROUND_KEYS * AES_BLOCK),
                     "counter 256: round keys readable");
    counter_blocks_contract(counter, in, blocks, out);
}

// Counter mode's whole blocks under s, in place, as gcm.c's seal runs them.
static void run_counter_blocks(const aes_key_schedule *s) {
    uint8_t counter[AES_BLOCK];
    uint8_t data[COUNTER_BLOCKS_MAX * AES_BLOCK];
    fill_nondet(counter, sizeof counter);
    fill_nondet(data, sizeof data);
    size_t blocks = nondet_size_t();
    __CPROVER_assume(blocks <= COUNTER_BLOCKS_MAX);
    aes_encrypt_counter_blocks(s, counter, data, blocks, data);
}

void aes_soft_expand_round_keys(const uint8_t key[AES_128_KEY],
                                uint8_t round_keys[AES_ROUND_KEYS * AES_BLOCK]) {
    __CPROVER_assert(__CPROVER_r_ok(key, AES_128_KEY), "table expand: key readable");
    __CPROVER_assert(__CPROVER_w_ok(round_keys, AES_ROUND_KEYS * AES_BLOCK),
                     "table expand: round keys writable");
    fill_nondet(round_keys, AES_ROUND_KEYS * AES_BLOCK);
    ran_on_table();
}

void aes_soft_cipher_block(const uint8_t round_keys[AES_ROUND_KEYS * AES_BLOCK],
                           const uint8_t in[AES_BLOCK], uint8_t out[AES_BLOCK]) {
    __CPROVER_assert(__CPROVER_r_ok(round_keys, AES_ROUND_KEYS * AES_BLOCK),
                     "table cipher: round keys readable");
    __CPROVER_assert(__CPROVER_r_ok(in, AES_BLOCK), "table cipher: input readable");
    __CPROVER_assert(__CPROVER_w_ok(out, AES_BLOCK), "table cipher: output writable");
    fill_nondet(out, AES_BLOCK);
    ran_on_table();
}

int main(void) {
    aes_public_key k;
    uint8_t dcid[CH_QUIC_DCID_MAX];
    uint8_t in[AES_BLOCK];
    uint8_t out[AES_BLOCK];

    // An Initial key under any answer, of any admitted connection ID
    // length, for an endpoint byte of any value.
    fill_nondet(dcid, sizeof dcid);
    size_t dcid_len = nondet_size_t();
    __CPROVER_assume(dcid_len <= sizeof dcid);
    uint8_t answer = nondet_u8();
    uint8_t recorded = answer == CH_AES_INSTRUCTIONS_PRESENT ? CH_AES_INSTRUCTIONS_PRESENT
                                                             : CH_AES_INSTRUCTIONS_ABSENT;
    instructions_allowed = answer == CH_AES_INSTRUCTIONS_PRESENT;
    traffic_key = 0;
    int rc = aes_public_key_initial(&k, answer, nondet_u32(), dcid, dcid_len, nondet_u8());
    __CPROVER_assert(rc == CH_OK || rc == CH_EINVAL, "initial: one of the two documented codes");
    if (rc == CH_OK) {
        __CPROVER_assert(k.key.instructions == recorded && k.hp.instructions == recorded,
                         "initial: each schedule records the cipher the answer names");
        fill_nondet(in, sizeof in);
        aes_encrypt_block(&k, in, out);
        // The header protection entry with one buffer, the shape
        // quic_initial.c's sample and mask allow.
        aes_encrypt_block_hp(&k, out, out);
        if (answer == CH_AES_INSTRUCTIONS_PRESENT) {
            run_counter_blocks(&k.key);
        }
    }

    // The Retry key, on the table under every answer.
    instructions_allowed = 0;
    aes_public_key_retry(&k, nondet_u32());
    __CPROVER_assert(k.key.instructions == CH_AES_INSTRUCTIONS_ABSENT,
                     "retry: the schedule records the table");
    fill_nondet(in, sizeof in);
    aes_encrypt_block(&k, in, out);

    // A traffic key of either length the contract admits.
    instructions_allowed = 1;
    traffic_key = 1;
    uint8_t key[AES_256_KEY];
    fill_nondet(key, sizeof key);
    size_t key_len = (nondet_u8() & 1U) ? AES_128_KEY : AES_256_KEY;
    aes_traffic_key t;
    aes_traffic_key_init(&t, key, key_len);
    __CPROVER_assert(t.key.instructions == CH_AES_INSTRUCTIONS_PRESENT,
                     "traffic: the schedule records the instructions");
    fill_nondet(in, sizeof in);
    aes_traffic_encrypt_block(&t, in, out);
    aes_encrypt_schedule(&t.key, out, out);
    run_counter_blocks(&t.key);
    return 0;
}
