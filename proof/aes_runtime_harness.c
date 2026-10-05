// Proves: in a QUIC host suite object (-DCH_CPU_RUNTIME), which holds
// aes_hw.c's AES instructions and quic_aes_soft.c's table beside them,
// aes.c puts each key on the cipher docs/decisions.md 81 and 89 name, and
// does so memory-safely and free of UB over unconstrained inputs:
//
//   - an Initial key expands and runs on the instructions only when the
//     session's ch_cfg.cpu holds CH_CPU_CONSTANT_TIME_AES, and on the
//     table for every other value, and both of its schedules record which;
//   - the Retry key expands and runs on the table whatever the value;
//   - the table runs no traffic key of either length.
//
// The value is any 32 bits, not only the ones init admits. Every init call
// refuses a value without CH_CPU_PROBED or with a bit cpu_cfg.h does not
// define, and this proves the AES bit alone picks the constructor's cipher.
//
// CBMC can read neither cipher whole here: the instructions have no C
// body, and proof/aes_harness.c proves the table itself. So all six entries
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
    __CPROVER_assert(instructions_allowed, "only the AES bit or a traffic key runs the "
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

    // An Initial key under any ch_cfg.cpu, of any admitted connection ID
    // length, for an endpoint byte of any value.
    fill_nondet(dcid, sizeof dcid);
    size_t dcid_len = nondet_size_t();
    __CPROVER_assume(dcid_len <= sizeof dcid);
    uint32_t cpu = nondet_u32();
    int stated = (cpu & CH_CPU_CONSTANT_TIME_AES) != 0;
    uint8_t recorded = stated ? AES_ON_INSTRUCTIONS : AES_ON_TABLE;
    instructions_allowed = stated;
    traffic_key = 0;
    int rc = aes_public_key_initial(&k, cpu, nondet_u32(), dcid, dcid_len, nondet_u8());
    __CPROVER_assert(rc == CH_OK || rc == CH_EINVAL, "initial: one of the two documented codes");
    if (rc == CH_OK) {
        __CPROVER_assert(k.key.instructions == recorded && k.hp.instructions == recorded,
                         "initial: each schedule records the cipher the AES bit names");
        fill_nondet(in, sizeof in);
        aes_encrypt_block(&k, in, out);
        // The header protection entry with one buffer, the shape
        // quic_initial.c's sample and mask allow.
        aes_encrypt_block_hp(&k, out, out);
    }

    // The Retry key, on the table under every value.
    instructions_allowed = 0;
    aes_public_key_retry(&k, nondet_u32());
    __CPROVER_assert(k.key.instructions == AES_ON_TABLE, "retry: the schedule records the table");
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
    __CPROVER_assert(t.key.instructions == AES_ON_INSTRUCTIONS,
                     "traffic: the schedule records the instructions");
    fill_nondet(in, sizeof in);
    aes_traffic_encrypt_block(&t, in, out);
    aes_encrypt_schedule(&t.key, out, out);
    return 0;
}
