// The powers of the hash subkey that a host object stores beside each
// AES-GCM key (suite.h, docs/decisions.md 234), read from the bytes of the
// key's owner. bin/aes_suite_test runs them over rec_dir, a TLS record
// direction, and bin/quic_suite_test over quic_keys, a QUIC key set. Each
// defines CHECK and includes this file after its own cases.
//
//   - The stored powers are the reference's: H^1 to H^8 times x^-1 with
//     each power's two words added, which test/ghash_powers_soft.h
//     computes from the block cipher's H with bit arithmetic alone, under
//     both key sizes.
//   - A KeyUpdate, and a QUIC key update, store the powers of the new key.
//   - An owner keyed without CH_CPU_CONSTANT_TIME_AES, or under ChaCha20,
//     stores none, and holds none of the key before.
//   - A seal under the stored powers writes the bytes a seal writes that
//     computes its powers, and each opens the other's, at every length
//     that takes each power and under every ch_cfg.cpu value that names a
//     kernel this CPU has.
//   - A seal reads the stored powers: one changed bit of the first power
//     changes the tag, under each of those values.
//   - gcm_traffic_key_store leaves no round key, no hash subkey and no
//     power on the stack below its caller.
//
// A device object stores no powers, and its binaries compile none of this.
#ifndef CH_TEST_GHASH_POWERS_TESTS_H
#define CH_TEST_GHASH_POWERS_TESTS_H
#ifdef CH_AES_STORED_SCHEDULE

#include "aes_block.h"
#include "gcm.h"
#include "ghash_powers_soft.h"
#include "hash_instructions_cpu.h"
#include "x86_kernels_cpu.h"

_Static_assert(GHASH_POWERS_SOFT_LEN == SUITE_GHASH_POWERS_LEN,
               "the reference writes the stored form's length");

static unsigned long powers_cases;

// want = the stored form of the powers of key's hash subkey, which is the
// forward cipher of a block of zeros (SP 800-38D §7.1).
static void powers_reference(uint8_t want[GHASH_POWERS_SOFT_LEN], const uint8_t *key,
                             size_t key_len) {
    static const uint8_t zero[AES_BLOCK] = {0};
    uint8_t round_keys[AES_256_ROUND_KEYS * AES_BLOCK];
    uint8_t subkey[AES_BLOCK];
    if (key_len == AES_256_KEY) {
        aes_expand_round_keys_256(key, round_keys);
        aes_cipher_block_256(round_keys, zero, subkey);
    } else {
        aes_expand_round_keys(key, round_keys);
        aes_cipher_block(round_keys, zero, subkey);
    }
    ghash_powers_soft(want, subkey);
}

static int powers_all_zero(const uint8_t *p, size_t n) {
    for (size_t i = 0; i < n; i++) {
        if (p[i] != 0) {
            return 0;
        }
    }
    return 1;
}

// The ch_cfg.cpu values that each name one AES-GCM kernel this CPU has:
// gcm_arm64.c's and gcm_arm64_eor3.c's on arm64, and on x86-64 gcm_hw.c's
// loops, gcm_vaes.c's and gcm_avx512_kernel.c's. Returns how many.
static size_t powers_cpu_values(uint32_t values[3]) {
    size_t count = 0;
    values[count++] = TEST_CPU;
#ifdef __aarch64__
    if (cpu_has_sha3_instructions()) {
        values[count++] = TEST_CPU | CH_CPU_CONSTANT_TIME_SHA3;
    }
#else
    if (x86_cpu_has_vaes()) {
        values[count++] = TEST_CPU | CH_CPU_VAES;
    }
    if (x86_cpu_has_avx512()) {
        values[count++] = TEST_CPU | CH_CPU_VAES | CH_CPU_AVX512;
    }
#endif
    return count;
}

// The plaintext lengths of the agreement cases: every count of blocks up
// to two passes of eight and past them, and the lengths each side of 32
// arm64 passes, where the passes run in pairs and take H^9 to H^16, and of
// one and 32 steps of the 512-bit kernel, which takes up to H^33.
static const size_t powers_lengths[] = {
    0,    1,    15,   16,   17,   31,   32,   33,   47,   48,    63,   64,   65,
    95,   96,   111,  112,  113,  127,  128,  129,  143,  144,   145,  255,  256,
    257,  300,  511,  512,  513,  527,  528,  1023, 1024, 1025,  4079, 4080, 4081,
    4095, 4096, 4097, 4111, 4112, 4113, 8191, 8192, 8193, 16000,
};
#define POWERS_LENGTHS (sizeof powers_lengths / sizeof powers_lengths[0])
#define POWERS_TEXT_MAX 16000

static uint8_t powers_text[POWERS_TEXT_MAX];
static const uint16_t powers_suites[2] = {SUITE_AES_128_GCM_SHA256, SUITE_AES_256_GCM_SHA384};

// ---------------------------------------------------------------- the store's stack

// test/stack_residue.c, compiled as a source of its own.
void stack_residue_take(volatile uint8_t *below, size_t n, uint8_t *copy);
const char *stack_residue_unsearched(void);

#define POWERS_RESIDUE_BYTES 4096
static uint8_t powers_residue_copy[POWERS_RESIDUE_BYTES];
static uint8_t powers_residue_key[AES_256_KEY];
static size_t powers_residue_key_len;
static uint8_t powers_residue_schedule[SUITE_AES_SCHEDULE_LEN];
static uint8_t powers_residue_stored[SUITE_GHASH_POWERS_LEN];

static __attribute__((noinline)) void powers_residue_call(void) {
    (void)gcm_traffic_key_store(powers_residue_schedule, powers_residue_stored, TEST_CPU,
                                powers_residue_key, powers_residue_key_len);
}

static __attribute__((noinline)) void powers_residue_snapshot(void) {
    volatile uint8_t below[POWERS_RESIDUE_BYTES];
    stack_residue_take(below, POWERS_RESIDUE_BYTES, powers_residue_copy);
}

static int powers_residue_holds(const uint8_t *p, size_t n) {
    for (size_t at = 0; at + n <= POWERS_RESIDUE_BYTES; at++) {
        if (memcmp(&powers_residue_copy[at], p, n) == 0) {
            return 1;
        }
    }
    return 0;
}

// The values of one store, looked for in the copy of the stack: each round
// key past the key's own bytes, the hash subkey as its 16 bytes and as the
// two words ghash_vector.h holds, and each power and each power's words
// added as the stored form holds them. They are computed after the copy,
// so the frames that compute them cannot leave them there first.
static void powers_residue_look(void) {
    size_t rounds = powers_residue_key_len == AES_256_KEY ? AES_256_ROUNDS : AES_128_ROUNDS;
    for (size_t r = powers_residue_key_len / AES_BLOCK; r <= rounds; r++) {
        CHECK(!powers_residue_holds(&powers_residue_schedule[r * AES_BLOCK], AES_BLOCK));
    }
    static const uint8_t zero[AES_BLOCK] = {0};
    uint8_t subkey[AES_BLOCK];
    uint8_t words[AES_BLOCK];
    if (powers_residue_key_len == AES_256_KEY) {
        aes_cipher_block_256(powers_residue_schedule, zero, subkey);
    } else {
        aes_cipher_block(powers_residue_schedule, zero, subkey);
    }
    for (size_t i = 0; i < 8; i++) {
        words[i] = subkey[7 - i];
        words[8 + i] = subkey[15 - i];
    }
    CHECK(!powers_residue_holds(subkey, AES_BLOCK));
    CHECK(!powers_residue_holds(words, AES_BLOCK));
    for (size_t i = 0; i < GHASH_POWERS_SOFT_COUNT; i++) {
        const uint8_t *power = &powers_residue_stored[i * 2 * AES_BLOCK];
        CHECK(!powers_residue_holds(power, AES_BLOCK));
        CHECK(!powers_residue_holds(&power[AES_BLOCK], 8));
    }
}

static void test_powers_store_residue(void) {
    if (stack_residue_unsearched() != NULL) {
        (void)printf("ghash powers: no search of the stack: %s\n", stack_residue_unsearched());
        return;
    }
    static const size_t key_lens[2] = {AES_128_KEY, AES_256_KEY};
    for (size_t i = 0; i < 2; i++) {
        for (size_t j = 0; j < sizeof powers_residue_key; j++) {
            powers_residue_key[j] = (uint8_t)(0x3b + 7 * j + 29 * i);
        }
        powers_residue_key_len = key_lens[i];
        powers_residue_call();
        powers_residue_snapshot();
        powers_residue_look();
        powers_cases++;
    }
}

#ifdef CH_TRANSPORT_QUIC_NONBLOCKING
// ---------------------------------------------------------------- a QUIC key set

static void test_powers_stored(void) {
    uint8_t secret[SHA384_LEN];
    uint8_t want[GHASH_POWERS_SOFT_LEN];
    uint8_t before[GHASH_POWERS_SOFT_LEN];
    memset(secret, 0x5a, sizeof secret);
    for (size_t i = 0; i < 2; i++) {
        size_t key_len = suite_key_len(powers_suites[i]);
        quic_keys k;
        memset(&k, 0, sizeof k);
        quic_keys_init_suite(TEST_CPU, &k, 1, secret, powers_suites[i]);
        powers_reference(want, k.key, key_len);
        CHECK(k.stored == 1 && memcmp(k.ghash_powers, want, sizeof want) == 0);
        memcpy(before, want, sizeof before);

        // RFC 9001 §6.1's key update stores the powers of the new key.
        quic_keys_update(TEST_CPU, secret, &k, 1);
        powers_reference(want, k.key, key_len);
        CHECK(memcmp(want, before, sizeof want) != 0);
        CHECK(k.stored == 1 && memcmp(k.ghash_powers, want, sizeof want) == 0);

        // The same set keyed without the AES bit, and then under ChaCha20
        // after an AES key, holds no power.
        quic_keys_init_suite(CH_CPU_PROBED, &k, 1, secret, powers_suites[i]);
        CHECK(k.stored == 0 && powers_all_zero(k.ghash_powers, sizeof k.ghash_powers));
        quic_keys_init_suite(TEST_CPU, &k, 1, secret, powers_suites[i]);
        CHECK(k.stored == 1 && !powers_all_zero(k.ghash_powers, sizeof k.ghash_powers));
        quic_keys_init_suite(TEST_CPU, &k, 1, secret, SUITE_CHACHA20_POLY1305_SHA256);
        CHECK(k.stored == 0 && powers_all_zero(k.ghash_powers, sizeof k.ghash_powers));
        powers_cases++;
    }
}

// A long header as quic_packet_seal takes it: the first byte, then bytes
// the protection does not read, and two bytes of packet number.
#define POWERS_HDR 24
#define POWERS_PACKET_MAX (POWERS_HDR + POWERS_TEXT_MAX + AEAD_TAG)
static uint8_t powers_packet[POWERS_PACKET_MAX];
static uint8_t powers_twin_packet[POWERS_PACKET_MAX];

// One length under one value and suite: the seal on stored powers against
// the seal of the same key with stored at 0, which expands the key and
// computes its powers, and each one's open of the packet.
static void powers_agree(uint32_t cpu, uint16_t suite, size_t n) {
    // The packet number and the payload hold 4 bytes or more
    // (quic_packet.h), so a payload holds 2 or more beside this number.
    if (n < 2) {
        return;
    }
    uint8_t secret[SHA384_LEN];
    uint8_t hdr[POWERS_HDR];
    memset(secret, 0x33, sizeof secret);
    memset(hdr, 0x11, sizeof hdr);
    hdr[0] = 0xe1;
    hdr[POWERS_HDR - 2] = 0;
    hdr[POWERS_HDR - 1] = 7;
    quic_keys k;
    quic_hp_key h;
    memset(&k, 0, sizeof k);
    quic_keys_init_suite(cpu, &k, 1, secret, suite);
    quic_hp_key_init_suite(cpu, &h, 1, secret, suite);
    quic_keys twin = k;
    twin.stored = 0;
    size_t len = 0;
    size_t twin_len = 0;
    CHECK(k.stored == 1);
    CHECK(quic_packet_seal(cpu, &k, &h, CH_LEVEL_HANDSHAKE, 0, 7, 2, hdr, sizeof hdr, powers_text,
                           n, powers_packet, sizeof powers_packet, &len) == CH_OK);
    CHECK(quic_packet_seal(cpu, &twin, &h, CH_LEVEL_HANDSHAKE, 0, 7, 2, hdr, sizeof hdr,
                           powers_text, n, powers_twin_packet, sizeof powers_twin_packet,
                           &twin_len) == CH_OK);
    CHECK(len == twin_len && memcmp(powers_packet, powers_twin_packet, len) == 0);
    uint64_t pn = 0;
    size_t opened = 0;
    CHECK(quic_packet_open_handshake(cpu, &twin, &h, powers_packet, len, sizeof hdr - 2, 6, &pn,
                                     &opened) == CH_OK);
    CHECK(opened == n && memcmp(&powers_packet[sizeof hdr], powers_text, n) == 0);
    CHECK(quic_packet_open_handshake(cpu, &k, &h, powers_twin_packet, twin_len, sizeof hdr - 2, 6,
                                     &pn, &opened) == CH_OK);
    CHECK(opened == n && memcmp(&powers_twin_packet[sizeof hdr], powers_text, n) == 0);
    powers_cases++;
}

// The seal reads the stored powers where they lie: with one bit of the
// set's first stored power changed, the same packet's ciphertext is the
// same and its tag is another. A seal that computed its powers from the
// key would write the same tag.
static void powers_are_read(uint32_t cpu, uint16_t suite) {
    uint8_t secret[SHA384_LEN];
    uint8_t hdr[POWERS_HDR];
    memset(secret, 0x33, sizeof secret);
    memset(hdr, 0x11, sizeof hdr);
    hdr[0] = 0xe1;
    hdr[POWERS_HDR - 2] = 0;
    hdr[POWERS_HDR - 1] = 7;
    quic_keys k;
    quic_hp_key h;
    memset(&k, 0, sizeof k);
    quic_keys_init_suite(cpu, &k, 1, secret, suite);
    quic_hp_key_init_suite(cpu, &h, 1, secret, suite);
    quic_keys changed = k;
    changed.ghash_powers[0] ^= 1;
    size_t n = 64;
    size_t len = 0;
    size_t changed_len = 0;
    CHECK(quic_packet_seal(cpu, &k, &h, CH_LEVEL_HANDSHAKE, 0, 7, 2, hdr, sizeof hdr, powers_text,
                           n, powers_packet, sizeof powers_packet, &len) == CH_OK);
    CHECK(quic_packet_seal(cpu, &changed, &h, CH_LEVEL_HANDSHAKE, 0, 7, 2, hdr, sizeof hdr,
                           powers_text, n, powers_twin_packet, sizeof powers_twin_packet,
                           &changed_len) == CH_OK);
    // Header protection samples the ciphertext past the packet number, so
    // the packets are compared from there: 4 bytes into the payload.
    size_t tag_at = sizeof hdr + n;
    CHECK(len == changed_len && len == tag_at + AEAD_TAG);
    CHECK(memcmp(&powers_packet[sizeof hdr + 4], &powers_twin_packet[sizeof hdr + 4], n - 4) == 0);
    CHECK(memcmp(&powers_packet[tag_at], &powers_twin_packet[tag_at], AEAD_TAG) != 0);
    powers_cases++;
}

// The set quic_keys_select chooses claims no stored schedule and no
// powers, so its packet computes both (docs/decisions.md 160).
static void test_powers_selected_set(void) {
    uint8_t secret[SHA384_LEN];
    memset(secret, 0x5a, sizeof secret);
    quic_keys sets[CH_QUIC_KEY_SETS];
    memset(sets, 0, sizeof sets);
    quic_keys_init_suite(TEST_CPU, &sets[CH_QUIC_KEY_CURRENT], 1, secret, SUITE_AES_256_GCM_SHA384);
    quic_keys chosen;
    memset(&chosen, 0xff, sizeof chosen);
    quic_keys_select(sets, CH_QUIC_KEY_CURRENT, &chosen);
    CHECK(chosen.stored == 0);
    CHECK(memcmp(chosen.key, sets[CH_QUIC_KEY_CURRENT].key, sizeof chosen.key) == 0);
    powers_cases++;
}
#else
// ---------------------------------------------------------------- a record direction

static void powers_dir(rec_dir *d, uint32_t cpu, const uint8_t *secret, uint16_t suite) {
    d->cpu = cpu;
    rec_dir_init_suite(d, secret, suite);
}

static void test_powers_stored(void) {
    uint8_t secret[SHA384_LEN];
    uint8_t want[GHASH_POWERS_SOFT_LEN];
    uint8_t before[GHASH_POWERS_SOFT_LEN];
    memset(secret, 0x5a, sizeof secret);
    for (size_t i = 0; i < 2; i++) {
        size_t key_len = suite_key_len(powers_suites[i]);
        rec_dir d;
        memset(&d, 0, sizeof d);
        powers_dir(&d, TEST_CPU, secret, powers_suites[i]);
        powers_reference(want, d.key, key_len);
        CHECK(d.stored == 1 && memcmp(d.ghash_powers, want, sizeof want) == 0);
        memcpy(before, want, sizeof before);

        // A KeyUpdate stores the powers of the new key.
        rec_dir_update(secret, &d);
        powers_reference(want, d.key, key_len);
        CHECK(memcmp(want, before, sizeof want) != 0);
        CHECK(d.stored == 1 && memcmp(d.ghash_powers, want, sizeof want) == 0);

        // The same direction keyed without the AES bit, and then under
        // ChaCha20 after an AES key, holds no power.
        powers_dir(&d, CH_CPU_PROBED, secret, powers_suites[i]);
        CHECK(d.stored == 0 && powers_all_zero(d.ghash_powers, sizeof d.ghash_powers));
        powers_dir(&d, TEST_CPU, secret, powers_suites[i]);
        CHECK(d.stored == 1 && !powers_all_zero(d.ghash_powers, sizeof d.ghash_powers));
        powers_dir(&d, TEST_CPU, secret, SUITE_CHACHA20_POLY1305_SHA256);
        CHECK(d.stored == 0 && powers_all_zero(d.ghash_powers, sizeof d.ghash_powers));
        powers_cases++;
    }
}

#define POWERS_RECORD_MAX (REC_OVERHEAD + POWERS_TEXT_MAX)
static uint8_t powers_record[POWERS_RECORD_MAX];
static uint8_t powers_twin_record[POWERS_RECORD_MAX];
static uint8_t powers_opened[POWERS_TEXT_MAX + 1];

// One length under one value and suite: the seal on stored powers against
// the seal of the same key with stored at 0, which expands the key and
// computes its powers, and each one's open of the other's record.
static void powers_agree(uint32_t cpu, uint16_t suite, size_t n) {
    uint8_t secret[SHA384_LEN];
    memset(secret, 0x33, sizeof secret);
    rec_dir d;
    memset(&d, 0, sizeof d);
    powers_dir(&d, cpu, secret, suite);
    rec_dir twin = d;
    twin.stored = 0;
    rec_dir reader = d;
    rec_dir twin_reader = twin;
    size_t len = 0;
    size_t twin_len = 0;
    CHECK(d.stored == 1);
    CHECK(rec_seal(&d, REC_APPDATA, powers_text, n, powers_record, sizeof powers_record, &len) ==
          0);
    CHECK(rec_seal(&twin, REC_APPDATA, powers_text, n, powers_twin_record,
                   sizeof powers_twin_record, &twin_len) == 0);
    CHECK(len == twin_len && memcmp(powers_record, powers_twin_record, len) == 0);
    size_t opened = 0;
    uint8_t type = 0;
    CHECK(rec_open(&twin_reader, powers_record, len, powers_opened, sizeof powers_opened, &opened,
                   &type) == 0);
    CHECK(opened == n && type == REC_APPDATA && memcmp(powers_opened, powers_text, n) == 0);
    CHECK(rec_open(&reader, powers_twin_record, twin_len, powers_opened, sizeof powers_opened,
                   &opened, &type) == 0);
    CHECK(opened == n && type == REC_APPDATA && memcmp(powers_opened, powers_text, n) == 0);
    powers_cases++;
}

// The seal reads the stored powers where they lie: with one bit of the
// direction's first stored power changed, the same record's ciphertext is
// the same and its tag is another. A seal that computed its powers from
// the key would write the same tag.
static void powers_are_read(uint32_t cpu, uint16_t suite) {
    uint8_t secret[SHA384_LEN];
    memset(secret, 0x33, sizeof secret);
    rec_dir d;
    memset(&d, 0, sizeof d);
    powers_dir(&d, cpu, secret, suite);
    rec_dir changed = d;
    changed.ghash_powers[0] ^= 1;
    size_t n = 64;
    size_t len = 0;
    size_t changed_len = 0;
    CHECK(rec_seal(&d, REC_APPDATA, powers_text, n, powers_record, sizeof powers_record, &len) ==
          0);
    CHECK(rec_seal(&changed, REC_APPDATA, powers_text, n, powers_twin_record,
                   sizeof powers_twin_record, &changed_len) == 0);
    size_t tag_at = REC_HDR + n + 1;
    CHECK(len == changed_len && len == tag_at + AEAD_TAG);
    CHECK(memcmp(powers_record, powers_twin_record, tag_at) == 0);
    CHECK(memcmp(&powers_record[tag_at], &powers_twin_record[tag_at], AEAD_TAG) != 0);
    powers_cases++;
}
#endif

static void test_ghash_powers(void) {
    for (size_t i = 0; i < sizeof powers_text; i++) {
        powers_text[i] = (uint8_t)(i * 13 + 5);
    }
    test_powers_stored();
#ifdef CH_TRANSPORT_QUIC_NONBLOCKING
    test_powers_selected_set();
#endif
    uint32_t values[3];
    size_t count = powers_cpu_values(values);
    for (size_t v = 0; v < count; v++) {
        for (size_t s = 0; s < 2; s++) {
            powers_are_read(values[v], powers_suites[s]);
            for (size_t l = 0; l < POWERS_LENGTHS && failures == 0; l++) {
                powers_agree(values[v], powers_suites[s], powers_lengths[l]);
            }
        }
    }
    test_powers_store_residue();
    if (failures == 0) {
        (void)printf("ghash powers: %lu cases under %zu values of ch_cfg.cpu: the stored powers "
                     "are the reference's, an update stores the new key's, and a seal and an "
                     "open on them agree with the ones that compute them\n",
                     powers_cases, count);
    }
}

#endif // CH_AES_STORED_SCHEDULE
#endif
