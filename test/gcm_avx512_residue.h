// bin/gcm_avx512_equiv_test's checks of where the 512-bit kernel reads, writes and leaves
// values: the buffers' ends, the depth of its frames, the stack after an entry's call and the
// vector and mask registers. test/gcm_avx512_equiv_test.c alone includes this file, on x86-64,
// after it defines the generator, fail, the key pair and the case buffers.
//
//   - Page ends: each text, output and associated data ends on the last byte of a page whose
//     next page has no access, for every payload length up to 600 bytes and for 16,385, so a
//     load or a store of one byte past any of them faults. The kernel's ciphertext, tag and
//     plaintext must be the loops' as well.
//   - Depth: the stack below a direct call of each of the kernel's four functions is painted
//     first, and the lowest byte the call changed must lie within GCM_AVX512_BELOW_LEN of its
//     caller, less 64 bytes for a caller at another alignment.
//   - Residue: after a seal and an open through gcm_avx512.c's entries, which wipe the stack and
//     the registers, the stack below the caller holds none of these values the call computed
//     from the key: each round key, the hash subkey H, H^k times x^-1 for k from 1 to 33,
//     E(K, J0), GHASH after the associated data, after each whole step and with the lengths
//     block, and the keystream E(K, counter block) of the first whole step's 32 blocks, of the
//     last two whole steps' 64 and of the 32 blocks past them, which hold every block the call's
//     last registers encrypt. The keystream of the steps between is not looked for. Each value is
//     looked for as SP 800-38D's 16 bytes, reversed, and with its two 8-byte halves exchanged in
//     both. And zmm0 to zmm31 and k1 to k7 read zero. The calls run 16,385 bytes, a 1-byte tail
//     that takes its keystream from the call's first register, and 16,884 bytes, a 500-byte tail
//     that runs on eight registers of its own. The same search after a direct call of the
//     kernel, with no wipe, prints what it finds and counts nothing: it says what the wipes are
//     there for. The values are computed after both copies of the stack are taken, so the frames
//     that compute them cannot leave them there first.
#ifndef CH_TEST_GCM_AVX512_RESIDUE_H
#define CH_TEST_GCM_AVX512_RESIDUE_H

#include <sys/mman.h>
#include <unistd.h>

#include "aes_block.h"
#include "avx512_wipe.h"
#include "gcm_avx512.h"
#include "gcm_avx512_kernel.h"

#define RESIDUE_BYTES 8192
#define RESIDUE_PAINT 0x5a
// The two payload lengths of the residue search: a 1-byte tail and a 500-byte tail past 32
// whole steps.
#define RESIDUE_N 16385
#define RESIDUE_N_LONG 16884
#define RESIDUE_AAD 13
#define VALUES_MAX 256

_Static_assert(RESIDUE_BYTES > GCM_AVX512_BELOW_LEN, "the copy reaches past the wipe");

static unsigned long residue_checks = 0;

// ---------------------------------------------------------------- page ends

// The address of the first byte past an accessible run of whole pages that holds at least len
// bytes: the next page has no access.
static uint8_t *guarded_end(size_t len) {
    size_t page = (size_t)sysconf(_SC_PAGESIZE);
    size_t pages = (len + page - 1) / page + 1;
    uint8_t *base =
        mmap(NULL, pages * page, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (base == MAP_FAILED || mprotect(base + (pages - 1) * page, page, PROT_NONE) != 0) {
        (void)fprintf(stderr, "gcm_avx512 equivalence: no guarded pages\n");
        exit(1);
    }
    return base + (pages - 1) * page;
}

// One case with each buffer at a page's end: the seal of plaintext and the open of its
// ciphertext under the kernel against the loops' seal.
static void page_end_case(const key_pair *k, uint8_t *text_end, uint8_t *out_end, uint8_t *aad_end,
                          size_t aad_len, size_t n) {
    uint8_t nonce[AES_IV];
    uint8_t tag[GCM_TAG];
    uint8_t got[GCM_TAG];
    rng_fill(nonce, sizeof nonce);
    rng_fill(aad_end - aad_len, aad_len);
    rng_fill(plaintext, n);
    gcm_traffic_seal(&k->loops, nonce, aad_end - aad_len, aad_len, plaintext, n, want_ct, tag);
    memcpy(text_end - n, plaintext, n);
    gcm_traffic_seal(&k->kernel, nonce, aad_end - aad_len, aad_len, text_end - n, n, out_end - n,
                     got);
    if (memcmp(out_end - n, want_ct, n) != 0 || memcmp(got, tag, GCM_TAG) != 0) {
        fail("the kernel's seal at the pages' ends", k->key_len, aad_len, n);
        return;
    }
    memcpy(text_end - n, want_ct, n);
    if (gcm_traffic_open(&k->kernel, nonce, aad_end - aad_len, aad_len, text_end - n, n, tag,
                         out_end - n) != 1 ||
        memcmp(out_end - n, plaintext, n) != 0) {
        fail("the kernel's open at the pages' ends", k->key_len, aad_len, n);
        return;
    }
    residue_checks++;
}

static void run_page_ends(void) {
    uint8_t *text_end = guarded_end(RESIDUE_N_LONG);
    uint8_t *out_end = guarded_end(RESIDUE_N_LONG);
    uint8_t *aad_end = guarded_end(MAX_AAD);
    static const size_t key_lens[2] = {AES_128_KEY, AES_256_KEY};
    for (size_t i = 0; i < 2; i++) {
        key_pair k;
        key_pair_init(&k, key_lens[i]);
        for (size_t n = 0; n <= 600 && failures == 0; n++) {
            page_end_case(&k, text_end, out_end, aad_end, n % 37, n);
        }
        page_end_case(&k, text_end, out_end, aad_end, 13, RESIDUE_N);
        page_end_case(&k, text_end, out_end, aad_end, 13, RESIDUE_N_LONG);
        ct_wipe(&k, sizeof k);
    }
}

// ---------------------------------------------------------------- values to look for

static struct {
    char name[48];
    uint8_t bytes[AES_BLOCK];
} values[VALUES_MAX];
static size_t value_count;

static void add_value(const char *name, size_t index, const uint8_t bytes[AES_BLOCK]) {
    CH_ASSERT(value_count < VALUES_MAX);
    (void)snprintf(values[value_count].name, sizeof values[value_count].name, "%s %zu", name,
                   index);
    memcpy(values[value_count].bytes, bytes, AES_BLOCK);
    value_count++;
}

// SP 800-38D §6.3's Algorithm 1: result = a times b in GF(2^128), bit by bit.
static void field_multiply(const uint8_t a[AES_BLOCK], const uint8_t b[AES_BLOCK],
                           uint8_t result[AES_BLOCK]) {
    uint8_t product[AES_BLOCK] = {0};
    uint8_t multiple[AES_BLOCK];
    memcpy(multiple, b, AES_BLOCK);
    for (size_t bit = 0; bit < (size_t)8 * AES_BLOCK; bit++) {
        if ((a[bit / 8] >> (7 - bit % 8)) & 1U) {
            for (size_t i = 0; i < AES_BLOCK; i++) {
                product[i] ^= multiple[i];
            }
        }
        int reduce = multiple[AES_BLOCK - 1] & 1;
        for (size_t i = AES_BLOCK - 1; i > 0; i--) {
            multiple[i] = (uint8_t)((multiple[i] >> 1) | (multiple[i - 1] << 7));
        }
        multiple[0] = (uint8_t)((multiple[0] >> 1) ^ (reduce ? 0xe1 : 0));
    }
    memcpy(result, product, AES_BLOCK);
}

// acc = (acc + the len bytes at p, zero-padded) times h, a block at a time.
static void ghash_blocks(uint8_t acc[AES_BLOCK], const uint8_t h[AES_BLOCK], const uint8_t *p,
                         size_t len) {
    for (size_t off = 0; off < len; off += AES_BLOCK) {
        for (size_t i = 0; i < AES_BLOCK && off + i < len; i++) {
            acc[i] ^= p[off + i];
        }
        field_multiply(acc, h, acc);
    }
}

// One block through the key's cipher, AES-128 or AES-256 by its round count.
static void cipher_one(const aes_traffic_key *k, const uint8_t input[AES_BLOCK],
                       uint8_t output[AES_BLOCK]) {
    if (k->key.rounds == AES_256_ROUNDS) {
        aes_cipher_block_256(k->key.round_keys, input, output);
    } else {
        aes_cipher_block(k->key.round_keys, input, output);
    }
}

// GHASH under h after the associated data, after each whole step of the n ciphertext bytes, and
// with the lengths block.
static void add_hash_sums(const uint8_t h[AES_BLOCK], const uint8_t *aad, const uint8_t *ct,
                          size_t n) {
    uint8_t acc[AES_BLOCK] = {0};
    ghash_blocks(acc, h, aad, RESIDUE_AAD);
    add_value("GHASH after the associated data", 0, acc);
    size_t steps = n / 512;
    for (size_t j = 0; j < steps; j++) {
        ghash_blocks(acc, h, &ct[512 * j], 512);
        add_value("GHASH after step", j, acc);
    }
    ghash_blocks(acc, h, &ct[512 * steps], n - 512 * steps);
    uint8_t lengths[AES_BLOCK] = {0};
    lengths[7] = (uint8_t)(8 * RESIDUE_AAD);
    for (size_t i = 0; i < 8; i++) {
        lengths[AES_BLOCK - 1 - i] = (uint8_t)(((uint64_t)n * 8U) >> (8 * i));
    }
    ghash_blocks(acc, h, lengths, AES_BLOCK);
    add_value("GHASH with the lengths block", 0, acc);
}

// The keystream of text block b of a call under k and nonce: E(K, counter block), whose last
// four bytes count b + 2 big-endian, since J0 counts 1 (SP 800-38D §7.1).
static void keystream_block(const aes_traffic_key *k, const uint8_t nonce[AES_IV], size_t b,
                            uint8_t keystream[AES_BLOCK]) {
    uint8_t counter[AES_BLOCK];
    memcpy(counter, nonce, AES_IV);
    uint32_t count = (uint32_t)b + 2U;
    for (size_t i = 0; i < 4; i++) {
        counter[AES_BLOCK - 1 - i] = (uint8_t)(count >> (8 * i));
    }
    cipher_one(k, counter, keystream);
}

// The keystream of the first whole step's 32 blocks, of the last two whole steps' 64 and of the
// 32 blocks past them. The blocks past the last whole step take a register of their own, or two,
// four or eight, and the call encrypts every counter block those registers hold, past the n
// bytes too; 32 blocks are the most eight registers hold. A 1-byte to 16-byte tail takes the
// keystream of the first of them, which the call's first register computes beside H and E(K, J0)
// whatever the length.
static void add_keystream(const aes_traffic_key *k, const uint8_t nonce[AES_IV], size_t n) {
    size_t past = n / 512 * 32;
    for (size_t b = 0; b < past + 32; b++) {
        if (b < 32 || b + 64 >= past) {
            uint8_t keystream[AES_BLOCK];
            keystream_block(k, nonce, b, keystream);
            add_value("keystream of block", b, keystream);
        }
    }
}

// The values of a call of n bytes under k that the search looks for: the file comment's list,
// from the call's key, nonce and associated data and its ciphertext.
static void collect_values(const aes_traffic_key *k, const uint8_t nonce[AES_IV],
                           const uint8_t *aad, const uint8_t *ct, size_t n) {
    static const uint8_t zero[AES_BLOCK] = {0};
    static const uint8_t inverse_x[AES_BLOCK] = {0xc2, [AES_BLOCK - 1] = 0x01};
    uint8_t h[AES_BLOCK];
    uint8_t block[AES_BLOCK];
    value_count = 0;
    for (size_t r = 0; r <= k->key.rounds; r++) {
        add_value("round key", r, &k->key.round_keys[r * AES_BLOCK]);
    }
    cipher_one(k, zero, h);
    add_value("H", 1, h);
    uint8_t power[AES_BLOCK];
    memcpy(power, h, AES_BLOCK);
    for (size_t p = 1; p <= 33; p++) {
        field_multiply(power, inverse_x, block);
        add_value("H^k times x^-1, k =", p, block);
        field_multiply(power, h, power);
    }
    uint8_t j0[AES_BLOCK] = {0};
    memcpy(j0, nonce, AES_IV);
    j0[AES_BLOCK - 1] = 1;
    cipher_one(k, j0, block);
    add_value("E(K, J0)", 0, block);
    add_hash_sums(h, aad, ct, n);
    add_keystream(k, nonce, n);
}

// ---------------------------------------------------------------- the stack and registers

// test/stack_residue.c, compiled as a source of its own.
void stack_residue_take(volatile uint8_t *below, size_t n, uint8_t *copy);
void stack_residue_fill(volatile uint8_t *below, size_t n, uint8_t value);
const char *stack_residue_unsearched(void);

// The stack below the caller after a direct call of the kernel, and after an entry's call.
static uint8_t residue_direct_copy[RESIDUE_BYTES];
static uint8_t residue_copy[RESIDUE_BYTES];

static __attribute__((noinline)) void residue_snapshot(uint8_t *copy) {
    volatile uint8_t below[RESIDUE_BYTES];
    stack_residue_take(below, RESIDUE_BYTES, copy);
}

static __attribute__((noinline)) void residue_paint(void) {
    volatile uint8_t below[RESIDUE_BYTES + 512];
    stack_residue_fill(below, sizeof below, RESIDUE_PAINT);
}

// zmm0 to zmm31 at 64 bytes each, then k1 to k7 at 8 bytes each, as they are, to
// registers_after.
#define STORE_VECTOR(n) "vmovdqu64 %%zmm" #n ", " #n "*64(%0)\n\t"
#define STORE_MASK(n, at) "kmovq %%k" #n ", " #at "(%0)\n\t"
static uint8_t registers_after[32 * 64 + 7 * 8];
static __attribute__((target("avx512f,avx512bw"), noinline)) void store_registers(void) {
    __asm__ volatile(
        STORE_VECTOR(0) STORE_VECTOR(1) STORE_VECTOR(2) STORE_VECTOR(3) STORE_VECTOR(4)
            STORE_VECTOR(5) STORE_VECTOR(6) STORE_VECTOR(7) STORE_VECTOR(8) STORE_VECTOR(9)
                STORE_VECTOR(10) STORE_VECTOR(11) STORE_VECTOR(12) STORE_VECTOR(13) STORE_VECTOR(14)
                    STORE_VECTOR(15) STORE_VECTOR(16) STORE_VECTOR(17) STORE_VECTOR(18)
                        STORE_VECTOR(19) STORE_VECTOR(20) STORE_VECTOR(21) STORE_VECTOR(22)
                            STORE_VECTOR(23) STORE_VECTOR(24) STORE_VECTOR(25) STORE_VECTOR(26)
                                STORE_VECTOR(27) STORE_VECTOR(28) STORE_VECTOR(29) STORE_VECTOR(30)
                                    STORE_VECTOR(31) STORE_MASK(1, 2048) STORE_MASK(2, 2056)
                                        STORE_MASK(3, 2064) STORE_MASK(4, 2072) STORE_MASK(5, 2080)
                                            STORE_MASK(6, 2088) STORE_MASK(7, 2096)
        :
        : "r"(registers_after)
        : "memory");
}

// The inputs and outputs of the call under test, static so that every call runs from one
// address with the same registers saved.
static key_pair residue_key;
static uint8_t residue_nonce[AES_IV];
static uint8_t residue_aad[RESIDUE_AAD];
static uint8_t residue_pt[RESIDUE_N_LONG];
static uint8_t residue_ct[RESIDUE_N_LONG];
static uint8_t residue_tag[GCM_TAG];
static size_t residue_n;
static int residue_open;
static int residue_direct;

// The call under test: a seal or an open through gcm_avx512.c's entries, which wipe the stack
// and the registers, or a direct call of the kernel, which wipes neither, and then the registers
// stored.
static __attribute__((noinline)) void call_under_test(void) {
    const aes_traffic_key *k = &residue_key.kernel;
    int big = k->key.rounds == AES_256_ROUNDS;
    if (!residue_direct && !residue_open) {
        gcm_seal_avx512(k->key.round_keys, k->key.rounds, residue_nonce, residue_aad, RESIDUE_AAD,
                        residue_pt, residue_n, residue_ct, residue_tag);
    } else if (!residue_direct) {
        gcm_open_avx512(k->key.round_keys, k->key.rounds, residue_nonce, residue_aad, RESIDUE_AAD,
                        residue_ct, residue_n, residue_pt, residue_tag);
    } else if (!residue_open) {
        (big ? gcm_avx512_seal_256 : gcm_avx512_seal_128)(k->key.round_keys, residue_nonce,
                                                          residue_aad, RESIDUE_AAD, residue_pt,
                                                          residue_n, residue_ct, residue_tag);
    } else {
        (big ? gcm_avx512_open_256 : gcm_avx512_open_128)(k->key.round_keys, residue_nonce,
                                                          residue_aad, RESIDUE_AAD, residue_ct,
                                                          residue_n, residue_pt, residue_tag);
    }
    store_registers();
}

// The four forms of one value the search looks for: SP 800-38D's 16 bytes, reversed, and each
// of those with its two 8-byte halves exchanged.
typedef struct {
    uint8_t form[4][AES_BLOCK];
} value_forms;

static void forms_of(size_t v, value_forms *forms) {
    for (size_t i = 0; i < AES_BLOCK; i++) {
        forms->form[0][i] = values[v].bytes[i];
        forms->form[1][i] = values[v].bytes[AES_BLOCK - 1 - i];
        forms->form[2][i] = values[v].bytes[(i + 8) % AES_BLOCK];
        forms->form[3][i] = values[v].bytes[AES_BLOCK - 1 - (i + 8) % AES_BLOCK];
    }
}

// The first of the four forms the len bytes at bytes hold at their lowest offset that holds
// one, or 4 when they hold none.
static size_t form_held(const uint8_t *bytes, size_t len, const value_forms *forms) {
    for (size_t at = 0; at + AES_BLOCK <= len; at++) {
        for (size_t f = 0; f < 4; f++) {
            if (memcmp(&bytes[at], forms->form[f], AES_BLOCK) == 0) {
                return f;
            }
        }
    }
    return 4;
}

// The values the snapshot or the registers hold, in any of the four forms, counted as failures
// where counted is set and printed either way.
static int values_held(const char *where, const uint8_t *bytes, size_t len, int counted) {
    int found = 0;
    for (size_t v = 0; v < value_count; v++) {
        value_forms forms;
        forms_of(v, &forms);
        size_t f = form_held(bytes, len, &forms);
        if (f < 4) {
            (void)fprintf(counted ? stderr : stdout, "%s %s holds %s, form %zu\n",
                          counted ? "FAIL" : "INFO", where, values[v].name, f);
            found = 1;
        }
    }
    return found;
}

// How far below its caller the direct call just made wrote, against the wipe's length.
static void check_depth(const char *what) {
    size_t depth = 0;
    for (size_t i = 0; i < RESIDUE_BYTES && depth == 0; i++) {
        if (residue_direct_copy[i] != RESIDUE_PAINT) {
            depth = RESIDUE_BYTES - i;
        }
    }
    (void)printf("gcm_avx512 %s: writes %zu bytes below its caller, and the entry wipes %d\n", what,
                 depth, GCM_AVX512_BELOW_LEN);
    if (depth == 0 || depth + 64 > GCM_AVX512_BELOW_LEN) {
        failures++;
        (void)fprintf(stderr, "FAIL depth: %s writes %zu bytes below its caller\n", what, depth);
        return;
    }
    residue_checks++;
}

// One direction under one key: a direct call of the kernel and an entry's call, each with the
// stack below copied after it, then the depth and the unwiped residue of the first, and the
// residue and the registers after the second.
static void residue_direction(const char *what, int open) {
    residue_open = open;
    residue_direct = 1;
    residue_paint();
    call_under_test();
    residue_snapshot(residue_direct_copy);
    avx512_wipe_registers();
    residue_direct = 0;
    call_under_test();
    residue_snapshot(residue_copy);
    check_depth(what);
    collect_values(&residue_key.kernel, residue_nonce, residue_aad, residue_ct, residue_n);
    (void)values_held(what, residue_direct_copy, RESIDUE_BYTES, 0);
    char where[128];
    (void)snprintf(where, sizeof where, "the stack after the entry's %s", what);
    int held = values_held(where, residue_copy, RESIDUE_BYTES, 1);
    for (size_t i = 0; i < sizeof registers_after; i++) {
        held |= registers_after[i] != 0;
    }
    if (held) {
        failures++;
        (void)fprintf(stderr,
                      "FAIL residue: %s left a value on the stack or a register that "
                      "is not zero\n",
                      what);
        return;
    }
    residue_checks++;
}

static void run_residue(void) {
    const char *unsearched = stack_residue_unsearched();
    if (unsearched != NULL) {
        (void)printf("gcm_avx512 equivalence: no search of the stack: %s\n", unsearched);
        return;
    }
    static const size_t key_lens[2] = {AES_128_KEY, AES_256_KEY};
    static const size_t lengths[2] = {RESIDUE_N, RESIDUE_N_LONG};
    for (size_t i = 0; i < 2; i++) {
        key_pair_init(&residue_key, key_lens[i]);
        rng_fill(residue_nonce, sizeof residue_nonce);
        rng_fill(residue_aad, sizeof residue_aad);
        rng_fill(residue_pt, sizeof residue_pt);
        for (size_t l = 0; l < 2; l++) {
            residue_n = lengths[l];
            gcm_traffic_seal(&residue_key.loops, residue_nonce, residue_aad, RESIDUE_AAD,
                             residue_pt, residue_n, residue_ct, residue_tag);
            char what[64];
            (void)snprintf(what, sizeof what, "AES-%zu seal of %zu bytes", 8 * key_lens[i],
                           residue_n);
            residue_direction(what, 0);
            (void)snprintf(what, sizeof what, "AES-%zu open of %zu bytes", 8 * key_lens[i],
                           residue_n);
            residue_direction(what, 1);
        }
    }
    ct_wipe(&residue_key, sizeof residue_key);
}

#endif
