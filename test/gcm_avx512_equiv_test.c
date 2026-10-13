// bin/gcm_avx512_equiv_test: gcm_avx512_kernel.c's whole AES-GCM seal and open against gcm.c's
// path on gcm_hw.c's 128-bit loops, byte for byte, and what the kernel leaves behind
// (docs/decisions.md 130). CBMC cannot read an intrinsic, so this binary is what holds the
// kernel: bin/ghash_equiv_test holds gcm_hw.c's loops to the portable GHASH the proofs cover.
//
//   - Equivalence. Each case seals and opens under two traffic keys from the same bytes: one whose
//     description of the CPU names the 512-bit kernel (CH_CPU_AVX512, CH_CPU_VAES and
//     CH_CPU_CONSTANT_TIME_AES) and one that names the AES bit alone. The kernel's ciphertext,
//     tag and plaintext must be the reference's. Each case seals out of place and in place, and
//     opens out of place, in place, below its ciphertext, and in record.c's layout, with the
//     plaintext written from the start of the 5-byte record header that is its associated data.
//     The bytes past n in every output buffer must stay as they were. A wrong tag, a flipped
//     ciphertext bit and a flipped associated-data bit must be refused, with the n output bytes
//     wiped to zero.
//   - Lengths: every payload length from 0 to 1,100 bytes, which puts each count of registers
//     and each partial register past a whole step through the kernel, under associated data of
//     0 to 40 bytes; the lengths each side of the first steps' ends, and of 16,384 and 16,385
//     bytes, a TLS record's; and random lengths up to MAX_DATA.
//   - The buffers' ends. The bytes past the last whole step load and store through byte masks.
//     Each case of a second pass puts its text, its output and its associated data so that each
//     ends on the last byte of a page whose next page has no access, so a load or a store of a
//     byte past any of them faults (test/gcm_avx512_residue.h).
//   - Depth and residue: how far below its caller a kernel call writes, which must lie inside
//     the GCM_AVX512_BELOW_LEN bytes the entry wipes, the stack after an entry's call, searched
//     for the values the residue header lists, which the call computed from the key, and zmm0 to
//     zmm31 and k1 to k7, which must read zero (test/gcm_avx512_residue.h).
//
// It runs where the kernel has a body, on x86-64, and skips on a CPU without what CH_CPU_AVX512
// names unless CH_REQUIRE_AVX512 is 1 (test/x86_kernels_cpu.h).
#include <stdio.h>
#include <stdlib.h>
#include <stdnoreturn.h>
#include <string.h>

#include "ch_assert.h"
#include "x86_kernels_cpu.h"

noreturn void ch_assert_fail(const char *cond, const char *file, int line) {
    (void)fprintf(stderr, "ASSERT %s:%d: %s\n", file, line, cond);
    abort();
}

#ifndef __x86_64__

int main(void) {
    (void)printf("SKIP gcm_avx512 equivalence: the 512-bit kernel is x86-64 only "
                 "(gcm_avx512.h)\n");
    return 0;
}

#else

#include "aes_traffic_key.h"
#include "cpu_cfg.h"
#include "ct.h"
#include "gcm.h"

#if !defined(CH_CPU_RUNTIME) || !defined(CH_SUITE_AES_GCM)
#error                                                                                             \
    "bin/gcm_avx512_equiv_test is a host object with the suite: -DCH_CPU_RUNTIME -DCH_SUITE_AES_GCM"
#endif

// The value that names the kernel, and the one that names the 128-bit loops.
#define KERNEL_CPU (CH_CPU_PROBED | CH_CPU_CONSTANT_TIME_AES | CH_CPU_VAES | CH_CPU_AVX512)
#define LOOPS_CPU (CH_CPU_PROBED | CH_CPU_CONSTANT_TIME_AES)

// The longest payload: past four of QUIC's largest datagrams' worth of steps, and 16 KiB records.
#define MAX_DATA 69000
#define MAX_AAD 300
// How far below its ciphertext the third open writes its plaintext, at most.
#define MAX_SHIFT 2048
// A TLS record's header, the associated data record.c hands the open (record.h's REC_HDR).
#define RECORD_HEADER 5
// The bytes after each output that must keep their value, and that value.
#define GUARD 64
#define UNWRITTEN 0xa5

static int failures = 0;
static unsigned long cases = 0;

// xorshift64 from a fixed seed, so a mismatch reproduces bit for bit.
static uint64_t rng_state = UINT64_C(0x9e3779b97f4a7c15);

static uint64_t rng_next(void) {
    uint64_t x = rng_state;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    rng_state = x;
    return x;
}

static void rng_fill(uint8_t *p, size_t n) {
    for (size_t i = 0; i < n; i++) {
        p[i] = (uint8_t)(rng_next() >> 56);
    }
}

static void fail(const char *what, size_t key_len, size_t aad_len, size_t n) {
    failures++;
    (void)fprintf(stderr, "FAIL %s: AES-%zu, associated data %zu bytes, payload %zu bytes\n", what,
                  8 * key_len, aad_len, n);
}

// The two keys of a case: the same bytes, the kernel's description and the loops'.
typedef struct {
    aes_traffic_key kernel;
    aes_traffic_key loops;
    size_t key_len;
} key_pair;

static void key_pair_init(key_pair *k, size_t key_len) {
    uint8_t key[AES_256_KEY];
    rng_fill(key, sizeof key);
    aes_traffic_key_init(&k->kernel, key, key_len);
    aes_traffic_key_init(&k->loops, key, key_len);
    aes_traffic_key_cpu(&k->kernel, KERNEL_CPU);
    aes_traffic_key_cpu(&k->loops, LOOPS_CPU);
    k->key_len = key_len;
}

static uint8_t plaintext[MAX_DATA];
static uint8_t want_ct[MAX_DATA];
static uint8_t out[MAX_DATA + GUARD];
static uint8_t shifted[MAX_SHIFT + MAX_DATA + GUARD];

// Whether the GUARD bytes at p kept UNWRITTEN.
static int untouched(const uint8_t *p) {
    for (size_t i = 0; i < GUARD; i++) {
        if (p[i] != UNWRITTEN) {
            return 0;
        }
    }
    return 1;
}

// Whether n bytes at p are zero.
static int all_zero(const uint8_t *p, size_t n) {
    for (size_t i = 0; i < n; i++) {
        if (p[i] != 0) {
            return 0;
        }
    }
    return 1;
}

// The kernel's open of want_ct with tag, out of place into out, as gcm.h promises it: the
// plaintext and 1 for the genuine tag, n zero bytes and 0 for any other, and the bytes past n
// unwritten either way.
static int open_out_of_place(const key_pair *k, const uint8_t nonce[AES_IV], const uint8_t *aad,
                             size_t aad_len, size_t n, const uint8_t tag[GCM_TAG], int genuine) {
    memset(out, UNWRITTEN, n + GUARD);
    int ok = gcm_traffic_open(&k->kernel, nonce, aad, aad_len, want_ct, n, tag, out);
    if (ok != genuine || !untouched(&out[n])) {
        return 0;
    }
    return genuine ? memcmp(out, plaintext, n) == 0 : all_zero(out, n);
}

// The seals of one case: the kernel's against the loops', out of place and in place.
static int seals_agree(const key_pair *k, const uint8_t nonce[AES_IV], const uint8_t *aad,
                       size_t aad_len, size_t n, uint8_t tag[GCM_TAG]) {
    uint8_t got_tag[GCM_TAG];
    gcm_traffic_seal(&k->loops, nonce, aad, aad_len, plaintext, n, want_ct, tag);
    memset(out, UNWRITTEN, n + GUARD);
    gcm_traffic_seal(&k->kernel, nonce, aad, aad_len, plaintext, n, out, got_tag);
    if (memcmp(out, want_ct, n) != 0 || memcmp(got_tag, tag, GCM_TAG) != 0 || !untouched(&out[n])) {
        return 0;
    }
    memcpy(out, plaintext, n);
    gcm_traffic_seal(&k->kernel, nonce, aad, aad_len, out, n, out, got_tag);
    return memcmp(out, want_ct, n) == 0 && memcmp(got_tag, tag, GCM_TAG) == 0 && untouched(&out[n]);
}

// The opens of one case in place and shift bytes below the ciphertext.
static int opens_overlapping(const key_pair *k, const uint8_t nonce[AES_IV], const uint8_t *aad,
                             size_t aad_len, size_t n, const uint8_t tag[GCM_TAG], size_t shift) {
    memcpy(out, want_ct, n);
    memset(&out[n], UNWRITTEN, GUARD);
    if (gcm_traffic_open(&k->kernel, nonce, aad, aad_len, out, n, tag, out) != 1 ||
        memcmp(out, plaintext, n) != 0 || !untouched(&out[n])) {
        return 0;
    }
    memcpy(&shifted[shift], want_ct, n);
    memset(&shifted[shift + n], UNWRITTEN, GUARD);
    return gcm_traffic_open(&k->kernel, nonce, aad, aad_len, &shifted[shift], n, tag, shifted) ==
               1 &&
           memcmp(shifted, plaintext, n) == 0;
}

// The open in record.c's layout: the 5-byte record header, which is the associated data, at the
// start of the buffer, the ciphertext right after it, and the plaintext written from the start,
// over the header and the ciphertext (record.c's open_aes_gcm). The ciphertext does not depend on
// the associated data, so want_ct serves, and the loops' seal under the header gives the tag.
static int open_over_header(const key_pair *k, const uint8_t nonce[AES_IV], size_t n) {
    uint8_t header[RECORD_HEADER];
    uint8_t tag[GCM_TAG];
    rng_fill(header, sizeof header);
    gcm_traffic_seal(&k->loops, nonce, header, RECORD_HEADER, plaintext, n, want_ct, tag);
    memcpy(shifted, header, RECORD_HEADER);
    memcpy(&shifted[RECORD_HEADER], want_ct, n);
    memset(&shifted[RECORD_HEADER + n], UNWRITTEN, GUARD);
    return gcm_traffic_open(&k->kernel, nonce, shifted, RECORD_HEADER, &shifted[RECORD_HEADER], n,
                            tag, shifted) == 1 &&
           memcmp(shifted, plaintext, n) == 0 && untouched(&shifted[RECORD_HEADER + n]);
}

// The refusals of one case: a wrong tag, a flipped ciphertext bit and a flipped
// associated-data bit.
static int refusals_hold(const key_pair *k, const uint8_t nonce[AES_IV], uint8_t *aad,
                         size_t aad_len, size_t n, const uint8_t tag[GCM_TAG]) {
    uint8_t wrong[GCM_TAG];
    memcpy(wrong, tag, GCM_TAG);
    wrong[rng_next() % GCM_TAG] ^= (uint8_t)(1U << (rng_next() % 8));
    if (!open_out_of_place(k, nonce, aad, aad_len, n, wrong, 0)) {
        return 0;
    }
    if (n > 0) {
        size_t bit = (size_t)(rng_next() % (8 * n));
        want_ct[bit / 8] ^= (uint8_t)(1U << (bit % 8));
        int refused = open_out_of_place(k, nonce, aad, aad_len, n, tag, 0);
        want_ct[bit / 8] ^= (uint8_t)(1U << (bit % 8));
        if (!refused) {
            return 0;
        }
    }
    if (aad_len > 0) {
        size_t bit = (size_t)(rng_next() % (8 * aad_len));
        aad[bit / 8] ^= (uint8_t)(1U << (bit % 8));
        int refused = open_out_of_place(k, nonce, aad, aad_len, n, tag, 0);
        aad[bit / 8] ^= (uint8_t)(1U << (bit % 8));
        return refused;
    }
    return 1;
}

// One case under a new key, nonce, associated data and payload of the given lengths.
static void run_case(size_t key_len, size_t aad_len, size_t n) {
    key_pair k;
    uint8_t nonce[AES_IV];
    uint8_t aad[MAX_AAD];
    uint8_t tag[GCM_TAG];
    key_pair_init(&k, key_len);
    rng_fill(nonce, sizeof nonce);
    rng_fill(aad, aad_len);
    rng_fill(plaintext, n);
    if (!seals_agree(&k, nonce, aad, aad_len, n, tag)) {
        fail("the kernel's seal differs from the loops' or wrote past n", key_len, aad_len, n);
    } else if (!open_out_of_place(&k, nonce, aad, aad_len, n, tag, 1)) {
        fail("the kernel's open out of place", key_len, aad_len, n);
    } else if (!opens_overlapping(&k, nonce, aad, aad_len, n, tag,
                                  1 + (size_t)(rng_next() % MAX_SHIFT))) {
        fail("the kernel's open in place or below its ciphertext", key_len, aad_len, n);
    } else if (!open_over_header(&k, nonce, n)) {
        fail("the kernel's open over a record's header", key_len, RECORD_HEADER, n);
    } else if (!refusals_hold(&k, nonce, aad, aad_len, n, tag)) {
        fail("the kernel took a wrong tag, ciphertext or associated data", key_len, aad_len, n);
    } else {
        cases++;
    }
    ct_wipe(&k, sizeof k);
}

// Every payload length up to 1,100 under several lengths of associated data, then the lengths
// each side of the ends of whole steps and of a TLS record, then random ones.
static void run_lengths(size_t key_len) {
    for (size_t n = 0; n <= 1100 && failures == 0; n++) {
        run_case(key_len, n % 41, n);
    }
    static const size_t steps[] = {1, 2, 3, 31, 32, 33, 127, 128, 134};
    static const int around[] = {-65, -64, -63, -17, -16, -15, -1, 0, 1, 15, 16, 17, 63, 64, 65};
    for (size_t s = 0; s < sizeof steps / sizeof steps[0]; s++) {
        for (size_t a = 0; a < sizeof around / sizeof around[0]; a++) {
            size_t n = (size_t)((long)(512 * steps[s]) + around[a]);
            run_case(key_len, (s + a) % 2 == 0 ? 5 : 13, n);
        }
    }
    run_case(key_len, 5, 16385);
    run_case(key_len, 0, MAX_DATA);
    for (int i = 0; i < 300 && failures == 0; i++) {
        size_t n = (size_t)(rng_next() % 17000);
        run_case(key_len, (size_t)(rng_next() % MAX_AAD), n);
    }
}

#include "gcm_avx512_residue.h"

int main(void) {
    if (!x86_cpu_has_avx512()) {
        if (x86_avx512_required()) {
            (void)fprintf(stderr, "gcm_avx512 equivalence: this CPU lacks what CH_CPU_AVX512 "
                                  "names, and CH_REQUIRE_AVX512 is 1\n");
            return 1;
        }
        (void)printf("SKIP gcm_avx512 equivalence: this CPU lacks what CH_CPU_AVX512 names\n");
        return 0;
    }
    run_lengths(AES_128_KEY);
    run_lengths(AES_256_KEY);
    run_page_ends();
    run_residue();
    if (failures != 0) {
        (void)printf("gcm_avx512 equivalence: %d failures\n", failures);
        return 1;
    }
    (void)printf("gcm_avx512 equivalence: %lu cases agree between the 512-bit kernel and the "
                 "128-bit loops, and %lu residue checks pass\n",
                 cases, residue_checks);
    return 0;
}

#endif // __x86_64__
