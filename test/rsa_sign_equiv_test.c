// A host object's RSA signer on 64-bit words against the portable code,
// which stays the reference (docs/decisions.md 95): the same inputs into
// both, the same bytes out.
//
// The private operation. A host object holds it twice: rsa_sp1 is
// rsa_sign.c's ladder on 32-bit words over n and d, the code a device
// object runs, and rsa_sign64_sp1 is rsa_sign64.c's, two fixed windows on
// 64-bit words over the primes, joined by the Chinese remainder theorem
// and checked with the public exponent. The ladder carries the CBMC
// lemmas, the Lean differential and the Wycheproof suite; this binary is
// what carries the other signer to the same answers on every input it
// tries:
//
//   - the four keys of test/rsa_sign_vectors.h, which openssl minted:
//     RSA-2048, RSA-2112, whose primes are half a word past a whole number
//     of 64-bit words, RSA-3072 and RSA-4096;
//   - under each, the messages 0, 1 and n - 1, whose signatures are
//     themselves, and random ones.
//
// The window, rsa_sign64_power, under moduli and exponents no key has.
// The ladder takes any odd modulus of 256 bytes with its top bit set and
// any exponent of that length, and 256 bytes is the longest prime the
// window takes, so there the two are compared directly: the exponents 0,
// 1, 2, 15, 16 and 17, which are each side of one digit, all ones, the top
// bit alone, every digit value in turn and zero high or low digits, and
// random moduli, exponents and messages. Under a modulus of a few words
// and an exponent of any length the ladder does not run, so the window is
// held to a square-and-multiply over rsa_mont64_mont_mul that reads one
// bit a step and keeps no table, and zero bytes ahead of an exponent must
// change nothing. bin/rsa_equiv_test holds that multiplication to the
// 32-bit arm.
//
// The PSS encoding around the private operation is rsa_sign.c's in both
// signers, and bin/rsa_sign_test_host signs the vectors' messages through
// rsa_sign64_pss and requires OpenSSL's bytes, and a fault's refusal.
//
// The wipes. test/rsa_sign_equiv_residue.h copies the stack that
// rsa_sign64_sp1 and rsa_sign64_key_ok left, after a signature, after a
// signature the check refused, and after the key test on a key it admits
// and on one it refuses, and requires no two words side by side of
// anything the call computed from the private key in the copy. It does
// the same after the reduction, the exponentiation and the recombination,
// each called on its own. test/rsa_sign_equiv_differential.h makes each
// of those calls under two secrets that a caller cannot tell apart and
// requires the two copies equal in every byte, which holds a value too
// short to look for. A binary built without optimization or under
// AddressSanitizer makes none of these runs and says why
// (test/stack_residue.c).
//
// The AVX-512 IFMA path (docs/decisions.md 120). Every case above that
// signs runs under a ch_cfg.cpu value with the multiply bit alone, which
// takes the window. On an x86-64 CPU with AVX-512 IFMA they run once more
// with CH_CPU_AVX512_IFMA beside it, which takes rsa_ifma_sign.c's
// exponentiations, the check on rsa_ifma.c and the wipes after both, so
// the residue and the differential runs hold those wipes too. A CPU
// without the instructions skips that pass and says so, and fails instead
// under CH_REQUIRE_AVX512_IFMA=1 (test/x86_kernels_cpu.h).
//
// The random values come from the seeded generator below, so an ordinary
// run replays exactly and the nightly can vary CH_RSA_EQUIV_SEED.
#include <stdio.h>
#include <stdlib.h>
#include <stdnoreturn.h>
#include <string.h>

#include "ch_assert.h"
#include "cpu_cfg.h"
#include "rsa_mont64.h"
#include "rsa_sign.h"
#include "rsa_sign64.h"
#include "rsa_sign_equiv_pieces.h"
#include "rsa_sign_key.h"
#include "x86_kernels_cpu.h"

noreturn void ch_assert_fail(const char *cond, const char *file, int line) {
    (void)fprintf(stderr, "ASSERT %s:%d: %s\n", file, line, cond);
    abort();
}

// xorshift64, as test/rsa_equiv_test.c writes it and for its reasons.
#define RSA_EQUIV_DEFAULT_SEED UINT64_C(0x9e3779b97f4a7c15)
static uint64_t rng_state = RSA_EQUIV_DEFAULT_SEED;

static uint64_t rng_seed_from_env(void) {
    const char *text = getenv("CH_RSA_EQUIV_SEED");
    if (text != NULL) {
        char *end = NULL;
        unsigned long long value = strtoull(text, &end, 0);
        if (end != text && *end == 0 && value != 0) {
            rng_state = (uint64_t)value;
        }
    }
    return rng_state;
}

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

static int failures = 0;
static unsigned long compared = 0;

static void print_hex(const char *name, const uint8_t *p, size_t n) {
    (void)fprintf(stderr, "  %s ", name);
    for (size_t i = 0; i < n; i++) {
        (void)fprintf(stderr, "%02x", p[i]);
    }
    (void)fprintf(stderr, "\n");
}

// The key every case writes into. It is static because it is 2 kB at the
// widest bound.
static ch_rsa_priv key;

// The ch_cfg.cpu value every signature here runs under: the multiply bit
// alone in the first pass, and with CH_CPU_AVX512_IFMA in the second.
#define EQUIV_WINDOW_CPU (CH_CPU_PROBED | CH_CPU_CONSTANT_TIME_MULTIPLY)
static uint32_t equiv_cpu = EQUIV_WINDOW_CPU;

// The length of the moduli the window is compared with the ladder under:
// the ladder's shortest, and the window's longest at this build's bound.
#define WINDOW_LEN 256

// A random odd modulus of WINDOW_LEN bytes with its top bit set, the shape
// rsa_sp1 takes, in key.n.
static void random_modulus(void) {
    memset(&key, 0, sizeof key);
    key.n_len = WINDOW_LEN;
    rng_fill(key.n, WINDOW_LEN);
    key.n[0] |= 0x80;
    key.n[WINDOW_LEN - 1] |= 1;
}

// A random message below key.n: random bytes with the top bit clear, which
// is below any modulus whose top bit is set.
static void random_message(uint8_t *em) {
    rng_fill(em, key.n_len);
    em[0] &= 0x7f;
}

// sig = em^d mod n by the window, for the n and d in key: the message
// into the Montgomery domain, rsa_sign64_power, and out again.
static void window_power(const uint8_t *em, uint8_t *sig) {
    rsa_mont64_modulus mod;
    uint64_t base[RSA_MONT64_WORDS_MAX] = {0};
    uint64_t power[RSA_MONT64_WORDS_MAX] = {0};
    uint64_t one[RSA_MONT64_WORDS_MAX] = {1};
    rsa_mont64_modulus_init(&mod, key.n, key.n_len, 8 * key.n_len);
    rsa_mont64_from_bytes(base, mod.words, em, key.n_len);
    rsa_mont64_mont_mul(base, base, mod.r2, &mod);
    rsa_sign64_power(power, base, key.d, key.n_len, &mod);
    rsa_mont64_mont_mul(power, one, power, &mod);
    rsa_mont64_to_bytes(sig, key.n_len, power);
}

static void report_mismatch(const char *case_name, const char *other, const uint8_t *em,
                            const uint8_t *ladder_out, const uint8_t *out) {
    failures++;
    (void)fprintf(stderr, "FAIL %s: the ladder and %s differ at %zu bytes\n", case_name, other,
                  key.n_len);
    print_hex("n     ", key.n, key.n_len);
    print_hex("d     ", key.d, key.n_len);
    print_hex("em    ", em, key.n_len);
    print_hex("ladder", ladder_out, key.n_len);
    print_hex("other ", out, key.n_len);
}

// key's n and d and one message into the ladder and the window. The
// outputs start from different bytes, so a side that wrote nothing cannot
// agree with the other by chance. out takes the window's answer.
static void compare_window(const char *case_name, const uint8_t *em, uint8_t *out) {
    uint8_t ladder_out[CH_RSA_MODULUS_MAX];
    memset(ladder_out, 0x55, sizeof ladder_out);
    memset(out, 0xaa, key.n_len);
    rsa_sp1(&key, em, ladder_out);
    window_power(em, out);
    if (memcmp(ladder_out, out, key.n_len) != 0) {
        report_mismatch(case_name, "the window", em, ladder_out, out);
        return;
    }
    compared++;
}

// compare_window, and the answer both must give.
static void compare_window_known(const char *case_name, const uint8_t *em, const uint8_t *want) {
    uint8_t out[CH_RSA_MODULUS_MAX];
    compare_window(case_name, em, out);
    if (memcmp(out, want, key.n_len) != 0) {
        failures++;
        (void)fprintf(stderr, "FAIL %s: both agree on a value that is not the power\n", case_name);
        print_hex("got ", out, key.n_len);
        print_hex("want", want, key.n_len);
    }
}

// key.d = the small value, in its last byte.
static void small_exponent(uint8_t value) {
    memset(key.d, 0, key.n_len);
    key.d[key.n_len - 1] = value;
}

// The exponents whose digits sit at an edge, each under one random modulus
// and one random message.
static void run_edge_exponents(void) {
    uint8_t em[CH_RSA_MODULUS_MAX];
    uint8_t out[CH_RSA_MODULUS_MAX];
    uint8_t one[CH_RSA_MODULUS_MAX] = {0};
    random_modulus();
    random_message(em);
    one[WINDOW_LEN - 1] = 1;

    small_exponent(0);
    compare_window_known("exponent 0", em, one);
    small_exponent(1);
    compare_window_known("exponent 1", em, em);
    static const uint8_t small[] = {2, 15, 16, 17};
    for (size_t i = 0; i < sizeof small; i++) {
        small_exponent(small[i]);
        compare_window("small exponent", em, out);
    }

    memset(key.d, 0xff, WINDOW_LEN);
    compare_window("exponent of all ones", em, out);

    memset(key.d, 0, WINDOW_LEN);
    key.d[0] = 0x80;
    compare_window("top bit alone", em, out);

    // Every digit value in turn: 0x01, 0x23, ... 0xef, repeated.
    for (size_t i = 0; i < WINDOW_LEN; i++) {
        key.d[i] = (uint8_t)(0x01 + 0x22 * (i % 8));
    }
    compare_window("every digit value", em, out);

    // A zero high digit over a random low digit in every byte, and the
    // other way around.
    rng_fill(key.d, WINDOW_LEN);
    for (size_t i = 0; i < WINDOW_LEN; i++) {
        key.d[i] &= 0x0f;
    }
    compare_window("zero high digits", em, out);
    rng_fill(key.d, WINDOW_LEN);
    for (size_t i = 0; i < WINDOW_LEN; i++) {
        key.d[i] &= 0xf0;
    }
    compare_window("zero low digits", em, out);

    for (int i = 0; i < 3; i++) {
        random_modulus();
        rng_fill(key.d, WINDOW_LEN);
        random_message(em);
        compare_window("random", em, out);
    }
}

// One message under a vector key into both signers, and the bytes both
// must write when want is not NULL.
static void compare_crt(const char *case_name, const uint8_t *em, const uint8_t *want) {
    uint8_t ladder_out[CH_RSA_MODULUS_MAX];
    uint8_t out[CH_RSA_MODULUS_MAX];
    memset(ladder_out, 0x55, sizeof ladder_out);
    memset(out, 0xaa, sizeof out);
    rsa_sp1(&key, em, ladder_out);
    if (!rsa_sign64_sp1(equiv_cpu, &key, em, out)) {
        failures++;
        (void)fprintf(stderr, "FAIL %s: the 64-bit signer refused its own signature at %zu bytes\n",
                      case_name, key.n_len);
        return;
    }
    if (memcmp(ladder_out, out, key.n_len) != 0) {
        report_mismatch(case_name, "the 64-bit signer", em, ladder_out, out);
        return;
    }
    if (want != NULL && memcmp(out, want, key.n_len) != 0) {
        failures++;
        (void)fprintf(stderr, "FAIL %s: both signers agree on a value that is not the power\n",
                      case_name);
        return;
    }
    compared++;
}

// The messages at an edge and random ones under one vector key. 0, 1 and
// n - 1 are their own signatures: the private exponent of an RSA key is
// odd and not zero.
static void run_key(const test_rsa_sign_key *from, int random_count) {
    if (from->n_len > CH_RSA_MODULUS_MAX) {
        return;
    }
    uint8_t em[CH_RSA_MODULUS_MAX];
    test_rsa_sign_key_load(&key, from);
    if (!rsa_sign64_key_ok(&key)) {
        failures++;
        (void)fprintf(stderr, "FAIL key: the 64-bit signer refuses a vector key of %zu bytes\n",
                      key.n_len);
        return;
    }

    memset(em, 0, key.n_len);
    compare_crt("message 0", em, em);
    em[key.n_len - 1] = 1;
    compare_crt("message 1", em, em);
    // n - 1: n is odd, so clearing its low bit subtracts one.
    memcpy(em, key.n, key.n_len);
    em[key.n_len - 1] &= 0xfe;
    compare_crt("message n - 1", em, em);

    for (int i = 0; i < random_count; i++) {
        random_message(em);
        compare_crt("random message", em, NULL);
    }
}

// o = base^e mod m in the Montgomery domain, one bit of e a step and no
// table: the reference for rsa_sign64_power at the sizes rsa_sp1 does not
// take. It is not constant time and nothing here is secret.
static void power_by_bits(uint64_t *o, const uint64_t *base, const uint8_t *e, size_t e_len,
                          const rsa_mont64_modulus *mod) {
    uint64_t one[RSA_MONT64_WORDS_MAX] = {1};
    rsa_mont64_mont_mul(o, one, mod->r2, mod);
    for (size_t bit = 8 * e_len; bit-- > 0;) {
        rsa_mont64_mont_mul(o, o, o, mod);
        if (((e[e_len - 1 - bit / 8] >> (bit % 8)) & 1) != 0) {
            rsa_mont64_mont_mul(o, o, base, mod);
        }
    }
}

// The window against power_by_bits under one random modulus of m_len
// bytes, for exponents of e_len bytes: random ones, all zeros and all
// ones, and each again behind three zero bytes.
static void run_window(size_t m_len, size_t e_len) {
    CH_ASSERT(m_len >= 1 && m_len <= CH_RSA_MODULUS_MAX && e_len <= CH_RSA_MODULUS_MAX);
    uint8_t m[CH_RSA_MODULUS_MAX] = {0};
    uint8_t e[CH_RSA_MODULUS_MAX + 3] = {0};
    rsa_mont64_modulus mod;
    uint64_t base[RSA_MONT64_WORDS_MAX];
    uint64_t want[RSA_MONT64_WORDS_MAX];
    uint64_t got[RSA_MONT64_WORDS_MAX];
    uint64_t padded[RSA_MONT64_WORDS_MAX];

    rng_fill(m, m_len);
    m[0] |= 0x80;
    m[m_len - 1] |= 1;
    rsa_mont64_modulus_init(&mod, m, m_len, 8 * m_len);
    size_t word_bytes = mod.words * sizeof(uint64_t);

    // A random base in the domain: random bytes with the top bit clear are
    // below m, and one multiplication by r2 moves them in.
    uint8_t bytes[CH_RSA_MODULUS_MAX];
    rng_fill(bytes, m_len);
    bytes[0] &= 0x7f;
    rsa_mont64_from_bytes(base, mod.words, bytes, m_len);
    rsa_mont64_mont_mul(base, base, mod.r2, &mod);

    for (int pattern = 0; pattern < 4; pattern++) {
        if (pattern < 2) {
            rng_fill(e + 3, e_len);
        } else {
            memset(e + 3, pattern == 2 ? 0x00 : 0xff, e_len);
        }
        power_by_bits(want, base, e + 3, e_len, &mod);
        rsa_sign64_power(got, base, e + 3, e_len, &mod);
        rsa_sign64_power(padded, base, e, e_len + 3, &mod);
        if (memcmp(want, got, word_bytes) != 0 || memcmp(want, padded, word_bytes) != 0) {
            failures++;
            (void)fprintf(stderr,
                          "FAIL window: a %zu-byte modulus and a %zu-byte exponent, pattern %d\n",
                          m_len, e_len, pattern);
            print_hex("m", m, m_len);
            print_hex("e", e + 3, e_len);
            continue;
        }
        compared += 2;
    }
}

#include "rsa_sign_equiv_residue.h"

// After the header above, whose copy of the stack and whose calls it uses.
#include "rsa_sign_equiv_differential.h"

// The runs over the stack a call left, under each of count keys, in a
// binary whose stack they can read: an optimized build without
// AddressSanitizer. Any other says why it makes none
// (test/stack_residue.c). make check builds such a binary, and the
// sanitizer lane does not. The residue runs come first: a signature and
// the key test, each again under a key it refuses, and the signature's
// pieces each on its own. Then the differential runs, which require one
// stack after two secrets.
static void run_stack(const test_rsa_sign_key *const *keys, size_t count) {
    const char *unsearched = stack_residue_unsearched();
    if (unsearched != NULL) {
        (void)printf("SKIP rsa_sign equivalence, the runs over the stack: %s\n", unsearched);
        return;
    }
    residue_run_from_env();
    for (size_t i = 0; i < count; i++) {
        for (int fault = 0; fault < 2; fault++) {
            run_residue(keys[i], fault);
            run_key_test_residue(keys[i], fault);
        }
        run_pieces_residue(keys[i]);
        run_differential(keys[i]);
    }
}

// Every case that signs: the stack runs and the four vector keys.
static void run_signatures(void) {
    static const test_rsa_sign_key key_2048 = TEST_RSA_SIGN_KEY(2048);
    static const test_rsa_sign_key key_2112 = TEST_RSA_SIGN_KEY(2112);
    static const test_rsa_sign_key key_3072 = TEST_RSA_SIGN_KEY(3072);
    static const test_rsa_sign_key key_4096 = TEST_RSA_SIGN_KEY(4096);

    static const test_rsa_sign_key *const stack_keys[] = {&key_2048, &key_2112, &key_4096};
    run_stack(stack_keys, sizeof stack_keys / sizeof stack_keys[0]);
    run_key(&key_2048, 3);
    run_key(&key_2112, 2);
    run_key(&key_3072, 1);
    run_key(&key_4096, 1);
}

#ifdef __x86_64__
// The second pass of run_signatures, on AVX-512 IFMA, where this CPU has
// it. Returns 0 when the CPU lacks it and the environment requires it.
static int run_ifma_signatures(void) {
    if (!x86_cpu_has_avx512_ifma()) {
        if (x86_ifma_required()) {
            (void)fprintf(stderr, "rsa_sign_equiv_test: this CPU lacks AVX-512 IFMA, and "
                                  "CH_REQUIRE_AVX512_IFMA is 1\n");
            return 0;
        }
        (void)printf("SKIP rsa_sign_equiv_test on AVX-512 IFMA: this CPU lacks it\n");
        return 1;
    }
    equiv_cpu = EQUIV_WINDOW_CPU | CH_CPU_AVX512_IFMA;
    run_signatures();
    equiv_cpu = EQUIV_WINDOW_CPU;
    (void)printf("rsa_sign_equiv_test: the private operation on AVX-512 IFMA ran\n");
    return 1;
}
#endif

int main(void) {
    uint64_t seed = rng_seed_from_env();
    run_signatures();
#ifdef __x86_64__
    if (!run_ifma_signatures()) {
        return 1;
    }
#endif
    run_edge_exponents();

    // Moduli of one word, of a word and a half, of the two halves of an
    // RSA-2048 and an RSA-2112 modulus, and exponents of one byte, of a
    // length that is no multiple of the word's, and of the modulus's.
    static const size_t modulus_lengths[] = {8, 12, 128, 132};
    for (size_t i = 0; i < sizeof modulus_lengths / sizeof modulus_lengths[0]; i++) {
        run_window(modulus_lengths[i], 1);
        run_window(modulus_lengths[i], 5);
        run_window(modulus_lengths[i], modulus_lengths[i]);
    }

    if (failures != 0) {
        (void)fprintf(stderr, "rsa_sign_equiv_test: %d failure(s), seed 0x%llx\n", failures,
                      (unsigned long long)seed);
        return 1;
    }
    (void)printf("rsa_sign_equiv_test: %lu comparisons of the private operation, seed 0x%llx, "
                 "all equal\n",
                 compared, (unsigned long long)seed);
    return 0;
}
