// ch_rsa_key_from_pem (pem_files.h) against files that OpenSSL wrote, and
// against keys this test writes from the 2048-bit key's integers
// (docs/decisions.md 184). The files are test/gen_pem_fixtures.py's.
//
// The 2048-bit and 3072-bit keys read, and the 4096-bit key reads where
// CH_RSA_MODULUS_MAX is 512 and is refused where it is 384. The 2048-bit
// key's integers equal the ones Python read from OpenSSL's DER, and the
// key signs a signature that verifies under its modulus. These are
// refused, each with the key zeroed:
//  - the PKCS #1 form, an id-RSASSA-PSS key, a three-prime key, a key
//    with the exponent 3, a P-256 key file and a 257-byte modulus;
//  - a leaf of another key, and a leaf that is not a certificate;
//  - a cpu value the object refuses;
//  - keys this test writes: a private exponent with one bit changed, a
//    prime with its top bit clear, an INTEGER with a leading zero octet
//    that is not canonical, a negative INTEGER, a CRT value one octet
//    too long, and a byte after the last INTEGER.
// The CRT values pass at their exact length: a value of n_len / 2 octets
// whose top bit is set reads, and one octet more is refused. Then the
// stack below each call holds no 8 bytes of d, p or q.
//
// The Makefile builds it as a ROLE=server device object, where the key
// holds n and d alone (bin/pem_files_rsa_test), and as a ROLE=both
// TRUST=webpki host object with CH_RSA_MODULUS_MAX 512, where it holds the
// five CRT values too. The host binary runs every case under two cpu
// values: CH_CPU_PROBED alone, which signs with rsa_sign.c's ladder, and
// with CH_CPU_CONSTANT_TIME_MULTIPLY, which signs with rsa_sign64.c.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ch_assert.h"
#include "cpu_cfg.h"
#include "ct.h"
#include "pem_armor.h"
#include "pem_files.h"
#include "pem_fixtures.h"
#include "pem_fixtures_rsa.h"
#include "rsa.h"
#include "rsa_sign.h"

static int failures = 0;
#define CHECK(cond)                                                                                \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            failures++;                                                                            \
            (void)fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);                  \
        }                                                                                          \
    } while (0)

noreturn void ch_assert_fail(const char *cond, const char *file, int line) {
    (void)fprintf(stderr, "ASSERT %s:%d: %s\n", file, line, cond);
    abort();
}

void stack_residue_take(volatile uint8_t *below, size_t n, uint8_t *copy);
const char *stack_residue_unsearched(void);

#ifdef CH_CPU_RUNTIME
static const uint32_t cpu_values[] = {CH_CPU_PROBED, CH_CPU_PROBED | CH_CPU_CONSTANT_TIME_MULTIPLY};
#define REFUSED_CPU 0U // no CH_CPU_PROBED
#define SIGNS_ON_LADDER(cpu) (((cpu) & CH_CPU_CONSTANT_TIME_MULTIPLY) == 0)
#else
// A device object takes 0 alone, and cpu_cfg.h defines no bit there.
static const uint32_t cpu_values[] = {0};
#define REFUSED_CPU 1U
#define SIGNS_ON_LADDER(cpu) ((void)(cpu), 1)
#endif

static ch_rsa_priv key;

static int key_zeroed(void) {
    const uint8_t *b = (const uint8_t *)&key;
    uint8_t any = 0;
    for (size_t i = 0; i < sizeof key; i++) {
        any |= b[i];
    }
    return any == 0;
}

static __attribute__((noinline)) int key_of(uint32_t cpu, const uint8_t *pem, size_t pem_len,
                                            const uint8_t *leaf, size_t leaf_len) {
    memset(&key, 0xa5, sizeof key);
    return ch_rsa_key_from_pem(cpu, pem, pem_len, leaf, leaf_len, &key);
}

// Whether the call refuses the file and zeroes the key.
static int refused(uint32_t cpu, const uint8_t *pem, size_t pem_len, const uint8_t *leaf,
                   size_t leaf_len) {
    return key_of(cpu, pem, pem_len, leaf, leaf_len) == CH_EINVAL && key_zeroed();
}

// One INTEGER of a key this test writes: content octets, as they go into
// the DER, so a test can write one that is not canonical.
typedef struct {
    uint8_t bytes[CH_RSA_MODULUS_MAX + 2];
    size_t len;
} integer;

// value, width bytes big-endian, as a canonical INTEGER: no leading zero
// octets, and one zero octet before a top bit that is set.
static integer canonical(const uint8_t *value, size_t width) {
    integer v = {{0}, 0};
    size_t start = 0;
    while (start + 1 < width && value[start] == 0) {
        start++;
    }
    if ((value[start] & 0x80) != 0) {
        v.bytes[v.len++] = 0;
    }
    memcpy(v.bytes + v.len, value + start, width - start);
    v.len += width - start;
    return v;
}

// A TLV header of tag and len at out. Returns its length.
static size_t header(uint8_t *out, uint8_t tag, size_t len) {
    out[0] = tag;
    if (len < 0x80) {
        out[1] = (uint8_t)len;
        return 2;
    }
    if (len < 0x100) {
        out[1] = 0x81;
        out[2] = (uint8_t)len;
        return 3;
    }
    out[1] = 0x82;
    out[2] = (uint8_t)(len >> 8);
    out[3] = (uint8_t)len;
    return 4;
}

// The integers of a key this test writes, in RSAPrivateKey's order, with
// the exponent written as 65537.
typedef struct {
    integer n, d, p, q, dp, dq, qinv;
} key_integers;

static key_integers fixture_integers(void) {
    key_integers k;
    k.n = canonical(pem_fixture_rsa2048_n, 256);
    k.d = canonical(pem_fixture_rsa2048_d, 256);
    k.p = canonical(pem_fixture_rsa2048_p, 128);
    k.q = canonical(pem_fixture_rsa2048_q, 128);
    k.dp = canonical(pem_fixture_rsa2048_dp, 128);
    k.dq = canonical(pem_fixture_rsa2048_dq, 128);
    k.qinv = canonical(pem_fixture_rsa2048_qinv, 128);
    return k;
}

static uint8_t body[2 * CH_PEM_RSA_KEY_DER_MAX];
static uint8_t der[2 * CH_PEM_RSA_KEY_DER_MAX];
static uint8_t file[4 * CH_PEM_RSA_KEY_DER_MAX];

// k as a PKCS #8 PrivateKeyInfo, with extra bytes after the last INTEGER,
// armoured as a PRIVATE KEY block in file. Returns the file's length.
static size_t write_key(const key_integers *k, size_t extra) {
    static const uint8_t version[] = {0x02, 0x01, 0x00};
    static const uint8_t exponent[] = {0x02, 0x03, 0x01, 0x00, 0x01};
    static const uint8_t algorithm[] = {0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,
                                        0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00};
    const integer *ints[] = {&k->n, &k->d, &k->p, &k->q, &k->dp, &k->dq, &k->qinv};
    size_t o = 0;
    memcpy(body + o, version, sizeof version);
    o += sizeof version;
    for (size_t i = 0; i < 7; i++) {
        o += header(body + o, 0x02, ints[i]->len);
        memcpy(body + o, ints[i]->bytes, ints[i]->len);
        o += ints[i]->len;
        if (i == 0) {
            memcpy(body + o, exponent, sizeof exponent);
            o += sizeof exponent;
        }
    }
    memset(body + o, 0, extra);
    o += extra;
    // RSAPrivateKey, then the OCTET STRING, then PrivateKeyInfo.
    size_t inner = header(der, 0x30, o);
    memmove(der + inner, body, o);
    inner += o;
    size_t outer_len = sizeof version + sizeof algorithm + 4 + inner;
    size_t w = header(body, 0x30, outer_len);
    memcpy(body + w, version, sizeof version);
    w += sizeof version;
    memcpy(body + w, algorithm, sizeof algorithm);
    w += sizeof algorithm;
    w += header(body + w, 0x04, inner);
    // gcc 15 reads no bound on inner here without this test, and refuses
    // the copy under -Wstringop-overflow.
    if (inner > sizeof der || inner > sizeof body - w) {
        return 0;
    }
    memcpy(body + w, der, inner);
    w += inner;
    return pem_armor_label("PRIVATE KEY", body, w, 64, "\n", file);
}

// Whether k, written as a file, reads under cpu against the 2048-bit
// key's leaf.
static int written_reads(uint32_t cpu, const key_integers *k, size_t extra) {
    size_t n = write_key(k, extra);
    return n != 0 &&
           key_of(cpu, file, n, pem_fixture_rsa2048_leaf, sizeof pem_fixture_rsa2048_leaf) == CH_OK;
}

static void test_files(uint32_t cpu) {
    const uint8_t *leaf = pem_fixture_rsa2048_leaf;
    const size_t leaf_len = sizeof pem_fixture_rsa2048_leaf;
    CHECK(key_of(cpu, pem_fixture_rsa2048, sizeof pem_fixture_rsa2048, leaf, leaf_len) == CH_OK);
    CHECK(key.n_len == 256 && memcmp(key.n, pem_fixture_rsa2048_n, 256) == 0 &&
          memcmp(key.d, pem_fixture_rsa2048_d, 256) == 0);
#ifdef CH_CPU_RUNTIME
    CHECK(memcmp(key.p, pem_fixture_rsa2048_p, 128) == 0 &&
          memcmp(key.q, pem_fixture_rsa2048_q, 128) == 0 &&
          memcmp(key.dp, pem_fixture_rsa2048_dp, 128) == 0 &&
          memcmp(key.dq, pem_fixture_rsa2048_dq, 128) == 0 &&
          memcmp(key.qinv, pem_fixture_rsa2048_qinv, 128) == 0);
#endif
    CHECK(key_of(cpu, pem_fixture_rsa3072, sizeof pem_fixture_rsa3072, pem_fixture_rsa3072_leaf,
                 sizeof pem_fixture_rsa3072_leaf) == CH_OK &&
          key.n_len == 384);
    int wide = key_of(cpu, pem_fixture_rsa4096, sizeof pem_fixture_rsa4096,
                      pem_fixture_rsa4096_leaf, sizeof pem_fixture_rsa4096_leaf);
#if CH_RSA_MODULUS_MAX >= 512
    CHECK(wide == CH_OK && key.n_len == 512);
#else
    CHECK(wide == CH_EINVAL && key_zeroed());
#endif
    CHECK(
        refused(cpu, pem_fixture_rsa2048_pkcs1, sizeof pem_fixture_rsa2048_pkcs1, leaf, leaf_len));
    CHECK(refused(cpu, pem_fixture_rsa_pss, sizeof pem_fixture_rsa_pss, leaf, leaf_len));
    CHECK(refused(cpu, pem_fixture_rsa2048_3prime, sizeof pem_fixture_rsa2048_3prime,
                  pem_fixture_rsa2048_3prime_leaf, sizeof pem_fixture_rsa2048_3prime_leaf));
    CHECK(refused(cpu, pem_fixture_rsa2048_e3, sizeof pem_fixture_rsa2048_e3,
                  pem_fixture_rsa2048_e3_leaf, sizeof pem_fixture_rsa2048_e3_leaf));
    CHECK(refused(cpu, pem_fixture_rsa2056, sizeof pem_fixture_rsa2056, pem_fixture_rsa2056_leaf,
                  sizeof pem_fixture_rsa2056_leaf));
    CHECK(refused(cpu, pem_fixture_key_pkcs8, sizeof pem_fixture_key_pkcs8, leaf, leaf_len));
    CHECK(refused(cpu, pem_fixture_rsa2048, sizeof pem_fixture_rsa2048,
                  pem_fixture_rsa2048_other_leaf, sizeof pem_fixture_rsa2048_other_leaf));
    CHECK(refused(cpu, pem_fixture_rsa2048, sizeof pem_fixture_rsa2048, pem_fixture_rsa2048_n,
                  sizeof pem_fixture_rsa2048_n));
}

// The key the call wrote signs, and the signature verifies under n.
static void test_signs(uint32_t cpu) {
    static uint8_t sig[CH_RSA_MODULUS_MAX];
    const uint8_t digest[32] = {1, 2, 3};
    const uint8_t salt[RSA_PSS_SALT_LEN] = {4, 5, 6};
    size_t sig_len = 0;
    CHECK(key_of(cpu, pem_fixture_rsa2048, sizeof pem_fixture_rsa2048, pem_fixture_rsa2048_leaf,
                 sizeof pem_fixture_rsa2048_leaf) == CH_OK);
    CHECK(rsa_pss_sign(&key, digest, salt, salt, sig, sizeof sig, &sig_len) == 1 && sig_len == 256);
    CHECK(rsa_pss_verify(pem_fixture_rsa2048_n, 256, digest, sig, sig_len) == 1);
}

static void test_written(uint32_t cpu) {
    key_integers k = fixture_integers();
    CHECK(written_reads(cpu, &k, 0));
    CHECK(memcmp(key.d, pem_fixture_rsa2048_d, 256) == 0);
    // One bit of d: the check signature does not verify.
    k.d.bytes[k.d.len - 1] ^= 0x02;
    CHECK(!written_reads(cpu, &k, 0) && key_zeroed());
    k = fixture_integers();
    // A prime with its top bit clear. Under the ladder no signature reads
    // p, so the top bit test alone refuses it.
    uint8_t half[128];
    memcpy(half, pem_fixture_rsa2048_p, sizeof half);
    half[0] &= 0x7f;
    k.p = canonical(half, sizeof half);
    CHECK(!written_reads(cpu, &k, 0) && key_zeroed());
    k = fixture_integers();
    // A leading zero octet before an octet whose top bit is clear.
    memmove(k.dq.bytes + 1, k.dq.bytes, k.dq.len);
    k.dq.bytes[0] = 0;
    k.dq.len++;
    CHECK(k.dq.bytes[1] < 0x80 && !written_reads(cpu, &k, 0) && key_zeroed());
    k = fixture_integers();
    // qinv with its zero octet dropped, or with its top bit set where it
    // had none, reads as a negative INTEGER.
    if (k.qinv.bytes[0] == 0) {
        memmove(k.qinv.bytes, k.qinv.bytes + 1, --k.qinv.len);
    } else {
        k.qinv.bytes[0] |= 0x80;
    }
    CHECK(!written_reads(cpu, &k, 0) && key_zeroed());
    k = fixture_integers();
    // dp at its field's length with its top bit set reads; one octet more
    // is refused. The value 2^1023 + dp mod 2^1023 has 128 octets, and a
    // ladder never reads dp. The 64-bit signer does, so there the check
    // signature does not verify.
    uint8_t wide[129] = {0};
    memcpy(wide + 1, pem_fixture_rsa2048_dp, 128);
    wide[1] |= 0x80;
    k.dp = canonical(wide + 1, 128);
    CHECK(k.dp.len == 129);
    int dp_read = written_reads(cpu, &k, 0);
    CHECK(dp_read == SIGNS_ON_LADDER(cpu));
    wide[0] = 0x01;
    k.dp = canonical(wide, sizeof wide);
    CHECK(k.dp.len == 129 && !written_reads(cpu, &k, 0) && key_zeroed());
    k = fixture_integers();
    CHECK(!written_reads(cpu, &k, 1) && key_zeroed());
}

static void test_cpu(void) {
    CHECK(refused(REFUSED_CPU, pem_fixture_rsa2048, sizeof pem_fixture_rsa2048,
                  pem_fixture_rsa2048_leaf, sizeof pem_fixture_rsa2048_leaf));
}

// The bytes the search reads below the caller: the call's frame, with the
// DER room, and the signer's frames.
#define RESIDUE_BYTES 32768
static uint8_t residue[RESIDUE_BYTES];

static __attribute__((noinline)) void snapshot(void) {
    volatile uint8_t below[RESIDUE_BYTES];
    stack_residue_take(below, RESIDUE_BYTES, residue);
}

static int residue_holds(const uint8_t *secret, size_t n) {
    for (size_t s = 0; s + 8 <= n; s += 4) {
        for (size_t i = 0; i + 8 <= RESIDUE_BYTES; i++) {
            if (memcmp(residue + i, secret + s, 8) == 0) {
                return 1;
            }
        }
    }
    return 0;
}

static int residue_holds_key(void) {
    return residue_holds(pem_fixture_rsa2048_d, 256) || residue_holds(pem_fixture_rsa2048_p, 128) ||
           residue_holds(pem_fixture_rsa2048_q, 128);
}

static void test_wipes(uint32_t cpu) {
    const char *reason = stack_residue_unsearched();
    if (reason != NULL) {
        (void)printf("pem_files_rsa_test: the stack is not searched: %s\n", reason);
        return;
    }
    // test_written's calls return key_integers by value, which hold d, p
    // and q. The first snapshot writes zero over what they left, so the
    // second reads what the call alone left.
    snapshot();
    CHECK(key_of(cpu, pem_fixture_rsa2048, sizeof pem_fixture_rsa2048, pem_fixture_rsa2048_leaf,
                 sizeof pem_fixture_rsa2048_leaf) == CH_OK);
    snapshot();
    CHECK(!residue_holds_key());
    CHECK(refused(cpu, pem_fixture_rsa2048, sizeof pem_fixture_rsa2048,
                  pem_fixture_rsa2048_other_leaf, sizeof pem_fixture_rsa2048_other_leaf));
    snapshot();
    CHECK(!residue_holds_key());
}

int main(void) {
    for (size_t i = 0; i < sizeof cpu_values / sizeof cpu_values[0]; i++) {
        test_files(cpu_values[i]);
        test_signs(cpu_values[i]);
        test_written(cpu_values[i]);
        test_wipes(cpu_values[i]);
    }
    test_cpu();
    ct_wipe(&key, sizeof key);
    if (failures != 0) {
        (void)fprintf(stderr, "pem_files_rsa_test: %d failure(s)\n", failures);
        return 1;
    }
    (void)printf("pem_files_rsa_test: OpenSSL's PKCS #8 keys read and sign, every refusal zeroes "
                 "the key, the stack holds no d, p or q: ok\n");
    return 0;
}
