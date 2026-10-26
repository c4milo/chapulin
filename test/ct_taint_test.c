// The Valgrind taint lane (docs/decisions.md 155, INV-60), the method of ctgrind
// and TIMECOP. Each case marks its secret inputs undefined (CT_SECRET, test/ct_taint.h), runs
// one operation of a host object, and marks the outputs that the protocol publishes defined
// again (CT_PUBLIC) before it compares them with the expected bytes. Memcheck reports each
// conditional jump and each memory address that an undefined value decides. So under
// `valgrind --error-exitcode=1` a branch or a table index on a secret fails the run.
//
// The binary is a host object's code (-DCH_CPU_RUNTIME), and it takes one ch_cfg.cpu value as
// its argument (test/test_cpu.h). The Makefile runs it once for each value that picks another
// path on the machine's architecture (make ct-taint). A value whose instructions the CPU lacks
// ends the run with SKIP, and Valgrind's virtual CPU reports no AVX-512, so the values that name
// it end there under Valgrind.
//
// Each CT_PUBLIC call carries the reason the value is public. A case never marks a value public
// that the library keeps secret, and no Valgrind suppression file exists for this lane.
//
// The binary also runs outside Valgrind, where the marks do nothing and the comparisons alone
// run. So `make ct-taint` on a machine without Valgrind still runs each case once.
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdnoreturn.h>
#include <string.h>

#include "aead.h"
#include "aes.h"
#include "aes_traffic_key.h"
#include "base64.h"
#include "ch_assert.h"
#include "ct.h"
#include "ct_taint.h"
#include "ct_taint_cases.h"
#include "gcm.h"
#include "hkdf.h"
#include "keysched.h"
#include "pem_fixtures.h"
#include "sha256.h"
#include "sha3.h"
#include "sha512.h"
#include "test_cpu.h"

noreturn void ch_assert_fail(const char *cond, const char *file, int line) {
    (void)fprintf(stderr, "CH_ASSERT(%s) failed at %s:%d\n", cond, file, line);
    abort();
}

static int failures;

// Counts a case whose public output is not the expected one.
static void check(int ok, const char *what) {
    if (!ok) {
        (void)printf("FAIL %s\n", what);
        failures++;
    }
}

// A deterministic secret of n bytes: the bytes differ from case to case, so no case runs on
// zeros alone.
static void fill(uint8_t *p, size_t n, uint8_t seed) {
    for (size_t i = 0; i < n; i++) {
        p[i] = (uint8_t)(seed + 37U * (uint8_t)i);
    }
}

// ct_memeq on two secret buffers, equal and not equal. The verdict is the value a caller reads.
static void case_ct_memeq(void) {
    uint8_t a[64];
    uint8_t b[64];
    fill(a, sizeof a, 1);
    memcpy(b, a, sizeof b);
    CT_SECRET(a, sizeof a);
    CT_SECRET(b, sizeof b);
    uint32_t same = ct_memeq(a, b, sizeof a);
    b[63] ^= 1;
    uint32_t differ = ct_memeq(a, b, sizeof a);
    // Public: the verdict is what the caller sees.
    CT_PUBLIC(&same, sizeof same);
    CT_PUBLIC(&differ, sizeof differ);
    check(same != 0 && differ == 0, "ct_memeq");
}

// The hashes on secret input, at a length that runs whole blocks and a partial one. Each digest
// is public here, as a transcript hash is; a digest that stays secret (an HMAC key's) only
// feeds other cases below.
static void case_hashes(uint32_t cpu) {
    uint8_t in[300];
    uint8_t a[SHA512_LEN];
    uint8_t b[SHA512_LEN];
    fill(in, sizeof in, 2);
    CT_SECRET(in, sizeof in);
    sha256_of_cpu(cpu, in, sizeof in, a);
    CT_PUBLIC(a, SHA256_LEN);
    CT_PUBLIC(in, sizeof in);
    sha256_of(in, sizeof in, b);
    check(memcmp(a, b, SHA256_LEN) == 0, "sha256");

    CT_SECRET(in, sizeof in);
    sha384_of_cpu(cpu, in, sizeof in, a);
    CT_PUBLIC(a, SHA384_LEN);
    CT_PUBLIC(in, sizeof in);
    sha384_of(in, sizeof in, b);
    check(memcmp(a, b, SHA384_LEN) == 0, "sha384");

    CT_SECRET(in, sizeof in);
    sha512_of_cpu(cpu, in, sizeof in, a);
    CT_PUBLIC(a, SHA512_LEN);
    CT_PUBLIC(in, sizeof in);
    sha512_of(in, sizeof in, b);
    check(memcmp(a, b, SHA512_LEN) == 0, "sha512");

    CT_SECRET(in, sizeof in);
    sha3_256_cpu(cpu, in, sizeof in, a);
    CT_PUBLIC(a, SHA3_256_LEN);
    CT_PUBLIC(in, sizeof in);
    sha3_256(in, sizeof in, b);
    check(memcmp(a, b, SHA3_256_LEN) == 0, "sha3-256");

    CT_SECRET(in, sizeof in);
    sha3_512_cpu(cpu, in, sizeof in, a);
    CT_PUBLIC(a, SHA3_512_LEN);
    CT_PUBLIC(in, sizeof in);
    sha3_512(in, sizeof in, b);
    check(memcmp(a, b, SHA3_512_LEN) == 0, "sha3-512");

    shake s;
    shake256_init(&s);
    CT_SECRET(in, sizeof in);
    shake_absorb_cpu(cpu, &s, in, sizeof in);
    shake_squeeze_cpu(cpu, &s, a, sizeof a);
    CT_PUBLIC(a, sizeof a);
    CT_PUBLIC(in, sizeof in);
    shake256_init(&s);
    shake_absorb(&s, in, sizeof in);
    shake_squeeze(&s, b, sizeof b);
    check(memcmp(a, b, sizeof a) == 0, "shake256");
}

// HMAC, HKDF and the TLS 1.3 key schedule under both hashes, with a secret key, a secret input
// key and secret traffic secrets. Each output is a secret the record layer keys with, so a case
// publishes it only to compare it with the same call on the portable code.
static void case_key_schedule(uint32_t cpu, size_t hash_len) {
    uint8_t key[48];
    uint8_t msg[100];
    uint8_t transcript[48];
    uint8_t a[48];
    uint8_t b[48];
    fill(key, sizeof key, 3);
    fill(msg, sizeof msg, 4);
    fill(transcript, sizeof transcript, 5);

    CT_SECRET(key, sizeof key);
    CT_SECRET(msg, sizeof msg);
    hmac_cpu(cpu, hash_len, key, sizeof key, msg, sizeof msg, a);
    CT_PUBLIC(a, hash_len);
    CT_PUBLIC(key, sizeof key);
    CT_PUBLIC(msg, sizeof msg);
    hmac(hash_len, key, sizeof key, msg, sizeof msg, b);
    check(memcmp(a, b, hash_len) == 0, "hmac");

    uint8_t early[48];
    uint8_t binder[48];
    uint8_t hs[48];
    uint8_t c_hs[48];
    uint8_t s_hs[48];
    uint8_t master[48];
    uint8_t c_ap[48];
    uint8_t s_ap[48];
    uint8_t res[48];
    uint8_t psk[48];
    uint8_t finished[48];
    CT_SECRET(key, sizeof key);
    CT_SECRET(msg, sizeof msg);
    ks_early_cpu(cpu, hash_len, key, hash_len, 1, early, binder);
    ks_handshake_cpu(cpu, hash_len, early, msg, 32, transcript, hs, c_hs, s_hs);
    ks_master_cpu(cpu, hash_len, hs, transcript, master, c_ap, s_ap);
    ks_res_master_cpu(cpu, hash_len, master, transcript, res);
    ks_res_psk_cpu(cpu, hash_len, res, transcript, 8, psk);
    // Public: verify_data travels in the Finished message.
    ks_verify_data_cpu(cpu, hash_len, c_hs, transcript, finished);
    CT_PUBLIC(finished, hash_len);
    CT_PUBLIC(psk, hash_len);
    CT_PUBLIC(key, sizeof key);
    CT_PUBLIC(msg, sizeof msg);
    ks_early(hash_len, key, hash_len, 1, early, binder);
    ks_handshake(hash_len, early, msg, 32, transcript, hs, c_hs, s_hs);
    ks_master(hash_len, hs, transcript, master, c_ap, s_ap);
    ks_res_master(hash_len, master, transcript, res);
    ks_res_psk(hash_len, res, transcript, 8, b);
    check(memcmp(psk, b, hash_len) == 0, "key schedule");
    ks_verify_data(hash_len, c_hs, transcript, b);
    check(memcmp(finished, b, hash_len) == 0, "verify_data");

    CT_SECRET(key, sizeof key);
    hkdf_expand_label_cpu(cpu, hash_len, key, "key", NULL, 0, a, 32);
    CT_PUBLIC(a, 32);
    CT_PUBLIC(key, sizeof key);
    hkdf_expand_label(hash_len, key, "key", NULL, 0, b, 32);
    check(memcmp(a, b, 32) == 0, "hkdf_expand_label");
}

// ChaCha20-Poly1305 with a secret key and secret plaintext. The ciphertext and the tag travel
// in the record, and the open's verdict is the one the record layer acts on.
static void case_chacha20_poly1305(uint32_t cpu) {
    uint8_t key[AEAD_KEY];
    uint8_t nonce[AEAD_NONCE];
    uint8_t aad[13];
    uint8_t pt[600];
    uint8_t ct[600];
    uint8_t back[600];
    uint8_t tag[AEAD_TAG];
    fill(key, sizeof key, 6);
    fill(nonce, sizeof nonce, 7);
    fill(aad, sizeof aad, 8);
    fill(pt, sizeof pt, 9);
    CT_SECRET(key, sizeof key);
    CT_SECRET(pt, sizeof pt);
    aead_seal_cpu(cpu, key, nonce, aad, sizeof aad, pt, sizeof pt, ct, tag);
    // Public: the ciphertext and the tag travel in the record.
    CT_PUBLIC(ct, sizeof ct);
    CT_PUBLIC(tag, sizeof tag);
    int opened = aead_open_cpu(cpu, key, nonce, aad, sizeof aad, ct, sizeof ct, tag, back);
    // Public: the verdict is the one the record layer acts on.
    CT_PUBLIC(&opened, sizeof opened);
    CT_PUBLIC(back, sizeof back);
    CT_PUBLIC(pt, sizeof pt);
    check(opened == 1 && memcmp(back, pt, sizeof pt) == 0, "chacha20-poly1305 open");
    tag[0] ^= 1;
    opened = aead_open_cpu(cpu, key, nonce, aad, sizeof aad, ct, sizeof ct, tag, back);
    CT_PUBLIC(&opened, sizeof opened);
    check(opened == 0, "chacha20-poly1305 refusal");
}

// The longest text case_aes_gcm seals: 32 passes of 8 blocks and a partial block, so on arm64 the
// passes run two at a time (gcm_arm64_passes.h, docs/decisions.md 158).
#define AES_GCM_TEXT_MAX 4200

// AES-GCM under a traffic key, AES-128 and AES-256, on the instructions the session's
// CH_CPU_CONSTANT_TIME_AES names, over n bytes of text. A session without the bit holds no AES-GCM
// traffic key (suite.h), so the case runs only under the bit. The table cipher runs QUIC's public
// keys alone (INV-26), and no case here gives it a key.
static void case_aes_gcm(uint32_t cpu, size_t key_len, size_t n) {
    if ((cpu & CH_CPU_CONSTANT_TIME_AES) == 0) {
        return;
    }
    uint8_t key[32];
    uint8_t nonce[AES_IV];
    uint8_t aad[13];
    static uint8_t pt[AES_GCM_TEXT_MAX];
    static uint8_t ct[AES_GCM_TEXT_MAX];
    static uint8_t back[AES_GCM_TEXT_MAX];
    uint8_t tag[GCM_TAG];
    fill(key, sizeof key, 10);
    fill(nonce, sizeof nonce, 11);
    fill(aad, sizeof aad, 12);
    fill(pt, n, 13);
    aes_traffic_key k;
    CT_SECRET(key, sizeof key);
    CT_SECRET(pt, n);
    aes_traffic_key_init_cpu(&k, cpu, key, key_len);
    gcm_traffic_seal(&k, nonce, aad, sizeof aad, pt, n, ct, tag);
    // Public: the ciphertext and the tag travel in the record.
    CT_PUBLIC(ct, n);
    CT_PUBLIC(tag, sizeof tag);
    int opened = gcm_traffic_open(&k, nonce, aad, sizeof aad, ct, n, tag, back);
    // Public: the verdict is the one the record layer acts on.
    CT_PUBLIC(&opened, sizeof opened);
    CT_PUBLIC(back, n);
    CT_PUBLIC(pt, n);
    check(opened == 1 && memcmp(back, pt, n) == 0, "aes-gcm open");
    tag[0] ^= 1;
    opened = gcm_traffic_open(&k, nonce, aad, sizeof aad, ct, n, tag, back);
    CT_PUBLIC(&opened, sizeof opened);
    check(opened == 0, "aes-gcm refusal");
    ct_wipe(&k, sizeof k);
}

// base64.c's class of each byte of a P-256 key file in PKCS #8 form, the text that spells the
// scalar. Each class is public only as far as the text's layout goes: whether a byte is in the
// alphabet, a line end or padding. So the case publishes each class's test against 63, the one
// bit pem.c's body loop branches on, and requires the classes to spell the file's own bytes.
static void case_base64_key_file(void) {
    uint8_t text[sizeof pem_fixture_key_pkcs8];
    memcpy(text, pem_fixture_key_pkcs8, sizeof text);
    CT_SECRET(text, sizeof text);
    size_t alphabet = 0;
    for (size_t i = 0; i < sizeof text; i++) {
        uint8_t class = base64_class(text[i]);
        uint8_t outside = (uint8_t)(class > 63);
        // Public: whether a byte is outside the alphabet is the text's layout.
        CT_PUBLIC(&outside, sizeof outside);
        alphabet += outside == 0;
    }
    CT_PUBLIC(text, sizeof text);
    check(alphabet > 100, "base64 classes");
}

int main(int argc, char **argv) {
    test_take_cpu(argc, argv);
    uint32_t cpu = test_cpu;
    (void)printf("%s Valgrind\n", CT_UNDER_VALGRIND() ? "under" : "not under");
    case_ct_memeq();
    case_hashes(cpu);
    case_key_schedule(cpu, SHA256_LEN);
    case_key_schedule(cpu, SHA384_LEN);
    case_chacha20_poly1305(cpu);
    case_aes_gcm(cpu, AES_128_KEY, 600);
    case_aes_gcm(cpu, AES_256_KEY, 600);
    case_aes_gcm(cpu, AES_128_KEY, AES_GCM_TEXT_MAX);
    case_aes_gcm(cpu, AES_256_KEY, AES_GCM_TEXT_MAX);
    case_base64_key_file();
    failures += ct_taint_public_key_cases(cpu);
    if (failures != 0) {
        (void)printf("ct_taint_test: %d cases failed\n", failures);
        return 1;
    }
    (void)printf("ct_taint_test: every case ran\n");
    return 0;
}
