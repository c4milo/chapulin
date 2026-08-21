// Differential oracle: drives the Lean executable spec (built as
// spec/.lake/build/bin/diffspec) over a blocking pipe line protocol and
// compares every C crypto module against it on deterministic
// pseudo-random inputs. Any divergence prints the request and both
// answers, then fails the build.
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#include "aead.h"
#include "ch_assert.h"
#include "chacha20.h"
#include "hkdf.h"
#include "keysched.h"
#include "poly1305.h"
#include "rand.h"
#include "record.h"
#include "sha256.h"
#include "testrand.h"
#include "x25519.h"

// Driver plumbing (PRNG, hex, spec pipe) and the P-256 and RSA sections
// live in sibling headers of this, the only translation unit.
#include "diffdrv.h"
#include "diffp256.h"
#include "diffrsa.h"
#include "diffx509.h"

noreturn void ch_assert_fail(const char *cond, const char *file, int line) {
    (void)fprintf(stderr, "ASSERT %s:%d: %s\n", file, line, cond);
    abort();
}

static void diff_sha256(void) {
    for (int i = 0; i < 300; i++) {
        uint8_t msg[200];
        size_t n = rng_below(201);
        rng_fill(msg, n);
        uint8_t d[SHA256_LEN];
        sha256_of(msg, n, d);
        char msg_hex[401];
        (void)hex_encode(msg_hex, msg, n);
        char want[65];
        (void)hex_encode(want, d, SHA256_LEN);
        char cmd[512];
        (void)snprintf(cmd, sizeof cmd, "sha256 %s", msg_hex);
        expect(cmd, want);
    }
}

static void diff_hmac(void) {
    for (int i = 0; i < 300; i++) {
        uint8_t key[200];
        size_t key_len = rng_below(201); // spans the B=64 hash-the-key edge
        rng_fill(key, key_len);
        uint8_t msg[200];
        size_t msg_len = rng_below(201);
        rng_fill(msg, msg_len);
        uint8_t mac[SHA256_LEN];
        hmac_sha256(key, key_len, msg, msg_len, mac);
        char key_hex[401];
        (void)hex_encode(key_hex, key, key_len);
        char msg_hex[401];
        (void)hex_encode(msg_hex, msg, msg_len);
        char want[65];
        (void)hex_encode(want, mac, SHA256_LEN);
        char cmd[1024];
        (void)snprintf(cmd, sizeof cmd, "hmac %s %s", key_hex, msg_hex);
        expect(cmd, want);
    }
}

static void diff_hkdf_extract(void) {
    for (int i = 0; i < 200; i++) {
        uint8_t salt[64];
        size_t salt_len = rng_below(65);
        rng_fill(salt, salt_len);
        uint8_t ikm[64];
        size_t ikm_len = rng_below(65);
        rng_fill(ikm, ikm_len);
        uint8_t prk[SHA256_LEN];
        hkdf_extract(salt, salt_len, ikm, ikm_len, prk);
        char salt_hex[129];
        (void)hex_encode(salt_hex, salt, salt_len);
        char ikm_hex[129];
        (void)hex_encode(ikm_hex, ikm, ikm_len);
        char want[65];
        (void)hex_encode(want, prk, SHA256_LEN);
        char cmd[512];
        (void)snprintf(cmd, sizeof cmd, "hkdf_extract %s %s", salt_hex, ikm_hex);
        expect(cmd, want);
    }
}

static void diff_hkdf_expand(void) {
    for (int i = 0; i < 200; i++) {
        uint8_t prk[SHA256_LEN];
        rng_fill(prk, sizeof prk);
        uint8_t info[64];
        size_t info_len = rng_below(65);
        rng_fill(info, info_len);
        size_t out_len = 1 + rng_below(64);
        uint8_t out[64];
        hkdf_expand(prk, info, info_len, out, out_len);
        char prk_hex[65];
        (void)hex_encode(prk_hex, prk, sizeof prk);
        char info_hex[129];
        (void)hex_encode(info_hex, info, info_len);
        char want[129];
        (void)hex_encode(want, out, out_len);
        char cmd[512];
        (void)snprintf(cmd, sizeof cmd, "hkdf_expand %s %s %zu", prk_hex, info_hex, out_len);
        expect(cmd, want);
    }
}

static void diff_expand_label(void) {
    static const char alnum[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    for (int i = 0; i < 200; i++) {
        uint8_t secret[SHA256_LEN];
        rng_fill(secret, sizeof secret);
        char label[HKDF_LABEL_MAX + 1];
        size_t label_len = 1 + rng_below(HKDF_LABEL_MAX);
        for (size_t j = 0; j < label_len; j++) {
            label[j] = alnum[rng_below(sizeof alnum - 1)];
        }
        label[label_len] = '\0';
        uint8_t ctx[32];
        size_t ctx_len = rng_below(33);
        rng_fill(ctx, ctx_len);
        size_t out_len = 1 + rng_below(64);
        uint8_t out[64];
        hkdf_expand_label(secret, label, ctx, ctx_len, out, out_len);
        char secret_hex[65];
        (void)hex_encode(secret_hex, secret, sizeof secret);
        char label_hex[2 * HKDF_LABEL_MAX + 1];
        (void)hex_encode(label_hex, (const uint8_t *)label, label_len);
        char ctx_hex[65];
        (void)hex_encode(ctx_hex, ctx, ctx_len);
        char want[129];
        (void)hex_encode(want, out, out_len);
        char cmd[512];
        (void)snprintf(cmd, sizeof cmd, "expand_label %s %s %s %zu", secret_hex, label_hex, ctx_hex,
                       out_len);
        expect(cmd, want);
    }

    // Boundary rows the random domain never reaches. The last valid
    // output length (255*HashLen, RFC 5869 §2.3) must agree byte for
    // byte; the first invalid length and unencodable label/context
    // fields (RFC 9846 §7.1 one-byte vectors) must be spec-side errors —
    // the C asserts on those inputs, so the spec is the comparable half.
    {
        uint8_t secret[SHA256_LEN] = {7};
        static uint8_t out[255 * SHA256_LEN];
        hkdf_expand_label(secret, "key", NULL, 0, out, sizeof out);
        char secret_hex[65];
        (void)hex_encode(secret_hex, secret, sizeof secret);
        static char want[2 * 255 * SHA256_LEN + 1];
        (void)hex_encode(want, out, sizeof out);
        static char cmd[2 * 255 * SHA256_LEN + 128];
        (void)snprintf(cmd, sizeof cmd, "expand_label %s 6b6579 - %d", secret_hex,
                       255 * SHA256_LEN);
        expect(cmd, want);
        (void)snprintf(cmd, sizeof cmd, "expand_label %s 6b6579 - %d", secret_hex,
                       255 * SHA256_LEN + 1);
        expect(cmd, "ERR expand_label len over 255*HashLen");
        char big[513];
        for (size_t i = 0; i < 250; i++) {
            big[2 * i] = '4';
            big[2 * i + 1] = '1';
        }
        big[500] = 0; // 250-byte label: "tls13 " prefix pushes it past 255
        (void)snprintf(cmd, sizeof cmd, "expand_label %s %s - 32", secret_hex, big);
        expect(cmd, "ERR expand_label label unencodable");
        for (size_t i = 0; i < 256; i++) {
            big[2 * i] = '0';
            big[2 * i + 1] = '0';
        }
        big[512] = 0; // 256-byte context: one over the one-byte vector
        (void)snprintf(cmd, sizeof cmd, "expand_label %s 6b6579 %s 32", secret_hex, big);
        expect(cmd, "ERR expand_label context unencodable");
    }
}

// The spec's schedule() must equal the C composition the handshake runs:
// ks_early -> ks_handshake (hello transcript) -> ks_master (finished
// transcript), per CONTRACT.md.
static void diff_schedule(void) {
    for (int i = 0; i < 100; i++) {
        uint8_t psk[32];
        rng_fill(psk, sizeof psk);
        uint8_t ecdhe[32];
        rng_fill(ecdhe, sizeof ecdhe);
        uint8_t hello[SHA256_LEN];
        rng_fill(hello, sizeof hello);
        uint8_t finished[SHA256_LEN];
        rng_fill(finished, sizeof finished);
        uint8_t early[SHA256_LEN];
        uint8_t binder[SHA256_LEN];
        ks_early(psk, sizeof psk, 0, early, binder);
        uint8_t handshake_secret[SHA256_LEN];
        uint8_t c_hs[SHA256_LEN];
        uint8_t s_hs[SHA256_LEN];
        ks_handshake(early, ecdhe, hello, handshake_secret, c_hs, s_hs);
        uint8_t master[SHA256_LEN];
        uint8_t c_ap[SHA256_LEN];
        uint8_t s_ap[SHA256_LEN];
        ks_master(handshake_secret, finished, master, c_ap, s_ap);
        char psk_hex[65];
        (void)hex_encode(psk_hex, psk, sizeof psk);
        char ecdhe_hex[65];
        (void)hex_encode(ecdhe_hex, ecdhe, sizeof ecdhe);
        char hello_hex[65];
        (void)hex_encode(hello_hex, hello, sizeof hello);
        char finished_hex[65];
        (void)hex_encode(finished_hex, finished, sizeof finished);
        char c_hs_hex[65];
        (void)hex_encode(c_hs_hex, c_hs, SHA256_LEN);
        char s_hs_hex[65];
        (void)hex_encode(s_hs_hex, s_hs, SHA256_LEN);
        char c_ap_hex[65];
        (void)hex_encode(c_ap_hex, c_ap, SHA256_LEN);
        char s_ap_hex[65];
        (void)hex_encode(s_ap_hex, s_ap, SHA256_LEN);
        char cmd[512];
        (void)snprintf(cmd, sizeof cmd, "schedule %s %s %s %s", psk_hex, ecdhe_hex, hello_hex,
                       finished_hex);
        char want[512];
        (void)snprintf(want, sizeof want, "%s %s %s %s", c_hs_hex, s_hs_hex, c_ap_hex, s_ap_hex);
        expect(cmd, want);
    }
}

static void diff_chacha20(void) {
    for (int i = 0; i < 200; i++) {
        uint8_t key[CHACHA20_KEY];
        rng_fill(key, sizeof key);
        uint8_t nonce[CHACHA20_NONCE];
        rng_fill(nonce, sizeof nonce);
        // Random start, capped so the 32-bit block counter never wraps
        // inside one message (RFC 8439 leaves wrap behavior to the caller).
        uint32_t counter = (uint32_t)rng_below(UINT64_C(0xffffff00));
        uint8_t data[300];
        size_t n = rng_below(301);
        rng_fill(data, n);
        uint8_t out[300];
        chacha20_xor(key, nonce, counter, data, out, n);
        char key_hex[65];
        (void)hex_encode(key_hex, key, sizeof key);
        char nonce_hex[25];
        (void)hex_encode(nonce_hex, nonce, sizeof nonce);
        char data_hex[601];
        (void)hex_encode(data_hex, data, n);
        char want[601];
        (void)hex_encode(want, out, n);
        char cmd[1024];
        (void)snprintf(cmd, sizeof cmd, "chacha20 %s %s %" PRIu32 " %s", key_hex, nonce_hex,
                       counter, data_hex);
        expect(cmd, want);
    }

    // Boundaries: the maximal counter over a single block (no wrap
    // inside the message) must agree; a counter past 32 bits has no C
    // representation and must be a spec-side error, never a wrap.
    {
        uint8_t key[CHACHA20_KEY] = {1};
        uint8_t nonce[CHACHA20_NONCE] = {2};
        uint8_t data[64];
        rng_fill(data, sizeof data);
        uint8_t out[64];
        chacha20_xor(key, nonce, 0xffffffffU, data, out, sizeof data);
        char key_hex[65];
        char nonce_hex[25];
        char data_hex[129];
        char want[129];
        (void)hex_encode(key_hex, key, sizeof key);
        (void)hex_encode(nonce_hex, nonce, sizeof nonce);
        (void)hex_encode(data_hex, data, sizeof data);
        (void)hex_encode(want, out, sizeof out);
        char cmd[512];
        (void)snprintf(cmd, sizeof cmd, "chacha20 %s %s 4294967295 %s", key_hex, nonce_hex,
                       data_hex);
        expect(cmd, want);
        (void)snprintf(cmd, sizeof cmd, "chacha20 %s %s 4294967296 00", key_hex, nonce_hex);
        expect(cmd, "ERR chacha20 counter over 32 bits");
    }
}

static void diff_poly1305(void) {
    for (int i = 0; i < 300; i++) {
        uint8_t key[POLY1305_KEY];
        rng_fill(key, sizeof key);
        uint8_t msg[200];
        size_t n = rng_below(201);
        rng_fill(msg, n);
        poly1305 p;
        poly1305_init(&p, key);
        poly1305_update(&p, msg, n);
        uint8_t tag[POLY1305_TAG];
        poly1305_final(&p, tag);
        char key_hex[65];
        (void)hex_encode(key_hex, key, sizeof key);
        char msg_hex[401];
        (void)hex_encode(msg_hex, msg, n);
        char want[33];
        (void)hex_encode(want, tag, sizeof tag);
        char cmd[512];
        (void)snprintf(cmd, sizeof cmd, "poly1305 %s %s", key_hex, msg_hex);
        expect(cmd, want);
    }
}

static void diff_aead_seal(void) {
    for (int i = 0; i < 200; i++) {
        uint8_t key[AEAD_KEY];
        rng_fill(key, sizeof key);
        uint8_t nonce[AEAD_NONCE];
        rng_fill(nonce, sizeof nonce);
        uint8_t aad[32];
        size_t aad_len = rng_below(33);
        rng_fill(aad, aad_len);
        uint8_t pt[200];
        size_t n = rng_below(201);
        rng_fill(pt, n);
        uint8_t sealed[200 + AEAD_TAG];
        aead_seal(key, nonce, aad, aad_len, pt, n, sealed, sealed + n);
        char key_hex[65];
        (void)hex_encode(key_hex, key, sizeof key);
        char nonce_hex[25];
        (void)hex_encode(nonce_hex, nonce, sizeof nonce);
        char aad_hex[65];
        (void)hex_encode(aad_hex, aad, aad_len);
        char pt_hex[401];
        (void)hex_encode(pt_hex, pt, n);
        char want[433];
        (void)hex_encode(want, sealed, n + AEAD_TAG);
        char cmd[1024];
        (void)snprintf(cmd, sizeof cmd, "aead_seal %s %s %s %s", key_hex, nonce_hex, aad_hex,
                       pt_hex);
        expect(cmd, want);
    }
}

static void diff_aead_open(void) {
    for (int i = 0; i < 200; i++) {
        uint8_t key[AEAD_KEY];
        rng_fill(key, sizeof key);
        uint8_t nonce[AEAD_NONCE];
        rng_fill(nonce, sizeof nonce);
        uint8_t aad[32];
        size_t aad_len = rng_below(33);
        rng_fill(aad, aad_len);
        uint8_t pt[200];
        size_t n = rng_below(201);
        rng_fill(pt, n);
        uint8_t ct[200];
        uint8_t tag[AEAD_TAG];
        aead_seal(key, nonce, aad, aad_len, pt, n, ct, tag);
        if (i % 2 == 1) { // corrupted-tag reject: flip one random tag byte
            tag[rng_below(AEAD_TAG)] ^= (uint8_t)(1 + rng_below(255));
        }
        uint8_t dec[200];
        char want[401];
        if (aead_open(key, nonce, aad, aad_len, ct, n, tag, dec)) {
            (void)hex_encode(want, dec, n);
        } else {
            (void)snprintf(want, sizeof want, "FAIL");
        }
        char key_hex[65];
        (void)hex_encode(key_hex, key, sizeof key);
        char nonce_hex[25];
        (void)hex_encode(nonce_hex, nonce, sizeof nonce);
        char aad_hex[65];
        (void)hex_encode(aad_hex, aad, aad_len);
        char ct_hex[401];
        (void)hex_encode(ct_hex, ct, n);
        char tag_hex[33];
        (void)hex_encode(tag_hex, tag, sizeof tag);
        char cmd[1024];
        (void)snprintf(cmd, sizeof cmd, "aead_open %s %s %s %s %s", key_hex, nonce_hex, aad_hex,
                       ct_hex, tag_hex);
        expect(cmd, want);
    }
}

static void diff_rec_seal(void) {
    for (int i = 0; i < 200; i++) {
        uint8_t secret[SHA256_LEN];
        rng_fill(secret, sizeof secret);
        uint8_t pt[200];
        size_t n = rng_below(201);
        rng_fill(pt, n);
        // Any sequence the C actually seals; it refuses UINT64_MAX to stop
        // before a wrap (RFC 9846 §5.5), which the pure spec does not model,
        // so that one value stays out of the compared domain.
        uint64_t seq = rng_next();
        if (seq == UINT64_MAX) {
            seq = UINT64_MAX - 1;
        }
        uint8_t type = (uint8_t)rng_below(256);
        rec_dir d;
        rec_dir_init(&d, secret);
        d.seq = seq; // force the sequence under test
        uint8_t rec[200 + REC_OVERHEAD];
        size_t record_len = 0;
        if (rec_seal(&d, type, pt, n, rec, sizeof rec, &record_len) != 0) {
            die("rec_seal refused a sized buffer");
        }
        char secret_hex[65];
        (void)hex_encode(secret_hex, secret, sizeof secret);
        char pt_hex[401];
        (void)hex_encode(pt_hex, pt, n);
        char want[2 * (200 + REC_OVERHEAD) + 1];
        (void)hex_encode(want, rec, record_len);
        char cmd[1024];
        (void)snprintf(cmd, sizeof cmd, "rec_seal %s %" PRIu64 " %u %s", secret_hex, seq, type,
                       pt_hex);
        expect(cmd, want);
    }

    // Boundaries: a full 2^14-byte plaintext (RFC 9846 §5.1's sender
    // cap) must agree end to end, and the wrap-guard sequence the C
    // refuses (§5.5) must be a spec-side error, never a truncation.
    {
        uint8_t secret[SHA256_LEN] = {9};
        static uint8_t pt[0x4000];
        rng_fill(pt, sizeof pt);
        rec_dir d;
        rec_dir_init(&d, secret);
        d.seq = 1;
        static uint8_t rec[0x4000 + REC_OVERHEAD];
        size_t record_len = 0;
        if (rec_seal(&d, 0x17, pt, sizeof pt, rec, sizeof rec, &record_len) != 0) {
            die("rec_seal refused the full-size plaintext");
        }
        char secret_hex[65];
        (void)hex_encode(secret_hex, secret, sizeof secret);
        static char pt_hex[2 * 0x4000 + 1];
        (void)hex_encode(pt_hex, pt, sizeof pt);
        static char want[2 * (0x4000 + REC_OVERHEAD) + 1];
        (void)hex_encode(want, rec, record_len);
        static char cmd[2 * 0x4000 + 256];
        (void)snprintf(cmd, sizeof cmd, "rec_seal %s 1 23 %s", secret_hex, pt_hex);
        expect(cmd, want);
        (void)snprintf(cmd, sizeof cmd, "rec_seal %s 18446744073709551615 23 00", secret_hex);
        expect(cmd, "ERR rec_seal seq at the wrap guard");
    }
}

// The KeyUpdate secret derivation (RFC 9846 §7.2). No third-party vector
// exists (RFC 8448 has no KeyUpdate) and e2e never triggers one, so this
// row is the derivation's only independent check.
static void diff_traffic_update(void) {
    for (int i = 0; i < 50; i++) {
        uint8_t secret[SHA256_LEN];
        rng_fill(secret, sizeof secret);
        char secret_hex[65];
        (void)hex_encode(secret_hex, secret, sizeof secret);
        rec_dir d;
        rec_dir_init(&d, secret);
        rec_dir_update(secret, &d); // advances the secret in place
        char want[65];
        (void)hex_encode(want, secret, sizeof secret);
        char cmd[128];
        (void)snprintf(cmd, sizeof cmd, "traffic_upd %s", secret_hex);
        expect(cmd, want);
    }
}

static void diff_x25519(void) {
    for (int i = 0; i < 100; i++) {
        uint8_t scalar[X25519_LEN];
        rng_fill(scalar, sizeof scalar);
        uint8_t point[X25519_LEN];
        rng_fill(point, sizeof point);
        uint8_t out[X25519_LEN];
        (void)x25519(out, scalar, point); // 0 = all-zero out; still comparable
        char key_hex[65];
        (void)hex_encode(key_hex, scalar, sizeof scalar);
        char point_hex[65];
        (void)hex_encode(point_hex, point, sizeof point);
        char want[65];
        (void)hex_encode(want, out, sizeof out);
        char cmd[512];
        (void)snprintf(cmd, sizeof cmd, "x25519 %s %s", key_hex, point_hex);
        expect(cmd, want);
    }
}

static void diff_x25519_base(void) {
    for (int i = 0; i < 50; i++) {
        uint8_t scalar[X25519_LEN];
        rng_fill(scalar, sizeof scalar);
        uint8_t out[X25519_LEN];
        x25519_base(out, scalar);
        char key_hex[65];
        (void)hex_encode(key_hex, scalar, sizeof scalar);
        char want[65];
        (void)hex_encode(want, out, sizeof out);
        char cmd[512];
        (void)snprintf(cmd, sizeof cmd, "x25519_base %s", key_hex);
        expect(cmd, want);
    }
}

int main(int argc, char **argv) {
    const char *path = argc > 1 ? argv[1] : "spec/.lake/build/bin/diffspec";
    spawn_spec(path);
    expect("selftest", "ok");
    diff_sha256();
    diff_hmac();
    diff_hkdf_extract();
    diff_hkdf_expand();
    diff_expand_label();
    diff_schedule();
    diff_chacha20();
    diff_poly1305();
    diff_aead_seal();
    diff_aead_open();
    diff_rec_seal();
    diff_traffic_update();
    diff_x25519();
    diff_x25519_base();
    diff_p256();
    diff_rsa();
    diff_x509();
    if (fclose(to_spec) != 0 || fclose(from_spec) != 0) {
        die("closing spec pipes failed");
    }
    int status = 0;
    (void)waitpid(spec_pid, &status, 0);
    (void)printf("diff: %ld comparisons, C == spec\n", comparisons);
    return 0;
}
