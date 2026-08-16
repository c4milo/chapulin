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
        char mh[401];
        (void)hex_enc(mh, msg, n);
        char want[65];
        (void)hex_enc(want, d, SHA256_LEN);
        char cmd[512];
        (void)snprintf(cmd, sizeof cmd, "sha256 %s", mh);
        expect(cmd, want);
    }
}

static void diff_hmac(void) {
    for (int i = 0; i < 300; i++) {
        uint8_t key[200];
        size_t keylen = rng_below(201); // spans the B=64 hash-the-key edge
        rng_fill(key, keylen);
        uint8_t msg[200];
        size_t msglen = rng_below(201);
        rng_fill(msg, msglen);
        uint8_t mac[SHA256_LEN];
        hmac_sha256(key, keylen, msg, msglen, mac);
        char kh[401];
        (void)hex_enc(kh, key, keylen);
        char mh[401];
        (void)hex_enc(mh, msg, msglen);
        char want[65];
        (void)hex_enc(want, mac, SHA256_LEN);
        char cmd[1024];
        (void)snprintf(cmd, sizeof cmd, "hmac %s %s", kh, mh);
        expect(cmd, want);
    }
}

static void diff_hkdf_extract(void) {
    for (int i = 0; i < 200; i++) {
        uint8_t salt[64];
        size_t saltlen = rng_below(65);
        rng_fill(salt, saltlen);
        uint8_t ikm[64];
        size_t ikmlen = rng_below(65);
        rng_fill(ikm, ikmlen);
        uint8_t prk[SHA256_LEN];
        hkdf_extract(salt, saltlen, ikm, ikmlen, prk);
        char sh[129];
        (void)hex_enc(sh, salt, saltlen);
        char ih[129];
        (void)hex_enc(ih, ikm, ikmlen);
        char want[65];
        (void)hex_enc(want, prk, SHA256_LEN);
        char cmd[512];
        (void)snprintf(cmd, sizeof cmd, "hkdf_extract %s %s", sh, ih);
        expect(cmd, want);
    }
}

static void diff_hkdf_expand(void) {
    for (int i = 0; i < 200; i++) {
        uint8_t prk[SHA256_LEN];
        rng_fill(prk, sizeof prk);
        uint8_t info[64];
        size_t infolen = rng_below(65);
        rng_fill(info, infolen);
        size_t outlen = 1 + rng_below(64);
        uint8_t out[64];
        hkdf_expand(prk, info, infolen, out, outlen);
        char ph[65];
        (void)hex_enc(ph, prk, sizeof prk);
        char ih[129];
        (void)hex_enc(ih, info, infolen);
        char want[129];
        (void)hex_enc(want, out, outlen);
        char cmd[512];
        (void)snprintf(cmd, sizeof cmd, "hkdf_expand %s %s %zu", ph, ih, outlen);
        expect(cmd, want);
    }
}

static void diff_expand_label(void) {
    static const char alnum[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    for (int i = 0; i < 200; i++) {
        uint8_t secret[SHA256_LEN];
        rng_fill(secret, sizeof secret);
        char label[HKDF_LABEL_MAX + 1];
        size_t lablen = 1 + rng_below(HKDF_LABEL_MAX);
        for (size_t j = 0; j < lablen; j++) {
            label[j] = alnum[rng_below(sizeof alnum - 1)];
        }
        label[lablen] = '\0';
        uint8_t ctx[32];
        size_t ctxlen = rng_below(33);
        rng_fill(ctx, ctxlen);
        size_t outlen = 1 + rng_below(64);
        uint8_t out[64];
        hkdf_expand_label(secret, label, ctx, ctxlen, out, outlen);
        char sh[65];
        (void)hex_enc(sh, secret, sizeof secret);
        char lh[2 * HKDF_LABEL_MAX + 1];
        (void)hex_enc(lh, (const uint8_t *)label, lablen);
        char ch[65];
        (void)hex_enc(ch, ctx, ctxlen);
        char want[129];
        (void)hex_enc(want, out, outlen);
        char cmd[512];
        (void)snprintf(cmd, sizeof cmd, "expand_label %s %s %s %zu", sh, lh, ch, outlen);
        expect(cmd, want);
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
        uint8_t fin[SHA256_LEN];
        rng_fill(fin, sizeof fin);
        uint8_t early[SHA256_LEN];
        uint8_t binder[SHA256_LEN];
        ks_early(psk, sizeof psk, 0, early, binder);
        uint8_t hs[SHA256_LEN];
        uint8_t c_hs[SHA256_LEN];
        uint8_t s_hs[SHA256_LEN];
        ks_handshake(early, ecdhe, hello, hs, c_hs, s_hs);
        uint8_t master[SHA256_LEN];
        uint8_t c_ap[SHA256_LEN];
        uint8_t s_ap[SHA256_LEN];
        ks_master(hs, fin, master, c_ap, s_ap);
        char ph[65];
        (void)hex_enc(ph, psk, sizeof psk);
        char eh[65];
        (void)hex_enc(eh, ecdhe, sizeof ecdhe);
        char h1[65];
        (void)hex_enc(h1, hello, sizeof hello);
        char h2[65];
        (void)hex_enc(h2, fin, sizeof fin);
        char w1[65];
        (void)hex_enc(w1, c_hs, SHA256_LEN);
        char w2[65];
        (void)hex_enc(w2, s_hs, SHA256_LEN);
        char w3[65];
        (void)hex_enc(w3, c_ap, SHA256_LEN);
        char w4[65];
        (void)hex_enc(w4, s_ap, SHA256_LEN);
        char cmd[512];
        (void)snprintf(cmd, sizeof cmd, "schedule %s %s %s %s", ph, eh, h1, h2);
        char want[512];
        (void)snprintf(want, sizeof want, "%s %s %s %s", w1, w2, w3, w4);
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
        char kh[65];
        (void)hex_enc(kh, key, sizeof key);
        char nh[25];
        (void)hex_enc(nh, nonce, sizeof nonce);
        char dh[601];
        (void)hex_enc(dh, data, n);
        char want[601];
        (void)hex_enc(want, out, n);
        char cmd[1024];
        (void)snprintf(cmd, sizeof cmd, "chacha20 %s %s %" PRIu32 " %s", kh, nh, counter, dh);
        expect(cmd, want);
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
        char kh[65];
        (void)hex_enc(kh, key, sizeof key);
        char mh[401];
        (void)hex_enc(mh, msg, n);
        char want[33];
        (void)hex_enc(want, tag, sizeof tag);
        char cmd[512];
        (void)snprintf(cmd, sizeof cmd, "poly1305 %s %s", kh, mh);
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
        size_t aadlen = rng_below(33);
        rng_fill(aad, aadlen);
        uint8_t pt[200];
        size_t n = rng_below(201);
        rng_fill(pt, n);
        uint8_t sealed[200 + AEAD_TAG];
        aead_seal(key, nonce, aad, aadlen, pt, n, sealed, sealed + n);
        char kh[65];
        (void)hex_enc(kh, key, sizeof key);
        char nh[25];
        (void)hex_enc(nh, nonce, sizeof nonce);
        char ah[65];
        (void)hex_enc(ah, aad, aadlen);
        char ph[401];
        (void)hex_enc(ph, pt, n);
        char want[433];
        (void)hex_enc(want, sealed, n + AEAD_TAG);
        char cmd[1024];
        (void)snprintf(cmd, sizeof cmd, "aead_seal %s %s %s %s", kh, nh, ah, ph);
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
        size_t aadlen = rng_below(33);
        rng_fill(aad, aadlen);
        uint8_t pt[200];
        size_t n = rng_below(201);
        rng_fill(pt, n);
        uint8_t ct[200];
        uint8_t tag[AEAD_TAG];
        aead_seal(key, nonce, aad, aadlen, pt, n, ct, tag);
        if (i % 2 == 1) { // corrupted-tag reject: flip one random tag byte
            tag[rng_below(AEAD_TAG)] ^= (uint8_t)(1 + rng_below(255));
        }
        uint8_t dec[200];
        char want[401];
        if (aead_open(key, nonce, aad, aadlen, ct, n, tag, dec)) {
            (void)hex_enc(want, dec, n);
        } else {
            (void)snprintf(want, sizeof want, "FAIL");
        }
        char kh[65];
        (void)hex_enc(kh, key, sizeof key);
        char nh[25];
        (void)hex_enc(nh, nonce, sizeof nonce);
        char ah[65];
        (void)hex_enc(ah, aad, aadlen);
        char ch[401];
        (void)hex_enc(ch, ct, n);
        char th[33];
        (void)hex_enc(th, tag, sizeof tag);
        char cmd[1024];
        (void)snprintf(cmd, sizeof cmd, "aead_open %s %s %s %s %s", kh, nh, ah, ch, th);
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
        // before a wrap (RFC 8446 §5.5), which the pure spec does not model,
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
        size_t recn = 0;
        if (rec_seal(&d, type, pt, n, rec, sizeof rec, &recn) != 0) {
            die("rec_seal refused a sized buffer");
        }
        char sh[65];
        (void)hex_enc(sh, secret, sizeof secret);
        char ph[401];
        (void)hex_enc(ph, pt, n);
        char want[2 * (200 + REC_OVERHEAD) + 1];
        (void)hex_enc(want, rec, recn);
        char cmd[1024];
        (void)snprintf(cmd, sizeof cmd, "rec_seal %s %" PRIu64 " %u %s", sh, seq, type, ph);
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
        char kh[65];
        (void)hex_enc(kh, scalar, sizeof scalar);
        char uh[65];
        (void)hex_enc(uh, point, sizeof point);
        char want[65];
        (void)hex_enc(want, out, sizeof out);
        char cmd[512];
        (void)snprintf(cmd, sizeof cmd, "x25519 %s %s", kh, uh);
        expect(cmd, want);
    }
}

static void diff_x25519_base(void) {
    for (int i = 0; i < 50; i++) {
        uint8_t scalar[X25519_LEN];
        rng_fill(scalar, sizeof scalar);
        uint8_t out[X25519_LEN];
        x25519_base(out, scalar);
        char kh[65];
        (void)hex_enc(kh, scalar, sizeof scalar);
        char want[65];
        (void)hex_enc(want, out, sizeof out);
        char cmd[512];
        (void)snprintf(cmd, sizeof cmd, "x25519_base %s", kh);
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
    diff_x25519();
    diff_x25519_base();
    diff_p256();
    diff_rsa();
    if (fclose(to_spec) != 0 || fclose(from_spec) != 0) {
        die("closing spec pipes failed");
    }
    int status = 0;
    (void)waitpid(spec_pid, &status, 0);
    (void)printf("diff: %ld comparisons, C == spec\n", comparisons);
    return 0;
}
