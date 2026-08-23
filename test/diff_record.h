// Record protection differential section: ChaCha20, Poly1305, the RFC
// 8439 AEAD seal and open, the record layer's rec_seal, and the
// KeyUpdate traffic-secret step. Every row runs the C module and the
// Lean spec on the same input and compares the bytes.
// Included by test/diff_test.c after diff_driver.h (single translation unit).
#ifndef CH_DIFFRECORD_H
#define CH_DIFFRECORD_H

#include "aead.h"
#include "chacha20.h"
#include "poly1305.h"
#include "record.h"
#include "sha256.h"

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
// Deprotection, the direction the spec models as of Record.open?. Two
// families: a record this build sealed, which must open to the same
// plaintext and content type on both sides, and a record with one bit
// flipped, which must be refused on both. The C answers first and the
// spec must reproduce it, so a divergence in either direction shows.
static void diff_rec_open(void) {
    for (int i = 0; i < 200; i++) {
        uint8_t secret[SHA256_LEN];
        rng_fill(secret, sizeof secret);
        uint8_t pt[200];
        size_t n = rng_below(201);
        rng_fill(pt, n);
        // rec_open reads the content type off the end of the inner
        // plaintext after stripping zero padding (RFC 9846 §5.4), so a
        // zero type is not recoverable and stays out of the domain.
        uint8_t type = (uint8_t)(1 + rng_below(255));
        uint64_t seq = rng_next();
        if (seq >= UINT64_MAX - 1) {
            seq = UINT64_MAX - 2;
        }
        rec_dir writer;
        rec_dir_init(&writer, secret);
        writer.seq = seq;
        uint8_t rec[200 + REC_OVERHEAD];
        size_t record_len = 0;
        if (rec_seal(&writer, type, pt, n, rec, sizeof rec, &record_len) != 0) {
            die("rec_seal refused a sized buffer");
        }
        // One row in three flips a bit, so both sides must refuse.
        int tampered = rng_below(3) == 0;
        if (tampered) {
            size_t at = rng_below(record_len);
            rec[at] ^= (uint8_t)(1U << rng_below(8));
        }

        // One row in four reads at a different sequence number, which is a
        // different nonce (RFC 9846 §5.3) and so a different tag. Both
        // sides must refuse, and neither may be fooled into agreeing.
        uint64_t read_seq = seq;
        if (!tampered && rng_below(4) == 0) {
            read_seq = seq ^ (1 + (rng_next() & 0xffff));
            if (read_seq >= UINT64_MAX - 1) {
                read_seq = seq;
            }
        }
        rec_dir reader;
        rec_dir_init(&reader, secret);
        reader.seq = read_seq;
        uint8_t got[200 + 1];
        size_t got_len = 0;
        uint8_t got_type = 0;
        int rc = rec_open(&reader, rec, record_len, got, sizeof got, &got_len, &got_type);

        char secret_hex[65];
        (void)hex_encode(secret_hex, secret, sizeof secret);
        char rec_hex[2 * (200 + REC_OVERHEAD) + 1];
        (void)hex_encode(rec_hex, rec, record_len);
        char want[2 * (200 + 1) + 32];
        if (rc != 0) {
            (void)snprintf(want, sizeof want, "ERR rec_open reject");
        } else {
            char got_hex[2 * (200 + 1) + 1];
            (void)hex_encode(got_hex, got, got_len);
            (void)snprintf(want, sizeof want, "ok %u %s", (unsigned)got_type, got_hex);
        }
        char cmd[2 * (200 + REC_OVERHEAD) + 256];
        (void)snprintf(cmd, sizeof cmd, "rec_open %s %llu %s", secret_hex,
                       (unsigned long long)read_seq, rec_hex);
        expect(cmd, want);
    }
}

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

#endif
