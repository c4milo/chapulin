// Property rows for the record read path, which no differential row can
// reach.
//
// A differential row asks whether the C computes the same answer as the
// spec, so it only covers what the spec models. spec/CONTRACT.md is
// explicit that it models no `Record.open`: deprotection lives in the C
// read path alone. `rec_open` therefore has an oracle for nothing it
// does, and test/unit_test.c reaches it with hand-written cases only.
//
// These rows put the seeded generator behind it: every plaintext length,
// content type, sequence number and tamper position the nightly seed
// search reaches. The rules come from what the spec proves about
// `Record.seal` — the round trip at the AEAD layer, and that a changed
// tag opens to nothing — read back through the C's own opener.
//
// Included by diff_test.c only, after diff_driver.h.
#ifndef CH_DIFF_PROPERTY_H
#define CH_DIFF_PROPERTY_H

#include "record.h"
#include "tls.h"

static long property_rows;

static void property_fail(const char *rule, const char *detail) {
    (void)fprintf(stderr, "property: %s\n  %s\n  replay with CH_DIFF_SEED=0x%016llx\n", rule,
                  detail, (unsigned long long)rng_state);
    exit(1);
}

// Seals one record under a fresh key at a drawn sequence number, and
// hands back a reader positioned to open it.
static size_t property_seal_one(rec_dir *reader, uint8_t *rec, size_t cap, const uint8_t *pt,
                                size_t n, uint8_t type, uint64_t seq) {
    uint8_t secret[SHA256_LEN];
    rng_fill(secret, sizeof secret);
    rec_dir writer;
    rec_dir_init(&writer, secret);
    rec_dir_init(reader, secret);
    writer.seq = seq;
    reader->seq = seq;
    size_t len = 0;
    if (rec_seal(&writer, type, pt, n, rec, cap, &len) != CH_OK) {
        property_fail("rec_seal refused a record inside its own limits", "");
    }
    return len;
}

// Spec.Record.aeadOpen_seal proves the sealed bytes open back to the
// plaintext and its content type at the AEAD layer. The C carries that
// through rec_open, which the spec does not model, so the round trip is
// checked here against the C's own opener.
static void property_record_round_trip(void) {
    for (int i = 0; i < 300; i++) {
        // One byte of headroom: the opened inner plaintext is the content
        // plus its type octet. The last content byte is forced nonzero
        // because RFC 9846 §5.4 pads with zeros and rec_open strips them,
        // so a plaintext ending in zero is not distinguishable from one
        // that was padded — the round trip cannot hold there.
        uint8_t pt[511];
        size_t n = rng_below(sizeof pt + 1);
        rng_fill(pt, n);
        if (n > 0 && pt[n - 1] == 0) {
            pt[n - 1] = 1;
        }
        uint8_t type = rng_below(2) == 0 ? REC_APPDATA : REC_HANDSHAKE;
        uint64_t seq = (rng_next() << 32) ^ rng_next();
        static uint8_t rec[1024];
        rec_dir reader;
        size_t len = property_seal_one(&reader, rec, sizeof rec, pt, n, type, seq);

        static uint8_t got[512];
        size_t got_len = 0;
        uint8_t got_type = 0;
        if (rec_open(&reader, rec, len, got, sizeof got, &got_len, &got_type) != CH_OK) {
            property_fail("a record this build sealed did not open", "");
        }
        if (got_len != n || (n != 0 && memcmp(got, pt, n) != 0) || got_type != type) {
            property_fail("the opened record is not what was sealed",
                          "the round trip must return the plaintext and its type");
        }
        property_rows++;
    }
}

// Spec.Aead.open?_ne_tag proves a changed tag opens to nothing. Every
// byte of a sealed record is covered by the tag or is the tag, so
// changing any one of them must make rec_open refuse.
static void property_record_tamper_refused(void) {
    for (int i = 0; i < 300; i++) {
        uint8_t pt[128];
        size_t n = 1 + rng_below(sizeof pt);
        rng_fill(pt, n);
        uint64_t seq = (rng_next() << 32) ^ rng_next();
        static uint8_t rec[512];
        rec_dir reader;
        size_t len = property_seal_one(&reader, rec, sizeof rec, pt, n, REC_APPDATA, seq);

        // Flip one bit anywhere in the record, header included.
        size_t at = rng_below(len);
        rec[at] ^= (uint8_t)(1U << rng_below(8));

        static uint8_t got[128];
        size_t got_len = 0;
        uint8_t got_type = 0;
        if (rec_open(&reader, rec, len, got, sizeof got, &got_len, &got_type) == CH_OK) {
            property_fail("a tampered record opened", "one flipped bit must fail the tag check");
        }
        property_rows++;
    }
}

// A reader whose sequence number ran ahead of the sealer computes a
// different nonce, so the tag cannot verify. This is the read-path half
// of Spec.Record.nonce_inj: distinct sequence numbers never agree.
static void property_record_sequence_bound(void) {
    for (int i = 0; i < 200; i++) {
        uint8_t pt[64];
        size_t n = 1 + rng_below(sizeof pt);
        rng_fill(pt, n);
        uint64_t seq = (rng_next() << 32) ^ rng_next();
        static uint8_t rec[256];
        rec_dir reader;
        size_t len = property_seal_one(&reader, rec, sizeof rec, pt, n, REC_APPDATA, seq);

        uint64_t skew = 1 + (rng_next() & 0xffff);
        reader.seq = seq + skew; // wraps harmlessly; still not seq
        static uint8_t got[64];
        size_t got_len = 0;
        uint8_t got_type = 0;
        if (reader.seq != seq &&
            rec_open(&reader, rec, len, got, sizeof got, &got_len, &got_type) == CH_OK) {
            property_fail("a record opened under the wrong sequence number",
                          "the nonce carries the sequence number, so it must not");
        }
        property_rows++;
    }
}

static void diff_properties(void) {
    property_record_round_trip();
    property_record_tamper_refused();
    property_record_sequence_bound();
    (void)printf("diff: %ld property rows over the read path the spec does not model\n",
                 property_rows);
}

#endif
