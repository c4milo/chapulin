// docs/entropy.md's boot-seed recipe, written the way the page tells an
// integrator to write it. make lib-check RAND=drbg compiles it against
// the headers and links it against the packaged object, as an image
// links it, so a recipe that calls a function the object keeps local
// fails there (https://github.com/c4milo/chapulin/issues/164). Then it
// starts one handshake, and the library draws the key share and the
// ClientHello random from the generator this file seeded.
//
// The three sources are fixed bytes here. On a device they are the
// factory secret in flash, the seed file, and samples of a cycle
// counter.
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdnoreturn.h>
#include <string.h>

#include "cfg.h"
#include "ch_assert.h"
#include "drbg.h"
#include "tls.h"

noreturn void ch_assert_fail(const char *cond, const char *file, int line) {
    (void)fprintf(stderr, "ASSERT %s:%d: %s\n", file, line, cond);
    abort();
}

// The sources docs/entropy.md lists, each at its own length.
static const uint8_t factory_secret[32] = {0x01};
static const uint8_t seed_file[32] = {0x02};
static const uint8_t jitter_samples[16] = {0x03};

// A wipe the compiler cannot remove: the stores go through a volatile
// pointer. The object keeps its own wipe local, so an image writes one.
static void wipe(uint8_t *p, size_t n) {
    volatile uint8_t *v = p;
    for (size_t i = 0; i < n; i++) {
        v[i] = 0;
    }
}

// Concatenate every source into one buffer and pass the whole buffer
// once. ch_drbg_seed hashes it into the generator key, so the image
// needs no hash of its own.
static void seed_at_boot(void) {
    uint8_t seed[sizeof factory_secret + sizeof seed_file + sizeof jitter_samples];
    memcpy(seed, factory_secret, sizeof factory_secret);
    memcpy(seed + sizeof factory_secret, seed_file, sizeof seed_file);
    memcpy(seed + sizeof factory_secret + sizeof seed_file, jitter_samples, sizeof jitter_samples);
    ch_drbg_seed(seed, sizeof seed);
    wipe(seed, sizeof seed);
}

// No server answers. The first byte sent is the record's content type,
// and every read fails, so ch_connect stops at its first read.
#define HANDSHAKE_RECORD 22
static uint8_t first_sent;

static int keep_send(void *io, const uint8_t *p, size_t n) {
    (void)io;
    if (first_sent == 0 && n > 0) {
        first_sent = p[0];
    }
    return 0;
}

static int fail_recv(void *io, uint8_t *p, size_t n) {
    (void)io;
    memset(p, 0, n);
    return -1;
}

#ifdef CH_TRUST_WEBPKI
// Placeholders: ch_connect checks that each field is set, and no
// certificate arrives here.
static const uint8_t anchor_name[2] = {0x30, 0x00};
static const uint8_t anchor_spki[2] = {0x30, 0x00};
static const ch_trust_anchor anchors[1] = {
    {anchor_name, sizeof anchor_name, anchor_spki, sizeof anchor_spki}
};
static const uint8_t hostname[11] = {'d', 'n', 's', '.', 'e', 'x', 'a', 'm', 'p', 'l', 'e'};
#else
static const uint8_t psk[32] = {0x0b};
static const uint8_t psk_id[6] = {'r', 'e', 'c', 'i', 'p', 'e'};
#endif

static uint8_t rxbuf[CH_MIN_RXBUF];
static ch_tls session;

int main(void) {
    seed_at_boot();
    ch_cfg cfg;
    memset(&cfg, 0, sizeof cfg);
    cfg.buf = rxbuf;
    cfg.buf_len = sizeof rxbuf;
    cfg.send = keep_send;
    cfg.recv = fail_recv;
#ifdef CH_TRUST_WEBPKI
    cfg.anchors = anchors;
    cfg.anchor_count = 1;
    cfg.hostname = hostname;
    cfg.hostname_len = sizeof hostname;
    cfg.now_seconds = 1789000000U;
#else
    cfg.psk = psk;
    cfg.psk_len = sizeof psk;
    cfg.psk_id = psk_id;
    cfg.psk_id_len = sizeof psk_id;
#endif
    int rc = ch_connect(&session, &cfg);
    ch_close(&session);
    if (rc != CH_EIO || first_sent != HANDSHAKE_RECORD) {
        (void)fprintf(stderr, "entropy_recipe: ch_connect sent no ClientHello (rc %d)\n", rc);
        return 1;
    }
    return 0;
}
