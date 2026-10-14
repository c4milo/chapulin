// The rows of bin/hash_runtime_test that a TRUST=webpki object alone
// holds: webpki_ticket.h's three calls, which a client makes with its
// session's value (docs/decisions.md 132). They are the configuration
// hash, a ticket's binding, and the check of a presented ticket, which
// runs both. test/hash_runtime_test.c includes this file after the names
// its rows read: input, key, transcript_hash, output, fill and CHECK.
//
// The configuration names a hostname in capitals, three anchors whose
// keys run past one SHA-256 block, and two SPKI pins. It presents a
// ticket whose binding setup_webpki_rows computes once on sha256.c,
// before any row counts. Outside TRUST=webpki setup_webpki_rows does
// nothing.
#ifndef CH_TEST_HASH_RUNTIME_WEBPKI_H
#define CH_TEST_HASH_RUNTIME_WEBPKI_H
#ifdef CH_TRUST_WEBPKI

#include "webpki_ticket.h"

#define WEBPKI_ANCHORS 3
static const uint8_t webpki_host[] = {'S', '3', '.', 'E', 'x', 'a', 'm', 'p',
                                      'l', 'e', '.', 'T', 'E', 'S', 'T'};
static uint8_t webpki_names[WEBPKI_ANCHORS][20];
static uint8_t webpki_spkis[WEBPKI_ANCHORS][100];
static ch_trust_anchor webpki_anchors[WEBPKI_ANCHORS];
static uint8_t webpki_pins[2][SHA256_LEN];
static uint8_t webpki_binding[SHA256_LEN];
static ch_cfg webpki_cfg;

static void setup_webpki_rows(void) {
    for (size_t i = 0; i < WEBPKI_ANCHORS; i++) {
        fill(webpki_names[i], sizeof webpki_names[i], (uint8_t)(0x20 + i));
        fill(webpki_spkis[i], sizeof webpki_spkis[i], (uint8_t)(0x60 + i));
        webpki_anchors[i] = (ch_trust_anchor){webpki_names[i], sizeof webpki_names[i],
                                              webpki_spkis[i], sizeof webpki_spkis[i]};
    }
    fill((uint8_t *)webpki_pins, sizeof webpki_pins, 0x33);
    memset(&webpki_cfg, 0, sizeof webpki_cfg);
    webpki_cfg.hostname = webpki_host;
    webpki_cfg.hostname_len = sizeof webpki_host;
    webpki_cfg.anchors = webpki_anchors;
    webpki_cfg.anchor_count = WEBPKI_ANCHORS;
    webpki_cfg.spki_pins = (const uint8_t *)webpki_pins;
    webpki_cfg.spki_pin_count = 2;
    webpki_cfg.psk = key;
    webpki_cfg.psk_len = SHA256_LEN;
    webpki_cfg.psk_id = input;
    webpki_cfg.psk_id_len = 8;
    webpki_cfg.resumption = 1;
    uint8_t config_hash[SHA256_LEN];
    webpki_ticket_config_hash(0, &webpki_cfg, config_hash);
    webpki_ticket_binding(0, key, SHA256_LEN, config_hash, webpki_binding);
    webpki_cfg.ticket_binding = webpki_binding;
}

static void row_webpki_ticket_config_hash(uint32_t cpu) {
    webpki_ticket_config_hash(cpu, &webpki_cfg, output);
}

static void row_webpki_ticket_binding(uint32_t cpu) {
    webpki_ticket_binding(cpu, key, SHA256_LEN, transcript_hash, output);
}

// The check reads the session's value from the configuration, as every
// init call hands it over. It takes the ticket on either path.
static void row_webpki_resumption_ok(uint32_t cpu) {
    ch_cfg cfg = webpki_cfg;
    cfg.cpu = cpu;
    output[0] = (uint8_t)webpki_resumption_ok(&cfg);
    CHECK(output[0] == 1);
}

#else

static void setup_webpki_rows(void) {
}

#endif // CH_TRUST_WEBPKI
#endif
