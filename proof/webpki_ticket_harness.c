// Proves: webpki_resumption_ok reads a presented ticket's PSK and binding
// only after the shape check admits them, and webpki_ticket_config_hash,
// which it runs on that path, reads only inside the hostname, the
// anchors and the SPKI pins the config names.
//
// The properties, over unconstrained inputs at the module's real bound: a
// hostname of 0 to CH_HOSTNAME_MAX bytes, 0 to CH_WEBPKI_ANCHOR_MAX
// anchors and 0 to CH_SPKI_PIN_MAX pins (a configuration of pins alone
// has no anchor and may have no hostname), and every PSK field NULL or
// set, with any length. Memory safety
// and absence of UB, which the automatic checks discharge.
// And the verdict's contract: webpki_resumption_ok answers 0 or 1, and 1
// only for a config whose PSK fields are all unset or that presents a
// ticket of the shape webpki_ticket.h states.
//
// What it does not prove, and why. SHA-256 is the contract stub in
// harness.h, so hmac_sha256 runs over a digest CBMC picks freshly each
// call and the binding comparison is unconstrained. Which bindings match is
// tested instead, in test/webpki_resume_cases.h, against a known answer
// computed outside this tree. Each anchor's name and spki are at most
// ANCHOR_FIELD_MAX bytes here: the hash passes them to sha256_update whole,
// so their length changes only the stub's readability check.
#define CH_PROOF_STUB_SHA256
#include "harness.h"

#include <string.h>

#include "webpki.h"
#include "webpki_ticket.c"

#define ANCHOR_FIELD_MAX 4

static uint8_t hostname[CH_HOSTNAME_MAX];
static uint8_t names[CH_WEBPKI_ANCHOR_MAX][ANCHOR_FIELD_MAX];
static uint8_t spkis[CH_WEBPKI_ANCHOR_MAX][ANCHOR_FIELD_MAX];
static ch_trust_anchor anchors[CH_WEBPKI_ANCHOR_MAX];
static uint8_t psk[SHA256_LEN + 1];
static uint8_t psk_id[CH_TICKET_ID_MAX + 1];
static uint8_t binding[SHA256_LEN];
static uint8_t pins[CH_SPKI_PIN_MAX][SHA256_LEN];

// A length for a field whose pointer is set: at most the buffer's size.
// With the pointer NULL, any length at all.
static size_t field_len(const uint8_t *p, size_t cap) {
    size_t n = nondet_size_t();
    __CPROVER_assume(p == NULL || n <= cap);
    return n;
}

int main(void) {
    ch_cfg cfg;
    memset(&cfg, 0, sizeof cfg);
    fill_nondet(hostname, sizeof hostname);
    cfg.hostname = hostname;
    cfg.hostname_len = nondet_size_t();
    __CPROVER_assume(cfg.hostname_len <= CH_HOSTNAME_MAX);
    cfg.anchor_count = nondet_size_t();
    __CPROVER_assume(cfg.anchor_count <= CH_WEBPKI_ANCHOR_MAX);
    for (size_t i = 0; i < CH_WEBPKI_ANCHOR_MAX; i++) {
        fill_nondet(names[i], ANCHOR_FIELD_MAX);
        fill_nondet(spkis[i], ANCHOR_FIELD_MAX);
        size_t name_len = nondet_size_t();
        size_t spki_len = nondet_size_t();
        __CPROVER_assume(name_len >= 1 && name_len <= ANCHOR_FIELD_MAX);
        __CPROVER_assume(spki_len >= 1 && spki_len <= ANCHOR_FIELD_MAX);
        anchors[i] = (ch_trust_anchor){names[i], name_len, spkis[i], spki_len};
    }
    cfg.anchors = anchors;
    fill_nondet((uint8_t *)pins, sizeof pins);
    cfg.spki_pins = (const uint8_t *)pins;
    cfg.spki_pin_count = nondet_size_t();
    __CPROVER_assume(cfg.spki_pin_count <= CH_SPKI_PIN_MAX);

    fill_nondet(psk, sizeof psk);
    fill_nondet(binding, sizeof binding);
    cfg.psk = (nondet_u8() & 1) ? psk : NULL;
    cfg.psk_len = field_len(cfg.psk, sizeof psk);
    cfg.psk_id = (nondet_u8() & 1) ? psk_id : NULL;
    cfg.psk_id_len = field_len(cfg.psk_id, sizeof psk_id);
    cfg.resumption = (int)nondet_u32();
    cfg.ticket_binding = (nondet_u8() & 1) ? binding : NULL;

    int ok = webpki_resumption_ok(&cfg);
    __CPROVER_assert(ok == 0 || ok == 1, "the verdict is 0 or 1");
    if (ok == 1) {
        int unset = cfg.psk == NULL && cfg.psk_len == 0 && cfg.psk_id == NULL &&
                    cfg.psk_id_len == 0 && cfg.resumption == 0 && cfg.ticket_binding == NULL;
        int ticket = cfg.resumption != 0 && cfg.psk != NULL && cfg.psk_len == SHA256_LEN &&
                     cfg.psk_id != NULL && cfg.psk_id_len >= 1 &&
                     cfg.psk_id_len <= CH_TICKET_ID_MAX && cfg.ticket_binding != NULL;
        __CPROVER_assert(unset || ticket, "only an unset config or a ticket of the stated shape");
    }

    return 0;
}
