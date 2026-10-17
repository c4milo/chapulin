// Proves: webpki_resumption_ok reads a presented ticket's PSK and binding
// only after the shape check admits them, and webpki_ticket_config_hash,
// which it runs on that path, reads only inside the hostname, the
// anchors and the SPKI pins the config names.
//
// The properties, over unconstrained inputs:
//  - a hostname of 0 to CH_HOSTNAME_MAX bytes, the module's real bound;
//  - 0 to CH_SPKI_PIN_MAX pins, the module's real bound;
//  - 0 to PROOF_ANCHORS anchors, a bound this harness chooses;
//  - every PSK field NULL or set, with any length.
// A configuration of pins alone has no anchor and may have no hostname.
// No cap bounds the anchor count (docs/decisions.md 131), so the anchor
// bound is the harness's own, 12. The hash reads each anchor the same
// way. So 12 anchors stand for any count a caller's array holds. Memory
// safety and absence of UB, which the automatic checks discharge.
// And the verdict's contract: webpki_resumption_ok answers 0 or 1, and 1
// only for a config whose PSK fields are all unset or that presents a
// ticket of the shape webpki_ticket.h states.
//
// The webpki_ticket launch line builds a device object, which holds one
// SHA-256. There the hash and the binding take a cpu argument and read no
// value (docs/decisions.md 132). The webpki_ticket_host line builds the same
// harness with -DCH_CPU_RUNTIME, the host arm. Its ch_cfg.cpu takes any
// 32-bit value, and the hash and the binding run on the path that value
// names. The host arm's calls on the SHA-256 instructions are contract
// stubs below, which run the portable call they stand for. Each stub
// asserts that cfg's value holds CH_CPU_CONSTANT_TIME_SHA256. After a
// ticket check under that bit, main asserts that the hash ended on the
// instructions and that the binding ran on them.
// bin/hash_runtime_test counts which path each call runs on a real CPU.
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
// The entries the formula's anchors array holds.
#define PROOF_ANCHORS 12

static uint8_t hostname[CH_HOSTNAME_MAX];
static uint8_t names[PROOF_ANCHORS][ANCHOR_FIELD_MAX];
static uint8_t spkis[PROOF_ANCHORS][ANCHOR_FIELD_MAX];
static ch_trust_anchor anchors[PROOF_ANCHORS];
static uint8_t psk[SHA256_LEN + 1];
static uint8_t psk_id[CH_TICKET_ID_MAX + 1];
// A presented ticket, whose binding webpki_resumption_ok compares.
static ch_saved_ticket ticket;
static uint8_t pins[CH_SPKI_PIN_MAX][SHA256_LEN];

#ifdef CH_CPU_RUNTIME
// cfg's ch_cfg.cpu, and which calls on the instructions ran.
static uint32_t harness_cpu;
static int final_ran;
static int hmac_ran;

// sha256_hw.c and hkdf_hw.c hold intrinsics, which CBMC cannot read.
// Each has the contract of the portable call it is named for
// (sha256.h, hkdf.h). So each stub runs that call: harness.h's SHA-256
// stubs, and hkdf.c's hmac_sha256 over them.
void sha256_update_hw(sha256 *s, const uint8_t *in, size_t n) {
    __CPROVER_assert(sha256_on_instructions(harness_cpu), "update_hw: only under the bit");
    sha256_update(s, in, n);
}

void sha256_final_hw(sha256 *s, uint8_t out[SHA256_LEN]) {
    __CPROVER_assert(sha256_on_instructions(harness_cpu), "final_hw: only under the bit");
    final_ran = 1;
    sha256_final(s, out);
}

void hmac_sha256_hw(const uint8_t *key, size_t key_len, const uint8_t *msg, size_t msg_len,
                    uint8_t out[SHA256_LEN]) {
    __CPROVER_assert(sha256_on_instructions(harness_cpu), "hmac_hw: only under the bit");
    hmac_ran = 1;
    hmac_sha256(key, key_len, msg, msg_len, out);
}
#endif

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
    __CPROVER_assume(cfg.anchor_count <= PROOF_ANCHORS);
    for (size_t i = 0; i < PROOF_ANCHORS; i++) {
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
    fill_nondet(ticket.ticket.binding, sizeof ticket.ticket.binding);
    cfg.psk = (nondet_u8() & 1) ? psk : NULL;
    cfg.psk_len = field_len(cfg.psk, sizeof psk);
    cfg.psk_id = (nondet_u8() & 1) ? psk_id : NULL;
    cfg.psk_id_len = field_len(cfg.psk_id, sizeof psk_id);
    cfg.ticket = (nondet_u8() & 1) ? &ticket : NULL;
#ifdef CH_CPU_RUNTIME
    harness_cpu = nondet_u32();
    cfg.cpu = harness_cpu;
#endif

    int ok = webpki_resumption_ok(&cfg);
    __CPROVER_assert(ok == 0 || ok == 1, "the verdict is 0 or 1");
    if (ok == 1) {
        int unset = cfg.psk == NULL && cfg.psk_len == 0 && cfg.psk_id == NULL &&
                    cfg.psk_id_len == 0 && cfg.ticket == NULL;
        int presented = cfg.ticket != NULL && cfg.psk != NULL && cfg.psk_len == SHA256_LEN &&
                        cfg.psk_id != NULL && cfg.psk_id_len >= 1 &&
                        cfg.psk_id_len <= CH_TICKET_ID_MAX;
        __CPROVER_assert(unset || presented,
                         "only an unset config or a ticket of the stated shape");
#ifdef CH_CPU_RUNTIME
        __CPROVER_assert(unset || !sha256_on_instructions(harness_cpu) || (final_ran && hmac_ran),
                         "a ticket check under the bit runs on the instructions");
#endif
    }

    return 0;
}
