// Proves: webpki_verify_leaf_pin (webpki_pin.c), the rule for an X.509
// chain under SPKI pins alone (docs/decisions.md 65), is memory-safe and
// UB-free over any list of up to CH_PROOF_LEAF_LIST_LEN bytes, any
// CH_SPKI_PIN_MAX pins or fewer and any output the caller left, and holds
// webpki_pin.h's contract. It returns CH_OK, CH_EPROTO or CH_EAUTH with an
// alert from webpki_pin.h's table; the key reader runs at most once, and
// only on entry 0; a refusal leaves out as it was; and CH_OK means:
//
//   - the list's first CertificateEntry is framed: its u24 length of at
//     least 1, that many bytes and an empty u16 extensions vector
//   - the one pin compare hashed exactly the SubjectPublicKeyInfo TLV the
//     key reader returned for entry 0, and one of the pins equals that
//     digest
//   - out holds the key that reader returned, of one of the three
//     algorithms and at most CH_WEBPKI_KEY_MAX bytes, with path_entries 1
//     and anchor_index 0, and the alert is the caller's
//
// Layered, the webpki_pin pattern. webpki_read_certificate_key is a stub
// to what webpki_cert_key proves: CH_OK or CH_EPROTO with one of two
// alerts, and on CH_OK a SubjectPublicKeyInfo TLV of at most SPKI_MAX
// bytes inside the certificate and a key of one of three algorithms and
// at most CH_WEBPKI_KEY_MAX bytes inside that TLV. SHA-256 is a contract
// stub that records what it hashed and the digest it answered.
// webpki_read_leaf_entry and webpki_read_entry (webpki.c), rbuf and
// ct_memeq are real. The raw and path calls in webpki_pin.c are in the
// goto model and unreached, so their readers need no stub here.
//
// The list is short so the framing's walk over CH_WEBPKI_FLIGHT_ENTRIES
// entries and one more stays small: 24 bytes hold four one-byte entries
// and part of a fifth. So the key the call copies is at most 24 bytes
// here; the copy is copy_key's, whose bounds webpki_pin checks at the raw
// key's full bound.
#include "harness.h"

#include <string.h>

#include "buf.h"
#include "handshake_message.h"
#include "sha256.h"
#include "webpki.h"

#ifndef CH_PROOF_LEAF_LIST_LEN
#define CH_PROOF_LEAF_LIST_LEN 24
#endif
// webpki_spki's proven bound on an accepted SubjectPublicKeyInfo.
#define SPKI_MAX 550

// What the SHA-256 stub saw: the last input, the count, and the last
// digest it answered.
static const uint8_t *hashed;
static size_t hashed_len;
static size_t hash_count;
static uint8_t last_digest[SHA256_LEN];

void sha256_of(const uint8_t *in, size_t n, uint8_t out[SHA256_LEN]) {
    __CPROVER_assert(n == 0 || __CPROVER_r_ok(in, n), "sha256_of: input readable");
    __CPROVER_assert(__CPROVER_w_ok(out, SHA256_LEN), "sha256_of: output writable");
    hashed = in;
    hashed_len = n;
    hash_count++;
    fill_nondet(out, SHA256_LEN);
    memcpy(last_digest, out, SHA256_LEN);
}

// What the key reader stub was handed and what it answered.
static size_t key_reads;
static const uint8_t *key_cert;
static webpki_cert key_answer;

int webpki_read_certificate_key(const uint8_t *cert, size_t cert_len, webpki_cert *out,
                                uint8_t *alert) {
    __CPROVER_assert(cert_len == 0 || __CPROVER_r_ok(cert, cert_len),
                     "key stub: the certificate is readable");
    __CPROVER_assert(__CPROVER_w_ok(out, sizeof *out), "key stub: out writable");
    __CPROVER_assert(__CPROVER_w_ok(alert, sizeof *alert), "key stub: alert writable");
    key_reads++;
    key_cert = cert;
    __CPROVER_havoc_object(out);
    if (nondet_u8() & 1) {
        if (nondet_u8() & 1) {
            *alert = ALERT_UNSUPPORTED_CERTIFICATE;
        }
        return CH_EPROTO;
    }
    size_t spki_off = nondet_size_t();
    size_t spki_len = nondet_size_t();
    __CPROVER_assume(cert_len <= CH_WEBPKI_CERT_MAX && spki_len <= cert_len &&
                     spki_off <= cert_len - spki_len && spki_len <= SPKI_MAX);
    size_t key_off = nondet_size_t();
    size_t key_len = nondet_size_t();
    __CPROVER_assume(key_len <= spki_len && key_off <= spki_len - key_len &&
                     key_len <= CH_WEBPKI_KEY_MAX);
    uint8_t alg = nondet_u8();
    __CPROVER_assume(alg >= WEBPKI_KEY_RSA && alg <= WEBPKI_KEY_P384);
    out->spki_tlv = cert + spki_off;
    out->spki_tlv_len = spki_len;
    out->spki.alg = alg;
    out->spki.key = cert + spki_off + key_off;
    out->spki.key_len = key_len;
    key_answer = *out;
    return CH_OK;
}

#include "webpki_pin.c"

// Whether one of the first count pins equals the last digest the stub
// answered.
static int digest_pinned(const uint8_t *pins, size_t count) {
    int found = 0;
    for (size_t i = 0; i < CH_SPKI_PIN_MAX; i++) {
        found |= i < count && memcmp(pins + i * SHA256_LEN, last_digest, SHA256_LEN) == 0;
    }
    return found;
}

static void check_refusal(int rc, uint8_t alert, const uint8_t *pins, size_t pin_count) {
    __CPROVER_assert(rc == CH_EPROTO || rc == CH_EAUTH, "leaf: a refusal is CH_EPROTO or CH_EAUTH");
    __CPROVER_assert(rc != CH_EAUTH || (alert == ALERT_BAD_CERTIFICATE && key_reads == 1 &&
                                        hash_count == 1 && !digest_pinned(pins, pin_count)),
                     "leaf: no pin naming the leaf's key is bad_certificate after one compare");
    __CPROVER_assert(rc != CH_EPROTO ||
                         ((alert == ALERT_BAD_CERTIFICATE || alert == ALERT_UNSUPPORTED_EXTENSION ||
                           alert == ALERT_UNSUPPORTED_CERTIFICATE) &&
                          hash_count == 0),
                     "leaf: a malformed list names one of the three alerts and hashes nothing");
}

int main(void) {
    // One flat array, the shape ch_cfg.spki_pins takes.
    static uint8_t pins[CH_SPKI_PIN_MAX * SHA256_LEN];
    fill_nondet(pins, sizeof pins);
    size_t pin_count = nondet_size_t();
    __CPROVER_assume(pin_count <= CH_SPKI_PIN_MAX);
    ch_cfg cfg;
    __CPROVER_havoc_object(&cfg);
    cfg.spki_pins = pins;
    cfg.spki_pin_count = pin_count;
    static uint8_t list[CH_PROOF_LEAF_LIST_LEN];
    fill_nondet(list, sizeof list);
    size_t list_len = nondet_size_t();
    __CPROVER_assume(list_len <= sizeof list);
    webpki_leaf_info out;
    __CPROVER_havoc_object(&out);
    const webpki_leaf_info before = out;
    // hsa_server_auth seeds bad_certificate, and so does this.
    uint8_t alert = ALERT_BAD_CERTIFICATE;

    int rc = webpki_verify_leaf_pin(list, list_len, &cfg, &out, &alert);
    __CPROVER_assert(key_reads <= 1 && (key_reads == 0 || key_cert == list + 3),
                     "leaf: the key reader runs at most once, on entry 0");
    size_t i = nondet_size_t();
    __CPROVER_assume(i < CH_WEBPKI_KEY_MAX);
    if (rc != CH_OK) {
        check_refusal(rc, alert, pins, pin_count);
        __CPROVER_assert(
            out.alg == before.alg && out.key_len == before.key_len && out.key[i] == before.key[i] &&
                out.path_entries == before.path_entries && out.anchor_index == before.anchor_index,
            "leaf: a refusal leaves out as it was");
        return 0;
    }
    size_t entry_len = ((size_t)list[0] << 16) | ((size_t)list[1] << 8) | list[2];
    __CPROVER_assert(entry_len >= 1 && entry_len + 5 <= list_len && list[entry_len + 3] == 0 &&
                         list[entry_len + 4] == 0,
                     "leaf: the first entry is framed");
    __CPROVER_assert(key_reads == 1 && hash_count == 1 && hashed == key_answer.spki_tlv &&
                         hashed_len == key_answer.spki_tlv_len,
                     "leaf: the pin compare hashed the leaf's SubjectPublicKeyInfo");
    __CPROVER_assert(digest_pinned(pins, pin_count), "leaf: a pin equals the leaf key's digest");
    __CPROVER_assert(alert == ALERT_BAD_CERTIFICATE, "leaf: success keeps the alert");
    __CPROVER_assert(out.alg == key_answer.spki.alg && out.key_len == key_answer.spki.key_len &&
                         (i >= out.key_len || out.key[i] == key_answer.spki.key[i]),
                     "leaf: out holds the leaf's key");
    __CPROVER_assert(out.path_entries == 1 && out.anchor_index == 0,
                     "leaf: the path is the leaf alone");
    return 0;
}
