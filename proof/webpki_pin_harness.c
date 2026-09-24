// Proves: the SPKI pin calls of webpki_pin.c are memory-safe and UB-free
// over any input at their real bounds, and hold webpki_pin.h's contracts.
//
// webpki_verify_raw_key runs over any list of up to one byte past a raw
// entry at CH_WEBPKI_SPKI_MAX, any CH_SPKI_PIN_MAX pins or fewer, and any
// output and alert the caller left. It returns CH_OK, CH_EPROTO or
// CH_EAUTH with an alert from webpki_pin.h's table; a refusal leaves out
// as it was; and CH_OK means:
//
//   - the list is one CertificateEntry, its u24 length followed by that
//     many bytes and an empty u16 extensions vector, and nothing after it
//   - the one pin compare hashed exactly the entry's bytes, and one of the
//     pins equals that digest
//   - out holds a key of one of the three algorithms and at most
//     CH_WEBPKI_KEY_MAX bytes, with path_entries and anchor_index 0, and
//     the alert is the caller's
//
// webpki_path_pinned runs over any list of up to CH_PROOF_PATH_LEN bytes,
// any anchors of unconstrained bytes and any leaf, the fields the walk
// writes included at every value. It answers 0 or 1; it parses at most
// path_entries certificates, the first under the leaf arm and the rest
// under the issuer arm; it hashes each of their SubjectPublicKeyInfo
// ranges and then the spki of cfg->anchors[anchor_index], and nothing
// else; and a leaf the walk cannot write, a path over CH_WEBPKI_CHAIN_MAX
// or an anchor index past anchor_count, answers 0.
//
// Layered, the webpki_chain pattern. The two readers are stubs that
// assert what the calls pass them and havoc their outputs within what
// their own harnesses prove: webpki_read_spki (webpki_spki: at most
// CH_WEBPKI_SPKI_MAX bytes consumed, the key inside them, at most
// CH_WEBPKI_KEY_MAX bytes, one of three algorithms) and
// webpki_parse_certificate (webpki_cert: CH_OK or CH_EPROTO, spki_tlv
// inside the certificate). SHA-256 is harness.h's contract stub, which
// sha256 proves; this harness's copy also records what it hashed and the
// digest it answered, which is how the asserts below read the compare.
// webpki_read_entry, rbuf and ct_memeq are real: webpki.c, buf.c and
// ct.c are on the launch line. The walk in webpki.c is in the goto model
// and unreached, so its callees need no stub.
//
// Not proved here: that a digest names the key it was taken over. The
// stub answers any digest; spec/lean/Spec/WebpkiPin.lean states the rule over
// the real SHA-256 and the differential compares the two.
#include "harness.h"

#include <string.h>

#include "buf.h"
#include "handshake_message.h"
#include "sha256.h"
#include "webpki.h"

// A raw list one byte longer than a whole entry at the cap: the u24
// length, CH_WEBPKI_SPKI_MAX bytes, the u16 extensions length, and one
// trailing byte, so both sides of the entry bound and of the exact fill
// are inside it.
#define RAW_LIST_LEN (CH_WEBPKI_SPKI_MAX + 6)
// The chain list webpki_path_pinned frames: CH_WEBPKI_CHAIN_MAX entries of
// a few bytes each, and one entry past them.
#ifndef CH_PROOF_PATH_LEN
#define CH_PROOF_PATH_LEN 24
#endif
// Anchors the configuration carries, and each one's unconstrained bytes.
#define CH_PROOF_ANCHORS 2
#define CH_PROOF_ANCHOR_LEN 8

// What the SHA-256 stub saw: every input it hashed, the count, and the
// last digest it answered.
#define HASH_RECORDS (CH_WEBPKI_CHAIN_MAX + 1)
static const uint8_t *hashed[HASH_RECORDS];
static size_t hashed_len[HASH_RECORDS];
static size_t hash_count;
static uint8_t last_digest[SHA256_LEN];

void sha256_of(const uint8_t *in, size_t n, uint8_t out[SHA256_LEN]) {
    __CPROVER_assert(n == 0 || __CPROVER_r_ok(in, n), "sha256_of: input readable");
    __CPROVER_assert(__CPROVER_w_ok(out, SHA256_LEN), "sha256_of: output writable");
    __CPROVER_assert(hash_count < HASH_RECORDS, "sha256_of: at most the path and its anchor");
    hashed[hash_count] = in;
    hashed_len[hash_count] = n;
    hash_count++;
    fill_nondet(out, SHA256_LEN);
    memcpy(last_digest, out, SHA256_LEN);
}

// A reader failure: any prefix of what remains consumed, err maybe set.
static int havoc_failure(rbuf *r) {
    size_t take = nondet_size_t();
    __CPROVER_assume(take <= rb_left(r));
    rb_skip(r, take);
    if (nondet_u8() & 1) {
        r->err = 1;
    }
    return 0;
}

int webpki_read_spki(rbuf *r, webpki_spki *out) {
    __CPROVER_assert(__CPROVER_w_ok(r, sizeof *r), "spki stub: rbuf writable");
    __CPROVER_assert(__CPROVER_w_ok(out, sizeof *out), "spki stub: out writable");
    if (nondet_u8() & 1) {
        return havoc_failure(r);
    }
    size_t take = nondet_size_t();
    __CPROVER_assume(take <= CH_WEBPKI_SPKI_MAX && !r->err && take <= rb_left(r));
    const uint8_t *start = rb_bytes(r, take);
    __CPROVER_assert(start != NULL, "spki stub: the consumed bytes are readable");
    size_t key_off = nondet_size_t();
    size_t key_len = nondet_size_t();
    __CPROVER_assume(key_len <= take && key_off <= take - key_len && key_len <= CH_WEBPKI_KEY_MAX);
    uint8_t alg = nondet_u8();
    __CPROVER_assume(alg >= WEBPKI_KEY_RSA && alg <= WEBPKI_KEY_P384);
    out->alg = alg;
    out->key = start + key_off;
    out->key_len = key_len;
    return 1;
}

// Certificates webpki_path_pinned parsed, and whether each asked for the
// arm its position names.
static size_t parse_count;

int webpki_parse_certificate(const uint8_t *cert, size_t cert_len, int is_ca, webpki_cert *out,
                             uint8_t *alert) {
    __CPROVER_assert(cert_len == 0 || __CPROVER_r_ok(cert, cert_len),
                     "parse stub: the certificate is readable");
    __CPROVER_assert(__CPROVER_w_ok(out, sizeof *out), "parse stub: out writable");
    __CPROVER_assert(__CPROVER_w_ok(alert, sizeof *alert), "parse stub: alert writable");
    __CPROVER_assert(is_ca == (parse_count > 0),
                     "parse stub: the leaf arm for entry 0, the issuer arm after it");
    parse_count++;
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
                     spki_off <= cert_len - spki_len);
    out->spki_tlv = cert + spki_off;
    out->spki_tlv_len = spki_len;
    return CH_OK;
}

#include "webpki_pin.c"

// 1 when [inner, inner + inner_len) lies inside [outer, outer + outer_len).
static int inside(const uint8_t *outer, size_t outer_len, const uint8_t *inner, size_t inner_len) {
    return inner >= outer && inner_len <= outer_len &&
           (size_t)(inner - outer) <= outer_len - inner_len;
}

// Whether one of the first count pins equals the last digest the stub
// answered.
static int digest_pinned(const uint8_t *pins, size_t count) {
    int found = 0;
    for (size_t i = 0; i < CH_SPKI_PIN_MAX; i++) {
        found |= i < count && memcmp(pins + i * SHA256_LEN, last_digest, SHA256_LEN) == 0;
    }
    return found;
}

static void prove_raw_key(ch_cfg *cfg, const uint8_t *pins) {
    static uint8_t list[RAW_LIST_LEN];
    fill_nondet(list, sizeof list);
    size_t list_len = nondet_size_t();
    __CPROVER_assume(list_len <= sizeof list);
    webpki_leaf_info out;
    __CPROVER_havoc_object(&out);
    const webpki_leaf_info before = out;
    hash_count = 0;
    // hsa_server_auth seeds bad_certificate, and so does this.
    uint8_t alert = ALERT_BAD_CERTIFICATE;

    int rc = webpki_verify_raw_key(list, list_len, cfg, &out, &alert);
    __CPROVER_assert(rc == CH_OK || rc == CH_EPROTO || rc == CH_EAUTH,
                     "raw: CH_OK, CH_EPROTO or CH_EAUTH");
    __CPROVER_assert(rc != CH_EAUTH || alert == ALERT_BAD_CERTIFICATE,
                     "raw: no pin naming the key is bad_certificate");
    __CPROVER_assert(rc != CH_EPROTO || alert == ALERT_BAD_CERTIFICATE ||
                         alert == ALERT_UNSUPPORTED_EXTENSION ||
                         alert == ALERT_UNSUPPORTED_CERTIFICATE,
                     "raw: a malformed list names one of the three alerts");
    __CPROVER_assert(rc != CH_EAUTH ||
                         (hash_count == 1 && !digest_pinned(pins, cfg->spki_pin_count)),
                     "raw: no pin naming the key means no pin equals its digest");
    if (rc != CH_OK) {
        size_t i = nondet_size_t();
        __CPROVER_assume(i < CH_WEBPKI_KEY_MAX);
        __CPROVER_assert(
            out.alg == before.alg && out.key_len == before.key_len && out.key[i] == before.key[i] &&
                out.path_entries == before.path_entries && out.anchor_index == before.anchor_index,
            "raw: a refusal leaves out as it was");
        return;
    }
    size_t entry_len = ((size_t)list[0] << 16) | ((size_t)list[1] << 8) | list[2];
    __CPROVER_assert(entry_len >= 1 && entry_len <= CH_WEBPKI_SPKI_MAX &&
                         list_len == entry_len + 5 && list[entry_len + 3] == 0 &&
                         list[entry_len + 4] == 0,
                     "raw: one entry, an empty extensions vector, nothing after it");
    __CPROVER_assert(hash_count == 1 && hashed[0] == list + 3 && hashed_len[0] == entry_len,
                     "raw: the pin compare hashed exactly the entry");
    __CPROVER_assert(digest_pinned(pins, cfg->spki_pin_count),
                     "raw: a pin equals the entry's digest");
    __CPROVER_assert(alert == ALERT_BAD_CERTIFICATE, "raw: success keeps the alert");
    __CPROVER_assert(out.alg >= WEBPKI_KEY_RSA && out.alg <= WEBPKI_KEY_P384 &&
                         out.key_len <= CH_WEBPKI_KEY_MAX,
                     "raw: the key is one of the three algorithms and fits");
    __CPROVER_assert(out.path_entries == 0 && out.anchor_index == 0,
                     "raw: a raw public key has no path");
}

static void prove_path_pinned(ch_cfg *cfg) {
    static uint8_t list[CH_PROOF_PATH_LEN];
    fill_nondet(list, sizeof list);
    size_t list_len = nondet_size_t();
    __CPROVER_assume(list_len <= sizeof list);
    static uint8_t spki_bytes[CH_PROOF_ANCHORS][CH_PROOF_ANCHOR_LEN];
    static ch_trust_anchor anchors[CH_PROOF_ANCHORS];
    for (size_t i = 0; i < CH_PROOF_ANCHORS; i++) {
        fill_nondet(spki_bytes[i], CH_PROOF_ANCHOR_LEN);
        size_t spki_len = nondet_size_t();
        __CPROVER_assume(spki_len <= CH_PROOF_ANCHOR_LEN);
        anchors[i].name = spki_bytes[i];
        anchors[i].name_len = 0;
        anchors[i].spki = spki_bytes[i];
        anchors[i].spki_len = spki_len;
    }
    size_t anchor_count = nondet_size_t();
    __CPROVER_assume(anchor_count <= CH_PROOF_ANCHORS);
    cfg->anchors = anchors;
    cfg->anchor_count = anchor_count;
    webpki_leaf_info leaf;
    __CPROVER_havoc_object(&leaf);
    hash_count = 0;
    parse_count = 0;

    int pinned = webpki_path_pinned(list, list_len, cfg, &leaf);
    __CPROVER_assert(pinned == 0 || pinned == 1, "path: 0 or 1");
    __CPROVER_assert(parse_count <= leaf.path_entries,
                     "path: no certificate past path_entries is parsed");
    if (!pinned) {
        return;
    }
    __CPROVER_assert(leaf.path_entries <= CH_WEBPKI_CHAIN_MAX && leaf.anchor_index < anchor_count,
                     "path: a match needs a path the walk can report");
    __CPROVER_assert(hash_count >= 1 && hash_count - 1 <= parse_count,
                     "path: one hash per parsed entry, then one for the anchor");
    size_t last = hash_count - 1;
    __CPROVER_assert(hashed[last] == anchors[leaf.anchor_index].spki &&
                         hashed_len[last] == anchors[leaf.anchor_index].spki_len,
                     "path: the anchor hashed is the one at anchor_index");
    for (size_t i = 0; i < HASH_RECORDS; i++) {
        __CPROVER_assert(i >= last || inside(list, list_len, hashed[i], hashed_len[i]),
                         "path: an entry's hash reads inside the list");
    }
}

int main(void) {
    // One flat array, the shape ch_cfg.spki_pins takes: the pins back to
    // back, SHA256_LEN bytes each.
    static uint8_t pins[CH_SPKI_PIN_MAX * SHA256_LEN];
    fill_nondet(pins, sizeof pins);
    size_t pin_count = nondet_size_t();
    __CPROVER_assume(pin_count <= CH_SPKI_PIN_MAX);
    ch_cfg cfg;
    __CPROVER_havoc_object(&cfg);
    cfg.spki_pins = pins;
    cfg.spki_pin_count = pin_count;
    prove_raw_key(&cfg, pins);
    // Fresh operands for the second call: other pins, another count.
    fill_nondet(pins, sizeof pins);
    pin_count = nondet_size_t();
    __CPROVER_assume(pin_count <= CH_SPKI_PIN_MAX);
    cfg.spki_pin_count = pin_count;
    prove_path_pinned(&cfg);
    return 0;
}
