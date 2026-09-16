// Proves: the TRUST=webpki extension walk (webpki_ext.c) is memory-safe
// and UB-free over any bytes, in five parts, split the way webpki_san
// splits the subjectAltName walk: a piece that reads one element is
// proven from any reader state at the real bound, and a loop over such
// pieces at the bound where its unrolled formula converges. The walk's
// statics are not replaceable from a harness (docs/proofs.md), so a
// composition proof unrolls every reader below it, which is what sets
// its bound. CH_PROOF_PARTS selects the parts by bit: this file's own
// launch line runs bits 1, 2 and 4, and webpki_ext_one_harness.c and
// webpki_ext_walk_harness.c run bits 8 and 16.
//
// Bit 1. read_purpose, one KeyPurposeId of an extendedKeyUsage, from
// ANY reader state over up to CH_WEBPKI_EXT_TLV_MAX bytes: any position,
// any length, either err value. An entry it accepts leaves err clear
// and moves the position forward by three bytes or more and never past
// the end, which is why read_ext_key_usage's loop ends; *server_auth
// only ever goes from 0 to 1. And x509_read_extension at this walk's
// CH_WEBPKI_EXT_TLV_MAX cap, from any reader state over one byte more:
// an accepted Extension leaves err clear, takes 7 to
// CH_WEBPKI_EXT_TLV_MAX bytes, and its extnID and extnValue lie inside
// them.
//
// Bit 2. read_basic_constraints over any extnValue of up to
// CH_WEBPKI_EXT_TLV_MAX bytes: cA is 0 or 1 and the pathLenConstraint
// -1 to 32767.
//
// Bit 4. read_ext_key_usage whole over any extnValue of up to
// CH_PROOF_PURPOSES_LEN bytes: server_auth is 0 or 1. With bit 1's
// contract for one entry, induction over the entries extends the
// loop's safety to any length.
//
// Bit 8. read_one_extension, one Extension judged, from ANY reader
// state over a list of up to CH_PROOF_ONE_LEN bytes, either arm, and
// any walk state before it (any seen bits, is_ca, path_len and san). It
// returns CH_OK or CH_EPROTO. A refusal leaves the alert at the caller's
// ALERT_BAD_CERTIFICATE or sets ALERT_UNSUPPORTED_CERTIFICATE. An
// accepted extension leaves err clear and the alert untouched, consumes
// 7 to CH_WEBPKI_EXT_TLV_MAX bytes, the shortest Extension TLV and the
// cap, which is why the walk's loop ends, and adds at most one of the
// four seen bits, never one already set. When it adds the
// subjectAltName bit, san points inside the bytes it consumed; otherwise
// san is unchanged. When it adds the basicConstraints bit, is_ca equals
// the arm and path_len is -1 or a constraint up to 32767, and -1 on the
// leaf arm; otherwise both are unchanged.
//
// Bit 16. webpki_read_extensions whole — the [3] wrapper, the SEQUENCE
// and its length check, the loop and its count cap, the required bits —
// over any bytes of up to CH_PROOF_EXT_LEN, read from their first byte
// with err clear. On CH_OK, err is clear, the seen bits hold the arm's
// required extensions, is_ca equals the arm, path_len is -1 on the leaf,
// and san is NULL or inside the bytes the call consumed, and not NULL
// on the leaf. The reader starts at the buffer's start rather than in
// any state, because that formula converges at 48 bytes where the
// any-state one does not (run.sh records both), and 48 bytes hold the
// leaf's shortest accepted field, 47 bytes; the issuer's is 34.
//
// CONCRETE: real bodies, the real rbuf (buf.c), the real DER readers
// (x509_der.c) and ct_memeq (ct.c) on the command line.
#include "harness.h"

#include "webpki_ext.c"

#ifndef CH_PROOF_PARTS
#define CH_PROOF_PARTS 7
#endif
#ifndef CH_PROOF_PURPOSES_LEN
#define CH_PROOF_PURPOSES_LEN 64
#endif
#ifndef CH_PROOF_ONE_LEN
#define CH_PROOF_ONE_LEN 64
#endif
#ifndef CH_PROOF_EXT_LEN
#define CH_PROOF_EXT_LEN 64
#endif

int nondet_int(void);

// The shortest Extension TLV: 30 05 06 01 <oid> 04 00.
#define EXTENSION_MIN 7
// The shortest KeyPurposeId: 06 01 <oid>.
#define PURPOSE_MIN 3

// A reader over buf at any position and either err value.
static void havoc_reader(rbuf *r, const uint8_t *buf, size_t cap) {
    size_t len = nondet_size_t();
    __CPROVER_assume(len <= cap);
    rb_init(r, buf, len);
    r->off = nondet_size_t();
    __CPROVER_assume(r->off <= len);
    r->err = nondet_u8() & 1;
}

// 1 when [inner, inner + inner_len) lies inside [outer, outer + outer_len).
static int inside(const uint8_t *outer, size_t outer_len, const uint8_t *inner, size_t inner_len) {
    return inner != NULL && inner >= outer && inner_len <= outer_len &&
           (size_t)(inner - outer) <= outer_len - inner_len;
}

static void one_purpose(void) {
    static uint8_t value[CH_WEBPKI_EXT_TLV_MAX];
    fill_nondet(value, sizeof value);
    rbuf v;
    havoc_reader(&v, value, sizeof value);
    size_t before = v.off;
    int server_auth = nondet_u8() & 1;
    int prior = server_auth;
    if (read_purpose(&v, &server_auth)) {
        __CPROVER_assert(!v.err, "purpose: success leaves err clear");
        __CPROVER_assert(v.off >= before + PURPOSE_MIN, "purpose: moves by three bytes or more");
        __CPROVER_assert(v.off <= v.len, "purpose: never moves past the end");
    }
    __CPROVER_assert(server_auth == prior || server_auth == 1, "purpose: server_auth goes 0 to 1");
}

// x509_read_extension at this walk's cap, from any reader state over
// one byte more than the cap: a success leaves err clear, consumes at
// most CH_WEBPKI_EXT_TLV_MAX bytes, and points the extnID and the
// extnValue inside them.
static void extension_reader(void) {
    static uint8_t list[CH_WEBPKI_EXT_TLV_MAX + 1];
    fill_nondet(list, sizeof list);
    rbuf r;
    havoc_reader(&r, list, sizeof list);
    size_t before = r.off;
    x509_extension ext;
    if (x509_read_extension(&r, CH_WEBPKI_EXT_TLV_MAX, &ext)) {
        __CPROVER_assert(!r.err && r.off <= r.len, "extension: success leaves err clear");
        size_t consumed = r.off - before;
        __CPROVER_assert(consumed >= EXTENSION_MIN && consumed <= CH_WEBPKI_EXT_TLV_MAX,
                         "extension: consumes 7 to CH_WEBPKI_EXT_TLV_MAX bytes");
        __CPROVER_assert(inside(list + before, consumed, ext.oid, ext.oid_len),
                         "extension: the extnID inside the consumed bytes");
        __CPROVER_assert(ext.value_len == 0 ||
                             inside(list + before, consumed, ext.value, ext.value_len),
                         "extension: the extnValue inside the consumed bytes");
        __CPROVER_assert(ext.critical == 0 || ext.critical == 1, "extension: critical is 0 or 1");
    }
}

static void purposes_reader(void) {
    uint8_t purposes[CH_PROOF_PURPOSES_LEN];
    fill_nondet(purposes, sizeof purposes);
    size_t purposes_len = nondet_size_t();
    __CPROVER_assume(purposes_len <= sizeof purposes);
    int server_auth = nondet_int();
    if (read_ext_key_usage(purposes, purposes_len, &server_auth)) {
        __CPROVER_assert(server_auth == 0 || server_auth == 1, "eku: server_auth is 0 or 1");
    }
}

static void constraints_reader(void) {
    static uint8_t constraints[CH_WEBPKI_EXT_TLV_MAX];
    fill_nondet(constraints, sizeof constraints);
    size_t constraints_len = nondet_size_t();
    __CPROVER_assume(constraints_len <= sizeof constraints);
    int ca = nondet_int();
    int path_len = nondet_int();
    if (read_basic_constraints(constraints, constraints_len, &ca, &path_len)) {
        __CPROVER_assert(ca == 0 || ca == 1, "bc: cA is 0 or 1");
        __CPROVER_assert(path_len >= -1 && path_len <= 32767, "bc: path_len in range");
    }
}

static void one_extension(void) {
    uint8_t list[CH_PROOF_ONE_LEN];
    fill_nondet(list, sizeof list);
    rbuf r;
    havoc_reader(&r, list, sizeof list);
    size_t before = r.off;
    int is_ca = nondet_u8() & 1;
    webpki_cert out;
    out.seen = nondet_u8();
    out.is_ca = nondet_u8();
    out.path_len = nondet_int();
    uint8_t other[1];
    out.san = (nondet_u8() & 1) ? other : NULL;
    out.san_len = nondet_size_t();
    const webpki_cert prior = out;
    uint8_t alert = ALERT_BAD_CERTIFICATE;

    int rc = read_one_extension(&r, is_ca, &out, &alert);
    __CPROVER_assert(rc == CH_OK || rc == CH_EPROTO, "one extension: CH_OK or CH_EPROTO");
    if (rc != CH_OK) {
        __CPROVER_assert(alert == ALERT_BAD_CERTIFICATE || alert == ALERT_UNSUPPORTED_CERTIFICATE,
                         "one extension: a refusal names one of the two alerts");
        return;
    }
    __CPROVER_assert(alert == ALERT_BAD_CERTIFICATE, "one extension: success keeps the alert");
    __CPROVER_assert(!r.err && r.off <= r.len, "one extension: success leaves err clear");
    size_t consumed = r.off - before;
    __CPROVER_assert(consumed >= EXTENSION_MIN && consumed <= CH_WEBPKI_EXT_TLV_MAX,
                     "one extension: consumes 7 to CH_WEBPKI_EXT_TLV_MAX bytes");
    uint8_t added = (uint8_t)(out.seen ^ prior.seen);
    __CPROVER_assert((out.seen & prior.seen) == prior.seen, "one extension: seen bits stay set");
    __CPROVER_assert(added == 0 || added == WEBPKI_EXT_KEY_USAGE ||
                         added == WEBPKI_EXT_EXT_KEY_USAGE ||
                         added == WEBPKI_EXT_BASIC_CONSTRAINTS || added == WEBPKI_EXT_SAN,
                     "one extension: adds at most one of the four bits");
    if (added == WEBPKI_EXT_SAN) {
        __CPROVER_assert(inside(list + before, consumed, out.san, out.san_len),
                         "one extension: san lies inside the consumed bytes");
    } else {
        __CPROVER_assert(out.san == prior.san && out.san_len == prior.san_len,
                         "one extension: san changes only with its bit");
    }
    if (added == WEBPKI_EXT_BASIC_CONSTRAINTS) {
        __CPROVER_assert(out.is_ca == is_ca, "one extension: cA equals the arm");
        __CPROVER_assert(out.path_len >= -1 && out.path_len <= 32767,
                         "one extension: path_len is -1 or a two-octet constraint");
        __CPROVER_assert(is_ca || out.path_len == -1, "one extension: no constraint on a leaf");
    } else {
        __CPROVER_assert(out.is_ca == prior.is_ca && out.path_len == prior.path_len,
                         "one extension: is_ca and path_len change only with their bit");
    }
}

static void whole_walk(void) {
    uint8_t field[CH_PROOF_EXT_LEN];
    fill_nondet(field, sizeof field);
    rbuf t;
    size_t field_len = nondet_size_t();
    __CPROVER_assume(field_len <= sizeof field);
    rb_init(&t, field, field_len);
    size_t before = t.off;
    int is_ca = nondet_u8() & 1;
    webpki_cert out;
    uint8_t alert = ALERT_BAD_CERTIFICATE;

    int rc = webpki_read_extensions(&t, is_ca, &out, &alert);
    __CPROVER_assert(rc == CH_OK || rc == CH_EPROTO, "walk: CH_OK or CH_EPROTO");
    if (rc != CH_OK) {
        __CPROVER_assert(alert == ALERT_BAD_CERTIFICATE || alert == ALERT_UNSUPPORTED_CERTIFICATE,
                         "walk: a refusal names one of the two alerts");
        return;
    }
    __CPROVER_assert(alert == ALERT_BAD_CERTIFICATE, "walk: success keeps the alert");
    __CPROVER_assert(!t.err && t.off <= t.len, "walk: success leaves err clear");
    size_t consumed = t.off - before;
    uint8_t required = is_ca ? ISSUER_REQUIRED : LEAF_REQUIRED;
    __CPROVER_assert((out.seen & required) == required, "walk: the arm's extensions were seen");
    __CPROVER_assert(out.is_ca == is_ca, "walk: is_ca equals the arm");
    __CPROVER_assert(is_ca || out.path_len == -1, "walk: no constraint on a leaf");
    __CPROVER_assert(out.path_len >= -1 && out.path_len <= 32767, "walk: path_len in range");
    __CPROVER_assert(out.san == NULL || inside(field + before, consumed, out.san, out.san_len),
                     "walk: san is NULL or inside the consumed bytes");
    __CPROVER_assert(out.san != NULL || out.san_len == 0, "walk: an absent san has no length");
    __CPROVER_assert(is_ca || out.san != NULL, "walk: a leaf records its san");
}

int main(void) {
    if (CH_PROOF_PARTS & 1) {
        one_purpose();
        extension_reader();
    }
    if (CH_PROOF_PARTS & 2) {
        constraints_reader();
    }
    if (CH_PROOF_PARTS & 4) {
        purposes_reader();
    }
    if (CH_PROOF_PARTS & 8) {
        one_extension();
    }
    if (CH_PROOF_PARTS & 16) {
        whole_walk();
    }
    return 0;
}
