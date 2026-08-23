// Proves: x509_verify_leaf — the profile walker in x509.c — is
// memory-safe and UB-free against ANY CertificateEntry list, and its
// result contract holds. CH_OK yields a key length within
// CH_X509_KEY_MAX, a ca_slot of 1 or 2, and the caller's alert seed
// untouched. Any other return is CH_EPROTO or CH_EAUTH, and the
// alert lands on the outcome x509.h documents for it.
//
// Two proofs share this file, splitting the bound where the RSA
// formula stops converging (measured: the full two-entry RSA formula
// has no kissat verdict in 25 minutes):
//   x509parse_ecdsa (fast tier): the FULL two-entry flight at 256
//     bytes — two maximum ECDSA certificates plus framing. Every
//     walker state is reachable: with the stubs below a primitive
//     may consume nothing, so the nine-extension overflow, the
//     third-entry rejection, and the intermediate arm all fit.
//   x509parse (slow tier): the RSA build at 840 bytes — one maximum
//     RSA certificate (a 384-byte key in the TBS, the 385-byte
//     signature BIT STRING a 384-byte CA modulus demands, headers)
//     plus framing, with room for a small second entry. The
//     two-entry walk itself rests on the ECDSA proof: the walker
//     code is identical outside the SPKI arm.
// The CH_OK tail stays reachable at each bound's maxima, not
// vacuously passed. (A draft of this harness once proved its CH_OK
// asserts against an empty path — caught by asserting 0 there and
// expecting a counterexample, a check worth repeating after edits.)
//
// Layered proof, the handshake-stubs-hsparse pattern: the x509_ DER
// primitives are stubs asserting their x509.h contracts and havocing
// outputs within exactly what x509der_harness proves — x509_der.c is
// NOT linked, so the object under proof is the walker's own
// arithmetic. sha256 and the build's signature verifier are contract
// stubs too (proven in sha256_harness and rsa_harness/p256_harness);
// the walker only routes pointers into them. buf.c is real.
//
// The CA-key domain is a superset of what ch_connect admits (the RSA
// stub never needs the odd-modulus bit), so nothing here rests on
// ch_connect's validation.
#define CH_PROOF_STUB_SHA256
#include "harness.h"

#include "buf.h"
#include "cfg.h"
#include "hsmsg.h"
#include "sha256.h"
#include "x509.h"

#ifdef CH_PIN_ECDSA
#include "p256.h"
#else
#include "rsa.h"
#endif

// One strict-reader step: consume a nondet prefix of what remains —
// never more than the primitive's own consumption bound — through the
// real rbuf, then fail or succeed nondeterministically. Success implies
// the reader entered and left with err clear, the shape x509der_harness
// proves for every primitive; failure may consume and may set err.
static int havoc_read(rbuf *r, size_t max_take) {
    __CPROVER_assert(__CPROVER_w_ok(r, sizeof *r), "stub: rbuf writable");
    size_t take = nondet_size_t();
    __CPROVER_assume(take <= max_take);
    if (take > rb_left(r)) {
        take = rb_left(r);
    }
    rb_skip(r, take);
    if (r->err || (nondet_u8() & 1)) {
        if (nondet_u8() & 1) {
            r->err = 1;
        }
        return 0;
    }
    return 1;
}

// The nondet length every successful read reports: x509der_harness
// proves len <= rb_left on success, and x509.c's exact-fill arithmetic
// rests on exactly that.
static int havoc_len(rbuf *r, size_t consume_max, size_t *out_len) {
    __CPROVER_assert(__CPROVER_w_ok(out_len, sizeof *out_len), "stub: out_len writable");
    if (!havoc_read(r, consume_max)) {
        return 0;
    }
    size_t len = nondet_size_t();
    __CPROVER_assume(len <= rb_left(r));
    *out_len = len;
    return 1;
}

int x509_read_len(rbuf *r, size_t *out_len) {
    return havoc_len(r, 3, out_len); // 1..3 length octets
}

int x509_read_header(rbuf *r, uint8_t tag, size_t *out_len) {
    (void)tag;
    return havoc_len(r, 4, out_len); // tag plus 1..3 length octets
}

int x509_read_exact(rbuf *r, const uint8_t *want, size_t n) {
    __CPROVER_assert(n == 0 || __CPROVER_r_ok(want, n), "exact: want readable");
    if (!havoc_read(r, n)) {
        return 0;
    }
    return nondet_u8() & 1; // a match is a value question, not a memory one
}

int x509_skip(rbuf *r, uint8_t tag) {
    (void)tag;
    return havoc_read(r, rb_left(r)); // header plus any admitted content
}

int x509_read_serial(rbuf *r) {
    return havoc_read(r, 23); // 2-byte header plus at most 21 content bytes
}

int x509_read_time(rbuf *r) {
    return havoc_read(r, 17); // tag, length, 15-digit GeneralizedTime
}

// The leaf path reads its notBefore through the extracting reader.
// Both outputs havoc, under the one postcondition the driver's bound
// arithmetic rests on: an accepted epoch is in range. That
// the reader's shape verdict matches x509_read_time's is proven in
// the x509der harness, over the real body.
int x509_read_time_epoch(rbuf *r, uint32_t *index, int *ok) {
    __CPROVER_assert(__CPROVER_w_ok(index, sizeof *index), "epoch: index writable");
    __CPROVER_assert(__CPROVER_w_ok(ok, sizeof *ok), "epoch: ok writable");
    uint32_t value = 0;
    fill_nondet((uint8_t *)&value, sizeof value);
    __CPROVER_assume(value <= CH_EPOCH_MAX);
    *index = value;
    *ok = nondet_u8() & 1;
    return havoc_read(r, 17);
}

// The walker demands digitalSignature (0x80) of the leaf and
// keyCertSign (0x04) of the intermediate; asserting the mask pins that
// routing here, because the profile split is the walker's own job.
int x509_read_keyusage(const uint8_t *v, size_t n, uint8_t required) {
    __CPROVER_assert(n == 0 || __CPROVER_r_ok(v, n), "ku: value readable");
    __CPROVER_assert(required == 0x80 || required == 0x04, "ku: mask is one of the two documented");
    return nondet_u8() & 1;
}

// On success the key points into the reader's buffer with the build's
// admitted length — the exact postcondition x509der_harness proves, and
// the one x509.c's copy into x509_leaf_info rests on.
int x509_read_spki(rbuf *r, const uint8_t **key, size_t *key_len) {
    __CPROVER_assert(__CPROVER_w_ok(key, sizeof *key), "spki: key out writable");
    __CPROVER_assert(__CPROVER_w_ok(key_len, sizeof *key_len), "spki: key_len out writable");
    if (!havoc_read(r, rb_left(r))) {
        return 0;
    }
    size_t klen;
#ifdef CH_PIN_ECDSA
    klen = 64;
#else
    klen = nondet_size_t();
    __CPROVER_assume(klen >= 256 && klen <= 384 && klen % 8 == 0);
#endif
    size_t key_off = nondet_size_t();
    __CPROVER_assume(key_off <= r->len && klen <= r->len - key_off);
    *key = r->p + key_off;
    *key_len = klen;
    return 1;
}

// On success the bytes point into the reader's buffer: the shape both
// the signature read and the SPKI paths rest on.
int x509_read_bitstring(rbuf *r, const uint8_t **bytes, size_t *n) {
    __CPROVER_assert(__CPROVER_w_ok(bytes, sizeof *bytes), "bits: bytes out writable");
    __CPROVER_assert(__CPROVER_w_ok(n, sizeof *n), "bits: n out writable");
    if (!havoc_read(r, rb_left(r))) {
        return 0;
    }
    size_t blen = nondet_size_t();
    size_t boff = nondet_size_t();
    __CPROVER_assume(boff <= r->len && blen <= r->len - boff);
    *bytes = r->p + boff;
    *n = blen;
    return 1;
}

// On success every part points into the reader's buffer and the whole
// TLV fit tlv_cap — the postconditions x509der_harness proves and the
// extension walk's bookkeeping rests on.
int x509_read_extension(rbuf *e, size_t tlv_cap, x509_extension *out) {
    __CPROVER_assert(__CPROVER_w_ok(out, sizeof *out), "ext: out writable");
    if (!havoc_read(e, tlv_cap)) {
        return 0;
    }
    size_t oid_len = nondet_size_t();
    size_t oid_off = nondet_size_t();
    __CPROVER_assume(oid_len >= 1 && oid_len <= 16);
    __CPROVER_assume(oid_off <= e->len && oid_len <= e->len - oid_off);
    out->oid = e->p + oid_off;
    out->oid_len = oid_len;
    size_t val_len = nondet_size_t();
    size_t val_off = nondet_size_t();
    __CPROVER_assume(val_len <= tlv_cap);
    __CPROVER_assume(val_off <= e->len && val_len <= e->len - val_off);
    out->value = e->p + val_off;
    out->value_len = val_len;
    out->critical = nondet_u8() & 1;
    return 1;
}

size_t x509_emit_header(uint8_t tag, size_t len, uint8_t out[4]) {
    (void)tag;
    (void)len;
    __CPROVER_assert(__CPROVER_w_ok(out, 4), "hdr: out writable");
    fill_nondet(out, 4);
    size_t n = nondet_size_t();
    __CPROVER_assume(n >= 2 && n <= 4); // x509der_harness proves the range
    return n;
}

// sha256 stubs: assert the contract the real code relies on, havoc the
// digest; the walker's memory shape never depends on a digest value.

// The build's signature verifier: the walker only routes pointers into
// it, so the stub asserts readability and answers nondet — both
// verdicts drive both pin slots, the intermediate-under-pin step, the
// leaf-under-intermediate step, and both CH_EAUTH tails.
#ifdef CH_PIN_ECDSA
int p256_ecdsa_verify(const uint8_t pub[64], const uint8_t msg_hash[32], const uint8_t *sig_der,
                      size_t sig_len) {
    __CPROVER_assert(__CPROVER_r_ok(pub, 64), "p256: pub readable");
    __CPROVER_assert(__CPROVER_r_ok(msg_hash, 32), "p256: hash readable");
    __CPROVER_assert(sig_len == 0 || __CPROVER_r_ok(sig_der, sig_len), "p256: sig readable");
    return nondet_u8() & 1;
}
#else
int rsa_pss_verify(const uint8_t *n, size_t n_len, const uint8_t msg_hash[32], const uint8_t *sig,
                   size_t sig_len) {
    __CPROVER_assert(n_len == 0 || __CPROVER_r_ok(n, n_len), "rsa: modulus readable");
    __CPROVER_assert(__CPROVER_r_ok(msg_hash, 32), "rsa: hash readable");
    __CPROVER_assert(sig_len == 0 || __CPROVER_r_ok(sig, sig_len), "rsa: sig readable");
    return nondet_u8() & 1;
}
#endif

#include "x509.c"

int main(void) {
// The proved bound; the header comment argues both numbers.
#ifndef X509PARSE_BOUND
#ifdef CH_PIN_ECDSA
#define X509PARSE_BOUND 256
#else
#define X509PARSE_BOUND 840
#endif
#endif
    uint8_t list[X509PARSE_BOUND];
    fill_nondet(list, sizeof list);
    size_t list_len = nondet_size_t();
    __CPROVER_assume(list_len <= sizeof list);

    // CA slots in ch_connect's length domain (values unconstrained —
    // a superset of its validation). Slot B is optional.
#ifdef CH_PIN_ECDSA
    uint8_t ca_a[64];
    uint8_t ca_b[64];
    size_t ca_a_len = 64;
    size_t ca_b_len = 64;
#else
    uint8_t ca_a[384];
    uint8_t ca_b[384];
    size_t ca_a_len = nondet_size_t();
    size_t ca_b_len = nondet_size_t();
    __CPROVER_assume(ca_a_len >= 256 && ca_a_len <= sizeof ca_a && ca_a_len % 8 == 0);
    __CPROVER_assume(ca_b_len >= 256 && ca_b_len <= sizeof ca_b && ca_b_len % 8 == 0);
#endif
    fill_nondet(ca_a, sizeof ca_a);
    fill_nondet(ca_b, sizeof ca_b);
    const uint8_t *slot_b = ca_b;
    if (nondet_u8() & 1) {
        slot_b = NULL;
        ca_b_len = 0;
    }

    x509_leaf_info out;
    uint8_t alert = ALERT_BAD_CERTIFICATE; // the caller's documented seed
    int rc = x509_verify_leaf(list, list_len, ca_a, ca_a_len, slot_b, ca_b_len, &out, &alert);

    if (rc == CH_OK) {
        __CPROVER_assert(out.key_len <= CH_X509_KEY_MAX, "success: key fits the copy buffer");
#ifdef CH_PIN_ECDSA
        __CPROVER_assert(out.key_len == 64, "success: the one P-256 key size");
#else
        __CPROVER_assert(out.key_len >= 256 && out.key_len <= 384 && out.key_len % 8 == 0,
                         "success: modulus in the verifier's admitted range");
#endif
        __CPROVER_assert(out.ca_slot == 1 || out.ca_slot == 2, "success: ca_slot names a slot");
        __CPROVER_assert(alert == ALERT_BAD_CERTIFICATE, "success leaves the caller's seed");
    } else if (rc == CH_EAUTH) {
        // The two signature outcomes: the chain head failing the pins,
        // or the leaf failing under its own pin-vouched intermediate.
        __CPROVER_assert(alert == ALERT_UNKNOWN_CA || alert == ALERT_BAD_CERTIFICATE,
                         "auth failure alert names the chain step");
    } else {
        __CPROVER_assert(rc == CH_EPROTO, "failure is CH_EPROTO or CH_EAUTH");
        // The two parse outcomes: malformed DER keeps the caller's
        // bad_certificate seed; off-profile overwrites it.
        __CPROVER_assert(alert == ALERT_BAD_CERTIFICATE || alert == ALERT_UNSUPPORTED_CERTIFICATE,
                         "parse failure alert is a certificate alert");
    }
    return 0;
}
