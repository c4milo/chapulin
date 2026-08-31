// Proves: ch_pubkey_from_pem is memory-safe and UB-free over any input,
// and honours its whole contract -- CH_OK yields a key length inside
// CH_X509_KEY_MAX, and every rejection yields zero with the key wiped.
//
// Layered, the x509parse-stubs-x509der pattern: the x509_ DER
// primitives are stubs asserting their x509.h contracts and havocing
// outputs, so x509_der.c is NOT linked and the object under proof is
// the walk's own sequencing. pem_decode_certificate is stubbed to the
// contract proof/pem_harness.c proves. buf.c is real.
//
// The stub for x509_read_spki deliberately models MORE than the real
// function returns: it havocs *key_len anywhere inside the decoded
// buffer rather than inside CH_X509_KEY_MAX. That is sound -- the real
// outputs are a subset -- and it is the point of the harness. What
// keeps the memcpy into key[CH_X509_KEY_MAX] in bounds is
// ch_pubkey_from_pem's own length check, and a stub constrained to the
// real range would prove that check trivially instead of proving it
// works.
#include "harness.h"

#include "buf.h"
#include "cfg.h"
#include "pem.h"
#include "x509.h"

uint32_t nondet_u32(void);
int nondet_int(void);

// The decoder is stubbed, so its input is only a readable object for
// the contract assert; its length carries no proof obligation here.
#define CH_CA_PROOF_PEM_LEN 32

// The decoded certificate every stub hands pointers into. One object,
// so a havocked key pointer always spans a readable region.
static uint8_t der_buf[CH_X509_MAX];

// pem.h's contract: CH_OK with a non-empty length inside the array, or
// CH_EINVAL with zero. proof/pem_harness.c proves it.
int pem_decode_certificate(const uint8_t *pem, size_t pem_len, uint8_t der[CH_X509_MAX],
                           size_t *der_len) {
    __CPROVER_assert(pem_len == 0 || __CPROVER_r_ok(pem, pem_len),
                     "pem_decode_certificate: input readable");
    __CPROVER_assert(__CPROVER_w_ok(der, CH_X509_MAX), "pem_decode_certificate: output writable");
    __CPROVER_assert(__CPROVER_w_ok(der_len, sizeof *der_len),
                     "pem_decode_certificate: length writable");
    fill_nondet(der, CH_X509_MAX);
    if (nondet_int()) {
        size_t n = nondet_size_t();
        __CPROVER_assume(n > 0 && n <= CH_X509_MAX);
        *der_len = n;
        return CH_OK;
    }
    *der_len = 0;
    return CH_EINVAL;
}

// Every reader below asserts the contract x509.h states and havocs
// within what x509der_harness proves: on success err stays clear and
// the reader consumed no more than was left.
static int reader_ok(rbuf *r) {
    __CPROVER_assert(__CPROVER_w_ok(r, sizeof *r), "reader: rbuf writable");
    if (r->err || !nondet_int()) {
        return 0;
    }
    size_t used = nondet_size_t();
    __CPROVER_assume(used <= r->len - r->off);
    r->off += used;
    return 1;
}

int x509_read_header(rbuf *r, uint8_t tag, size_t *out_len) {
    (void)tag;
    __CPROVER_assert(__CPROVER_w_ok(out_len, sizeof *out_len), "read_header: length writable");
    if (!reader_ok(r)) {
        return 0;
    }
    size_t len = nondet_size_t();
    __CPROVER_assume(len <= r->len - r->off);
    *out_len = len;
    return 1;
}

int x509_read_exact(rbuf *r, const uint8_t *want, size_t n) {
    __CPROVER_assert(n == 0 || __CPROVER_r_ok(want, n), "read_exact: pattern readable");
    return reader_ok(r);
}

int x509_skip(rbuf *r, uint8_t tag) {
    (void)tag;
    return reader_ok(r);
}

int x509_read_serial(rbuf *r) {
    return reader_ok(r);
}

int x509_read_bitstring(rbuf *r, const uint8_t **bytes, size_t *n) {
    __CPROVER_assert(__CPROVER_w_ok(bytes, sizeof *bytes), "bitstring: pointer writable");
    __CPROVER_assert(__CPROVER_w_ok(n, sizeof *n), "bitstring: length writable");
    if (!reader_ok(r)) {
        return 0;
    }
    size_t k = nondet_size_t();
    __CPROVER_assume(k <= sizeof der_buf);
    *bytes = der_buf;
    *n = k;
    return 1;
}

int x509_read_extension(rbuf *e, size_t tlv_cap, x509_extension *out) {
    __CPROVER_assert(__CPROVER_w_ok(out, sizeof *out), "read_extension: output writable");
    __CPROVER_assert(tlv_cap == CH_X509_EXT_TLV_MAX, "read_extension: the walker's own cap");
    if (!reader_ok(e)) {
        return 0;
    }
    size_t oid_len = nondet_size_t();
    size_t val_len = nondet_size_t();
    __CPROVER_assume(oid_len <= sizeof der_buf && val_len <= sizeof der_buf);
    out->oid = der_buf;
    out->oid_len = oid_len;
    out->value = der_buf;
    out->value_len = val_len;
    out->critical = nondet_int();
    return 1;
}

int x509_read_keyusage(const uint8_t *v, size_t n, uint8_t required) {
    __CPROVER_assert(n == 0 || __CPROVER_r_ok(v, n), "keyusage: value readable");
    __CPROVER_assert(required == 0x04, "keyusage: the provisioning walk asks for keyCertSign");
    return nondet_int();
}

// Wider than the real function's outputs on purpose: see the header.
int x509_read_spki(rbuf *r, const uint8_t **key, size_t *key_len) {
    __CPROVER_assert(__CPROVER_w_ok(key, sizeof *key), "spki: pointer writable");
    __CPROVER_assert(__CPROVER_w_ok(key_len, sizeof *key_len), "spki: length writable");
    if (!reader_ok(r)) {
        // x509_read_spki leaves its outputs set on some failing paths,
        // which is exactly why the entry clears them itself. Model that.
        *key = der_buf;
        *key_len = nondet_size_t();
        return 0;
    }
    size_t n = nondet_size_t();
    __CPROVER_assume(n <= sizeof der_buf);
    *key = der_buf;
    *key_len = n;
    return 1;
}

#include "x509_ca.c"

int main(void) {
    fill_nondet(der_buf, sizeof der_buf);

    uint8_t pem[CH_CA_PROOF_PEM_LEN];
    fill_nondet(pem, sizeof pem);
    size_t pem_len = nondet_size_t();
    __CPROVER_assume(pem_len <= sizeof pem);

    uint8_t der[CH_X509_MAX];
    uint8_t key[CH_X509_KEY_MAX];
    fill_nondet(key, sizeof key);
    size_t key_len = nondet_size_t();

    int rc = ch_pubkey_from_pem(pem, pem_len, der, key, &key_len);

    __CPROVER_assert(rc == CH_OK || rc == CH_EINVAL, "ch_pubkey_from_pem: two codes only");
    if (rc == CH_OK) {
        __CPROVER_assert(key_len > 0 && key_len <= CH_X509_KEY_MAX,
                         "CH_OK: a non-empty key inside the caller's array");
    } else {
        __CPROVER_assert(key_len == 0, "CH_EINVAL: the length is zero");
        for (size_t i = 0; i < sizeof key; i++) {
            __CPROVER_assert(key[i] == 0, "CH_EINVAL: the key is wiped");
        }
    }
    return 0;
}
