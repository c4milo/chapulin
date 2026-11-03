// The three x509_der.h primitives as stubs, for a harness that proves a
// reader of x509_pem.c over inputs of up to 2^40 bytes. Each stub asserts
// its contract and havocs within what proof/x509der_harness.c proves. A
// primitive that succeeds consumes bytes the reader still held:
// x509_read_header and x509_skip at least a tag and a length octet, and
// x509_read_exact exactly the bytes it compares. proof/x509_pem_harness.c
// and proof/x509_pem_rsa_harness.c include it, and neither links
// x509_der.c.
#ifndef CH_PROOF_X509_DER_LAYER_H
#define CH_PROOF_X509_DER_LAYER_H

#include "buf.h"
#include "harness.h"
#include "x509_der.h"

// The largest input: 2^40 bytes, past any object a caller holds.
#define INPUT_MAX ((size_t)1 << 40)

int nondet_int(void);

// One primitive's consumption: fails, or takes `least` to all of what is
// left.
static int consumed(rbuf *r, size_t least) {
    __CPROVER_assert(__CPROVER_w_ok(r, sizeof *r), "primitive: rbuf writable");
    if (r->err || !nondet_int() || rb_left(r) < least) {
        return 0;
    }
    size_t used = nondet_size_t();
    __CPROVER_assume(used >= least && used <= rb_left(r));
    rb_skip(r, used);
    return 1;
}

int x509_read_header(rbuf *r, uint8_t tag, size_t *out_len) {
    (void)tag;
    __CPROVER_assert(__CPROVER_w_ok(out_len, sizeof *out_len), "read_header: length writable");
    if (!consumed(r, 2)) {
        return 0;
    }
    size_t len = nondet_size_t();
    __CPROVER_assume(len <= rb_left(r));
    *out_len = len;
    return 1;
}

int x509_skip(rbuf *r, uint8_t tag) {
    (void)tag;
    return consumed(r, 2);
}

int x509_read_exact(rbuf *r, const uint8_t *want, size_t n) {
    __CPROVER_assert(n == 0 || __CPROVER_r_ok(want, n), "read_exact: pattern readable");
    __CPROVER_assert(__CPROVER_w_ok(r, sizeof *r), "read_exact: rbuf writable");
    if (r->err || rb_left(r) < n || !nondet_int()) {
        return 0;
    }
    rb_skip(r, n);
    return 1;
}

#endif
