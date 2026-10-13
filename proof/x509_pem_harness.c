// Proves: the two certificate readers of x509_pem.c are memory-safe and
// UB-free over every input of up to 2^40 bytes, and honour their
// contracts (x509_pem.h):
//
//   - x509_pem_read_subject_key, over a certificate of any n bytes up to
//     2^40. On 1, the subject Name and the subjectPublicKeyInfo are whole
//     TLVs of two bytes or more inside the certificate, the Name first;
//   - x509_pem_spki_is_p256, over any SubjectPublicKeyInfo up to that
//     size: a flag, and 1 only for exactly 91 bytes.
//
// 2^40 stands for no cap. ch_p256_key_from_pem passes its caller's leaf
// with no cap of its own. A chain's and a bundle's blocks are at most the
// caller's DER room. No leaf that a caller holds in memory is 2^40 bytes
// long.
//
// proof/x509_pem_key_harness.c proves the two key readers.
//
// Layered, as the x509ca harness is. The three x509_der.h primitives that
// the readers call are stubs. They assert their contracts and havoc
// within what proof/x509der_harness.c proves. So x509_der.c is not
// linked, and the object under proof is the walk's own order of steps
// over a real rbuf (buf.c). A primitive that succeeds consumes bytes the
// reader still held. x509_read_header and x509_skip consume at least a
// tag and a length octet, and x509_read_exact exactly the bytes it
// compares. The walk over the real primitives returned no verdict in 300
// s at a load average near 30, and 39 s in these layers. The key readers,
// whose DER is under 160 bytes, run over the real ones.
//
// Each input is a heap object of exactly n bytes, as in webpki_cert_key,
// so a read at input[n] is a bounds failure whatever n is.
#include "harness.h"

#include <stdlib.h>

#include "buf.h"
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

#include "x509_pem.c"

// 1 when [inner, inner + inner_len) lies inside [outer, outer + outer_len).
static int inside(const uint8_t *outer, size_t outer_len, const uint8_t *inner, size_t inner_len) {
    return inner != NULL && inner >= outer && inner_len <= outer_len &&
           (size_t)(inner - outer) <= outer_len - inner_len;
}

static void prove_subject_key(void) {
    size_t n = nondet_size_t();
    __CPROVER_assume(n <= INPUT_MAX);
    uint8_t *cert = malloc(n);
    __CPROVER_assume(cert != NULL);
    const uint8_t *name = NULL;
    const uint8_t *spki = NULL;
    size_t name_len = 0;
    size_t spki_len = 0;
    if (x509_pem_read_subject_key(cert, n, &name, &name_len, &spki, &spki_len)) {
        __CPROVER_assert(inside(cert, n, name, name_len) && name_len >= 2,
                         "subject: a whole TLV inside the certificate");
        __CPROVER_assert(inside(cert, n, spki, spki_len) && spki_len >= 2,
                         "subjectPublicKeyInfo: a whole TLV inside the certificate");
        __CPROVER_assert(name + name_len <= spki, "the Name comes before the key");
    }
    free(cert);
}

static void prove_spki_is_p256(void) {
    size_t n = nondet_size_t();
    __CPROVER_assume(n <= INPUT_MAX);
    uint8_t *spki = malloc(n);
    __CPROVER_assume(spki != NULL);
    uint8_t point[64];
    fill_nondet(point, sizeof point);
    int is = x509_pem_spki_is_p256(spki, n, point);
    __CPROVER_assert(is == 0 || is == 1, "spki_is_p256: a flag");
    __CPROVER_assert(!is || n == 91, "spki_is_p256: 1 only for the 91 bytes of a P-256 key");
    free(spki);
}

int main(void) {
    prove_subject_key();
    prove_spki_is_p256();
    return 0;
}
