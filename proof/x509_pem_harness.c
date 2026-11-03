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
// the readers call are stubs (proof/x509_der_layer.h). They assert their contracts and havoc
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

#include "x509_der_layer.h"

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
