// Proves: x509_pem.c's two RSA readers, in a server role, are memory-safe
// and UB-free over every input of up to 2^40 bytes, and honour their
// contracts (x509_pem.h):
//
//   - x509_pem_read_rsa_pkcs8, over a key's DER of any n bytes up to 2^40.
//     On 1, each of the seven INTEGERs it returns is one or more octets
//     inside the DER;
//   - x509_pem_spki_is_rsa, over any SubjectPublicKeyInfo up to that size
//     and any modulus up to CH_RSA_MODULUS_MAX bytes: a flag.
//
// 2^40 stands for no cap, as in proof/x509_pem_harness.c. The key call
// decodes into a room of CH_PEM_RSA_KEY_DER_MAX bytes, and it passes its
// caller's leaf with no cap of its own.
//
// Layered, as proof/x509_pem_harness.c is: the three x509_der.h
// primitives are proof/x509_der_layer.h's stubs, and x509_der.c is not
// linked. So the object under proof is each reader's own order of steps
// over a real rbuf (buf.c). Over the real primitives a DER of up to
// CH_PEM_RSA_KEY_DER_MAX + 1 bytes returned no verdict in 20 minutes.
// proof/x509_pem_rsa_integer_harness.c proves x509_pem_integer_to_bytes
// over its real code.
//
// Each input is a heap object of exactly n bytes, so a read at input[n]
// is a bounds failure whatever n is.
#include "harness.h"

#include <stdlib.h>

#include "rsa.h" // CH_RSA_MODULUS_MAX

#include "x509_der_layer.h"

#include "x509_pem.c"

// 1 when [inner, inner + inner_len) lies inside [outer, outer + outer_len).
static int inside(const uint8_t *outer, size_t outer_len, const uint8_t *inner, size_t inner_len) {
    return inner != NULL && inner >= outer && inner_len <= outer_len &&
           (size_t)(inner - outer) <= outer_len - inner_len;
}

static void prove_pkcs8(void) {
    size_t n = nondet_size_t();
    __CPROVER_assume(n <= INPUT_MAX);
    uint8_t *der = malloc(n);
    __CPROVER_assume(der != NULL);
    x509_pem_rsa_key key;
    int ok = x509_pem_read_rsa_pkcs8(der, n, &key);
    __CPROVER_assert(ok == 0 || ok == 1, "pkcs8: a flag");
    if (ok) {
        const x509_pem_integer *fields[] = {&key.n,  &key.d,  &key.p,   &key.q,
                                            &key.dp, &key.dq, &key.qinv};
        for (size_t i = 0; i < 7; i++) {
            __CPROVER_assert(fields[i]->len >= 1 &&
                                 inside(der, n, fields[i]->bytes, fields[i]->len),
                             "1: each INTEGER's octets inside the DER");
        }
    }
    free(der);
}

static void prove_spki(void) {
    size_t spki_len = nondet_size_t();
    size_t n_len = nondet_size_t();
    __CPROVER_assume(spki_len <= INPUT_MAX && n_len >= 1 && n_len <= CH_RSA_MODULUS_MAX);
    uint8_t *spki = malloc(spki_len);
    uint8_t *n = malloc(n_len);
    __CPROVER_assume(spki != NULL && n != NULL);
    int ok = x509_pem_spki_is_rsa(spki, spki_len, n, n_len);
    __CPROVER_assert(ok == 0 || ok == 1, "spki: a flag");
    free(spki);
    free(n);
}

int main(void) {
    prove_pkcs8();
    prove_spki();
    return 0;
}
