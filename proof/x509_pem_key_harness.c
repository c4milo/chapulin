// Proves two things about x509_pem.c.
//
// The two key readers are x509_pem_read_pkcs8 and x509_pem_read_sec1.
// They are memory-safe and UB-free over a key's DER of any n bytes up to
// one past CH_PEM_KEY_DER_MAX, the room pem_files.c decodes a key into.
// They
// honour their contract (x509_pem.h). On 1, the point, when there is
// one, is 64 bytes inside the DER. On 0, the scalar holds what the caller
// left, so a refusal copies out no byte of the secret.
//
// x509_pem_parameters_are_p256 is memory-safe over an EC PARAMETERS
// block's DER of any n bytes up to one past CH_PEM_PARAMETERS_DER_MAX,
// the room pem_files.c decodes it into. It answers 1 for prime256v1's
// OBJECT IDENTIFIER alone: on 1, n is 10 and the bytes are the OID's.
//
// Concrete, as proof/x509_pem_harness.c is. The DER primitives in
// x509_der.c, rbuf (buf.c) and ct_memeq (ct.c) are real. The DER is a
// heap object of exactly n bytes.
#include "harness.h"

#include <stdlib.h>

#include "pem.h"
#include "x509_pem.c"

// 1 when [inner, inner + inner_len) lies inside [outer, outer + outer_len).
static int inside(const uint8_t *outer, size_t outer_len, const uint8_t *inner, size_t inner_len) {
    return inner != NULL && inner >= outer && inner_len <= outer_len &&
           (size_t)(inner - outer) <= outer_len - inner_len;
}

static void prove_key(int pkcs8) {
    size_t n = nondet_size_t();
    __CPROVER_assume(n <= CH_PEM_KEY_DER_MAX + 1);
    uint8_t *der = malloc(n);
    __CPROVER_assume(der != NULL);
    uint8_t scalar[32];
    uint8_t before[32];
    fill_nondet(scalar, sizeof scalar);
    for (size_t i = 0; i < sizeof scalar; i++) {
        before[i] = scalar[i];
    }
    const uint8_t *point = NULL;
    int ok = pkcs8 ? x509_pem_read_pkcs8(der, n, scalar, &point)
                   : x509_pem_read_sec1(der, n, scalar, &point);
    __CPROVER_assert(ok == 0 || ok == 1, "key reader: a flag");
    if (ok) {
        __CPROVER_assert(point == NULL || inside(der, n, point, 64),
                         "1: the point is 64 bytes inside the DER");
    } else {
        for (size_t i = 0; i < sizeof scalar; i++) {
            __CPROVER_assert(scalar[i] == before[i], "0: no byte of the scalar is written");
        }
    }
    free(der);
}

static void prove_parameters(void) {
    static const uint8_t prime256v1[] = {0x06, 0x08, 0x2a, 0x86, 0x48,
                                         0xce, 0x3d, 0x03, 0x01, 0x07};
    size_t n = nondet_size_t();
    __CPROVER_assume(n <= CH_PEM_PARAMETERS_DER_MAX + 1);
    uint8_t *der = malloc(n);
    __CPROVER_assume(der != NULL);
    int ok = x509_pem_parameters_are_p256(der, n);
    __CPROVER_assert(ok == 0 || ok == 1, "parameters: a flag");
    if (ok) {
        __CPROVER_assert(n == sizeof prime256v1, "1: the OID's ten bytes");
        for (size_t i = 0; i < sizeof prime256v1; i++) {
            __CPROVER_assert(der[i] == prime256v1[i], "1: the bytes are prime256v1's OID");
        }
    }
    free(der);
}

int main(void) {
    prove_key(1);
    prove_key(0);
    prove_parameters();
    return 0;
}
