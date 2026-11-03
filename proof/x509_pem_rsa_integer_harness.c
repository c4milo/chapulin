// Proves: x509_pem_integer_to_bytes (x509_pem.c), in a server role, is
// memory-safe and UB-free over content octets of any length up to two
// past its field, at the two field lengths the key call passes at the
// modulus bound, CH_RSA_MODULUS_MAX and half of it. Over a field of
// symbolic length up to that bound the formula gave no verdict in 25
// minutes. Over fields of up to PROOF_VALUE_MAX bytes and content of up to
// two octets more, it honours its contract (x509_pem.h): it answers 1
// exactly for a canonical non-negative INTEGER whose value fits the
// field, and then the field holds the value, padded on the left with zero
// bytes.
//
// Concrete: the function reads no x509_der.h primitive, and runs over its
// real code. Each input of the first part is a heap object of exactly its
// length.
#include "harness.h"

#include <stdlib.h>

#include "rsa.h" // CH_RSA_MODULUS_MAX

#include "x509_pem.c"

// The longest field the functional part reads.
#define PROOF_VALUE_MAX 6

// Memory safety at the two field lengths the key call passes at the
// modulus bound: CH_RSA_MODULUS_MAX for n and d, and half of it for the
// CRT values. The content's length is any one up to two past the field.
static void prove_bounds(size_t out_len) {
    size_t len = nondet_size_t();
    __CPROVER_assume(len <= out_len + 2);
    uint8_t *octets = malloc(len);
    uint8_t *out = malloc(out_len);
    __CPROVER_assume((octets != NULL || len == 0) && out != NULL);
    x509_pem_integer v = {octets, len};
    int ok = x509_pem_integer_to_bytes(v, out, out_len);
    __CPROVER_assert(ok == 0 || ok == 1, "integer: a flag");
    free(octets);
    free(out);
}

// The contract, over small lengths: the answer and the bytes.
static void prove_contract(void) {
    size_t out_len = nondet_size_t();
    size_t len = nondet_size_t();
    __CPROVER_assume(out_len >= 1 && out_len <= PROOF_VALUE_MAX && len >= 1 &&
                     len <= PROOF_VALUE_MAX + 2);
    uint8_t octets[PROOF_VALUE_MAX + 2];
    uint8_t out[PROOF_VALUE_MAX];
    fill_nondet(octets, sizeof octets);
    x509_pem_integer v = {octets, len};
    int ok = x509_pem_integer_to_bytes(v, out, out_len);
    // X.690 section 8.3.2: no leading zero octet before an octet whose top
    // bit is clear. A top bit set in the first octet makes it negative.
    int canonical = (octets[0] & 0x80) == 0 && !(len > 1 && octets[0] == 0 && octets[1] < 0x80);
    size_t lead = len > 1 && octets[0] == 0 ? 1 : 0;
    int fits = len - lead <= out_len;
    __CPROVER_assert(ok == (canonical && fits), "integer: 1 for a canonical value that fits");
    if (ok) {
        size_t pad = out_len - (len - lead);
        for (size_t i = 0; i < out_len; i++) {
            uint8_t want = i < pad ? 0 : octets[lead + i - pad];
            __CPROVER_assert(out[i] == want, "integer: the value, padded on the left");
        }
    }
}

int main(void) {
    prove_bounds(CH_RSA_MODULUS_MAX);
    prove_bounds(CH_RSA_MODULUS_MAX / 2);
    prove_contract();
    return 0;
}
