// The keys and certificate lists of the ML-DSA-87 PROFILE=cnsa2 tests
// (docs/decisions.md 157), for test/cnsa2_test.c and test/cnsa2_quic_test.c.
// A root, an intermediate and a server key come from fixed seeds through
// the test-only signer, and the lists are built at run time
// (test/mldsa_cert.h). A raw build pins the server key and reads no
// certificate; a CA build pins the root. Include it after
// test/cnsa2_mock.h. Not a standalone translation unit.
#ifndef CH_CNSA2_MLDSA_FIXTURE_H
#define CH_CNSA2_MLDSA_FIXTURE_H

#include "mldsa_cert.h"

static mldsa_test_key root_key;
static mldsa_test_key int_key;
static mldsa_test_key server_key;
static mldsa_test_key stranger_key; // a key nobody pins
static int fixture_ready;

// A CertificateEntry list of up to three certificates of CH_X509_MAX
// bytes, with a margin for a list that is one byte over.
typedef struct {
    uint8_t bytes[3 * (CH_X509_MAX + 5) + 64];
    size_t len;
} cert_list;

static void fixture_keys(void) {
    if (fixture_ready) {
        return;
    }
    uint8_t seed[32] = {0};
    seed[0] = 1;
    mldsa_test_keygen(&root_key, seed);
    seed[0] = 2;
    mldsa_test_keygen(&int_key, seed);
    seed[0] = 3;
    mldsa_test_keygen(&server_key, seed);
    seed[0] = 4;
    mldsa_test_keygen(&stranger_key, seed);
    fixture_ready = 1;
}

// Appends one CertificateEntry: the u24 length, the certificate and an
// empty extensions vector.
static void list_add(cert_list *l, const uint8_t *cert, size_t n) {
    wbuf w;
    wb_init(&w, l->bytes + l->len, sizeof l->bytes - l->len);
    wb_u24(&w, (uint32_t)n);
    wb_bytes(&w, cert, n);
    wb_u16(&w, 0);
    CHECK(!w.err);
    l->len += w.err ? 0 : w.len;
}

// Builds into out a certificate of exactly size bytes, or the profile's
// natural size when size is 0, by padding the subject name. Returns its
// length.
static size_t cert_of_size(uint8_t *out, const uint8_t *pk, const mldsa_test_key *issuer, int is_ca,
                           size_t size) {
    mldsa_cert_shape shape = {0};
    shape.is_ca = is_ca;
    size_t n = mldsa_cert_build(out, pk, is_ca ? "fleet-intermediate" : "controller-01", issuer,
                                issuer == &root_key ? "fleet-root" : "fleet-intermediate", &shape);
    for (int step = 0; step < 8 && size != 0 && n != size; step++) {
        shape.name_pad = (size_t)((long)shape.name_pad + (long)size - (long)n);
        n = mldsa_cert_build(out, pk, is_ca ? "fleet-intermediate" : "controller-01", issuer,
                             issuer == &root_key ? "fleet-root" : "fleet-intermediate", &shape);
    }
    CHECK(size == 0 || n == size);
    return n;
}

// The server's leaf under the root, alone, at size bytes or its natural
// size.
static void list_flat(cert_list *l, size_t size) {
    static uint8_t cert[CH_X509_MAX + 64];
    l->len = 0;
    list_add(l, cert, cert_of_size(cert, server_key.pk, &root_key, 0, size));
}

#ifdef CH_TRUST_CA
// The server's leaf under the intermediate, then the intermediate under
// the root, each at size bytes or its natural size, and a third entry
// after them when with_third is set. Three ML-DSA-87 certificates pass
// the 16 KiB a handshake message holds, so the third is 16 bytes, which
// the walk refuses before it reads them.
static void list_chain(cert_list *l, size_t size, int with_third) {
    static uint8_t cert[CH_X509_MAX + 64];
    l->len = 0;
    list_add(l, cert, cert_of_size(cert, server_key.pk, &int_key, 0, size));
    list_add(l, cert, cert_of_size(cert, int_key.pk, &root_key, 1, size));
    if (with_third) {
        static const uint8_t third[16] = {0x30, 0x0e};
        list_add(l, third, sizeof third);
    }
}
#endif

#endif
