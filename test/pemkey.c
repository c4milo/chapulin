// Provisioning tool for the e2e suite: reads one PEM certificate and
// prints the public key ch_pubkey_from_pem extracts, as lowercase hex.
// Exits 1 and prints nothing when the certificate is rejected.
//
// The suite compares its output against the key openssl reports for
// the same material, which is the only place a real openssl-produced
// armour reaches the decoder.
#include <stdio.h>
#include <stdlib.h>
#include <stdnoreturn.h>

#include "pem.h"
#include "x509_ca.h"

noreturn void ch_assert_fail(const char *cond, const char *file, int line) {
    (void)fprintf(stderr, "ASSERT %s:%d: %s\n", file, line, cond);
    abort();
}

int main(int argc, char **argv) {
    if (argc != 2) {
        (void)fprintf(stderr, "usage: pemkey <certificate.pem>\n");
        return 2;
    }
    static uint8_t pem[CH_PEM_MAX + 1];
    FILE *f = fopen(argv[1], "rb");
    if (f == NULL) {
        perror(argv[1]);
        return 2;
    }
    size_t n = fread(pem, 1, sizeof pem, f);
    (void)fclose(f);

    static uint8_t der[CH_X509_MAX];
    static uint8_t key[CH_X509_KEY_MAX];
    size_t key_len = 0;
    if (ch_pubkey_from_pem(pem, n, der, key, &key_len) != CH_OK) {
        return 1;
    }
    for (size_t i = 0; i < key_len; i++) {
        (void)printf("%02x", key[i]);
    }
    (void)printf("\n");
    return 0;
}
