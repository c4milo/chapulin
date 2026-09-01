// Known-answer main for the Cortex-M3 QEMU smoke run: SHA-256, x25519
// and the AEAD, each printed as hex through the platform hook. The
// harness builds this file twice -- once for the host, once for
// thumbv7m -- and the two outputs must be byte-identical, with the
// SHA-256 line also checked against the FIPS 180-4 "abc" vector so
// host and target cannot both be wrong the same way.
//
// No libc: the runtime file supplies plat_write/plat_exit and the mem
// routines, and every input here is fixed.
#include <stddef.h>
#include <stdint.h>
#include <stdnoreturn.h>

#include "aead.h"
#include "sha256.h"
#include "x25519.h"

void plat_write(const char *s);
void plat_exit(int code);

noreturn void ch_assert_fail(const char *cond, const char *file, int line) {
    (void)cond;
    (void)file;
    (void)line;
    plat_write("ASSERT\n");
    plat_exit(1);
    for (;;) {}
}

static void put_hex(const char *label, const uint8_t *p, size_t n) {
    static const char digits[] = "0123456789abcdef";
    char line[2 * 64 + 2];
    size_t o = 0;
    for (size_t i = 0; i < n && o + 2 < sizeof line - 1; i++) {
        line[o++] = digits[p[i] >> 4];
        line[o++] = digits[p[i] & 0xF];
    }
    line[o++] = '\n';
    line[o] = 0;
    plat_write(label);
    plat_write(line);
}

int main(void) {
    // FIPS 180-4: the "abc" vector.
    uint8_t digest[SHA256_LEN];
    sha256_of((const uint8_t *)"abc", 3, digest);
    put_hex("sha256 ", digest, sizeof digest);

    // x25519 of a fixed scalar times the base point. The scalar is
    // arbitrary but fixed; the check is host == target, not a
    // published vector.
    uint8_t scalar[X25519_LEN];
    for (size_t i = 0; i < sizeof scalar; i++) {
        scalar[i] = (uint8_t)(i * 7 + 1);
    }
    uint8_t point[X25519_LEN];
    x25519_base(point, scalar);
    put_hex("x25519 ", point, sizeof point);

    // One AEAD seal over fixed key, nonce, aad and plaintext.
    uint8_t key[AEAD_KEY];
    uint8_t nonce[AEAD_NONCE];
    uint8_t pt[32];
    uint8_t ct[32];
    uint8_t tag[AEAD_TAG];
    for (size_t i = 0; i < sizeof key; i++) {
        key[i] = (uint8_t)(0xA0 + i);
    }
    for (size_t i = 0; i < sizeof nonce; i++) {
        nonce[i] = (uint8_t)(0x50 + i);
    }
    for (size_t i = 0; i < sizeof pt; i++) {
        pt[i] = (uint8_t)i;
    }
    aead_seal(key, nonce, (const uint8_t *)"aad", 3, pt, sizeof pt, ct, tag);
    put_hex("aead-ct ", ct, sizeof ct);
    put_hex("aead-tag ", tag, sizeof tag);

    // And the tag must open again on the target itself.
    uint8_t back[32];
    if (aead_open(key, nonce, (const uint8_t *)"aad", 3, ct, sizeof ct, tag, back) != 1) {
        plat_write("FAIL aead reopen\n");
        plat_exit(1);
    }
    plat_write("PASS\n");
    plat_exit(0);
    return 0;
}
