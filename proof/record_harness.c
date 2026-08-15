// Proves: rec_dir_init/update, rec_seal, and rec_open are memory-safe and
// UB-free — rec_open on FULLY HOSTILE bytes (any string up to 160 bytes
// presented as a record), rec_seal across its size contract. The padding
// strip and type extraction run over havoc'd plaintext, which covers
// every decrypt result the AEAD could ever produce.
//
// Layered proof: hkdf and aead are replaced by stubs asserting the
// contracts their own harnesses proved, havocing outputs. aead_open's
// stub writes plaintext only when it reports success — exactly the
// all-or-nothing property the aead proof established. The functional
// round-trip (type/length preserved) is proven at the aead layer and
// tested end to end in unit and e2e.
#include "harness.h"

#include "aead.h"
#include "hkdf.h"

void hkdf_expand_label(const uint8_t secret[SHA256_LEN], const char *label, const uint8_t *ctx,
                       size_t ctxlen, uint8_t *out, size_t outlen) {
    __CPROVER_assert(__CPROVER_r_ok(secret, SHA256_LEN), "label: secret readable");
    __CPROVER_assert(__CPROVER_r_ok(label, 1), "label: label readable");
    __CPROVER_assert(ctxlen == 0 || __CPROVER_r_ok(ctx, ctxlen), "label: ctx readable");
    __CPROVER_assert(__CPROVER_w_ok(out, outlen), "label: output writable");
    fill_nondet(out, outlen);
}

void aead_seal(const uint8_t key[AEAD_KEY], const uint8_t nonce[AEAD_NONCE], const uint8_t *aad,
               size_t aadlen, const uint8_t *pt, size_t n, uint8_t *ct, uint8_t tag[AEAD_TAG]) {
    __CPROVER_assert(__CPROVER_r_ok(key, AEAD_KEY), "seal: key readable");
    __CPROVER_assert(__CPROVER_r_ok(nonce, AEAD_NONCE), "seal: nonce readable");
    __CPROVER_assert(aadlen == 0 || __CPROVER_r_ok(aad, aadlen), "seal: aad readable");
    __CPROVER_assert(n == 0 || __CPROVER_r_ok(pt, n), "seal: pt readable");
    __CPROVER_assert(n == 0 || __CPROVER_w_ok(ct, n), "seal: ct writable");
    __CPROVER_assert(__CPROVER_w_ok(tag, AEAD_TAG), "seal: tag writable");
    fill_nondet(ct, n);
    fill_nondet(tag, AEAD_TAG);
}

int aead_open(const uint8_t key[AEAD_KEY], const uint8_t nonce[AEAD_NONCE], const uint8_t *aad,
              size_t aadlen, const uint8_t *ct, size_t n, const uint8_t tag[AEAD_TAG],
              uint8_t *pt) {
    __CPROVER_assert(__CPROVER_r_ok(key, AEAD_KEY), "open: key readable");
    __CPROVER_assert(__CPROVER_r_ok(nonce, AEAD_NONCE), "open: nonce readable");
    __CPROVER_assert(aadlen == 0 || __CPROVER_r_ok(aad, aadlen), "open: aad readable");
    __CPROVER_assert(n == 0 || __CPROVER_r_ok(ct, n), "open: ct readable");
    __CPROVER_assert(__CPROVER_r_ok(tag, AEAD_TAG), "open: tag readable");
    if (nondet_u8() & 1) {
        __CPROVER_assert(n == 0 || __CPROVER_w_ok(pt, n), "open: pt writable");
        fill_nondet(pt, n); // success: any plaintext the AEAD could yield
        return 1;
    }
    return 0; // failure: writes nothing, like the proven aead contract
}

#include "record.c"

int main(void) {
    uint8_t secret[SHA256_LEN];
    fill_nondet(secret, sizeof secret);
    rec_dir tx;
    rec_dir_init(&tx, secret);
    rec_dir_update(secret, &tx);

    // Seal across the size contract, including n = 0 (KeyUpdate-sized).
    uint8_t pt[64];
    fill_nondet(pt, sizeof pt);
    size_t n = nondet_size_t();
    __CPROVER_assume(n <= sizeof pt);
    uint8_t rec[REC_HDR + sizeof pt + 1 + AEAD_TAG];
    size_t recn = 0;
    __CPROVER_assert(rec_seal(&tx, nondet_u8(), pt, n, rec, sizeof rec, &recn) == 0, "seal fits");

    // Hostile input: any bytes, any claimed length; must return, not trap.
    uint8_t evil[160];
    fill_nondet(evil, sizeof evil);
    size_t evillen = nondet_size_t();
    __CPROVER_assume(evillen <= sizeof evil);
    uint8_t out[160];
    size_t outn = 0;
    uint8_t otype = 0;
    (void)rec_open(&tx, evil, evillen, out, sizeof out, &outn, &otype);
    return 0;
}
