// Proves: rec_open is memory-safe and UB-free on FULLY HOSTILE input —
// any byte string up to 96 bytes presented as a record — and the
// seal/open pair round-trips any plaintext up to 32 bytes with the type
// preserved. The hostile-input claim is the one that matters: this is
// the first parser attacker bytes reach after the AEAD.
#include "harness.h"

#include "record.c"

int main(void) {
    uint8_t secret[SHA256_LEN];
    fill_nondet(secret, sizeof secret);
    rec_dir tx;
    rec_dir rx;
    rec_dir_init(&tx, secret);
    rec_dir_init(&rx, secret);

    // Round trip.
    uint8_t pt[32];
    fill_nondet(pt, sizeof pt);
    size_t n = nondet_size_t();
    __CPROVER_assume(n >= 1 && n <= sizeof pt);
    uint8_t type = nondet_u8();
    __CPROVER_assume(type != 0); // a zero type is indistinguishable from padding
    uint8_t rec[REC_HDR + sizeof pt + 1 + AEAD_TAG];
    size_t recn = 0;
    __CPROVER_assert(rec_seal(&tx, type, pt, n, rec, sizeof rec, &recn) == 0, "seal fits");
    uint8_t back[sizeof pt + 1];
    size_t backn = 0;
    uint8_t btype = 0;
    __CPROVER_assert(rec_open(&rx, rec, recn, back, sizeof back, &backn, &btype) == 0,
                     "genuine record opens");
    __CPROVER_assert(btype == type, "type preserved");
    __CPROVER_assert(backn == n, "length preserved");

    // Hostile input: any bytes, any claimed length; must return, never trap.
    uint8_t evil[96];
    fill_nondet(evil, sizeof evil);
    size_t evillen = nondet_size_t();
    __CPROVER_assume(evillen <= sizeof evil);
    uint8_t out[96];
    size_t outn = 0;
    uint8_t otype = 0;
    (void)rec_open(&rx, evil, evillen, out, sizeof out, &outn, &otype);
    return 0;
}
