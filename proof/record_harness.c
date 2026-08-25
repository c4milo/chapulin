// Proves: rec_dir_init/update, rec_seal, and rec_open are memory-safe and
// UB-free — rec_open on FULLY HOSTILE bytes (any string up to 160 bytes
// presented as a record), both into a separate buffer and in place
// (pt == rec, the shape both shipped callers use), and rec_seal across
// its size contract and over the whole rec_dir domain: any key, IV, and
// sequence number — the seq == UINT64_MAX arm both seal and open refuse
// included — into an output buffer of any claimed size. The padding
// strip and type extraction run over havoc'd plaintext, which covers
// every decrypt result the AEAD could ever produce.
//
// Layered proof: hkdf and aead are replaced by stubs asserting the
// contracts their own harnesses proved — hkdf_expand_label's stub also
// asserts its callee's CH_ASSERT preconditions, so a caller change
// violating them fails here, not only at runtime — havocing outputs.
// aead_open's stub writes plaintext only when it reports success —
// exactly the all-or-nothing property the aead proof established. The
// functional round-trip (type/length preserved) is proven at the aead
// layer and tested end to end in unit and e2e.
#include "harness.h"

#include <string.h>

#include "aead.h"
#include "hkdf.h"

void hkdf_expand_label(const uint8_t secret[SHA256_LEN], const char *label, const uint8_t *ctx,
                       size_t ctx_len, uint8_t *out, size_t out_len) {
    __CPROVER_assert(__CPROVER_r_ok(secret, SHA256_LEN), "label: secret readable");
    __CPROVER_assert(__CPROVER_r_ok(label, 1), "label: label readable");
    __CPROVER_assert(ctx_len == 0 || __CPROVER_r_ok(ctx, ctx_len), "label: ctx readable");
    __CPROVER_assert(__CPROVER_w_ok(out, out_len), "label: output writable");
    // The callee's CH_ASSERT preconditions (hkdf.c), asserted so a
    // caller that breaks them fails this proof, not only the runtime.
    size_t label_len = strlen(label);
    __CPROVER_assert(label_len > 0 && label_len <= HKDF_LABEL_MAX, "label: length in contract");
    __CPROVER_assert(ctx_len <= SHA256_LEN, "label: ctx within contract");
    __CPROVER_assert(out_len <= 0xffff, "label: output within contract");
    fill_nondet(out, out_len);
}

void aead_seal(const uint8_t key[AEAD_KEY], const uint8_t nonce[AEAD_NONCE], const uint8_t *aad,
               size_t aad_len, const uint8_t *pt, size_t n, uint8_t *ct, uint8_t tag[AEAD_TAG]) {
    __CPROVER_assert(__CPROVER_r_ok(key, AEAD_KEY), "seal: key readable");
    __CPROVER_assert(__CPROVER_r_ok(nonce, AEAD_NONCE), "seal: nonce readable");
    __CPROVER_assert(aad_len == 0 || __CPROVER_r_ok(aad, aad_len), "seal: aad readable");
    __CPROVER_assert(n == 0 || __CPROVER_r_ok(pt, n), "seal: pt readable");
    __CPROVER_assert(n == 0 || __CPROVER_w_ok(ct, n), "seal: ct writable");
    __CPROVER_assert(__CPROVER_w_ok(tag, AEAD_TAG), "seal: tag writable");
    fill_nondet(ct, n);
    fill_nondet(tag, AEAD_TAG);
}

int aead_open(const uint8_t key[AEAD_KEY], const uint8_t nonce[AEAD_NONCE], const uint8_t *aad,
              size_t aad_len, const uint8_t *ct, size_t n, const uint8_t tag[AEAD_TAG],
              uint8_t *pt) {
    __CPROVER_assert(__CPROVER_r_ok(key, AEAD_KEY), "open: key readable");
    __CPROVER_assert(__CPROVER_r_ok(nonce, AEAD_NONCE), "open: nonce readable");
    __CPROVER_assert(aad_len == 0 || __CPROVER_r_ok(aad, aad_len), "open: aad readable");
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

// Spec.Record.nonce_inj, proved of the model, asserted here of the C:
// distinct sequence numbers under one traffic key never build the same
// nonce. A repeat would reuse a ChaCha20-Poly1305 nonce, which loses
// confidentiality and lets a forgery through, so this is the one record
// property worth proving over every input rather than sampling.
static void nonce_is_injective(void) {
    rec_dir lo;
    rec_dir hi;
    fill_nondet(lo.iv, AEAD_NONCE);
    for (size_t i = 0; i < AEAD_NONCE; i++) {
        hi.iv[i] = lo.iv[i]; // one traffic key, so one IV
    }
    uint8_t lo_bytes[8];
    uint8_t hi_bytes[8];
    fill_nondet(lo_bytes, sizeof lo_bytes);
    fill_nondet(hi_bytes, sizeof hi_bytes);
    lo.seq = 0;
    hi.seq = 0;
    for (size_t i = 0; i < 8; i++) {
        lo.seq = (lo.seq << 8) | lo_bytes[i];
        hi.seq = (hi.seq << 8) | hi_bytes[i];
    }
    __CPROVER_assume(lo.seq != hi.seq);

    uint8_t lo_nonce[AEAD_NONCE];
    uint8_t hi_nonce[AEAD_NONCE];
    nonce_of(&lo, lo_nonce);
    nonce_of(&hi, hi_nonce);

    int differs = 0;
    for (size_t i = 0; i < AEAD_NONCE; i++) {
        if (lo_nonce[i] != hi_nonce[i]) {
            differs = 1;
        }
    }
    __CPROVER_assert(differs, "distinct sequence numbers build distinct nonces");
}

int main(void) {
    nonce_is_injective();

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
    size_t record_len = 0;
    __CPROVER_assert(rec_seal(&tx, nondet_u8(), pt, n, rec, sizeof rec, &record_len) == 0,
                     "seal fits");

    // Hostile input: any bytes, any claimed length; must return, not trap.
    uint8_t evil[160];
    fill_nondet(evil, sizeof evil);
    size_t evil_len = nondet_size_t();
    __CPROVER_assume(evil_len <= sizeof evil);
    uint8_t out[160];
    size_t out_len = 0;
    uint8_t outer_type = 0;
    (void)rec_open(&tx, evil, evil_len, out, sizeof out, &out_len, &outer_type);

    // The whole rec_dir domain — any key, IV, and sequence number,
    // covering the seq == UINT64_MAX refusal — with an output buffer of
    // any claimed size, so the short-buffer arm fires too.
    rec_dir any;
    fill_nondet(any.key, AEAD_KEY);
    fill_nondet(any.iv, AEAD_NONCE);
    any.seq = (uint64_t)nondet_i64();
    fill_nondet(pt, sizeof pt);
    n = nondet_size_t();
    __CPROVER_assume(n <= sizeof pt);
    size_t cap = nondet_size_t();
    __CPROVER_assume(cap <= sizeof rec);
    (void)rec_seal(&any, nondet_u8(), pt, n, rec, cap, &record_len);

    // Both shipped callers decrypt in place (pt == rec), so the proof
    // drives that shape from the havocked direction state.
    fill_nondet(evil, sizeof evil);
    evil_len = nondet_size_t();
    __CPROVER_assume(evil_len <= sizeof evil);
    (void)rec_open(&any, evil, evil_len, evil, sizeof evil, &out_len, &outer_type);
    return 0;
}
