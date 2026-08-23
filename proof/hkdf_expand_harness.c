// Proves: hkdf_expand and hkdf_expand_label are memory-safe and UB-free
// for any output up to 96 bytes (three blocks: the T(1) special case, the
// chained middle, a partial tail — every structural path), any info up to
// 48, any label 1..12, any context up to 32. The RFC 5869 255-block
// maximum only repeats the middle case, and symbolic offsets over an 8 kB
// output array stall the solver. The extract/hmac half is
// hkdf_harness.c; the sha256 stubs assert its proven contract.
#define CH_PROOF_STUB_SHA256
#include "harness.h"

#include "sha256.h"

#include "hkdf.c"

int main(void) {
    uint8_t info[48];
    uint8_t prk[SHA256_LEN];
    uint8_t out[3 * SHA256_LEN];
    fill_nondet(info, sizeof info);
    fill_nondet(prk, sizeof prk);

    size_t out_len = nondet_size_t();
    size_t info_len = nondet_size_t();
    __CPROVER_assume(out_len >= 1 && out_len <= sizeof out);
    __CPROVER_assume(info_len <= sizeof info);
    hkdf_expand(prk, info, info_len, out, out_len);

    // Any label the contract admits, not just the ones TLS uses today.
    char label[HKDF_LABEL_MAX + 1];
    size_t lab = nondet_size_t();
    __CPROVER_assume(lab >= 1 && lab <= HKDF_LABEL_MAX);
    for (size_t i = 0; i < lab; i++) {
        char c = (char)nondet_u8();
        __CPROVER_assume(c != 0);
        label[i] = c;
    }
    label[lab] = 0;
    size_t ctx_len = nondet_size_t();
    __CPROVER_assume(ctx_len <= SHA256_LEN);
    size_t out_len2 = nondet_size_t();
    __CPROVER_assume(out_len2 >= 1 && out_len2 <= 64);
    hkdf_expand_label(prk, label, info, ctx_len, out, out_len2);
    return 0;
}
