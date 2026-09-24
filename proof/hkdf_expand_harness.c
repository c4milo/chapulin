// Proves: hkdf_expand and hkdf_expand_label are memory-safe and UB-free
// for any output up to 96 bytes (three blocks: the T(1) special case, the
// chained middle, a partial tail — every structural path), any info up to
// HKDF_INFO_MAX — the contract's own CH_ASSERT bound, 54 at the default
// label cap and the size expand_label builds — any label 1..HKDF_LABEL_MAX,
// any context up to 32. The bound was a literal 64 while the cap was
// fixed; it follows the cap now, so the EXPORTER axis, which raises the
// cap to 32, widens this domain with it. One function per formula: each
// call carries a whole expand body, and both in one returned no verdict
// in 1800 s once info reached the bound of 64.
// hkdf_expand_label_harness.c defines the selector and includes this
// file, the handshake variants' pattern. The RFC 5869 255-block
// maximum only repeats the middle case, and symbolic offsets over an 8 kB
// output array stall the solver. The extract/hmac half is
// hkdf_harness.c; the sha256 stubs assert its proven contract.
//
// hkdf384_expand_harness.c and hkdf384_expand_label_harness.c compile
// this file under CH_HASH_SHA384 with hash_len fixed at SHA384_LEN: the
// output reaches three 48-byte blocks, the info buffer grows to 70 bytes
// and the context to 48. The SHA-256 arm of that build, hash_len 32 in
// the larger buffers, is not under proof there; this file's SHA-256
// launch lines prove it in buffers sized exactly to it.
#define CH_PROOF_STUB_SHA256
#include "harness.h"

#include "sha256.h"

#include "hkdf.c"

#ifdef CH_HASH_SHA384
#define PROOF_HASH_LEN SHA384_LEN
#else
#define PROOF_HASH_LEN SHA256_LEN
#endif

int main(void) {
    uint8_t info[HKDF_INFO_MAX];
    uint8_t prk[PROOF_HASH_LEN];
    uint8_t out[(size_t)3 * PROOF_HASH_LEN];
    fill_nondet(info, sizeof info);
    fill_nondet(prk, sizeof prk);

#ifndef CH_PROOF_EXPAND_LABEL
    size_t out_len = nondet_size_t();
    size_t info_len = nondet_size_t();
    __CPROVER_assume(out_len >= 1 && out_len <= sizeof out);
    __CPROVER_assume(info_len <= sizeof info);
    hkdf_expand(PROOF_HASH_LEN, prk, info, info_len, out, out_len);
#else
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
    fill_nondet(info, sizeof info);
    size_t ctx_len = nondet_size_t();
    __CPROVER_assume(ctx_len <= PROOF_HASH_LEN);
    size_t out_len2 = nondet_size_t();
    __CPROVER_assume(out_len2 >= 1 && out_len2 <= sizeof out);
    hkdf_expand_label(PROOF_HASH_LEN, prk, label, info, ctx_len, out, out_len2);
#endif
    return 0;
}
