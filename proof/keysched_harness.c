// Proves: every key-schedule entry point is memory-safe and UB-free over
// unconstrained secrets and lengths. Nothing here asserts what an output
// holds; the vectors in test/ do that.
//
// hkdf is real here rather than stubbed: the schedule is a sequence of
// Extract and Expand-Label calls, so stubbing them would leave almost
// nothing under proof. sha256 keeps harness.h's contract stub, which is
// what holds the formula down -- the schedule's own arithmetic is length
// handling, not compression.
// The schedule is length handling over Extract and Expand-Label, not
// compression, so sha256 comes in as harness.h's contract stub.
#define CH_PROOF_STUB_SHA256
#include "harness.h"

#include "sha256.h"

// hkdf comes in as source, not a link line: harness.h's sha256 stubs are
// static, so a separately compiled hkdf.c would call bodies that are not there.
#include "hkdf.c"
#include "keysched.c"

// keysched384_harness.c compiles this file under CH_HASH_SHA384 with
// hash_len fixed at SHA384_LEN, the schedule TLS_AES_256_GCM_SHA384
// runs: every secret, the transcript hash and the PSK are 48 bytes.
#ifdef CH_HASH_SHA384
#define PROOF_HASH_LEN SHA384_LEN
#else
#define PROOF_HASH_LEN SHA256_LEN
#endif
#define KS_VAR_MAX PROOF_HASH_LEN

int main(void) {
    uint8_t early[PROOF_HASH_LEN];
    uint8_t binder_key[PROOF_HASH_LEN];
    uint8_t var[KS_VAR_MAX];
    uint8_t transcript[PROOF_HASH_LEN];
    fill_nondet(var, sizeof var);
    fill_nondet(transcript, sizeof transcript);

    size_t var_len = nondet_size_t();
    __CPROVER_assume(var_len <= sizeof var);
    ks_early(PROOF_HASH_LEN, var, var_len, (int)nondet_u8(), early, binder_key);

    uint8_t key[PROOF_HASH_LEN];
    uint8_t out[PROOF_HASH_LEN];
    fill_nondet(key, sizeof key);
    ks_verify_data(PROOF_HASH_LEN, key, transcript, out);

    uint8_t handshake_secret[PROOF_HASH_LEN];
    uint8_t c_hs[PROOF_HASH_LEN];
    uint8_t s_hs[PROOF_HASH_LEN];
    size_t ecdhe_len = nondet_size_t();
    __CPROVER_assume(ecdhe_len <= sizeof var);
    ks_handshake(PROOF_HASH_LEN, early, var, ecdhe_len, transcript, handshake_secret, c_hs, s_hs);

    uint8_t master[PROOF_HASH_LEN];
    uint8_t c_ap[PROOF_HASH_LEN];
    uint8_t s_ap[PROOF_HASH_LEN];
    ks_master(PROOF_HASH_LEN, handshake_secret, transcript, master, c_ap, s_ap);

    uint8_t res_master[PROOF_HASH_LEN];
    ks_res_master(PROOF_HASH_LEN, master, transcript, res_master);

    uint8_t psk[PROOF_HASH_LEN];
    size_t nonce_len = nondet_size_t();
    __CPROVER_assume(nonce_len <= sizeof var);
    ks_res_psk(PROOF_HASH_LEN, res_master, var, nonce_len, psk);

#ifdef CH_EXPORTER
    // The exporter of RFC 9846 §7.5, which the EXPORTER axis compiles.
    // Its label is the caller's and this axis widens hkdf's cap from 12
    // to 32, so what is new is the arithmetic at lengths the base leg
    // never reaches. Two fixed lengths cover it: 13, the first the old
    // cap refused, and HKDF_LABEL_MAX, the new cap itself. The label's
    // bytes stay free. A length left free as well ran with no verdict
    // for ten minutes at 1.4 GB: strlen over free bytes, the copy into
    // the info buffer and hkdf_expand's loop each fork on it, and the
    // base leg converges in 13 s with every length it takes fixed.
    uint8_t exp_master[PROOF_HASH_LEN];
    ks_exp_master(PROOF_HASH_LEN, master, transcript, exp_master);

    size_t context_len = nondet_size_t();
    __CPROVER_assume(context_len <= sizeof var);
    size_t out_len = nondet_size_t();
    __CPROVER_assume(out_len >= 1 && out_len <= PROOF_HASH_LEN);
    // A buffer of its own: a caller's context and its output are two
    // objects, so proving the aliased shape would prove something no
    // caller asks for (docs/proofs.md).
    uint8_t exported[PROOF_HASH_LEN];

    char label[HKDF_LABEL_MAX + 1];
    for (size_t i = 0; i < HKDF_LABEL_MAX; i++) {
        label[i] = (char)nondet_u8();
        __CPROVER_assume(label[i] != '\0');
    }
    label[13] = '\0';
    ks_exporter(PROOF_HASH_LEN, exp_master, label, var, context_len, exported, out_len);
    label[13] = 'x';
    label[HKDF_LABEL_MAX] = '\0';
    ks_exporter(PROOF_HASH_LEN, exp_master, label, var, context_len, exported, out_len);
#endif
    return 0;
}
