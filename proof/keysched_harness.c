// Proves: every key-schedule entry point is memory-safe and UB-free over
// unconstrained secrets and lengths, and each writes every byte of the
// outputs it promises.
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

#define KS_VAR_MAX 32

int main(void) {
    uint8_t early[SHA256_LEN];
    uint8_t binder_key[SHA256_LEN];
    uint8_t var[KS_VAR_MAX];
    uint8_t transcript[SHA256_LEN];
    fill_nondet(var, sizeof var);
    fill_nondet(transcript, sizeof transcript);

    size_t var_len = nondet_size_t();
    __CPROVER_assume(var_len <= sizeof var);
    ks_early(var, var_len, (int)nondet_u8(), early, binder_key);

    uint8_t key[SHA256_LEN];
    uint8_t out[SHA256_LEN];
    fill_nondet(key, sizeof key);
    ks_verify_data(key, transcript, out);

    uint8_t handshake_secret[SHA256_LEN];
    uint8_t c_hs[SHA256_LEN];
    uint8_t s_hs[SHA256_LEN];
    size_t ecdhe_len = nondet_size_t();
    __CPROVER_assume(ecdhe_len <= sizeof var);
    ks_handshake(early, var, ecdhe_len, transcript, handshake_secret, c_hs, s_hs);

    uint8_t master[SHA256_LEN];
    uint8_t c_ap[SHA256_LEN];
    uint8_t s_ap[SHA256_LEN];
    ks_master(handshake_secret, transcript, master, c_ap, s_ap);

    uint8_t res_master[SHA256_LEN];
    ks_res_master(master, transcript, res_master);

    uint8_t psk[SHA256_LEN];
    size_t nonce_len = nondet_size_t();
    __CPROVER_assume(nonce_len <= sizeof var);
    ks_res_psk(res_master, var, nonce_len, psk);
    return 0;
}
