// Proves: in a CH_HASH_SHA384 build, the transcript's two hashes and its
// three readers are memory safe for both hash lengths the build holds:
// transcript_update over any message up to 64 bytes, hsr_transcript_hash
// and transcript_hash_after with and without bytes after the transcript,
// and hsr_restart_transcript, which hashes the first ClientHello at
// hash_len and writes RFC 9846 §4.4.1's synthetic message and the retry.
// hash_len is free over SHA256_LEN and SHA384_LEN, so both arms of each
// reader are under proof, and each reader leaves its output at hash_len
// bytes.
//
// Layered proof: SHA-256 and SHA-384 are the contract stubs in
// proof/harness.h, which sha256_harness.c and sha512_harness.c discharge.
// handshake_record.c comes in whole for its two transcript calls; main
// reaches nothing else in it.
#define CH_HASH_SHA384
#define CH_PROOF_STUB_SHA256
#define CH_PROOF_STUB_SHA384
#include "harness.h"

#include "handshake_record.c"

#define TRANSCRIPT_MSG_MAX 64

int main(void) {
    ch_tls t;
    handshake_state h;
    memset(&h, 0, sizeof h);
    h.t = &t;
    transcript_init(&t.transcript);

    uint8_t msg[TRANSCRIPT_MSG_MAX];
    fill_nondet(msg, sizeof msg);
    size_t n = nondet_size_t();
    __CPROVER_assume(n <= sizeof msg);
    transcript_update(&t.transcript, msg, n);

    size_t hash_len = nondet_size_t();
    __CPROVER_assume(hash_len == SHA256_LEN || hash_len == SHA384_LEN);
    uint8_t out[HKDF_HASH_MAX];
    __CPROVER_assert(hsr_transcript_hash(&h, hash_len, out) == CH_OK, "hash: never fails");

    size_t extra = nondet_size_t();
    __CPROVER_assume(extra <= sizeof msg);
    transcript_hash_after(&t.transcript, hash_len, msg, extra, out);

    size_t retry_len = nondet_size_t();
    __CPROVER_assume(retry_len <= sizeof msg);
    hsr_restart_transcript(&h, hash_len, msg, retry_len);
    __CPROVER_assert(hsr_transcript_hash(&h, hash_len, out) == CH_OK, "hash after a retry");
    return 0;
}
