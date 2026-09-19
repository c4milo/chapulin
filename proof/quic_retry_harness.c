// Proves: quic_retry_ok reads only inside the pseudo-packet and the tag
// it is handed, commits no undefined behavior, answers 1 for the tag
// gcm_seal computes over that pseudo-packet, and answers 0 for a tag
// that differs from it in one byte. It runs over any pseudo-packet up
// to RETRY_PSEUDO_MAX bytes, any length up to that bound, and a
// difference at any tag position by any nonzero amount. A tag differing
// in two bytes or more is not proved here; ct_harness proves ct_memeq
// over its whole domain.
//
// The two calls quic_retry_ok makes are contract stubs below, so this
// formula holds the Retry step's own framing rather than AES-128-GCM.
// quic_aes_harness proves the cipher and the two constructors;
// quic_gcm_safety, quic_gcm_refusal and quic_ghash prove the AEAD; and
// test/quic_vectors.c checks the whole computation against RFC 9001
// Appendix A.4.
//
// The gcm_seal stub asserts more than pointer validity, because RFC
// 9001 §5.8 fixes every input this one caller passes: the key
// aes_public_key_retry wrote, the nonce §5.8 prints, the caller's
// pseudo-packet as associated data, and an empty plaintext. Each is an
// assertion below, so a quic_retry.c that built its own nonce, or that
// sealed the pseudo-packet as plaintext instead of as associated data,
// fails here and not only in the vector test.
//
// The length bound is this harness's, not the module's. quic_retry.h
// states no bound on n, and every byte of the pseudo-packet is read
// inside gcm_seal, which is stubbed here and proven at its own bound.
// 64 covers Appendix A.4's 29-byte pseudo-packet with room either side.
#include "harness.h"

#include "quic_aes_key.h"
#include "quic_gcm.h"

// The pseudo-packet bound this formula runs to.
#define RETRY_PSEUDO_MAX 64

// RFC 9001 §5.8's printed nonce, 0x461599d35d632bf2239825bb
// (rfc9001.txt:1501-1502). It is the only nonce gcm_seal may be handed
// here, and the stub below asserts that.
static const uint8_t EXPECTED_NONCE[AES_IV] = {0x46, 0x15, 0x99, 0xd3, 0x5d, 0x63,
                                               0x2b, 0xf2, 0x23, 0x98, 0x25, 0xbb};

// The pseudo-packet main() passes, so the gcm_seal stub can check that
// the bytes it is handed as associated data are the caller's own.
static const uint8_t *harness_pseudo;
static size_t harness_n;

// The key image aes_public_key_retry writes. Havoc'd once, so every call
// sees the same key and no output byte is a value this harness chose.
static aes_public_key stub_key;
static int stub_key_ready;

static void stub_key_init(void) {
    if (!stub_key_ready) {
        fill_nondet(stub_key.key.round_keys, sizeof stub_key.key.round_keys);
        fill_nondet(stub_key.iv, sizeof stub_key.iv);
        fill_nondet(stub_key.hp.round_keys, sizeof stub_key.hp.round_keys);
        stub_key_ready = 1;
    }
}

void aes_public_key_retry(aes_public_key *k) {
    __CPROVER_assert(__CPROVER_w_ok(k, sizeof *k), "aes_public_key_retry: key writable");
    stub_key_init();
    *k = stub_key;
}

// The tag model: GCM_TAG bytes that are a function of the associated
// data, its length and the key, and of nothing else. Being a function is
// what lets a genuine tag match on the second call; depending on every
// associated-data byte is what keeps a changed pseudo-packet from
// tagging the same way. The mixing is a rotate and an xor, never a
// multiply, for the reason proof/aead_stubs.h states.
static void stub_tag_of(const uint8_t *aad, size_t aad_len, uint8_t tag[GCM_TAG]) {
    stub_key_init();
    for (size_t i = 0; i < GCM_TAG; i++) {
        tag[i] = stub_key.key.round_keys[i];
    }
    uint8_t carry = (uint8_t)aad_len;
    for (size_t i = 0; i < aad_len; i++) {
        carry = (uint8_t)(((carry << 1) | (carry >> 7)) ^ aad[i]);
        // & 15 rather than % GCM_TAG: CBMC builds a modulo from the C, so
        // a divisor becomes a 64-bit division circuit (docs/proofs.md).
        tag[i & (GCM_TAG - 1)] = (uint8_t)(tag[i & (GCM_TAG - 1)] ^ carry);
    }
}

void gcm_seal(const aes_public_key *k, const uint8_t nonce[AES_IV], const uint8_t *aad,
              size_t aad_len, const uint8_t *pt, size_t n, uint8_t *ct, uint8_t tag[GCM_TAG]) {
    __CPROVER_assert(__CPROVER_r_ok(k, sizeof *k), "gcm_seal: key readable");
    __CPROVER_assert(__CPROVER_r_ok(nonce, AES_IV), "gcm_seal: nonce readable");
    __CPROVER_assert(aad_len == 0 || __CPROVER_r_ok(aad, aad_len), "gcm_seal: aad readable");
    __CPROVER_assert(n == 0 || __CPROVER_r_ok(pt, n), "gcm_seal: plaintext readable");
    __CPROVER_assert(n == 0 || __CPROVER_w_ok(ct, n), "gcm_seal: ciphertext writable");
    __CPROVER_assert(__CPROVER_w_ok(tag, GCM_TAG), "gcm_seal: tag writable");

    // What RFC 9001 §5.8 fixes, checked at the one call that passes it.
    // The first AES_128_KEY bytes of a schedule are the key itself (FIPS
    // 197 §5.2), so comparing them is comparing the §5.8 key.
    stub_key_init();
    for (size_t i = 0; i < AES_128_KEY; i++) {
        __CPROVER_assert(k->key.round_keys[i] == stub_key.key.round_keys[i],
                         "gcm_seal: sealing under the key aes_public_key_retry wrote");
    }
    for (size_t i = 0; i < AES_IV; i++) {
        __CPROVER_assert(nonce[i] == EXPECTED_NONCE[i], "gcm_seal: the nonce RFC 9001 §5.8 "
                                                        "prints");
    }
    __CPROVER_assert(n == 0, "gcm_seal: the empty plaintext of RFC 9001 §5.8");
    __CPROVER_assert(aad == harness_pseudo && aad_len == harness_n,
                     "gcm_seal: the caller's whole pseudo-packet as associated data");

    // No ciphertext byte is written: n is 0 above, so there are none.
    (void)ct;
    stub_tag_of(aad, aad_len, tag);
}

#include "quic_retry.c"

int main(void) {
    uint8_t pseudo[RETRY_PSEUDO_MAX];
    fill_nondet(pseudo, sizeof pseudo);
    size_t n = nondet_size_t();
    __CPROVER_assume(n <= sizeof pseudo);
    harness_pseudo = pseudo;
    harness_n = n;

    uint8_t want[GCM_TAG];
    stub_tag_of(pseudo, n, want);
    __CPROVER_assert(quic_retry_ok(pseudo, n, want) == 1, "a genuine Retry tag validates");

    // One tag byte different, at any position and by any nonzero amount.
    // RFC 9000 §17.2.5.2 makes the client discard that Retry packet.
    uint8_t forged[GCM_TAG];
    for (size_t i = 0; i < GCM_TAG; i++) {
        forged[i] = want[i];
    }
    size_t at = nondet_size_t();
    uint8_t delta = nondet_u8();
    __CPROVER_assume(at < GCM_TAG);
    __CPROVER_assume(delta != 0);
    forged[at] = (uint8_t)(forged[at] ^ delta);
    __CPROVER_assert(quic_retry_ok(pseudo, n, forged) == 0,
                     "a tag that differs in one byte does not");
    return 0;
}
