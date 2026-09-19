// Proves: every entry of quic_packet.c reads and writes only inside the
// buffers its caller gave it and commits no undefined behavior, over
// unconstrained packets, keys, lengths, packet numbers and key set
// names.
//
// Two shifts are what this formula exists for. quic_pn_read shifts by a
// distance built from pn_len and quic_pn_decode by one built from
// pn_len too, and a distance at or past the operand's width is
// undefined. Both mask the distance rather than trusting the contract,
// so both calls take an unconstrained pn_len here: --undefined-shift-
// check is what says the masks hold.
//
// The three offsets the open path computes are the other half. The
// §5.4.2 check is an rbuf read, and everything after it -- the packet
// number field, the associated data, the ciphertext and the tag --
// sits at an offset derived from pn_off and the pn_len the unprotected
// byte 0 reported. --pointer-check and --bounds-check are what say
// those derivations stay inside the packet.
//
// ChaCha20 and the AEAD are contract stubs below, so this formula holds
// the framing rather than a keystream and a Poly1305 tag: chacha20 and
// aead have harnesses of their own, and RFC 9001 Appendix A.5's whole
// packet is checked end to end in test/quic_packet_tests.h. What the
// stubs give up is stated with each one.
#include "harness.h"

#include "aead.h"
#include "chacha20.h"

int nondet_int(void);
uint64_t nondet_u64(void);

// WHAT THIS MODELS: CHACHA20_BLOCK unconstrained keystream bytes, so
// quic_hp_mask is proven over every mask ChaCha20 could produce rather
// than one CBMC picked. WHAT IT NO LONGER PROVES: that chacha20.c
// computes RFC 8439's block. chacha20_harness does that, and RFC 9001
// Appendix A.5's sample and mask check the pair together.
void chacha20_block(const uint8_t key[CHACHA20_KEY], const uint8_t nonce[CHACHA20_NONCE],
                    uint32_t counter, uint8_t out[CHACHA20_BLOCK]) {
    __CPROVER_assert(__CPROVER_r_ok(key, CHACHA20_KEY), "chacha20_block: key readable");
    __CPROVER_assert(__CPROVER_r_ok(nonce, CHACHA20_NONCE), "chacha20_block: nonce readable");
    __CPROVER_assert(__CPROVER_w_ok(out, CHACHA20_BLOCK), "chacha20_block: output writable");
    (void)counter;
    fill_nondet(out, CHACHA20_BLOCK);
}

// WHAT THIS MODELS: n unconstrained ciphertext bytes and an
// unconstrained tag. WHAT IT NO LONGER PROVES: RFC 8439's seal, which
// aead_harness holds.
void aead_seal(const uint8_t key[AEAD_KEY], const uint8_t nonce[AEAD_NONCE], const uint8_t *aad,
               size_t aad_len, const uint8_t *pt, size_t n, uint8_t *ct, uint8_t tag[AEAD_TAG]) {
    __CPROVER_assert(__CPROVER_r_ok(key, AEAD_KEY), "aead_seal: key readable");
    __CPROVER_assert(__CPROVER_r_ok(nonce, AEAD_NONCE), "aead_seal: nonce readable");
    __CPROVER_assert(aad_len == 0 || __CPROVER_r_ok(aad, aad_len), "aead_seal: aad readable");
    __CPROVER_assert(n == 0 || __CPROVER_r_ok(pt, n), "aead_seal: plaintext readable");
    __CPROVER_assert(n == 0 || __CPROVER_w_ok(ct, n), "aead_seal: ciphertext writable");
    __CPROVER_assert(__CPROVER_w_ok(tag, AEAD_TAG), "aead_seal: tag writable");
    fill_nondet(ct, n);
    fill_nondet(tag, AEAD_TAG);
}

// WHAT THIS MODELS: a nondet verdict, with n unconstrained plaintext
// bytes written only when it says the tag matched. Both open paths are
// therefore proven on the discard arm and on the success arm. WHAT IT
// NO LONGER PROVES: that aead.c verifies before it decrypts, which
// aead_harness holds.
int aead_open(const uint8_t key[AEAD_KEY], const uint8_t nonce[AEAD_NONCE], const uint8_t *aad,
              size_t aad_len, const uint8_t *ct, size_t n, const uint8_t tag[AEAD_TAG],
              uint8_t *pt) {
    __CPROVER_assert(__CPROVER_r_ok(key, AEAD_KEY), "aead_open: key readable");
    __CPROVER_assert(__CPROVER_r_ok(nonce, AEAD_NONCE), "aead_open: nonce readable");
    __CPROVER_assert(aad_len == 0 || __CPROVER_r_ok(aad, aad_len), "aead_open: aad readable");
    __CPROVER_assert(n == 0 || __CPROVER_r_ok(ct, n), "aead_open: ciphertext readable");
    __CPROVER_assert(__CPROVER_r_ok(tag, AEAD_TAG), "aead_open: tag readable");
    __CPROVER_assert(n == 0 || __CPROVER_w_ok(pt, n), "aead_open: plaintext writable");
    if (nondet_int() == 0) {
        return 0;
    }
    fill_nondet(pt, n);
    return 1;
}

#include "quic_packet.c"

// The packet buffer both open calls work in and the seal call writes
// into. It has to hold one packet the §5.4.2 check admits -- pn_off +
// QUIC_PN_MAX_LEN + QUIC_HP_SAMPLE_LEN bytes at least -- and a few more
// so pkt_len can run on both sides of that bound. 40 is that with room.
#ifndef CH_PROOF_PKT_LEN
#define CH_PROOF_PKT_LEN 40
#endif

// The header and the payload quic_packet_seal takes. Both lengths are
// symbolic inside them, and the two ends of the §5.4.2 rule are inside
// the range: pn_len + pt_len reaches QUIC_PN_MAX_LEN and falls below
// it.
#define CH_PROOF_HDR_LEN 8
#define CH_PROOF_PT_LEN 8

// The pieces that do not open or seal a packet: the mask, the two
// header protection directions, the packet number field, the nonce and
// the two key set calls. Every operand is havocked again before every
// call, so none of them reads a value an earlier call left.
static void prove_pieces(void) {
    quic_hp_key h;
    quic_keys sets[CH_QUIC_KEY_SETS];
    quic_keys chosen;
    uint8_t pkt[CH_PROOF_PKT_LEN];
    uint8_t sample[QUIC_HP_SAMPLE_LEN];
    uint8_t mask[QUIC_HP_MASK_LEN];
    uint8_t iv[AEAD_NONCE];
    uint8_t nonce[AEAD_NONCE];

    fill_nondet((uint8_t *)&h, sizeof h);
    fill_nondet(sample, sizeof sample);
    quic_hp_mask(&h, sample, mask);

    // The contract's pn_off range: pkt holds QUIC_PN_MAX_LEN bytes
    // there. pn_len takes its whole documented range and level takes
    // every value, because first_byte_bits reads level and nothing
    // else does.
    size_t pn_off = nondet_size_t();
    size_t pn_len = nondet_size_t();
    __CPROVER_assume(pn_off <= CH_PROOF_PKT_LEN - QUIC_PN_MAX_LEN);
    __CPROVER_assume(pn_len >= 1 && pn_len <= QUIC_PN_MAX_LEN);
    fill_nondet(pkt, sizeof pkt);
    fill_nondet(mask, sizeof mask);
    quic_header_protect(pkt, pn_off, pn_len, nondet_u8(), mask);

    fill_nondet(pkt, sizeof pkt);
    fill_nondet(mask, sizeof mask);
    size_t reported = quic_header_unprotect(pkt, pn_off, nondet_u8(), mask);
    __CPROVER_assert(reported >= 1 && reported <= QUIC_PN_MAX_LEN,
                     "quic_header_unprotect: the length it reports is 1 to QUIC_PN_MAX_LEN");

    // pn_len is unconstrained for these two, because each masks its own
    // shift distance rather than resting on the contract.
    fill_nondet(pkt, sizeof pkt);
    (void)quic_pn_read(pkt, pn_off, nondet_size_t());
    (void)quic_pn_decode(nondet_u64(), nondet_u64(), nondet_size_t());

    fill_nondet(iv, sizeof iv);
    quic_nonce(iv, nondet_u64(), nonce);

    uint8_t selected = quic_key_set_select(nondet_u8(), nondet_u8(), nondet_u64(), nondet_u64());
    __CPROVER_assert(selected <= CH_QUIC_KEY_NEXT,
                     "quic_key_set_select: it names one of the three sets");

    // quic_keys_select takes an unconstrained name, because it reads
    // all three sets under a mask and indexes none of them by it.
    fill_nondet((uint8_t *)sets, sizeof sets);
    quic_keys_select(sets, nondet_u8(), &chosen);
}

// quic_packet_seal over symbolic lengths and a symbolic capacity, with
// out overlapping neither hdr nor pt, the aliasing its contract states.
static void prove_seal(void) {
    quic_keys k;
    quic_hp_key h;
    uint8_t hdr[CH_PROOF_HDR_LEN];
    uint8_t pt[CH_PROOF_PT_LEN];
    uint8_t out[CH_PROOF_PKT_LEN];
    size_t out_len = 0;

    size_t hdr_len = nondet_size_t();
    size_t pt_len = nondet_size_t();
    size_t pn_len = nondet_size_t();
    size_t cap = nondet_size_t();
    __CPROVER_assume(hdr_len <= CH_PROOF_HDR_LEN);
    __CPROVER_assume(pt_len <= CH_PROOF_PT_LEN);
    __CPROVER_assume(pn_len <= QUIC_PN_MAX_LEN + 1);
    __CPROVER_assume(cap <= CH_PROOF_PKT_LEN);
    fill_nondet((uint8_t *)&k, sizeof k);
    fill_nondet((uint8_t *)&h, sizeof h);
    fill_nondet(hdr, sizeof hdr);
    fill_nondet(pt, sizeof pt);
    fill_nondet(out, sizeof out);

    int rc = quic_packet_seal(&k, &h, nondet_u8(), nondet_u64(), pn_len, hdr, hdr_len, pt, pt_len,
                              out, cap, &out_len);
    __CPROVER_assert(rc == CH_OK || rc == CH_EINVAL || rc == CH_ECAP,
                     "quic_packet_seal: it returns one of the three codes its header names");
    if (rc == CH_OK) {
        __CPROVER_assert(out_len == hdr_len + pt_len + AEAD_TAG,
                         "quic_packet_seal: the length it reports is the whole packet");
        __CPROVER_assert(out_len <= cap, "quic_packet_seal: the packet fits the caller's buffer");
    }
}

// Both open calls over a symbolic packet length and a symbolic packet
// number offset, so the §5.4.2 discard and the open past it are both
// reached.
static void prove_open(void) {
    quic_keys k;
    quic_keys sets[CH_QUIC_KEY_SETS];
    quic_hp_key h;
    uint8_t pkt[CH_PROOF_PKT_LEN];
    uint64_t pn = 0;
    size_t pt_len = 0;
    uint8_t key_set = 0;

    size_t pkt_len = nondet_size_t();
    size_t pn_off = nondet_size_t();
    __CPROVER_assume(pkt_len <= CH_PROOF_PKT_LEN);
    __CPROVER_assume(pn_off <= pkt_len);
    fill_nondet((uint8_t *)&k, sizeof k);
    fill_nondet((uint8_t *)&h, sizeof h);
    fill_nondet(pkt, sizeof pkt);

    int rc = quic_packet_open_handshake(&k, &h, pkt, pkt_len, pn_off, nondet_u64(), &pn, &pt_len);
    __CPROVER_assert(rc == CH_OK || rc == CH_QUIC_DISCARD,
                     "quic_packet_open_handshake: it returns one of the two codes its header "
                     "names");
    if (rc == CH_OK) {
        __CPROVER_assert(pn_off + pt_len <= pkt_len,
                         "quic_packet_open_handshake: the plaintext it reports is in the packet");
    }

    pkt_len = nondet_size_t();
    pn_off = nondet_size_t();
    __CPROVER_assume(pkt_len <= CH_PROOF_PKT_LEN);
    __CPROVER_assume(pn_off <= pkt_len);
    fill_nondet((uint8_t *)sets, sizeof sets);
    fill_nondet((uint8_t *)&h, sizeof h);
    fill_nondet(pkt, sizeof pkt);

    rc = quic_packet_open_application(sets, &h, nondet_u8(), pkt, pkt_len, pn_off, nondet_u64(),
                                      nondet_u64(), &key_set, &pn, &pt_len);
    __CPROVER_assert(rc == CH_OK || rc == CH_QUIC_DISCARD,
                     "quic_packet_open_application: it returns one of the two codes its header "
                     "names");
    if (rc == CH_OK) {
        __CPROVER_assert(key_set <= CH_QUIC_KEY_NEXT,
                         "quic_packet_open_application: it names one of the three sets");
    }
}

int main(void) {
    prove_pieces();
    prove_seal();
    prove_open();
    (void)quic_integrity_limit_exceeded(nondet_u64());
    (void)quic_confidentiality_limit_reached(nondet_u64());
    return 0;
}
