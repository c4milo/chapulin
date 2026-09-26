// QUIC packet protection (RFC 9001 §5.3) and header protection (§5.4)
// under the suite TLS negotiated (rfc9001.txt:1109-1113), plus the §6.5
// receive key set rule, the §5.4.2 length checks and the §6.6 limits.
// quic_packet.h states every contract below and cites the RFC lines each
// one comes from; this file states how each one is met.
//
// A -DCH_SUITE_AES_GCM build runs AES-GCM and AES header protection
// (§5.4.3) under both AES suites. The keys here come from traffic
// secrets and are secret, so ct.h refuses the define without AES=hw and
// CH_NATIVE_AES, or AES=extern and CH_AES_EXTERN_CONSTANT_TIME (INV-26).
// Every dispatch reads a key set's suite, which
// the ServerHello named in the clear.
//
// The §9.5 rule, as code. RFC 9001 §9.5 makes the packet number and its
// encoded length secret in both directions (rfc9001.txt:2110-2112,
// rfc9001.txt:2114-2116), so every compare that reads one is mask
// arithmetic: below_mask over two packet numbers, byte_in_use over the
// packet number length, and ct_memeq over a key set name. No `if` in
// this file reads a secret and no array index does either. The compares
// that do branch read values the caller passed and the wire shows: a
// buffer capacity, a header length, a packet length and the encryption
// level.
#include "quic_packet.h"

#ifdef CH_TRANSPORT_QUIC_NONBLOCKING

#include "buf.h"
#include "ch_assert.h"
#include "ct.h"
#ifdef CH_SUITE_AES_GCM
#include "aes_traffic_key.h"
#include "gcm.h"
#include "suite.h"
#endif

// The AEAD k's suite names, over n bytes of pt sealed into ct with the
// tag after them. AES round keys die with this frame, and an AES-GCM set
// counts the packet for §6.6.
static void seal_body(quic_keys *k, const uint8_t nonce[AEAD_NONCE], const uint8_t *aad,
                      size_t aad_len, const uint8_t *pt, size_t n, uint8_t *ct) {
#ifdef CH_SUITE_AES_GCM
    if (suite_runs_aes_gcm(k->suite)) {
        aes_traffic_key key;
        aes_traffic_key_init(&key, k->key, suite_key_len(k->suite));
        gcm_traffic_seal(&key, nonce, aad, aad_len, pt, n, ct, ct + n);
        ct_wipe(&key, sizeof key);
        k->sealed++;
        return;
    }
#endif
    aead_seal(k->key, nonce, aad, aad_len, pt, n, ct, ct + n);
}

// The other direction, ct and its tag opened into pt: 1 when the tag
// matched, and 0, with nothing written, when it did not.
static int open_body(const quic_keys *k, const uint8_t nonce[AEAD_NONCE], const uint8_t *aad,
                     size_t aad_len, const uint8_t *ct, size_t n, uint8_t *pt) {
#ifdef CH_SUITE_AES_GCM
    if (suite_runs_aes_gcm(k->suite)) {
        aes_traffic_key key;
        aes_traffic_key_init(&key, k->key, suite_key_len(k->suite));
        int ok = gcm_traffic_open(&key, nonce, aad, aad_len, ct, n, ct + n, pt);
        ct_wipe(&key, sizeof key);
        return ok;
    }
#endif
    return aead_open(k->key, nonce, aad, aad_len, ct, n, ct + n, pt);
}

// The packet number space of RFC 9000 §17.1: every packet number is
// below 2^62 (rfc9000.txt:4897-4899). RFC 9000 Appendix A.3's second
// guard compares a candidate against this bound less one window
// (rfc9000.txt:8358-8381).
#define QUIC_PN_LIMIT (UINT64_C(1) << 62)

// QUIC_KEY_PHASE_BIT sits at bit 2 of byte 0, so one right shift
// reduces it to 0 or 1 and no compare is needed, which is the form
// quic_key_set_select's contract asks its caller for.
#define QUIC_KEY_PHASE_SHIFT 2
_Static_assert(QUIC_KEY_PHASE_BIT == (1U << QUIC_KEY_PHASE_SHIFT),
               "the Key Phase bit and the shift that reduces it must name the same bit");

// All ones when a is below b, and zero otherwise, for any two 64-bit
// values. It never compares: the borrow out of a - b is built from the
// operand bits (Hacker's Delight, "Comparison Predicates"), and the
// mask is that borrow less one, complemented. That last step is
// poly1305_final's shape rather than `0 - borrow`, because ct.h records
// gcc rewriting `X & -Y` into a multiply when it knows Y is 0 or 1, and
// this file is held at zero wide multiplies.
static uint64_t below_mask(uint64_t a, uint64_t b) {
    uint64_t borrow = ((~a & b) | ((~a | b) & (a - b))) >> 63;
    return ~(borrow - 1);
}

// 0xff while i is below pn_len and 0 from pn_len on. Both values are at
// most QUIC_PN_MAX_LEN, so the borrow out of the 32-bit subtraction is
// the whole answer, and the caller's loop reads and writes the same
// four bytes whatever pn_len is.
static uint8_t byte_in_use(size_t i, size_t pn_len) {
    uint32_t borrow = ((uint32_t)i - (uint32_t)pn_len) >> 31;
    return (uint8_t)~(borrow - 1U);
}

// All ones when the two key set names match, and zero otherwise.
// CLAUDE.md sends every comparison of secret bytes through ct_memeq,
// and the name a packet selects is secret: it comes from the Key Phase
// bit and the recovered packet number, which §9.5 covers
// (rfc9001.txt:2110-2112).
static uint8_t set_in_use(uint8_t name, uint8_t selected) {
    uint32_t same = ct_memeq(&name, &selected, 1);
    return (uint8_t)~(same - 1U);
}

// Which bits of byte 0 the first mask byte covers: the low four for a
// long header and the low five for a short one (RFC 9001 §5.4,
// rfc9001.txt:1164-1170). level is the caller's own value and the wire
// carries the same fact in byte 0's Header Form bit, so this compare
// reveals nothing and takes a branch.
static uint8_t first_byte_bits(uint8_t level) {
    if (level == CH_LEVEL_APPLICATION) {
        return QUIC_HP_BITS_SHORT;
    }
    return QUIC_HP_BITS_LONG;
}

// XORs mask[1] through mask[pn_len] into the packet number field, the
// step both directions of §5.4.1 share (rfc9001.txt:1188-1193). It
// always touches QUIC_PN_MAX_LEN bytes at pn_off: a byte past the
// packet number is written with a mask byte of zero and keeps its
// value, so neither the trip count nor the addresses depend on pn_len.
static void mask_pn_field(uint8_t *pkt, size_t pn_off, size_t pn_len,
                          const uint8_t mask[QUIC_HP_MASK_LEN]) {
    for (size_t i = 0; i < QUIC_PN_MAX_LEN; i++) {
        pkt[pn_off + i] ^= mask[1 + i] & byte_in_use(i, pn_len);
    }
}

// From here to quic_keys_select, no entry checks an argument against
// NULL, and the three entries ch_quic_seal and ch_quic_open reach all
// do. Each one here writes through every pointer it takes before it can
// return, so a null faults on the write whatever a check said first,
// and cppcheck reads the check as redundant for that reason. The three
// entries are different: they compare lengths first and return before
// they write a byte.
void quic_hp_mask(const quic_hp_key *h, const uint8_t sample[QUIC_HP_SAMPLE_LEN],
                  uint8_t mask[QUIC_HP_MASK_LEN]) {
#ifdef CH_SUITE_AES_GCM
    // §5.4.3: the first QUIC_HP_MASK_LEN bytes of AES-ECB(hp_key, sample),
    // under a key as long as the suite's (rfc9001.txt:1332-1336).
    if (suite_runs_aes_gcm(h->suite)) {
        aes_traffic_key k;
        aes_traffic_key_init(&k, h->key, suite_key_len(h->suite));
        uint8_t block[AES_BLOCK];
        aes_traffic_encrypt_block(&k, sample, block);
        for (size_t i = 0; i < QUIC_HP_MASK_LEN; i++) {
            mask[i] = block[i];
        }
        ct_wipe(block, sizeof block);
        ct_wipe(&k, sizeof k);
        return;
    }
#endif
    // §5.4.4: the counter is sample[0..3] read little-endian and the
    // nonce is sample[4..15] taken as bytes (rfc9001.txt:1344-1347).
    // Both are assembled byte by byte, so no step assumes host
    // endianness.
    uint32_t counter = 0;
    for (size_t i = 0; i < 4; i++) {
        counter |= (uint32_t)sample[i] << (8 * i);
    }
    uint8_t nonce[CHACHA20_NONCE];
    for (size_t i = 0; i < CHACHA20_NONCE; i++) {
        nonce[i] = sample[4 + i];
    }
    // The mask is the first QUIC_HP_MASK_LEN bytes of the block, which
    // is what ChaCha20 over five zero bytes produces
    // (rfc9001.txt:1354-1361).
    uint8_t block[CHACHA20_BLOCK];
    chacha20_block(h->key, nonce, counter, block);
    for (size_t i = 0; i < QUIC_HP_MASK_LEN; i++) {
        mask[i] = block[i];
    }
    // The whole block is keystream under a secret key, the five bytes
    // the caller now holds a copy of included.
    ct_wipe(block, sizeof block);
}

void quic_header_protect(uint8_t *pkt, size_t pn_off, size_t pn_len, uint8_t level,
                         const uint8_t mask[QUIC_HP_MASK_LEN]) {
    pkt[0] ^= mask[0] & first_byte_bits(level);
    mask_pn_field(pkt, pn_off, pn_len, mask);
}

size_t quic_header_unprotect(uint8_t *pkt, size_t pn_off, uint8_t level,
                             const uint8_t mask[QUIC_HP_MASK_LEN]) {
    // §5.4.1's one difference from the send direction: byte 0 is
    // unmasked first, because the packet number length lives in it
    // (rfc9001.txt:1196-1198).
    pkt[0] ^= mask[0] & first_byte_bits(level);
    size_t pn_len = (size_t)(pkt[0] & QUIC_PN_LEN_BITS) + 1;
    mask_pn_field(pkt, pn_off, pn_len, mask);
    return pn_len;
}

uint64_t quic_pn_read(const uint8_t *pkt, size_t pn_off, size_t pn_len) {
    uint32_t whole = 0;
    for (size_t i = 0; i < QUIC_PN_MAX_LEN; i++) {
        whole = (whole << 8) | pkt[pn_off + i];
    }
    // The field is the first pn_len of those four bytes, so the bytes
    // past it shift out. The distance is masked to 0, 8, 16 or 24, so
    // no pn_len makes the shift undefined, and the distance is all that
    // depends on pn_len: the four reads above do not.
    unsigned drop = (unsigned)((QUIC_PN_MAX_LEN - pn_len) & 3U) << 3;
    return (uint64_t)(whole >> drop);
}

uint64_t quic_pn_decode(uint64_t largest_pn, uint64_t truncated_pn, size_t pn_len) {
    // RFC 9000 Appendix A.3's DecodePacketNumber, with pn_nbits as
    // 8 * pn_len (rfc9000.txt:8358-8381). The mask holds the shift
    // distance below 64 for every pn_len, so no caller can make it
    // undefined.
    unsigned pn_nbits = (unsigned)(pn_len & 7U) << 3;
    uint64_t expected_pn = largest_pn + 1;
    uint64_t pn_win = UINT64_C(1) << pn_nbits;
    uint64_t pn_hwin = pn_win >> 1;
    uint64_t pn_mask = pn_win - 1;
    uint64_t candidate_pn = (expected_pn & ~pn_mask) | truncated_pn;
    // Figure 47's first if: candidate_pn <= expected_pn - pn_hwin and
    // candidate_pn < 2^62 - pn_win. The first is written as an addition
    // so the subtraction cannot underflow; largest_pn is at most 2^62-1
    // and pn_hwin at most 2^31, so neither sum wraps.
    uint64_t wrapped_up = ~below_mask(expected_pn, candidate_pn + pn_hwin) &
                          below_mask(candidate_pn, QUIC_PN_LIMIT - pn_win);
    // Figure 47's second if: candidate_pn > expected_pn + pn_hwin and
    // candidate_pn >= pn_win.
    uint64_t wrapped_down =
        below_mask(expected_pn + pn_hwin, candidate_pn) & ~below_mask(candidate_pn, pn_win);
    // The two guards cannot both hold, because pn_hwin is never
    // negative, so at most one window is added or taken away.
    return candidate_pn + (pn_win & wrapped_up) - (pn_win & wrapped_down);
}

void quic_nonce(const uint8_t iv[AEAD_NONCE], uint64_t pn, uint8_t nonce[AEAD_NONCE]) {
    // §5.3: the packet number in network byte order, left-padded with
    // zeros to the IV's length, XORed with the IV
    // (rfc9001.txt:1134-1139). The padding is what the first
    // AEAD_NONCE - 8 bytes get, so they are the IV unchanged.
    for (size_t i = 0; i < AEAD_NONCE; i++) {
        nonce[i] = iv[i];
    }
    for (size_t i = 0; i < 8; i++) {
        nonce[AEAD_NONCE - 1 - i] ^= (uint8_t)(pn >> (8 * i));
    }
}

uint8_t quic_key_set_select(uint8_t key_phase, uint8_t packet_key_phase, uint64_t pn,
                            uint64_t current_phase_lowest_pn) {
    // §6.5: the bit picks the phase, and when it differs from the
    // stored one the recovered packet number tells the previous phase
    // from the next (rfc9001.txt:1735-1743). Both values are 0 or 1 by
    // contract, so their difference is one bit and & 1 holds it there
    // whatever a caller passes.
    uint32_t differs = ((uint32_t)key_phase ^ (uint32_t)packet_key_phase) & 1U;
    uint32_t same_phase = differs - 1U;
    // Below current_phase_lowest_pn the previous set opens the packet,
    // at or above it the next set does. Selecting the next set that way
    // keeps the §5.5 MUST against opening a higher-numbered packet
    // under the previous keys (rfc9001.txt:1365-1369).
    uint32_t below = (uint32_t)below_mask(pn, current_phase_lowest_pn);
    uint32_t other_phase = (CH_QUIC_KEY_PREVIOUS & below) | (CH_QUIC_KEY_NEXT & ~below);
    uint32_t selected = (CH_QUIC_KEY_CURRENT & same_phase) | (other_phase & ~same_phase);
    return (uint8_t)selected;
}

void quic_keys_select(const quic_keys sets[CH_QUIC_KEY_SETS], uint8_t selected, quic_keys *out) {
    for (size_t i = 0; i < AEAD_KEY; i++) {
        out->key[i] = 0;
    }
    for (size_t i = 0; i < AEAD_NONCE; i++) {
        out->iv[i] = 0;
    }
    // The loop counter is the index, never selected, so all three sets
    // are read at the same addresses whichever one wins. A selected
    // value outside the three names leaves out zero, and zero keys open
    // no packet.
    for (size_t s = 0; s < CH_QUIC_KEY_SETS; s++) {
        uint8_t take = set_in_use((uint8_t)s, selected);
        for (size_t i = 0; i < AEAD_KEY; i++) {
            out->key[i] |= sets[s].key[i] & take;
        }
        for (size_t i = 0; i < AEAD_NONCE; i++) {
            out->iv[i] |= sets[s].iv[i] & take;
        }
    }
#ifdef CH_SUITE_AES_GCM
    // Every set of a connection runs one public suite, a key update included.
    out->suite = sets[CH_QUIC_KEY_CURRENT].suite;
    out->sealed = 0;
#endif
}

int quic_packet_seal(quic_keys *k, const quic_hp_key *h, uint8_t level, uint64_t pn, size_t pn_len,
                     const uint8_t *hdr, size_t hdr_len, const uint8_t *pt, size_t pt_len,
                     uint8_t *out, size_t cap, size_t *out_len) {
    CH_ASSERT(k != NULL);
    CH_ASSERT(h != NULL);
    CH_ASSERT(hdr != NULL);
    CH_ASSERT(out != NULL);
    CH_ASSERT(out_len != NULL);
    if (pn_len == 0 || pn_len > QUIC_PN_MAX_LEN || hdr_len < pn_len) {
        return CH_EINVAL;
    }
    // §5.4.2: the encoded packet number and the protected payload must
    // run at least QUIC_PN_MAX_LEN bytes past the sample
    // (rfc9001.txt:1283-1286). AEAD_TAG and QUIC_HP_SAMPLE_LEN are both
    // 16, so the tag alone answers the sample and what is left to
    // require is pn_len + pt_len >= QUIC_PN_MAX_LEN. The line below
    // subtracts rather than adds, so a pt_len the caller passed cannot
    // wrap the sum past the test.
    if (pt_len < QUIC_PN_MAX_LEN - pn_len) {
        return CH_EINVAL;
    }
    // The packet is the header, the plaintext and the tag. Each step
    // takes one of the three out of cap, so no sum of caller lengths
    // wraps here either.
    if (cap < AEAD_TAG || cap - AEAD_TAG < pt_len || cap - AEAD_TAG - pt_len < hdr_len) {
        return CH_ECAP;
    }
#ifdef CH_SUITE_AES_GCM
    // §6.6's AES-GCM confidentiality limit, per key set and one packet
    // early, as at the Initial level (rfc9001.txt:1812-1815).
    if (suite_runs_aes_gcm(k->suite) && quic_confidentiality_limit_reached(k->sealed)) {
        return CH_EINVAL;
    }
#endif
    size_t total = hdr_len + pt_len + AEAD_TAG;

    // The writer places the header copy. The AEAD writes the
    // ciphertext and the tag after it, inside the room the check above
    // proved, so this call cannot overrun and w.err stays clear.
    wbuf w;
    wb_init(&w, out, cap);
    wb_bytes(&w, hdr, hdr_len);
    CH_ASSERT(w.err == 0);

    uint8_t nonce[AEAD_NONCE];
    quic_nonce(k->iv, pn, nonce);
    // §5.3 makes the unprotected header the associated data
    // (rfc9001.txt:1141-1143), and out holds it now.
    seal_body(k, nonce, out, hdr_len, pt, pt_len, out + hdr_len);
    ct_wipe(nonce, sizeof nonce);

    // §5.4.1 applies header protection after packet protection
    // (rfc9001.txt:1183-1184), and §5.4.2 puts the sample
    // QUIC_PN_MAX_LEN bytes past the packet number offset
    // (rfc9001.txt:1274-1278).
    size_t pn_off = hdr_len - pn_len;
    uint8_t mask[QUIC_HP_MASK_LEN];
    quic_hp_mask(h, out + pn_off + QUIC_PN_MAX_LEN, mask);
    quic_header_protect(out, pn_off, pn_len, level, mask);
    ct_wipe(mask, sizeof mask);

    *out_len = total;
    return CH_OK;
}

// The §5.4.2 length check and the three steps §9.5 keeps together,
// less the AEAD: the mask, the unprotect and the packet number
// recovery (rfc9001.txt:2110-2112). It writes pn_len and the recovered
// packet number and returns CH_OK, or leaves both alone and returns
// CH_QUIC_DISCARD for a packet too short to hold a complete sample
// (rfc9001.txt:1280-1281).
static int unprotect_header(const quic_hp_key *h, uint8_t *pkt, size_t pkt_len, size_t pn_off,
                            uint8_t level, uint64_t largest_pn, size_t *pn_len, uint64_t *pn) {
    // The check is a minimum length rather than an rbuf read, because a
    // packet is not a container with fields that fill it: the
    // ciphertext runs from the packet number field to the last byte, so
    // INV-25's reader would have nothing to compare. Subtracting rather
    // than adding keeps a pn_off the caller passed from wrapping the
    // sum. It runs before the sample is read, so no byte of a short
    // packet is read and no byte of its header is written.
    if (pkt_len < pn_off || pkt_len - pn_off < QUIC_PN_MAX_LEN + QUIC_HP_SAMPLE_LEN) {
        return CH_QUIC_DISCARD;
    }
    uint8_t mask[QUIC_HP_MASK_LEN];
    quic_hp_mask(h, pkt + pn_off + QUIC_PN_MAX_LEN, mask);
    *pn_len = quic_header_unprotect(pkt, pn_off, level, mask);
    ct_wipe(mask, sizeof mask);
    *pn = quic_pn_decode(largest_pn, quic_pn_read(pkt, pn_off, *pn_len), *pn_len);
    return CH_OK;
}

// Packet protection removal, the third of §9.5's steps: the §5.3 nonce,
// then open_body in place with the unprotected header as the associated
// data. body_off is pn_off + pn_len, so the header runs from pkt to
// body_off and the ciphertext and tag fill the rest of the packet.
//
// The caller has run unprotect_header, so pkt_len is at least pn_off +
// QUIC_PN_MAX_LEN + QUIC_HP_SAMPLE_LEN and pn_len is at most
// QUIC_PN_MAX_LEN. Those two make pkt_len - body_off at least
// QUIC_HP_SAMPLE_LEN, which is AEAD_TAG, so the ciphertext length below
// does not wrap and is zero at the shortest packet the check admits.
static int open_payload(const quic_keys *k, uint8_t *pkt, size_t pkt_len, size_t body_off,
                        uint64_t pn, size_t *pt_len) {
    size_t ct_len = pkt_len - body_off - AEAD_TAG;
    uint8_t nonce[AEAD_NONCE];
    quic_nonce(k->iv, pn, nonce);
    int opened = open_body(k, nonce, pkt, body_off, pkt + body_off, ct_len, pkt + body_off);
    ct_wipe(nonce, sizeof nonce);
    if (opened == 0) {
        // RFC 9001 §5.5 calls a tag that does not match a discard
        // rather than a protocol error (rfc9001.txt:1373-1376), and
        // the AEAD released no plaintext byte.
        return CH_QUIC_DISCARD;
    }
    *pt_len = ct_len;
    return CH_OK;
}

int quic_packet_open_handshake(const quic_keys *k, const quic_hp_key *h, uint8_t *pkt,
                               size_t pkt_len, size_t pn_off, uint64_t largest_pn, uint64_t *pn,
                               size_t *pt_len) {
    CH_ASSERT(k != NULL);
    CH_ASSERT(h != NULL);
    CH_ASSERT(pkt != NULL);
    CH_ASSERT(pn != NULL);
    CH_ASSERT(pt_len != NULL);
    size_t pn_len = 0;
    uint64_t recovered = 0;
    if (unprotect_header(h, pkt, pkt_len, pn_off, CH_LEVEL_HANDSHAKE, largest_pn, &pn_len,
                         &recovered) != CH_OK) {
        return CH_QUIC_DISCARD;
    }
    size_t opened_len = 0;
    if (open_payload(k, pkt, pkt_len, pn_off + pn_len, recovered, &opened_len) != CH_OK) {
        return CH_QUIC_DISCARD;
    }
    *pn = recovered;
    *pt_len = opened_len;
    return CH_OK;
}

int quic_packet_open_application(const quic_keys sets[CH_QUIC_KEY_SETS], const quic_hp_key *h,
                                 uint8_t key_phase, uint8_t *pkt, size_t pkt_len, size_t pn_off,
                                 uint64_t largest_pn, uint64_t current_phase_lowest_pn,
                                 uint8_t *key_set, uint64_t *pn, size_t *pt_len) {
    CH_ASSERT(sets != NULL);
    CH_ASSERT(h != NULL);
    CH_ASSERT(pkt != NULL);
    CH_ASSERT(key_set != NULL);
    CH_ASSERT(pn != NULL);
    CH_ASSERT(pt_len != NULL);
    size_t pn_len = 0;
    uint64_t recovered = 0;
    if (unprotect_header(h, pkt, pkt_len, pn_off, CH_LEVEL_APPLICATION, largest_pn, &pn_len,
                         &recovered) != CH_OK) {
        return CH_QUIC_DISCARD;
    }
    // §6.5's selection sits between packet number recovery and packet
    // protection removal. The shift is what reduces the bit to 0 or 1;
    // a compare here would be the timing side channel §6.5 names
    // (rfc9001.txt:1745-1748).
    uint8_t packet_key_phase = (uint8_t)((pkt[0] & QUIC_KEY_PHASE_BIT) >> QUIC_KEY_PHASE_SHIFT);
    uint8_t selected =
        quic_key_set_select(key_phase, packet_key_phase, recovered, current_phase_lowest_pn);
    quic_keys chosen;
    quic_keys_select(sets, selected, &chosen);
    size_t opened_len = 0;
    int rc = open_payload(&chosen, pkt, pkt_len, pn_off + pn_len, recovered, &opened_len);
    ct_wipe(&chosen, sizeof chosen);
    if (rc != CH_OK) {
        // §5.5's second MUST: a packet that appears to carry a key
        // update and does not authenticate changes nothing
        // (rfc9001.txt:1369-1371), so key_set stays unwritten.
        return CH_QUIC_DISCARD;
    }
    *key_set = selected;
    *pn = recovered;
    *pt_len = opened_len;
    return CH_OK;
}

int quic_integrity_limit_exceeded(uint64_t open_failures) {
    // §6.6 closes once the count exceeds the limit (rfc9001.txt:1823-1827).
    // The count is this session's own, not a peer value, so this branches.
    return open_failures > QUIC_INTEGRITY_LIMIT ? 1 : 0;
}

int quic_confidentiality_limit_reached(uint64_t sealed) {
    // One packet stricter than §6.6 (rfc9001.txt:1801-1803). The limit
    // is lowered rather than the count raised, so UINT64_MAX answers 1.
    return sealed >= QUIC_CONFIDENTIALITY_LIMIT - 1 ? 1 : 0;
}

#endif // CH_TRANSPORT_QUIC_NONBLOCKING
