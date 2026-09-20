// The Initial packet path of RFC 9001: §5.2's key derivation from the
// Destination Connection ID, §5.3 packet protection under
// AEAD_AES_128_GCM, and §5.4's header protection under the §5.4.3
// AES-ECB mask. quic_initial.h states every contract; this file
// implements them and nothing else.
//
// Each call takes the endpoint its caller is, derives the one
// direction's key it needs on its own stack, and lets it die with the
// frame. That is INV-26's structural check:
// this file, quic_retry.c and quic_aes.c are the only sources that
// include quic_aes_key.h, so they are the only ones that can hold an
// aes_public_key, and no line anywhere keeps one between calls.
#include "quic_initial.h"

#ifdef CH_TRANSPORT_QUIC

#include "quic_aes_key.h"

// The endpoint that wrote what this caller opens: the one the caller is
// not. RFC 9001 §5.2 derives one Initial secret per endpoint and each
// endpoint reads what the other wrote (rfc9001.txt:1057-1061), so this
// function and the endpoint each entry is handed are the whole of the
// role in the Initial path. A value that is neither name is returned
// unchanged, and aes_public_key_initial then refuses it.
static uint8_t peer_endpoint(uint8_t endpoint) {
    if (endpoint == CH_QUIC_ENDPOINT_CLIENT) {
        return CH_QUIC_ENDPOINT_SERVER;
    }
    if (endpoint == CH_QUIC_ENDPOINT_SERVER) {
        return CH_QUIC_ENDPOINT_CLIENT;
    }
    return endpoint;
}

// RFC 9001 §5.3's nonce: the packet number in network byte order,
// left-padded with zeros to the length of the packet protection IV and
// exclusive-ORed with that IV (rfc9001.txt:1134-1139). It writes every
// byte the same way whatever pn is, so no step branches on the packet
// number or on the length the caller encoded it in, which §9.5 requires
// of the send path (rfc9001.txt:2114-2116), and it writes one byte at a
// time, so no step assumes host endianness.
//
// quic_packet.c's quic_nonce builds the same value for the levels whose
// AEAD is ChaCha20-Poly1305, over an IV that file sizes with AEAD_NONCE.
// This one reads the AES_IV-length iv field of an aes_public_key, which
// only this file, quic_retry.c and quic_aes.c can name, and takes no
// constant from the other AEAD.
static void initial_nonce(const aes_public_key *k, uint64_t pn, uint8_t nonce[AES_IV]) {
    for (size_t i = 0; i < AES_IV; i++) {
        nonce[i] = k->iv[i];
    }
    for (size_t i = 0; i < 8; i++) {
        nonce[AES_IV - 1 - i] = (uint8_t)(nonce[AES_IV - 1 - i] ^ (uint8_t)(pn >> (8 * i)));
    }
}

// RFC 9001 §5.4.3's mask block for one packet: AES-ECB under the header
// protection key over the QUIC_HP_SAMPLE_LEN sample that starts
// QUIC_PN_MAX_LEN bytes past the packet number offset
// (rfc9001.txt:1274-1278, rfc9001.txt:1332-1336). Both entries below
// take the sample from that one offset, so the §5.4.2 arithmetic is
// written once. The caller has already checked that those bytes are
// present. aes_encrypt_block_hp writes all AES_BLOCK bytes, and
// quic_header_protect and quic_header_unprotect read the first
// QUIC_HP_MASK_LEN of them.
static void sample_mask(const aes_public_key *k, const uint8_t *pkt, size_t pn_off,
                        uint8_t mask[AES_BLOCK]) {
    aes_encrypt_block_hp(k, &pkt[pn_off + QUIC_PN_MAX_LEN], mask);
}

int quic_initial_seal(uint8_t endpoint, const uint8_t *dcid, size_t dcid_len, uint64_t pn,
                      size_t pn_len, const uint8_t *hdr, size_t hdr_len, const uint8_t *pt,
                      size_t pt_len, uint8_t *out, size_t cap, size_t *out_len) {
    // The send key of RFC 9001 §5.2, under the caller's own endpoint.
    // aes_public_key_initial returns CH_EINVAL for a dcid_len above
    // CH_QUIC_DCID_MAX and for an endpoint that is neither of the two,
    // which are the refusals this entry documents, so both bounds are
    // checked in one place. It writes nothing outside k.
    aes_public_key k;
    int rc = aes_public_key_initial(&k, dcid, dcid_len, endpoint);
    if (rc != CH_OK) {
        return rc;
    }
    if (pn_len == 0 || pn_len > QUIC_PN_MAX_LEN || hdr_len < pn_len) {
        return CH_EINVAL;
    }
    // RFC 9001 §5.4.2: the encoded packet number and the protected
    // payload together must run at least QUIC_PN_MAX_LEN bytes past the
    // start of the sample, so the sample sits inside the packet
    // (rfc9001.txt:1283-1286). pn_len is at most QUIC_PN_MAX_LEN here,
    // so the subtraction cannot wrap.
    if (pt_len < (size_t)QUIC_PN_MAX_LEN - pn_len) {
        return CH_EINVAL;
    }
    // out holds the header, the payload and the tag. Each compare
    // subtracts what is already accounted for, so no sum of two caller
    // lengths is formed and none can wrap.
    if (cap < hdr_len || cap - hdr_len < pt_len || cap - hdr_len - pt_len < GCM_TAG) {
        return CH_ECAP;
    }

    // Packet protection first, header protection second, the order RFC
    // 9001 §5.3 states (rfc9001.txt:1129-1132).
    uint8_t nonce[AES_IV];
    initial_nonce(&k, pn, nonce);
    for (size_t i = 0; i < hdr_len; i++) {
        out[i] = hdr[i];
    }
    // The associated data is the whole unprotected header, up to and
    // including the packet number (rfc9001.txt:1141-1143). hdr holds
    // those bytes and out now holds a copy of them; the AEAD reads the
    // caller's, which no step here writes.
    gcm_seal(&k, nonce, hdr, hdr_len, pt, pt_len, &out[hdr_len], &out[hdr_len + pt_len]);

    size_t pn_off = hdr_len - pn_len;
    uint8_t mask[AES_BLOCK];
    sample_mask(&k, out, pn_off, mask);
    // An Initial packet carries a long header, so the first mask byte
    // covers the low four bits of byte 0 and the next pn_len bytes
    // cover the packet number (rfc9001.txt:1164-1166,
    // rfc9001.txt:1202-1211).
    quic_header_protect(out, pn_off, pn_len, CH_LEVEL_INITIAL, mask);
    *out_len = hdr_len + pt_len + GCM_TAG;
    // No wipe: the key, the nonce and the mask are public bytes, for
    // the reason quic_aes.c states at its own derivation. A ct_wipe
    // here would tell a reader they are secret.
    return CH_OK;
}

int quic_initial_open(uint8_t endpoint, const uint8_t *dcid, size_t dcid_len, uint8_t *pkt,
                      size_t pkt_len, size_t pn_off, uint64_t largest_pn, uint64_t *pn,
                      size_t *pt_len) {
    // The receive key of RFC 9001 §5.2, under the endpoint the caller is
    // not, built on this frame the way the send key is. It runs before
    // this call reads a byte of pkt, so both refusals below touch no
    // packet byte.
    aes_public_key k;
    int rc = aes_public_key_initial(&k, dcid, dcid_len, peer_endpoint(endpoint));
    if (rc != CH_OK) {
        return rc;
    }
    // RFC 9001 §5.4.2: an endpoint discards a packet that is not long
    // enough to hold a complete sample (rfc9001.txt:1280-1281). The
    // compares subtract rather than add, so neither side can wrap, and
    // both run before any byte of pkt is read or written.
    if (pkt_len < pn_off || pkt_len - pn_off < QUIC_PN_MAX_LEN + QUIC_HP_SAMPLE_LEN) {
        return CH_QUIC_DISCARD;
    }

    uint8_t mask[AES_BLOCK];
    sample_mask(&k, pkt, pn_off, mask);
    // quic_header_unprotect uncovers byte 0 first, because its low two
    // bits carry the packet number length the rest of this call needs
    // (rfc9001.txt:1195-1198). It answers 1 to QUIC_PN_MAX_LEN and
    // nothing else, so the offsets below stay inside the length checked
    // above.
    size_t pn_len = quic_header_unprotect(pkt, pn_off, CH_LEVEL_INITIAL, mask);
    uint64_t truncated_pn = quic_pn_read(pkt, pn_off, pn_len);
    // RFC 9000 Appendix A.3 recovers the full number. It is written to
    // *pn only after the tag matches.
    uint64_t recovered_pn = quic_pn_decode(largest_pn, truncated_pn, pn_len);

    // The header ends where the packet number does, and the tag is the
    // last GCM_TAG bytes of the packet.
    size_t hdr_len = pn_off + pn_len;
    size_t ct_len = pkt_len - hdr_len - GCM_TAG;
    uint8_t nonce[AES_IV];
    initial_nonce(&k, recovered_pn, nonce);
    // In place, which quic_gcm.h admits as pt == ct: the plaintext
    // replaces the ciphertext where it sat, right after the header.
    if (!gcm_open(&k, nonce, pkt, hdr_len, &pkt[hdr_len], ct_len, &pkt[hdr_len + ct_len],
                  &pkt[hdr_len])) {
        return CH_QUIC_DISCARD;
    }
    *pn = recovered_pn;
    *pt_len = ct_len;
    return CH_OK;
}

#endif // CH_TRANSPORT_QUIC
