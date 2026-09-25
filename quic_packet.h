// QUIC packet protection (RFC 9001 §5.3) and header protection (§5.4)
// for the levels whose AEAD is the cipher suite TLS negotiated
// (docs/decisions.md 58): the Handshake level and the 1-RTT
// level. It also holds the §6.5 rule that picks a 1-RTT receive key
// set, the §5.4.2 length checks and the §6.6 limits. Only a
// TRANSPORT=quic build compiles it. docs/quic.md states the mode.
//
// These are the calls ch_quic_seal and ch_quic_open make. quic.c holds
// the session and its counters and passes the key values down; this
// file reads no session field and opens no socket.
// quic_initial.c computes the AES-ECB mask of §5.4.3 under the Initial
// keys and calls the header protection pair below with it, so no other
// file writes a masked byte.
//
// The constant-time obligation RFC 9001 §9.5 puts on both directions,
// as a contract on every call below. Receiving, §9.5 says header
// protection removal, packet number recovery and packet protection
// removal MUST be applied together without timing and other side
// channels (rfc9001.txt:2110-2112), so one call does all three:
// quic_packet_open_handshake and quic_packet_open_application, and no
// caller splits them apart. Sending, §9.5 says construction and
// protection of packet payloads and packet numbers MUST be free from
// side channels that would reveal the packet number or its encoded size
// (rfc9001.txt:2114-2116), so pn and pn_len are secret bytes here: the
// nonce construction, the packet number read and the mask application
// take no branch on either and use neither as a memory index.
//
// Two compares carry that rule, and both are branchless mask
// arithmetic of the kind ct.h states and CLAUDE.md requires, never an
// if: the packet's Key Phase bit against the stored key_phase, and the
// recovered packet number against current_phase_lowest_pn.
// quic_key_set_select holds both, and the value it returns indexes no
// array: quic_keys_select reads all CH_QUIC_KEY_SETS sets and combines
// them under masks.
//
// Three calls move packet bytes outside the rbuf reader and the wbuf
// writer, and they are the only ones here that do: quic_header_protect
// and quic_header_unprotect write masked bytes in place, because §5.4.1
// applies the mask in place, and quic_pn_read reads the packet number
// field in place. Each runs only after the §5.4.2 length check has
// proved those bytes present. rbuf cannot serve them: its bounds checks
// branch, and §9.5 makes the packet number and its encoded length
// secret (rfc9001.txt:2114-2116). The three read and write the same
// QUIC_PN_MAX_LEN bytes whatever pn_len is and select with mask
// arithmetic instead.
#ifndef CH_QUIC_PACKET_H
#define CH_QUIC_PACKET_H
#ifdef CH_TRANSPORT_QUIC

#include <stddef.h>
#include <stdint.h>

#include "aead.h"
#include "cfg.h"
#include "quic_keys.h"

// A packet number is an integer in the range 0 to 2^62-1, encoded in 1
// to 4 bytes in network byte order (RFC 9000 §17.1,
// rfc9000.txt:4897-4899, rfc9000.txt:4903-4905). Every read and write
// of those bytes goes byte by byte, so no step assumes host endianness.
#define QUIC_PN_MAX_LEN 4

// The two least significant bits of byte 0 hold the packet number
// length minus one, in both header forms (RFC 9000 §17.2 and §17.3.1,
// rfc9000.txt:5060-5067, rfc9000.txt:5521-5527). Header protection
// covers them, so a receiver reads them after the mask is removed.
#define QUIC_PN_LEN_BITS 0x03

// The Key Phase bit of a short header's byte 0, which header
// protection covers too (RFC 9000 §17.3.1, rfc9000.txt:5515-5519). The
// sender writes it from ch_quic_key_phase before it calls
// quic_packet_seal; the receiver reads it after quic_header_unprotect
// and hands it to quic_key_set_select.
#define QUIC_KEY_PHASE_BIT 0x04

// The header protection sample: 16 bytes of the packet's ciphertext,
// starting QUIC_PN_MAX_LEN bytes after the packet number offset,
// because a receiver does not know the packet number length yet and
// the field is assumed to be at its maximum (RFC 9001 §5.4.2,
// rfc9001.txt:1274-1278).
#define QUIC_HP_SAMPLE_LEN 16

// The mask is 5 bytes (RFC 9001 §5.4.1, rfc9001.txt:1188-1193).
#define QUIC_HP_MASK_LEN 5

// Which bits of byte 0 the first mask byte covers: the low four for a
// long header, the low five for a short header (RFC 9001 §5.4,
// rfc9001.txt:1164-1170, and the pseudocode at rfc9001.txt:1202-1211).
// CH_LEVEL_INITIAL and CH_LEVEL_HANDSHAKE carry long headers and take
// QUIC_HP_BITS_LONG; CH_LEVEL_APPLICATION carries a short header and
// takes QUIC_HP_BITS_SHORT.
#define QUIC_HP_BITS_LONG 0x0f
#define QUIC_HP_BITS_SHORT 0x1f

// The RFC 9001 §6.6 limits, in packets.
//
// QUIC_INTEGRITY_LIMIT is the count of received packets that fail
// authentication, across every key of one connection, that
// AEAD_CHACHA20_POLY1305 permits: 2^36 invalid packets
// (rfc9001.txt:1830-1831). The endpoint closes once the count exceeds
// it (rfc9001.txt:1823-1827). AES-GCM permits 2^52
// (rfc9001.txt:1829-1830), so this one limit, the stricter, covers every
// level and every suite, the AES-128-GCM Initial level included.
//
// QUIC_CONFIDENTIALITY_LIMIT is the count of packets encrypted under
// one set of keys that AES-GCM permits: 2^23 encrypted packets
// (rfc9001.txt:1812-1813). The Initial keys pay it, and so does every
// key set of an AES-GCM suite. For AEAD_CHACHA20_POLY1305 the limit is
// greater than the packet number space and is disregarded
// (rfc9001.txt:1814-1815).
//
// ch_quic holds open_failures, because §6.6 counts failures per
// connection, and initial_sealed; quic.c raises both. An AES-GCM key
// set counts its own packets in quic_keys.sealed, which quic_packet_seal
// raises. Each asks the two predicates below what its count now means.
#define QUIC_INTEGRITY_LIMIT (UINT64_C(1) << 36)
#define QUIC_CONFIDENTIALITY_LIMIT (UINT64_C(1) << 23)

// Writes the 5 header protection mask bytes of RFC 9001 §5.4.4
// (rfc9001.txt:1338-1362), or under an AES-GCM suite those of §5.4.3,
// AES-ECB at the suite's key length (rfc9001.txt:1332-1336).
//
// The ChaCha20 mask is the first QUIC_HP_MASK_LEN bytes of one block
// under h's key, which equals ChaCha20 applied to 5 zero bytes
// (rfc9001.txt:1354-1361). The counter is sample[0..3] read as a
// little-endian 32-bit value, assembled byte by byte: §5.4.4 says an
// implementation that takes a 32-bit integer in place of the byte
// sequence reads it little-endian (rfc9001.txt:1344-1347), and
// assembling it byte by byte keeps the build off host endianness. The
// nonce is sample[4..15] taken as bytes, in that order.
//
// Requires: h was written by quic_hp_key_init; sample points at
// QUIC_HP_SAMPLE_LEN readable bytes, taken the way §5.4.2 says; mask
// points at QUIC_HP_MASK_LEN writable bytes not overlapping sample.
//
// Writes QUIC_HP_MASK_LEN bytes and cannot fail, so it returns
// nothing. It wipes the block it computed, and any AES round keys, with
// ct_wipe, because both come from a secret key.
//
// RFC 9001 Appendix A.5 is the vector: sample
// 5e5cd55c41f69080575d7999c25a5bfb gives mask aefefe7d03
// (rfc9001.txt:2546-2547).
void quic_hp_mask(const quic_hp_key *h, const uint8_t sample[QUIC_HP_SAMPLE_LEN],
                  uint8_t mask[QUIC_HP_MASK_LEN]);

// Applies the header protection mask to a packet in place (RFC 9001
// §5.4.1, rfc9001.txt:1188-1193 and the pseudocode at
// rfc9001.txt:1202-1211).
//
// The mask rule, exactly. The first mask byte covers the low four bits
// of byte 0 for a long header and the low five bits for a short header:
// pkt[0] ^= mask[0] & QUIC_HP_BITS_LONG, or mask[0] &
// QUIC_HP_BITS_SHORT. The next pn_len mask bytes, mask[1] through
// mask[pn_len], cover the pn_len packet number bytes at pn_off. The
// remaining QUIC_HP_MASK_LEN - 1 - pn_len mask bytes go unused, which
// is what §5.4.1 says of the bytes a shorter packet number encoding
// leaves over. level picks the width rather than byte 0's Header Form
// bit, because level is the caller's own public value:
// CH_LEVEL_INITIAL and CH_LEVEL_HANDSHAKE take QUIC_HP_BITS_LONG,
// CH_LEVEL_APPLICATION takes QUIC_HP_BITS_SHORT.
//
// How it meets §9.5 (rfc9001.txt:2114-2116), where pn_len is a secret:
// the loop always reads and always writes the same QUIC_PN_MAX_LEN
// bytes at pn_off, and selects each mask byte against pn_len with
// branchless mask arithmetic, so a byte past the packet number is
// written with a mask byte of zero and keeps its value. Neither the
// trip count nor the addresses touched depend on pn_len.
//
// Requires: pkt points at pn_off + QUIC_PN_MAX_LEN writable bytes, the
// count the seal and open calls' §5.4.2 checks guarantee; pn_len is 1
// to QUIC_PN_MAX_LEN; level is one of the three CH_LEVEL_ values; mask
// points at QUIC_HP_MASK_LEN readable bytes. The caller has already
// sealed the payload, because §5.4.1 applies header protection after
// packet protection (rfc9001.txt:1183-1184).
//
// Writes byte 0 and QUIC_PN_MAX_LEN bytes at pn_off, and cannot fail,
// so it returns nothing.
void quic_header_protect(uint8_t *pkt, size_t pn_off, size_t pn_len, uint8_t level,
                         const uint8_t mask[QUIC_HP_MASK_LEN]);

// Removes the header protection mask from a packet in place and
// reports the packet number length it uncovered. It differs from
// quic_header_protect only in when the packet number length is known,
// which is the difference §5.4.1 names (rfc9001.txt:1196-1198): it
// unmasks byte 0 first, reads the length from byte 0's low two bits,
// then unmasks the packet number bytes. The mask rule and the §9.5
// obligation are quic_header_protect's, unchanged, and this call is one
// step of the process rfc9001.txt:2110-2112 requires to run together
// with packet number recovery and packet protection removal.
//
// Requires: pkt points at pn_off + QUIC_PN_MAX_LEN readable and
// writable bytes; level is one of the three CH_LEVEL_ values; mask
// points at QUIC_HP_MASK_LEN readable bytes.
//
// Returns the packet number length in bytes, (pkt[0] &
// QUIC_PN_LEN_BITS) + 1, which is 1 to QUIC_PN_MAX_LEN and nothing
// else, so it cannot fail. The unprotected header stays in pkt, where
// the caller reads the reserved bits and the Key Phase bit.
size_t quic_header_unprotect(uint8_t *pkt, size_t pn_off, uint8_t level,
                             const uint8_t mask[QUIC_HP_MASK_LEN]);

// Reads the encoded packet number out of an unprotected header: the
// pn_len bytes at pn_off, in network byte order (RFC 9000 §17.1,
// rfc9000.txt:4897-4899). It always reads QUIC_PN_MAX_LEN bytes and
// then clears the bytes above pn_len with branchless mask arithmetic,
// so neither the addresses read nor the work done depends on pn_len,
// which §9.5 makes a secret.
//
// Requires: pkt points at pn_off + QUIC_PN_MAX_LEN readable bytes;
// pn_len is 1 to QUIC_PN_MAX_LEN, the value quic_header_unprotect
// returned.
//
// Returns the encoded value, which is at most 2^32-1. It is the
// truncated_pn quic_pn_decode takes, not a full packet number.
uint64_t quic_pn_read(const uint8_t *pkt, size_t pn_off, size_t pn_len);

// Recovers the full packet number from the encoded one, which is the
// DecodePacketNumber of RFC 9000 Appendix A.3
// (rfc9000.txt:8358-8381). pn_len counts bytes, so the algorithm's
// pn_nbits is 8 * pn_len.
//
// largest_pn is the largest packet number the caller has successfully
// processed in that packet number space (rfc9000.txt:8350-8351), which
// an earlier successful open is its only source for, and why the open
// calls report the number they recovered.
//
// Both comparisons Figure 47 writes as an if are branchless mask
// arithmetic here, under §9.5 (rfc9001.txt:2110-2112): the recovered
// number is exactly the value an attacker guesses at. The arithmetic
// keeps Figure 47's overflow and underflow guards, so the result stays
// in 0 to 2^62-1.
//
// Requires: pn_len is 1 to QUIC_PN_MAX_LEN; truncated_pn is below
// 2^(8 * pn_len), which quic_pn_read returns for that pn_len;
// largest_pn is at most 2^62-1.
//
// Returns the recovered packet number and cannot fail: every input
// decodes to a number in range, and a wrong one fails the AEAD tag
// instead, which RFC 9001 §5.5 calls a discard (rfc9001.txt:1373-1376).
uint64_t quic_pn_decode(uint64_t largest_pn, uint64_t truncated_pn, size_t pn_len);

// Builds the AEAD nonce of RFC 9001 §5.3: the packet number in network
// byte order, left-padded with zeros to the length of the packet
// protection IV, exclusive-ORed with that IV (rfc9001.txt:1134-1139).
// It writes all AEAD_NONCE bytes with the same XORs whatever pn is, so
// no step branches on the packet number or on its encoded size, which
// §9.5 requires of both directions (rfc9001.txt:2110-2112,
// rfc9001.txt:2114-2116). It writes one byte at a time, so no step
// assumes host endianness.
//
// Requires: iv points at AEAD_NONCE readable bytes, the packet
// protection IV quic_keys_init wrote; nonce points at AEAD_NONCE
// writable bytes; iv and nonce do not overlap; pn is at most 2^62-1
// (RFC 9000 §12.3). A larger pn is not checked and costs no compare:
// its high bits XOR into the nonce, the peer computes a different one,
// and the packet fails to open.
//
// Writes AEAD_NONCE bytes and cannot fail, so it returns nothing.
void quic_nonce(const uint8_t iv[AEAD_NONCE], uint64_t pn, uint8_t nonce[AEAD_NONCE]);

// Picks the 1-RTT receive key set for one packet, which is the rule of
// RFC 9001 §6.5 (rfc9001.txt:1735-1743). The Key Phase bit alone does
// not answer, because packets from the previous phase and packets from
// the next phase carry the same Key Phase value
// (rfc9001.txt:1735-1737). So the bit picks the phase and
// the recovered packet number tells the two apart: when the packet's
// bit equals the stored key_phase the current set opens the packet;
// when it differs, a packet number below current_phase_lowest_pn takes
// the previous set and one at or above it takes the next set
// (rfc9001.txt:1739-1743). Selecting the next set that way keeps the
// §5.5 MUST that forbids opening a higher-numbered packet under the
// previous keys (rfc9001.txt:1365-1369).
//
// Both compares are branchless mask arithmetic and never an if. §6.5
// asks for that in its own words: the selection must not expose a
// timing side channel that reveals which keys removed protection
// (rfc9001.txt:1745-1748), and §9.5 states it again for the Key Phase
// bit (rfc9001.txt:2110-2112).
//
// Requires: key_phase is 0 or 1, the bit ch_quic holds for the current
// 1-RTT set; packet_key_phase is 0 or 1, byte 0's QUIC_KEY_PHASE_BIT
// after quic_header_unprotect, reduced to that range by the caller
// with a shift rather than a compare; pn is the number quic_pn_decode
// recovered; current_phase_lowest_pn is the lowest packet number the
// caller has processed under the current key phase.
//
// Returns CH_QUIC_KEY_PREVIOUS, CH_QUIC_KEY_CURRENT or
// CH_QUIC_KEY_NEXT (cfg.h) and cannot fail. It is pure: it installs
// nothing, and a CH_QUIC_KEY_NEXT result only names the set that opens
// this packet. ch_quic_key_update installs the update, which the caller
// runs after a successful open reports it (§6.2,
// rfc9001.txt:1654-1656).
uint8_t quic_key_set_select(uint8_t key_phase, uint8_t packet_key_phase, uint64_t pn,
                            uint64_t current_phase_lowest_pn);

// Copies one of the CH_QUIC_KEY_SETS receive key sets into out,
// without using selected as a memory index. It reads every byte of all
// three sets and combines them under a mask built from selected, so
// the addresses it reads are the same whichever set wins. CLAUDE.md's
// rule against secret-dependent memory indices requires that here,
// because selected comes from the Key Phase bit and the recovered
// packet number, and §9.5 makes both secret (rfc9001.txt:2110-2112).
//
// Requires: sets points at CH_QUIC_KEY_SETS readable quic_keys, the
// three the session holds; selected is CH_QUIC_KEY_PREVIOUS,
// CH_QUIC_KEY_CURRENT or CH_QUIC_KEY_NEXT; out points at one writable
// quic_keys that does not overlap sets. A wiped set reads as zero and
// opens no packet, which is what ch_quic_drop_previous_keys leaves.
//
// Writes out whole and cannot fail, so it returns nothing. out holds
// key material, so the caller wipes it with ct_wipe on every path.
void quic_keys_select(const quic_keys sets[CH_QUIC_KEY_SETS], uint8_t selected, quic_keys *out);

// Protects one packet under k and h and writes it whole into out:
// packet protection first (RFC 9001 §5.3), then header protection (§5.4).
//
// It copies the hdr_len header bytes into out, seals pt after them
// with the header as the associated data (rfc9001.txt:1141-1143) and
// the nonce quic_nonce builds, writes the AEAD_TAG tag after the
// ciphertext, and masks the copy. It modifies neither hdr nor pt.
//
// hdr carries the packet number field the caller encoded, so hdr_len
// counts those bytes and pn_len says how many of the last ones they
// are; pn is that same number and it builds the nonce. The packet
// number offset is hdr_len - pn_len. At CH_LEVEL_APPLICATION the
// caller has already written byte 0's QUIC_KEY_PHASE_BIT from
// ch_quic_key_phase, and this call only masks that byte.
//
// The §5.4.2 length rule (rfc9001.txt:1283-1286): the encoded packet
// number and the protected payload together must run at least
// QUIC_PN_MAX_LEN bytes past the sample, so the sample sits inside the
// packet. Written out, pn_len + pt_len + AEAD_TAG >= QUIC_PN_MAX_LEN +
// QUIC_HP_SAMPLE_LEN, which is pn_len + pt_len >= 4 because the AEAD
// adds 16 bytes. The caller pads a short payload, because the caller
// frames the packet; this call refuses one it cannot sample. The
// boundary test is that pn_len + pt_len == 4 seals and 3 refuses.
//
// Requires: k and h hold that level's send keys; level is
// CH_LEVEL_HANDSHAKE or CH_LEVEL_APPLICATION, because quic_initial.c
// runs the Initial level; hdr points at hdr_len readable bytes; pt
// points at pt_len readable bytes; out points at cap writable bytes
// and overlaps neither hdr nor pt; pn is at most 2^62-1.
//
// Returns CH_OK and writes hdr_len + pt_len + AEAD_TAG bytes into out
// and that same count into *out_len.
//
// Returns CH_EINVAL and writes nothing, leaving *out_len alone, when
// pn_len is 0 or above QUIC_PN_MAX_LEN, when hdr_len is below pn_len,
// or when the §5.4.2 rule above fails. Returns CH_ECAP and writes
// nothing, leaving *out_len alone, when cap is below hdr_len + pt_len
// + AEAD_TAG. The argument checks run first, so a call wrong in both
// ways returns CH_EINVAL whatever buffer it was given. Neither code
// touches k or h, and both leave the session live. Those checks branch
// on lengths the caller passed and produce no packet; every step that
// does produce bytes runs after them and takes no branch and no memory
// index on pn or pn_len, which is the §9.5 send rule
// (rfc9001.txt:2114-2116).
//
// Under an AES-GCM suite §6.6's confidentiality limit is this call's:
// it returns CH_EINVAL and writes nothing for the packet that would
// bring k->sealed to QUIC_CONFIDENTIALITY_LIMIT (rfc9001.txt:1812-1813),
// and raises k->sealed for each packet it seals, the one field of k it
// writes. A key update writes a new set and starts the count again.
int quic_packet_seal(quic_keys *k, const quic_hp_key *h, uint8_t level, uint64_t pn, size_t pn_len,
                     const uint8_t *hdr, size_t hdr_len, const uint8_t *pt, size_t pt_len,
                     uint8_t *out, size_t cap, size_t *out_len);

// Opens one Handshake-level packet in place: it removes header
// protection, recovers the packet number and removes packet protection,
// the three steps RFC 9001 §9.5 requires one function to apply together
// (rfc9001.txt:2110-2112). The Handshake level has one receive key set,
// so nothing here selects one and a long header carries no Key Phase
// bit. The steps are
// quic_hp_mask over the sample at pn_off + QUIC_PN_MAX_LEN,
// quic_header_unprotect, quic_pn_read, quic_pn_decode, quic_nonce and
// k's AEAD, with the unprotected header as the associated data.
//
// The §5.4.2 discard (rfc9001.txt:1280-1281): a packet that cannot
// hold a complete sample is discarded. That is pkt_len below pn_off +
// QUIC_PN_MAX_LEN + QUIC_HP_SAMPLE_LEN, and the check runs before the
// sample is read, so a short packet is never touched. The boundary
// test is that the last valid length opens and the first invalid one
// discards.
//
// Requires: k and h hold the Handshake receive keys; pkt points at
// pkt_len readable and writable bytes and holds one whole packet,
// which the caller owns; pn_off is the offset of the packet number
// field and is at most pkt_len; largest_pn is the largest packet
// number the caller processed in that space, or 0 before the first.
//
// Returns CH_OK, leaves the unprotected header at the front of pkt,
// puts the plaintext at pn_off + pn_len, writes the plaintext length
// in bytes to *pt_len and the recovered packet number to *pn.
//
// Returns CH_QUIC_DISCARD in two cases, leaves *pn and *pt_len alone,
// releases no plaintext byte and leaves the session live. The two count
// differently, so ch_quic_open tells them apart by the check that
// produced them. A packet too short to sample is discarded by §5.4.2
// before the sample is read (rfc9001.txt:1280-1281); it never reaches
// the AEAD, so it is no authentication failure and raises open_failures
// nowhere, because §6.6 counts received packets that fail
// authentication (rfc9001.txt:1823-1827). A packet whose tag does not
// match is that authentication failure, which RFC 9001 §5.5 calls a
// discard rather than a protocol error or an attack
// (rfc9001.txt:1373-1376): ch_quic_open raises open_failures for it and
// asks quic_integrity_limit_exceeded what the new count means. Its
// header bytes are unmasked in place by then, so the packet no longer
// holds the bytes that arrived and the caller drops it rather than
// reading them. This call raises no counter itself: the §6.6 counts are
// per connection and live in ch_quic.
//
// No other code is returned. ch_quic_open refuses a call at a level
// whose keys are not installed, and an out-of-order call, before it
// reaches here.
int quic_packet_open_handshake(const quic_keys *k, const quic_hp_key *h, uint8_t *pkt,
                               size_t pkt_len, size_t pn_off, uint64_t largest_pn, uint64_t *pn,
                               size_t *pt_len);

// Opens one 1-RTT packet in place. It runs quic_packet_open_handshake's
// three steps in one call and adds the §6.5 receive key set selection
// between packet number recovery and packet protection removal:
// quic_key_set_select picks the set from the packet's Key Phase bit
// and the recovered packet number, quic_keys_select copies it.
//
// Requires: sets points at CH_QUIC_KEY_SETS readable quic_keys, the
// session's previous, current and next 1-RTT receive sets; h holds the
// 1-RTT receive header protection key, which §5.4 keeps for the whole
// connection (rfc9001.txt:1172-1174); key_phase is the bit the current
// set carries, 0 or 1; pkt, pkt_len, pn_off and largest_pn are
// quic_packet_open_handshake's, over the application packet number
// space; current_phase_lowest_pn is the lowest packet number the
// caller has processed under the current key phase.
//
// Returns CH_OK, leaves the unprotected header at the front of pkt,
// puts the plaintext at pn_off + pn_len, writes the plaintext length
// to *pt_len, the recovered packet number to *pn and the set that
// opened the packet to *key_set: CH_QUIC_KEY_PREVIOUS,
// CH_QUIC_KEY_CURRENT or CH_QUIC_KEY_NEXT. A CH_QUIC_KEY_NEXT result
// is a peer-initiated key update, and the caller must call
// ch_quic_key_update before it seals the ACK (§6.2,
// rfc9001.txt:1654-1656).
//
// Returns CH_QUIC_DISCARD on the same two grounds
// quic_packet_open_handshake lists, counted the same way — the §5.4.2
// length discard raises nothing and the tag mismatch is what
// ch_quic_open counts in open_failures — and writes none of the three
// outputs. *key_set is written only on a successful open, so a packet
// whose Key Phase bit differs from key_phase and then fails to
// authenticate changes nothing at all. That is the second §5.5 MUST
// (rfc9001.txt:1369-1371), and §6.3 gives the reason, that such packets
// are easy to forge (rfc9001.txt:1706-1707). This call installs no key
// set and derives none: §6.3 makes deriving a set while opening a
// packet a timing signal (rfc9001.txt:1692-1696).
//
// No other code is returned. ch_quic_open refuses a 1-RTT packet that
// arrives before the handshake completes (RFC 9001 §5.7,
// rfc9001.txt:1484-1486), so that check does not run here.
int quic_packet_open_application(const quic_keys sets[CH_QUIC_KEY_SETS], const quic_hp_key *h,
                                 uint8_t key_phase, uint8_t *pkt, size_t pkt_len, size_t pn_off,
                                 uint64_t largest_pn, uint64_t current_phase_lowest_pn,
                                 uint8_t *key_set, uint64_t *pn, size_t *pt_len);

// Whether the connection has passed RFC 9001 §6.6's integrity limit
// and must process no more packets (rfc9001.txt:1823-1827).
//
// Requires: open_failures is the count of received packets that failed
// authentication in this connection, across every level, with the
// current failure already added to it.
//
// Returns 1 when open_failures is above QUIC_INTEGRITY_LIMIT and 0
// otherwise, so the 2^36th failed open is still a discard and the
// 2^36+1st stops the session. It changes nothing: the caller returns
// CH_QUIC_AEAD_LIMIT and makes the session dead, and colibri sends
// CONNECTION_CLOSE with AEAD_LIMIT_REACHED.
int quic_integrity_limit_exceeded(uint64_t open_failures);

// Whether sealing one more packet under one set of AES-GCM keys would
// reach RFC 9001 §6.6's confidentiality limit (rfc9001.txt:1800-1803,
// rfc9001.txt:1812-1813). quic.c asks it for the Initial keys and
// quic_packet_seal for an AES-GCM suite's.
//
// Requires: sealed is the count of packets already sealed under those
// keys, ch_quic's initial_sealed or quic_keys.sealed.
//
// Returns 1 when sealed + 1 reaches QUIC_CONFIDENTIALITY_LIMIT, so the
// call refuses the 2^23rd packet. That is one packet stricter than
// §6.6, which stops an endpoint once the count exceeds the limit
// (rfc9001.txt:1801-1803), and never weaker. ch_quic_initial_keys does
// not reset initial_sealed after a Retry, so one running count covers
// both sets of Initial keys.
//
// Both refusals return CH_EINVAL, because CH_QUIC_DISCARD and
// CH_QUIC_AEAD_LIMIT are ch_quic_open's alone, and leave the session
// live. Every later seal under those keys is refused the same way, so
// the keys are used no more, which is §6.6's MUST (rfc9001.txt:1800-1803).
int quic_confidentiality_limit_reached(uint64_t sealed);

#endif // CH_TRANSPORT_QUIC
#endif
