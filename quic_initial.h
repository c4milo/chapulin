// The QUIC Initial packet path: RFC 9001 §5.2's key derivation from the
// Destination Connection ID and the salt the RFC prints, AEAD_AES_128_GCM
// packet protection in both directions, and §5.4.3's AES-ECB header
// protection mask under the Initial keys. Only a TRANSPORT=quic-nonblocking build
// compiles it.
//
// This file and quic_retry.[ch] are the only sources that may call a
// symbol aes.h or gcm.h declares. That rule is INV-26 in
// docs/invariants.md, the AES exception: a lookup-table cipher is
// allowed in this tree only where every key it sees is public, and the
// Initial keys are public because anyone who reads a long header reads
// the Destination Connection ID they are derived from. RFC 9001 draws
// that conclusion itself: Initial packets are not considered to have
// confidentiality or integrity protection (rfc9001.txt:999-1001). The
// Semgrep rule inv-26-aes-public-keys-only fails a call to any aes_ or
// gcm_ symbol outside quic_initial.c, quic_retry.c, aes.c and
// gcm.c.
// docs/quic.md, "Where packet protection lives", states the trade.
//
// Every encryption level above Initial runs ChaCha20-Poly1305 through
// quic_packet.[ch] instead, because that is the cipher suite this client
// offers. The two files share the mask application: this one computes an
// AES-ECB mask and passes its first 5 bytes to quic_packet.h's
// quic_header_protect and quic_header_unprotect, so no third file writes
// a masked byte.
//
// Layering. Nothing here sees ch_quic. quic.c holds the Destination
// Connection ID as initial_dcid and passes it in, and each call below
// derives the one direction's key it needs on its own stack. So the
// public entries ch_quic_seal and ch_quic_open reach the AES through
// this file, name no aes_ or gcm_ symbol themselves, and never hold a
// key: quic.c cannot declare an aes_public_key at all, because
// aes.h leaves that type incomplete and quic.c does not include
// aes_public_key.h.
#ifndef CH_QUIC_INITIAL_H
#define CH_QUIC_INITIAL_H
#ifdef CH_TRANSPORT_QUIC_NONBLOCKING

#include <stddef.h>
#include <stdint.h>

#include "aes.h"
#include "cfg.h"
#include "gcm.h"
#include "quic_packet.h"

// Two constants govern both packet paths, and quic_packet.h declares
// both: QUIC_PN_MAX_LEN, the longest encoded packet number field (RFC
// 9000 §17.1, rfc9000.txt:5073-5074), and QUIC_HP_SAMPLE_LEN, the
// length of the header protection sample (RFC 9001 §5.4.2,
// rfc9001.txt:1274-1278). This file states the §5.4.2 bound in the same
// spelling quic_packet.h does, pn_off + QUIC_PN_MAX_LEN +
// QUIC_HP_SAMPLE_LEN, so one number never carries two names. The sample
// starts QUIC_PN_MAX_LEN bytes past the packet number offset, because a
// receiver that has not removed header protection yet does not know the
// packet number length and takes the sample as if the field were its
// longest. AES_BLOCK keeps the one meaning aes.h gives it, the
// FIPS 197 block, which is also the input §5.4.3 feeds to AES-ECB whole
// (rfc9001.txt:1332-1336).
//
// The library builds as C, so the guard always runs. It holds the two
// names to the one length §5.4.3 needs: this file passes a §5.4.2
// sample to aes_encrypt_block_hp, whose input is a FIPS 197 block, so a
// later edit to either constant fails the build here instead of
// sampling the wrong bytes.
#ifndef __cplusplus
_Static_assert(AES_BLOCK == QUIC_HP_SAMPLE_LEN,
               "AES-ECB header protection reads one block as the sample");
#endif

// Both calls below take the Destination Connection ID rather than a
// key, and each derives the one direction's key it needs on its own
// stack. aes_public_key_initial does that derivation: the shared secret
// is HKDF-Extract over the printed salt
// 0x38762cf7f55934b34d179ae6a4c80cadccbb7f0a and dcid
// (rfc9001.txt:1051-1055, rfc9001.txt:1066), then one label per
// endpoint, "client in" and "server in" (rfc9001.txt:1057-1061). RFC
// 9001 Appendix A.1 is the vector for both endpoints
// (rfc9001.txt:2352-2377).
//
// Which label each entry derives under follows from endpoint, the first
// argument of both, which says which endpoint the caller is:
// CH_QUIC_ENDPOINT_CLIENT or CH_QUIC_ENDPOINT_SERVER (cfg.h). The seal
// derives that endpoint's secret and the open derives the other one's,
// because RFC 9001 §5.2 gives each endpoint its own and each reads what
// the other wrote. So a client passes CH_QUIC_ENDPOINT_CLIENT at both
// calls and a server passes CH_QUIC_ENDPOINT_SERVER at both, and the
// contracts below say "send" and "receive" because they name the
// caller's own two directions.
//
// The endpoint is an argument rather than a build define because
// srv_cfg.h refuses CH_ROLE_SERVER beside CH_TRANSPORT_QUIC_NONBLOCKING until a
// QUIC server driver exists, so no build could select the server
// mapping and no test could reach it. Nothing is negotiated here: a
// caller is one endpoint and passes the same value at every call.
// aes_public_key_initial refuses any third value, so a caller that
// passes one gets CH_EINVAL from both entries rather than a key.
//
// Deriving per packet rather than once is INV-26's structural check. A
// key that lives only inside one call is a key no other line can write
// a traffic secret into, and this file is the only one besides
// quic_retry.c that may hold an aes_public_key at all. The cost per
// packet is one HKDF-Extract, three HKDF-Expand-Label calls and two key
// expansions; no bench in this tree times them yet.
//
// dcid is the Destination Connection ID of the client's first Initial
// packet, which the caller chose, and after a Retry it is the Source
// Connection ID the server sent, which RFC 9000 §17.2.5.2 makes the
// client's new Destination Connection ID (rfc9000.txt:5417-5420). §5.2
// changes the secrets when a Retry arrives (rfc9001.txt:1092-1094), and
// the caller passes the new connection ID from then on; no key is ever
// updated, because none is kept. A zero-length dcid is legal, because
// §5.2 allows a zero-length Source Connection ID in a Retry
// (rfc9001.txt:1098-1100). ch_quic holds these bytes in initial_dcid
// and initial_dcid_len, and ch_quic_initial_keys bounds the length
// before it stores them.
//
// Both calls return CH_EINVAL and write nothing when dcid_len is above
// CH_QUIC_DCID_MAX, the RFC 9000 §17.2 cap on a version 1 connection
// ID, or when endpoint is neither of the two cfg.h names. Both check
// both before they derive or write anything.

// Protects one Initial packet under the send key and writes the whole
// packet into out: the header copied from hdr, the sealed payload after
// it, the GCM_TAG tag after that, and the §5.4 header protection mask
// applied to the copy in out. It modifies neither hdr nor pt. It derives
// the send key from dcid under endpoint's own label on its own stack and
// lets it die with the frame.
//
// Packet protection runs before header protection, the order RFC 9001
// §5.3 states (rfc9001.txt:1129-1132). The nonce is the packet
// protection IV with pn left-padded to AES_IV bytes and exclusive-ORed
// into it (rfc9001.txt:1135-1139). The associated data is the whole
// unprotected
// header, hdr_len bytes of it, up to and including the packet number
// (rfc9001.txt:1141-1143). The mask is AES-ECB under the header
// protection key over the QUIC_HP_SAMPLE_LEN sample that starts
// QUIC_PN_MAX_LEN bytes after the packet number offset in out, which
// aes_encrypt_block_hp computes (rfc9001.txt:1332-1336). Its first
// QUIC_HP_MASK_LEN bytes go to quic_packet.h's quic_header_protect
// (rfc9001.txt:1188-1193): an Initial packet carries a long header, so
// the mask covers the low four bits of byte 0 and the pn_len packet
// number bytes, and the mask bytes a shorter packet number leaves over
// stay unused (rfc9001.txt:1164-1166, rfc9001.txt:1202-1211).
//
// Requires: dcid points at dcid_len readable bytes, and dcid is read
// only when dcid_len is above 0. hdr points at hdr_len
// readable bytes and holds one whole unprotected Initial header,
// including the packet number field the caller encoded, with the Length
// field already covering pn_len + pt_len + GCM_TAG bytes; chapulin
// parses no header field and checks none. pn_len says how many of the
// last hdr_len bytes are that packet number field, so the packet number
// offset is hdr_len - pn_len. pn is the full packet number those bytes
// encode, below 2^62, the range RFC 9000 §17.1 gives the field
// (rfc9000.txt:4903-4905). pt points at pt_len readable bytes and out at
// cap writable bytes. out overlaps neither hdr nor pt.
//
// Returns CH_OK, writes hdr_len + pt_len + GCM_TAG bytes into out and
// sets *out_len to that count.
//
// Returns CH_ECAP and writes nothing when cap is below
// hdr_len + pt_len + GCM_TAG. *out_len is not written either, so the
// caller sizes its own buffer from that sum and calls again.
//
// Returns CH_EINVAL and writes nothing when endpoint is neither cfg.h
// name, when dcid_len is above CH_QUIC_DCID_MAX, when pn_len is 0 or
// above QUIC_PN_MAX_LEN, when hdr_len is below pn_len, or when
// pn_len + pt_len is below
// QUIC_PN_MAX_LEN. The last refusal keeps the
// sample inside out: the sample starts QUIC_PN_MAX_LEN bytes past the
// packet number offset and runs QUIC_HP_SAMPLE_LEN bytes, and out holds
// pn_len + pt_len + GCM_TAG bytes from that offset on. RFC 9001 §5.4.2
// states the same rule as padding, that
// the encoded packet number and the protected payload together must be
// at least 4 bytes longer than the sample (rfc9001.txt:1283-1286).
// Writing that padding is the caller's, because the caller frames the
// packet.
// The boundary test is that pn_len + pt_len == 4 seals and
// pn_len + pt_len == 3 returns CH_EINVAL.
//
// RFC 9001 §9.5 makes the packet number and the length it was encoded in
// secret bytes on this path: packet payloads and packet numbers must be
// free of side channels that reveal the packet number or the size it was
// encoded in (rfc9001.txt:2114-2116). The length refusals above are the
// only reads of pn_len that decide a branch, they run before any byte is
// sealed, and they reveal only a length the caller passed. Every step
// after them — the nonce, the seal and the mask — takes no branch and no
// memory index on pn or pn_len. No codegen check measures that here,
// because quic_initial.c sits in WIDEMUL_PUBLIC, and what the check would
// measure leaks nothing: anyone can compute the Initial keys and read
// the packet number this rule protects (rfc9001.txt:999-1001). The rule
// still binds the code.
//
// This call keeps no count. RFC 9001 §6.6 caps AEAD_AES_128_GCM at 2^23
// encrypted packets under one key (rfc9001.txt:1812-1813), and ch_quic
// counts what it seals at this level in initial_sealed and refuses the
// 2^23rd before it calls here.
int quic_initial_seal(uint8_t endpoint, const uint8_t *dcid, size_t dcid_len, uint64_t pn,
                      size_t pn_len, const uint8_t *hdr, size_t hdr_len, const uint8_t *pt,
                      size_t pt_len, uint8_t *out, size_t cap, size_t *out_len);

// Removes header protection, recovers the packet number and removes
// packet protection from one Initial packet, in place in pkt. The three
// run in one call because RFC 9001 §9.5 requires header protection
// removal, packet number recovery and packet protection removal to be
// applied together without timing and other side channels
// (rfc9001.txt:2110-2112). It derives the receive key from dcid under
// the label of the endpoint the caller is not, on its own stack, and
// lets it die with the frame.
//
// The steps are §5.4.1's in reverse, then §5.3's. The
// QUIC_HP_SAMPLE_LEN sample starts QUIC_PN_MAX_LEN bytes after pn_off;
// aes_encrypt_block_hp computes the mask block and quic_packet.h's
// quic_header_unprotect applies its first QUIC_HP_MASK_LEN bytes to
// byte 0 and the packet number field, at
// the long header's four-bit width (rfc9001.txt:1202-1211). Removing the
// mask differs from applying it in one way only: the packet number
// length is not known until byte 0 is unmasked, because byte 0 carries
// that length in its low two bits and those bits are masked
// (rfc9001.txt:1195-1198). The truncated packet number and largest_pn
// give the full one by RFC 9000 Appendix A.3's algorithm
// (rfc9000.txt:8343-8351). The nonce and the associated data are then
// §5.3's, the same two values quic_initial_seal builds.
//
// Requires: dcid points at dcid_len readable bytes, and dcid is read
// only when dcid_len is above 0. pkt points at pkt_len readable
// and writable bytes and holds one whole Initial packet, which the
// caller owns and which the caller has already separated from any other
// packet in the datagram (rfc9001.txt:1320-1321). pn_off is the offset
// of the packet number field in pkt, which the caller read from the
// long header's Length field and the connection ID lengths before it
// called; chapulin parses no header field. largest_pn is the largest
// packet number the caller has successfully processed in the Initial
// packet number space, the value RFC 9000 Appendix A.3 decodes against
// (rfc9000.txt:8350-8351). pn and pt_len are not NULL.
//
// Returns CH_OK and, in pkt, leaves the unprotected header at the front
// and the plaintext after it at pn_off + pn_len, where pn_len is one
// plus the low two bits of byte 0 (rfc9000.txt:5073-5076). *pt_len is
// that plaintext's length in bytes and *pn is the recovered packet
// number. The caller reads byte 0 of pkt for the packet number length
// and the reserved bits, and feeds *pn to the next call's largest_pn.
//
// Returns CH_EINVAL and writes nothing when endpoint is neither cfg.h
// name or when dcid_len is above CH_QUIC_DCID_MAX, both of which it
// checks before it reads a byte of pkt.
//
// Returns CH_QUIC_DISCARD (cfg.h) in two cases, writes neither output
// and leaves the session alive. The two cases differ in what the caller
// then counts, so they are stated apart.
//
// First, when pkt_len is below pn_off + QUIC_PN_MAX_LEN +
// QUIC_HP_SAMPLE_LEN: RFC 9001 §5.4.2 makes an endpoint discard a
// packet not long enough to hold a complete sample
// (rfc9001.txt:1280-1281), and this call refuses before it samples, so
// it reads and writes no byte of pkt at all. That packet never reaches
// the AEAD, so it is no authentication failure and the caller counts it
// nowhere: §6.6's integrity limit counts received packets that fail
// authentication (rfc9001.txt:1823-1827). The boundary test is that a
// packet of exactly that length opens and one byte less discards.
//
// Second, when the tag does not match, which RFC 9001 §5.5 says does
// not necessarily indicate a protocol error or an attack
// (rfc9001.txt:1373-1376). That one is an authentication failure, and
// ch_quic_open raises ch_quic's open_failures for it and asks
// quic_integrity_limit_exceeded what the new count means. A discard
// writes no plaintext byte anywhere. The rest of pkt is unspecified
// after this second case, because the call works in place and has
// already removed the header protection; the caller drops the packet,
// so it reads none of it.
//
// No other return code exists for this call. It raises no counter
// itself: the §6.6 counts are per connection and live in ch_quic
// (docs/quic.md, "What the mode does not do").
int quic_initial_open(uint8_t endpoint, const uint8_t *dcid, size_t dcid_len, uint8_t *pkt,
                      size_t pkt_len, size_t pn_off, uint64_t largest_pn, uint64_t *pn,
                      size_t *pt_len);

#endif // CH_TRANSPORT_QUIC_NONBLOCKING
#endif
