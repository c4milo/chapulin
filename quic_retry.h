// The Retry Integrity Tag of RFC 9001 §5.8: AEAD_AES_128_GCM over the
// Retry Pseudo-Packet, under the 128-bit key and the 96-bit nonce the
// RFC prints, compared against the tag the packet carried. Only a
// TRANSPORT=quic build compiles it.
//
// This file and quic_initial.[ch] are the only sources that may call a
// symbol quic_aes.h or quic_gcm.h declares. That rule is INV-26 in
// docs/invariants.md, the AES exception: a lookup-table cipher is
// allowed in this tree only where every key it sees is public, and this
// key is printed in the RFC itself (rfc9001.txt:1499-1500). RFC 9001 §5
// draws the conclusion: Retry packets use a fixed key and so lack
// confidentiality and integrity protection (rfc9001.txt:1002-1003). The
// Semgrep rule inv-26-aes-public-keys-only fails a call to any aes_ or
// gcm_ symbol outside quic_initial.c, quic_retry.c, quic_aes.c and
// quic_gcm.c.
// docs/quic.md, "Where packet protection lives", states the trade.
//
// A Retry packet carries no protected payload and no protected header
// field, so §5.4's header protection does not apply to it
// (rfc9001.txt:1177-1179) and nothing here computes a mask. This file
// holds one call.
#ifndef CH_QUIC_RETRY_H
#define CH_QUIC_RETRY_H
#ifdef CH_TRANSPORT_QUIC

#include <stddef.h>
#include <stdint.h>

#include "quic_aes.h"
#include "quic_gcm.h"

// Recomputes the Retry Integrity Tag over the caller's Retry
// Pseudo-Packet and reports whether it equals tag. RFC 9001 §5.8 fixes
// every input (rfc9001.txt:1496-1507): the key K is the 128-bit constant
// 0xbe0c690b9f66575a1d766b54e368c84e, which aes_public_key_retry writes;
// the nonce N is the 96-bit constant 0x461599d35d632bf2239825bb, which
// quic_retry.c holds, because quic_aes.h leaves the iv field of a Retry
// key zero; the plaintext is empty; and the associated data is the whole
// pseudo-packet. So the computation is one gcm_seal over an empty
// plaintext, then one ct_memeq over GCM_TAG bytes.
//
// Requires: pseudo points at n readable bytes and tag at GCM_TAG
// readable bytes.
//
// pseudo is the Retry Pseudo-Packet of RFC 9001 Figure 8
// (rfc9001.txt:1514-1529), which the caller builds: it takes the Retry
// packet as received, removes the Retry Integrity Tag from the end, and
// writes two fields in front of what is left — one byte holding the
// length of the Original Destination Connection ID, then that
// connection ID itself (rfc9001.txt:1531-1544). The Original
// Destination Connection ID is the one the client put in the Initial
// packet this Retry answers. Including it means only an endpoint that
// observed that Initial packet can compute a tag that matches. tag is
// the GCM_TAG bytes the Retry packet carried at its end. chapulin reads
// no field of either: it computes the tag over the bytes it is given,
// so a caller that builds the pseudo-packet wrongly gets a 0 and no
// diagnosis. RFC 9001
// Appendix A.4 is the vector (rfc9001.txt:2490-2498).
//
// Returns 1 for a matching tag and 0 otherwise, through ct_memeq. It is
// not a ch_err and CH_OK has no meaning here, which is why the return
// type is uint8_t and not the int every ch_err-returning call in this
// tree uses: a caller cannot compare it against CH_OK without the
// compiler saying so, and a caller that did would accept exactly the
// forged Retry packets RFC 9000 §17.2.5.2 makes it discard.
// ch_quic_retry_ok forwards this value unchanged.
//
// The time this call takes depends on n alone. It
// touches no session state, so a 0 fails nothing by itself: RFC 9000
// §17.2.5.2 makes a client discard a Retry packet whose tag cannot be
// validated (rfc9000.txt:5407-5411), and discarding it is the caller's
// step. ch_quic's count of failed opens belongs to ch_quic_open and this
// call never raises it.
//
// Three other Retry rules of RFC 9000 §17.2.5.2 are the caller's too,
// because each reads a field chapulin does not parse: a client accepts
// at most one Retry per connection attempt (rfc9000.txt:5402-5405), it
// discards a Retry whose Retry Token field is empty
// (rfc9000.txt:5410-5411), and it discards a Retry whose Source
// Connection ID equals the Destination Connection ID of its own Initial
// packet (rfc9000.txt:5387-5390). After a Retry the caller does two
// things here: it calls quic_initial_keys again with the server's
// Source Connection ID, which §5.2 makes the new Destination Connection
// ID and the new Initial secret (rfc9001.txt:1092-1094), and it keeps
// its count of packets sealed under the Initial keys running across
// both key sets.
//
// It expands the printed key into one aes_public_key on its own stack
// frame and stores nothing, because a connection attempt accepts at most
// one Retry. lint-stack measures that frame against STACK_BUDGET. The
// frame is not wiped: every byte of that key is printed in the RFC, so
// there is no secret to wipe.
uint8_t quic_retry_ok(const uint8_t *pseudo, size_t n, const uint8_t tag[GCM_TAG]);

#endif // CH_TRANSPORT_QUIC
#endif
