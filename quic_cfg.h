// The caller-facing declarations of a TRANSPORT=quic-nonblocking build: the two result codes
// ch_quic_open adds, the encryption levels, the key directions, the connection ID cap and the
// QUIC version numbers. cfg.h includes this header under CH_TRANSPORT_QUIC_NONBLOCKING alone, the
// way it includes webpki_cfg.h under CH_TRUST_WEBPKI, so a TCP build declares none of it. The
// body is guarded on the same define, so a file that includes this header outside cfg.h reads
// nothing in a TCP build either.
//
// A TRANSPORT=quic-nonblocking build runs this client over QUIC's CRYPTO frames and protects QUIC
// packets with the keys the handshake produces (RFC 9001, docs/quic.md). It has no record
// layer: §4.1.3 takes the unprotected content of TLS handshake records as the content of
// CRYPTO frames and uses no TLS record protection (rfc9001.txt:462-464).
//
// One caller contract holds for every call that takes CRYPTO bytes, and nothing checks it
// at run time: the caller delivers each level's bytes once and in order, and never
// re-delivers bytes chapulin has consumed. A retransmitted CRYPTO frame is a duplicate the
// caller drops, and chapulin stores no CRYPTO stream offset to tell one from new data.
#ifndef CH_QUIC_CFG_H
#define CH_QUIC_CFG_H
#ifdef CH_TRANSPORT_QUIC_NONBLOCKING

// The two result codes below sit beside cfg.h's CH_EINVAL, both int. The CH_QUIC_ prefix says
// neither has a meaning on the TCP transports, and ch_quic_open alone returns either.
//
// CH_QUIC_DISCARD leaves the session live, as cfg.h's CH_RECORD_AGAIN does, for a packet the
// caller drops: one that failed to authenticate, which RFC 9001 §5.5
// says does not necessarily indicate a protocol error or an attack (rfc9001.txt:1373-1376),
// or one too short to hold a header protection sample, which §5.4.2 discards
// (rfc9001.txt:1280-1281). Only the first raises ch_quic's open_failures, and quic.h states
// both cases in full. INV-13 carries the code.
//
// CH_QUIC_AEAD_LIMIT ends that tolerance: §6.6 makes an endpoint close and process no
// further packets once failed authentications exceed the AEAD's integrity limit
// (rfc9001.txt:1823-1827). A call that carries open_failures past it leaves the session
// dead.
#define CH_QUIC_DISCARD (-7)
#define CH_QUIC_AEAD_LIMIT (-8)

// The encryption levels, in the order the handshake reaches them (RFC 9001 §4.1.3,
// rfc9001.txt:455-460). CH_LEVEL_APPLICATION is QUIC's 1-RTT level; this build offers no
// 0-RTT, so no level names it. The values are compared, never used as an index into a key
// field.
#define CH_LEVEL_INITIAL 0
#define CH_LEVEL_HANDSHAKE 1
#define CH_LEVEL_APPLICATION 2

// The direction on_level_ready reports: read opens what the peer sent, write protects what
// this caller sends, and RFC 9001 §5.1 gives each level separate secrets per direction
// (rfc9001.txt:1010-1012). A direction is not an endpoint, and aes.h holds the two
// endpoint names beside the derivation that reads them. CH_QUIC_DCID_MAX caps §5.2's other
// input and sizes ch_quic's initial_dcid: a version 1 connection ID is at most 20 bytes and
// may be empty (rfc9000.txt:4991-4998, rfc9001.txt:1098-1100).
#define CH_KEY_READ 0
#define CH_KEY_WRITE 1
#define CH_QUIC_DCID_MAX 20

// The Version field values of RFC 9001's QUIC version 1 and RFC 9369's QUIC version 2
// (rfc9369.txt:137-141), which ch_cfg.quic_original_version and every call that takes a
// version name. A version is the caller's value, like the level: the caller reads it from
// the long header, and chapulin reads no header byte to learn it (docs/decisions.md 79).
// Whether this build derives a version's keys is one rule in one place, quic_version.h's
// quic_version_derived, and every call that takes a version refuses one it does not derive.
// This build derives version 1's keys alone.
#define CH_QUIC_VERSION_1 0x00000001U
#define CH_QUIC_VERSION_2 0x6B3343CFU

// quic_keys.h holds the three 1-RTT receive key set names and their count
// CH_QUIC_KEY_SETS, and quic.h includes it, so ch_quic_open's key_set output has a name.

#endif // CH_TRANSPORT_QUIC_NONBLOCKING
#endif
