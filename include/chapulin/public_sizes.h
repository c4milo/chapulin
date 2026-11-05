// The sizes the public headers name: the hash lengths that size a ticket's
// secrets, the longest key a CA build extracts, the QUIC key sets
// ch_quic_open reports, the AES block and key sizes of ch_aes_block, and
// the longest run of KeyUpdates a TCP session reads.
// Each is defined here once. The internal headers that use one include
// this header, so a public header needs no internal header for a size.
// It holds numbers and the defines that choose between them, and no type
// and no call.
#ifndef CH_PUBLIC_SIZES_H
#define CH_PUBLIC_SIZES_H

// SHA-256 and SHA-384 output lengths (FIPS 180-4).
#define SHA256_LEN 32
#define SHA384_LEN 48

// SHA-384 joins HMAC and HKDF under CH_HASH_SHA384. A -DCH_SUITE_AES_GCM
// build sets it here, because TLS_AES_256_GCM_SHA384 hashes with SHA-384;
// a test binary or a proof harness sets it on its own to run the SHA-384
// vectors on a host with no AES instructions. Every other build compiles
// SHA-256 alone, links no sha512.c, and keeps every secret at 32 bytes.
#if defined(CH_SUITE_AES_GCM) && !defined(CH_HASH_SHA384)
#define CH_HASH_SHA384
#endif

// The longest hash output, and so the longest secret, this build holds.
#ifdef CH_HASH_SHA384
#define HKDF_HASH_MAX SHA384_LEN
#else
#define HKDF_HASH_MAX SHA256_LEN
#endif

// Extracted leaf identity: the SPKI key bytes, copied out because the
// message buffer is reused before CertificateVerify arrives.
#ifdef CH_PIN_ECDSA
#define CH_X509_KEY_MAX 64
#elif defined(CH_PIN_MLDSA)
#define CH_X509_KEY_MAX 2592 // MLDSA87_PK_LEN
#else
#define CH_X509_KEY_MAX 384
#endif

// The 1-RTT receive key sets a session holds, and the three names that
// index them, which ch_quic_open reports in its key_set output and
// ch_quic_key_update rotates. RFC 9001 §6.3 makes the current and the
// next set a floor (rfc9001.txt:1711-1712) and the previous set is this
// design's choice, so a packet delayed across a key update still opens
// (docs/quic.md, "The decision"). A CH_QUIC_KEY_NEXT result is a
// peer-initiated key update (rfc9001.txt:1654-1656). Every read of the
// array uses one of the three names; no index is computed, and no index
// comes from a secret.
#define CH_QUIC_KEY_SETS 3
#define CH_QUIC_KEY_PREVIOUS 0
#define CH_QUIC_KEY_CURRENT 1
#define CH_QUIC_KEY_NEXT 2

#if defined(CH_TRANSPORT_QUIC_NONBLOCKING) || defined(CH_SUITE_AES_GCM)
#define AES_BLOCK 16   // FIPS 197 block size
#define AES_128_KEY 16 // the key size of every public key, and of AES-128 suites
#define AES_256_KEY 32 // FIPS 197 Table 3, Nk = 8 words
#define GCM_TAG 16     // the 128-bit authentication tag, the only length used
#endif

// The tag of every AEAD here, ChaCha20-Poly1305 (RFC 8439 §2.5) and
// AES-GCM alike.
#define AEAD_TAG 16

// A TLS record's header, and what record protection adds to a record's
// plaintext: the header, the inner content type and the tag (RFC 9846
// §5.2).
#define REC_HDR 5
#define REC_OVERHEAD (REC_HDR + 1 + AEAD_TAG)

// 2^24.5 full-size records under one set of keys (rfc9846.txt:3750-3753).
// This is 2^24, the largest power of two at or below that figure, and it
// counts every record under the key, whatever its size. So an AES-GCM
// write key seals at sequence numbers 0 to REC_AES_GCM_RECORDS_MAX - 1 and
// at none above: rec_seal refuses one at or above REC_AES_GCM_RECORDS_MAX,
// and ch_write (tls_write.c) sends the KeyUpdate that retires the key at
// its last sequence number, REC_AES_GCM_RECORDS_MAX - 1. ChaCha20-Poly1305
// has no such limit: its sequence number would wrap first
// (rfc9846.txt:3752-3754), and rec_seal's wrap guard stops it there. Only
// a -DCH_SUITE_AES_GCM build runs AES-GCM, and every TCP build defines the
// number because tls.h's ch_writable_len counts in it.
#define REC_AES_GCM_RECORDS_MAX 16777216

// The largest ClientHello, or ServerHello, this build writes: the hello
// half of the TX staging array (session.h, docs/decisions.md 22 and 71).
// The values are CH_HELLO_MAX's per build, repeated as literals because
// handshake_message.h is an internal header; handshake.c and quic.c
// assert the two agree, so a stale literal fails the build.
#if defined(CH_SUITE_AES_GCM) && defined(CH_TRUST_WEBPKI)
#define CH_TX_AES_SUITES (4 + 16)
#else
#define CH_TX_AES_SUITES 0
#endif
// A server role stages its ServerHello in the same array, in the clear, so the array holds
// the largest one (SRV_SERVER_HELLO_MAX, which srv_flight.h asserts equal): 1664 bytes with
// the 1568-byte ML-KEM-1024 ciphertext, which every server can select (docs/decisions.md 162
// and 179). It raises the classic raw and ca values below.
#define CH_TX_SERVER_HELLO 1664
#ifdef CH_TRANSPORT_QUIC_NONBLOCKING
// A QUIC hello differs from the TCP one by three extensions. It drops
// the 6-byte record_size_limit, because RFC 9001 §4.1.3 removes the
// record layer that extension sizes (rfc9001.txt:462-464). It adds
// quic_transport_parameters, 4 framing bytes over a body of at most
// CH_TRANSPORT_PARAMS_MAX (§8.2). And it adds the 270-byte ALPN offer
// in every trust mode, because §8.1 makes ALPN mandatory there
// (rfc9001.txt:1891-1895), where a TCP device build sends none. So each
// value is the TCP one plus 254, and plus 270 again in the two device
// modes. These are CH_HELLO_MAX's QUIC values, repeated as literals for
// the reason the TCP ones are, and quic.c asserts the two agree. The
// webpki one carries the 23 bytes of CH_HELLO_CERT_PATH_MAX, as the TCP
// one does: the builder is the same, and ch_quic_init takes SPKI pins, so
// the 7-byte server_certificate_type offer goes out over QUIC too
// (docs/decisions.md 64). It takes CH_TX_AES_SUITES on top, as the TCP
// webpki value does.
#ifdef CH_TRUST_WEBPKI
#define CH_TX_HELLO (2650 + CH_TX_AES_SUITES)
#elif defined(CH_PROFILE_CNSA2) && !defined(CH_ROLE_SERVER)
#define CH_TX_HELLO 2698
#elif defined(CH_KEX_PQ)
#define CH_TX_HELLO 2325
#elif defined(CH_ROLE_SERVER)
#define CH_TX_HELLO CH_TX_SERVER_HELLO
#else
#define CH_TX_HELLO 1141
#endif
#elif defined(CH_TRUST_WEBPKI)
// The TRUST=webpki value takes CH_TX_AES_SUITES on top: 20 bytes for a
// SUITE=aesgcm webpki client (CH_CLIENT_AES_SUITES in suite.h), 0 in
// every other build. That client lists two more cipher suites, 4 bytes,
// and a ticket from a TLS_AES_256_GCM_SHA384 session carries a SHA-384
// binder, 16 bytes longer than the SHA-256 one the sum below counts.
// The pq sum below plus the two extensions a TRUST=webpki hello adds:
// the 262-byte server_name at the longest hostname (4 type and length,
// 2 list length, 1 name_type, 2 name length, 253 name) and the 270-byte
// application_layer_protocol_negotiation at the longest offer (4 type
// and length, 2 list length, then 8 names of 1 length byte and 32 name
// bytes). Then the second group every webpki hello offers beside the
// hybrid (docs/decisions.md 53): x25519 in supported_groups, 2 bytes,
// and its KeyShareEntry, 36 bytes. Then secp256r1 in supported_groups, 2
// bytes, which the first hello lists with no share (docs/decisions.md
// 63); the retry hello that carries its share is shorter than this one.
// Then the certificate path every webpki hello offers, a resuming one
// included (docs/decisions.md 55): the 16-byte signature_algorithms of
// five schemes and the 7-byte server_certificate_type of a config with
// SPKI pins and anchors: 1801 + 262 + 270 + 2 + 36 + 2 + 16 + 7.
#define CH_TX_HELLO (2396 + CH_TX_AES_SUITES)
#elif defined(CH_PROFILE_CNSA2) && !defined(CH_ROLE_SERVER) // pq sum, 1568 key, 133 cookie
#define CH_TX_HELLO 2174
#elif defined(CH_KEX_PQ)
// 137 fixed + 320 ticket identity + 128 cookie with framing + the
// 1216-byte hybrid share.
#define CH_TX_HELLO 1801
#elif defined(CH_ROLE_SERVER)
#define CH_TX_HELLO CH_TX_SERVER_HELLO
#else
// The same sum with a 32-byte x25519 share: 617. Above the 529 a sealed record
// needs, which is why a maximum ticket identity plus a maximum retry cookie
// used to fail closed with CH_ECAP
// (https://github.com/c4milo/chapulin/issues/46).
#define CH_TX_HELLO 617
#endif

#ifndef CH_TRANSPORT_QUIC_NONBLOCKING
// The most KeyUpdates one run holds. A run is the KeyUpdates a connected
// TCP session reads with no record of application data of one byte or
// more between them. ch_read refuses the next KeyUpdate of a full run
// with unexpected_message and CH_KEY_UPDATE_LIMIT (result.h), before it
// rekeys. Every build holds 16, and no define changes it: the build
// record holds the value (build.h), and docs/decisions.md 138 states why
// 16. tls.c requires it below CH_QUIET_CAP, and tls.h states which of the
// two limits one ch_read meets first. A TRANSPORT=quic-nonblocking build
// reads no TLS KeyUpdate.
#define CH_KEY_UPDATE_RUN_MAX 16
#endif

// The three cipher suites (RFC 9846 Appendix B.4).
#define SUITE_CHACHA20_POLY1305_SHA256 0x1303
// TLS_AES_128_GCM_SHA256, which RFC 9846 section 9.1 makes mandatory to
// implement, and TLS_AES_256_GCM_SHA384, which it makes a SHOULD
// (rfc9846.txt:4540-4543). Only a -DCH_SUITE_AES_GCM build offers or
// selects either.
#define SUITE_AES_128_GCM_SHA256 0x1301
#define SUITE_AES_256_GCM_SHA384 0x1302

// The names a caller writes in ch_cfg.cipher_suites and ch_srv_cfg.cipher_suites, and compares
// ch_tls.suite with: the names RFC 9846 Appendix B.4 gives the three suites, with the CH_
// prefix of every public name. The SUITE_ names above are the ones this tree's sources use.
#define CH_TLS_CHACHA20_POLY1305_SHA256 SUITE_CHACHA20_POLY1305_SHA256
#define CH_TLS_AES_128_GCM_SHA256 SUITE_AES_128_GCM_SHA256
#define CH_TLS_AES_256_GCM_SHA384 SUITE_AES_256_GCM_SHA384

#endif
