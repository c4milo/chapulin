// The PEM files an operator holds, decoded for a configuration
// (https://github.com/c4milo/chapulin/issues/192). A server's
// certificate chain and its P-256 private key decode into what
// srv_cfg.h's ch_identity takes. A client's CA bundle decodes into what
// ch_cfg.anchors takes (webpki_cfg.h). colibri's tls module calls these
// calls through the Zig API (docs/zig.md), and it parses no PEM and no
// key structure of its own.
//
// No call does I/O. Each reads octets that the caller has read, writes
// into rooms that the caller places, and keeps no pointer once it
// returns. Each returns CH_OK or CH_EINVAL and nothing else. A call
// refuses a file whole, and the caller answers every refusal with a
// report of the file.
//
// The caller sizes each room: the DER room by its length in bytes, and
// the array of entries by its count. A call fills each room up to its
// size, and refuses a file that does not fit. It does not cut the file
// short. No cap of this tree bounds a bundle. A chain holds at most 255
// certificates (below). Base64 spells 3 bytes in 4 characters, so the DER
// of a file is at most three quarters of its text. A DER room of
// pem_len / 4 * 3 bytes holds the DER of any file.
//
// A FILE THAT DECODES IS NOT AUTHENTICATED. No call reads a signature, a
// date or a name, and a file that decodes proves nothing about who wrote
// it. The files are trusted because the operator placed them, as pem.h
// says of every block.
//
// Which objects define the calls decides which builds declare them
// (INV-36). Every object with a server role, ROLE=server and ROLE=both,
// defines the chain and the key calls. Every TRUST=webpki object, client
// or ROLE=both, defines the bundle call. colibri's ROLE=both TRUST=webpki
// object has all three. Every call names the object's transport in its
// symbol, as ch_srv_check does (docs/decisions.md 61), because one image
// links one object of each transport. Under the define of the objects
// that define it, the name of each call maps to its symbol, as its
// declaration does.
//
// docs/decisions.md 131 states why these calls exist and where each
// file's grammar ends.
#ifndef CH_PEM_FILES_H
#define CH_PEM_FILES_H

#include <stddef.h>
#include <stdint.h>

#include "cfg.h"
#include "pem.h"

#ifdef CH_ROLE_SERVER
#ifdef CH_TRANSPORT_QUIC_NONBLOCKING
#define ch_chain_from_pem ch_chain_from_pem_quic_nonblocking
#define ch_p256_key_from_pem ch_p256_key_from_pem_quic_nonblocking
#elif defined(CH_TRANSPORT_TCP_NONBLOCKING)
#define ch_chain_from_pem ch_chain_from_pem_tcp_nonblocking
#define ch_p256_key_from_pem ch_p256_key_from_pem_tcp_nonblocking
#else
#define ch_chain_from_pem ch_chain_from_pem_tcp_blocking
#define ch_p256_key_from_pem ch_p256_key_from_pem_tcp_blocking
#endif

// Decodes a certificate chain: one or more CERTIFICATE blocks,
// end-entity first, in the file's order. The file is strict, as
// pem_decode_certificate's is. The first BEGIN line starts at the first
// byte. Outside the blocks lie CR and LF alone, and an LF comes before
// each next BEGIN line (pem_blocks.h).
//
// Writes each certificate's DER into der, der_len bytes, one certificate
// after another, and points chain[i] at it. chain holds chain_max
// entries. Then chain and *chain_count are what ch_identity's chain and
// chain_count take. der must outlive every session that uses the chain,
// as every pointer in ch_cfg must.
//
// A chain holds at most 255 certificates, because ch_identity's
// chain_count is a uint8_t. A server sends at most that many, so 255 is
// the one bound the call adds to the caller's rooms.
//
// It judges no certificate: it reads no signature, date, name or key.
// Each block must read as a certificate's outer fields, the fields that
// x509_pem_read_subject_key reads. So the call refuses a block of DER
// that is not a certificate, and the clients do not have to.
// ch_p256_key_from_pem reads the leaf's key.
//
// Returns CH_OK with *chain_count 1 to 255. Returns CH_EINVAL with
// *chain_count 0 for:
//  - DER over der_len bytes in all;
//  - more blocks than chain_max, or more than 255;
//  - no block;
//  - text that the grammar refuses;
//  - a block whose outer fields do not read.
// der and chain then hold unspecified bytes. Certificates are public, so
// the call wipes nothing.
int CH_MUST_USE ch_chain_from_pem(const uint8_t *pem, size_t pem_len, uint8_t *der, size_t der_len,
                                  ch_cert *chain, size_t chain_max, uint8_t *chain_count);

// Decodes a P-256 private key. The file holds one PRIVATE KEY block, a
// PKCS #8 PrivateKeyInfo (RFC 5958), or one EC PRIVATE KEY block, a SEC 1
// ECPrivateKey (RFC 5915). One EC PARAMETERS block may come before an EC
// PRIVATE KEY block, as `openssl ecparam -genkey` writes it. That block
// must name prime256v1 (x509_pem_parameters_are_p256). Outside the
// blocks lie CR and LF alone, and an LF comes before the key's BEGIN
// line. pem_len is at most CH_PEM_KEY_TEXT_MAX (pem.h). x509_pem.h
// states each form's fields.
//
// cpu describes the CPU, as ch_cfg.cpu does in a host object (cpu_cfg.h).
// The call takes the value that the caller's sessions take. As every init
// call does, it refuses a value without CH_CPU_PROBED or with a bit that
// the object does not define (cpu.h). A device object defines no bit and
// holds one multiply. So there cpu is 0, and the call refuses any other
// value.
//
// Writes the private scalar, 32 big-endian bytes, to priv, and its
// public point X||Y, 64 bytes, to pub. These are what ch_identity's
// ecdsa_p256 slot takes as priv and pub (srv_cfg.h). The call computes
// the point from the scalar in constant time (p256_ecdh.h), also when the
// file carries a point. Under CH_CPU_CONSTANT_TIME_MULTIPLY a host object
// computes it on the wide P-256 field, as p256_sign_cpu signs. Without
// that bit it computes it on ct.h's 16x16 decomposition (widemul.h).
//
// leaf is the end-entity certificate's DER, chain[0] from
// ch_chain_from_pem. Its subjectPublicKeyInfo must be P-256's with the
// point pub, byte for byte. So the call refuses a key that is not the
// certificate's, and the clients do not have to.
//
// Returns CH_OK. Returns CH_EINVAL, with priv and pub zeroed, for:
//  - a cpu value that the object refuses;
//  - a pem_len over the cap;
//  - a block of any other label, ENCRYPTED PRIVATE KEY among them, since
//    this tree holds no password;
//  - an EC PARAMETERS block that names another curve or holds other DER;
//  - a second EC PARAMETERS block, or one before a PRIVATE KEY block;
//  - a form or a field that the grammar refuses;
//  - a curve other than P-256;
//  - a scalar outside 1 to n - 1;
//  - a publicKey field whose point is not the scalar's;
//  - a leaf that is not a certificate, or whose key is not that point.
//
// The scalar is a secret. Before the call returns, on every path, it
// wipes every copy it makes: the decoded DER, the base64 accumulator and
// its copies of the scalar. Two copies are the caller's. One is priv,
// which ch_identity points at and which chapulin never copies
// (srv_cfg.h). The other is the text in pem, which the caller wipes once
// this returns.
int CH_MUST_USE ch_p256_key_from_pem(uint32_t cpu, const uint8_t *pem, size_t pem_len,
                                     const uint8_t *leaf, size_t leaf_len, uint8_t priv[32],
                                     uint8_t pub[64]);
#endif

#ifdef CH_TRUST_WEBPKI
#ifdef CH_TRANSPORT_QUIC_NONBLOCKING
#define ch_anchors_from_pem ch_anchors_from_pem_quic_nonblocking
#elif defined(CH_TRANSPORT_TCP_NONBLOCKING)
#define ch_anchors_from_pem ch_anchors_from_pem_tcp_nonblocking
#else
#define ch_anchors_from_pem ch_anchors_from_pem_tcp_blocking
#endif

// Decodes a CA bundle: one or more CERTIFICATE blocks. A BEGIN line is a
// line that starts with "-----BEGIN ", the first 11 bytes of RFC 7468's
// pre-encapsulation boundary, whatever follows them (pem_blocks.h).
//  - A BEGIN line opens a block. The call reads it if it is
//    "-----BEGIN CERTIFICATE-----" and refuses the file if not. So a block
//    under another label, such as OpenSSL's TRUSTED CERTIFICATE or the
//    legacy X509 CERTIFICATE, refuses the file.
//  - "-----BEGIN " at any other byte of a line refuses the file: behind a
//    byte-order mark, an indent or a comment's text.
//  - Every other line is text, and the call skips it, before, between
//    and after the blocks. So the name and '=' lines that curl's
//    cacert.pem carries above each root read. A comment that holds
//    "-----BEGIN" with no space after it is text too.
//  - Each block's END line ends its line.
// So the call reads every block that opens at a BEGIN line, or it
// refuses the file. The 11 bytes must match byte for byte. A line that
// differs inside them is not a BEGIN line, for example "-----begin " or a
// tab after BEGIN. The call skips that line as text, and the block's body
// and END line too. So the call reads the file without that root.
// OpenSSL and LibreSSL read no root from such a block either.
//
// Writes each certificate's DER into der, der_len bytes, one certificate
// after another. Points anchors[i].name and anchors[i].spki at the
// certificate's subject Name and its SubjectPublicKeyInfo, each the whole
// DER TLV. anchors holds anchor_max entries. Then anchors and
// *anchor_count are what ch_cfg.anchors and anchor_count take, which no
// cap bounds (webpki_cfg.h). der must outlive every session that uses the
// anchors.
//
// It takes each root and judges nothing: it reads no signature, date,
// extension or key algorithm, only the outer fields that
// x509_pem_read_subject_key states. A root whose key the chain walk
// cannot use verifies no chain (docs/webpki.md, "Trust anchors").
//
// Returns CH_OK with *anchor_count 1 to anchor_max. Returns CH_EINVAL
// with *anchor_count 0 for:
//  - DER over der_len bytes in all;
//  - more blocks than anchor_max;
//  - no block;
//  - text or a block that the grammar refuses;
//  - a certificate whose outer fields do not read.
// der and anchors then hold unspecified bytes.
int CH_MUST_USE ch_anchors_from_pem(const uint8_t *pem, size_t pem_len, uint8_t *der,
                                    size_t der_len, ch_trust_anchor *anchors, size_t anchor_max,
                                    size_t *anchor_count);
#endif

#endif
