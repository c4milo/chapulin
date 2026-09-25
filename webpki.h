// Web PKI chain verification (TRUST=webpki). A server's certificate
// chain is verified against trust anchors the caller supplies, its
// validity dates against a clock the caller supplies, and the server's
// hostname against the leaf's subjectAltName. The profile, its bounds,
// the chain walk and what the mode does not check are recorded in
// docs/webpki.md; this header is that document as contracts.
//
// The mode is host-side. Seven files implement it, one concern each,
// and this header declares all of them: webpki_time.c (dates),
// webpki_name.c (hostnames), webpki_spki.c (public keys),
// webpki_sigalg.c (signature algorithms and the verify dispatch),
// webpki_ext.c (extensions), webpki_cert.c (one certificate) and
// webpki.c (the walk). The INV-5 tripwire (.semgrep/invariants.yml)
// bans calls named x509_*, asn1_* or der_* outside the certificate
// files; it does not match webpki_* calls. Everything below
// webpki_verify_chain has external linkage because the proof, fuzz
// and strictness builds call it, and no lint keeps library code
// from calling it: treat it as a module internal by convention.
#ifndef CH_WEBPKI_H
#define CH_WEBPKI_H

#include <stddef.h>
#include <stdint.h>

#include "buf.h"
#include "cfg.h"

// Bounds. Every value is a measurement or a formula over one; the
// table in docs/webpki.md names each measurement. The code enforces
// them and the proof harnesses use them as bounds, so the proved
// domain equals the accepted domain.
#define CH_WEBPKI_CERT_MAX 3072    // one CertificateEntry's certificate
#define CH_WEBPKI_CHAIN_MAX 3      // certificates the walk reads and verifies
#define CH_WEBPKI_FLIGHT_ENTRIES 4 // entries a Certificate message may carry
#define CH_WEBPKI_EXT_COUNT_MAX 16 // extensions in one certificate
#define CH_WEBPKI_EXT_TLV_MAX 1024 // one Extension TLV
#define CH_WEBPKI_SERIAL_MAX 20    // serialNumber value bytes (RFC 5280 §4.1.2.2)
#define CH_WEBPKI_KEY_MAX 512      // the leaf key copied out: an RSA-4096 modulus
#define CH_HOSTNAME_MAX 253        // DNS's own limit on a name
// The largest SubjectPublicKeyInfo webpki_read_spki accepts, an RSA-4096
// key's: a SEQUENCE header, rsaEncryption's 15-byte AlgorithmIdentifier,
// a BIT STRING header and its unused-bits octet, the RSAPublicKey and
// INTEGER headers, the pad octet, the 512-byte modulus and the 5-byte
// exponent, 4 + 15 + 4 + 1 + 4 + 4 + 1 + 512 + 5. It bounds the one
// entry of an RFC 7250 raw public key (webpki_pin.h).
#define CH_WEBPKI_SPKI_MAX 550

// Public-key algorithm of a decoded SubjectPublicKeyInfo.
#define WEBPKI_KEY_RSA 1  // rsaEncryption, exponent 65537
#define WEBPKI_KEY_P256 2 // id-ecPublicKey, prime256v1
#define WEBPKI_KEY_P384 3 // id-ecPublicKey, secp384r1

// A decoded public key: a pointer into the caller's buffer, valid
// until that buffer is reused. RSA: the modulus value bytes, 256 to
// CH_RSA_MODULUS_MAX in steps of 8, odd. P-256: X||Y, 64 bytes.
// P-384: X||Y, 96 bytes.
typedef struct {
    uint8_t alg;
    const uint8_t *key;
    size_t key_len;
} webpki_spki;

// Signature algorithm of a certificate, the four the mode admits.
// SHA-1, RSA-PSS and every other AlgorithmIdentifier are refused.
#define WEBPKI_SIG_RSA_SHA256 1   // sha256WithRSAEncryption, PKCS#1 v1.5
#define WEBPKI_SIG_RSA_SHA384 2   // sha384WithRSAEncryption, PKCS#1 v1.5
#define WEBPKI_SIG_ECDSA_SHA256 3 // ecdsa-with-SHA256
#define WEBPKI_SIG_ECDSA_SHA384 4 // ecdsa-with-SHA384

// Which recognized extensions a certificate carried, as bits in
// webpki_cert.seen. A duplicate of any of them is refused.
#define WEBPKI_EXT_KEY_USAGE 1
#define WEBPKI_EXT_EXT_KEY_USAGE 2
#define WEBPKI_EXT_BASIC_CONSTRAINTS 4
#define WEBPKI_EXT_SAN 8

// One parsed certificate. Every pointer points into the caller's
// buffer. tbs is the TBSCertificate content without its header: the
// signed bytes are the re-emitted header followed by tbs, which is
// what webpki_verify hashes. issuer and subject are whole Name TLVs,
// header included, because the walk and the anchors compare them byte
// for byte and never read inside them.
typedef struct {
    const uint8_t *tbs;
    size_t tbs_len;
    const uint8_t *issuer;
    size_t issuer_len;
    const uint8_t *subject;
    size_t subject_len;
    uint64_t not_before; // packed dates, see webpki_read_time
    uint64_t not_after;
    webpki_spki spki;
    // The whole SubjectPublicKeyInfo TLV spki was read from, header
    // included: the bytes an SPKI pin hashes (webpki_pin.h).
    const uint8_t *spki_tlv;
    size_t spki_tlv_len;
    uint8_t sigalg; // WEBPKI_SIG_*, equal in the TBS and the outer field
    const uint8_t *sig;
    size_t sig_len;
    const uint8_t *san; // subjectAltName extnValue, the GeneralNames TLV; NULL if absent
    size_t san_len;
    uint8_t seen;  // WEBPKI_EXT_* bits
    uint8_t is_ca; // basicConstraints cA
    int path_len;  // pathLenConstraint, -1 when absent
} webpki_cert;

// The verified leaf's key, copied out because the message buffer is
// reused before CertificateVerify arrives. alg picks the
// CertificateVerify scheme: rsa_pss_rsae_sha256 for an RSA key,
// ecdsa_secp256r1_sha256 for P-256, ecdsa_secp384r1_sha384 for P-384
// (RFC 9846 §4.3.3 binds the hash to the curve there, and only there).
//
// path_entries and anchor_index name the path webpki_verify_chain
// validated, which the SPKI pins may match anywhere on (RFC 7858 §4.2):
// the first path_entries entries of the Certificate list, the leaf
// first, then the anchor at anchor_index in ch_cfg.anchors. A raw public
// key has no path, and webpki_verify_raw_key leaves both at 0. A leaf
// pinned with no anchor is a path of the leaf alone, and
// webpki_verify_leaf_pin writes path_entries 1 and anchor_index 0.
typedef struct {
    uint8_t alg; // WEBPKI_KEY_*
    uint8_t key[CH_WEBPKI_KEY_MAX];
    size_t key_len;
    uint8_t path_entries;
    uint8_t anchor_index;
} webpki_leaf_info;

// The walk (docs/webpki.md, "The chain walk"). Reads the Certificate
// message's CertificateEntry list, verifies the leaf's profile,
// validity and hostname, then walks issuers until an anchor both names
// the issuer and verifies the signature, consulting the anchors before
// reading each next entry. Entries after the terminating certificate
// are sized by read_entries and not parsed. The caller seeds *alert
// with ALERT_BAD_CERTIFICATE; the walk overwrites it only when it
// knows better:
//   malformed DER, an entry over CH_WEBPKI_CERT_MAX, a serial over
//   CH_WEBPKI_SERIAL_MAX, more than CH_WEBPKI_EXT_COUNT_MAX extensions
//   or an Extension over CH_WEBPKI_EXT_TLV_MAX, more than
//   CH_WEBPKI_FLIGHT_ENTRIES entries             -> ALERT_BAD_CERTIFICATE, CH_EPROTO
//   a non-empty per-entry extensions vector, on
//   any entry (RFC 9846 §4.3: this client offered
//   no extension a CertificateEntry answers)     -> ALERT_UNSUPPORTED_EXTENSION, CH_EPROTO
//   a recognized off-profile fact: an algorithm or key the mode
//   refuses, an unknown critical or duplicate extension, a leaf
//   without subjectAltName, digitalSignature or serverAuth, an issuer
//   without cA or keyCertSign, a pathLenConstraint the CA certificates
//   under it exceed (RFC 5280 §6.1.4 (l): a self-issued one does not
//   count), an issuer whose subject is not this certificate's
//   issuer                                    -> ALERT_UNSUPPORTED_CERTIFICATE, CH_EPROTO
//   now_seconds outside a validity            -> ALERT_CERTIFICATE_EXPIRED, CH_EAUTH
//   no dNSName matches the hostname           -> ALERT_BAD_CERTIFICATE, CH_EAUTH
//   a signature that fails under its issuer   -> ALERT_BAD_CERTIFICATE, CH_EAUTH
//   the entries run out before an anchor
//   verifies, or CH_WEBPKI_CHAIN_MAX is reached -> ALERT_UNKNOWN_CA, CH_EAUTH
// Four fields are the exception to the first row: malformed DER in one of
// them reports ALERT_UNSUPPORTED_CERTIFICATE, because one reader answers
// one verdict for both cases. webpki_read_sigalg compares the TBS
// signature AlgorithmIdentifier against the four encodings the mode
// admits, and x509_read_exact compares the outer signatureAlgorithm
// against the TBS signature field it must equal, so a malformed field
// differs from those bytes exactly as an unadmitted one does.
// webpki_read_spki answers one 0 for a key the mode refuses and for
// malformed DER, and x509_read_keyusage one 0 for a missing keyUsage bit
// and for malformed DER. test/webpki_cert_test.c pins all four alerts.
// Returns CH_OK with out filled, or the error above. On CH_OK,
// out->path_entries is the count of certificates the walk read, 1 to
// CH_WEBPKI_CHAIN_MAX with the leaf counted, and out->anchor_index is
// the index in cfg->anchors of the first anchor whose subject Name is the
// last one's issuer Name and whose key verifies its signature.
int webpki_verify_chain(const uint8_t *list, size_t list_len, const ch_cfg *cfg,
                        webpki_leaf_info *out, uint8_t *alert);

// One CertificateEntry of RFC 9846 §4.5.1 from r: a u24 length of 1 to
// cert_max, that many bytes, and a u16 extensions vector that must be
// empty. Returns CH_OK with *cert and *cert_len naming the bytes and r
// past the entry. Otherwise CH_EPROTO, with *alert set to
// ALERT_BAD_CERTIFICATE for the framing and ALERT_UNSUPPORTED_EXTENSION
// for a non-empty extensions vector (RFC 9846 §4.3: this client offers no
// extension a CertificateEntry could answer). The walk reads each entry
// of a chain through it, and webpki_verify_raw_key the one entry of a raw
// public key. Defined in webpki.c.
int webpki_read_entry(rbuf *r, size_t cert_max, const uint8_t **cert, size_t *cert_len,
                      uint8_t *alert);

// A whole CertificateEntry list, framed as the walk frames it: 1 to
// CH_WEBPKI_FLIGHT_ENTRIES entries of 1 to CH_WEBPKI_CERT_MAX bytes, every
// extensions vector empty, filling the list exactly. Returns CH_OK with
// *leaf and *leaf_len naming entry 0, and reads no entry's content.
// Otherwise CH_EPROTO, with *alert as webpki_read_entry sets it and
// ALERT_BAD_CERTIFICATE for an empty list or one entry too many.
// webpki_verify_leaf_pin reads a chain with it (webpki_pin.h). Defined in
// webpki.c.
int webpki_read_leaf_entry(const uint8_t *list, size_t list_len, const uint8_t **leaf,
                           size_t *leaf_len, uint8_t *alert);

// One whole certificate: SEQUENCE { tbs, sigAlg, sigValue }, canonical
// DER on every field it decodes except the one KeyPurposeId case
// webpki_read_extensions names, version 3, exactly the profile arm
// is_ca names — the leaf (0) needs subjectAltName, keyUsage
// digitalSignature, extendedKeyUsage id-kp-serverAuth and
// basicConstraints absent or cA FALSE; an issuer (1) needs
// basicConstraints critical with cA TRUE and keyUsage keyCertSign.
// Unrecognized critical extensions and the issuerUniqueID and
// subjectUniqueID fields are refused. Fills out
// with pointers into cert, spki_tlv among them: the bytes
// webpki_read_spki consumed. Alert convention as webpki_verify_chain.
// Defined in webpki_cert.c.
int webpki_parse_certificate(const uint8_t *cert, size_t cert_len, int is_ca, webpki_cert *out,
                             uint8_t *alert);

// One certificate read only as far as its key: the Certificate SEQUENCE,
// of at most CH_WEBPKI_CERT_MAX bytes and filling cert, and its
// TBSCertificate's fields through subjectPublicKeyInfo, each under the
// reader webpki_parse_certificate hands it to: version 3, serialNumber,
// signature, issuer, validity, subject and subjectPublicKeyInfo. The
// dates are read for their shape and compared with no clock. The fields
// after the key are skipped as whole TLVs and never read: exactly one
// extensions [3] TLV must fill the rest of the TBSCertificate, and one
// signatureAlgorithm SEQUENCE and one signature BIT STRING the rest of
// the Certificate (INV-25). Fills out's tbs, issuer, subject, dates,
// sigalg, spki and spki_tlv, and writes no other field. Alert convention
// as webpki_verify_chain. webpki_verify_leaf_pin reads the leaf of a
// configuration with SPKI pins and no anchors with it (webpki_pin.h).
// Defined in webpki_cert.c.
int webpki_read_certificate_key(const uint8_t *cert, size_t cert_len, webpki_cert *out,
                                uint8_t *alert);

// extensions [3] EXPLICIT Extensions, required. Walks at most
// CH_WEBPKI_EXT_COUNT_MAX extensions of at most CH_WEBPKI_EXT_TLV_MAX
// bytes each, judges keyUsage, extendedKeyUsage, basicConstraints and
// subjectAltName by the arm is_ca names, records them in out->seen,
// out->is_ca, out->path_len and out->san, and refuses unknown critical
// extensions and a second copy of any of the four it judges. A second
// copy of an unknown extension is not refused. An unknown non-critical
// extension is skipped with its extnValue unread, but its Extension TLV
// is still read, so a malformed one, or an extnID over the 16 bytes
// x509_read_extension admits, refuses the certificate.
// keyUsage needs the arm's bit and admits others beside it;
// extendedKeyUsage needs id-kp-serverAuth among its purposes on the
// leaf and is not read on an issuer; a pathLenConstraint is a
// canonical INTEGER of one or two content octets, only beside cA TRUE.
// A KeyPurposeId other than id-kp-serverAuth is read for its tag and
// length alone, so a non-minimal OBJECT IDENTIFIER beside serverAuth is
// accepted; every extnID is checked for minimal sub-identifiers.
// subjectAltName is recorded and not read here: an extnValue that is
// empty or is not a GeneralNames passes this walk, and webpki_match_san
// then refuses it as a hostname that does not match. Returns CH_OK or
// CH_EPROTO with *alert as above. Defined in webpki_ext.c.
int webpki_read_extensions(rbuf *t, int is_ca, webpki_cert *out, uint8_t *alert);

// subjectPublicKeyInfo for the three admitted algorithms, each
// AlgorithmIdentifier byte-compared against its one canonical
// encoding, the RSA exponent byte-compared against 65537, the modulus
// held to rsa.h's range and oddness with exactly one 0x00 pad octet,
// the EC point to the uncompressed form. Whether the point lies on the
// curve is not checked here: p256_ecdsa_verify and p384_ecdsa_verify
// check it before any arithmetic. Returns 1, fills out and advances r
// past the SPKI, or returns 0. Defined in webpki_spki.c.
int webpki_read_spki(rbuf *r, webpki_spki *out);

// AlgorithmIdentifier TLV to WEBPKI_SIG_*, byte-compared against the
// four canonical encodings: RSA ones carry NULL parameters, ECDSA
// ones carry none (RFC 5758 §3.2). Returns 1, sets *sigalg and
// advances r past the field, or returns 0. Defined in webpki_sigalg.c.
int webpki_read_sigalg(rbuf *r, uint8_t *sigalg);

// Verifies cert's signature under signer's key: hashes the re-emitted
// TBS header and cert->tbs with the hash cert->sigalg names, then
// dispatches to rsa_pkcs1_verify, p256_ecdsa_verify or
// p384_ecdsa_verify. The digest a curve takes is fixed at its own
// length, so this is where FIPS 186-4 §6.4 happens: a 48-byte digest
// is cut to its leftmost 32 bytes for P-256, and a 32-byte digest is
// left-padded with zeros to 48 for P-384, the same integer. An RSA
// algorithm with an EC key, or the reverse, returns 0, as does a
// cert->tbs_len over CH_WEBPKI_CERT_MAX. All inputs are public;
// variable time is deliberate. Returns 1 or 0. Defined in
// webpki_sigalg.c.
int webpki_verify(const webpki_cert *cert, const webpki_spki *signer);

// Dates. A Time is UTCTime "YYMMDDHHMMSSZ" or GeneralizedTime
// "YYYYMMDDHHMMSSZ", zulu only, and RFC 5280 §4.1.2.5 fixes which:
// UTCTime through 2049 (YY 50..99 is 1950..1999, 00..49 is 2000..2049),
// GeneralizedTime from 2050. Each field is range-checked (month 1..12,
// day 1..the month's length in that year, hour 0..23, minute and
// second 0..59). The packed form is the decimal number
// YYYYMMDDHHMMSS, so two packed dates compare as integers with no
// division, and notBefore <= now <= notAfter is three of those
// compares. Returns 1 and sets *packed, or 0. Defined in
// webpki_time.c.
int webpki_read_time(rbuf *r, uint64_t *packed);

// The caller's clock, seconds since 1970-01-01T00:00:00Z, in the same
// packed form. A clock past 9999-12-31T23:59:59Z packs as that
// instant, 99991231235959 — the value RFC 5280 §4.1.2.5 gives a
// certificate with no well-defined expiration — so the packed clock
// never leaves the range webpki_read_time produces, and a later clock
// never packs lower than an earlier one. The one routine in the mode
// that divides; it runs once per connection on the caller's value,
// never on peer input. Defined in webpki_time.c.
uint64_t webpki_pack_seconds(uint64_t now_seconds);

// Hostnames. The reference name is checked for shape before anything
// is matched against it: 1..CH_HOSTNAME_MAX bytes, only [A-Za-z0-9.-],
// no empty label, no leading or trailing dot, no label over 63 bytes,
// no label that starts or ends with '-', and a last label that is not
// all digits (RFC 6066 forbids an IP literal in server_name). The
// hyphen rule is the label rule of RFC 952 as RFC 1123 §2.1 amends it:
// a label holds letters, digits and hyphens, and starts and ends with
// a letter or digit, where RFC 952 required a letter first. This check
// is the whole defence against a presented name carrying NUL or '*':
// the reference name holds neither, so a match compares equal-length
// byte ranges and a NUL in a presented name can only fail. Returns 1
// or 0. Defined in webpki_name.c.
int webpki_hostname_ok(const uint8_t *host, size_t host_len);

// Matches host against the dNSName entries of a GeneralNames TLV
// (the subjectAltName extnValue), ASCII case-insensitively. The
// content of the other eight GeneralName types is skipped unread;
// there is no fallback to the subject common name. A wildcard is the
// entire leftmost label of the presented name and matches exactly one
// label of host; a pattern with fewer than two labels after the
// wildcard matches nothing, so "*.com" matches nothing without a
// public suffix list. A partial-label wildcard matches nothing. A
// dNSName byte outside ASCII equals no byte of host, so that entry
// does not match, and the GeneralNames is not refused for it.
// The caller has checked host with webpki_hostname_ok. Returns 1 on a
// match, 0 on none or on malformed GeneralNames. Each entry's tag
// must be one of GeneralName's nine DER identifier bytes — 0xa0,
// 0x81, 0x82, 0xa3, 0xa4, 0xa5, 0x86, 0x87, 0x88 — which refuses
// every universal tag and the high-tag-number form, and its length
// must be minimal and inside the SEQUENCE. One entry that breaks
// either rule refuses the whole GeneralNames, even after a match.
// Defined in webpki_name.c.
int webpki_match_san(const uint8_t *san, size_t san_len, const uint8_t *host, size_t host_len);

// Whether cfg meets every configuration rule of this mode: the anchors,
// hostname and clock, or SPKI pins alone (webpki_cfg.h); the PSK fields
// (webpki_ticket.h); both pin slots unset; and the ALPN offer. Reads the
// caller's configuration alone. Defined in webpki_cfg.c.
int webpki_cfg_ok(const ch_cfg *cfg);

#endif
