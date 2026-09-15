// RSASSA-PKCS1-v1_5 differential section (RFC 8017 §8.2): the Lean spec
// mints a signature (rsa_pkcs1_sign) over a random digest with the same
// fixed test keypairs diff_rsa.h holds, and the C verifier must accept
// it, reject a copy with one mutated digest byte, and reject three
// one-byte signature flips (last byte, padding region, top byte).
// The spec's own verifier is cross-checked on the same inputs, so the
// section still exercises the oracle before rsa_pkcs1.[ch] land. The C
// side only ever verifies; the private exponent stays on the spec side.
//
// v1.5 is a certificate-chain signature, never a CertificateVerify one
// (RFC 9846 §4.4.3 forbids rsa_pkcs1_* there), and a public chain
// carries both sha256WithRSAEncryption and sha384WithRSAEncryption. So
// the rows alternate the digest length, 32 and 48, beside the modulus,
// 2048 and 3072 bits; the digest length alone selects the DigestInfo.
//
// The signature crosses the pipe as raw k-octet hex, as in diff_rsa.h.
// Included by test/diff_test.c after diff_driver.h and diff_rsa.h
// (single translation unit): the keys and DIFF_RSA_E come from there.
//
// spec/Main.lean must serve two ops, shaped like rsa_sign and rsa_verify
// without a salt; the digest length, 32 or 48, selects the DigestInfo:
//   rsa_pkcs1_sign <n-hex> <d-hex> <e> <digest-hex>      -> signature hex
//   rsa_pkcs1_verify <n-hex> <e> <digest-hex> <sig-hex>  -> "1" or "0"
#ifndef CH_DIFFRSAPKCS1_H
#define CH_DIFFRSAPKCS1_H

#ifdef __has_include
#if __has_include("rsa_pkcs1.h")
#include "rsa_pkcs1.h"
#define DIFF_HAVE_RSA_PKCS1 1
#endif
#endif

// Digest sizes the section alternates between.
#define DIFF_PKCS1_SHA256_LEN 32
#define DIFF_PKCS1_SHA384_LEN 48
// Largest modulus the section signs under, in bytes (RSA-3072).
#define DIFF_PKCS1_N_MAX 384
// The DigestInfo prefix before the digest octets is 19 bytes for both
// SHA-256 and SHA-384 (RFC 8017 §9.2 note 1), so T = 19 + digest_len.
#define DIFF_PKCS1_DIGESTINFO_PREFIX_LEN 19

#ifdef DIFF_HAVE_RSA_PKCS1
// Runs the C verifier over one minted row: accept the good signature,
// reject the mutated digest, and reject three one-byte signature flips.
static void diff_rsa_pkcs1_check_c(const char *n_hex, size_t n_len, const uint8_t *digest,
                                   const uint8_t *bad, size_t digest_len, const char *sig_hex,
                                   size_t sig_len, const char *digest_hex) {
    uint8_t n[DIFF_PKCS1_N_MAX];
    uint8_t sig[DIFF_PKCS1_N_MAX];
    if (n_len > sizeof n || !hex_decode(n, n_hex, n_len) || !hex_decode(sig, sig_hex, sig_len)) {
        die("rsa_pkcs1: malformed key or signature");
    }
    if (rsa_pkcs1_verify(n, n_len, digest, digest_len, sig, sig_len) != 1) {
        (void)fprintf(stderr, "diff mismatch: C rsa_pkcs1_verify rejected\n  h: %s\n", digest_hex);
        exit(1);
    }
    if (rsa_pkcs1_verify(n, n_len, bad, digest_len, sig, sig_len) != 0) {
        (void)fprintf(stderr,
                      "diff mismatch: C rsa_pkcs1_verify accepted a mutated digest\n  h: %s\n",
                      digest_hex);
        exit(1);
    }

    // A one-byte signature flip must be rejected too. The mutated
    // digest above only exercises the final compare; a signature flip
    // scrambles the whole recovered EM through RSAVP1, so these
    // exercise the earlier reject branches (the s >= n gate, the two
    // leading bytes, the 0xff walk, the 0x00 separator, the DigestInfo
    // prefix) instead. EM is 0x00 || 0x01 || PS || 0x00 || T, so PS
    // spans bytes 2 to n_len - t_len - 2. Flip at the last byte,
    // inside PS, and at the top byte.
    size_t t_len = DIFF_PKCS1_DIGESTINFO_PREFIX_LEN + digest_len;
    size_t flip[3];
    flip[0] = sig_len - 1;
    flip[1] = 2 + rng_below(n_len - t_len - 3);
    flip[2] = 0;
    for (size_t j = 0; j < 3; j++) {
        uint8_t bad_sig[DIFF_PKCS1_N_MAX];
        memcpy(bad_sig, sig, sig_len);
        bad_sig[flip[j]] ^= (uint8_t)(1 + rng_below(255));
        if (rsa_pkcs1_verify(n, n_len, digest, digest_len, bad_sig, sig_len) != 0) {
            (void)fprintf(stderr,
                          "diff mismatch: C rsa_pkcs1_verify accepted a mutated signature\n"
                          "  flipped byte: %zu\n  h: %s\n",
                          flip[j], digest_hex);
            exit(1);
        }
    }
    comparisons += 5;
}
#endif

static void diff_rsa_pkcs1(void) {
#ifndef DIFF_HAVE_RSA_PKCS1
    (void)fprintf(stderr, "diff: rsa_pkcs1: spec-only pass, rsa_pkcs1.h not present yet\n");
#endif
    for (int i = 0; i < 40; i++) {
        // Alternate the two moduli on bit 0 and the two digest lengths
        // on bit 1, so every pairing runs ten rows.
        const char *n_hex = (i & 1) ? diff_rsa_n3072 : diff_rsa_n2048;
        const char *d_hex = (i & 1) ? diff_rsa_d3072 : diff_rsa_d2048;
        size_t n_len = strlen(n_hex) / 2;
        size_t digest_len = (i & 2) ? DIFF_PKCS1_SHA384_LEN : DIFF_PKCS1_SHA256_LEN;

        uint8_t digest[DIFF_PKCS1_SHA384_LEN];
        rng_fill(digest, digest_len);
        char digest_hex[2 * DIFF_PKCS1_SHA384_LEN + 1];
        (void)hex_encode(digest_hex, digest, digest_len);

        // The spec signs the digest; the reply is the raw k-octet
        // signature as hex.
        char cmd[2048];
        (void)snprintf(cmd, sizeof cmd, "rsa_pkcs1_sign %s %s %d %s", n_hex, d_hex, DIFF_RSA_E,
                       digest_hex);
        char sig_hex[1024];
        query(cmd, sig_hex, sizeof sig_hex);
        size_t sig_len = strlen(sig_hex) / 2;
        if (sig_len != n_len || strlen(sig_hex) % 2 != 0) {
            die("rsa_pkcs1_sign: malformed spec response");
        }

        // A one-byte flip of the digest must be rejected everywhere.
        uint8_t bad[DIFF_PKCS1_SHA384_LEN];
        memcpy(bad, digest, digest_len);
        bad[rng_below(digest_len)] ^= (uint8_t)(1 + rng_below(255));
        char bad_hex[2 * DIFF_PKCS1_SHA384_LEN + 1];
        (void)hex_encode(bad_hex, bad, digest_len);

        // Cross-check the spec's own verifier on the minted signature.
        (void)snprintf(cmd, sizeof cmd, "rsa_pkcs1_verify %s %d %s %s", n_hex, DIFF_RSA_E,
                       digest_hex, sig_hex);
        expect(cmd, "1");
        (void)snprintf(cmd, sizeof cmd, "rsa_pkcs1_verify %s %d %s %s", n_hex, DIFF_RSA_E, bad_hex,
                       sig_hex);
        expect(cmd, "0");

#ifdef DIFF_HAVE_RSA_PKCS1
        diff_rsa_pkcs1_check_c(n_hex, n_len, digest, bad, digest_len, sig_hex, sig_len, digest_hex);
#endif
    }
}

#endif
