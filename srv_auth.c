// The server's own authentication flight: which provisioned identity
// signs a CertificateVerify, what that signature covers, and the
// boot-time check that a provisioned key pair works. srv_auth.h states
// the contract each function below meets and the reasons behind it.
//
// Two signers do the arithmetic and this file calls one of them per
// scheme: p256_sign for SIGALG_ECDSA_P256_SHA256 and rsa_pss_sign for
// SIGALG_RSA_PSS_RSAE_SHA256. The boot-time check calls the matching
// verifier, p256_ecdsa_verify or rsa_pss_verify, which a ROLE=server
// object already carries.
//
// No line here reads a byte behind ch_identity.priv. This file tests
// priv_len against the size of the type the scheme's signer declares
// and hands the pointer on, so the private key is read inside
// p256_sign.c and rsa_sign.c and nowhere else.
#include "srv_auth.h"

#ifdef CH_ROLE_SERVER

#include <string.h>

#include "ch_assert.h"
#include "ct.h"
#include "handshake_message.h"
#include "p256.h"
#include "p256_sign.h"
#include "rsa_sign.h"

// The 64 bytes of 0x20 that RFC 9846 section 4.4.3 puts in front of the
// signed content.
#define SRV_SIGNED_PAD_LEN 64

// The context string of a server's CertificateVerify. Every copy below
// writes sizeof this array, which carries the terminating NUL, and that
// NUL is the single separator byte section 4.4.3 puts after the string.
static const char srv_cv_context[] = "TLS 1.3, server CertificateVerify";

// The largest signed content this build assembles, in bytes: the
// padding, the context string with its separator, and the longest
// transcript hash any cipher suite names (SRV_COOKIE_HASH_MAX).
#define SRV_SIGNED_CONTENT_MAX (SRV_SIGNED_PAD_LEN + sizeof srv_cv_context + SRV_COOKIE_HASH_MAX)

// The bytes each scheme's key pointers name. The ECDSA private scalar
// is P256_PRIV_LEN (p256_sign.h) and its public point is the 64-byte
// X||Y p256_ecdsa_verify reads (p256.h). The RSA private key is one
// ch_rsa_priv (rsa_sign.h) and its public modulus is pub_len bytes,
// whose range rsa_pss_verify checks itself.
#define SRV_P256_PUB_LEN 64

// True when the caller provisioned this slot: a chain holding at least
// one entry and both key pointers set. It reads no byte of either key
// and no byte of the chain.
static int identity_provisioned(const ch_identity *id) {
    return id->chain != NULL && id->chain_count > 0 && id->priv != NULL && id->pub != NULL;
}

uint8_t srv_identity_live(const ch_cfg *cfg) {
    uint8_t live = 0;
    if (identity_provisioned(&cfg->srv.ecdsa_p256)) {
        live |= SRV_IDENTITY_ECDSA_P256;
    }
    if (identity_provisioned(&cfg->srv.rsa_pss)) {
        live |= SRV_IDENTITY_RSA_PSS;
    }
    return live;
}

const ch_identity *srv_identity_for(const ch_cfg *cfg, uint16_t sigalg) {
    const ch_identity *id;
    if (sigalg == SIGALG_ECDSA_P256_SHA256) {
        id = &cfg->srv.ecdsa_p256;
    } else if (sigalg == SIGALG_RSA_PSS_RSAE_SHA256) {
        id = &cfg->srv.rsa_pss;
    } else {
        // Every other code point, including the RSASSA-PKCS1-v1_5 ones
        // RFC 9846 section 4.3.3 leaves undefined for signed handshake
        // messages.
        return NULL;
    }
    if (!identity_provisioned(id)) {
        return NULL;
    }
    return id;
}

void srv_hash_signed_content(uint16_t sigalg, const uint8_t *transcript_hash, size_t hash_len,
                             uint8_t out[SHA256_LEN]) {
    // The SignatureScheme names the hash run over the content, and the
    // cipher suite names the transcript hash that goes inside it. Both
    // schemes this build signs with name SHA-256, so one arm covers
    // both; a scheme naming another hash needs its own arm here and a
    // wider out. This assert catches a caller that reached here with a
    // scheme srv_identity_for never returns an identity for, which is a
    // selection bug and not peer input.
    CH_ASSERT(sigalg == SIGALG_ECDSA_P256_SHA256 || sigalg == SIGALG_RSA_PSS_RSAE_SHA256);
    CH_ASSERT(hash_len >= SHA256_LEN && hash_len <= SRV_COOKIE_HASH_MAX);

    uint8_t content[SRV_SIGNED_CONTENT_MAX];
    memset(content, 0x20, SRV_SIGNED_PAD_LEN);
    // sizeof keeps the NUL, which is the separator byte.
    memcpy(content + SRV_SIGNED_PAD_LEN, srv_cv_context, sizeof srv_cv_context);
    memcpy(content + SRV_SIGNED_PAD_LEN + sizeof srv_cv_context, transcript_hash, hash_len);

    sha256 s;
    sha256_init(&s);
    sha256_update(&s, content, SRV_SIGNED_PAD_LEN + sizeof srv_cv_context + hash_len);
    sha256_final(&s, out);

    // Both the staging array and the hash context hold the transcript
    // hash, which is derived from secrets.
    ct_wipe(content, sizeof content);
    ct_wipe(&s, sizeof s);
}

// True when the slot's two lengths are the lengths this scheme's key
// types have. It is what makes the pointers safe to pass on: p256_sign
// reads P256_PRIV_LEN bytes and p256_ecdsa_verify reads SRV_P256_PUB_LEN
// bytes whatever the slot claims, and rsa_pss_sign reads a whole
// ch_rsa_priv. The RSA modulus needs no test here, because pub_len is
// the length rsa_pss_verify takes as a parameter and checks.
static int key_lengths_match(const ch_identity *id, uint16_t sigalg) {
    if (sigalg == SIGALG_ECDSA_P256_SHA256) {
        return id->priv_len == P256_PRIV_LEN && id->pub_len == SRV_P256_PUB_LEN;
    }
    return id->priv_len == sizeof(ch_rsa_priv);
}

// The bytes this identity's signature takes, which is what cap must
// hold. An RSA-PSS signature is exactly as long as the modulus, and
// pub_len is that length, so the RSA answer is exact. A DER
// ECDSA-Sig-Value is 70, 71 or 72 bytes depending on the leading zero
// each INTEGER needs, a choice the signature values make, so the ECDSA
// answer is the longest of the three and p256_sign refuses a cap below
// what it actually writes.
static size_t signature_bound(const ch_identity *id, uint16_t sigalg) {
    if (sigalg == SIGALG_ECDSA_P256_SHA256) {
        return P256_SIG_MAX;
    }
    return id->pub_len;
}

// Signs one digest with the identity the scheme names. Returns 1 on
// success and 0 on refusal, the convention both signers use. It passes
// the private key as a pointer: the signer reads the bytes behind it
// and this file does not.
static int sign_digest(const ch_identity *id, uint16_t sigalg, const uint8_t digest[SHA256_LEN],
                       uint8_t *sig, size_t cap, size_t *sig_len) {
    if (sigalg == SIGALG_ECDSA_P256_SHA256) {
        return p256_sign(id->priv, digest, sig, cap, sig_len);
    }
    return rsa_pss_sign(id->priv, digest, sig, cap, sig_len);
}

int srv_sign_certificate_verify(const ch_cfg *cfg, uint16_t sigalg, const uint8_t *transcript_hash,
                                size_t hash_len, uint8_t *sig, size_t cap, size_t *sig_len,
                                uint8_t *alert) {
    const ch_identity *id = srv_identity_for(cfg, sigalg);
    if (id == NULL || !key_lengths_match(id, sigalg)) {
        *alert = ALERT_INTERNAL_ERROR;
        return CH_EINVAL;
    }
    if (cap < signature_bound(id, sigalg)) {
        *alert = ALERT_INTERNAL_ERROR;
        return CH_ECAP;
    }

    uint8_t digest[SHA256_LEN];
    srv_hash_signed_content(sigalg, transcript_hash, hash_len, digest);
    int signed_ok = sign_digest(id, sigalg, digest, sig, cap, sig_len);
    // The digest is the SHA-256 of a content that holds the transcript
    // hash, which is derived from secrets.
    ct_wipe(digest, sizeof digest);
    if (!signed_ok) {
        // A signer that refused may have written part of a signature
        // first, so the wipe clears whatever it left and the zero
        // length reports nothing usable. A caller that ignored the
        // return value would write zeros into a CertificateVerify
        // rather than those bytes. The alert is the one srv_auth.h
        // names: a server that cannot sign with a key it selected has a
        // local fault.
        ct_wipe(sig, cap);
        *sig_len = 0;
        *alert = ALERT_INTERNAL_ERROR;
        return CH_EINVAL;
    }
    return CH_OK;
}

// Verifies one signature under the public key in the slot, with the
// verifier the scheme names. Returns 1 when it verified and 0
// otherwise, the convention both verifiers use.
static int verify_digest(const ch_identity *id, uint16_t sigalg, const uint8_t digest[SHA256_LEN],
                         const uint8_t *sig, size_t sig_len) {
    if (sigalg == SIGALG_ECDSA_P256_SHA256) {
        return p256_ecdsa_verify(id->pub, digest, sig, sig_len);
    }
    return rsa_pss_verify(id->pub, id->pub_len, digest, sig, sig_len);
}

int srv_identity_check(const ch_cfg *cfg, uint16_t sigalg) {
    const ch_identity *id = srv_identity_for(cfg, sigalg);
    if (id == NULL || !key_lengths_match(id, sigalg)) {
        return CH_EINVAL;
    }

    // The fixed message srv_auth.h names is a transcript hash of
    // SHA256_LEN zero bytes, run through the same assembly a handshake
    // signs: 64 bytes of 0x20, the context string, the separator, and
    // then those zeros. The check signs the content a handshake signs,
    // so a pass here is evidence about the handshake.
    uint8_t transcript[SHA256_LEN];
    memset(transcript, 0, sizeof transcript);
    uint8_t digest[SHA256_LEN];
    srv_hash_signed_content(sigalg, transcript, sizeof transcript, digest);

    // Every byte in this frame is public: a constant message, its
    // digest, and a signature over it. The private key was never copied
    // here, so nothing below is wiped.
    uint8_t sig[SRV_SIG_MAX];
    size_t sig_len = 0;
    if (!sign_digest(id, sigalg, digest, sig, sizeof sig, &sig_len)) {
        return CH_EINVAL;
    }
    if (!verify_digest(id, sigalg, digest, sig, sig_len)) {
        return CH_EINVAL;
    }
    return CH_OK;
}

#endif // CH_ROLE_SERVER
