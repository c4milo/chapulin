// The server's own authentication flight: which provisioned identity
// signs a CertificateVerify, what that signature covers, and the
// boot-time check that a provisioned key pair works. srv_auth.h states
// the contract each function below meets and the reasons behind it.
//
// Two signers this file needs are not in this tree: p256_sign.c for
// SIGALG_ECDSA_P256_SHA256 and rsa_sign.c for
// SIGALG_RSA_PSS_RSAE_SHA256. So srv_sign_certificate_verify and
// srv_identity_check refuse, and neither ever reports success. Each
// states at its refusal what the commit that lands a signer replaces.
//
// Everything that does not need a signer is implemented: the two slot
// predicates, the signed content of RFC 9846 section 4.4.3, the SHA-256
// over that content, and the two refusals srv_auth.h documents for
// srv_sign_certificate_verify.
//
// No line here reads a byte of ch_identity.priv. That encoding belongs
// to the signing lane and this file invents none.
#include "srv_auth.h"

#ifdef CH_ROLE_SERVER

#include <string.h>

#include "ch_assert.h"
#include "ct.h"
#include "handshake_message.h"

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

// The largest DER ECDSA-Sig-Value over P-256, in bytes: the SEQUENCE
// header and two INTEGERs of at most 33 bytes each. srv_auth.h states
// the same 72.
#define SRV_SIG_MAX_ECDSA_P256 72

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

// The largest signature the named scheme can produce, in bytes. An
// RSA-PSS signature is exactly as long as the modulus, a length only the
// signer knows, so the answer for that scheme is the build's ceiling.
static size_t signature_bound(uint16_t sigalg) {
    if (sigalg == SIGALG_ECDSA_P256_SHA256) {
        return SRV_SIG_MAX_ECDSA_P256;
    }
    return SRV_SIG_MAX;
}

int srv_sign_certificate_verify(const ch_cfg *cfg, uint16_t sigalg, const uint8_t *transcript_hash,
                                size_t hash_len, uint8_t *sig, size_t cap, size_t *sig_len,
                                uint8_t *alert) {
    const ch_identity *id = srv_identity_for(cfg, sigalg);
    if (id == NULL) {
        *alert = ALERT_INTERNAL_ERROR;
        return CH_EINVAL;
    }
    // srv_auth.h refuses a cap below the signature this identity
    // produces. Only the signer knows that length, so until a signer
    // lands the test is against the largest the scheme can produce: it
    // refuses more caps than the contract does and never fewer. Callers
    // pass SRV_SIG_MAX, which clears both readings.
    if (cap < signature_bound(sigalg)) {
        *alert = ALERT_INTERNAL_ERROR;
        return CH_ECAP;
    }

    uint8_t digest[SHA256_LEN];
    srv_hash_signed_content(sigalg, transcript_hash, hash_len, digest);
    ct_wipe(digest, sizeof digest);

    // The digest is built and there is nothing in this tree to sign it
    // with: p256_sign.c and rsa_sign.c do not exist, and srv_auth.h
    // leaves the encoding of ch_identity.priv to whichever lands first,
    // so no line here reads a byte of it. The refusal clears the
    // staging buffer and reports a zero length, so a caller that
    // ignored the return value would write zeros into a
    // CertificateVerify rather than whatever that array held. The alert
    // is the one srv_auth.h names: a server that cannot sign with a key
    // it selected has a local fault. The commit that lands a signer
    // replaces these four lines with its call.
    memset(sig, 0, cap);
    *sig_len = 0;
    *alert = ALERT_INTERNAL_ERROR;
    return CH_EINVAL;
}

int srv_identity_check(const ch_cfg *cfg, uint16_t sigalg) {
    if (srv_identity_for(cfg, sigalg) == NULL) {
        return CH_EINVAL;
    }
    // The slot is provisioned, and the check srv_auth.h describes signs
    // a fixed message with it and verifies the result. No signer exists
    // in this tree, so there is no signature to hand a verifier and the
    // check cannot pass; srv_auth.h makes a signer that refused
    // CH_EINVAL, which is this. The verifier each scheme names,
    // p256_ecdsa_verify for ecdsa_secp256r1_sha256 and rsa_pss_verify
    // for rsa_pss_rsae_sha256, is already in a ROLE=server object, so
    // the commit that lands a signer adds the two calls here and
    // nothing else.
    return CH_EINVAL;
}

#endif // CH_ROLE_SERVER
