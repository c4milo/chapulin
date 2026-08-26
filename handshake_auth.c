// Server authentication for handshake.c: the Certificate and
// CertificateVerify flight, the pinned-key and pinned-CA checks, and
// the monotonic revocation epoch. See handshake_auth.h for the two
// entry points the state machine calls.
#include "handshake_auth.h"

#include <string.h>

#include "ch_assert.h"
#include "ct.h"
#include "handshake_message.h"
#include "handshake_parser.h"
#include "handshake_record.h"
#include "session.h"

// Exactly one pinned-mode verifier is linked per build (Makefile PIN).
#ifdef CH_PIN_ECDSA
#include "p256.h"
#else
#include "rsa.h"
#endif
#ifdef CH_TRUST_CA
#include "x509.h"
#endif

// CertificateVerify: parse, rebuild the §4.5.2 signed content, and
// verify against pin slot A then B. The TRUST=ca build swaps in the
// leaf key here.
static int check_certificate_verify(handshake_state *h, const uint8_t hash[SHA256_LEN]) {
    uint8_t type = 0;
    const uint8_t *raw = NULL;
    size_t raw_len = 0;
    int rc = hsr_next_msg(h, &type, &raw, &raw_len);
    if (rc != CH_OK) {
        return rc;
    }
    if (type != HS_CERTIFICATE_VERIFY) {
        h->alert = ALERT_UNEXPECTED_MESSAGE;
        return CH_EPROTO;
    }
    const uint8_t *sig = NULL;
    size_t sig_len = 0;
    h->alert = ALERT_DECODE_ERROR;
    rc = hsp_parse_certificate_verify(raw + 4, raw_len - 4, &sig, &sig_len, &h->alert);
    if (rc != CH_OK) {
        return rc;
    }

    // Signed content per §4.5.2: 64 spaces, context string, NUL, transcript.
    static const char ctx[] = "TLS 1.3, server CertificateVerify";
    uint8_t pad[64];
    memset(pad, ' ', sizeof pad);
    sha256 s;
    sha256_init(&s);
    sha256_update(&s, pad, sizeof pad);
    sha256_update(&s, (const uint8_t *)ctx, sizeof ctx); // sizeof keeps the NUL
    sha256_update(&s, hash, SHA256_LEN);
    uint8_t signed_hash[SHA256_LEN];
    sha256_final(&s, signed_hash);

    // All inputs are public, so variable timing leaks nothing.
#ifdef CH_TRUST_CA
    // The chain's leaf key signs the handshake; the pins already
    // vouched for the chain in hsa_server_auth.
    int sig_ok;
#ifdef CH_PIN_ECDSA
    sig_ok = p256_ecdsa_verify(h->leaf.key, signed_hash, sig, sig_len);
#else
    sig_ok = rsa_pss_verify(h->leaf.key, h->leaf.key_len, signed_hash, sig, sig_len);
#endif
#else
    // Slot A, then slot B: the second attempt covers rotation.
    const uint8_t *keys[2] = {h->t->cfg.server_pubkey, h->t->cfg.server_pubkey2};
    int sig_ok = 0;
    for (int i = 0; i < 2 && !sig_ok && keys[i] != NULL; i++) {
#ifdef CH_PIN_ECDSA
        sig_ok = p256_ecdsa_verify(keys[i], signed_hash, sig, sig_len);
#else
        size_t len = i == 0 ? h->t->cfg.server_pubkey_len : h->t->cfg.server_pubkey2_len;
        sig_ok = rsa_pss_verify(keys[i], len, signed_hash, sig, sig_len);
#endif
        if (sig_ok) {
            h->t->pin_slot = (uint8_t)(i + 1);
        }
    }
#endif
    if (!sig_ok) {
        h->alert = ALERT_DECRYPT_ERROR;
        return CH_EAUTH;
    }
    sha256_update(&h->t->transcript, raw, raw_len);
    return CH_OK;
}

// Pinned-key server authentication (RFC 9846 §4.5.1 and §4.5.2): accept the
// Certificate message with minimal framing checks — its contents are
// authenticated by the signature, not by parsing — then require a
// CertificateVerify whose signature (RSA-PSS by default, ECDSA-P256 under
// CH_PIN_ECDSA) over the running transcript checks out against either
// provisioned pin slot (slot B holds the staged next key, docs/rotation.md).
#ifdef CH_TRUST_CA
// The monotonic revocation rule (docs/ca.md), a no-op until the
// caller configures the epoch callbacks. A CA-signed certificate is
// public, so anyone can replay a leaf harvested from a real server.
// Rejecting on the chain verdict alone is safe: it only fails the
// handshake closed. Raising the stored epoch is not, because that
// outlives the session, so hsa_epoch_commit raises it once the peer has
// proved it holds the leaf key. Below the stored epoch means revoked.
// A date that is not a valid epoch date, or is more than
// CH_EPOCH_BOUND steps ahead, means a bad issuance or a poisoning
// attempt.
static int epoch_check(handshake_state *h) {
    ch_tls *t = h->t;
    if (t->cfg.epoch_load == NULL) {
        return CH_OK;
    }
    // Set the status on failure too: both paths return CH_EAUTH, so
    // only epoch_status separates revoked from out of range, and
    // each needs a different response.
    t->epoch_seen = h->leaf.epoch_ok ? h->leaf.epoch : 0;
    if (!h->leaf.epoch_ok || h->leaf.epoch > t->epoch + CH_EPOCH_BOUND) {
        t->epoch_status = CH_EPOCH_UNTRUSTED;
        h->alert = ALERT_BAD_CERTIFICATE;
        return CH_EAUTH;
    }
    if (h->leaf.epoch < t->epoch) {
        t->epoch_status = CH_EPOCH_REVOKED;
        h->alert = ALERT_CERTIFICATE_REVOKED;
        return CH_EAUTH;
    }
    t->epoch_status = h->leaf.epoch > t->epoch ? CH_EPOCH_AHEAD : CH_EPOCH_MATCHED;
    return CH_OK;
}

// Raises the stored epoch. Runs only after CertificateVerify proved
// the peer holds the leaf key and Finished covered the transcript,
// so the recorded epoch came from a real server, not from a copied
// certificate. A PSK handshake never fills h->leaf, and the zeroed
// epoch_ok stops it here. Persisting is best effort: a failed store
// keeps the session and reports through epoch_store_failed, because
// the connection is authenticated either way.
void hsa_epoch_commit(handshake_state *h) {
    ch_tls *t = h->t;
    // run() calls this once, after expect_finished returned CH_OK. An
    // earlier call is a programmer error, not bad peer input: it would
    // raise state that outlives the session on a certificate anyone can
    // copy. The check sits above the early return on purpose — below
    // it, a commit that repeats the stored epoch returns without
    // running and the mistake would surface only sometimes.
    CH_ASSERT(h->server_finished_ok);
    if (t->cfg.epoch_load == NULL || !h->leaf.epoch_ok || h->leaf.epoch <= t->epoch) {
        return;
    }
    t->epoch = h->leaf.epoch;
    t->epoch_store_failed = t->cfg.epoch_store(t->cfg.epoch_io, h->leaf.epoch) != 0;
}
#endif

int hsa_server_auth(handshake_state *h) {
    uint8_t type = 0;
    const uint8_t *raw = NULL;
    size_t raw_len = 0;
    int rc = hsr_next_msg(h, &type, &raw, &raw_len);
    if (rc != CH_OK) {
        return rc;
    }
    if (type == HS_CERTIFICATE_REQUEST) {
        h->alert = ALERT_HANDSHAKE_FAILURE; // no client certificates here
        return CH_EAUTH;
    }
    if (type != HS_CERTIFICATE) {
        h->alert = ALERT_UNEXPECTED_MESSAGE;
        return CH_EPROTO;
    }
    const uint8_t *list = NULL;
    size_t list_len = 0;
    h->alert = ALERT_DECODE_ERROR;
    rc = hsp_parse_certificate(raw + 4, raw_len - 4, &list, &list_len, &h->alert);
    if (rc != CH_OK) {
        return rc;
    }
#ifdef CH_TRUST_CA
    // CA mode: the chain must verify up to a pinned CA key before
    // anything else happens; the leaf key then stands in for the
    // pins at CertificateVerify. The raw message is hashed either
    // way — the transcript covers what the server sent.
    h->alert = ALERT_BAD_CERTIFICATE;
    rc = x509_verify_leaf(list, list_len, h->t->cfg.server_pubkey, h->t->cfg.server_pubkey_len,
                          h->t->cfg.server_pubkey2, h->t->cfg.server_pubkey2_len, &h->leaf,
                          &h->alert);
    if (rc != CH_OK) {
        return rc;
    }
    h->t->pin_slot = h->leaf.ca_slot;
    rc = epoch_check(h);
    if (rc != CH_OK) {
        return rc;
    }
#endif
    sha256_update(&h->t->transcript, raw, raw_len);

    uint8_t hash[SHA256_LEN];
    (void)hsr_transcript_hash(h, hash);
    return check_certificate_verify(h, hash);
}
