// The server's handshake output, one implementation per transport.
// srv_out.h states the contract and why the two differ.
#include "srv_out.h"

#ifdef CH_ROLE_SERVER

#include <string.h>

#include "cfg.h"
#include "ct.h"
#include "handshake_message.h"
#include "sha256.h"
// Both TCP transports seal, and only tcp-blocking sends: io.h is
// included for either, so emit below is a single arm a .violation mutant
// can flip. A tcp-nonblocking build declares io_send_all and calls it nowhere.
#ifndef CH_TRANSPORT_QUIC_NONBLOCKING
#include "io.h"
#include "record.h"
#endif

#ifdef CH_TRANSPORT_QUIC_NONBLOCKING

// Hands n bytes to the caller at the level the driver set. RFC 9001
// section 4.1.3 makes the unprotected content of a handshake record the
// content of a CRYPTO frame, so there is no header to write and no record
// to seal (rfc9001.txt:462-464).
//
// ch_srv_check refuses a configuration whose on_crypto_out is NULL, so
// this call needs no NULL test: a server whose flight reaches nobody
// completes no handshake.
static int push(handshake_state *h, const uint8_t *p, size_t n) {
    const ch_cfg *cfg = &h->t->cfg;
    return cfg->srv.on_crypto_out(cfg->io, h->level, p, n) == 0 ? CH_OK : CH_EIO;
}

// No record bounds a CRYPTO frame's content, so the staging cap is the
// only limit here. RFC 9001 section 4.1.3 removed record_size_limit with
// the record layer, and a QUIC build declares no ch_tls.peer_limit for
// this to read.
size_t srv_out_limit(const ch_tls *t) {
    (void)t;
    return CH_TX_PT;
}

// A message a TCP build would send in the clear. It is staged at t->tx
// itself, because SRV_OUT_STAGE is 0 where no record header precedes it.
int srv_out_plain(handshake_state *h, size_t n) {
    return push(h, h->t->tx, n);
}

// A message a TCP build would seal. QUIC protects the packet rather than
// the record, so these bytes go out exactly as the handler wrote them.
int srv_out_sealed(handshake_state *h, const uint8_t *pt, size_t n) {
    return push(h, pt, n);
}

#else

// The largest plaintext one record carries: this build's cap, lowered to
// the client's record_size_limit.
size_t srv_out_limit(const ch_tls *t) {
    return t->peer_limit < CH_TX_PT ? t->peer_limit : CH_TX_PT;
}

// Where one finished record goes. A TRANSPORT=tcp-blocking server writes it to
// the socket through the caller's blocking send. A TRANSPORT=tcp-nonblocking
// server hands it to the caller, which owns the socket, so nothing here
// blocks and no record waits for one to drain. srv_cfg.h states why this
// mode pushes rather than staging a record for a caller to pull.
//
// ch_srv_record_init refuses a configuration whose on_record_out is
// NULL, so this call needs no NULL test, the same way push does.
static int emit(ch_tls *t, const uint8_t *p, size_t n) {
#ifdef CH_TRANSPORT_TCP_NONBLOCKING
    const ch_cfg *cfg = &t->cfg;
    return cfg->srv.on_record_out(cfg->io, p, n) == 0 ? CH_OK : CH_EIO;
#else
    return io_send_all(&t->cfg, p, n);
#endif
}

int srv_out_record(ch_tls *t, const uint8_t *rec, size_t n) {
    return emit(t, rec, n);
}

// Sends the n bytes staged at t->tx + REC_HDR as one plaintext handshake
// record. RFC 9846 §5.1 fixes legacy_record_version at 0x0303 here.
int srv_out_plain(handshake_state *h, size_t n) {
    ch_tls *t = h->t;
    t->tx[0] = REC_HANDSHAKE;
    t->tx[1] = 0x03;
    t->tx[2] = 0x03;
    t->tx[3] = (uint8_t)(n >> 8);
    t->tx[4] = (uint8_t)n;
    return emit(t, t->tx, REC_HDR + n);
}

// Seals pt as one or more handshake records, each carrying at most
// srv_out_limit bytes. RFC 9846 §5.1 permits a message to span records and
// forbids interleaving another type (rfc9846.txt:3460-3462), which a
// straight-line writer cannot do. pt lies outside t->tx, where rec_seal
// writes.
int srv_out_sealed(handshake_state *h, const uint8_t *pt, size_t n) {
    ch_tls *t = h->t;
    size_t limit = srv_out_limit(t);
    while (n > 0) {
        size_t take = n < limit ? n : limit;
        size_t out_len = 0;
        if (rec_seal(&t->wr, REC_HANDSHAKE, pt, take, t->tx, sizeof t->tx, &out_len) != 0) {
            h->alert = ALERT_INTERNAL_ERROR;
            return CH_ECAP;
        }
        int rc = emit(t, t->tx, out_len);
        if (rc != CH_OK) {
            return rc;
        }
        pt += take;
        n -= take;
    }
    return CH_OK;
}

#endif

// Hashes what the writer holds and sends it as one sealed record.
void srv_frag_flush(srv_frag *f) {
    if (f->rc != CH_OK || f->len == 0) {
        return;
    }
    transcript_update(&f->h->t->transcript, f->buf, f->len);
    f->rc = srv_out_sealed(f->h, f->buf, f->len);
    f->len = 0;
}

void srv_frag_bytes(srv_frag *f, const uint8_t *p, size_t n) {
    size_t limit = srv_out_limit(f->h->t);
    while (n > 0 && f->rc == CH_OK) {
        size_t take = n < limit - f->len ? n : limit - f->len;
        memcpy(f->buf + f->len, p, take);
        f->len += take;
        p += take;
        n -= take;
        if (f->len == limit) {
            srv_frag_flush(f);
        }
    }
}

#endif // CH_ROLE_SERVER
