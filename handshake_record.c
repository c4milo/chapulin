// The handshake reads records here, tolerates compat-mode
// CCS noise within its cap, decrypts once keys are up, and
// reassembles complete handshake messages across records in cfg.buf.
// Split from handshake.c so the driver file stays one readable
// concern; external linkage keeps the reader provable and fuzzable on
// its own. Contract in handshake_record.h.
#include "handshake_record.h"

#include <string.h>

#include "buf.h"
#include "cfg.h"
#include "handshake_message.h"
#if !defined(CH_TRANSPORT_QUIC) && !defined(CH_TRANSPORT_RECORD)
#include "io.h"
#include "record.h"
#endif

#if !defined(CH_TRANSPORT_QUIC) && !defined(CH_TRANSPORT_RECORD)
// Appends one record's handshake bytes at buf[part..]. Plaintext records
// shed their header in place; protected ones decrypt in place.
static int accept_record(handshake_state *h, size_t part, uint8_t outer, size_t record_len) {
    ch_tls *t = h->t;
    uint8_t *buf = t->cfg.buf;
    if (!h->encrypted) {
        if (outer != REC_HANDSHAKE) {
            return CH_EPROTO;
        }
        memmove(buf + part, buf + part + REC_HDR, record_len - REC_HDR);
        t->pt_len = part + record_len - REC_HDR;
        return CH_OK;
    }
    if (outer != REC_APPDATA) {
        return CH_EPROTO;
    }
    size_t n = 0;
    uint8_t inner_type = 0;
    if (rec_open(&t->rd, buf + part, record_len, buf + part, t->cfg.buf_len - part, &n,
                 &inner_type) != 0) {
        h->alert = ALERT_BAD_RECORD_MAC;
        return CH_EAUTH;
    }
    if (inner_type != REC_HANDSHAKE) {
        return CH_EPROTO;
    }
    t->pt_len = part + n;
    return CH_OK;
}

// Reads records until one carrying handshake bytes lands, decrypting once
// keys are up, and appends its plaintext to the unconsumed bytes already
// in cfg.buf so messages may span records.
// Middlebox-compat noise, never hashed. RFC 9846 §5: exactly one
// 0x01 byte. Each call spends one of the four tolerated CCS
// records, so a hostile stream stays finite.
static int ccs_tolerable(handshake_state *h, size_t part, size_t record_len) {
    if (record_len != REC_HDR + 1 || h->t->cfg.buf[part + REC_HDR] != 1) {
        return 0;
    }
    h->ccs_seen++;
    return h->ccs_seen <= 4;
}

// An empty fragment is legal once in a while; a stream of them must
// not pin the handshake. A fragment that made progress is free; an
// empty one spends quiet budget.
static int quiet_stream_capped(handshake_state *h, size_t part) {
    if (h->t->pt_len != part) {
        return 0;
    }
    h->quiet++;
    return h->quiet > CH_QUIET_CAP;
}

int hsr_fetch_record(handshake_state *h) {
    ch_tls *t = h->t;
    if (t->pt_off > 0) {
        memmove(t->cfg.buf, t->cfg.buf + t->pt_off, t->pt_len - t->pt_off);
        t->pt_len -= t->pt_off;
        t->pt_off = 0;
    }
    for (;;) {
        size_t part = t->pt_len;
        uint8_t outer = 0;
        size_t record_len = 0;
        int rc =
            io_read_record(&t->cfg, t->cfg.buf + part, t->cfg.buf_len - part, &outer, &record_len);
        if (rc != CH_OK) {
            return rc;
        }
        if (outer == REC_CCS) {
            if (!ccs_tolerable(h, part, record_len)) {
                h->alert = ALERT_UNEXPECTED_MESSAGE;
                return CH_EPROTO;
            }
            continue;
        }
        if (outer == REC_ALERT) {
            return CH_EPROTO; // peer aborted; nothing to salvage
        }
        rc = accept_record(h, part, outer, record_len);
        if (rc != CH_OK) {
            return rc;
        }
        if (quiet_stream_capped(h, part)) {
            h->alert = ALERT_UNEXPECTED_MESSAGE;
            return CH_EPROTO;
        }
        return CH_OK;
    }
}

// Yields the next complete handshake message, raw (header included) for
// the transcript. Pointers land in cfg.buf and die at the next call.
int hsr_next_msg(handshake_state *h, uint8_t *type, const uint8_t **raw, size_t *raw_len) {
    ch_tls *t = h->t;
    for (;;) {
        const uint8_t *p = t->cfg.buf + t->pt_off;
        size_t avail = t->pt_len - t->pt_off;
        if (avail >= 4) {
            size_t msg_len = ((size_t)p[1] << 16) | ((size_t)p[2] << 8) | p[3];
            if (msg_len > 0x4000) {
                return CH_EPROTO; // nothing we accept is this large
            }
            if (avail >= 4 + msg_len) {
                *type = p[0];
                *raw = p;
                *raw_len = 4 + msg_len;
                t->pt_off += 4 + msg_len;
                return CH_OK;
            }
        }
        int rc = hsr_fetch_record(h);
        if (rc != CH_OK) {
            return rc;
        }
    }
}

#endif // CH_TRANSPORT_QUIC || CH_TRANSPORT_RECORD

#if defined(CH_TRANSPORT_QUIC) || defined(CH_TRANSPORT_RECORD)
size_t hsr_feed(handshake_state *h, const uint8_t *p, size_t n) {
    ch_tls *t = h->t;
    // Compact first, the way the TLS reader compacts before it reads a
    // record, so the unread bytes start at cfg.buf and the room is one
    // subtraction.
    if (t->pt_off > 0) {
        memmove(t->cfg.buf, t->cfg.buf + t->pt_off, t->pt_len - t->pt_off);
        t->pt_len -= t->pt_off;
        t->pt_off = 0;
    }
    size_t room = t->cfg.buf_len - t->pt_len;
    size_t take = n < room ? n : room;
    memcpy(t->cfg.buf + t->pt_len, p, take);
    t->pt_len += take;
    return take;
}

int hsr_peek_message(const handshake_state *h, size_t *raw_len, uint8_t *alert) {
    const ch_tls *t = h->t;
    size_t avail = t->pt_len - t->pt_off;
    if (avail < 4) {
        return HSR_INCOMPLETE;
    }
    const uint8_t *p = t->cfg.buf + t->pt_off;
    size_t msg_len = ((size_t)p[1] << 16) | ((size_t)p[2] << 8) | p[3];
    if (msg_len > 0x4000) {
        *alert = ALERT_DECODE_ERROR; // nothing we accept is this large
        return CH_EPROTO;
    }
    if (4 + msg_len > t->cfg.buf_len) {
        // A QUIC client sends no record_size_limit, so cfg.buf_len is
        // the only bound a peer meets and a message that could never
        // fit is refused at the header rather than waited for.
        *alert = ALERT_INTERNAL_ERROR;
        return CH_ECAP;
    }
    if (avail < 4 + msg_len) {
        return HSR_INCOMPLETE;
    }
    *raw_len = 4 + msg_len;
    return CH_OK;
}

// Yields the message hsr_peek_message has already found whole. It waits
// for nothing: the caller owns the transport and feeds CRYPTO bytes in
// through hsr_feed. The driver peeks before every step, so the CH_ECAP
// hsr_peek_message can answer is never returned to a caller here; this call
// passes it on rather than hiding it.
int hsr_next_msg(handshake_state *h, uint8_t *type, const uint8_t **raw, size_t *raw_len) {
    ch_tls *t = h->t;
    size_t whole = 0;
    uint8_t alert = 0;
    int rc = hsr_peek_message(h, &whole, &alert);
    if (rc == HSR_INCOMPLETE) {
        return CH_EINVAL; // the driver called without a whole message
    }
    if (rc != CH_OK) {
        h->alert = alert;
        return rc;
    }
    const uint8_t *p = t->cfg.buf + t->pt_off;
    *type = p[0];
    *raw = p;
    *raw_len = whole;
    t->pt_off += whole;
    return CH_OK;
}
#endif // CH_TRANSPORT_QUIC || CH_TRANSPORT_RECORD

#ifdef CH_TRANSPORT_QUIC
int hsr_peek_type(const handshake_state *h, uint8_t *type) {
    const ch_tls *t = h->t;
    if (t->pt_off == t->pt_len) {
        return HSR_INCOMPLETE;
    }
    *type = t->cfg.buf[t->pt_off];
    return CH_OK;
}
#endif

int hsr_transcript_hash(handshake_state *h, size_t hash_len, uint8_t *out) {
    transcript_hash_after(&h->t->transcript, hash_len, NULL, 0, out);
    return CH_OK;
}

void hsr_restart_transcript(handshake_state *h, size_t hash_len, const uint8_t *retry, size_t n) {
    uint8_t ch1[HKDF_HASH_MAX];
    transcript_hash_after(&h->t->transcript, hash_len, NULL, 0, ch1);
    const uint8_t synth[4] = {HS_MESSAGE_HASH, 0, 0, (uint8_t)hash_len};
    transcript_init(&h->t->transcript);
    transcript_update(&h->t->transcript, synth, sizeof synth);
    transcript_update(&h->t->transcript, ch1, hash_len);
    transcript_update(&h->t->transcript, retry, n);
}
