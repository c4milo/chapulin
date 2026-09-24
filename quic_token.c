// The Retry token: mint and check. quic_token.h states the layout and each
// rule. Reading goes through the rbuf reader and writing through the wbuf
// writer (buf.h), so no step here does raw buffer arithmetic, and the issue
// instant moves one byte at a time, so no multi-byte value assumes host
// endianness.
#include "quic_token.h"

#if defined(CH_ROLE_SERVER) && defined(CH_TRANSPORT_QUIC)

#include <string.h>

#include "buf.h"
#include "ch_assert.h"
#include "ct.h"
#include "hkdf.h"

// The ASCII bytes "chapulin quic token", which the tag covers ahead of
// everything else. quic_token.h states why the tag input starts with them.
static const uint8_t token_label[] = {'c', 'h', 'a', 'p', 'u', 'l', 'i', 'n', ' ', 'q',
                                      'u', 'i', 'c', ' ', 't', 'o', 'k', 'e', 'n'};

// The bytes of issued_seconds in the token.
#define QUIC_TOKEN_INSTANT_LEN 8

// Every token byte that is not a connection ID: the type byte, the issue
// instant, the two length bytes and the tag. It is 43, the shortest token.
#define QUIC_TOKEN_FIXED (1 + QUIC_TOKEN_INSTANT_LEN + 1 + 1 + SHA256_LEN)

// The longest tag input: the label, the byte holding address_len, the
// address, and the longest body, which is every token byte before the tag.
#define QUIC_TOKEN_TAG_INPUT_MAX                                                                   \
    (sizeof token_label + 1 + CH_QUIC_TOKEN_ADDRESS_MAX + CH_QUIC_TOKEN_MAX - SHA256_LEN)

// Whether address_len is a length both calls accept: at least one byte,
// because a token bound to no address validates every address, and at most
// CH_QUIC_TOKEN_ADDRESS_MAX.
static int address_len_ok(size_t address_len) {
    return address_len > 0 && address_len <= CH_QUIC_TOKEN_ADDRESS_MAX;
}

// Writes issued_seconds as QUIC_TOKEN_INSTANT_LEN bytes, the most
// significant first.
static void write_instant(wbuf *w, uint64_t seconds) {
    for (int shift = 56; shift >= 0; shift -= 8) {
        wb_u8(w, (uint8_t)(seconds >> shift));
    }
}

// Reads the QUIC_TOKEN_INSTANT_LEN bytes write_instant wrote. A short token
// sets r->err, which the caller reads.
static uint64_t read_instant(rbuf *r) {
    uint64_t seconds = 0;
    for (int i = 0; i < QUIC_TOKEN_INSTANT_LEN; i++) {
        seconds = (seconds << 8) | rb_u8(r);
    }
    return seconds;
}

// Writes the tag quic_token.h describes: HMAC-SHA-256 under key over the
// label, one byte holding address_len, the address and the body_len body
// bytes. Both callers check address_len and bound body_len before they call,
// so the input always fits its buffer, and the assert holds them to that.
// The input holds no secret: the label is printed above, and the address and
// the body are bytes the client sent or will be sent.
static void token_tag(const uint8_t key[CH_QUIC_TOKEN_KEY_LEN], const uint8_t *address,
                      size_t address_len, const uint8_t *body, size_t body_len,
                      uint8_t tag[SHA256_LEN]) {
    uint8_t input[QUIC_TOKEN_TAG_INPUT_MAX];
    wbuf w;
    wb_init(&w, input, sizeof input);
    wb_bytes(&w, token_label, sizeof token_label);
    wb_u8(&w, (uint8_t)address_len);
    wb_bytes(&w, address, address_len);
    wb_bytes(&w, body, body_len);
    CH_ASSERT(w.err == 0);
    hmac_sha256(key, CH_QUIC_TOKEN_KEY_LEN, input, w.len, tag);
}

int ch_srv_quic_token_mint(const uint8_t key[CH_QUIC_TOKEN_KEY_LEN], const uint8_t *address,
                           size_t address_len, const ch_quic_retry_cids *cids,
                           uint64_t issued_seconds, uint8_t *out, size_t cap, size_t *out_len) {
    if (!address_len_ok(address_len) || cids->original_dcid_len > CH_QUIC_DCID_MAX ||
        cids->retry_scid_len > CH_QUIC_DCID_MAX) {
        return CH_EINVAL;
    }
    // The whole token's length, checked before the first byte is written,
    // because the contract refuses a short cap having written nothing and the
    // writer would leave a partial token behind.
    size_t total = QUIC_TOKEN_FIXED + cids->original_dcid_len + cids->retry_scid_len;
    if (cap < total) {
        return CH_ECAP;
    }

    wbuf w;
    wb_init(&w, out, cap);
    wb_u8(&w, QUIC_TOKEN_TYPE_RETRY);
    write_instant(&w, issued_seconds);
    wb_u8(&w, cids->original_dcid_len);
    wb_bytes(&w, cids->original_dcid, cids->original_dcid_len);
    wb_u8(&w, cids->retry_scid_len);
    wb_bytes(&w, cids->retry_scid, cids->retry_scid_len);

    // Everything written so far is the body, so the tag covers the first
    // w.len bytes of out. The tag goes out in the clear as the token's last
    // field, so nothing wipes it.
    uint8_t tag[SHA256_LEN];
    token_tag(key, address, address_len, out, w.len, tag);
    wb_bytes(&w, tag, sizeof tag);

    // The cap check above is what keeps the writer inside out, so the writer
    // cannot have refused a byte.
    CH_ASSERT(w.err == 0 && w.len == total);
    *out_len = w.len;
    return CH_OK;
}

int ch_srv_quic_token_check(const uint8_t key[CH_QUIC_TOKEN_KEY_LEN], const uint8_t *token,
                            size_t n, const uint8_t *address, size_t address_len,
                            uint64_t now_seconds, uint64_t lifetime_seconds,
                            ch_quic_retry_cids *cids) {
    if (!address_len_ok(address_len)) {
        return CH_EINVAL;
    }

    // The type byte decides which of the two refusals a bad token earns, so
    // it is read before anything else.
    rbuf r;
    rb_init(&r, token, n);
    uint8_t type = rb_u8(&r);
    if (r.err || type != QUIC_TOKEN_TYPE_RETRY) {
        return CH_EPROTO;
    }

    uint64_t issued_seconds = read_instant(&r);
    size_t original_dcid_len = rb_u8(&r);
    const uint8_t *original_dcid = rb_bytes(&r, original_dcid_len);
    size_t retry_scid_len = rb_u8(&r);
    const uint8_t *retry_scid = rb_bytes(&r, retry_scid_len);
    const uint8_t *tag = rb_bytes(&r, SHA256_LEN);
    // INV-25's exact-fill check: r.err refuses a token shorter than its two
    // length bytes fix, and a byte left over refuses one longer. The reader is
    // bounded by n, so neither answer came from a read past the end. The two
    // caps keep each connection ID inside the array *cids gives it.
    if (r.err || rb_left(&r) != 0 || original_dcid_len > CH_QUIC_DCID_MAX ||
        retry_scid_len > CH_QUIC_DCID_MAX) {
        return CH_EAUTH;
    }

    // The tag covers the body, which is every byte before the tag itself.
    // ct_memeq compares all SHA256_LEN bytes, so a client cannot search for a
    // valid tag one byte per attempt. want is the correct tag over a body the
    // client chose, so it is wiped rather than left on the stack.
    uint8_t want[SHA256_LEN];
    token_tag(key, address, address_len, token, n - SHA256_LEN, want);
    uint32_t equal = ct_memeq(tag, want, SHA256_LEN);
    ct_wipe(want, sizeof want);
    if (equal == 0) {
        return CH_EAUTH;
    }

    // The window. The first comparison refuses a token issued after
    // now_seconds, and it is what keeps the subtraction from wrapping.
    if (now_seconds < issued_seconds || now_seconds - issued_seconds > lifetime_seconds) {
        return CH_EAUTH;
    }

    memcpy(cids->original_dcid, original_dcid, original_dcid_len);
    cids->original_dcid_len = (uint8_t)original_dcid_len;
    memcpy(cids->retry_scid, retry_scid, retry_scid_len);
    cids->retry_scid_len = (uint8_t)retry_scid_len;
    return CH_OK;
}

#endif // CH_ROLE_SERVER && CH_TRANSPORT_QUIC
