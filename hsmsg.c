#include "hsmsg.h"

#include "buf.h"

size_t hs_build_ch(uint8_t *out, size_t cap, const ms_cfg *cfg, const uint8_t pub[32],
                   const uint8_t random32[32], uint16_t rsl, const uint8_t *cookie,
                   size_t cookielen) {
    wbuf w;
    wb_init(&w, out, cap);

    wb_u8(&w, HS_CLIENT_HELLO);
    size_t msg = wb_mark(&w, 3);
    wb_u16(&w, 0x0303); // legacy_version
    wb_bytes(&w, random32, 32);
    wb_u8(&w, 0);  // empty legacy_session_id: no middlebox compat needed
    wb_u16(&w, 2); // one suite
    wb_u16(&w, SUITE_CHACHA20_POLY1305_SHA256);
    wb_u8(&w, 1); // legacy_compression_methods = {null}
    wb_u8(&w, 0);

    size_t exts = wb_mark(&w, 2);

    wb_u16(&w, EXT_SUPPORTED_VERSIONS);
    wb_u16(&w, 3);
    wb_u8(&w, 2);
    wb_u16(&w, TLS13);

    wb_u16(&w, EXT_SUPPORTED_GROUPS);
    wb_u16(&w, 4);
    wb_u16(&w, 2);
    wb_u16(&w, GROUP_X25519);

    wb_u16(&w, EXT_KEY_SHARE);
    wb_u16(&w, 2 + 2 + 2 + 32);
    wb_u16(&w, 2 + 2 + 32); // client_shares length
    wb_u16(&w, GROUP_X25519);
    wb_u16(&w, 32);
    wb_bytes(&w, pub, 32);

    // Sent in both modes: without it a server (Go enforces this) will not
    // issue session tickets, and pinned mode relies on tickets to make
    // reconnects cheap.
    wb_u16(&w, EXT_PSK_MODES);
    wb_u16(&w, 2);
    wb_u8(&w, 1);
    wb_u8(&w, 1); // psk_dhe_ke only

    wb_u16(&w, EXT_RECORD_SIZE_LIMIT);
    wb_u16(&w, 2);
    wb_u16(&w, rsl);

    if (cookie != NULL) {
        wb_u16(&w, EXT_COOKIE);
        wb_u16(&w, (uint16_t)(2 + cookielen));
        wb_u16(&w, (uint16_t)cookielen);
        wb_bytes(&w, cookie, cookielen);
    }

    if (cfg->psk == NULL) {
        // Pinned-key mode: the server authenticates by signature, so
        // offer the one algorithm the pin can be.
        wb_u16(&w, EXT_SIGNATURE_ALGORITHMS);
        wb_u16(&w, 4);
        wb_u16(&w, 2);
        wb_u16(&w, SIGALG_ECDSA_P256_SHA256);
    } else {
        // pre_shared_key comes last (RFC 8446 §4.2.11).
        wb_u16(&w, EXT_PRE_SHARED_KEY);
        size_t psk = wb_mark(&w, 2);
        size_t ids = wb_mark(&w, 2);
        wb_u16(&w, (uint16_t)cfg->psk_id_len);
        wb_bytes(&w, cfg->psk_id, cfg->psk_id_len);
        uint32_t age = cfg->resumption ? cfg->obfuscated_age : 0;
        wb_u16(&w, (uint16_t)(age >> 16));
        wb_u16(&w, (uint16_t)age);
        wb_patch16(&w, ids);
        wb_u16(&w, 33); // binders list: one 32-byte binder
        wb_u8(&w, 32);
        size_t binder = wb_mark(&w, 32);
        (void)binder;
        wb_patch16(&w, psk);
    }

    wb_patch16(&w, exts);
    wb_patch24(&w, msg);
    return w.err ? 0 : w.len;
}
