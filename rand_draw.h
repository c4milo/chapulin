// The one path every library draw takes (INV-4). rand_draw writes n bytes
// from the source the session's configuration names, whose contract
// rand.h states. It sits apart from rand.h because it reads ch_cfg, and
// rand.h is the header an image's hook includes with none of the
// library's build defines.
#ifndef CH_RAND_DRAW_H
#define CH_RAND_DRAW_H

#include <stddef.h>
#include <stdint.h>

#include "cfg.h"
#include "rand.h"

// Writes n random bytes at p from the source cfg names: the session's
// cfg->rand_bytes, handed cfg->rand_io, under RAND=session, and
// ch_rand_bytes under the other two patterns. Every library draw calls
// this and nothing else (INV-4), so a RAND=extern or RAND=drbg build draws
// exactly as it did before RAND=session existed. The caller passes the
// configuration of the session the draw serves, the copy the session
// holds, never another session's. Under RAND=session an init call or
// ch_srv_check accepted that configuration first, so rand_source_ok holds
// for it.
static inline void rand_draw(const ch_cfg *cfg, uint8_t *p, size_t n) {
#ifdef CH_RAND_SESSION
    cfg->rand_bytes(cfg->rand_io, p, n);
#else
    (void)cfg;
    ch_rand_bytes(p, n);
#endif
}

#ifdef CH_RAND_SESSION
// Whether cfg names a source rand_draw can draw from: a rand_bytes that is
// not NULL. Every init call and ch_srv_check refuse a configuration it
// rejects with CH_EINVAL before they draw or send anything. Only a
// RAND=session build has the field, so only that build declares this: the
// other two patterns draw from the one hook the link supplies, and there
// is nothing to refuse.
static inline int rand_source_ok(const ch_cfg *cfg) {
    return cfg->rand_bytes != NULL;
}
#endif

#endif
