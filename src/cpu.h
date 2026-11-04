// The rule every init call and ch_srv_check apply to ch_cfg.cpu in a host object
// (docs/decisions.md 89). cpu_cfg.h states the bits. This header sits apart from it because it
// reads ch_cfg, which cfg.h declares after it includes cpu_cfg.h, as rand_draw.h sits apart from
// rand.h.
#ifndef CH_CPU_H
#define CH_CPU_H

#include <stdint.h>

#include "cfg.h"

#ifdef CH_CPU_RUNTIME
// Whether cpu is a value this object takes as a description of its CPU. The value holds
// CH_CPU_PROBED, and no bit outside CH_CPU_DEFINED, the bits this object defines for its
// architecture. A predicate over the caller's value, which holds no secret.
static inline int cpu_value_ok(uint32_t cpu) {
    return (cpu & CH_CPU_PROBED) != 0 && (cpu & ~(uint32_t)CH_CPU_DEFINED) == 0;
}

// Whether cfg->cpu is a value a session takes, by cpu_value_ok's rule. Every init call and
// ch_srv_check refuse a configuration this rejects with CH_EINVAL before they send anything.
static inline int cpu_bits_ok(const ch_cfg *cfg) {
    return cpu_value_ok(cfg->cpu);
}
#else
// A device object defines no bit, not CH_CPU_PROBED either. One call takes a cpu argument in
// every object, ch_p256_key_from_pem (pem_files.h), and a device object takes 0 from it alone.
// Every other value holds a bit that this object does not define.
static inline int cpu_value_ok(uint32_t cpu) {
    return cpu == 0;
}
#endif

// cfg's cpu as the argument of a call that takes a session's ch_cfg.cpu in every build, as
// quic_packet.h's three do: the field in a host object, and 0 in a device object, which declares
// no such field, holds one path for each primitive, and never evaluates cfg here.
#ifdef CH_CPU_RUNTIME
#define CH_CFG_CPU(cfg) ((cfg).cpu)
#else
#define CH_CFG_CPU(cfg) 0U
#endif

#endif
