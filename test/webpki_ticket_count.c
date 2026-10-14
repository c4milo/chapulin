// webpki_ticket.c for four test binaries, with each configuration hash
// and each binding counted (test/webpki_ticket_count.h).
//
// Each hash in webpki_ticket.c ends with one call to sha256_final_cpu, or
// to sha256_final in a device object. Each binding is one call to
// hmac_sha256_cpu, or to hmac_sha256 in a device object. This file
// compiles webpki_ticket.c with those calls renamed to count_final and
// count_hmac. Each of the two counts the call, records its cpu value, and
// then makes the call it replaces. So the counts include the calls that
// webpki_ticket.c makes to itself, and each hash still runs on the path
// its value names. A device object records 0, the value CH_CFG_CPU gives
// it.
//
// The headers come first, so their declarations keep their own names.
// The renames then change only the calls in webpki_ticket.c's text.
#include "webpki_ticket_count.h"
#include "buf.h"
#include "ch_assert.h"
#include "cpu.h"
#include "ct.h"
#include "hkdf.h"
#include "sha256.h"
#include "suite.h"
#include "webpki.h"
#include "webpki_ticket.h"

static void count_final(uint32_t cpu, sha256 *s, uint8_t out[SHA256_LEN]);
static void count_hmac(uint32_t cpu, const uint8_t *key, size_t key_len, const uint8_t *msg,
                       size_t msg_len, uint8_t out[SHA256_LEN]);

#ifdef CH_CPU_RUNTIME
#define sha256_final_cpu count_final
#define hmac_sha256_cpu count_hmac
#else
#define sha256_final(s, out) count_final(0U, (s), (out))
#define hmac_sha256(key, key_len, msg, msg_len, out)                                               \
    count_hmac(0U, (key), (key_len), (msg), (msg_len), (out))
#endif
#include "webpki_ticket.c"
#ifdef CH_CPU_RUNTIME
#undef sha256_final_cpu
#undef hmac_sha256_cpu
#else
#undef sha256_final
#undef hmac_sha256
#endif

unsigned long webpki_ticket_config_hash_calls;
uint32_t webpki_ticket_config_hash_cpu;
unsigned long webpki_ticket_binding_calls;
uint32_t webpki_ticket_binding_cpu;

static void count_final(uint32_t cpu, sha256 *s, uint8_t out[SHA256_LEN]) {
    webpki_ticket_config_hash_calls++;
    webpki_ticket_config_hash_cpu = cpu;
#ifdef CH_CPU_RUNTIME
    sha256_final_cpu(cpu, s, out);
#else
    sha256_final(s, out);
#endif
}

static void count_hmac(uint32_t cpu, const uint8_t *key, size_t key_len, const uint8_t *msg,
                       size_t msg_len, uint8_t out[SHA256_LEN]) {
    webpki_ticket_binding_calls++;
    webpki_ticket_binding_cpu = cpu;
#ifdef CH_CPU_RUNTIME
    hmac_sha256_cpu(cpu, key, key_len, msg, msg_len, out);
#else
    hmac_sha256(key, key_len, msg, msg_len, out);
#endif
}
