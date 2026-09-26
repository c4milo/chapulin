// A consumer of the packaged object, the way a firmware image or a Zig
// program is one: it compiles against the headers under defines of its
// own and links bin/chapulin.o. lib-check builds it three times against
// every object it checks. Compiled under the object's own defines it must
// read ch_build equal to its header view and exit 0. Compiled with
// CH_PIN_ECDSA moved it must read a difference and exit 1. Compiled with
// the transport moved it must not link, because build.h then names
// another transport's record. Exit 2 means the program's own header view
// is wrong, whichever object it links.
//
// It opens no session, so no hook below is ever called. The object
// imports them all the same, and a program that links it defines them,
// as every image does. Each stops the program if it runs, and each hook
// that has an output clears it first, as its contract asks.
#include <inttypes.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdnoreturn.h>
#include <string.h>

#include "build.h"
#include "ch_assert.h"
#ifdef CH_RAND_EXTERN
#include "rand.h"
#endif
#ifdef CH_KEYLOG
#include "keylog.h"
#endif

noreturn void ch_assert_fail(const char *cond, const char *file, int line) {
    (void)fprintf(stderr, "ASSERT %s:%d: %s\n", file, line, cond);
    abort();
}

#ifdef CH_RAND_EXTERN
void ch_rand_bytes(uint8_t *p, size_t n) {
    memset(p, 0, n);
    abort();
}
#endif

#ifdef CH_KEYLOG
void ch_keylog(void *io, const char *label, const uint8_t client_random[CH_KEYLOG_RANDOM_LEN],
               const uint8_t *secret, size_t secret_len) {
    (void)io;
    (void)label;
    (void)client_random;
    (void)secret;
    (void)secret_len;
    abort();
}
#endif

#ifdef CH_AES_EXTERN
// aes_block.h declares this hook, and only a library source reads
// that header, so the declaration is repeated here. An AES=extern object
// imports it whenever it compiles AES, and the transport this program
// moves can be the one that decides that.
void ch_aes_block(const uint8_t key[16], const uint8_t in[16], uint8_t out[16]);
void ch_aes_block(const uint8_t key[16], const uint8_t in[16], uint8_t out[16]) {
    (void)key;
    (void)in;
    memset(out, 0, 16);
    abort();
}
#endif

// The axes restated from this program's own defines, one line per
// define, rather than read from build.h. A CH_BUILD_AXES that forgets a
// define then differs from this value under the build that sets it.
static uint32_t axes_from_defines(void) {
    uint32_t axes = 0;
#ifdef CH_TRUST_CA
    axes |= CH_BUILD_TRUST_CA;
#endif
#ifdef CH_TRUST_WEBPKI
    axes |= CH_BUILD_TRUST_WEBPKI;
#endif
#ifdef CH_PIN_ECDSA
    axes |= CH_BUILD_PIN_ECDSA;
#endif
#ifdef CH_KEX_PQ
    axes |= CH_BUILD_KEX_PQ;
#endif
#ifdef CH_TRANSPORT_QUIC_NONBLOCKING
    axes |= CH_BUILD_TRANSPORT_QUIC_NONBLOCKING;
#endif
#ifdef CH_TRANSPORT_TCP_NONBLOCKING
    axes |= CH_BUILD_TRANSPORT_TCP_NONBLOCKING;
#endif
#ifdef CH_SUITE_AES_GCM
    axes |= CH_BUILD_SUITE_AES_GCM;
#endif
#ifdef CH_ROLE_SERVER
    axes |= CH_BUILD_ROLE_SERVER;
#endif
#ifdef CH_EXPORTER
    axes |= CH_BUILD_EXPORTER;
#endif
#ifdef CH_KEYLOG
    axes |= CH_BUILD_KEYLOG;
#endif
    return axes;
}

// One field of the record: its name, what ch_build holds, and what this
// program's headers compute.
typedef struct {
    const char *name;
    uint32_t object;
    uint32_t header;
} field;

int main(void) {
    if (CH_BUILD_AXES != axes_from_defines()) {
        (void)printf("build_test: CH_BUILD_AXES is %#" PRIx32 ", and this program's defines "
                     "set %#" PRIx32 "\n",
                     (uint32_t)CH_BUILD_AXES, axes_from_defines());
        return 2;
    }
    // The other fields exist only in a record of this format, so a
    // record of another one is reported by its version alone.
    if (ch_build.version != CH_BUILD_VERSION) {
        (void)printf("build_test: ch_build.version is %" PRIu32 ", and this program's headers "
                     "are format %" PRIu32 "\n",
                     ch_build.version, (uint32_t)CH_BUILD_VERSION);
        return ch_build_matches(&ch_build) ? 2 : 1;
    }
    const field fields[] = {
        {"axes",                 ch_build.axes,                 CH_BUILD_AXES                },
        {"sizeof_ch_cfg",        ch_build.sizeof_ch_cfg,        CH_BUILD_SIZEOF_CH_CFG       },
        {"sizeof_ch_tls",        ch_build.sizeof_ch_tls,        CH_BUILD_SIZEOF_CH_TLS       },
        {"sizeof_ch_ticket",     ch_build.sizeof_ch_ticket,     CH_BUILD_SIZEOF_CH_TICKET    },
        {"sizeof_ch_record",     ch_build.sizeof_ch_record,     CH_BUILD_SIZEOF_CH_RECORD    },
        {"sizeof_ch_quic",       ch_build.sizeof_ch_quic,       CH_BUILD_SIZEOF_CH_QUIC      },
        {"sizeof_ch_rsa_priv",   ch_build.sizeof_ch_rsa_priv,   CH_BUILD_SIZEOF_CH_RSA_PRIV  },
        {"tx_stage",             ch_build.tx_stage,             CH_BUILD_TX_STAGE            },
        {"min_rxbuf",            ch_build.min_rxbuf,            CH_BUILD_MIN_RXBUF           },
        {"x509_max",             ch_build.x509_max,             CH_BUILD_X509_MAX            },
        {"transport_params_max", ch_build.transport_params_max, CH_BUILD_TRANSPORT_PARAMS_MAX},
    };
    size_t differ = 0;
    for (size_t i = 0; i < sizeof fields / sizeof fields[0]; i++) {
        if (fields[i].object != fields[i].header) {
            (void)printf("build_test: ch_build.%s is %" PRIu32 ", and this program's headers "
                         "compute %" PRIu32 "\n",
                         fields[i].name, fields[i].object, fields[i].header);
            differ++;
        }
    }
    // The predicate must say what the fields say. A predicate that skips
    // a field answers 1 here while that field differs.
    int matches = ch_build_matches(&ch_build);
    if (matches != (differ == 0)) {
        (void)printf("build_test: ch_build_matches answers %d with %zu fields differing\n", matches,
                     differ);
        return 2;
    }
    return matches ? 0 : 1;
}
