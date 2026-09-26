// The build record: what one packaged object was compiled with, so a
// consumer can compare it against the headers it compiles under.
//
// A consumer links bin/chapulin.o and reads these headers under defines
// it writes itself. Nothing in the link checks that the two agree: an
// object built with -DCH_TRUST_WEBPKI and a consumer that forgot the
// define disagree about sizeof(ch_tls), CH_TX_STAGE and CH_MIN_RXBUF,
// and the program links and runs anyway. So every packaged object
// exports one const data symbol, its build record, holding the values
// below as the object computed them, and this header computes the same
// values from the consumer's own defines. A consumer calls
// ch_build_matches(&ch_build) once at startup, or compares the fields
// itself, and refuses to run on a mismatch. Nothing in the library
// calls the comparison: a consumer asks, and no init call changes.
//
// docs/decisions.md 56 states why the record is data rather than a
// check inside ch_connect and the init calls, and which defines it
// records and which it leaves out. docs/decisions.md 61 states why the
// record's symbol name carries the object's transport.
#ifndef CH_BUILD_H
#define CH_BUILD_H

#include <stdint.h>

#include "cfg.h"
#include "session.h"
#ifdef CH_TRANSPORT_TCP_NONBLOCKING
#include "tcp_nonblocking.h"
#endif
#ifdef CH_TRANSPORT_QUIC_NONBLOCKING
#include "quic.h"
#endif
#ifdef CH_ROLE_SERVER
#include "rsa_sign.h"
#endif

// The format of ch_build_info. A later format appends fields and raises
// this number, so version is the one field every format holds.
#define CH_BUILD_VERSION 1U

// One bit of ch_build_info.axes per build define that changes a public
// layout or a public bound. Each bit is named after its define, and the
// right column says what the define changes.
//
//   CH_TRUST_CA            CH_MIN_RXBUF, the handshake state that
//                          ch_record and ch_quic hold, and adds
//                          ch_pubkey_from_pem's CH_X509_MAX-byte buffer
//   CH_TRUST_WEBPKI        ch_cfg, ch_tls, ch_ticket, ch_record, ch_quic,
//                          CH_TX_STAGE and CH_MIN_RXBUF
//   CH_PIN_ECDSA           CH_X509_MAX, and with it a CA mode's
//                          CH_MIN_RXBUF, and the length of a pinned key
//   CH_KEX_PQ              ch_tls, ch_record, ch_quic, CH_TX_STAGE and
//                          CH_MIN_RXBUF
//   CH_TRANSPORT_QUIC_NONBLOCKING
//                          ch_cfg, ch_tls, CH_TX_STAGE and CH_MIN_RXBUF,
//                          and adds ch_quic
//   CH_TRANSPORT_TCP_NONBLOCKING
//                          ch_tls, and adds ch_record
//   CH_SUITE_AES_GCM       ch_cfg, ch_tls, ch_ticket, ch_record, ch_quic
//                          and CH_TX_STAGE: a server's suite order,
//                          SHA-384's secrets and PSK, a webpki hello's
//                          two more suites and longer binder, and each
//                          QUIC key set's suite
//   CH_ROLE_SERVER         ch_cfg, ch_tls and CH_TX_STAGE, and adds
//                          ch_rsa_priv
//   CH_EXPORTER            ch_tls
//   CH_KEYLOG              the handshake state that ch_record and ch_quic
//                          hold
//
// Left out, because no public layout or bound reads them: the RAND
// pattern, CH_ROLE_BOTH, the AES implementation, X25519=wide and the
// four timing assertions, CH_NATIVE_WIDEMUL (which WIDEMUL=native
// sets), CH_NATIVE_AES, CH_AES_EXTERN_CONSTANT_TIME and
// CH_NATIVE_MUL128. CH_KEX_TWO_GROUPS and
// CH_KEX_HYBRID are left out too: cfg.h computes both from
// CH_TRUST_WEBPKI and CH_KEX_PQ, so a bit for either would repeat those
// two. docs/decisions.md 56 gives the reason for each.
#define CH_BUILD_TRUST_CA 0x001U
#define CH_BUILD_TRUST_WEBPKI 0x002U
#define CH_BUILD_PIN_ECDSA 0x004U
#define CH_BUILD_KEX_PQ 0x008U
#define CH_BUILD_TRANSPORT_QUIC_NONBLOCKING 0x010U
#define CH_BUILD_TRANSPORT_TCP_NONBLOCKING 0x020U
#define CH_BUILD_SUITE_AES_GCM 0x040U
#define CH_BUILD_ROLE_SERVER 0x080U
#define CH_BUILD_EXPORTER 0x100U
#define CH_BUILD_KEYLOG 0x200U

// Each CH_BUILD_IF_ value is its bit when this translation unit defines
// the define it names, and 0 when it does not. CH_BUILD_AXES is their
// union: the axes the headers describe under the defines in force here.
#ifdef CH_TRUST_CA
#define CH_BUILD_IF_TRUST_CA CH_BUILD_TRUST_CA
#else
#define CH_BUILD_IF_TRUST_CA 0U
#endif
#ifdef CH_TRUST_WEBPKI
#define CH_BUILD_IF_TRUST_WEBPKI CH_BUILD_TRUST_WEBPKI
#else
#define CH_BUILD_IF_TRUST_WEBPKI 0U
#endif
#ifdef CH_PIN_ECDSA
#define CH_BUILD_IF_PIN_ECDSA CH_BUILD_PIN_ECDSA
#else
#define CH_BUILD_IF_PIN_ECDSA 0U
#endif
#ifdef CH_KEX_PQ
#define CH_BUILD_IF_KEX_PQ CH_BUILD_KEX_PQ
#else
#define CH_BUILD_IF_KEX_PQ 0U
#endif
#ifdef CH_TRANSPORT_QUIC_NONBLOCKING
#define CH_BUILD_IF_TRANSPORT_QUIC_NONBLOCKING CH_BUILD_TRANSPORT_QUIC_NONBLOCKING
#else
#define CH_BUILD_IF_TRANSPORT_QUIC_NONBLOCKING 0U
#endif
#ifdef CH_TRANSPORT_TCP_NONBLOCKING
#define CH_BUILD_IF_TRANSPORT_TCP_NONBLOCKING CH_BUILD_TRANSPORT_TCP_NONBLOCKING
#else
#define CH_BUILD_IF_TRANSPORT_TCP_NONBLOCKING 0U
#endif
#ifdef CH_SUITE_AES_GCM
#define CH_BUILD_IF_SUITE_AES_GCM CH_BUILD_SUITE_AES_GCM
#else
#define CH_BUILD_IF_SUITE_AES_GCM 0U
#endif
#ifdef CH_ROLE_SERVER
#define CH_BUILD_IF_ROLE_SERVER CH_BUILD_ROLE_SERVER
#else
#define CH_BUILD_IF_ROLE_SERVER 0U
#endif
#ifdef CH_EXPORTER
#define CH_BUILD_IF_EXPORTER CH_BUILD_EXPORTER
#else
#define CH_BUILD_IF_EXPORTER 0U
#endif
#ifdef CH_KEYLOG
#define CH_BUILD_IF_KEYLOG CH_BUILD_KEYLOG
#else
#define CH_BUILD_IF_KEYLOG 0U
#endif
#define CH_BUILD_AXES                                                                              \
    (CH_BUILD_IF_TRUST_CA | CH_BUILD_IF_TRUST_WEBPKI | CH_BUILD_IF_PIN_ECDSA |                     \
     CH_BUILD_IF_KEX_PQ | CH_BUILD_IF_TRANSPORT_QUIC_NONBLOCKING |                                 \
     CH_BUILD_IF_TRANSPORT_TCP_NONBLOCKING | CH_BUILD_IF_SUITE_AES_GCM | CH_BUILD_IF_ROLE_SERVER | \
     CH_BUILD_IF_EXPORTER | CH_BUILD_IF_KEYLOG)

// The sizes of the public structs a consumer declares or reads, in
// bytes, and 0 for a struct this build does not declare. A server role
// uses ch_tls, ch_record and ch_quic like a client does, and adds
// ch_rsa_priv, the RSA-PSS private key its ch_identity points at.
#define CH_BUILD_SIZEOF_CH_CFG ((uint32_t)sizeof(ch_cfg))
#define CH_BUILD_SIZEOF_CH_TLS ((uint32_t)sizeof(ch_tls))
#define CH_BUILD_SIZEOF_CH_TICKET ((uint32_t)sizeof(ch_ticket))
#ifdef CH_TRANSPORT_TCP_NONBLOCKING
#define CH_BUILD_SIZEOF_CH_RECORD ((uint32_t)sizeof(ch_record))
#else
#define CH_BUILD_SIZEOF_CH_RECORD 0U
#endif
#ifdef CH_TRANSPORT_QUIC_NONBLOCKING
#define CH_BUILD_SIZEOF_CH_QUIC ((uint32_t)sizeof(ch_quic))
#else
#define CH_BUILD_SIZEOF_CH_QUIC 0U
#endif
#ifdef CH_ROLE_SERVER
#define CH_BUILD_SIZEOF_CH_RSA_PRIV ((uint32_t)sizeof(ch_rsa_priv))
#else
#define CH_BUILD_SIZEOF_CH_RSA_PRIV 0U
#endif

// The bounds a consumer sizes its own buffers from, and 0 for a bound
// this build does not check. CH_TX_STAGE sizes ch_tls.tx. CH_MIN_RXBUF
// is the smallest cfg.buf_len every init call accepts, in every
// transport and role. CH_X509_MAX is the length of the DER buffer
// ch_pubkey_from_pem writes, which only a CA mode exports.
// CH_TRANSPORT_PARAMS_MAX is the longest cfg.transport_params a QUIC
// build accepts. Each of the four sits under #ifndef, so a build can set
// it with a -D of its own, and the axes alone cannot tell two builds
// apart that set it differently.
#define CH_BUILD_TX_STAGE ((uint32_t)CH_TX_STAGE)
#define CH_BUILD_MIN_RXBUF ((uint32_t)CH_MIN_RXBUF)
#ifdef CH_TRUST_CA
#define CH_BUILD_X509_MAX ((uint32_t)CH_X509_MAX)
#else
#define CH_BUILD_X509_MAX 0U
#endif
#ifdef CH_TRANSPORT_QUIC_NONBLOCKING
#define CH_BUILD_TRANSPORT_PARAMS_MAX ((uint32_t)CH_TRANSPORT_PARAMS_MAX)
#else
#define CH_BUILD_TRANSPORT_PARAMS_MAX 0U
#endif

// The record. Every field is a uint32_t, so the struct has no padding
// and the same layout in every language that reads it. Each field holds
// the value of the CH_BUILD_ macro of the same name, computed under the
// object's defines.
typedef struct {
    uint32_t version;              // CH_BUILD_VERSION
    uint32_t axes;                 // CH_BUILD_AXES
    uint32_t sizeof_ch_cfg;        // CH_BUILD_SIZEOF_CH_CFG
    uint32_t sizeof_ch_tls;        // CH_BUILD_SIZEOF_CH_TLS
    uint32_t sizeof_ch_ticket;     // CH_BUILD_SIZEOF_CH_TICKET
    uint32_t sizeof_ch_record;     // CH_BUILD_SIZEOF_CH_RECORD
    uint32_t sizeof_ch_quic;       // CH_BUILD_SIZEOF_CH_QUIC
    uint32_t sizeof_ch_rsa_priv;   // CH_BUILD_SIZEOF_CH_RSA_PRIV
    uint32_t tx_stage;             // CH_BUILD_TX_STAGE
    uint32_t min_rxbuf;            // CH_BUILD_MIN_RXBUF
    uint32_t x509_max;             // CH_BUILD_X509_MAX
    uint32_t transport_params_max; // CH_BUILD_TRANSPORT_PARAMS_MAX
} ch_build_info;

#ifndef __cplusplus
_Static_assert(sizeof(ch_build_info) == 12 * sizeof(uint32_t),
               "ch_build_info holds twelve uint32_t fields and no padding");
#endif

// The record of the object this program links, defined in build.c. Its
// symbol name is the type's name followed by the object's transport,
// because one image may link one object of each transport and two
// definitions of one name do not link: ch_build_info_tcp_blocking,
// ch_build_info_tcp_nonblocking or ch_build_info_quic_nonblocking.
// ch_build is the name of the one the defines in force here select, so
// ch_build_matches(&ch_build) reads the record of the object whose
// headers this translation unit compiles against.
//
// Zig's translate-c turns the macro into a constant initialized from an
// extern variable, which Zig refuses to evaluate, so a Zig program writes
// the transport's name itself: &c.ch_build_info_tcp_nonblocking, not
// &c.ch_build.
#ifdef CH_TRANSPORT_QUIC_NONBLOCKING
#define ch_build ch_build_info_quic_nonblocking
#elif defined(CH_TRANSPORT_TCP_NONBLOCKING)
#define ch_build ch_build_info_tcp_nonblocking
#else
#define ch_build ch_build_info_tcp_blocking
#endif
extern const ch_build_info ch_build;

// Whether b holds the values this translation unit's headers compute: 1
// when every field matches, 0 otherwise. A consumer passes &ch_build. It
// reads b and nothing else, and it compares version first, so a record
// in another format compares unequal before any later field is read, and
// a header newer than the object never reads past the end of the
// object's shorter record.
static inline int ch_build_matches(const ch_build_info *b) {
    return b->version == CH_BUILD_VERSION && b->axes == CH_BUILD_AXES &&
           b->sizeof_ch_cfg == CH_BUILD_SIZEOF_CH_CFG &&
           b->sizeof_ch_tls == CH_BUILD_SIZEOF_CH_TLS &&
           b->sizeof_ch_ticket == CH_BUILD_SIZEOF_CH_TICKET &&
           b->sizeof_ch_record == CH_BUILD_SIZEOF_CH_RECORD &&
           b->sizeof_ch_quic == CH_BUILD_SIZEOF_CH_QUIC &&
           b->sizeof_ch_rsa_priv == CH_BUILD_SIZEOF_CH_RSA_PRIV &&
           b->tx_stage == CH_BUILD_TX_STAGE && b->min_rxbuf == CH_BUILD_MIN_RXBUF &&
           b->x509_max == CH_BUILD_X509_MAX &&
           b->transport_params_max == CH_BUILD_TRANSPORT_PARAMS_MAX;
}

#endif
