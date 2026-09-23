// The SUITE=aesgcm TRUST=webpki variant of the handshake_parser proof:
// the same harness over the ServerHello parser of the client that offers
// both cipher suites (docs/decisions.md entry 45), where cipher_suite
// may carry TLS_AES_128_GCM_SHA256 as well as ChaCha20. The launch line
// passes the suite define and the two ct.h requires beside it, and no
// AES source: the parser compares a code point and runs no cipher. A
// proof name is one launch line, so the variant gets its own file, the
// hello_build_webpki precedent.
#if !defined(CH_SUITE_AES_GCM) || !defined(CH_TRUST_WEBPKI)
#error                                                                                             \
    "handshake_parser_suite proves the two-suite arm; its launch line must pass -DCH_SUITE_AES_GCM -DCH_TRUST_WEBPKI"
#endif
#include "handshake_parser_harness.c"
