// The SUITE=aesgcm variant of the quic_config_webpki proof: the same
// harness over the configuration rules of the QUIC client that offers
// three cipher suites, which add the client's suite list,
// ch_cfg.cipher_suites (webpki_cfg.h, docs/decisions.md 80). The launch
// line passes the suite define and the two ct.h requires beside it, and no
// AES source: the rules compare code points and run no cipher. A proof
// name is one launch line, so the variant gets its own file, the
// hello_build_webpki precedent.
#if !defined(CH_SUITE_AES_GCM) || !defined(CH_TRUST_WEBPKI)
#error                                                                                             \
    "quic_config_webpki_suite proves the suite list rule; its launch line must pass -DCH_SUITE_AES_GCM -DCH_TRUST_WEBPKI"
#endif
#include "quic_config_webpki_harness.c"
