// The SUITE=aesgcm TRUST=webpki variant of the hello_build proof: the same
// harness over the builder of the client that offers three cipher
// suites, in suite.h's default order or in the order ch_cfg.cipher_suites
// names (docs/decisions.md 80), and whose ticket may carry a SHA-384
// binder, against that build's CH_HELLO_MAX. The launch line passes the
// suite define and the two ct.h requires beside it, and no AES source:
// the builder writes code points and runs no cipher. A proof name is one
// launch line, so the variant gets its own file, the hello_build_webpki
// precedent.
#if !defined(CH_SUITE_AES_GCM) || !defined(CH_TRUST_WEBPKI)
#error                                                                                             \
    "hello_build_suite proves the three-suite builder; its launch line must pass -DCH_SUITE_AES_GCM -DCH_TRUST_WEBPKI"
#endif
#include "hello_build_harness.c"
