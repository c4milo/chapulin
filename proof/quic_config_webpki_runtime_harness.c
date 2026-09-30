// The AES=runtime variant of the quic_config_webpki_suite proof: the same
// harness over the configuration rules of the QUIC client whose object
// holds the AES instructions and the table, which add the caller's answer
// about the instructions, ch_cfg.aes_instructions (cfg.h,
// docs/decisions.md 81). The answer is any byte. The launch line passes
// the suite define and the statement ct.h requires beside AES=runtime, and
// no AES source: the rules compare bytes and code points and run no
// cipher. A proof name is one launch line, so the variant gets its own
// file, as quic_config_webpki_suite does.
#if !defined(CH_AES_RUNTIME) || !defined(CH_SUITE_AES_GCM) || !defined(CH_TRUST_WEBPKI)
#error                                                                                             \
    "quic_config_webpki_runtime proves the AES=runtime answer rule; its launch line must pass -DCH_AES_RUNTIME -DCH_SUITE_AES_GCM -DCH_TRUST_WEBPKI"
#endif
#include "quic_config_webpki_harness.c"
