// The host-object variant of the pem_files proof: the same harness in an
// object built with -DCH_CPU_RUNTIME, where ch_p256_key_from_pem takes a
// cpu value with CH_CPU_PROBED and refuses a bit the architecture does not
// define, and computes the point under the multiply answer the value
// gives (docs/decisions.md 131). A proof name is one launch line, so the
// variant gets its own file, the quic_config_webpki_suite precedent.
#ifndef CH_CPU_RUNTIME
#error                                                                                             \
    "pem_files_host proves the host object's cpu rule; its launch line must pass -DCH_CPU_RUNTIME"
#endif
#include "pem_files_harness.c"
