// The host-object variant of the pem_files_rsa proof: the same harness in
// an object built with -DCH_CPU_RUNTIME, where ch_rsa_key_from_pem takes a
// cpu value with CH_CPU_PROBED, keeps the five CRT values in the key, and
// signs with rsa_sign64.c too under CH_CPU_CONSTANT_TIME_MULTIPLY
// (docs/decisions.md 184). A proof name is one launch line, so the variant
// gets its own file, as pem_files_host does.
#ifndef CH_CPU_RUNTIME
#error "pem_files_rsa_host proves the host object's key; its launch line must pass -DCH_CPU_RUNTIME"
#endif
#include "pem_files_rsa_harness.c"
