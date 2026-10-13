// The QUIC variant of the gcm_avx512_wipe proof: the same harness compiled as a QUIC host object
// without SUITE=aesgcm compiles gcm_avx512.c, whose entries then call the AES-128 functions
// alone. A proof name is one launch line, so the variant gets its own file, the rsa_mul_webpki
// precedent.
#include "gcm_avx512_wipe_harness.c"
