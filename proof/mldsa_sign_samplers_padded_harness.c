// The padded form of RejBoundedPoly's passes, which a host object compiles
// (docs/decisions.md 200): the passes run over 976 positions of an array of
// 992 entries, whose entries from 962 up are zero. See
// mldsa_sign_samplers_harness.c for what it proves.
#define MLDS_ETA_PADDED 1
#include "mldsa_sign_samplers_harness.c"
