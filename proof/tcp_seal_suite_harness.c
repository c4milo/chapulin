// Proves proof/tcp_seal_harness.c's claims again in the -DCH_SUITE_AES_GCM
// build, which proof/run.sh's tcp_seal_suite launch line passes, with the
// write key's suite and sequence number unconstrained. There
// records_per_key and records_before_key_update read the suite, so the
// formula covers an AES-GCM write key at every sequence number below its
// ceiling and past it, and the KeyUpdate a key that cannot seal a whole
// write needs first (docs/decisions.md 248).
#include "tcp_seal_harness.c"
