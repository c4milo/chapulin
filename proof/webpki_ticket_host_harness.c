// The host-object variant of the webpki_ticket proof: the same harness
// in an object built with -DCH_CPU_RUNTIME. There webpki_ticket.c's host
// arm hashes and binds on the SHA-256 path that ch_cfg.cpu names
// (docs/decisions.md 132). A proof name is one launch line, so the
// variant gets its own file, the quic_config_webpki_suite precedent.
#ifndef CH_CPU_RUNTIME
#error "webpki_ticket_host proves the host arm; its launch line must pass -DCH_CPU_RUNTIME"
#endif
#include "webpki_ticket_harness.c"
