// The counts of the configuration hashes and the bindings that
// webpki_ticket.c runs (docs/decisions.md 132). Four test binaries link
// test/webpki_ticket_count.c in place of webpki_ticket.c:
//   - bin/webpki_session_test and bin/webpki_session_host, for ch_connect;
//   - bin/webpki_loop_aes, for ch_record_init and a received ticket;
//   - bin/quic_loop_aes, for ch_quic_init and a received ticket.
// That file counts the last call of each hash and the one call of each
// binding. So a count holds every hash and every binding: the init
// calls' hashes, the check of a presented ticket in webpki_resumption_ok,
// the bindings handshake_post.c gives to received tickets, and the
// test's own calls. The library's other sources run unchanged, and each
// hash runs on the path its cpu value names.
//
// The names are these tests' alone, as test/hash_runtime_count.h's are.
#ifndef CH_TEST_WEBPKI_TICKET_COUNT_H
#define CH_TEST_WEBPKI_TICKET_COUNT_H

#include <stdint.h>

// The configuration hashes webpki_ticket.c ran, and the cpu value of the
// last one.
extern unsigned long webpki_ticket_config_hash_calls;
extern uint32_t webpki_ticket_config_hash_cpu;
// The bindings webpki_ticket.c ran, and the cpu value of the last one.
extern unsigned long webpki_ticket_binding_calls;
extern uint32_t webpki_ticket_binding_cpu;

#endif
