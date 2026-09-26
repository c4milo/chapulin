// chapulin's server API: a TLS 1.3 server for the same devices the
// client targets, built with ROLE=server. It speaks one profile —
// TLS_CHACHA20_POLY1305_SHA256 over the X25519MLKEM768 hybrid, or over
// x25519 for a client that does not list the hybrid, with the server
// authenticated by a certificate chain the caller provisioned and the
// client authenticated by nothing. ch_tls.group reports which group ran
// (srv_kex.h). Zero heap: the session struct, the caller's receive buffer and the
// caller's own chains and keys are the entire working set.
//
// Five calls, not two. ch_read, ch_write and ch_close are the same
// functions in the same file as the client's and keep their tls.h
// contracts exactly, because record.[ch] names no side: rec_seal
// writes application_data unconditionally and rec_open refuses any
// other outer type. One name per thing, so a server's read is
// ch_read. The two calls below are what a server adds, and
// ch_connect is what it drops: tls.h declares that one only when
// CH_ROLE_SERVER is unset, so a server firmware that calls it fails to
// compile rather than to link.
//
// What this build does not meet, stated here rather than discovered
// later. RFC 9846 §9.1 requires TLS_AES_128_GCM_SHA256 and recommends
// TLS_AES_256_GCM_SHA384 beside the suite above. This build offers
// neither, because the only AES in this tree is the software S-box
// table in aes.c, which is admitted for QUIC Initial keys because
// those keys are public, and a TLS traffic key is secret: that table
// would leak it through cache timing. A client that offers only an
// AES-GCM suite gets handshake_failure. The suites drop in when a
// constant-time AES exists, and this header claims no §9.1 conformance
// before then. §9.1 also requires secp256r1 for the key
// exchange, which this build does not offer either, for the reason
// srv_parser.h gives at SRV_GROUP_X25519.
//
// What it declines conformantly, each with the permission it takes: no
// client certificates (§4.4.2 makes the request a MAY), no 0-RTT (it
// takes the first behavior §4.3.10 permits and answers 1-RTT), no
// post-handshake authentication (§4.7.2 makes it a MAY), and no
// requirement that the client send server_name (§9.2 makes requiring
// it a MAY). docs/server.md lists every one with its RFC line.
//
// It resumes. With cfg.srv.ticket_key and cfg.srv.now_seconds set, it
// issues one NewSessionTicket after every handshake and accepts its own
// tickets as PSKs under psk_dhe_ke, with a key exchange and no
// Certificate; ch_tls.psk_selected tells a resumed session from a full
// one. srv_resume.h states the rules and srv_ticket.h the ticket.
#ifndef CH_SRV_H
#define CH_SRV_H
#ifdef CH_ROLE_SERVER

#include "cfg.h"
#include "tls.h"

// Runs the full handshake as the server, over a connection the caller
// has already accepted and the same blocking I/O callbacks and
// ch_rand_bytes a client build needs. On CH_OK the session is ready
// for ch_read and ch_write. Any error sends the alert the failure
// chose, wipes all key material and leaves the session dead.
//
// It checks the configuration before it reads a byte and returns
// CH_EINVAL, having sent nothing, when: no identity is provisioned;
// cfg.srv.cookie_key is NULL, because §9.2 makes the cookie extension
// mandatory to implement and a stateless HelloRetryRequest cannot be
// minted without that key; cfg.buf or cfg.send or cfg.recv is NULL;
// cfg.buf_len is below the floor this build needs; cfg.srv.sni_cap is
// not 0 while cfg.srv.sni_buf is NULL; cfg.srv.require_server_name is
// set while cfg.srv.sni_buf is NULL, because a server that requires a
// name it cannot report would refuse every client silently; or the
// ALPN list breaks the rules cfg.h states for it.
//
// A NULL cfg.srv.ticket_key or a cfg.srv.now_seconds of 0 is not
// refused: the server then issues no ticket and accepts none, and every
// handshake authenticates with a certificate.
//
// It returns CH_EINVAL for the client-only fields too, rather than
// ignoring them: cfg.psk, cfg.psk_id, cfg.resumption, either
// server_pubkey slot, cfg.require_pq and the epoch callbacks all
// answer "do I trust this peer", which a server that judges no peer
// key never asks. That is the fail-closed shape a TRUST=webpki build
// already uses for the pin fields.
//
// The receive buffer floor is the one bound this API leaves open. A
// ClientHello is bounded by cfg.buf_len and by nothing else, so a
// device that passes a small buffer serves the clients whose hellos
// fit it and answers CH_ECAP to the rest. The floor constant is not
// declared yet, because no measurement exists: docs/server.md's
// "Bounds that need measuring" names bench/sram.sh as what produces
// it, and this header will state the number rather than an estimate.
int ch_srv_accept(ch_tls *t, const ch_cfg *cfg);

// Checks at boot that this build can sign with each provisioned
// private key and that each result verifies under the public key in
// the same slot. Runs no I/O and touches no session.
//
// It is the boot-time replacement for parsing the chain: it catches a
// broken signer and a key the operator paired with the wrong slot
// once, at boot, with a local error code, instead of a client-side
// alert on every connection. It reads no chain bytes, so it catches
// neither a chain whose end-entity key is not the provisioned public
// key nor a fallback chain signed with SHA-1; a provisioning script
// does both off the device.
//
// Returns CH_OK when at least one identity is provisioned and every
// provisioned identity signed and verified. Returns CH_EINVAL for a
// configuration that cannot serve: no identity at all, or a slot whose
// signer refused or whose signature the verifier rejected. It does not
// report which slots are live, because its result is one code; a
// caller that needs to know reads its own ch_cfg.
//
// Every server object exports it, so its symbol name carries the
// object's transport, as the build record's does (build.h): an image
// that links a tcp-nonblocking server and a QUIC server holds one of each,
// and each reads the ch_cfg layout of its own transport
// (docs/decisions.md 61).
#ifdef CH_TRANSPORT_QUIC_NONBLOCKING
#define ch_srv_check ch_srv_check_quic_nonblocking
#elif defined(CH_TRANSPORT_TCP_NONBLOCKING)
#define ch_srv_check ch_srv_check_tcp_nonblocking
#else
#define ch_srv_check ch_srv_check_tcp_blocking
#endif
int ch_srv_check(const ch_cfg *cfg);

#endif // CH_ROLE_SERVER
#endif
