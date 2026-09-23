// The key log: each traffic secret a handshake derives, handed to the
// image as it is derived, so a tool that reads the NSS key log format
// can decrypt a capture of the connection. colibri's interop endpoint
// writes these lines to SSLKEYLOGFILE; chapulin writes nothing itself,
// because it does no I/O the caller did not supply.
//
// This is the one place a secret leaves chapulin on purpose, and the
// KEYLOG axis exists so that no build carries it by accident. It is off
// by default, and a device client build refuses it: the header below
// and the Makefile stop a raw or ca trust mode with ROLE=client, which
// is what a pinned firmware image is. docs/decisions.md 44 states what
// the axis admits and why the server's TRUST=none is among them.
//
// The hook is defined by the image, the way rand.h's ch_rand_bytes is:
// a KEYLOG=on object leaves ch_keylog undefined, so an image that turned
// the axis on and wired nothing fails to link rather than logging into
// nowhere. io is the session's cfg.io, so one hook can tell connections
// apart. client_random is the ClientHello's random on both ends, which
// is the key the format files each line under. The call must not fail
// and must not block: it runs inside the handshake step that derived
// the secret.
#ifndef CH_KEYLOG_H
#define CH_KEYLOG_H
#ifdef CH_KEYLOG

// A client in a device trust mode: no server role, and a trust mode
// other than webpki, which is the host-side one. CH_TRUST_CA and the
// raw modes set no define that says "device", so the test is the
// absence of both host markers.
#if !defined(CH_ROLE_SERVER) && !defined(CH_TRUST_WEBPKI)
#error "CH_KEYLOG is refused for a device client: build TRUST=webpki, ROLE=server or ROLE=both"
#endif

#include <stdint.h>

#include "sha256.h"

// The client random's length. It is the same 32 bytes both ends read
// from one ClientHello (RFC 9846 §4.1.2).
#define CH_KEYLOG_RANDOM_LEN 32

// The four labels, spelled as the NSS key log format spells them. A
// KeyUpdate derives a new traffic secret, and the format has no label
// for it: a reader derives the next generation from the _0 secret.
#define CH_KEYLOG_CLIENT_HANDSHAKE "CLIENT_HANDSHAKE_TRAFFIC_SECRET"
#define CH_KEYLOG_SERVER_HANDSHAKE "SERVER_HANDSHAKE_TRAFFIC_SECRET"
#define CH_KEYLOG_CLIENT_TRAFFIC "CLIENT_TRAFFIC_SECRET_0"
#define CH_KEYLOG_SERVER_TRAFFIC "SERVER_TRAFFIC_SECRET_0"

void ch_keylog(void *io, const char *label, const uint8_t client_random[CH_KEYLOG_RANDOM_LEN],
               const uint8_t secret[SHA256_LEN]);

#endif // CH_KEYLOG
#endif
