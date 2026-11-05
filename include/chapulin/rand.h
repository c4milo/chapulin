// Where the library's random bytes come from. The build declares one of
// three patterns (cfg.h, docs/entropy.md):
//
//   RAND=extern   the image defines ch_rand_bytes below: a hardware RNG,
//                 or a generator of its own.
//   RAND=drbg     drbg.[ch] defines it, the seeded generator a part
//                 without an RNG uses, and the image seeds it at boot.
//   RAND=session  each session's ch_cfg names a source of its own, which
//                 the library calls as rand_bytes(rand_io, p, n). No
//                 object declares, defines or calls ch_rand_bytes.
//
// Every library draw goes through rand_draw (rand_draw.h), which calls
// the one source the pattern names.
//
// The contract, whichever the source. It writes n random bytes at p and
// returns nothing. It must not fail: a device without entropy has no
// business starting a handshake, so a source that cannot fill p blocks
// or stops the program rather than return. In production it is a
// cryptographically strong generator. A bare counter or a clock is not a
// source, and neither is a deterministic stream, which gives predictable
// keys to anyone who knows its seed: a seeded stream that replays a
// connection is for tests alone.
//
// ch_rand_bytes is defined once for every chapulin object an image
// links, and it must be safe to call from several threads at once
// (docs/porting.md, "Linking two transports into one image"). Under
// RAND=session a session draws from its own source alone, so the library
// holds no entropy state that sessions share, and sessions on different
// threads need no lock unless their sources share state of their own.
// rand_io is handed to rand_bytes unread and may be NULL. A session copies
// both fields with the rest of ch_cfg, so what rand_io points at must
// outlive the session. Every init call and ch_srv_check refuse a NULL
// rand_bytes with CH_EINVAL, before a byte is sent.
//
// An image's hook may include this header with none of the library's
// build defines, so this header includes no other header of the
// library's. The host tests use the OS entropy source, and the
// RAND=session builds of the loop tests a seeded stream per session
// (test/rand_session.h).
#ifndef CH_RAND_H
#define CH_RAND_H

#include <stddef.h>
#include <stdint.h>

// A RAND=session object neither defines nor imports the hook, so this
// header declares it only for the other two patterns.
#ifndef CH_RAND_SESSION
void ch_rand_bytes(uint8_t *p, size_t n);
#endif

#endif
