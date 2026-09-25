// The halves test/lib-pair-check.sh links into one image, one per
// transport (test/lib_pair_half.c). Each is named for its transport, as
// the build record it reads is (build.h), because an image holds at most
// one object of each transport. Each returns 0 when the object it was
// compiled for answered every step as its headers say, and 1 after it
// names the step that did not.
#ifndef LIB_PAIR_H
#define LIB_PAIR_H

#include <stdint.h>

int lib_pair_tcp_blocking(void);
int lib_pair_tcp_nonblocking(void);
int lib_pair_quic_nonblocking(void);

#ifdef LIB_PAIR_KEYLOG
// The key log hook a KEYLOG=on object imports. keylog.h declares it only
// under that object's defines, and test/lib_pair_main.c, which defines
// it, compiles under no object's defines, so the declaration is repeated
// here.
void ch_keylog(void *io, const char *label, const uint8_t client_random[32],
               const uint8_t secret[32]);
#endif

#endif
