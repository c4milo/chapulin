// sha512.c's second arm, which a device object holds, in a host test binary
// (test/sha512_portable.c): the seven calls of sha512.h under second names.
// Each has the contract of the call it is named for, on the same context
// type, and the two arms keep the same state in it.
#ifndef CH_TEST_SHA512_PORTABLE_H
#define CH_TEST_SHA512_PORTABLE_H

#include <stddef.h>
#include <stdint.h>

#include "sha512.h"

void sha512_init_portable(sha512 *s);
void sha384_init_portable(sha512 *s);
void sha512_update_portable(sha512 *s, const uint8_t *in, size_t n);
void sha512_final_portable(sha512 *s, uint8_t out[SHA512_LEN]);
void sha384_final_portable(sha512 *s, uint8_t out[SHA384_LEN]);
void sha512_of_portable(const uint8_t *in, size_t n, uint8_t out[SHA512_LEN]);
void sha384_of_portable(const uint8_t *in, size_t n, uint8_t out[SHA384_LEN]);

#endif
