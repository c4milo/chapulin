// The wipe of the stack rsa_sign64.c's private calls used (docs/decisions.md 181).
//
// rsa_sign64.c wipes every array it names through ct_wipe. A compiler also keeps values in stack
// slots of its own, which no ct_wipe can name: the registers a function saves when it is called,
// and whatever does not fit in registers. bin/rsa_sign_equiv_test found such slots that held
// words computed from the primes and the exponents after the calls returned: gcc 15.2 for
// x86-64, on the ubuntu-26.04 runner, left them below rsa_sign64_power, rsa_sign64_sp1, the
// reduction modulo a prime and the recombination, as deep as 12,416 bytes under the caller.
//
// So each of those calls is a wrapper: it calls a body of its own and then rsa_sign64_wipe_below.
// The body's frame, and the frames of every call it made, lay in the stack right under the
// wrapper's frame. rsa_sign64_wipe_below's own frame lies in the same place, and it holds one
// array of RSA_SIGN64_BELOW_LEN bytes, which it wipes. A session on AVX-512 IFMA has its own
// wipe after the kernel, which rsa_ifma_sign.h declares.
//
// What this does not clear: a register, which holds what the last instruction left in it until
// another writes it, as it does after every wipe written in C.
#ifndef CH_RSA_SIGN64_WIPE_H
#define CH_RSA_SIGN64_WIPE_H

#ifdef CH_CPU_RUNTIME

#include "rsa.h"

// The bytes of stack rsa_sign64_wipe_below wipes: 32 for each byte of the modulus bound, 12,288
// at 384 and 16,384 at 512. The deepest call, rsa_sign64_sp1, wrote 12,416 bytes below its
// caller at the 512-byte bound under gcc 15.2 for x86-64. bin/rsa_sign_equiv_test requires
// the stack below each wrapped call equal under two secrets, so a wipe too short fails it.
// lint-stack holds this file's frame under STACK_BUDGET_RSA_SIGN64_WIPE.
#define RSA_SIGN64_BELOW_LEN (32 * CH_RSA_MODULUS_MAX)

// Writes zero over the RSA_SIGN64_BELOW_LEN bytes of stack under the caller's frame.
void rsa_sign64_wipe_below(void);

#endif // CH_CPU_RUNTIME

#endif
