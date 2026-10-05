// The wipe of the stack a wide P-256 call used (docs/decisions.md 94).
//
// Every wide routine wipes the objects it names through ct_wipe. A compiler also keeps values
// in stack slots of its own, which no ct_wipe can name: the registers a function saves when it
// is called, and whatever does not fit in registers. On arm64 the wide field multiply keeps
// every limb in registers. On x86-64, which has half as many, Apple clang 21 keeps ten limbs of
// each multiply in such slots, and bin/p256_equiv_test found a limb of a shared secret and a
// limb of a nonce's inverse there after the calls returned.
//
// So widemul.h calls p256_wide_wipe_below after each wide call whose operands are secret. The
// frames of that call, and of every call it made, lay in the stack right under the frame of
// the function widemul.h's dispatcher is compiled into. p256_wide_wipe_below's own frame lies
// in the same place, and it holds one array of P256_WIDE_BELOW_LEN bytes, which it wipes.
// bin/p256_equiv_test measures how far below its caller each wide call writes and requires it
// inside that array, and then looks in the stack for the limbs the call must not leave behind
// (test/p256_equiv_residue.h).
//
// What this does not clear: a register, which holds what the last instruction left in it until
// another writes it, as it does after every wipe written in C.
#ifndef CH_P256_WIDE_WIPE_H
#define CH_P256_WIDE_WIPE_H

#ifdef CH_CPU_RUNTIME

// The bytes of stack p256_wide_wipe_below wipes. The deepest wide call, p256_wide_mul, holds
// eight multiples of its point and writes at most 1,872 bytes below its caller on the
// compilers bin/p256_equiv_test runs under, and lint-stack holds a frame of a server object
// under 2,560.
#define P256_WIDE_BELOW_LEN 2400

// Writes zero over the P256_WIDE_BELOW_LEN bytes of stack under the caller's frame.
void p256_wide_wipe_below(void);

#endif // CH_CPU_RUNTIME

#endif
