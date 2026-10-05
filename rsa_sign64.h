// RSA-PSS signing on 64-bit limbs: the signer a host object
// (-DCH_CPU_RUNTIME, cpu_cfg.h) runs for a session whose ch_cfg.cpu holds
// CH_CPU_CONSTANT_TIME_MULTIPLY, as x25519_wide.c is the X25519 such a
// session runs (docs/decisions.md 95). widemul.h calls this file's
// entries for that session alone. A session without the bit runs
// rsa_sign.c's ladder on ct.h's 16x16 decomposition, and a device object
// holds that ladder alone.
//
// It signs what rsa_sign.c signs: the same key and the same encoded
// message give the same bytes. rsa_sign.c stays the reference, and
// bin/rsa_sign_equiv_test compares the two.
//
// What differs is how the private operation runs. It is two
// exponentiations, one modulo each prime with dp and dq, joined by the
// Chinese remainder theorem, where the ladder runs one modulo n with d:
// each is over a modulus of half the length and an exponent of half the
// length. The limbs are rsa_mont64.c's, 64 bits each, on the 64x64->128
// multiply the session's bit states. Each exponent is read four bits at a
// time against a table of the base's first sixteen powers: four squarings
// and one multiplication for four bits, where the ladder runs four of
// each.
//
// The check. rsa_sign64_sp1 raises the signature it computed to the
// public exponent and compares the result with the encoded message before
// it writes a byte of the signature. A fault in either half, or a key
// whose five CRT integers do not belong to its modulus, gives a value
// that differs from the signature modulo one prime alone, and one such
// value with the message is enough to factor the modulus (Boneh, DeMillo
// and Lipton). So a signature that fails the check is an error: the call
// returns 0, writes nothing to sig, and the session fails closed
// (srv_auth.c). The check costs one public operation, which is one part
// in twenty of a signature.
//
// What the constant-time claim covers. A step runs the same four
// squarings, the same read of the table and the same multiplication
// whatever the four bits are. The read touches all sixteen entries and
// keeps one by a mask, so no memory index comes from an exponent. The
// step count is two for each byte of an exponent, leading zero bytes
// included, so neither an exponent's value nor its bit length changes how
// long a signature takes. The reduction of the message modulo each prime
// and the recombination select with masks and never an if. Every product
// is one ct_mul128, whose timing is the caller's statement. Two verdicts
// leave by a branch, and a caller sees both anyway: whether the key is
// one this file signs with, and whether the signature passed its check.
//
// What a compiler may do with a mask is part of that claim. A mask that
// keeps one table entry is all ones at one position, and clang for x86-64
// compiled the first form of that read to a branch on the digit and a
// read of the one entry that matched. So the read hides each mask behind
// a volatile pointer (rsa_sign64.c, table_select). What holds this, and
// every other select in the two files, is make lint-wide-multiply's count
// of the conditional branches two compilers' builds have, a Semgrep rule
// on the read, and a reading of the assembly of nine builds, which INV-16
// names (docs/invariants.md). A build outside those nine has the rule and
// the counts, and no such reading.
//
// What is wiped. Every array this file and rsa_mont64.c hold a value
// computed from the key in is wiped before its function returns, and on
// both verdicts of the check: a candidate that failed is as secret as a
// prime. bin/rsa_sign_equiv_test copies the stack after a signature, after
// a refused one, after the key test and after each piece on its own, and
// looks for each such value. It also makes each of those calls under two
// secrets a caller cannot tell apart and requires the two stacks equal in
// every byte, which holds a value too short to look for: the first form
// of the table read left the four bits of an exponent its last step read,
// in a register that a later call saved in its frame.
//
// What the wipes do not cover. A wipe names an array, not a register. The
// registers no callee saves hold what the last arithmetic left in them
// when a signature returns, and code that runs later may store them:
// Darwin's stack probe stores two. And a compiler that was not asked to
// optimize keeps every local in its frame, where no wipe names it, so
// that test makes no run over the stack in such a build, nor under
// AddressSanitizer (test/stack_residue.c).
//
// What it does not cover is what rsa_sign.h says of the ladder: this
// file blinds nothing, so it does not answer an attacker who measures
// power or emissions over many signatures. The check answers a fault
// that changes the signature. It does not answer one that skips the
// check itself.
#ifndef CH_RSA_SIGN64_H
#define CH_RSA_SIGN64_H

#include <stddef.h>
#include <stdint.h>

#include "rsa_mont64.h"
#include "rsa_sign.h"

#ifdef CH_CPU_RUNTIME

// Whether k is a key rsa_sign64_pss signs with: one rsa_pss_sign_key_ok
// admits whose p and q multiply to n. The modulus is odd and has its top
// bit set, so that product also says each prime is odd and has the top
// bit of its n_len / 2 bytes, which the arithmetic here needs. It says
// nothing of dp, dq and qinv: a wrong one gives a signature that fails
// its check, which rsa_sign64_sp1 refuses to return, and a server signs
// once with each key when it checks its configuration (srv_auth.h), so a
// key with a wrong one is refused there.
//
// p and q are secret. The product is computed and compared in constant
// time, and the answer is the one thing that leaves. rsa_sign64_pss runs
// this first, and a server runs it when it checks its configuration.
// Returns 1 or 0.
int rsa_sign64_key_ok(const ch_rsa_priv *k);

// rsa_pss_sign (rsa_sign.h) on this file's private operation, under the
// same contract, with one more way to return 0: a signature that failed
// its check, after which sig holds what it held before. rsa_sign64.c
// compiles it from rsa_sign.c, so the test of cap and the PSS encoder are
// that file's for both signers.
int rsa_sign64_pss(const ch_rsa_priv *k, const uint8_t msg_hash[32],
                   const uint8_t salt[RSA_PSS_SALT_LEN], uint8_t *sig, size_t cap, size_t *sig_len);

// rsa_sp1 (rsa_sign.h) by the Chinese remainder theorem: sig = em^d mod
// n, computed from p, q, dp, dq and qinv, with em and sig both n_len
// big-endian bytes, for a key rsa_sign64_key_ok admits and an em below n.
// Returns 1 when the signature passed its check and was written, and 0
// when it failed, with no byte of sig written. Not part of the public
// API.
int rsa_sign64_sp1(const ch_rsa_priv *k, const uint8_t *em, uint8_t *sig);

// o = base^e mod m, in the Montgomery domain of mod: base is a Montgomery
// form below m and o takes one. e is e_len big-endian bytes, every one of
// which is read. mod is at most a prime's limbs, half of
// RSA_MONT64_LIMBS_MAX. o may be base. It is an entry of its own so that
// bin/rsa_sign_equiv_test can hold the exponentiation to rsa_sign.c's
// ladder over any modulus and any exponent. Not part of the public API.
void rsa_sign64_power(uint64_t *o, const uint64_t *base, const uint8_t *e, size_t e_len,
                      const rsa_mont64_modulus *mod);

#endif // CH_CPU_RUNTIME

#endif
