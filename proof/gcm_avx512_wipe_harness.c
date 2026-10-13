// Proves: gcm_seal_avx512 and gcm_open_avx512 (gcm_avx512.c) are memory-safe and UB-free for
// each round count gcm_avx512.h admits and for associated data and text up to 2^32 bytes, in
// separate buffers or in place, and each one:
//
//   - calls the kernel's function for its direction and its round count once, with its own
//     arguments: the AES-128 function for AES_128_ROUNDS and the AES-256 function for
//     AES_256_ROUNDS;
//   - then wipes GCM_AVX512_BELOW_LEN bytes once, through wipe_frame, and the wipe covers
//     wipe_frame's array and no byte outside it;
//   - then calls avx512_wipe_registers once.
//
// The kernel's four functions, ct_wipe and avx512_wipe_registers are stubs, defined here before
// gcm_avx512.c, and each records its call. Each kernel stub asserts what gcm_avx512_kernel.h
// requires of its pointers at its own key size, so AES-128 round keys handed to an AES-256
// function fail a read check, and the harness compares the call it records with the call it
// made. The kernel stubs write nothing: neither entry reads what the kernel writes. ct_wipe is
// proof/ct_wipe_stub.c's loop of bounds-checked stores, so the wipe writes inside wipe_frame's
// array, and the unwinding assertion on that loop proves it ran the length the stub records and
// no more. ct_wipe and the register wipe's stub each require the calls before them.
//
// The launch lines define CH_GCM_AVX512_MODEL, which opens gcm_avx512.c's x86-64 guard on the
// machine cbmc runs on: cbmc takes its preprocessor from that machine, clang's for arm64 on a
// Mac. gcm_avx512_wipe compiles a build with AES-256, and gcm_avx512_wipe_quic one without,
// whose entries call the AES-128 functions alone.
//
// CBMC reads the volatile pointer as the value it was initialized with, wipe_frame, as
// proof/ct_wipe_harness.c says of ct_wipe.c's pointer.
//
// Not proven here, and not a property of C: that the array lies where the kernel's frames lay.
// bin/gcm_avx512_equiv_test measures that on each compiler it runs under
// (test/gcm_avx512_residue.h). Nothing here reads the kernel, which CBMC cannot read.
#include "harness.h"

#include <stdlib.h>

#include "aes.h"

// The longest associated data and text the harness takes, 2^32 bytes.
#define WIPE_LEN_MAX ((size_t)1 << 32)

// The kernel call the stubs saw.
typedef struct {
    int calls;
    int open;
    size_t rounds;
    const uint8_t *round_keys;
    const uint8_t *nonce;
    const uint8_t *aad;
    size_t aad_len;
    const uint8_t *in;
    size_t n;
    uint8_t *out;
    uint8_t *tag;
} kernel_call;

static kernel_call seen;
static int wipes;
static size_t wipe_len;
static int register_wipes;

// What gcm_avx512_kernel.h requires of a call at rounds rounds, asserted, and the call recorded.
static void kernel_stub(int open, size_t rounds, const uint8_t *round_keys, const uint8_t *nonce,
                        const uint8_t *aad, size_t aad_len, const uint8_t *in, size_t n,
                        uint8_t *out, uint8_t *tag) {
    __CPROVER_assert(__CPROVER_r_ok(round_keys, (rounds + 1) * AES_BLOCK),
                     "kernel: the round keys of its key size readable");
    __CPROVER_assert(__CPROVER_r_ok(nonce, AES_IV), "kernel: the nonce readable");
    __CPROVER_assert(aad_len == 0 || __CPROVER_r_ok(aad, aad_len),
                     "kernel: the associated data readable");
    __CPROVER_assert(n == 0 || __CPROVER_r_ok(in, n), "kernel: the input readable");
    __CPROVER_assert(n == 0 || __CPROVER_w_ok(out, n), "kernel: the output writable");
    __CPROVER_assert(__CPROVER_w_ok(tag, AES_BLOCK), "kernel: the tag writable");
    __CPROVER_assert(register_wipes == 0, "kernel: runs before the register wipe");
    seen.calls++;
    seen.open = open;
    seen.rounds = rounds;
    seen.round_keys = round_keys;
    seen.nonce = nonce;
    seen.aad = aad;
    seen.aad_len = aad_len;
    seen.in = in;
    seen.n = n;
    seen.out = out;
    seen.tag = tag;
}

void gcm_avx512_seal_128(const uint8_t *round_keys, const uint8_t nonce[AES_IV], const uint8_t *aad,
                         size_t aad_len, const uint8_t *pt, size_t n, uint8_t *ct,
                         uint8_t tag[AES_BLOCK]) {
    kernel_stub(0, AES_128_ROUNDS, round_keys, nonce, aad, aad_len, pt, n, ct, tag);
}

void gcm_avx512_open_128(const uint8_t *round_keys, const uint8_t nonce[AES_IV], const uint8_t *aad,
                         size_t aad_len, const uint8_t *ct, size_t n, uint8_t *pt,
                         uint8_t want[AES_BLOCK]) {
    kernel_stub(1, AES_128_ROUNDS, round_keys, nonce, aad, aad_len, ct, n, pt, want);
}

#ifdef CH_AES_256
void gcm_avx512_seal_256(const uint8_t *round_keys, const uint8_t nonce[AES_IV], const uint8_t *aad,
                         size_t aad_len, const uint8_t *pt, size_t n, uint8_t *ct,
                         uint8_t tag[AES_BLOCK]) {
    kernel_stub(0, AES_256_ROUNDS, round_keys, nonce, aad, aad_len, pt, n, ct, tag);
}

void gcm_avx512_open_256(const uint8_t *round_keys, const uint8_t nonce[AES_IV], const uint8_t *aad,
                         size_t aad_len, const uint8_t *ct, size_t n, uint8_t *pt,
                         uint8_t want[AES_BLOCK]) {
    kernel_stub(1, AES_256_ROUNDS, round_keys, nonce, aad, aad_len, ct, n, pt, want);
}
#endif

// proof/ct_wipe_stub.c's loop, with the call recorded. gcm_avx512.c calls ct_wipe from
// wipe_frame alone.
void ct_wipe(void *p, size_t n) {
    __CPROVER_assert(seen.calls == 1 && register_wipes == 0,
                     "stack wipe: runs after the kernel's one call and before the register wipe");
    wipes++;
    wipe_len = n;
    volatile uint8_t *v = (volatile uint8_t *)p;
    for (size_t i = 0; i < n; i++) {
        v[i] = 0;
    }
}

void avx512_wipe_registers(void) {
    __CPROVER_assert(seen.calls == 1 && wipes == 1,
                     "register wipe: runs after the kernel's one call and the stack wipe");
    register_wipes++;
}

#include "gcm_avx512.c"

int main(void) {
    size_t rounds = nondet_size_t();
#ifdef CH_AES_256
    __CPROVER_assume(rounds == AES_128_ROUNDS || rounds == AES_256_ROUNDS);
#else
    __CPROVER_assume(rounds == AES_128_ROUNDS);
#endif
    size_t aad_len = nondet_size_t();
    size_t n = nondet_size_t();
    __CPROVER_assume(aad_len <= WIPE_LEN_MAX && n <= WIPE_LEN_MAX);
    uint8_t nonce[AES_IV];
    uint8_t tag[AES_BLOCK];
    uint8_t *round_keys = malloc((rounds + 1) * AES_BLOCK);
    uint8_t *aad = (aad_len == 0 && (nondet_u8() & 1U) != 0) ? NULL : malloc(aad_len);
    uint8_t *in = malloc(n);
    uint8_t *out = (nondet_u8() & 1U) != 0 ? in : malloc(n);
    __CPROVER_assume(round_keys != NULL && (aad != NULL || aad_len == 0) && in != NULL &&
                     out != NULL);

    int open = (nondet_u8() & 1U) != 0;
    if (open) {
        gcm_open_avx512(round_keys, rounds, nonce, aad, aad_len, in, n, out, tag);
    } else {
        gcm_seal_avx512(round_keys, rounds, nonce, aad, aad_len, in, n, out, tag);
    }

    __CPROVER_assert(seen.calls == 1, "entry: one call of the kernel");
    __CPROVER_assert(seen.open == open, "entry: the kernel's function for its direction");
    __CPROVER_assert(seen.rounds == rounds, "entry: the kernel's function for its round count");
    __CPROVER_assert(seen.round_keys == round_keys && seen.nonce == nonce && seen.aad == aad &&
                         seen.aad_len == aad_len && seen.in == in && seen.n == n &&
                         seen.out == out && seen.tag == tag,
                     "entry: the kernel gets the entry's own arguments");
    __CPROVER_assert(wipes == 1 && wipe_len == GCM_AVX512_BELOW_LEN,
                     "entry: one stack wipe of GCM_AVX512_BELOW_LEN bytes after the kernel");
    __CPROVER_assert(register_wipes == 1, "entry: one register wipe after the stack wipe");
    return 0;
}
