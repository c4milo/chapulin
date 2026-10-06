// What the wide P-256 calls leave on the stack. Each wide routine keeps its
// secrets in objects it names, the 64-bit limbs of a scalar, the powers of
// the nonce, the running points and the coordinates of the product, and
// wipes each through ct_wipe before it returns. The compiler keeps more in
// stack slots of its own, which no ct_wipe can name, so widemul.h calls
// p256_wide_wipe_below after each wide call whose operands are secret
// (p256_wide_wipe.h). A frame is dead after its call returns, but its bytes
// stay in memory below this binary's own frames until another call writes
// over them.
//
// Three checks, each on a copy residue_snapshot takes of the RESIDUE_BYTES
// of stack below its caller, which run_stack runs for every build but a
// sanitizer's:
//
//   run_depth paints that stack, calls each wide entry by its own name, and
//   requires the lowest byte the call wrote within P256_WIDE_BELOW_LEN of
//   its caller, so the wipe covers every frame the call used.
//
//   run_wiped calls each of the six dispatchers in widemul.h that hand a
//   wide entry a secret, and requires the stack below each call to hold zero
//   for nearly that length, so the wipe ran and wrote where the frames lay.
//
//   run_residue_sign and run_residue_ecdh make one signature and one key
//   exchange under the constant-time answer and look for any 64-bit limb,
//   in the host's byte order at any byte offset, of the values the call
//   must not leave behind, and run_residue_sign_on_instructions makes one
//   more signature through p256_sign_cpu, whose nonce's HMACs run on the
//   SHA-256 instructions, and looks for the same. After a signature: the
//   private scalar d, the nonce k, its inverse and z + r d, which gives d
//   to whoever holds the signature, and the nonce and its inverse in the
//   Montgomery domain modulo n, which is how p256_wide_scalar_inverse holds
//   them between products. After a key exchange: the private scalar and
//   the shared X coordinate, as it is and in the Montgomery domain modulo
//   p. And each of d, the nonce, z + r d and the key exchange's scalar less
//   n modulo 2^256, which is what p256_scalar_reduced_mask and the conditional
//   subtraction in p256_scalar_add compute into a temporary: the session
//   runs those two on p256_scalar.c under either answer, and they wipe
//   that temporary themselves (p256_scalar.h).
//
// One limb is enough to fail: a compiler that keeps a secret in slots of
// its own need not keep its four limbs side by side. A limb of 64 random
// bits matches no other eight bytes by chance. Two 32-bit limbs of
// p256_scalar.h's scalar are one such limb, so a copy p256_sign.c or
// p256_ecdh.c left is found too.
//
// The nonce is not an output, so the run recovers it from the signature:
// k = s^-1 (z + r d). Every value is computed only after the copy, and on
// p256_scalar.c and p256_field.c, so this file's own frames and the wide
// files' cannot hold them first.
//
// RESIDUE_BYTES stays under 4096 on purpose. A frame of 4096 bytes or more
// makes the compiler call a stack probe before anything else, and Darwin's
// stores two scratch registers on the stack. After a call those registers
// can still hold limbs the call computed with: a register is out of every
// wipe's reach, as it is for every wipe written in C. At 16384 bytes the
// probe of residue_snapshot itself stored a limb of a shared secret that
// way, which was this file's doing and not the library's.
//
// Included by test/p256_equiv_test.c only, which declares the generator,
// report and the counts this file uses.
#ifndef CH_P256_EQUIV_RESIDUE_H
#define CH_P256_EQUIV_RESIDUE_H

#include "hash_instructions_cpu.h"
#include "p256_wide_wipe.h"

#define RESIDUE_BYTES 3072
#define RESIDUE_PAINT 0xa5

static uint8_t residue_copy[RESIDUE_BYTES];
static uint8_t residue_priv[P256_SCALAR_LEN];
static uint8_t residue_hash[32];
static uint8_t residue_peer[P256_POINT_LEN];
static uint8_t residue_sig[P256_SIG_MAX];
static size_t residue_sig_len;
static uint8_t residue_shared[P256_SECRET_LEN];
static p256_scalar residue_scalar;
static p256_scalar residue_scalar_out;
static p256_point residue_point;
static p256_point residue_point_out;

// test/stack_residue.c, compiled as a source of its own.
void stack_residue_take(volatile uint8_t *below, size_t n, uint8_t *copy);

static __attribute__((noinline)) void residue_snapshot(void) {
    volatile uint8_t below[RESIDUE_BYTES];
    stack_residue_take(below, RESIDUE_BYTES, residue_copy);
}

// Writes RESIDUE_PAINT over the stack residue_snapshot copies, and over
// RESIDUE_PAINT_MARGIN bytes below that, so the copy's lowest bytes are
// painted wherever a compiler puts each function's array in its frame.
#define RESIDUE_PAINT_MARGIN 512
void stack_residue_fill(volatile uint8_t *below, size_t n, uint8_t value);

static __attribute__((noinline)) void residue_paint(void) {
    volatile uint8_t below[RESIDUE_BYTES + RESIDUE_PAINT_MARGIN];
    stack_residue_fill(below, sizeof below, RESIDUE_PAINT);
}

// The wide entries widemul.h dispatches to with secret operands, each under
// its own name, with no wipe after it.
enum { WIDE_MUL, WIDE_BASE_MUL, WIDE_AFFINE, WIDE_SCALAR_MUL, WIDE_SCALAR_INVERSE, WIDE_ENTRIES };
static const char *const WIDE_ENTRY_NAME[WIDE_ENTRIES] = {
    "p256_wide_mul", "p256_wide_base_mul", "p256_wide_point_affine", "p256_wide_scalar_mul",
    "p256_wide_scalar_inverse"};

static __attribute__((noinline)) void residue_wide_call(int entry) {
    if (entry == WIDE_MUL) {
        p256_wide_mul(&residue_point_out, &residue_scalar, &residue_point);
    } else if (entry == WIDE_BASE_MUL) {
        p256_wide_base_mul(&residue_point_out, &residue_scalar);
    } else if (entry == WIDE_AFFINE) {
        (void)p256_wide_point_affine(residue_shared, residue_hash, &residue_point);
    } else if (entry == WIDE_SCALAR_MUL) {
        p256_wide_scalar_mul(&residue_scalar_out, &residue_scalar, &residue_scalar);
    } else {
        p256_wide_scalar_inverse(&residue_scalar_out, &residue_scalar);
    }
}

// How far below its caller each wide entry writes: within the bytes
// p256_wide_wipe_below wipes.
static void run_depth(void) {
    random_scalar(&residue_scalar);
    p256_wide_base_mul(&residue_point, &residue_scalar);
    for (int entry = 0; entry < WIDE_ENTRIES; entry++) {
        residue_paint();
        residue_wide_call(entry);
        residue_snapshot();
        size_t depth = 0;
        for (size_t i = 0; i < RESIDUE_BYTES; i++) {
            if (residue_copy[i] != RESIDUE_PAINT) {
                depth = RESIDUE_BYTES - i;
                break;
            }
        }
        (void)printf("p256_equiv: %s writes %zu bytes below its caller\n", WIDE_ENTRY_NAME[entry],
                     depth);
        report("depth", WIDE_ENTRY_NAME[entry], depth > 0 && depth <= P256_WIDE_BELOW_LEN);
    }
}

// The six dispatchers of widemul.h that hand a wide entry a secret, each under the
// constant-time answer. widemul_p256_point_from_bytes is not among them: it reads a
// peer's point, which is public, and wipes nothing.
enum {
    DISPATCH_MUL,
    DISPATCH_BASE_MUL,
    DISPATCH_AFFINE,
    DISPATCH_AFFINE_X,
    DISPATCH_SCALAR_MUL,
    DISPATCH_SCALAR_INVERSE,
    DISPATCHERS
};
static const char *const DISPATCH_NAME[DISPATCHERS] = {
    "widemul_p256_point_mul",      "widemul_p256_point_base_mul", "widemul_p256_point_affine",
    "widemul_p256_point_affine_x", "widemul_p256_scalar_mul",     "widemul_p256_scalar_inverse"};

static __attribute__((noinline)) void residue_dispatched_call(int entry) {
    const uint8_t widemul = WIDEMUL_CONSTANT_TIME;
    if (entry == DISPATCH_MUL) {
        widemul_p256_point_mul(widemul, &residue_point_out, &residue_scalar, &residue_point);
    } else if (entry == DISPATCH_BASE_MUL) {
        widemul_p256_point_base_mul(widemul, &residue_point_out, &residue_scalar);
    } else if (entry == DISPATCH_AFFINE) {
        (void)widemul_p256_point_affine(widemul, residue_shared, residue_hash, &residue_point);
    } else if (entry == DISPATCH_AFFINE_X) {
        (void)widemul_p256_point_affine_x(widemul, residue_shared, &residue_point);
    } else if (entry == DISPATCH_SCALAR_MUL) {
        widemul_p256_scalar_mul(widemul, &residue_scalar_out, &residue_scalar, &residue_scalar);
    } else {
        widemul_p256_scalar_inverse(widemul, &residue_scalar_out, &residue_scalar);
    }
}

// The stack below each dispatched call: zero where p256_wide_wipe_below's
// array lay. The frames of this file's two functions and of the wipe's own
// lie above the array, so the run of zero bytes is short of its length by
// at most RESIDUE_FRAMES.
#define RESIDUE_FRAMES 160
static void run_wiped(void) {
    for (int entry = 0; entry < DISPATCHERS; entry++) {
        residue_paint();
        residue_dispatched_call(entry);
        residue_snapshot();
        size_t longest = 0;
        size_t run = 0;
        for (size_t i = 0; i < RESIDUE_BYTES; i++) {
            run = residue_copy[i] == 0 ? run + 1 : 0;
            if (run > longest) {
                longest = run;
            }
        }
        report("wiped", DISPATCH_NAME[entry], longest + RESIDUE_FRAMES >= P256_WIDE_BELOW_LEN);
    }
}

// cpu 0 signs through p256_sign under the constant-time answer, and any
// other value through p256_sign_cpu, the entry a server signs through.
static __attribute__((noinline)) int residue_sign(uint32_t cpu) {
    if (cpu == 0) {
        return p256_sign(WIDEMUL_CONSTANT_TIME, residue_priv, residue_hash, residue_sig,
                         sizeof residue_sig, &residue_sig_len);
    }
    return p256_sign_cpu(cpu, residue_priv, residue_hash, residue_sig, sizeof residue_sig,
                         &residue_sig_len);
}

static __attribute__((noinline)) int residue_ecdh(void) {
    return p256_ecdh(WIDEMUL_CONSTANT_TIME, residue_priv, residue_peer, residue_shared);
}

// Whether the copy holds any of the four 64-bit limbs of the eight 32-bit
// limbs at limb, at any byte offset.
static int residue_holds(const uint32_t limb[8]) {
    for (size_t i = 0; i < 4; i++) {
        uint64_t wide = (uint64_t)limb[2 * i] | ((uint64_t)limb[2 * i + 1] << 32);
        for (size_t at = 0; at + sizeof wide <= RESIDUE_BYTES; at++) {
            uint64_t word;
            memcpy(&word, &residue_copy[at], sizeof word);
            if (word == wide) {
                return 1;
            }
        }
    }
    return 0;
}

// Whether the copy holds a limb of a - n modulo 2^256.
static int residue_holds_less_n(const p256_scalar *a) {
    static const uint32_t n[8] = {0xfc632551, 0xf3b9cac2, 0xa7179e84, 0xbce6faad,
                                  0xffffffff, 0xffffffff, 0x00000000, 0xffffffff};
    uint32_t difference[8];
    uint64_t borrow = 0;
    for (size_t i = 0; i < 8; i++) {
        uint64_t limb = (uint64_t)a->limb[i] - n[i] - borrow;
        difference[i] = (uint32_t)limb;
        borrow = (limb >> 32) & 1U;
    }
    return residue_holds(difference);
}

// a * 2^256 mod n, the form p256_wide_scalar.c computes on. p256_scalar.h
// has no entry into the Montgomery domain, so this multiplies by
// 2^256 mod n, which is 2^256 - n.
static void scalar_to_mont(p256_scalar *o, const p256_scalar *a) {
    static const p256_scalar r_mod_n = {
        {0x039cdaaf, 0x0c46353d, 0x58e8617b, 0x43190552, 0, 0, 0xffffffff, 0}
    };
    p256_scalar_mul(o, a, &r_mod_n);
}

// The two INTEGERs of a DER ECDSA-Sig-Value, each as a scalar.
static void residue_read_signature(p256_scalar *r, p256_scalar *s) {
    uint8_t value[2][P256_SCALAR_LEN];
    const uint8_t *at = residue_sig + 2;
    for (size_t i = 0; i < 2; i++) {
        size_t len = at[1];
        const uint8_t *content = at + 2;
        // A leading zero byte keeps a value with its top bit set positive.
        size_t skip = len > P256_SCALAR_LEN ? len - P256_SCALAR_LEN : 0;
        memset(value[i], 0, P256_SCALAR_LEN);
        memcpy(value[i] + P256_SCALAR_LEN - (len - skip), content + skip, len - skip);
        at = content + len;
    }
    p256_scalar_from_bytes(r, value[0]);
    p256_scalar_from_bytes(s, value[1]);
}

// One signature through residue_sign(cpu), and the search of the stack it
// left. group names the signer in each report.
static void run_residue_sign(uint32_t cpu, const char *group) {
    do {
        rng_fill(residue_priv, sizeof residue_priv);
    } while (!p256_sign_key_ok(residue_priv));
    rng_fill(residue_hash, sizeof residue_hash);
    int signed_ok = residue_sign(cpu);
    residue_snapshot();
    report(group, "the signature under the constant-time answer", signed_ok == 1);

    p256_scalar d;
    p256_scalar z;
    p256_scalar r;
    p256_scalar s;
    p256_scalar k;
    p256_scalar k_inverse;
    p256_scalar other;
    p256_scalar_from_bytes(&d, residue_priv);
    p256_scalar_from_bytes(&z, residue_hash);
    p256_scalar_reduce(&z, &z);
    residue_read_signature(&r, &s);
    // k = s^-1 (z + r d), and its inverse is s (z + r d)^-1.
    p256_scalar_mul(&k, &r, &d);
    p256_scalar_add(&k, &z, &k);
    report(group, "no limb of z + r d below a signature", !residue_holds(k.limb));
    report(group, "no limb of z + r d less n below a signature", !residue_holds_less_n(&k));
    report(group, "no limb of the private scalar less n below a signature",
           !residue_holds_less_n(&d));
    p256_scalar_inverse(&k_inverse, &k);
    p256_scalar_mul(&k_inverse, &s, &k_inverse);
    p256_scalar_inverse(&other, &s);
    p256_scalar_mul(&k, &other, &k);

    report(group, "no limb of the private scalar below a signature", !residue_holds(d.limb));
    report(group, "no limb of the nonce below a signature", !residue_holds(k.limb));
    report(group, "no limb of the nonce less n below a signature", !residue_holds_less_n(&k));
    report(group, "no limb of the nonce's inverse below a signature",
           !residue_holds(k_inverse.limb));
    scalar_to_mont(&other, &k);
    report(group, "no limb of the nonce times R below a signature", !residue_holds(other.limb));
    scalar_to_mont(&other, &k_inverse);
    report(group, "no limb of the nonce's inverse times R below a signature",
           !residue_holds(other.limb));
}

// The search above on a signature through p256_sign_cpu with the SHA-256
// bit, so the nonce's HMACs ran on sha256_hw.c and hkdf_hw.c: their frames
// lie below the signer's too. A CPU without the instructions skips it, or
// fails where the environment requires them (test/hash_instructions_cpu.h).
static void run_residue_sign_on_instructions(void) {
    if (!cpu_has_sha256_instructions()) {
        report("residue, the nonce on the SHA-256 instructions",
               "the CPU has the SHA-256 instructions the environment requires",
               !hash_instructions_required());
        (void)printf("p256_equiv: SKIP the signature with the nonce on the SHA-256 "
                     "instructions: this CPU lacks them\n");
        return;
    }
    run_residue_sign(CH_CPU_PROBED | CH_CPU_CONSTANT_TIME_MULTIPLY | CH_CPU_CONSTANT_TIME_SHA256,
                     "residue, the nonce on the SHA-256 instructions");
}

static void run_residue_ecdh(void) {
    uint8_t draw[P256_SCALAR_LEN];
    uint8_t peer_priv[P256_SCALAR_LEN];
    do {
        rng_fill(draw, sizeof draw);
    } while (!p256_ecdh_keygen(WIDEMUL_NOT_STATED, draw, peer_priv, residue_peer));
    do {
        rng_fill(residue_priv, sizeof residue_priv);
    } while (!p256_sign_key_ok(residue_priv));
    int shared_ok = residue_ecdh();
    residue_snapshot();
    report("residue", "the key exchange under the constant-time answer", shared_ok == 1);

    p256_scalar k;
    p256_fe x;
    p256_fe x_mont;
    p256_scalar_from_bytes(&k, residue_priv);
    p256_fe_from_bytes(&x, residue_shared);
    p256_fe_to_mont(&x_mont, &x);
    report("residue", "no limb of the private scalar below a key exchange", !residue_holds(k.limb));
    report("residue", "no limb of the private scalar less n below a key exchange",
           !residue_holds_less_n(&k));
    report("residue", "no limb of the shared secret below a key exchange", !residue_holds(x.limb));
    report("residue", "no limb of the shared secret times R below a key exchange",
           !residue_holds(x_mont.limb));
}

// The four checks above, unless the environment names CH_P256_EQUIV_NO_STACK. make
// san-check sets it: a sanitizer puts a redzone beside every local and keeps in memory
// what an optimizer keeps in a register, so a sanitized build's frames are several times
// the object's and hold copies the object never makes. Its depths and its residue say
// nothing of what ships, and that lane runs this binary for the memory errors a
// sanitizer finds in the comparisons before these.
static void run_stack(void) {
    if (getenv("CH_P256_EQUIV_NO_STACK") != NULL) {
        (void)printf("p256_equiv: SKIP the stack checks: CH_P256_EQUIV_NO_STACK is set\n");
        return;
    }
    run_depth();
    run_wiped();
    run_residue_sign(0, "residue");
    run_residue_sign_on_instructions();
    run_residue_ecdh();
}

#endif
