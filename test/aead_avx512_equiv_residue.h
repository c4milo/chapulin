// What aead_avx512.c's one pass leaves behind, for
// test/aead_avx512_equiv_test.c alone, which declares the generator, the
// failure count and the buffers this file uses.
//
// run_residue calls aead_avx512_seal and aead_avx512_open over
// RESIDUE_LENGTH bytes, from a poly1305 keyed as aead.c keys it, copies the
// stack below its caller as deep as RESIDUE_BYTES after each, and looks in
// the copy, at every byte offset, for the key's eight words side by side,
// as the input words of a pass hold them, and for r^2 to r^16 in each
// layout poly1305_ifma_group.h holds a power in: three uint64_t digits side
// by side, as the struct of powers holds r's, one digit in every 64 bytes,
// as an IFMA multiplier's three vectors hold a lane's power, and one digit
// in every 24 or 32 bytes. Each entry wipes its words and its powers before
// it returns. The search finds no key word alone, for the reason
// test/chacha20_equiv_residue.h gives, and no running sum of the lanes, for
// the reason docs/decisions.md 121 gives.
//
// It also sets every bit of zmm0 to zmm31 and k1 to k7 before each entry,
// and requires every bit of them zero after it, since they held the key's
// words, the keystream, the powers of r and the lanes' sums
// (docs/decisions.md 121 and 226).
//
// A third call runs chacha20_avx512_xor over RESIDUE_ROW_LENGTH bytes, one
// row pass alone, with the same two checks. A row pass holds the key's
// words 0 to 3 in every quarter of one vector and words 4 to 7 in every
// quarter of the next, so two such vectors side by side in a frame spell
// the key. The seal's last pass and the open's last bytes run a row pass
// beside a pass of sixteen blocks, and this call runs the row pass that
// chacha20_avx512.c gives a short message (docs/decisions.md 228).
#ifndef CH_AEAD_AVX512_EQUIV_RESIDUE_H
#define CH_AEAD_AVX512_EQUIV_RESIDUE_H

// Four passes and 37 bytes: two passes absorb, and the last bytes run on a
// row pass beside the last whole pass.
#define RESIDUE_LENGTH ((size_t)4096 + 37)
// Three blocks and 37 bytes, on one row pass.
#define RESIDUE_ROW_LENGTH ((size_t)3 * 64 + 37)
// Deep enough for an entry's frame, which holds its struct of powers,
// 1,984 bytes, beside the pass's spills.
#define RESIDUE_BYTES 12288
// r^2 to r^16.
#define RESIDUE_POWERS 15
#define RESIDUE_WORD_MASK 0x3ffffffU

static uint8_t residue_copy[RESIDUE_BYTES];

// test/stack_residue.c, compiled as a source of its own.
void stack_residue_take(volatile uint8_t *below, size_t n, uint8_t *copy);
const char *stack_residue_unsearched(void);

static __attribute__((noinline)) void residue_snapshot(void) {
    volatile uint8_t below[RESIDUE_BYTES];
    stack_residue_take(below, RESIDUE_BYTES, residue_copy);
}

// zmm0 to zmm31 at 64 bytes each, then k1 to k7 at 8 bytes each.
#define RESIDUE_REGISTER_BYTES (32 * 64 + 7 * 8)
#define SET_VECTOR(n) "vpternlogd $0xff, %%zmm" #n ", %%zmm" #n ", %%zmm" #n "\n\t"
#define SET_MASK(n) "kxnorw %%k0, %%k0, %%k" #n "\n\t"
#define STORE_VECTOR(n) "vmovdqu64 %%zmm" #n ", " #n "*64(%0)\n\t"
#define STORE_MASK(n, at) "kmovq %%k" #n ", " #at "(%0)\n\t"
static uint8_t registers_after[RESIDUE_REGISTER_BYTES];

static __attribute__((target("avx512f,avx512bw"), noinline)) void set_registers(void) {
    __asm__ volatile(
        SET_VECTOR(0) SET_VECTOR(1) SET_VECTOR(2) SET_VECTOR(3) SET_VECTOR(4) SET_VECTOR(5)
            SET_VECTOR(6) SET_VECTOR(7) SET_VECTOR(8) SET_VECTOR(9) SET_VECTOR(10) SET_VECTOR(11)
                SET_VECTOR(12) SET_VECTOR(13) SET_VECTOR(14) SET_VECTOR(15) SET_VECTOR(16)
                    SET_VECTOR(17) SET_VECTOR(18) SET_VECTOR(19) SET_VECTOR(20) SET_VECTOR(21)
                        SET_VECTOR(22) SET_VECTOR(23) SET_VECTOR(24) SET_VECTOR(25) SET_VECTOR(26)
                            SET_VECTOR(27) SET_VECTOR(28) SET_VECTOR(29) SET_VECTOR(30)
                                SET_VECTOR(31) SET_MASK(1) SET_MASK(2) SET_MASK(3) SET_MASK(4)
                                    SET_MASK(5) SET_MASK(6) SET_MASK(7)
        :
        :
        : "memory");
}

static __attribute__((target("avx512f,avx512bw"), noinline)) void store_registers(void) {
    __asm__ volatile(
        STORE_VECTOR(0) STORE_VECTOR(1) STORE_VECTOR(2) STORE_VECTOR(3) STORE_VECTOR(4)
            STORE_VECTOR(5) STORE_VECTOR(6) STORE_VECTOR(7) STORE_VECTOR(8) STORE_VECTOR(9)
                STORE_VECTOR(10) STORE_VECTOR(11) STORE_VECTOR(12) STORE_VECTOR(13) STORE_VECTOR(14)
                    STORE_VECTOR(15) STORE_VECTOR(16) STORE_VECTOR(17) STORE_VECTOR(18)
                        STORE_VECTOR(19) STORE_VECTOR(20) STORE_VECTOR(21) STORE_VECTOR(22)
                            STORE_VECTOR(23) STORE_VECTOR(24) STORE_VECTOR(25) STORE_VECTOR(26)
                                STORE_VECTOR(27) STORE_VECTOR(28) STORE_VECTOR(29) STORE_VECTOR(30)
                                    STORE_VECTOR(31) STORE_MASK(1, 2048) STORE_MASK(2, 2056)
                                        STORE_MASK(3, 2064) STORE_MASK(4, 2072) STORE_MASK(5, 2080)
                                            STORE_MASK(6, 2088) STORE_MASK(7, 2096)
        :
        : "r"(registers_after)
        : "memory");
}

// One entry called alone, from a poly1305 keyed as aead.c keys it, so that
// no call after it writes over its dead frames before the copy, with the
// registers set before it and stored after it.
static __attribute__((noinline)) void residue_entry(int seal) {
    static poly1305 state;
    uint8_t otk[CHACHA20_BLOCK];
    chacha20_block(key, nonce, 0, otk);
    poly1305_init(&state, otk);
    ct_wipe(otk, sizeof otk);
    set_registers();
    if (seal) {
        aead_avx512_seal(key, nonce, &state, message, RESIDUE_LENGTH, sealed);
    } else {
        aead_avx512_open(key, nonce, &state, sealed, RESIDUE_LENGTH, buffer);
    }
    store_registers();
}

// chacha20_avx512_xor called alone over one row pass, with the registers
// set before it and stored after it.
static __attribute__((noinline)) void residue_row_pass(void) {
    set_registers();
    chacha20_avx512_xor(key, nonce, 1, message, buffer, RESIDUE_ROW_LENGTH);
    store_registers();
}

// value carried and reduced modulo 2^130 - 5 to its one form below it.
static void residue_reduce(const uint64_t in[5], uint32_t out[5]) {
    uint64_t d[5];
    memcpy(d, in, sizeof d);
    for (int round = 0; round < 3; round++) {
        for (size_t i = 0; i < 4; i++) {
            d[i + 1] += d[i] >> 26;
            d[i] &= RESIDUE_WORD_MASK;
        }
        d[0] += (d[4] >> 26) * 5;
        d[4] &= RESIDUE_WORD_MASK;
    }
    // value + 5 at or past 2^130 means value is at or past 2^130 - 5.
    uint64_t g[5];
    g[0] = d[0] + 5;
    for (size_t i = 0; i < 4; i++) {
        g[i + 1] = d[i + 1] + (g[i] >> 26);
        g[i] &= RESIDUE_WORD_MASK;
    }
    int past = (g[4] >> 26) != 0;
    for (size_t i = 0; i < 5; i++) {
        out[i] = (uint32_t)(past ? (g[i] & RESIDUE_WORD_MASK) : d[i]);
    }
}

static void residue_multiply(const uint32_t a[5], const uint32_t b[5], uint32_t out[5]) {
    uint64_t d[5] = {0, 0, 0, 0, 0};
    for (size_t i = 0; i < 5; i++) {
        for (size_t j = 0; j < 5; j++) {
            uint64_t product = (uint64_t)a[i] * b[j];
            // A product past word 4 is past 2^130, which is 5 modulo
            // 2^130 - 5.
            d[(i + j) % 5] += i + j < 5 ? product : 5 * product;
        }
    }
    residue_reduce(d, out);
}

// Whether the copy holds power as three digits stride bytes apart, at any
// byte offset: digit0 + digit1 2^44 + digit2 2^88, each digit below 2^45.
static int residue_holds_digits(const uint32_t power[5], size_t stride) {
    for (size_t at = 0; at + 2 * stride + 8 <= RESIDUE_BYTES; at++) {
        uint64_t digit[3];
        int small = 1;
        for (size_t i = 0; i < 3; i++) {
            memcpy(&digit[i], &residue_copy[at + i * stride], sizeof digit[i]);
            small &= digit[i] < (UINT64_C(1) << 45);
        }
        if (!small) {
            continue;
        }
        const uint64_t words[5] = {
            digit[0] & RESIDUE_WORD_MASK,
            (digit[0] >> 26) + ((digit[1] & 0xff) << 18),
            digit[1] >> 8,
            (digit[2] & 0xffff) << 10,
            digit[2] >> 16,
        };
        uint32_t value[5];
        residue_reduce(words, value);
        if (memcmp(value, power, sizeof value) == 0) {
            return 1;
        }
    }
    return 0;
}

// r from the Poly1305 key of key and nonce, clamped, in five words.
static void residue_r(uint32_t r[5]) {
    uint8_t otk[CHACHA20_BLOCK];
    chacha20_block(key, nonce, 0, otk);
    poly1305 p;
    poly1305_init(&p, otk);
    memcpy(r, p.r, sizeof p.r);
}

static void residue_search(const char *call) {
    compared++;
    for (size_t at = 0; at + AEAD_KEY <= RESIDUE_BYTES; at++) {
        if (memcmp(&residue_copy[at], key, AEAD_KEY) == 0) {
            failures++;
            (void)fprintf(stderr,
                          "aead avx512 equivalence: residue: the stack below %s holds the key "
                          "at byte %zu of the copy\n",
                          call, at);
            return;
        }
    }
    uint32_t r[5];
    uint32_t power[5];
    residue_r(r);
    memcpy(power, r, sizeof power);
    static const size_t strides[4] = {8, 24, 32, 64};
    for (size_t k = 2; k < 2 + RESIDUE_POWERS; k++) {
        residue_multiply(power, r, power);
        for (size_t s = 0; s < 4; s++) {
            if (residue_holds_digits(power, strides[s])) {
                failures++;
                (void)fprintf(stderr,
                              "aead avx512 equivalence: residue: the stack below %s holds r^%zu, "
                              "one digit every %zu bytes\n",
                              call, k, strides[s]);
                return;
            }
        }
    }
}

static void residue_registers(const char *call) {
    compared++;
    for (size_t i = 0; i < RESIDUE_REGISTER_BYTES; i++) {
        if (registers_after[i] != 0) {
            failures++;
            (void)fprintf(stderr,
                          "aead avx512 equivalence: registers: %s left byte %zu of zmm0 to zmm31 "
                          "and k1 to k7 set\n",
                          call, i);
            return;
        }
    }
}

static void run_residue(void) {
    const char *unsearched = stack_residue_unsearched();
    rng_fill(message, RESIDUE_LENGTH);
    residue_entry(1);
    residue_snapshot();
    if (unsearched == NULL) {
        residue_search("a seal");
    }
    residue_registers("a seal");
    residue_entry(0);
    residue_snapshot();
    if (unsearched == NULL) {
        residue_search("an open");
    }
    residue_registers("an open");
    residue_row_pass();
    residue_snapshot();
    if (unsearched == NULL) {
        residue_search("a ChaCha20 row pass");
    }
    residue_registers("a ChaCha20 row pass");
    if (unsearched != NULL) {
        printf("aead avx512 equivalence: no search of the stack: %s\n", unsearched);
    }
}

#endif
