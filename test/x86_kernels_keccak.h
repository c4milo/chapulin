// bin/x86_kernels_test's Keccak rows: ML-KEM's three session calls and sha3.h's four entries.
// test/x86_kernels_test.c alone includes this file, on x86-64, after it defines CHECK, failures,
// payload, fill, names_avx2 and widemul_of_cpu.
//
// mlkem.h's entries run mlkem_avx2.c's copy, whose matrix is on the four-way Keccak, where the
// value holds CH_CPU_AVX2 (docs/decisions.md 107). test/x86_kernels_count.c counts the calls into
// it.
//
// sha3.h's four entries that take a session's ch_cfg.cpu run sha3_hw.c's x86-64 copy, sha3.c on
// ANDN and RORX, where the value holds CH_CPU_BMI1 and CH_CPU_BMI2_ADX (docs/decisions.md 217).
// The binary links test/x86_kernels_count.c's six stand-ins in that file's place: each counts a
// call and runs it on sha3.c. ML-KEM's three session calls make SHA-3 and SHAKE calls that take
// no value, so they send none to the copy under any value.
#ifndef CH_TEST_X86_KERNELS_KECCAK_H
#define CH_TEST_X86_KERNELS_KECCAK_H

#include <string.h>

#include "mlkem.h"
#include "sha3.h"
#include "x86_kernels_count.h"

// Whether the calls into ML-KEM's copy since the last look are these, and
// resets them.
static int mlkem_calls_are(unsigned long keygen, unsigned long encaps, unsigned long decaps) {
    int same = x86_mlkem_keygen_calls == keygen && x86_mlkem_encaps_calls == encaps &&
               x86_mlkem_decaps_calls == decaps;
    if (!same) {
        (void)fprintf(stderr,
                      "calls: ML-KEM's copy, key generation %lu, encapsulation %lu, decapsulation "
                      "%lu; want %lu, %lu, %lu\n",
                      x86_mlkem_keygen_calls, x86_mlkem_encaps_calls, x86_mlkem_decaps_calls,
                      keygen, encaps, decaps);
    }
    x86_mlkem_keygen_calls = 0;
    x86_mlkem_encaps_calls = 0;
    x86_mlkem_decaps_calls = 0;
    return same;
}

// ML-KEM's three session calls: each runs mlkem_avx2.c's copy where the
// value holds CH_CPU_AVX2 and the call it is named for everywhere else, and
// gives that call's bytes. The encapsulation key sits at dk + 1152, as
// mlkem.h says.
static void check_mlkem(uint32_t cpu) {
    uint8_t d[32];
    uint8_t z[32];
    uint8_t m[32];
    fill(d, sizeof d, 0x55);
    fill(z, sizeof z, 0x66);
    fill(m, sizeof m, 0x77);
    static uint8_t dk[MLKEM_DK_LEN];
    static uint8_t dk_cpu[MLKEM_DK_LEN];
    mlkem_keygen_dk(dk, d, z);
    mlkem_keygen_dk_cpu(cpu, dk_cpu, d, z);
    CHECK(mlkem_calls_are(names_avx2(cpu), 0, 0));
    CHECK(memcmp(dk_cpu, dk, sizeof dk) == 0);

    const uint8_t *ek = dk + 1152;
    uint8_t widemul = widemul_of_cpu(cpu);
    uint8_t ct[MLKEM_CT_LEN];
    uint8_t ct_cpu[MLKEM_CT_LEN];
    uint8_t ss[MLKEM_SS_LEN];
    uint8_t ss_cpu[MLKEM_SS_LEN];
    CHECK(mlkem_encaps_derand(widemul, ct, ss, ek, m) == 0);
    CHECK(mlkem_encaps_derand_cpu(cpu, widemul, ct_cpu, ss_cpu, ek, m) == 0);
    CHECK(mlkem_calls_are(0, names_avx2(cpu), 0));
    CHECK(memcmp(ct_cpu, ct, sizeof ct) == 0 && memcmp(ss_cpu, ss, sizeof ss) == 0);

    uint8_t back[MLKEM_SS_LEN];
    mlkem_decaps_cpu(cpu, widemul, back, ct, dk);
    CHECK(mlkem_calls_are(0, 0, names_avx2(cpu)));
    CHECK(memcmp(back, ss, sizeof back) == 0);
}

// Whether the calls into sha3_hw.c's copy since the last look are want, and
// a reset of the count.
static int sha3_bmi_calls_are(unsigned long want) {
    int same = x86_sha3_bmi_calls == want;
    if (!same) {
        (void)fprintf(stderr, "x86 kernels: %lu calls into sha3_hw.c's copy, not %lu\n",
                      x86_sha3_bmi_calls, want);
    }
    x86_sha3_bmi_calls = 0;
    return same;
}

// sha3.h's four entries that take a value: each runs sha3_hw.c's copy where the value holds
// CH_CPU_BMI1 and CH_CPU_BMI2_ADX, written here apart from sha3_on_instructions, and sha3.c
// anywhere else, with the same bytes. Then ML-KEM's three session calls, which make SHA-3 and
// SHAKE calls that take no value, and so none into the copy.
static void check_sha3(uint32_t cpu) {
    unsigned long copy = (cpu & CH_CPU_BMI1) != 0 && (cpu & CH_CPU_BMI2_ADX) != 0;
    uint8_t want[SHA3_512_LEN];
    uint8_t got[SHA3_512_LEN];
    x86_sha3_bmi_calls = 0;
    sha3_256(payload, PAYLOAD, want);
    sha3_256_cpu(cpu, payload, PAYLOAD, got);
    CHECK(sha3_bmi_calls_are(copy));
    CHECK(memcmp(got, want, SHA3_256_LEN) == 0);
    sha3_512(payload, PAYLOAD, want);
    sha3_512_cpu(cpu, payload, PAYLOAD, got);
    CHECK(sha3_bmi_calls_are(copy));
    CHECK(memcmp(got, want, SHA3_512_LEN) == 0);
    shake s;
    shake256_init(&s);
    shake_absorb(&s, payload, PAYLOAD);
    shake_squeeze(&s, want, sizeof want);
    shake256_init(&s);
    shake_absorb_cpu(cpu, &s, payload, PAYLOAD);
    shake_squeeze_cpu(cpu, &s, got, sizeof got);
    CHECK(sha3_bmi_calls_are(2 * copy));
    CHECK(memcmp(got, want, sizeof got) == 0);
    check_mlkem(cpu);
    CHECK(sha3_bmi_calls_are(0));
}

#endif
