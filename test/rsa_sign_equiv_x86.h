// The second and third passes of test/rsa_sign_equiv_test.c's run_signatures,
// on an x86-64 CPU: on AVX-512 IFMA (docs/decisions.md 120) and on MULX, ADCX
// and ADOX (docs/decisions.md 183), each where this CPU has the instructions.
// test/rsa_sign_equiv_test.c includes this file after run_signatures, whose
// equiv_cpu, window_adx and failure counts it uses.
#ifndef CH_TEST_RSA_SIGN_EQUIV_X86_H
#define CH_TEST_RSA_SIGN_EQUIV_X86_H

#ifdef __x86_64__
// The second pass of run_signatures, on AVX-512 IFMA, where this CPU has
// it. Returns 0 when the CPU lacks it and the environment requires it.
static int run_ifma_signatures(void) {
    if (!x86_cpu_has_avx512_ifma()) {
        if (x86_ifma_required()) {
            (void)fprintf(stderr, "rsa_sign_equiv_test: this CPU lacks AVX-512 IFMA, and "
                                  "CH_REQUIRE_AVX512_IFMA is 1\n");
            return 0;
        }
        (void)printf("SKIP rsa_sign_equiv_test on AVX-512 IFMA: this CPU lacks it\n");
        return 1;
    }
    equiv_cpu = EQUIV_WINDOW_CPU | CH_CPU_AVX512_IFMA;
    run_signatures();
    equiv_cpu = EQUIV_WINDOW_CPU;
    (void)printf("rsa_sign_equiv_test: the private operation on AVX-512 IFMA ran\n");
    return 1;
}

// The third pass, on MULX, ADCX and ADOX, where this CPU has BMI2 and ADX
// (docs/decisions.md 183): every signature, the residue runs and the
// differential under CH_CPU_BMI2_ADX beside the multiply bit, and the
// window in run_window. Returns 0 when the CPU lacks them and the
// environment requires them.
static int run_adx_signatures(void) {
    if (!x86_cpu_has_bmi2_adx()) {
        if (x86_bmi2_adx_required()) {
            (void)fprintf(stderr, "rsa_sign_equiv_test: this CPU lacks BMI2 or ADX, and "
                                  "CH_REQUIRE_BMI2_ADX is 1\n");
            return 0;
        }
        (void)printf("SKIP rsa_sign_equiv_test on MULX and ADX: this CPU lacks BMI2 or ADX\n");
        return 1;
    }
    window_adx = 1;
    equiv_cpu = EQUIV_WINDOW_CPU | CH_CPU_BMI2_ADX;
    run_signatures();
    equiv_cpu = EQUIV_WINDOW_CPU;
    (void)printf("rsa_sign_equiv_test: the private operation on MULX and ADX ran\n");
    return 1;
}
#endif

#endif
