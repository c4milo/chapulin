// Times OpenSSL's ML-KEM-768 encapsulation as a TLS server runs it: to a public key that arrives as
// bytes, so each operation makes the key object from those bytes and then encapsulates to it.
// bench/primitives.sh builds it against the OpenSSL whose binary it times, and puts its row in
// place of the encapsulation row of `openssl speed`, which reuses one key object for every
// operation (docs/decisions.md 239). On a Neoverse N2 that reused key took 17.5 us an
// encapsulation and a key made from bytes 32.5 us.
//
// Usage: openssl_kem LABEL
//
// It prints one row shaped as primitives.c's: mlkem768_encaps, LABEL as the build, "op", 0 bytes,
// and the nanoseconds of one operation, the median of SAMPLES samples. The clock is the thread's
// CPU time, as in primitives.c. The decapsulation row stays `openssl speed`'s: a TLS client keeps
// the key object its key generation made, so that reuse is the work a handshake does.
#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#define SAMPLES 11
#define SAMPLE_NS 2e6

static unsigned char pub[1184];
static size_t pub_len = sizeof pub;

static double now_ns(void) {
    struct timespec t;
    clock_gettime(CLOCK_THREAD_CPUTIME_ID, &t);
    return (double)t.tv_sec * 1e9 + (double)t.tv_nsec;
}

// One encapsulation to a key made from pub's bytes. 0 on failure.
static int encapsulate_fresh(void) {
    unsigned char ct[1088], ss[32];
    size_t ct_len = sizeof ct, ss_len = sizeof ss;
    EVP_PKEY *key = EVP_PKEY_new_raw_public_key_ex(NULL, "ML-KEM-768", NULL, pub, pub_len);
    EVP_PKEY_CTX *ctx = key ? EVP_PKEY_CTX_new_from_pkey(NULL, key, NULL) : NULL;
    int ok = ctx && EVP_PKEY_encapsulate_init(ctx, NULL) == 1 &&
             EVP_PKEY_encapsulate(ctx, ct, &ct_len, ss, &ss_len) == 1;
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(key);
    return ok;
}

static int compare(const void *a, const void *b) {
    double x = *(const double *)a, y = *(const double *)b;
    return (x > y) - (x < y);
}

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "usage: %s LABEL\n", argv[0]);
        return 2;
    }
    EVP_PKEY_CTX *kctx = EVP_PKEY_CTX_new_from_name(NULL, "ML-KEM-768", NULL);
    EVP_PKEY *pair = NULL;
    if (!kctx || EVP_PKEY_keygen_init(kctx) != 1 || EVP_PKEY_generate(kctx, &pair) != 1 ||
        EVP_PKEY_get_raw_public_key(pair, pub, &pub_len) != 1 || pub_len != sizeof pub) {
        fprintf(stderr, "openssl_kem: this OpenSSL cannot make an ML-KEM-768 key\n");
        return 1;
    }
    // Repetitions: doubled until one sample takes SAMPLE_NS, which also warms the caches.
    long reps = 1;
    for (;;) {
        double t0 = now_ns();
        for (long i = 0; i < reps; i++) {
            if (!encapsulate_fresh()) {
                fprintf(stderr, "openssl_kem: an encapsulation failed\n");
                return 1;
            }
        }
        if (now_ns() - t0 >= SAMPLE_NS) {
            break;
        }
        reps *= 2;
    }
    double samples[SAMPLES];
    for (int s = 0; s < SAMPLES; s++) {
        double t0 = now_ns();
        for (long i = 0; i < reps; i++) {
            if (!encapsulate_fresh()) {
                return 1;
            }
        }
        samples[s] = (now_ns() - t0) / (double)reps;
    }
    qsort(samples, SAMPLES, sizeof samples[0], compare);
    printf("mlkem768_encaps,%s,op,0,%.4f,,,\n", argv[1], samples[SAMPLES / 2]);
    EVP_PKEY_free(pair);
    EVP_PKEY_CTX_free(kctx);
    return 0;
}
