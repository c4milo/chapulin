// Plumbing for the differential oracle driver: deterministic PRNG, hex
// codecs, and the pipe protocol to the Lean spec process. Included by
// test/diff.c only (single translation unit, like testrand.h).
#ifndef CH_DIFFDRV_H
#define CH_DIFFDRV_H

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// xorshift64 with a fixed seed: every run replays the same inputs, so a
// mismatch is reproducible bit-for-bit. Never seeded from time().
static uint64_t rng_state = UINT64_C(0x6d617461736170f5);

static inline uint64_t rng_next(void) {
    uint64_t x = rng_state;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    rng_state = x;
    return x;
}

static inline size_t rng_below(size_t n) {
    return (size_t)(rng_next() % n);
}

static inline void rng_fill(uint8_t *p, size_t n) {
    for (size_t i = 0; i < n; i++) {
        p[i] = (uint8_t)(rng_next() >> 56);
    }
}

// Line-protocol hex: lowercase, "-" for the empty string.
static inline size_t hex_encode(char *dst, const uint8_t *p, size_t n) {
    static const char digits[] = "0123456789abcdef";
    if (n == 0) {
        dst[0] = '-';
        dst[1] = '\0';
        return 1;
    }
    for (size_t i = 0; i < n; i++) {
        dst[2 * i] = digits[p[i] >> 4];
        dst[2 * i + 1] = digits[p[i] & 0xf];
    }
    dst[2 * n] = '\0';
    return 2 * n;
}

static int hex_digit(char c) {
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    }
    return -1;
}

// Decodes exactly n bytes of lowercase hex; 0 on any bad digit.
static inline int hex_decode(uint8_t *dst, const char *src, size_t n) {
    for (size_t i = 0; i < n; i++) {
        int hi = hex_digit(src[2 * i]);
        int lo = hex_digit(src[2 * i + 1]);
        if (hi < 0 || lo < 0) {
            return 0;
        }
        dst[i] = (uint8_t)((hi << 4) | lo);
    }
    return 1;
}

static FILE *to_spec;
static FILE *from_spec;
static pid_t spec_pid;
static long comparisons;

static void die(const char *msg) {
    (void)fprintf(stderr, "diff: %s\n", msg);
    exit(1);
}

static void spawn_spec(const char *path) {
    int in_fd[2];  // driver -> spec stdin
    int out_fd[2]; // spec stdout -> driver
    if (pipe(in_fd) != 0 || pipe(out_fd) != 0) {
        die("pipe failed");
    }
    spec_pid = fork();
    if (spec_pid < 0) {
        die("fork failed");
    }
    if (spec_pid == 0) {
        if (dup2(in_fd[0], STDIN_FILENO) < 0 || dup2(out_fd[1], STDOUT_FILENO) < 0) {
            _exit(127);
        }
        close(in_fd[0]);
        close(in_fd[1]);
        close(out_fd[0]);
        close(out_fd[1]);
        execl(path, path, (char *)NULL);
        _exit(127);
    }
    close(in_fd[0]);
    close(out_fd[1]);
    to_spec = fdopen(in_fd[1], "w");
    from_spec = fdopen(out_fd[0], "r");
    if (to_spec == NULL || from_spec == NULL) {
        die("fdopen failed");
    }
}

// Sends one request line, hands back the raw response line. For answers
// the driver cannot predict (e.g. spec-minted signatures); ERR and FAIL
// are fatal here, so callers only ever see well-formed payloads.
static void query(const char *cmd, char *out, size_t out_len) {
    (void)fputs(cmd, to_spec);
    (void)fputc('\n', to_spec);
    (void)fflush(to_spec);
    if (fgets(out, (int)out_len, from_spec) == NULL) {
        die("spec process closed the pipe (did spec/.lake/build/bin/diffspec build?)");
    }
    char *nl = strchr(out, '\n');
    if (nl != NULL) {
        *nl = '\0';
    }
    if (strncmp(out, "ERR", 3) == 0 || strcmp(out, "FAIL") == 0) {
        (void)fprintf(stderr, "diff spec refusal:\n  cmd:  %s\n  spec: %s\n", cmd, out);
        exit(1);
    }
}

// Sends one request line, reads one response line, compares against the
// C-side answer. Exits with the full transcript on the first mismatch.
static inline void expect(const char *cmd, const char *want) {
    (void)fputs(cmd, to_spec);
    (void)fputc('\n', to_spec);
    (void)fflush(to_spec);
    // Sized for the largest reply any row produces: a sealed full-size
    // record is 2*(2^14 + overhead) hex characters.
    static char got[40960];
    if (fgets(got, sizeof got, from_spec) == NULL) {
        die("spec process closed the pipe (did spec/.lake/build/bin/diffspec build?)");
    }
    char *nl = strchr(got, '\n');
    if (nl != NULL) {
        *nl = '\0';
    }
    comparisons++;
    if (strcmp(got, want) != 0) {
        (void)fprintf(stderr, "diff mismatch:\n  cmd:  %s\n  C:    %s\n  spec: %s\n", cmd, want,
                      got);
        exit(1);
    }
}

#endif
