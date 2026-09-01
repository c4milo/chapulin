// Cortex-M3 runtime for the QEMU smoke run: the vector table, a reset
// handler that clears .bss and calls main, semihosting for output and
// exit, and the byte-wise mem routines a freestanding build needs. On
// the MPS2-AN385 everything -- code, data, stack -- lives in the ZBT
// SRAM at address zero, so there is no flash-to-RAM copy.
#include <stddef.h>
#include <stdint.h>

extern uint8_t __bss_start[];
extern uint8_t __bss_end[];
extern uint8_t __stack_top[];

int main(void);

// ARM semihosting (BKPT 0xAB): operation in r0, parameter in r1.
static long semihost(long op, long param) {
    register long r0 __asm__("r0") = op;
    register long r1 __asm__("r1") = param;
    __asm__ volatile("bkpt #0xAB" : "+r"(r0) : "r"(r1) : "memory");
    return r0;
}

void plat_write(const char *s) {
    (void)semihost(0x04, (long)s); // SYS_WRITE0: NUL-terminated string
}

void plat_exit(int code) {
    // SYS_EXIT: ADP_Stopped_ApplicationExit reports success to qemu;
    // any other reason code makes qemu exit nonzero.
    (void)semihost(0x18, code == 0 ? 0x20026 : 0x20024);
    for (;;) {}
}

void reset_handler(void) {
    for (uint8_t *p = __bss_start; p < __bss_end; p++) {
        *p = 0;
    }
    plat_exit(main());
}

__attribute__((section(".vectors"), used)) static const struct {
    const void *stack;
    void (*reset)(void);
} vectors = {__stack_top, reset_handler};

void *memcpy(void *d, const void *s, size_t n) {
    uint8_t *dp = d;
    const uint8_t *sp = s;
    while (n--) {
        *dp++ = *sp++;
    }
    return d;
}
void *memmove(void *d, const void *s, size_t n) {
    uint8_t *dp = d;
    const uint8_t *sp = s;
    if (dp < sp) {
        while (n--) {
            *dp++ = *sp++;
        }
    } else {
        while (n--) {
            dp[n] = sp[n];
        }
    }
    return d;
}
void *memset(void *d, int c, size_t n) {
    uint8_t *dp = d;
    while (n--) {
        *dp++ = (uint8_t)c;
    }
    return d;
}
int memcmp(const void *a, const void *b, size_t n) {
    const uint8_t *ap = a;
    const uint8_t *bp = b;
    for (; n--; ap++, bp++) {
        if (*ap != *bp) {
            return *ap < *bp ? -1 : 1;
        }
    }
    return 0;
}
size_t strlen(const char *s) {
    const char *p = s;
    while (*p) {
        p++;
    }
    return (size_t)(p - s);
}

// The Arm EABI's own runtime calls: clang lowers block copies and
// clears to these on thumbv7m. The EABI's memset takes (dest, n, c) --
// the argument order is not libc's.
void __aeabi_memcpy(void *d, const void *s, size_t n) {
    (void)memcpy(d, s, n);
}
void __aeabi_memcpy4(void *d, const void *s, size_t n) {
    (void)memcpy(d, s, n);
}
void __aeabi_memcpy8(void *d, const void *s, size_t n) {
    (void)memcpy(d, s, n);
}
void __aeabi_memmove(void *d, const void *s, size_t n) {
    (void)memmove(d, s, n);
}
void __aeabi_memmove4(void *d, const void *s, size_t n) {
    (void)memmove(d, s, n);
}
void __aeabi_memmove8(void *d, const void *s, size_t n) {
    (void)memmove(d, s, n);
}
void __aeabi_memset(void *d, size_t n, int c) {
    (void)memset(d, c, n);
}
void __aeabi_memset4(void *d, size_t n, int c) {
    (void)memset(d, c, n);
}
void __aeabi_memset8(void *d, size_t n, int c) {
    (void)memset(d, c, n);
}
void __aeabi_memclr(void *d, size_t n) {
    (void)memset(d, 0, n);
}
void __aeabi_memclr4(void *d, size_t n) {
    (void)memset(d, 0, n);
}
void __aeabi_memclr8(void *d, size_t n) {
    (void)memset(d, 0, n);
}
