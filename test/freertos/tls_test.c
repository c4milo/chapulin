// FreeRTOS+TCP on QEMU's MPS2-AN385: static IPv4 over the emulated
// LAN9118, one TCP connection through QEMU's user-mode network to an
// echo service on the host (10.0.2.2), a round trip verified byte for
// byte, then PASS over semihosting.
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "FreeRTOS.h"
#include "task.h"

#include "FreeRTOS_IP.h"
#include "FreeRTOS_Sockets.h"

extern uint8_t __bss_start[];
extern uint8_t __bss_end[];
extern uint8_t __stack_top[];

static long semihost(long op, long param) {
    register long r0 __asm__("r0") = op;
    register long r1 __asm__("r1") = param;
    __asm__ volatile("bkpt #0xAB" : "+r"(r0) : "r"(r1) : "memory");
    return r0;
}
static void plat_write(const char *s) {
    (void)semihost(0x04, (long)s);
}
static void plat_exit(int code) {
    (void)semihost(0x18, code == 0 ? 0x20026 : 0x20024);
    for (;;) {}
}

void freertos_assert_fail(const char *file, int line) {
    char buf[12];
    int i = sizeof buf - 1;
    buf[i--] = 0;
    if (line == 0) {
        buf[i--] = '0';
    }
    while (line > 0 && i >= 0) {
        buf[i--] = (char)('0' + line % 10);
        line /= 10;
    }
    plat_write("configASSERT ");
    plat_write(file);
    plat_write(":");
    plat_write(&buf[i + 1]);
    plat_write("\n");
    plat_exit(1);
}

static StaticTask_t idle_tcb;
static StackType_t idle_stack[configMINIMAL_STACK_SIZE];
void vApplicationGetIdleTaskMemory(StaticTask_t **tcb, StackType_t **stack, uint32_t *n) {
    *tcb = &idle_tcb;
    *stack = idle_stack;
    *n = configMINIMAL_STACK_SIZE;
}

// Deterministic: TCP needs numbers, the test needs replayability.
static uint32_t rng_state = 0x1234567u;
static uint32_t rng_next(void) {
    rng_state ^= rng_state << 13;
    rng_state ^= rng_state >> 17;
    rng_state ^= rng_state << 5;
    return rng_state;
}
BaseType_t xApplicationGetRandomNumber(uint32_t *out) {
    *out = rng_next();
    return pdTRUE;
}
uint32_t ulApplicationGetNextSequenceNumber(uint32_t a, uint16_t b, uint32_t c, uint16_t d) {
    (void)a;
    (void)b;
    (void)c;
    (void)d;
    return rng_next();
}

static const uint8_t mac[6] = {0x02, 0x11, 0x22, 0x33, 0x44, 0x55};
static NetworkInterface_t iface;
static NetworkEndPoint_t endpoint;

NetworkInterface_t *pxMPS2_FillInterfaceDescriptor(BaseType_t idx, NetworkInterface_t *out);

#include "tls.h"

extern void ch_assert_fail(const char *cond, const char *file, int line);
void ch_assert_fail(const char *cond, const char *file, int line) {
    (void)cond;
    freertos_assert_fail(file, line);
}

// Deterministic handshake randomness: fine against a live peer -- the
// server contributes its own entropy -- and it makes failures replay.
void ch_rand_bytes(uint8_t *p, size_t n) {
    for (size_t i = 0; i < n; i++) {
        uint32_t v = rng_next();
        p[i] = (uint8_t)(v >> 24);
    }
}

static int io_send(void *ctx, const uint8_t *p, size_t n) {
    Socket_t s = *(Socket_t *)ctx;
    size_t off = 0;
    while (off < n) {
        BaseType_t r = FreeRTOS_send(s, p + off, n - off, 0);
        if (r <= 0) {
            return -1;
        }
        off += (size_t)r;
    }
    return 0;
}
static int io_recv(void *ctx, uint8_t *p, size_t n) {
    Socket_t s = *(Socket_t *)ctx;
    BaseType_t r = FreeRTOS_recv(s, p, n, 0);
    return r > 0 ? (int)r : -1;
}

static const uint8_t psk[32] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
                                0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16,
                                0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20};

static void client_task(void *arg) {
    (void)arg;
    static Socket_t sock;
    sock = FreeRTOS_socket(FREERTOS_AF_INET, FREERTOS_SOCK_STREAM, FREERTOS_IPPROTO_TCP);
    if (sock == FREERTOS_INVALID_SOCKET) {
        plat_write("FAIL socket\n");
        plat_exit(1);
    }
    struct freertos_sockaddr addr;
    memset(&addr, 0, sizeof addr);
    addr.sin_family = FREERTOS_AF_INET;
    addr.sin_port = FreeRTOS_htons(4433);
    addr.sin_address.ulIP_IPv4 = FreeRTOS_inet_addr_quick(10, 0, 2, 2);
    if (FreeRTOS_connect(sock, &addr, sizeof addr) != 0) {
        plat_write("FAIL connect\n");
        plat_exit(1);
    }

    static uint8_t rxbuf[2048];
    static ch_tls tls;
    ch_cfg cfg;
    memset(&cfg, 0, sizeof cfg);
    cfg.buf = rxbuf;
    cfg.buf_len = sizeof rxbuf;
    cfg.send = io_send;
    cfg.recv = io_recv;
    cfg.io = &sock;
    cfg.psk = psk;
    cfg.psk_len = sizeof psk;
    cfg.psk_id = (const uint8_t *)"device-42";
    cfg.psk_id_len = 9;

    if (ch_connect(&tls, &cfg) != CH_OK) {
        plat_write("FAIL ch_connect\n");
        plat_exit(1);
    }
    plat_write("tls up\n");

    // The e2e servers run -rev: send a line, read it reversed.
    static const char msg[] = "freertos\n";
    if (ch_write(&tls, (const uint8_t *)msg, sizeof msg - 1) != CH_OK) {
        plat_write("FAIL ch_write\n");
        plat_exit(1);
    }
    uint8_t back[16];
    size_t got = 0;
    while (got < 8) {
        int r = ch_read(&tls, back + got, sizeof back - got);
        if (r <= 0) {
            plat_write("FAIL ch_read\n");
            plat_exit(1);
        }
        got += (size_t)r;
    }
    if (memcmp(back, "sotreerf", 8) != 0) {
        back[got < sizeof back ? got : sizeof back - 1] = 0;
        plat_write("FAIL echo: ");
        plat_write((const char *)back);
        plat_write("\n");
        plat_exit(1);
    }
    ch_close(&tls);
    plat_write("PASS\n");
    plat_exit(0);
}

static StaticTask_t client_tcb;
static StackType_t client_stack[4096];

void vApplicationIPNetworkEventHook_Multi(eIPCallbackEvent_t event, struct xNetworkEndPoint *ep) {
    (void)ep;
    static BaseType_t started = pdFALSE;
    if (event == eNetworkUp && started == pdFALSE) {
        started = pdTRUE;
        plat_write("net up\n");
        (void)xTaskCreateStatic(client_task, "client", 4096, NULL, 2, client_stack, &client_tcb);
    }
}

int main(void) {
    // The driver enables the ethernet IRQ in the NVIC but never sets
    // its priority, which defaults to 0 -- above
    // configMAX_SYSCALL_INTERRUPT_PRIORITY, so the ISR's FromISR calls
    // trip the port's validation. One byte in the IPR field fixes it.
    (*(volatile uint8_t *)(0xE000E400UL + 13)) = 190;
    (void)pxMPS2_FillInterfaceDescriptor(0, &iface);
    FreeRTOS_FillEndPoint(&iface, &endpoint, (const uint8_t[]){10, 0, 2, 15},
                          (const uint8_t[]){255, 255, 255, 0}, (const uint8_t[]){10, 0, 2, 2},
                          (const uint8_t[]){0, 0, 0, 0}, mac);
    if (FreeRTOS_IPInit_Multi() != pdPASS) {
        plat_write("FAIL ipinit\n");
        plat_exit(1);
    }
    vTaskStartScheduler();
    plat_write("FAIL scheduler returned\n");
    plat_exit(1);
    return 0;
}

void reset_handler(void) {
    for (uint8_t *p = __bss_start; p < __bss_end; p++) {
        *p = 0;
    }
    plat_exit(main());
}

static void default_handler(void) {
    plat_write("FAIL unexpected exception\n");
    plat_exit(1);
}

extern void vPortSVCHandler(void);
extern void xPortPendSVHandler(void);
extern void xPortSysTickHandler(void);
extern void EthernetISR(void);

// System vectors, then the external interrupts out to the LAN9118's
// IRQ 13 (vector 29), which the driver enables in the NVIC itself.
__attribute__((section(".vectors"), used)) static const struct {
    unsigned char *sp;
    void (*handlers[29])(void);
} vectors = {
    __stack_top,
    {reset_handler,
      default_handler, default_handler,
      default_handler, default_handler,
      default_handler, 0,
      0, 0,
      0, vPortSVCHandler,
      default_handler, 0,
      xPortPendSVHandler, xPortSysTickHandler, // external IRQs 0..13
     default_handler, default_handler,
      default_handler, default_handler,
      default_handler, default_handler,
      default_handler, default_handler,
      default_handler, default_handler,
      default_handler, default_handler,
      default_handler, EthernetISR},
};

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

// The network interface prints its MAC once through snprintf; a
// freestanding image has no formatting to offer and the test does not
// read it, so this stub just terminates the buffer.
int snprintf(char *out, size_t cap, const char *fmt, ...) {
    (void)fmt;
    if (cap > 0) {
        out[0] = 0;
    }
    return 0;
}
