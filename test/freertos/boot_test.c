// FreeRTOS on QEMU's MPS2-AN385: two static tasks ping-pong prints, so
// the PASS line proves the scheduler context-switched, not just that
// main ran. Semihosting for output and exit, everything static.
#include <stddef.h>
#include <stdint.h>

#include "FreeRTOS.h"
#include "task.h"

extern uint8_t __bss_start[];
extern uint8_t __bss_end[];
extern uint8_t __stack_top[];

static long semihost(long op, long param) {
    long res;
    __asm__ volatile("mov r0, %1\n\tmov r1, %2\n\tbkpt #0xAB\n\tmov %0, r0"
                     : "=r"(res)
                     : "r"(op), "r"(param)
                     : "r0", "r1", "memory");
    return res;
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
void vApplicationGetIdleTaskMemory(StaticTask_t **ppxIdleTaskTCBBuffer,
                                   StackType_t **ppxIdleTaskStackBuffer,
                                   uint32_t *puxIdleTaskStackSize) {
    *ppxIdleTaskTCBBuffer = &idle_tcb;
    *ppxIdleTaskStackBuffer = idle_stack;
    *puxIdleTaskStackSize = configMINIMAL_STACK_SIZE;
}

static volatile int pings;

static void ping_task(void *arg) {
    (void)arg;
    for (int i = 0; i < 3; i++) {
        plat_write("ping\n");
        pings++;
        vTaskDelay(1);
    }
    vTaskDelete(NULL);
}

static void pong_task(void *arg) {
    (void)arg;
    for (int i = 0; i < 3; i++) {
        plat_write("pong\n");
        vTaskDelay(1);
    }
    if (pings == 3) {
        plat_write("PASS\n");
        plat_exit(0);
    }
    plat_write("FAIL: ping never ran\n");
    plat_exit(1);
}

static StaticTask_t ping_tcb, pong_tcb;
static StackType_t ping_stack[configMINIMAL_STACK_SIZE], pong_stack[configMINIMAL_STACK_SIZE];

int main(void) {
    (void)xTaskCreateStatic(ping_task, "ping", configMINIMAL_STACK_SIZE, NULL, 2, ping_stack,
                            &ping_tcb);
    (void)xTaskCreateStatic(pong_task, "pong", configMINIMAL_STACK_SIZE, NULL, 1, pong_stack,
                            &pong_tcb);
    vTaskStartScheduler();
    plat_write("FAIL: scheduler returned\n");
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
    plat_write("FAIL: unexpected exception\n");
    plat_exit(1);
}

extern void vPortSVCHandler(void);
extern void xPortPendSVHandler(void);
extern void xPortSysTickHandler(void);

// The M-profile vector table. The struct form avoids the object-to-
// function-pointer cast -Wpedantic rejects under gcc.
__attribute__((section(".vectors"), used)) static const struct {
    unsigned char *sp;
    void (*handlers[15])(void);
} vectors = {
    __stack_top,
    {reset_handler, default_handler, default_handler, default_handler, default_handler,
      default_handler, 0, 0, 0, 0, vPortSVCHandler, default_handler, 0, xPortPendSVHandler,
      xPortSysTickHandler},
};

void *memset(void *d, int c, size_t n) {
    uint8_t *dp = d;
    while (n--) {
        *dp++ = (uint8_t)c;
    }
    return d;
}
void *memcpy(void *d, const void *s, size_t n) {
    uint8_t *dp = d;
    const uint8_t *sp = s;
    while (n--) {
        *dp++ = *sp++;
    }
    return d;
}
