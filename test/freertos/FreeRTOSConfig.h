#ifndef FREERTOS_CONFIG_H
#define FREERTOS_CONFIG_H

void freertos_assert_fail(const char *file, int line);

#define configUSE_PREEMPTION 1
#define configUSE_IDLE_HOOK 0
#define configUSE_TICK_HOOK 0
#define configCPU_CLOCK_HZ 25000000UL
#define configTICK_RATE_HZ 1000
#define configMAX_PRIORITIES 5
#define configMINIMAL_STACK_SIZE 256
#define configMAX_TASK_NAME_LEN 12
#define configUSE_16_BIT_TICKS 0
#define configIDLE_SHOULD_YIELD 1
#define configSUPPORT_STATIC_ALLOCATION 1
#define configSUPPORT_DYNAMIC_ALLOCATION 1
#define configTOTAL_HEAP_SIZE (96 * 1024)
#define configUSE_MUTEXES 0
#define configUSE_COUNTING_SEMAPHORES 1
#define configQUEUE_REGISTRY_SIZE 0
#define configUSE_TRACE_FACILITY 0
#define configUSE_TIMERS 0
#define configCHECK_FOR_STACK_OVERFLOW 0

#define INCLUDE_vTaskDelay 1
#define INCLUDE_vTaskDelete 1

#define configKERNEL_INTERRUPT_PRIORITY 255
#define configMAX_SYSCALL_INTERRUPT_PRIORITY 190

#define configASSERT(x)                                                                            \
    do {                                                                                           \
        if (!(x)) {                                                                                \
            freertos_assert_fail(__FILE__, __LINE__);                                              \
        }                                                                                          \
    } while (0)

#endif
