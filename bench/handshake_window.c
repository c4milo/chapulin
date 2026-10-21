// The window bench/handshake_window.h describes. The counter is Linux's
// perf_events counter of the instructions this process retires in user
// mode. Another system has no such counter, and there --count fails.
#define _GNU_SOURCE
#include "handshake_window.h"

#include <arpa/inet.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#ifdef __linux__
#include <linux/perf_event.h>
#include <sys/syscall.h>
#endif

static int counter_fd = -1;
static uint64_t at_open;
static uint64_t at_handshake;
static uint64_t at_close;

// The three calls write here, so no two of them have the same body.
volatile unsigned bench_window_mark;

int bench_counter_open(int count) {
    if (count == 0) {
        return 0;
    }
#ifdef __linux__
    struct perf_event_attr attr;
    memset(&attr, 0, sizeof attr);
    attr.type = PERF_TYPE_HARDWARE;
    attr.size = sizeof attr;
    attr.config = PERF_COUNT_HW_INSTRUCTIONS;
    attr.exclude_kernel = 1;
    attr.exclude_hv = 1;
    long fd = syscall(SYS_perf_event_open, &attr, 0, -1, -1, 0);
    if (fd < 0) {
        return -1;
    }
    counter_fd = (int)fd;
    return 0;
#else
    return -1;
#endif
}

static uint64_t counter_read(void) {
    uint64_t value = 0;
#ifdef __linux__
    if (counter_fd >= 0 && read(counter_fd, &value, sizeof value) != (ssize_t)sizeof value) {
        value = 0;
    }
#endif
    return value;
}

__attribute__((noinline)) void bench_window_open(void) {
    bench_window_mark = 1;
    at_open = counter_read();
}

__attribute__((noinline)) void bench_window_handshake(void) {
    bench_window_mark = 2;
    at_handshake = counter_read();
}

__attribute__((noinline)) void bench_window_close(void) {
    bench_window_mark = 3;
    at_close = counter_read();
}

void bench_window_report(unsigned index) {
    if (counter_fd < 0) {
        return;
    }
    printf("connection %u handshake %llu exchange %llu\n", index,
           (unsigned long long)(at_handshake - at_open),
           (unsigned long long)(at_close - at_handshake));
    fflush(stdout);
}

__attribute__((noinline)) void bench_counted(void (*connection)(int fd, void *context), int fd,
                                             void *context) {
    connection(fd, context);
    bench_window_mark = 4;
}

int bench_serve(unsigned port, unsigned connections, unsigned counted,
                void (*connection)(int fd, void *context), void *context) {
    fprintf(stderr, "bench_window_open 0x%" PRIxPTR "\n", (uintptr_t)bench_window_open);
    int listener = socket(AF_INET, SOCK_STREAM, 0);
    if (listener < 0) {
        perror("socket");
        return 1;
    }
    int one = 1;
    (void)setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    struct sockaddr_in address;
    memset(&address, 0, sizeof address);
    address.sin_family = AF_INET;
    address.sin_port = htons((uint16_t)port);
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(listener, (struct sockaddr *)&address, sizeof address) != 0 ||
        listen(listener, 4) != 0) {
        perror("bind");
        close(listener);
        return 1;
    }
    for (unsigned index = 1; index <= connections; index++) {
        int fd = accept(listener, NULL, NULL);
        if (fd < 0) {
            perror("accept");
            close(listener);
            return 1;
        }
        (void)setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
        if (index == counted) {
            bench_counted(connection, fd, context);
        } else {
            connection(fd, context);
        }
        bench_window_report(index);
    }
    close(listener);
    return 0;
}
