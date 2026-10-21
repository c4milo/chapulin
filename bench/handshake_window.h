// The window bench/handshake-n2.sh counts on the server's side of one
// TLS connection, which bench/handshake_server.c (chapulin) and
// bench/handshake_openssl_server.c (OpenSSL) share. Each server serves its
// connections one at a time, and each connection runs the same steps:
//
//   1. bench_window_open, after accept returns;
//   2. the handshake, in a function named bench_handshake;
//   3. bench_window_handshake, once the handshake is complete;
//   4. the request and the response, in a function named bench_exchange,
//      and the two close_notify;
//   5. close of the socket, then bench_window_close.
//
// Three tools read the same window:
//
//   - With --count, each of the three calls reads a perf_events counter
//     of the process's user-mode instructions, and the server prints the
//     two parts of each connection. This is the count perf stat -e
//     instructions:u makes, read at the three points.
//   - Under valgrind's callgrind, the server calls bench_counted for the
//     connection that --counted names, so --toggle-collect=bench_counted
//     collects that connection alone.
//   - Under QEMU, bench/handshake_stages.py finds the entries of the three
//     calls in the trace by their symbols.
//
// The three calls are not inline and each writes a different value, so a
// compiler or a linker that folds identical functions keeps them apart.
#ifndef BENCH_HANDSHAKE_WINDOW_H
#define BENCH_HANDSHAKE_WINDOW_H

#include <stdint.h>

// Opens the counter when count is not zero. Returns 0, or -1 when the
// kernel refuses the counter.
int bench_counter_open(int count);

void bench_window_open(void);
void bench_window_handshake(void);
void bench_window_close(void);

// Prints the two parts of connection index (1 for the first) to stdout,
// in the form bench/handshake-n2.sh reads, when the counter is open.
void bench_window_report(unsigned index);

// Runs connection(fd, context) as the counted connection. Under
// callgrind's --toggle-collect=bench_counted it is the one connection
// whose instructions callgrind collects.
void bench_counted(void (*connection)(int fd, void *context), int fd, void *context);

// Listens on 127.0.0.1:port and serves connections one at a time, each
// through connection(fd, context), which opens and closes the window
// and closes fd. Connection number counted (1 for the first) runs
// through bench_counted. It prints the address of bench_window_open to
// stderr first, which the QEMU trace reads to place the binary. Returns
// 0, or 1 when a socket call fails.
int bench_serve(unsigned port, unsigned connections, unsigned counted,
                void (*connection)(int fd, void *context), void *context);

#endif
