// The server side of the connection
// https://github.com/c4milo/chapulin/issues/188 measures, over OpenSSL:
// bench/handshake-n2.sh builds it against the runner's OpenSSL 3.0 and
// against the OpenSSL tools/toolchain.env pins, and counts it beside
// bench/handshake_server.c.
//
// It serves what that program serves: TLS 1.3 alone, the chain and key
// of the same PEM files, ALPN h2 and http/1.1, and no session tickets
// and no session cache, so every handshake is a full one. Its suites and
// groups are OpenSSL's defaults, which hold what the client offers.
//
// Usage: handshake_openssl_server PORT CONNECTIONS COUNTED CHAIN_PEM KEY_PEM [--count]
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "handshake_window.h"

#define REQUEST_LEN 100
#define RESPONSE_LEN 256

static SSL_CTX *ctx;
static SSL *ssl;
static int ssl_fd;

static void fail(const char *what) {
    fprintf(stderr, "handshake_openssl_server: %s\n", what);
    ERR_print_errors_fp(stderr);
    exit(1);
}

// RFC 7301: the first of the server's protocols the client offers.
static int select_alpn(SSL *s, const unsigned char **out, unsigned char *outlen,
                       const unsigned char *in, unsigned int inlen, void *arg) {
    static const unsigned char ours[] = "\x02h2\x08http/1.1";
    (void)s;
    (void)arg;
    unsigned char *chosen = NULL;
    if (SSL_select_next_proto(&chosen, outlen, ours, sizeof ours - 1, in, inlen) !=
        OPENSSL_NPN_NEGOTIATED) {
        return SSL_TLSEXT_ERR_ALERT_FATAL;
    }
    *out = chosen;
    return SSL_TLSEXT_ERR_OK;
}

__attribute__((noinline)) void bench_handshake(void) {
    ssl = SSL_new(ctx);
    if (ssl == NULL || SSL_set_fd(ssl, ssl_fd) != 1) {
        fail("SSL_new failed");
    }
    if (SSL_accept(ssl) != 1) {
        fail("SSL_accept failed");
    }
}

__attribute__((noinline)) void bench_exchange(void) {
    unsigned char request[REQUEST_LEN];
    size_t have = 0;
    while (have < sizeof request) {
        int got = SSL_read(ssl, request + have, (int)(sizeof request - have));
        if (got <= 0) {
            fail("SSL_read did not return the request");
        }
        have += (size_t)got;
    }
    unsigned char response[RESPONSE_LEN];
    memset(response, 'r', sizeof response);
    if (SSL_write(ssl, response, (int)sizeof response) != (int)sizeof response) {
        fail("SSL_write failed");
    }
    if (SSL_read(ssl, request, (int)sizeof request) > 0 ||
        SSL_get_error(ssl, 0) != SSL_ERROR_ZERO_RETURN) {
        fail("SSL_read did not return the client's close_notify");
    }
    if (SSL_shutdown(ssl) < 0) {
        fail("SSL_shutdown failed");
    }
    SSL_free(ssl);
    ssl = NULL;
    close(ssl_fd);
}

static void connection(int fd, void *context) {
    (void)context;
    ssl_fd = fd;
    bench_window_open();
    bench_handshake();
    bench_window_handshake();
    bench_exchange();
    bench_window_close();
}

int main(int argc, char **argv) {
    if (argc < 6) {
        fprintf(stderr, "usage: %s PORT CONNECTIONS COUNTED CHAIN_PEM KEY_PEM [--count]\n",
                argv[0]);
        return 2;
    }
    unsigned port = (unsigned)strtoul(argv[1], NULL, 10);
    unsigned connections = (unsigned)strtoul(argv[2], NULL, 10);
    unsigned counted = (unsigned)strtoul(argv[3], NULL, 10);
    int count = argc > 6 && strcmp(argv[6], "--count") == 0;

    ctx = SSL_CTX_new(TLS_server_method());
    if (ctx == NULL || SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION) != 1 ||
        SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION) != 1 ||
        SSL_CTX_use_certificate_chain_file(ctx, argv[4]) != 1 ||
        SSL_CTX_use_PrivateKey_file(ctx, argv[5], SSL_FILETYPE_PEM) != 1 ||
        SSL_CTX_check_private_key(ctx) != 1 || SSL_CTX_set_num_tickets(ctx, 0) != 1) {
        fail("the context refused the configuration");
    }
    SSL_CTX_set_options(ctx, SSL_OP_NO_TICKET);
    SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_OFF);
    SSL_CTX_set_alpn_select_cb(ctx, select_alpn, NULL);
    if (bench_counter_open(count) != 0) {
        fail("the kernel refused the instruction counter");
    }
    int rc = bench_serve(port, connections, counted, connection, NULL);
    SSL_CTX_free(ctx);
    return rc;
}
