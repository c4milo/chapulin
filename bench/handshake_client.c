// The client side of the connection
// https://github.com/c4milo/chapulin/issues/188 measures, which
// bench/handshake-n2.sh runs against each server it counts. It offers
// what h2load 1.59.0 offers in colibri's bench: TLS 1.3 with
// TLS_AES_256_GCM_SHA384 alone, the groups X25519, P-256, P-384 and P-521
// with one X25519 share, the server name localhost and ALPN h2. It does
// not check the server's chain. After the handshake it sends one record
// of REQUEST_LEN bytes, reads RESPONSE_LEN bytes, sends close_notify and
// reads the server's.
//
// Usage: handshake_client PORT CONNECTIONS
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define REQUEST_LEN 100
#define RESPONSE_LEN 256
// The server may still be starting, under QEMU or valgrind for seconds.
#define CONNECT_TRIES 600
#define CONNECT_WAIT_NS 100000000L

static void fail(const char *what) {
    fprintf(stderr, "handshake_client: %s\n", what);
    ERR_print_errors_fp(stderr);
    exit(1);
}

static int connect_to(unsigned port) {
    struct sockaddr_in address;
    memset(&address, 0, sizeof address);
    address.sin_family = AF_INET;
    address.sin_port = htons((uint16_t)port);
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    for (int tries = 0; tries < CONNECT_TRIES; tries++) {
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0) {
            fail("socket failed");
        }
        if (connect(fd, (struct sockaddr *)&address, sizeof address) == 0) {
            int one = 1;
            (void)setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
            return fd;
        }
        close(fd);
        struct timespec wait = {0, CONNECT_WAIT_NS};
        nanosleep(&wait, NULL);
    }
    fail("the server never accepted a connection");
    return -1;
}

static void one_connection(SSL_CTX *ctx, unsigned port) {
    int fd = connect_to(port);
    SSL *ssl = SSL_new(ctx);
    if (ssl == NULL || SSL_set_fd(ssl, fd) != 1 ||
        SSL_set_tlsext_host_name(ssl, "localhost") != 1 ||
        SSL_set1_groups_list(ssl, "X25519:P-256:P-384:P-521") != 1) {
        fail("SSL_new failed");
    }
    if (SSL_connect(ssl) != 1) {
        fail("SSL_connect failed");
    }
    const unsigned char *alpn = NULL;
    unsigned int alpn_len = 0;
    SSL_get0_alpn_selected(ssl, &alpn, &alpn_len);
    if (alpn_len != 2 || memcmp(alpn, "h2", 2) != 0 ||
        strcmp(SSL_get_cipher_name(ssl), "TLS_AES_256_GCM_SHA384") != 0) {
        fail("the server did not select h2 and TLS_AES_256_GCM_SHA384");
    }
    unsigned char request[REQUEST_LEN];
    memset(request, 'q', sizeof request);
    if (SSL_write(ssl, request, (int)sizeof request) != (int)sizeof request) {
        fail("SSL_write failed");
    }
    unsigned char response[RESPONSE_LEN];
    size_t have = 0;
    while (have < sizeof response) {
        int got = SSL_read(ssl, response + have, (int)(sizeof response - have));
        if (got <= 0) {
            fail("SSL_read did not return the response");
        }
        have += (size_t)got;
    }
    // The first call sends close_notify, and the second reads the server's.
    if (SSL_shutdown(ssl) < 0 || SSL_shutdown(ssl) != 1) {
        fail("the server sent no close_notify");
    }
    SSL_free(ssl);
    close(fd);
}

int main(int argc, char **argv) {
    if (argc != 3) {
        fprintf(stderr, "usage: %s PORT CONNECTIONS\n", argv[0]);
        return 2;
    }
    unsigned port = (unsigned)strtoul(argv[1], NULL, 10);
    unsigned connections = (unsigned)strtoul(argv[2], NULL, 10);
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (ctx == NULL || SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION) != 1 ||
        SSL_CTX_set_ciphersuites(ctx, "TLS_AES_256_GCM_SHA384") != 1 ||
        SSL_CTX_set_alpn_protos(ctx, (const unsigned char *)"\x02h2", 3) != 0) {
        fail("the context refused the configuration");
    }
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
    for (unsigned i = 0; i < connections; i++) {
        one_connection(ctx, port);
    }
    SSL_CTX_free(ctx);
    return 0;
}
