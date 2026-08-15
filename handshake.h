// The TLS 1.3 ECDHE-PSK client handshake: one entry point that drives the
// caller's I/O from ClientHello to connected, including one
// HelloRetryRequest round. Everything it learns lands in the ms_tls
// session; every failure wipes and kills the session.
#ifndef MS_HANDSHAKE_H
#define MS_HANDSHAKE_H

#include "tls.h"

int ms_handshake(ms_tls *t);

// Shared with tls.c (session teardown and alerts).
#define ALERT_CLOSE_NOTIFY 0
#define ALERT_UNEXPECTED_MESSAGE 10
#define ALERT_BAD_RECORD_MAC 20
#define ALERT_RECORD_OVERFLOW 22
#define ALERT_HANDSHAKE_FAILURE 40
#define ALERT_ILLEGAL_PARAMETER 47
#define ALERT_DECODE_ERROR 50
#define ALERT_DECRYPT_ERROR 51
#define ALERT_INTERNAL_ERROR 80

#define MS_ST_START 0
#define MS_ST_CONNECTED 1
#define MS_ST_CLOSED 2
#define MS_ST_FAILED 3

// Sends an alert record (best effort, encrypted iff keys are installed)
// and wipes all key material. Defined in tls.c.
void tlsi_fail(ms_tls *t, uint8_t desc);
int tlsi_send_alert(ms_tls *t, uint8_t level, uint8_t desc);

#endif
