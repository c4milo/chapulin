// What the ClientHello parser's two files share, and nothing outside them
// uses: srv_parser.c walks the message and srv_parser_ext.c reads each
// extension it recognizes. The parser is one concern in two files because
// one file of it ran past the 500-line limit, not because there are two
// concerns; webpki.h holds its seven files the same way and says the same
// thing about them. srv_parser.h states the parser's contract. Treat
// everything here as a module internal: no lint stops a third file from
// including this header or calling srv_read_extension, and nothing else
// should.
#ifndef CH_SRV_PARSER_EXT_H
#define CH_SRV_PARSER_EXT_H
#ifdef CH_ROLE_SERVER

#include <stddef.h>
#include <stdint.h>

#include "buf.h"
#include "cfg.h"
#include "sha256.h"
#include "srv_parser.h"

// Everything one parse carries between the readers: the body's length,
// which truncated_len counts from, the output, the caller's ALPN offer,
// the alert slot and the running frozen digest.
typedef struct {
    size_t n;
    client_hello *ch;
    const ch_alpn_protocol *offered;
    size_t offered_count;
    uint8_t *alert;
    sha256 frozen;
} hello_parse;

// Writes the description a refusal owes and returns the refusal, so
// every refusal in either file is one line that names its alert.
static inline int srv_refuse(uint8_t *alert, uint8_t description) {
    *alert = description;
    return CH_EPROTO;
}

// Reads the two-byte length of a list of two-byte code points and holds
// it to the list's syntax: at least one code point, an even byte count,
// and no more bytes than the reader has left. The last term keeps the
// walks that follow at the list's own length on a message that lies
// about it. Returns 1 with *list_len written, or 0 for a length outside
// the syntax, which the caller answers with decode_error.
//
// That last term carries no verdict of its own, and no test guards it,
// because deleting it changes no answer its callers give. A list longer
// than the bytes left makes srv_list_has read past the end, which sets
// the reader's sticky error, and every caller then refuses with
// decode_error: parse_extension on rb_left, and parse_head on the
// compression bytes it reads next. The term makes that refusal happen
// here instead of two reads later, and nothing else, so a mutant that
// removes it is not a coverage hole and test/violations/ holds none.
static inline int srv_open_code_point_list(rbuf *r, size_t *list_len) {
    *list_len = rb_u16(r);
    return !r->err && *list_len >= 2 && (*list_len & 1) == 0 && *list_len <= rb_left(r);
}

// Whether the next list_len bytes of r, a list srv_open_code_point_list
// admitted, hold code. It reads the whole list either way, so r ends at
// the list's end, and a code point outside this build's tables is read
// and ignored (rfc9846.txt:4636-4637).
static inline int srv_list_has(rbuf *r, size_t list_len, uint16_t code) {
    int found = 0;
    for (size_t i = 0; i < list_len; i += 2) {
        if (rb_u16(r) == code) {
            found = 1;
        }
    }
    return found;
}

// Reads one recognized extension's body. e is bounded by the length the
// message gave that extension, so no reader walks past it; type is a
// value srv_ext_known answers 1 for; data_off is where the body starts,
// counted from the start of the ClientHello body, and only
// pre_shared_key reads it. Returns CH_OK, or CH_EPROTO with p->alert
// written. The caller holds the body to being read exactly, so a reader
// that leaves bytes behind is refused without checking for itself.
// Defined in srv_parser_ext.c.
int srv_read_extension(rbuf *e, uint16_t type, size_t data_off, hello_parse *p);

#endif // CH_ROLE_SERVER
#endif
