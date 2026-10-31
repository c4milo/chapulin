// A run of blocks in one text: a server's certificate chain, a client's
// CA bundle and a private key file (pem_files.h). pem.c reads each block.
// This file reads the text around the blocks and between them.
//
// RFC 7468 section 2 permits data before the encapsulation boundaries,
// and its parsers MUST NOT malfunction on it. Section 5.2 shows
// explanatory text above a CERTIFICATE block, and curl's cacert.pem
// carries a name and a line of '=' above each root. So every file skips
// text before, between and after its blocks. The owner ruled so for a
// bundle on 2026-10-13, and for a chain and a key file on 2026-10-31
// (docs/decisions.md 131 and 170). A BEGIN line of a label the caller
// does not read refuses the file. So the run reads every block that opens
// at a BEGIN line, or it refuses the file.
//
// The caller reads the blocks one at a time through pem_blocks_next and
// names each block's label, so it decides which blocks a file holds,
// where each block's DER goes and how many blocks it takes. This file
// holds no count of its own and no array.
//
// A block that decodes is not authenticated (pem.h). A key block's DER is
// a secret, and the caller wipes the room it gave. The text outside the
// blocks is public, and the reader branches on it. pem.c decodes a
// block's body in constant time (base64.h).
#ifndef CH_PEM_BLOCKS_H
#define CH_PEM_BLOCKS_H

#include <stddef.h>
#include <stdint.h>

#include "buf.h"

// What may lie outside the blocks: text lines, and the BEGIN lines of the
// labels the caller reads. RFC 7468 section 3 writes a pre-encapsulation
// boundary as "-----BEGIN ", a label and "-----". Here a BEGIN line is a
// line that starts with the first 11 bytes, "-----BEGIN ", whatever
// follows them.
//  - The one BEGIN line that opens a block is the BEGIN line of the label
//    the caller names, and a line terminator. pem_read_block then judges
//    the block whole.
//  - Every other BEGIN line breaks the rule. Its label is another one,
//    such as TRUSTED CERTIFICATE or X509 CERTIFICATE, or its boundary is
//    broken, for example with four dashes at its end.
//  - "-----BEGIN " at any other byte of a line breaks the rule too. It
//    can stand behind a byte-order mark, an indent or a comment's text.
//  - Every other line is text. The reader skips it through its LF or to
//    the end of the input, before the first block, between blocks and
//    after the last. A comment that holds "-----BEGIN" with no space after
//    it is text.
// The lines a file carries as text do not hold "-----BEGIN ": a root's
// name, a line of '=', a certificate's Subject: line and a block's base64.
// Each block's END line ends its line: the input ends there, or LF or
// CR LF follows it.
//
// The 11 bytes match byte for byte. A line that differs inside them is
// text, for example "-----begin " or "-----BEGIN" and a tab. An END line
// outside a block is text too. So when a block's first line differs
// inside the 11 bytes, the reader skips that line, the body and the END
// line as text.

// The reader of one run: the text not yet read, and whether a block was
// read. The caller places it and pem_blocks_init fills it. The fields are
// this file's.
typedef struct {
    rbuf text;
    uint8_t started; // 1 once pem_blocks_next has read a block
} pem_blocks;

// Sets b to read pem from its first byte.
void pem_blocks_init(pem_blocks *b, const uint8_t *pem, size_t pem_len);

// What pem_blocks_next found.
#define PEM_BLOCKS_END 0     // the text ended where the rule lets it, and no block was read
#define PEM_BLOCKS_READ 1    // a block was read
#define PEM_BLOCKS_REFUSED 2 // the text or the block broke a rule

// Reads the text before the next block, and that block, which must carry
// label, one of pem.h's PEM_LABEL_ values. Appends the block's DER to der.
//
// Returns PEM_BLOCKS_READ, and *block and *block_len then name the DER
// this call appended, 1 byte or more inside der's room. Returns
// PEM_BLOCKS_END when the text ends where the rule lets it. A text with
// no block gives it on the first call, and the caller refuses a run of no
// block. Returns PEM_BLOCKS_REFUSED when the text breaks the rule, when
// the block carries another label or breaks pem_read_block's grammar, or
// when the DER outgrows der's room. After
// PEM_BLOCKS_END or PEM_BLOCKS_REFUSED the caller makes no further call
// on b. On PEM_BLOCKS_REFUSED, der's room holds unspecified bytes after
// the length it had.
int pem_blocks_next(pem_blocks *b, uint8_t label, wbuf *der, const uint8_t **block,
                    size_t *block_len);

#endif
