// A run of CERTIFICATE blocks in one text: a server's certificate chain
// or a client's CA bundle (pem_files.h). pem.c reads each block. This
// file reads the text around the blocks and between them, which is the
// one place the two files differ.
//
// A chain is strict, as pem_decode_certificate is. The first block opens
// at the first byte, and outside the blocks there is nothing but CR and
// LF. A bundle skips text. curl's cacert.pem, for one, carries a name and
// a line of '=' above each root, and comment lines above the first root.
// The owner ruled on 2026-10-13 that a bundle skips text before, between
// and after its blocks. He also ruled that a BEGIN line of any label but
// CERTIFICATE refuses the bundle. So the run reads every block that opens
// at a BEGIN line, or it refuses the bundle. A chain and a key file stay
// strict (docs/decisions.md 131).
//
// The caller reads the blocks one at a time through pem_blocks_next, so
// it decides where each block's DER goes and how many blocks it takes.
// This file holds no count of its own and no array.
//
// A block that decodes is not authenticated (pem.h). Certificates are
// public, so nothing here is wiped.
#ifndef CH_PEM_BLOCKS_H
#define CH_PEM_BLOCKS_H

#include <stddef.h>
#include <stdint.h>

#include "buf.h"

// What may lie outside the blocks.
//
// PEM_TEXT_REFUSED: CR and LF alone. The first block's BEGIN line starts
// at the first byte. Between two blocks lie one or more CR and LF bytes,
// and the last of them is LF, so each BEGIN line starts a line. After the
// last block lie CR and LF bytes or nothing.
//
// PEM_TEXT_SKIPPED: text lines, and BEGIN lines of CERTIFICATE alone.
// RFC 7468 section 3 writes a pre-encapsulation boundary as "-----BEGIN ",
// a label and "-----". Here a BEGIN line is a line that starts with the
// first 11 bytes, "-----BEGIN ", whatever follows them.
//  - The one BEGIN line that opens a block is "-----BEGIN CERTIFICATE-----"
//    and a line terminator. pem_read_block then judges the block whole.
//  - Every other BEGIN line breaks the rule. Its label is another one,
//    such as TRUSTED CERTIFICATE or X509 CERTIFICATE, or its boundary is
//    broken, for example with four dashes at its end.
//  - "-----BEGIN " at any other byte of a line breaks the rule too. It
//    can stand behind a byte-order mark, an indent or a comment's text.
//  - Every other line is text. The reader skips it through its LF or to
//    the end of the input, before the first block, between blocks and
//    after the last. A comment that holds "-----BEGIN" with no space after
//    it is text.
// The lines a bundle carries as text do not hold "-----BEGIN ": a root's
// name, a line of '=' and a block's base64. Each block's END line ends its
// line: the input ends there, or LF or CR LF follows it.
//
// The 11 bytes match byte for byte. A line that differs inside them is
// text, for example "-----begin " or "-----BEGIN" and a tab. An END line
// outside a block is text too. So when a block's first line differs
// inside the 11 bytes, the reader skips that line, the body and the END
// line as text.
#define PEM_TEXT_REFUSED 0
#define PEM_TEXT_SKIPPED 1

// The reader of one run: the text not yet read, the text rule, and
// whether a block was read. The caller places it and pem_blocks_init
// fills it. The fields are this file's.
typedef struct {
    rbuf text;
    uint8_t rule;    // PEM_TEXT_REFUSED or PEM_TEXT_SKIPPED
    uint8_t started; // 1 once pem_blocks_next has read a block
} pem_blocks;

// Sets b to read pem from its first byte under rule.
void pem_blocks_init(pem_blocks *b, const uint8_t *pem, size_t pem_len, uint8_t rule);

// What pem_blocks_next found.
#define PEM_BLOCKS_END 0     // the text ended where the rule lets it, and no block was read
#define PEM_BLOCKS_READ 1    // a block was read
#define PEM_BLOCKS_REFUSED 2 // the text or the block broke a rule

// Reads the text before the next block under b's rule, and that block.
// Appends the block's DER to der.
//
// Returns PEM_BLOCKS_READ, and *block and *block_len then name the DER
// this call appended, 1 byte or more inside der's room. Returns
// PEM_BLOCKS_END when the text ends where the rule lets it. A text with
// no block gives it on the first call, and the caller refuses a run of no
// block. Returns
// PEM_BLOCKS_REFUSED when the text breaks the rule, when a block breaks
// pem_read_block's grammar, or when the DER outgrows der's room. After
// PEM_BLOCKS_END or PEM_BLOCKS_REFUSED the caller makes no further call
// on b. On PEM_BLOCKS_REFUSED, der's room holds unspecified bytes after
// the length it had.
int pem_blocks_next(pem_blocks *b, wbuf *der, const uint8_t **block, size_t *block_len);

// Reads the CR and LF bytes at r's position and stops at the first other
// byte, which it leaves unread. Returns the last byte it read, '\r' or
// '\n', or 0 when it read none. A next block's BEGIN line starts a line
// when this returns '\n' and a byte follows. The chain's rule reads the
// text between two blocks through it, and so does pem_files.c between a
// key file's EC PARAMETERS block and its key.
uint8_t pem_skip_line_breaks(rbuf *r);

#endif
