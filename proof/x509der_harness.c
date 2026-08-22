// Proves: every DER primitive in x509_der.c is memory-safe and UB-free,
// CONCRETE (real bodies, real rbuf via buf.c), over nondet bytes at the
// bound the certificate grammar admits for that primitive:
//
//   x509_read_len/header : consume at most 4 bytes (tag plus the 0x82
//                          length form, the longest under CH_X509_MAX),
//                          driven over the 448-byte buffer so all three
//                          admitted length forms can succeed — the 0x82
//                          arm needs at least 0x100 trailing bytes
//   x509_read_exact      : compare of up to 67 bytes, the largest pinned
//                          constant (the RSA-PSS AlgorithmIdentifier)
//   x509_skip            : header plus content over the 448-byte buffer
//   x509_read_serial     : 24 bytes; the largest shape is 23 (2-byte
//                          header + 21 content), so a trailing byte exists
//   x509_read_time       : 20 bytes; the largest shape is 17 (tag + len +
//                          15-digit GeneralizedTime)
//   x509_read_time_epoch : 17 bytes, the largest Time shape itself,
//                          run beside x509_read_time on identical
//                          rbuf states to prove the two share one
//                          acceptance grammar
//   x509_read_keyusage   : 8 bytes; the largest shape is 5 (2-byte
//                          header + 3 content), driven with both
//                          required masks the walker passes — 0x80
//                          digitalSignature (leaf) and 0x04
//                          keyCertSign (intermediate)
//   x509_read_spki       : 448 bytes; a 3072-bit RSA SPKI measures 422
//                          (the ECDSA SPKI is 91), so the bound covers
//                          the largest admitted key with margin
//   x509_read_bitstring  : 448 bytes, the SPKI bound; the signature
//                          BIT STRING (header + pad + 385 content)
//                          also fits it
//   x509_read_extension  : 256 bytes, CH_X509_EXT_TLV_MAX — the cap
//                          the walker itself enforces per extension
//   x509_emit_header     : any len up to 0xffff, the 0x82 ceiling
//
// The explicit asserts are the postconditions x509.c's walker relies on
// and x509parse_harness's stubs havoc within: a successful read leaves
// err clear and yields len <= rb_left, and a successful SPKI read yields
// a key pointing into the input with key_len 64 (ECDSA build) or
// 256..384 in whole 8-byte steps (RSA build). Proving them here is what
// lets x509parse_harness stub these primitives soundly, the way
// hsparse_harness's cookie asserts license handshake_harness's stub.
// Built with buf.c on the CBMC command line — the file's full dependency
// closure; a missing body would havoc the callee and void the proof.
#include "harness.h"

#include "x509_der.c"

int main(void) {
    // One 448-byte nondet buffer feeds every rbuf-shaped primitive; each
    // call re-inits its own rbuf over it with its own nondet length, so
    // no call constrains another's input.
    uint8_t tlv[448];
    fill_nondet(tlv, sizeof tlv);
    size_t n = nondet_size_t();
    __CPROVER_assume(n <= sizeof tlv);
    rbuf r;

    // x509_read_len: the length postcondition every caller's rb_bytes
    // and exact-fill arithmetic rests on.
    rb_init(&r, tlv, n);
    size_t len = 0;
    if (x509_read_len(&r, &len)) {
        __CPROVER_assert(!r.err, "read_len success leaves err clear");
        __CPROVER_assert(len <= rb_left(&r), "read_len yields len within the remaining bytes");
    }

    // x509_read_header: tag byte plus the same length contract.
    rb_init(&r, tlv, n);
    if (x509_read_header(&r, nondet_u8(), &len)) {
        __CPROVER_assert(!r.err, "read_header success leaves err clear");
        __CPROVER_assert(len <= rb_left(&r), "read_header yields len within the remaining bytes");
    }

    // x509_read_exact at the largest pinned constant's width.
    uint8_t want[67];
    fill_nondet(want, sizeof want);
    size_t want_len = nondet_size_t();
    __CPROVER_assume(want_len <= sizeof want);
    rb_init(&r, tlv, n);
    (void)x509_read_exact(&r, want, want_len);

    // x509_skip: any tag, any admitted length.
    rb_init(&r, tlv, n);
    (void)x509_skip(&r, nondet_u8());

    // x509_read_serial at its 24-byte bound.
    uint8_t serial[24];
    fill_nondet(serial, sizeof serial);
    size_t serial_len = nondet_size_t();
    __CPROVER_assume(serial_len <= sizeof serial);
    rb_init(&r, serial, serial_len);
    (void)x509_read_serial(&r);

    // x509_read_time at its 20-byte bound.
    uint8_t time_bytes[20];
    fill_nondet(time_bytes, sizeof time_bytes);
    size_t time_len = nondet_size_t();
    __CPROVER_assume(time_len <= sizeof time_bytes);
    rb_init(&r, time_bytes, time_len);
    (void)x509_read_time(&r);

    // x509_read_time_epoch at the 17-byte largest Time shape: a buffer
    // under the 15-byte smallest shape never parses, an epoch-shaped
    // date yields a number in 0..CH_EPOCH_MAX, and the
    // accept/reject verdict equals x509_read_time's on an identical
    // rbuf state — extraction leaves grammar acceptance unchanged.
    {
        uint8_t epoch_bytes[17];
        fill_nondet(epoch_bytes, sizeof epoch_bytes);
        size_t epoch_len = nondet_size_t();
        __CPROVER_assume(epoch_len <= sizeof epoch_bytes);
        rbuf shape;
        rb_init(&shape, epoch_bytes, epoch_len);
        int shape_rc = x509_read_time(&shape);
        rb_init(&r, epoch_bytes, epoch_len);
        uint32_t epoch_index = 0;
        int epoch_ok = 0;
        int rc = x509_read_time_epoch(&r, &epoch_index, &epoch_ok);
        __CPROVER_assert(rc == shape_rc, "epoch verdict equals read_time on the same bytes");
        if (epoch_len < 15) {
            __CPROVER_assert(rc == 0, "a buffer under the smallest Time shape never parses");
        }
        if (rc == 1 && epoch_ok == 1) {
            __CPROVER_assert(epoch_index <= CH_EPOCH_MAX, "epoch number stays in range");
        }
    }

    // x509_read_keyusage at its 8-byte bound, zero length included:
    // x509.c hands it an extnValue that may be empty. The nondet mask
    // choice drives both callers' demands, the leaf's digitalSignature
    // and the intermediate's keyCertSign.
    uint8_t ku[8];
    fill_nondet(ku, sizeof ku);
    size_t ku_len = nondet_size_t();
    __CPROVER_assume(ku_len <= sizeof ku);
    uint8_t ku_required = (nondet_u8() & 1) ? 0x80 : 0x04;
    (void)x509_read_keyusage(ku, ku_len, ku_required);

    // x509_read_spki: the key postcondition x509.c's copy loop rests on
    // (key readable for key_len, key_len within CH_X509_KEY_MAX).
    const uint8_t *key = NULL;
    size_t key_len = 0;
    rb_init(&r, tlv, n);
    if (x509_read_spki(&r, &key, &key_len)) {
        __CPROVER_assert(key >= tlv && key <= tlv + n, "spki key points into the input");
        __CPROVER_assert(key_len <= (size_t)(tlv + n - key), "spki key_len within the input");
#ifdef CH_PIN_ECDSA
        __CPROVER_assert(key_len == 64, "spki yields the one P-256 key size");
#else
        __CPROVER_assert(key_len >= 256 && key_len <= 384 && key_len % 8 == 0,
                         "spki yields a modulus in the verifier's admitted range");
#endif
    }

    // x509_read_bitstring at the SPKI/signature bound: on success the
    // bytes point into the input and fit what remains — the shape both
    // the signature read and the SPKI arms rest on.
    {
        rbuf r;
        size_t n = nondet_size_t();
        __CPROVER_assume(n <= sizeof tlv);
        rb_init(&r, tlv, n);
        const uint8_t *bytes = NULL;
        size_t blen = 0;
        if (x509_read_bitstring(&r, &bytes, &blen)) {
            __CPROVER_assert(!r.err, "bitstring success leaves err clear");
            __CPROVER_assert(bytes >= tlv && bytes + blen <= tlv + n,
                             "bitstring bytes stay inside the input");
        }
    }

    // x509_read_extension at the walker's own per-extension cap: on
    // success every part points into the input — the postconditions
    // x509parse_harness's stub havocs within.
    {
        uint8_t ext_tlv[CH_X509_EXT_TLV_MAX];
        fill_nondet(ext_tlv, sizeof ext_tlv);
        rbuf r;
        size_t n = nondet_size_t();
        __CPROVER_assume(n <= sizeof ext_tlv);
        rb_init(&r, ext_tlv, n);
        x509_extension ext;
        if (x509_read_extension(&r, CH_X509_EXT_TLV_MAX, &ext)) {
            __CPROVER_assert(!r.err, "extension success leaves err clear");
            __CPROVER_assert(ext.oid >= ext_tlv && ext.oid + ext.oid_len <= ext_tlv + n,
                             "extension oid stays inside the input");
            __CPROVER_assert(ext.oid_len >= 1 && ext.oid_len <= 16, "extension oid length bounded");
            __CPROVER_assert(ext.value >= ext_tlv && ext.value + ext.value_len <= ext_tlv + n,
                             "extension value stays inside the input");
            __CPROVER_assert(ext.critical == 0 || ext.critical == 1, "critical is boolean");
        }
    }

    // x509_emit_header: the 2..4 size x509.c's hdr[4] and the TBS hash
    // rest on.
    uint8_t hdr[4];
    size_t emit_len = nondet_size_t();
    __CPROVER_assume(emit_len <= 0xffff);
    size_t hdr_len = x509_emit_header(nondet_u8(), emit_len, hdr);
    __CPROVER_assert(hdr_len >= 2 && hdr_len <= 4, "emit_header returns its documented 2..4 size");
    return 0;
}
