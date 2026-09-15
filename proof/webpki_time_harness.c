// Proves: webpki_read_time is memory-safe and UB-free on any bytes
// from any reader state — any length up to 40 bytes, any position,
// either err value — where 40 bytes hold either Time shape with bytes
// after it, and honours its contract: a success leaves err clear,
// consumes exactly one Time TLV (15 or 17 bytes), and yields a packed
// value inside [19500101000000, 99991231235959], the range the chain
// walk compares the caller's clock against. webpki_pack_seconds is
// safe over every uint64 — the clamp at SECONDS_MAX is under proof,
// not assumed — and yields a value inside the same range.
//
// What this does not prove is that the packed clock keeps the order
// of clocks, pack(a) <= pack(b) for a <= b, which is what lets
// validity compare packed numbers. Asserted here over two nondet
// clocks, that property is the equivalence of two division chains,
// and kissat returned no verdict on it in 30 minutes where the rest of
// this formula closes in three seconds. The evidence for it is
// Spec.WebpkiTime.packSeconds_mono, proven of the model for every
// count of seconds, and the differential, which compares the C with
// that model on random clocks and every clamp edge.
//
// CONCRETE: real bodies, the real rbuf (buf.c) and the real length
// reader (x509_der.c) on the command line, the file's full dependency
// closure; a missing body would havoc the callee and void the proof.
#include "harness.h"

#include "webpki_time.c"

uint64_t nondet_u64(void);

#define PACKED_MIN UINT64_C(19500101000000)
#define PACKED_EPOCH UINT64_C(19700101000000)
#define PACKED_MAX UINT64_C(99991231235959)

int main(void) {
    uint8_t tlv[40];
    fill_nondet(tlv, sizeof tlv);
    size_t n = nondet_size_t();
    __CPROVER_assume(n <= sizeof tlv);
    rbuf r;
    rb_init(&r, tlv, n);
    r.off = nondet_size_t();
    __CPROVER_assume(r.off <= n);
    r.err = nondet_u8() & 1;
    size_t before = r.off;
    uint64_t packed = 0;
    if (webpki_read_time(&r, &packed)) {
        __CPROVER_assert(!r.err, "read_time success leaves err clear");
        size_t consumed = r.off - before;
        __CPROVER_assert(consumed == 15 || consumed == 17,
                         "read_time consumes exactly one Time TLV");
        __CPROVER_assert(packed >= PACKED_MIN && packed <= PACKED_MAX,
                         "read_time yields a packed value inside the range");
    }

    // The caller's clock: any value, both halves of the clamp.
    uint64_t now_seconds = nondet_u64();
    uint64_t packed_now = webpki_pack_seconds(now_seconds);
    __CPROVER_assert(packed_now >= PACKED_EPOCH && packed_now <= PACKED_MAX,
                     "pack_seconds yields a packed value inside the range");
    return 0;
}
