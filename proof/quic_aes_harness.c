// Proves: the AES-128 key schedule and forward cipher of FIPS 197, and
// both aes_public_key constructors, are memory-safe and UB-free over
// unconstrained inputs at the module's real bound. The bound that is not
// a fixed-size buffer is the Destination Connection ID, which RFC 9000
// §17.2 caps at CH_QUIC_DCID_MAX bytes; the harness drives every length from
// zero to that cap, and one past it, where the header promises a refusal
// that writes nothing.
//
// The direction byte is unconstrained rather than one of the two the
// header names, so the refusal arm is proven over every other value.
//
// Aliasing: quic_packet.c will pass the sample buffer as the output of
// the §5.4.3 mask and quic_gcm.c reuses its counter block, so both block
// entries are called with in == out as well as with distinct buffers.
//
// HKDF is a contract stub (proof/quic_aes_stubs.h), which states what
// the composition gives up and where the real functions are proven.
#include "harness.h"

#include "quic_aes_stubs.h"

#include "quic_aes.c"

int main(void) {
    aes_public_key k;
    uint8_t dcid[CH_QUIC_DCID_MAX];
    uint8_t in[AES_BLOCK];
    uint8_t out[AES_BLOCK];

    // A connection ID of any admitted length, and a direction byte of
    // any value at all.
    fill_nondet(dcid, sizeof dcid);
    size_t dcid_len = nondet_size_t();
    __CPROVER_assume(dcid_len <= sizeof dcid);
    uint8_t direction = nondet_u8();
    int rc = aes_public_key_initial(&k, dcid, dcid_len, direction);
    __CPROVER_assert(rc == CH_OK || rc == CH_EINVAL, "initial: one of the two documented codes");

    // The first length past the cap. The header says the call reads no
    // connection ID there, so the pointer is NULL and any read is a
    // proof failure.
    __CPROVER_assert(aes_public_key_initial(&k, NULL, CH_QUIC_DCID_MAX + 1, CH_KEY_WRITE) ==
                         CH_EINVAL,
                     "initial: one past the cap refuses");

    // A key set the constructors did not write is still a key the block
    // entries must handle, so the schedules are havocked before the
    // calls below rather than left as the call above wrote them.
    fill_nondet(k.key.round_keys, sizeof k.key.round_keys);
    fill_nondet(k.hp.round_keys, sizeof k.hp.round_keys);
    fill_nondet(k.iv, sizeof k.iv);

    fill_nondet(in, sizeof in);
    aes_encrypt_block(&k, in, out);

    fill_nondet(in, sizeof in);
    aes_encrypt_block_hp(&k, in, out);

    // The same two calls with one buffer, the shape the headers allow.
    fill_nondet(out, sizeof out);
    aes_encrypt_block(&k, out, out);
    fill_nondet(out, sizeof out);
    aes_encrypt_block_hp(&k, out, out);

    aes_public_key_retry(&k);
    fill_nondet(in, sizeof in);
    aes_encrypt_block(&k, in, out);
    return 0;
}
