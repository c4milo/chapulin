// One operation per build, selected by -DOP_*, repeated ITERS times
// over fixed inputs; the ITERS=0 build of the same source is the
// baseline. Shared by bench/insn-mips.sh, bench/insn-m3.sh and
// bench/insn-rv32.sh; the runtime under it is per-architecture and
// lives in each script.
#include <stddef.h>
#include <stdint.h>

#include "aead.h"
#include "ct.h"
#include "hkdf.h"
#include "keysched.h"
#include "mlkem.h"
#include "p256.h"
#include "record.h"
#include "rsa.h"
#include "sha256.h"
#include "x25519.h"

#include "insn_vectors.h"

// Fixed message bytes; only lengths shape the work below. The hybrid
// ClientHello is the longest flight, so its length sizes the buffer and
// comes from MLKEM_EK_LEN rather than a number written here.
#define CH_CLASSIC_LEN 218
#define SH_CLASSIC_LEN 122
#define CH_HYBRID_LEN (CH_CLASSIC_LEN + MLKEM_EK_LEN)
#define SH_HYBRID_LEN (SH_CLASSIC_LEN + MLKEM_CT_LEN)
static uint8_t msg[CH_HYBRID_LEN];
static volatile uint32_t sink;

#ifdef OP_HANDSHAKE
// The crypto of one default-build (PIN=rsa, raw-pin trust) handshake in
// handshake.c run() order: x25519 keygen and shared secret, the full key
// schedule with both Finished MACs and all four traffic-key derivations,
// one RSA-3072-PSS CertificateVerify check, and 2244 bytes of transcript.
// Message parsing and record protection stay out; the aead row covers the
// latter. A PIN=ecdsa handshake swaps the rsa row's cost for the p256
// row's. Returns a fold of the outputs, or all-ones on a failed check.
static uint32_t hs_once(void) {
    static const uint8_t nopsk[SHA256_LEN] = {0};
    uint8_t early[32], binder[32], hs_sec[32], c_hs[32], s_hs[32];
    uint8_t master[32], c_ap[32], s_ap[32], res[32];
    uint8_t pub[32], ecdhe[32], hash[32], vdata[32], wire[32];
    rec_dir rd, wr;
    sha256 tr, snap;

    x25519_base(pub, X25519_SCALAR);
    ks_early(nopsk, sizeof nopsk, 0, early, binder);
    sha256_init(&tr);
    sha256_update(&tr, msg, CH_CLASSIC_LEN); // ClientHello
    sha256_update(&tr, msg, SH_CLASSIC_LEN); // ServerHello
    if (!x25519(ecdhe, X25519_SCALAR, X25519_POINT)) {
        return 0xffffffffu;
    }
    snap = tr;
    sha256_final(&snap, hash); // CH..SH
    ks_handshake(early, ecdhe, sizeof ecdhe, hash, hs_sec, c_hs, s_hs);
    rec_dir_init(&rd, s_hs);
    rec_dir_init(&wr, c_hs);
    sha256_update(&tr, msg, 40);   // EncryptedExtensions
    sha256_update(&tr, msg, 1400); // Certificate: raw-pin mode only hashes it
    snap = tr;
    sha256_final(&snap, hash); // CH..Certificate

    // CertificateVerify signed content: 64 spaces, context string, NUL,
    // transcript hash. The hardcoded signature then verifies against its
    // own vector hash; the verify work is hash-value independent in shape.
    static const char ctx[] = "TLS 1.3, server CertificateVerify";
    uint8_t pad[64];
    for (size_t i = 0; i < sizeof pad; i++) {
        pad[i] = ' ';
    }
    uint8_t nul = 0;
    uint8_t signed_hash[32];
    sha256 sc;
    sha256_init(&sc);
    sha256_update(&sc, pad, sizeof pad);
    sha256_update(&sc, (const uint8_t *)ctx, sizeof ctx - 1);
    sha256_update(&sc, &nul, 1);
    sha256_update(&sc, hash, SHA256_LEN);
    sha256_final(&sc, signed_hash);
    sink = signed_hash[0];
    if (rsa_pss_verify(RSA_N, sizeof RSA_N, RSA_HASH, RSA_SIG, sizeof RSA_SIG) != 1) {
        return 0xffffffffu;
    }
    sha256_update(&tr, msg, 392); // CertificateVerify (384-byte signature)
    snap = tr;
    sha256_final(&snap, hash);         // CH..CertificateVerify
    ks_verify_data(s_hs, hash, vdata); // server Finished MAC
    for (size_t i = 0; i < 32; i++) {
        wire[i] = vdata[i];
    }
    if (!ct_memeq(vdata, wire, SHA256_LEN)) {
        return 0xffffffffu;
    }
    sha256_update(&tr, msg, 36); // server Finished
    snap = tr;
    sha256_final(&snap, hash); // CH..server Finished
    ks_master(hs_sec, hash, master, c_ap, s_ap);
    ks_verify_data(c_hs, hash, vdata); // client Finished MAC
    sha256_update(&tr, msg, 36);       // client Finished
    snap = tr;
    sha256_final(&snap, hash); // CH..client Finished
    ks_res_master(master, hash, res);
    rec_dir_init(&rd, s_ap);
    rec_dir_init(&wr, c_ap);
    return (uint32_t)res[0] + rd.key[0] + wr.iv[0] + binder[0] + pub[0];
}
#endif

#if defined(OP_HANDSHAKE_PQ)
// The crypto of one KEX=pq handshake: hs_once's flight with the hybrid
// share in place of the x25519 one. Both scalar multiplications sit
// inside the measured loop as in hs_once, so a change to x25519's
// count moves this row by about twice x25519's delta, the step
// handshake_crypto takes. An experiment once read this row unchanged
// while x25519 moved. A clean rebuild of both drivers under one ct.h
// edit does not reproduce that: +5,135,890 on x25519_scalarmult moved
// both handshake rows by +10,271,808, twice that delta and 28 more
// that the experiment did not trace, from one 44,927-instruction
// ITERS=0 baseline, and bench/insn-mips.sh has no build cache, so the
// reading came from a binary built without the edit
// (https://github.com/c4milo/chapulin/issues/129).
static uint32_t hs_once_pq(void) {
    static const uint8_t nopsk[SHA256_LEN] = {0};
    uint8_t early[32], binder[32], hs_sec[32], c_hs[32], s_hs[32];
    uint8_t master[32], c_ap[32], s_ap[32], res[32];
    uint8_t pub[32], hash[32], vdata[32], wire[32];
    uint8_t ikm[MLKEM_SS_LEN + X25519_LEN];
    static uint8_t server_ct[MLKEM_CT_LEN];
    rec_dir rd, wr;
    sha256 tr, snap;

    // ClientHello: the x25519 share, and the ML-KEM key pair re-expanded
    // from its seed. Only dk is needed here; the ek bytes live inside it.
    x25519_base(pub, X25519_SCALAR);
    {
        uint8_t dk[MLKEM_DK_LEN];
        mlkem_keygen_dk(dk, MLKEM_D, MLKEM_Z);
        sink = dk[0];
    }
    ks_early(nopsk, sizeof nopsk, 0, early, binder);
    sha256_init(&tr);
    sha256_update(&tr, msg, CH_HYBRID_LEN);
    sha256_update(&tr, msg, SH_HYBRID_LEN);

    // hybrid_secret: second expansion, decapsulate, then x25519. ML-KEM
    // occupies ikm[0..31] and x25519 ikm[32..63], RFC 10024's order.
    {
        uint8_t dk[MLKEM_DK_LEN];
        mlkem_keygen_dk(dk, MLKEM_D, MLKEM_Z);
        mlkem_decaps(ikm, server_ct, dk);
    }
    if (!x25519(ikm + MLKEM_SS_LEN, X25519_SCALAR, X25519_POINT)) {
        return 0xffffffffu;
    }
    snap = tr;
    sha256_final(&snap, hash);
    ks_handshake(early, ikm, sizeof ikm, hash, hs_sec, c_hs, s_hs);
    rec_dir_init(&rd, s_hs);
    rec_dir_init(&wr, c_hs);

    // The rest of the flight is the classic one: pq changes share sizes
    // and secret derivation, not the messages after ServerHello.
    sha256_update(&tr, msg, 40);
    sha256_update(&tr, msg, 1400);
    snap = tr;
    sha256_final(&snap, hash);
    if (rsa_pss_verify(RSA_N, sizeof RSA_N, RSA_HASH, RSA_SIG, sizeof RSA_SIG) != 1) {
        return 0xffffffffu;
    }
    sha256_update(&tr, msg, 392);
    snap = tr;
    sha256_final(&snap, hash);
    ks_verify_data(s_hs, hash, vdata);
    for (size_t i = 0; i < 32; i++) {
        wire[i] = vdata[i];
    }
    if (!ct_memeq(vdata, wire, SHA256_LEN)) {
        return 0xffffffffu;
    }
    sha256_update(&tr, msg, 36);
    snap = tr;
    sha256_final(&snap, hash);
    ks_master(hs_sec, hash, master, c_ap, s_ap);
    ks_verify_data(c_hs, hash, vdata);
    sha256_update(&tr, msg, 36);
    snap = tr;
    sha256_final(&snap, hash);
    ks_res_master(master, hash, res);
    rec_dir_init(&rd, s_ap);
    rec_dir_init(&wr, c_ap);
    return (uint32_t)res[0] + rd.key[0] + wr.iv[0] + binder[0] + pub[0];
}
#endif

int app_main(void) {
    for (size_t i = 0; i < sizeof msg; i++) {
        msg[i] = (uint8_t)(i * 251u + 17u);
    }
    uint32_t acc = 0;
    int bad = 0;

#if defined(OP_SHA256_1K)
    uint8_t out[SHA256_LEN];
    for (int k = 0; k < ITERS; k++) {
        sha256_of(msg, 1024, out);
        acc += out[0];
    }
#elif defined(OP_HKDF)
    uint8_t out[SHA256_LEN];
    for (int k = 0; k < ITERS; k++) {
        hkdf_expand_label(msg, "c hs traffic", msg + 32, 32, out, 32);
        acc += out[0];
    }
#elif defined(OP_AEAD_1K)
    static uint8_t ct_out[1024];
    uint8_t tag[AEAD_TAG];
    for (int k = 0; k < ITERS; k++) {
        aead_seal(msg, msg + 32, msg + 44, 5, msg, 1024, ct_out, tag);
        acc += tag[0];
    }
#elif defined(OP_X25519)
    uint8_t out[X25519_LEN];
    int ok = 0;
    for (int k = 0; k < ITERS; k++) {
        ok += x25519(out, X25519_SCALAR, X25519_POINT);
        acc += out[0];
    }
    if (ITERS > 0) {
        bad = ok != ITERS || !ct_memeq(out, X25519_WANT, 32);
    }
#elif defined(OP_P256)
    int ok = 0;
    for (int k = 0; k < ITERS; k++) {
        ok += p256_ecdsa_verify(P256_PUB, P256_HASH, P256_SIG, sizeof P256_SIG);
    }
    if (ITERS > 0) {
        bad = ok != ITERS;
    }
    acc += (uint32_t)ok;
#elif defined(OP_RSA)
    int ok = 0;
    for (int k = 0; k < ITERS; k++) {
        ok += rsa_pss_verify(RSA_N, sizeof RSA_N, RSA_HASH, RSA_SIG, sizeof RSA_SIG);
    }
    if (ITERS > 0) {
        bad = ok != ITERS;
    }
    acc += (uint32_t)ok;
#elif defined(OP_MLKEM_KEYGEN)
    static uint8_t ek[MLKEM_EK_LEN], dk[MLKEM_DK_LEN];
    for (int k = 0; k < ITERS; k++) {
        mlkem_keygen_derand(ek, dk, MLKEM_D, MLKEM_Z);
        acc += dk[0];
    }
#elif defined(OP_MLKEM_DECAPS)
    // The key pair and ciphertext are built outside the loop, so the
    // ITERS=0 baseline carries them and the subtraction leaves decaps alone.
    static uint8_t ek[MLKEM_EK_LEN], dk[MLKEM_DK_LEN];
    static uint8_t kem_ct[MLKEM_CT_LEN], ss[MLKEM_SS_LEN];
    mlkem_keygen_derand(ek, dk, MLKEM_D, MLKEM_Z);
    if (mlkem_encaps_derand(kem_ct, ss, ek, MLKEM_M) != 0) {
        return 3;
    }
    for (int k = 0; k < ITERS; k++) {
        mlkem_decaps(ss, kem_ct, dk);
        acc += ss[0];
    }
    if (ITERS > 0) {
        bad = !ct_memeq(ss, MLKEM_K_WANT, MLKEM_SS_LEN);
    }
#elif defined(OP_HANDSHAKE_PQ)
    for (int k = 0; k < ITERS; k++) {
        uint32_t r = hs_once_pq();
        if (r == 0xffffffffu) {
            bad = 1;
        }
        acc += r;
    }
#elif defined(OP_HANDSHAKE)
    for (int k = 0; k < ITERS; k++) {
        uint32_t r = hs_once();
        if (r == 0xffffffffu) {
            bad = 1;
        }
        acc += r;
    }
#endif
    sink = acc;
    return bad ? 3 : 0;
}
