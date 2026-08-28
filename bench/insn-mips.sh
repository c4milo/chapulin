#!/usr/bin/env bash
# Measures the crypto in honest device-CPU units: dynamic INSTRUCTION
# counts for mips32r2, not guessed milliseconds. Builds a freestanding
# big-endian Linux binary per operation (own __start, exit/write syscalls,
# byte-wise mem routines — no libc), runs it under qemu-user with one
# instruction per translation block, and counts executed instructions from
# the exec log. Counts are deterministic and baseline-subtracted: an
# ITERS=0 build of the same binary removes startup, input setup, and the
# stack paint. Every input is fixed and no I/O happens inside a measured
# loop. memcpy is byte-wise here, so counts lean conservative. Writes
# bench/results-insn.csv. Skips without docker.
set -euo pipefail

if [ "${1:-}" != "--inside" ]; then
    cd "$(dirname "$0")/.."
    # shellcheck source=bench/toolchain.env
    . bench/toolchain.env
    command -v docker >/dev/null 2>&1 || {
        echo "SKIP insn count: docker not available" >&2
        exit 0
    }
    TMPOUT=$(mktemp)
    trap 'rm -f "$TMPOUT"' EXIT
    docker run --rm -e "CLANG_MAJOR=$CLANG_MAJOR" \
        -v "$PWD":/src:ro -w /src "alpine@$ALPINE_DIGEST" \
        sh -c 'apk add -q bash clang lld qemu-mips >/dev/null 2>&1 \
               && exec bash /src/bench/insn-mips.sh --inside' \
        > "$TMPOUT"
    # Redirecting straight at the committed file truncated it the moment the
    # run started, so a failing measurement destroyed the last good numbers.
    mv "$TMPOUT" bench/results-insn.csv
    echo "wrote bench/results-insn.csv" >&2
    exit 0
fi

# ---- inside the container from here on; CSV goes to stdout ----
# The digest pins the base image, not apk, which resolves against the live
# repository. A compiler whose major moved would publish different numbers
# for unchanged sources, so stop rather than measure (bench/toolchain.env).
cver=$(clang --version | head -1)
case "$cver" in
*"clang version ${CLANG_MAJOR:?}."*) ;;
*) echo "FAIL: expected clang $CLANG_MAJOR, container has: $cver" >&2; exit 1 ;;
esac
echo "$cver" >&2

W=/tmp/insn
mkdir -p "$W/shim"

# Declaration-only libc surface; the runtime below supplies the bodies.
cat > "$W/shim/string.h" <<'EOF'
#pragma once
#include <stddef.h>
void *memcpy(void *, const void *, size_t);
void *memmove(void *, const void *, size_t);
void *memset(void *, int, size_t);
int memcmp(const void *, const void *, size_t);
size_t strlen(const char *);
EOF

# The runtime a libc would provide: entry, exit/write syscalls (o32 ABI),
# byte-wise mem/str routines, and the two chapulin platform hooks. Stack
# painting mirrors how firmware measures high-water; its cost lands in
# baseline and full runs alike, so the subtraction drops it.
cat > "$W/runtime.c" <<'EOF'
#include <stddef.h>
#include <stdint.h>

static void sys_exit(long code) {
    register long v0 __asm__("$2") = 4001;
    register long a0 __asm__("$4") = code;
    __asm__ volatile("syscall" : "+r"(v0) : "r"(a0) : "memory");
}
static void sys_write(long fd, const void *buf, unsigned long n) {
    register long v0 __asm__("$2") = 4004;
    register long a0 __asm__("$4") = fd;
    register long a1 __asm__("$5") = (long)buf;
    register long a2 __asm__("$6") = (long)n;
    __asm__ volatile("syscall" : "+r"(v0) : "r"(a0), "r"(a1), "r"(a2) : "$7", "memory");
}

void *memcpy(void *d, const void *s, size_t n) {
    unsigned char *dp = d;
    const unsigned char *sp = s;
    while (n--) { *dp++ = *sp++; }
    return d;
}
void *memmove(void *d, const void *s, size_t n) {
    unsigned char *dp = d;
    const unsigned char *sp = s;
    if (dp < sp) {
        while (n--) { *dp++ = *sp++; }
    } else {
        while (n--) { dp[n] = sp[n]; }
    }
    return d;
}
void *memset(void *d, int c, size_t n) {
    unsigned char *dp = d;
    while (n--) { *dp++ = (unsigned char)c; }
    return d;
}
int memcmp(const void *a, const void *b, size_t n) {
    const unsigned char *ap = a;
    const unsigned char *bp = b;
    for (; n--; ap++, bp++) {
        if (*ap != *bp) { return *ap - *bp; }
    }
    return 0;
}
size_t strlen(const char *s) {
    const char *p = s;
    while (*p) { p++; }
    return (size_t)(p - s);
}

// chapulin's platform hooks. The bench needs determinism, not entropy;
// nothing in the measured paths calls ch_rand_bytes anyway.
void ch_rand_bytes(uint8_t *p, size_t n) {
    uint32_t x = 0x2545f491u;
    while (n--) {
        x = x * 1103515245u + 12345u;
        *p++ = (uint8_t)(x >> 16);
    }
}
_Noreturn void ch_assert_fail(const char *cond, const char *file, int line) {
    (void)cond;
    (void)file;
    (void)line;
    sys_write(2, "ch_assert\n", 10);
    sys_exit(134);
    __builtin_unreachable();
}

static void write_num(unsigned long v) {
    char buf[12];
    int i = 11;
    buf[11] = '\n';
    if (v == 0) { buf[--i] = '0'; }
    while (v) { buf[--i] = (char)('0' + (v % 10)); v /= 10; }
    sys_write(1, buf + i, (unsigned long)(12 - i));
}

// Stack painting, the way firmware measures high-water: paint below $sp at
// entry, run, then scan up for the deepest word the run dirtied.
enum { PAINT_WORDS = (16384 / 4) - 16 };
int app_main(void);
void __start(void) {
    long sp;
    __asm__("move %0, $sp" : "=r"(sp));
    volatile unsigned *lo = (volatile unsigned *)((sp - 16384) & ~3L);
    for (int i = 0; i < PAINT_WORDS; i++) { lo[i] = 0xA5A5A5A5U; }
    int rc = app_main();
    unsigned long high_water = 0;
    for (int i = 0; i < PAINT_WORDS; i++) {
        if (lo[i] != 0xA5A5A5A5U) {
            high_water = (unsigned long)(sp - (long)&lo[i]);
            break;
        }
    }
    write_num(high_water);
    sys_exit(rc);
    __builtin_unreachable();
}
EOF

hexc() { printf '%s' "$1" | sed 's/../0x&,/g'; }

# The same vectors test/unit_test.c and test/rsa_test.c check, so a wrong
# freestanding build fails loudly instead of producing counts for garbage.
cat > "$W/vectors.h" <<EOF
// RFC 7748 §5.2 x25519 vector 1; RFC 6979 A.2.5 P-256 key with its
// "sample" signature (SHA-256 hash of "sample", DER signature).
static const uint8_t X25519_SCALAR[32] = {
    $(hexc a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4)};
static const uint8_t X25519_POINT[32] = {
    $(hexc e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c)};
static const uint8_t X25519_WANT[32] = {
    $(hexc c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552)};
// FIPS 203 known-answer vector 0, the same seeds test/mlkem_test.c checks,
// so a wrong freestanding build fails loudly instead of counting garbage.
static const uint8_t MLKEM_D[32] = {
    $(hexc aeed86158e34d8e1f0a0b5eea10f6c10e8d5827ad42f444abb29c79510103184)};
static const uint8_t MLKEM_Z[32] = {
    $(hexc e3ee0a22d4686b6c8cb995e25893cdf12a974dc71a3672a706118f53a813dec7)};
static const uint8_t MLKEM_M[32] = {
    $(hexc a877c13d2d9b9ce9cb3a5708c8912103f0b052869c2aaccc34ea8268ed16c0b7)};
static const uint8_t MLKEM_K_WANT[32] = {
    $(hexc b100ca39eaf924878e62dd8fe70b6ba78d95e2d53217ba55c07d904c25d73850)};
static const uint8_t P256_PUB[64] = {
    $(hexc 60fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6)
    $(hexc 7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299)};
static const uint8_t P256_HASH[32] = {
    $(hexc af2bdbe1aa9b6ec1e2ade1d694f41fc71a831d0268e9891562113d8a62add1bf)};
static const uint8_t P256_SIG[72] = {
    $(hexc 3046022100efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716)
    $(hexc 022100f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8)};
// test/rsa_test.c key A with its "vector one" signature: RSA-3072, PSS,
// saltlen 32, MGF1-SHA256; the hash is SHA-256 of the vector-one message.
static const uint8_t RSA_N[384] = {
    $(hexc e9d26f221079cc18141338902c501646e0ebfa2d892c7d14ceebef13197041b0e370510fa9f7db7d)
    $(hexc b28cb25c9d8ba8c26488e39274380d10ec07cf389fd2843657b93cd72fd4b7ac61d5943679263e8c)
    $(hexc 67b918704ff60177f8c3c66cd96397857a20b83f837ab0f9037f23560ec93a8d2292597209148a1d)
    $(hexc 355680f72323e282b37c199032f593103804c5ca28f515b4bcc3af8021f789181d0c9831135469a0)
    $(hexc ceb0d19b1c63cd3cc3c0bc2cc2a4285961f141d869436b53db609bc84968c509d9f01da596f80b21)
    $(hexc 69ac41f196f28431bb13a24ad54d29ef991ed6eaf6f7de4de4dad9fefe88fdf9ce2d0058627de3f9)
    $(hexc 005c70a00ca7a151d354ff4829307ac918deea6699a45532e031cceb47e0f2c834e242cb0e997417)
    $(hexc 499345ef23ee074dd4fc46da69b3c05d9c644b429f0d7233deb151264d42546a9b67d22c78a5c541)
    $(hexc 3b725a403991191261513926e9072d762e6b584369ab9a85cc1ed0fa2a295756a3ac761066876c7e)
    $(hexc 40d5e44042a731d25343c3c201ec5225c97b1367397d7fc3)};
static const uint8_t RSA_HASH[32] = {
    $(hexc 6b6512ead21e357c79e716ae2a5eb387cbb3786a1d3eb784b8cfcf443647f551)};
static const uint8_t RSA_SIG[384] = {
    $(hexc 3660ad5981502185fa10bfaa20287c78f3c6ab0fabd7c3b40659c36a5eb5aa3e6874d035fee34e37)
    $(hexc ccd5dfe1ffc423cffa16b79b0272a507d351d1893d9cb7dc587610a797869139ffdb5f4127d9a613)
    $(hexc c6957dc76559a337a0c8215d312944109ccce24505681782237fcb01528c7ba471b5690d6c9ffd71)
    $(hexc 6f8a71ef31434940baaf75b0f7958a4a4b93c22b9d0f816016bec8495bc0167ce3393bc976b7515f)
    $(hexc cc916535d757ad1c45f6be21f02a6f118091acf753f389ad76cb5ab5d8c3a78e12436caf4ee4d53c)
    $(hexc 0e0c696928f6c8ecef0c011b8ae4b95c50220d3365488e83fe37014986a56797cc897009639b2c0f)
    $(hexc 663e1baa3d3639c0c5509318eba257a41044d58270570da793ee84fceea0c3cf490484e5aa5657ff)
    $(hexc b6b7efb8ed3fd35ea9068de4c3100c906e12d01e246f22a1e532741ca03ca675d2bac2a9b72766db)
    $(hexc 9734b6fa518a66368f4a0afb669a54438d601303c531ddfd820b4bfd553a93c1936c1412e553882a)
    $(hexc 10ab21f60407227572fe8ec82fbe1e9d9670bf5bc19acf10)};
EOF

# One operation per build, selected by -DOP_*, repeated ITERS times over
# fixed inputs. The ITERS=0 build of the same source is the baseline.
cat > "$W/driver.c" <<'EOF'
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

#include "vectors.h"

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
    for (size_t i = 0; i < sizeof pad; i++) { pad[i] = ' '; }
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
    for (size_t i = 0; i < 32; i++) { wire[i] = vdata[i]; }
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
    for (size_t i = 0; i < 32; i++) { wire[i] = vdata[i]; }
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
    for (size_t i = 0; i < sizeof msg; i++) { msg[i] = (uint8_t)(i * 251u + 17u); }
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
    if (ITERS > 0) { bad = ok != ITERS || !ct_memeq(out, X25519_WANT, 32); }
#elif defined(OP_P256)
    int ok = 0;
    for (int k = 0; k < ITERS; k++) {
        ok += p256_ecdsa_verify(P256_PUB, P256_HASH, P256_SIG, sizeof P256_SIG);
    }
    if (ITERS > 0) { bad = ok != ITERS; }
    acc += (uint32_t)ok;
#elif defined(OP_RSA)
    int ok = 0;
    for (int k = 0; k < ITERS; k++) {
        ok += rsa_pss_verify(RSA_N, sizeof RSA_N, RSA_HASH, RSA_SIG, sizeof RSA_SIG);
    }
    if (ITERS > 0) { bad = ok != ITERS; }
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
    if (mlkem_encaps_derand(kem_ct, ss, ek, MLKEM_M) != 0) { return 3; }
    for (int k = 0; k < ITERS; k++) {
        mlkem_decaps(ss, kem_ct, dk);
        acc += ss[0];
    }
    if (ITERS > 0) { bad = !ct_memeq(ss, MLKEM_K_WANT, MLKEM_SS_LEN); }
#elif defined(OP_HANDSHAKE_PQ)
    for (int k = 0; k < ITERS; k++) {
        uint32_t r = hs_once_pq();
        if (r == 0xffffffffu) { bad = 1; }
        acc += r;
    }
#elif defined(OP_HANDSHAKE)
    for (int k = 0; k < ITERS; k++) {
        uint32_t r = hs_once();
        if (r == 0xffffffffu) { bad = 1; }
        acc += r;
    }
#endif
    sink = acc;
    return bad ? 3 : 0;
}
EOF

# Alpine clang defaults the stack protector ON; there is no libc to supply
# __stack_chk_fail here, and canaries would inflate the counts anyway. -G0
# keeps data out of the $gp-relative small-data sections: nothing sets up
# $gp without a crt0, and gp-relative loads fault at address zero.
CC="clang -target mips-linux-musl -march=mips32r2 -mno-abicalls -fno-pic -G0 \
    -Os -fno-stack-protector -ffreestanding -nostdlibinc -nostdlib \
    -fuse-ld=lld -static -I/src -I$W/shim -I$W"
SRCS="/src/ct.c /src/sha256.c /src/hkdf.c /src/chacha20.c /src/poly1305.c \
      /src/aead.c /src/x25519.c /src/p256.c /src/rsa.c /src/rsa_mont.c \
      /src/buf.c /src/keysched.c /src/record.c \
      /src/sha3.c /src/mlkem.c /src/mlkem_poly.c"

build() { # $1 = OP macro  $2 = ITERS  -> binary path on stdout
    # CC holds the compiler and its flags, SRCS the sixteen source paths.
    # The shell has to split both into separate arguments; quoting either
    # would hand clang one argument containing spaces. Neither value holds a
    # glob character, so the other half of SC2086 does not apply.
    # shellcheck disable=SC2086
    $CC "-DOP_$1" "-DITERS=$2" "$W/driver.c" "$W/runtime.c" $SRCS -o "$W/bin_$1_$2"
    echo "$W/bin_$1_$2"
}

run_plain() { # $1 = binary: guest's stack high-water on stdout, dies on bad exit
    HW=$(qemu-mips "$1") || { echo "FAIL: guest exited $? running $1" >&2; exit 1; }
    echo "$HW"
}

count() { # $1 = binary: executed-instruction count on stdout
    run_plain "$1" >/dev/null
    qemu-mips -one-insn-per-tb -d exec,nochain -D /dev/stdout "$1" | wc -l || exit 1
}

# Determinism spot check: identical counts or the method is broken.
BIN=$(build SHA256_1K 4)
C1=$(count "$BIN")
C2=$(count "$BIN")
[ "$C1" -eq "$C2" ] || { echo "FAIL: counts not deterministic ($C1 vs $C2)" >&2; exit 1; }
echo "determinism check: two runs, both $C1 insns" >&2

echo "op,insns,stack_high_water_bytes"
row() { # $1 = CSV name  $2 = OP macro  $3 = ITERS  -> per-op insns on stdout fd 3
    BASE=$(count "$(build "$2" 0)")
    FULL_BIN=$(build "$2" "$3")
    HW=$(run_plain "$FULL_BIN")
    FULL=$(count "$FULL_BIN")
    INSNS=$(( (FULL - BASE) / $3 ))
    echo "$1,$INSNS,$HW"
    echo "  $1: $INSNS insns, stack $HW B" >&2
    eval "N_$2=$INSNS"
}

row sha256_1kib SHA256_1K 16
row hkdf_expand_label_32b HKDF 16
row aead_seal_1kib AEAD_1K 16
row x25519_scalarmult X25519 1
row p256_ecdsa_verify P256 1
row rsa_pss_verify_3072 RSA 1
row mlkem_keygen MLKEM_KEYGEN 4
row mlkem_decaps MLKEM_DECAPS 4
row handshake_crypto HANDSHAKE 1
row handshake_crypto_pq HANDSHAKE_PQ 1

awk -v s="$N_SHA256_1K" -v h="$N_HKDF" -v a="$N_AEAD_1K" \
    -v x="$N_X25519" -v p="$N_P256" -v r="$N_RSA" -v hs="$N_HANDSHAKE" 'BEGIN {
    printf "# at 500 MHz and 1.0 IPC: sha256_1kib %.3f ms, hkdf_expand_label_32b %.3f ms, ", s / 5e5, h / 5e5
    printf "aead_seal_1kib %.3f ms, x25519_scalarmult %.3f ms, ", a / 5e5, x / 5e5
    printf "p256_ecdsa_verify %.3f ms, rsa_pss_verify_3072 %.3f ms, handshake_crypto %.3f ms\n", p / 5e5, r / 5e5, hs / 5e5
}'
awk -v x="$N_X25519" -v hs="$N_HANDSHAKE" 'BEGIN {
    printf "x25519 share of handshake_crypto: 2 x %d = %d of %d insns (%.1f%%)\n",
        x, 2 * x, hs, 200.0 * x / hs
}' >&2
