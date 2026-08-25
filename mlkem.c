// ML-KEM-768 (FIPS 203): K-PKE (Algorithms 13-15) and the
// Fujisaki-Okamoto KEM wrapper (Algorithms 16-18) around it.
//
// G = SHA3-512, H = SHA3-256, J = SHAKE256(32), PRF and XOF are SHAKE.
// Every secret stack buffer is wiped before return. The one implicit
// reject select is branchless masked arithmetic over 32 bytes.
#include "mlkem.h"

#include <string.h>

#include "ct.h"
#include "mlkem_poly.h"
#include "sha3.h"

#define MLK_DKPKE_BYTES 1152 // K-PKE secret key: ByteEncode12 of s-hat
#define MLK_U_BYTES 960      // compressed u vector inside a ciphertext

// out = sum_j a[j] o b[j], the NTT-domain dot product. The result keeps
// the Montgomery R^-1 factor that basemul introduces.
static void mlk_polyvec_dot(mlk_poly *out, const mlk_polyvec *a, const mlk_polyvec *b) {
    mlk_poly prod;
    for (unsigned j = 0; j < 3; j++) {
        mlk_poly_basemul(&prod, &a->vec[j], &b->vec[j]);
        if (j == 0) {
            *out = prod;
        } else {
            mlk_poly_add(out, out, &prod);
        }
    }
    ct_wipe(&prod, sizeof prod);
}

// out = row i of A o s, expanding A one entry at a time from the public
// seed. FIPS 203 samples A[i][j] from rho || j || i, so keygen
// (transposed = 0) reads row i of A and encrypt (transposed = 1) reads
// row i of A^T; the index bytes are public, so the choice is not a
// secret-dependent branch. prod holds products of a public matrix entry
// with the secret vector, so it is wiped; a is public.
static void mlk_matvec_row(mlk_poly *out, const uint8_t seed[32], unsigned i, int transposed,
                           const mlk_polyvec *s) {
    mlk_poly a;
    mlk_poly prod;
    for (unsigned j = 0; j < 3; j++) {
        uint8_t x0 = transposed ? (uint8_t)i : (uint8_t)j;
        uint8_t x1 = transposed ? (uint8_t)j : (uint8_t)i;
        mlk_sample_ntt(&a, seed, x0, x1);
        mlk_poly_basemul(&prod, &a, &s->vec[j]);
        if (j == 0) {
            *out = prod;
        } else {
            mlk_poly_add(out, out, &prod);
        }
    }
    ct_wipe(&prod, sizeof prod);
}

// K-PKE.KeyGen (Algorithm 13). Writes ek (t-hat || rho) and the K-PKE
// secret key dkpke (s-hat). sigma and the secret vectors are wiped.
static void mlk_pke_keygen(uint8_t ek[MLKEM_EK_LEN], uint8_t dkpke[MLK_DKPKE_BYTES],
                           const uint8_t d[32]) {
    uint8_t gin[33];
    uint8_t g[64];
    mlk_polyvec s;
    mlk_polyvec e;
    mlk_polyvec t;
    memcpy(gin, d, 32);
    gin[32] = MLKEM_K;
    sha3_512(gin, 33, g); // (rho, sigma) = G(d || k)
    const uint8_t *rho = g;
    const uint8_t *sigma = g + 32;
    for (unsigned i = 0; i < 3; i++) {
        mlk_sample_cbd(&s.vec[i], sigma, (uint8_t)i);
        mlk_sample_cbd(&e.vec[i], sigma, (uint8_t)(3 + i));
        mlk_poly_ntt(&s.vec[i]);
        mlk_poly_ntt(&e.vec[i]);
    }
    for (unsigned i = 0; i < 3; i++) {
        mlk_matvec_row(&t.vec[i], rho, i, 0, &s); // t = A o s (with R^-1)
        mlk_poly_tomont(&t.vec[i]);               // undo the R^-1
        mlk_poly_add(&t.vec[i], &t.vec[i], &e.vec[i]);
        mlk_poly_reduce(&t.vec[i]);
        mlk_poly_tobytes(ek + (size_t)384 * i, &t.vec[i]);
        mlk_poly_tobytes(dkpke + (size_t)384 * i, &s.vec[i]);
    }
    memcpy(ek + 1152, rho, 32);
    ct_wipe(gin, sizeof gin);
    ct_wipe(g, sizeof g);
    ct_wipe(&s, sizeof s);
    ct_wipe(&e, sizeof e);
}

// K-PKE.Encrypt (Algorithm 14). coins seeds the noise; m is the 32-byte
// message. Writes the 1088-byte ciphertext.
static void mlk_pke_encrypt(uint8_t ct[MLKEM_CT_LEN], const uint8_t ek[MLKEM_EK_LEN],
                            const uint8_t m[32], const uint8_t coins[32]) {
    const uint8_t *rho = ek + 1152;
    mlk_polyvec t;
    mlk_polyvec r;
    mlk_polyvec u;
    mlk_poly v;
    mlk_poly noise;
    for (unsigned i = 0; i < 3; i++) {
        mlk_poly_frombytes(&t.vec[i], ek + (size_t)384 * i);
        mlk_sample_cbd(&r.vec[i], coins, (uint8_t)i);
        mlk_poly_ntt(&r.vec[i]);
    }
    for (unsigned i = 0; i < 3; i++) {
        mlk_matvec_row(&u.vec[i], rho, i, 1, &r); // A^T o r (with R^-1)
        mlk_poly_invntt(&u.vec[i]);               // inverse NTT absorbs R^-1
        mlk_sample_cbd(&noise, coins, (uint8_t)(3 + i));
        mlk_poly_add(&u.vec[i], &u.vec[i], &noise); // + e1
        mlk_poly_reduce(&u.vec[i]);
    }
    mlk_polyvec_dot(&v, &t, &r); // t o r (with R^-1)
    mlk_poly_invntt(&v);
    mlk_sample_cbd(&noise, coins, 6); // e2
    mlk_poly_add(&v, &v, &noise);
    mlk_poly_frommsg(&noise, m); // Decompress1(m)
    mlk_poly_add(&v, &v, &noise);
    mlk_poly_reduce(&v);
    mlk_polyvec_compress(ct, &u);
    mlk_poly_compress(ct + MLK_U_BYTES, &v);
    // u and v are published only compressed; the low bits the
    // compression drops depend on the secret noise, so both are wiped.
    ct_wipe(&r, sizeof r);
    ct_wipe(&u, sizeof u);
    ct_wipe(&v, sizeof v);
    ct_wipe(&noise, sizeof noise);
}

// K-PKE.Decrypt (Algorithm 15). Recovers the 32-byte message from a
// ciphertext and the K-PKE secret key.
static void mlk_pke_decrypt(uint8_t m[32], const uint8_t dkpke[MLK_DKPKE_BYTES],
                            const uint8_t ct[MLKEM_CT_LEN]) {
    mlk_polyvec u;
    mlk_polyvec s;
    mlk_poly v;
    mlk_poly w;
    mlk_polyvec_decompress(&u, ct);
    mlk_poly_decompress(&v, ct + MLK_U_BYTES);
    for (unsigned i = 0; i < 3; i++) {
        mlk_poly_ntt(&u.vec[i]);
        mlk_poly_frombytes(&s.vec[i], dkpke + (size_t)384 * i);
    }
    mlk_polyvec_dot(&w, &s, &u); // s o NTT(u) (with R^-1)
    mlk_poly_invntt(&w);         // inverse NTT absorbs R^-1
    mlk_poly_sub(&w, &v, &w);    // v - s o u
    mlk_poly_reduce(&w);
    mlk_poly_tomsg(m, &w);
    ct_wipe(&s, sizeof s);
    ct_wipe(&w, sizeof w);
}

// FIPS 203 section 7.2 modulus check: every 12-bit field of the encoded
// t-hat must be a valid Z_q element. ByteDecode12 reduces mod q, so a
// field at or above q would not round-trip. Reads only the public ek, so
// the value-dependent branch leaks nothing. Returns nonzero on failure.
static int mlk_modulus_check(const uint8_t ek[MLKEM_EK_LEN]) {
    for (unsigned i = 0; i < 1152; i += 3) {
        uint16_t lo = (uint16_t)((ek[i] | ((uint16_t)ek[i + 1] << 8)) & 0xfff);
        uint16_t hi = (uint16_t)(((ek[i + 1] >> 4) | ((uint16_t)ek[i + 2] << 4)) & 0xfff);
        if (lo >= MLKEM_Q || hi >= MLKEM_Q) {
            return 1;
        }
    }
    return 0;
}

// K_bar = J(z || ct) = SHAKE256(z || ct, 32), the implicit-reject secret.
static void mlk_reject_secret(uint8_t out[32], const uint8_t z[32],
                              const uint8_t ct[MLKEM_CT_LEN]) {
    shake s;
    shake256_init(&s);
    shake_absorb(&s, z, 32);
    shake_absorb(&s, ct, MLKEM_CT_LEN);
    shake_squeeze(&s, out, 32);
    ct_wipe(&s, sizeof s);
}

void mlkem_keygen_derand(uint8_t ek[MLKEM_EK_LEN], uint8_t dk[MLKEM_DK_LEN], const uint8_t d[32],
                         const uint8_t z[32]) {
    // dk = dkpke || ek || H(ek) || z.
    mlk_pke_keygen(ek, dk, d);
    memcpy(dk + 1152, ek, MLKEM_EK_LEN);
    sha3_256(ek, MLKEM_EK_LEN, dk + 2336);
    memcpy(dk + 2368, z, 32);
}

int mlkem_encaps_derand(uint8_t ct[MLKEM_CT_LEN], uint8_t ss[MLKEM_SS_LEN],
                        const uint8_t ek[MLKEM_EK_LEN], const uint8_t m[32]) {
    if (mlk_modulus_check(ek) != 0) {
        return 1;
    }
    uint8_t gin[64]; // m || H(ek)
    uint8_t g[64];   // (K, r)
    memcpy(gin, m, 32);
    sha3_256(ek, MLKEM_EK_LEN, gin + 32);
    sha3_512(gin, 64, g);
    mlk_pke_encrypt(ct, ek, m, g + 32); // coins = r
    memcpy(ss, g, 32);                  // shared secret = K
    ct_wipe(gin, sizeof gin);
    ct_wipe(g, sizeof g);
    return 0;
}

void mlkem_decaps(uint8_t ss[MLKEM_SS_LEN], const uint8_t ct[MLKEM_CT_LEN],
                  const uint8_t dk[MLKEM_DK_LEN]) {
    const uint8_t *dkpke = dk;
    const uint8_t *ek = dk + 1152;
    const uint8_t *h = dk + 2336; // H(ek)
    const uint8_t *z = dk + 2368;
    uint8_t mp[32];
    uint8_t gin[64]; // m' || h
    uint8_t g[64];   // (K', r')
    uint8_t kbar[32];
    uint8_t ct2[MLKEM_CT_LEN];
    mlk_pke_decrypt(mp, dkpke, ct);
    memcpy(gin, mp, 32);
    memcpy(gin + 32, h, 32);
    sha3_512(gin, 64, g);
    mlk_reject_secret(kbar, z, ct);
    mlk_pke_encrypt(ct2, ek, mp, g + 32); // re-encrypt with r'
    // ss = (ct == ct2) ? K' : K_bar, selected in constant time.
    uint32_t eq = ct_memeq(ct, ct2, MLKEM_CT_LEN);
    uint8_t keep = (uint8_t)(-(uint8_t)eq); // 0xff on match, 0x00 otherwise
    for (unsigned i = 0; i < 32; i++) {
        ss[i] = (uint8_t)((g[i] & keep) | (kbar[i] & (uint8_t)~keep));
    }
    ct_wipe(mp, sizeof mp);
    ct_wipe(gin, sizeof gin);
    ct_wipe(g, sizeof g);
    ct_wipe(kbar, sizeof kbar);
    ct_wipe(ct2, sizeof ct2);
}
