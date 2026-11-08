// The body of keccak_neon.c's two permutations. keccak_neon.c includes this file twice: once
// with the four operations below on plain NEON, and once, where clang compiled the object, on
// FEAT_SHA3's instructions. So both forms run the same text, and only the four operations
// differ. Before each include keccak_neon.c defines:
//
//   KN_PERMUTE         the name of the function this file defines.
//   kn_xor3(x, y, z)   x ^ y ^ z, each lane: EOR3.
//   kn_rax1(x, y)      x ^ rotate_left(y, 1), each lane: RAX1.
//   kn_xar(x, y, r)    rotate_left(x ^ y, r), each lane, for r from 1 to 63: XAR by 64 - r.
//   kn_bcax(x, y, z)   x ^ (y & ~z), each lane: BCAX.
//
// One round is sha3.c's keccak_round with each step on one of the four operations, in
// sha3_hw.c's order (docs/decisions.md 99):
//
//   theta: two kn_xor3 make a column's parity, and kn_rax1 is d[x] = c[x - 1] ^
//     rotate_left(c[x + 1], 1).
//   rho and pi: kn_xar is theta's XOR of d into a lane and rho's rotation of it, at once. The
//     sources and the offsets are sha3.c's 25 lines.
//   chi: kn_bcax(b[x], b[x + 2], b[x + 1]) is b[x] ^ (~b[x + 1] & b[x + 2]).
//   iota: an exclusive OR with the round constant in both lanes.
//
// The state stays in 25 registers through the 24 rounds, and the five values of d are computed
// in the order that reads each parity for the last time as early as it can, as in sha3_hw.c.
// No include guard: the file is read twice on purpose.

void KN_PERMUTE(keccak_x2 *s) {
    uint64x2_t a0 = vld1q_u64(s->lane[0]);
    uint64x2_t a1 = vld1q_u64(s->lane[1]);
    uint64x2_t a2 = vld1q_u64(s->lane[2]);
    uint64x2_t a3 = vld1q_u64(s->lane[3]);
    uint64x2_t a4 = vld1q_u64(s->lane[4]);
    uint64x2_t a5 = vld1q_u64(s->lane[5]);
    uint64x2_t a6 = vld1q_u64(s->lane[6]);
    uint64x2_t a7 = vld1q_u64(s->lane[7]);
    uint64x2_t a8 = vld1q_u64(s->lane[8]);
    uint64x2_t a9 = vld1q_u64(s->lane[9]);
    uint64x2_t a10 = vld1q_u64(s->lane[10]);
    uint64x2_t a11 = vld1q_u64(s->lane[11]);
    uint64x2_t a12 = vld1q_u64(s->lane[12]);
    uint64x2_t a13 = vld1q_u64(s->lane[13]);
    uint64x2_t a14 = vld1q_u64(s->lane[14]);
    uint64x2_t a15 = vld1q_u64(s->lane[15]);
    uint64x2_t a16 = vld1q_u64(s->lane[16]);
    uint64x2_t a17 = vld1q_u64(s->lane[17]);
    uint64x2_t a18 = vld1q_u64(s->lane[18]);
    uint64x2_t a19 = vld1q_u64(s->lane[19]);
    uint64x2_t a20 = vld1q_u64(s->lane[20]);
    uint64x2_t a21 = vld1q_u64(s->lane[21]);
    uint64x2_t a22 = vld1q_u64(s->lane[22]);
    uint64x2_t a23 = vld1q_u64(s->lane[23]);
    uint64x2_t a24 = vld1q_u64(s->lane[24]);

    for (int round = 0; round < 24; round++) {
        uint64x2_t c0 = kn_xor3(kn_xor3(a0, a5, a10), a15, a20);
        uint64x2_t c2 = kn_xor3(kn_xor3(a2, a7, a12), a17, a22);
        uint64x2_t d1 = kn_rax1(c0, c2);
        uint64x2_t c1 = kn_xor3(kn_xor3(a1, a6, a11), a16, a21);
        uint64x2_t b1 = kn_xar(a6, d1, 44);
        uint64x2_t b8 = kn_xar(a16, d1, 45);
        uint64x2_t b10 = kn_xar(a1, d1, 1);
        uint64x2_t b17 = kn_xar(a11, d1, 10);
        uint64x2_t b24 = kn_xar(a21, d1, 2);
        uint64x2_t c3 = kn_xor3(kn_xor3(a3, a8, a13), a18, a23);
        uint64x2_t d4 = kn_rax1(c3, c0);
        uint64x2_t c4 = kn_xor3(kn_xor3(a4, a9, a14), a19, a24);
        uint64x2_t b4 = kn_xar(a24, d4, 14);
        uint64x2_t b6 = kn_xar(a9, d4, 20);
        uint64x2_t b13 = kn_xar(a19, d4, 8);
        uint64x2_t b15 = kn_xar(a4, d4, 27);
        uint64x2_t b22 = kn_xar(a14, d4, 39);
        uint64x2_t d3 = kn_rax1(c2, c4);
        uint64x2_t b3 = kn_xar(a18, d3, 21);
        uint64x2_t b5 = kn_xar(a3, d3, 28);
        uint64x2_t b12 = kn_xar(a13, d3, 25);
        uint64x2_t b19 = kn_xar(a23, d3, 56);
        uint64x2_t b21 = kn_xar(a8, d3, 55);
        uint64x2_t d0 = kn_rax1(c4, c1);
        uint64x2_t b0 = veorq_u64(a0, d0);
        uint64x2_t b7 = kn_xar(a10, d0, 3);
        uint64x2_t b14 = kn_xar(a20, d0, 18);
        uint64x2_t b16 = kn_xar(a5, d0, 36);
        uint64x2_t b23 = kn_xar(a15, d0, 41);
        uint64x2_t d2 = kn_rax1(c1, c3);
        uint64x2_t b2 = kn_xar(a12, d2, 43);
        uint64x2_t b9 = kn_xar(a22, d2, 61);
        uint64x2_t b11 = kn_xar(a7, d2, 6);
        uint64x2_t b18 = kn_xar(a17, d2, 15);
        uint64x2_t b20 = kn_xar(a2, d2, 62);

        a0 = kn_bcax(b0, b2, b1);
        a1 = kn_bcax(b1, b3, b2);
        a2 = kn_bcax(b2, b4, b3);
        a3 = kn_bcax(b3, b0, b4);
        a4 = kn_bcax(b4, b1, b0);
        a5 = kn_bcax(b5, b7, b6);
        a6 = kn_bcax(b6, b8, b7);
        a7 = kn_bcax(b7, b9, b8);
        a8 = kn_bcax(b8, b5, b9);
        a9 = kn_bcax(b9, b6, b5);
        a10 = kn_bcax(b10, b12, b11);
        a11 = kn_bcax(b11, b13, b12);
        a12 = kn_bcax(b12, b14, b13);
        a13 = kn_bcax(b13, b10, b14);
        a14 = kn_bcax(b14, b11, b10);
        a15 = kn_bcax(b15, b17, b16);
        a16 = kn_bcax(b16, b18, b17);
        a17 = kn_bcax(b17, b19, b18);
        a18 = kn_bcax(b18, b15, b19);
        a19 = kn_bcax(b19, b16, b15);
        a20 = kn_bcax(b20, b22, b21);
        a21 = kn_bcax(b21, b23, b22);
        a22 = kn_bcax(b22, b24, b23);
        a23 = kn_bcax(b23, b20, b24);
        a24 = kn_bcax(b24, b21, b20);

        a0 = veorq_u64(a0, vld1q_dup_u64(&RC[round]));
    }

    vst1q_u64(s->lane[0], a0);
    vst1q_u64(s->lane[1], a1);
    vst1q_u64(s->lane[2], a2);
    vst1q_u64(s->lane[3], a3);
    vst1q_u64(s->lane[4], a4);
    vst1q_u64(s->lane[5], a5);
    vst1q_u64(s->lane[6], a6);
    vst1q_u64(s->lane[7], a7);
    vst1q_u64(s->lane[8], a8);
    vst1q_u64(s->lane[9], a9);
    vst1q_u64(s->lane[10], a10);
    vst1q_u64(s->lane[11], a11);
    vst1q_u64(s->lane[12], a12);
    vst1q_u64(s->lane[13], a13);
    vst1q_u64(s->lane[14], a14);
    vst1q_u64(s->lane[15], a15);
    vst1q_u64(s->lane[16], a16);
    vst1q_u64(s->lane[17], a17);
    vst1q_u64(s->lane[18], a18);
    vst1q_u64(s->lane[19], a19);
    vst1q_u64(s->lane[20], a20);
    vst1q_u64(s->lane[21], a21);
    vst1q_u64(s->lane[22], a22);
    vst1q_u64(s->lane[23], a23);
    vst1q_u64(s->lane[24], a24);
}
