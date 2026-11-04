// The twiddle factors of ML-KEM-768's NTT: mlkem_poly.c's loops read them,
// and in a host object mlkem_vector.c reads them too. Each file that
// includes this header holds its own copy of the table, 256 bytes, and a
// device object holds mlkem_poly.c's alone.
//
// zetas[k] = zeta^bitreverse7(k) * 2^16 mod q, reduced to (-q/2, q/2].
// zeta = 17 is the primitive 256th root fixed by FIPS 203. The forward and
// inverse transforms read entries 1 to 127, one for each block of
// butterflies, and the base multiplication reads entries 64 to 127.
#ifndef CH_MLKEM_ZETAS_H
#define CH_MLKEM_ZETAS_H

#include <stdint.h>

static const int16_t MLK_ZETAS[128] = {
    -1044, -758,  -359,  -1517, 1493,  1422,  287,   202,   -171,  622,   1577,  182,   962,
    -1202, -1474, 1468,  573,   -1325, 264,   383,   -829,  1458,  -1602, -130,  -681,  1017,
    732,   608,   -1542, 411,   -205,  -1571, 1223,  652,   -552,  1015,  -1293, 1491,  -282,
    -1544, 516,   -8,    -320,  -666,  -1618, -1162, 126,   1469,  -853,  -90,   -271,  830,
    107,   -1421, -247,  -951,  -398,  961,   -1508, -725,  448,   -1065, 677,   -1275, -1103,
    430,   555,   843,   -1251, 871,   1550,  105,   422,   587,   177,   -235,  -291,  -460,
    1574,  1653,  -246,  778,   1159,  -147,  -777,  1483,  -602,  1119,  -1590, 644,   -872,
    349,   418,   329,   -156,  -75,   817,   1097,  603,   610,   1322,  -1285, -1465, 384,
    -1215, -136,  1218,  -1335, -874,  220,   -1187, -1659, -1185, -1530, -1278, 794,   -1510,
    -854,  -870,  478,   -108,  -308,  996,   991,   958,   -1460, 1522,  1628};

#endif
