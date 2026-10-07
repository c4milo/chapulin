// The names of mlkem.c's copy for an x86-64 host object's sessions with
// CH_CPU_AVX2 (mlkem_avx2.c, docs/decisions.md 107). mlkem_avx2.c includes
// this header and then mlkem.c, so the copy is mlkem.c's own text compiled
// once more, as keccak_hw.h's copies are for the SHA-3 instructions.
//
// The renames give the four functions mlkem.c defines outside its
// translation unit a second name, the first with _avx2 after it, so the two
// copies define no name twice. They rename mlkem.h's declarations as well
// as the definitions. Every other call keeps its name: the copy runs
// mlkem_poly.c, sha3.c and mlkem_vector.c as mlkem.c does, and differs from
// it in mlk_matvec_row alone. mlkem.h reads CH_MLKEM_AVX2_H: the copy takes
// its declarations of the _avx2 names and none of its entries, whose two
// arms the renames would send to one path.
#ifndef CH_MLKEM_AVX2_H
#define CH_MLKEM_AVX2_H

#ifndef CH_CPU_RUNTIME
#error "a copy for the AVX2 Keccak belongs to a host object (docs/decisions.md 107)"
#endif

#define mlkem_keygen_dk mlkem_keygen_dk_avx2
#define mlkem_keygen_derand mlkem_keygen_derand_avx2
#define mlkem_encaps_derand mlkem_encaps_derand_avx2
#define mlkem_decaps mlkem_decaps_avx2

#endif
