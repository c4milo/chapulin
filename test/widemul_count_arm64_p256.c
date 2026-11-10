// p256_arm64_point.c, p256_arm64_mul.c and p256_arm64_verify.c, the copy of
// P-256's wide files in an arm64 host object (p256_arm64.h), with the entries
// widemul.h and p256.c dispatch to under second names
// (test/widemul_runtime_count.h). Each define renames a p256_arm64_ name,
// which p256_arm64_names.h then gives to the wide name the copied file
// spells, so the copy's own calls and its definitions take the second name.
// p256_arm64_field.c and p256_arm64_verify_point.c hold no dispatched entry,
// and a counting binary links them as they are. p256_wide_scalar_mul takes
// its second name here for test/widemul_count_wide_p256.c's reason: the
// verifier's call of it then counts for neither answer. On another
// architecture it compiles to nothing.
#define p256_arm64_point_from_bytes p256_arm64_point_from_bytes_counted
#define p256_arm64_point_affine p256_arm64_point_affine_counted
#define p256_arm64_point_on_curve p256_arm64_point_on_curve_counted
#define p256_arm64_mul p256_arm64_mul_counted
#define p256_arm64_base_mul p256_arm64_base_mul_counted
#define p256_arm64_verify_rs p256_arm64_verify_rs_counted
#define p256_wide_scalar_mul p256_wide_scalar_mul_counted

#include "p256_arm64_mul.c"
#include "p256_arm64_point.c"
#include "p256_arm64_verify.c"
