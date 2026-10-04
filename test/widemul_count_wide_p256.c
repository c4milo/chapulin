// p256_wide_scalar.c, p256_wide_point.c and p256_wide_mul.c, P-256's
// second copy in a host object, with the six entries widemul.h dispatches
// to under second names (test/widemul_runtime_count.h). The renames are
// here and not in test/widemul_count_names.h for the reason
// test/widemul_count_wide.c gives: no other unit compiles these files.
// p256_wide_field.c, which they call, has no dispatched entry and is
// linked as it is. The three define no static name twice, so one unit
// holds them.
#define p256_wide_scalar_mul p256_wide_scalar_mul_counted
#define p256_wide_scalar_inverse p256_wide_scalar_inverse_counted
#define p256_wide_point_from_bytes p256_wide_point_from_bytes_counted
#define p256_wide_point_affine p256_wide_point_affine_counted
#define p256_wide_mul p256_wide_mul_counted
#define p256_wide_base_mul p256_wide_base_mul_counted

#include "p256_wide_mul.c"
#include "p256_wide_point.c"
#include "p256_wide_scalar.c"
