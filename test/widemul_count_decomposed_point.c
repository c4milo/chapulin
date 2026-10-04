// p256_point.c under its own names, with the entries widemul.h dispatches
// to under test/widemul_count_names.h's second names
// (test/widemul_runtime_count.h). p256_field.c, which it calls, has no
// dispatched entry and is linked as it is.
#include "widemul_count_names.h"

#include "p256_point.c"
