// chacha20_vector.c under CH_CHACHA_VECTOR, for bin/chacha20_equiv_test.
// That binary also links chacha20.c, compiled without the define so that
// chacha20_xor is the portable loop, and one compile line cannot give the
// two sources different defines, so this translation unit gives the vector
// path its own. The two sources define different external names, so
// nothing is renamed.
#define CH_CHACHA_VECTOR
#include "chacha20_vector.c"
