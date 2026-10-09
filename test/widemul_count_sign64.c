// rsa_sign64.c, RSA signing's second copy in a host object, with the three
// entries widemul.h dispatches to under second names
// (test/widemul_runtime_count.h). The renames are here and not in
// test/widemul_count_names.h, because rsa_sign64.c renames rsa_sign.c's
// entry itself to compile rsa_sign.c's key test and encoder inside it, and
// that header renames rsa_sign.c's entry under its device name for the
// other units.
#define rsa_sign64_pss rsa_sign64_pss_counted
#define rsa_sign64_sp1 rsa_sign64_sp1_counted
#define rsa_sign64_key_ok rsa_sign64_key_ok_counted

#include "rsa_sign64.c"
