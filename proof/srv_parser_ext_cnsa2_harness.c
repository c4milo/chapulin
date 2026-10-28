// Proves: srv_parser_ext_harness.c's properties under the PROFILE=cnsa2
// server's defines (docs/decisions.md 162): every reader of
// srv_parser_ext.c over an unconstrained body up to EXT_MAX bytes, any type
// and any offset, with the profile's one group, one scheme and the
// share length MLKEM_EK_LEN. A body this short holds no full-length share,
// so every key_share entry for the profile's group is refused here, and
// srv_parser_ext_cnsa2_share holds the full-length one.
#include "srv_parser_ext_harness.c"
