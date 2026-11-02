// Proves proof/srv_parser_ext_cnsa2_share_harness.c's claims for the
// key_share reader of a server outside PROFILE=cnsa2, which holds
// ML-KEM-1024 beside its other three groups (docs/decisions.md 179): its
// launch line passes the default server's defines.
#ifdef CH_PROFILE_CNSA2
#error "srv_parser_ext_mlkem1024_share_harness proves the server outside PROFILE=cnsa2"
#endif
#include "srv_parser_ext_cnsa2_share_harness.c"
