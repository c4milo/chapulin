// The TRUST=webpki variant of the eeparse proof: the same harness over
// the EncryptedExtensions parser's webpki arm, which admits one empty
// server_name acknowledgement and one server_certificate_type beside
// the other two extensions, each only when the ClientHello asked for it.
// -DCH_TRUST_WEBPKI comes from the launch line rather than a #define
// here, because handshake_parser_ee.c is its own translation unit on
// that line and a define in this file would not reach it. A proof name is one
// launch line, so the variant gets its own file, the pem_ecdsa precedent.
#ifndef CH_TRUST_WEBPKI
#error "eeparse_webpki proves the TRUST=webpki arm; its launch line must pass -DCH_TRUST_WEBPKI"
#endif
#include "eeparse_harness.c"
