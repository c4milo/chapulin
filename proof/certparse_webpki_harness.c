// The TRUST=webpki variant of the certparse proof: the same harness over
// the CertificateVerify parser's webpki arm, which admits three schemes
// and reports which. -DCH_TRUST_WEBPKI comes from the launch line rather
// than a #define here, because handshake_parser.c is its own translation
// unit on that line and a define in this file would not reach it. A
// proof name is one launch line, so the variant gets its own file, the
// pem_ecdsa precedent.
#ifndef CH_TRUST_WEBPKI
#error "certparse_webpki proves the TRUST=webpki arm; its launch line must pass -DCH_TRUST_WEBPKI"
#endif
#include "certparse_harness.c"
