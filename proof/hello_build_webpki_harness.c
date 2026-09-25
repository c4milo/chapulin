// The TRUST=webpki variant of the hello_build proof: the same harness
// over the builder's webpki arm, which adds the server_name extension,
// five signature schemes and the three-group offer, the hybrid and x25519
// key shares or the one secp256r1 share of a retry hello, against that
// build's larger CH_HELLO_MAX. The
// launch line passes -DCH_TRUST_WEBPKI so buf.c and this file see the
// same build. A proof name is one launch line, so the variant gets its
// own file, the pem_ecdsa precedent.
#ifndef CH_TRUST_WEBPKI
#error "hello_build_webpki proves the TRUST=webpki arm; its launch line must pass -DCH_TRUST_WEBPKI"
#endif
#include "hello_build_harness.c"
