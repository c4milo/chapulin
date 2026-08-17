// libFuzzer harness for the two handshake message parsers that face
// pre-authentication attacker bytes: hsp_parse_sh (ServerHello) and
// hsp_parse_ee (EncryptedExtensions). Both live in hsparse.c and depend
// only on buf.c, so those two files are the whole link line.
#include <stdint.h>
#include <string.h>

#include "cfg.h"
#include "hsparse.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    sh_info si;
    memset(&si, 0, sizeof si);
    (void)hsp_parse_sh(data, size, &si, (int)(size & 1));

    uint16_t peer_limit = CH_TX_PT;
    uint8_t alert = 0;
    (void)hsp_parse_ee(data, size, &peer_limit, &alert);
    return 0;
}
