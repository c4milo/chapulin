// libFuzzer harness for the two handshake message parsers that face
// pre-authentication attacker bytes: hsp_parse_server_hello (ServerHello) in
// handshake_parser.c and hsp_parse_encrypted_exts (EncryptedExtensions) in
// handshake_parser_ee.c. Both depend only on buf.c, so those three files are
// the whole link line.
#include <stdint.h>
#include <string.h>

#include "cfg.h"
#include "handshake_parser.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    server_hello_info info;
    memset(&info, 0, sizeof info);
    (void)hsp_parse_server_hello(data, size, &info, (int)(size & 1));

    uint16_t peer_limit = CH_TX_PT;
    uint8_t alert = 0;
    (void)hsp_parse_encrypted_exts(data, size, &peer_limit, &alert);
    return 0;
}
