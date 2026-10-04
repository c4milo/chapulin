// record.c compiled with its AEAD calls replaced, for bench/record.c only.
// The first four #defines rename rec_seal's and rec_open's calls to
// gcm_traffic_seal, gcm_traffic_open, aead_seal and aead_open, and the
// declarations record.c reads, to bench/record_stub.c's stubs, which do
// nothing. record.c's own text is unchanged, so the two renamed entries
// time what the record layer does besides the AEAD: the header, the copy
// of the caller's plaintext, the nonce, the AES key expansion and its
// wipe. The other renames keep this copy's external names apart from the
// library's record.o, which the bench also links. The include names the
// parent directory because a quoted include looks in bench/ first, and
// bench/record.c is the bench itself.
#define gcm_traffic_seal bench_stub_gcm_traffic_seal
#define gcm_traffic_open bench_stub_gcm_traffic_open
#define aead_seal_cpu bench_stub_aead_seal_cpu
#define aead_open_cpu bench_stub_aead_open_cpu
#define rec_dir_init bench_layer_rec_dir_init
#define rec_dir_init_suite bench_layer_rec_dir_init_suite
#define rec_dir_update bench_layer_rec_dir_update
#define rec_seal bench_rec_seal_without_aead
#define rec_open bench_rec_open_without_aead

#include "../record.c"

#include "record_stages.h"
