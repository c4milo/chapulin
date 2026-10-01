// Test and bench code only. A build that force-includes this header
// (-include) runs every one of gcm_hw.c's three entries on gcm_vaes.c's
// 256-bit kernel of the same shape, whatever gcm_hw.c's use_vaes answers:
// the header renames each entry to its kernel, in gcm.c's calls and in any
// test that calls an entry itself. Such a build links gcm_vaes.c and not
// gcm_hw.c, and links test/x86_kernels_route.c, which stops it before main
// on a CPU without VAES and VPCLMULQDQ. That is how SP 800-38D's vectors,
// Wycheproof, the AEAD's equivalence cases, the stack residue checks and
// the record bench run on the kernels while use_vaes still answers 0
// (docs/decisions.md 90).
#ifndef CH_TEST_GCM_VAES_ROUTE_H
#define CH_TEST_GCM_VAES_ROUTE_H

#define TEST_ROUTE_VAES
#define gcm_counter_blocks_hw gcm_counter_blocks_vaes
#define gcm_seal_passes_hw gcm_seal_passes_vaes
#define gcm_open_passes_hw gcm_open_passes_vaes

#endif
