// The copy of a file that calls SHA-2, for a host object's sessions on the CPU's hash
// instructions (-DCH_CPU_RUNTIME, docs/decisions.md 93). hkdf_hw.c and keysched_hw.c each include
// this header and then their file, so the copy is the same source text as the file under its own
// names, compiled once more, as widemul_native.h compiles a file again on the native multiply.
//
// The renames below do two things. They send the copy's hash calls to the entries that run on
// the instructions, sha256_hw.c's, where the file under its own names calls sha256.c's portable
// ones. And they give every function the copied files define outside their own translation
// unit a second name, the first with _hw after it, so the two copies define no name twice. They
// rename the declarations each file's header gives as well as its definitions, and a call from
// keysched.c to hkdf.c calls the copy of the callee. The entries that end hkdf.h and keysched.h
// call the _hw names for a session whose ch_cfg.cpu names the instructions of the hash the call
// runs, and the file under its own names for any other.
//
// Every call in the two files runs the one hash its hash_len argument names, so a copy that
// holds two hashes still runs each on its own bit alone: the entries pick a copy by the bit of
// that hash (hkdf.h's hash_on_instructions). SHA-384 has no entry on the instructions yet, so
// the copies' SHA-384 arms call sha512.c's portable code, and no entry calls a copy at that
// hash length.
//
// Every name the copied files define outside their unit is here. A name left out is defined by
// both copies, and the link of the object refuses it. sha256.h, hkdf.h and keysched.h read
// CH_HASH_HW_H: a copy takes their declarations of the _hw names and none of their entries,
// whose two arms the renames would send to one path.
#ifndef CH_HASH_HW_H
#define CH_HASH_HW_H

#ifndef CH_CPU_RUNTIME
#error "a copy on the hash instructions belongs to a host object (docs/decisions.md 93)"
#endif

// sha256.c's three calls that hash. sha256_init writes the initial value alone and keeps its
// name: both paths start from it.
#define sha256_update sha256_update_hw
#define sha256_final sha256_final_hw
#define sha256_of sha256_of_hw

// hkdf.c.
#define hmac_sha256 hmac_sha256_hw
#define hmac_sha384 hmac_sha384_hw
#define hmac hmac_hw
#define hkdf_extract hkdf_extract_hw
#define hkdf_expand hkdf_expand_hw
#define hkdf_expand_label hkdf_expand_label_hw
#define hkdf_derive_secret hkdf_derive_secret_hw

// keysched.c.
#define ks_early ks_early_hw
#define ks_verify_data ks_verify_data_hw
#define ks_handshake ks_handshake_hw
#define ks_master ks_master_hw
#define ks_res_master ks_res_master_hw
#define ks_res_psk ks_res_psk_hw
#define ks_exp_master ks_exp_master_hw
#define ks_exporter ks_exporter_hw

#endif
