// The EXPORTER arm of the key schedule proof: ks_exp_master and
// ks_exporter compile only under that axis, and it widens hkdf's label
// cap from 12 to 32, so hkdf_expand_label serializes into a larger info
// buffer and hkdf_expand hashes a longer message. A proof at one size
// does not carry to the other, which is why this is a second leg rather
// than a define on the first. See keysched_harness.c for the rest.
#include "keysched_harness.c"
