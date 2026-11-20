# shellcheck shell=bash
# Whether this Linux arm64 core is an Arm Neoverse N2: implementer 0x41,
# part 0xd49, as /proc/cpuinfo states them. On that core the SHA-3
# instructions run Keccak 1.8 times slower than the general registers, so
# a caller there leaves CH_CPU_CONSTANT_TIME_SHA3 clear and states
# CH_CPU_CONSTANT_TIME_EOR3, which keeps AES-GCM's EOR3 (docs/usage.md,
# docs/decisions.md 240 and 244). bench/primitives.sh then states every bit
# but the SHA-3 one, and bench/record.sh times its EOR3 rows under
# ch_cfg.cpu 0x2003 in place of 0x83.
# bench/primitives.sh and bench/record.sh source this file.
neoverse_n2() {
    [ -r /proc/cpuinfo ] &&
        [ "$(sed -n '/^CPU implementer/{s/^CPU implementer[[:space:]]*: //p;q;}' /proc/cpuinfo)" = 0x41 ] &&
        [ "$(sed -n '/^CPU part/{s/^CPU part[[:space:]]*: //p;q;}' /proc/cpuinfo)" = 0xd49 ]
}
