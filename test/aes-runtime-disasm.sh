#!/usr/bin/env bash
# Shows that a host object carries each instruction set a ch_cfg.cpu bit
# names in the files written for it and nowhere else (docs/decisions.md
# 81, 88, 89 and 93):
#
#   - the AES and carry-less multiply instructions in aes_hw.c's,
#     ghash_hw.c's, gcm_hw.c's and gcm_vaes.c's functions. gcm_vaes.c
#     holds the 256-bit kernels on x86-64 and nothing on arm64.
#   - the SHA-256 instructions in sha256_hw.c's.
#   - the SHA-512 instructions in sha512_hw.c's, which has a body on arm64
#     alone and which an object with SUITE=aesgcm alone packages.
#
# bin/aes_runtime_test counts the calls into the AES files and finds none
# without the CH_CPU_CONSTANT_TIME_AES bit, and bin/hash_runtime_test the
# calls into sha256_hw.c and sha512_hw.c and finds none without the hash's
# bit; this shows that no other file of the object runs the instructions.
#
# QEMU's arm64 models all implement the AES and SHA-256 extensions, so
# test/aes-runtime-qemu.sh runs the rows without those two bits on an
# x86-64 CPU model alone, and on arm64 this script is what reads the
# object. CI's arm64 job runs it. It runs on x86-64 as well.
#
# It builds three host objects with this host's compiler and no
# instruction flag: the TCP server with the suite (check-lib-server-aes),
# the ROLE=both TRUST=webpki QUIC object with the suite
# (check-lib-quic-aes), and the TRUST=webpki QUIC client without it, whose
# AES runs QUIC's public keys alone. For each it disassembles every
# source's object and requires:
#
#   - no AES or carry-less multiply instruction in any object but
#     aes_hw.o, ghash_hw.o, gcm_hw.o and gcm_vaes.o, no SHA-256
#     instruction in any object but sha256_hw.o, and no SHA-512
#     instruction in any object but sha512_hw.o;
#   - an AES instruction in aes_hw.o, a carry-less multiply in ghash_hw.o,
#     both in gcm_hw.o, a SHA-256 instruction in sha256_hw.o, and on arm64
#     a SHA-512 instruction in sha512_hw.o, so a disassembler that spells
#     one another way fails the check rather than passes it;
#   - on arm64, none of FEAT_SHA3's eor3, rax1, xar and bcax in
#     sha512_hw.o. That file's target attribute turns them on beside the
#     SHA-512 ones, a compiler writes them for plain C, and
#     CH_CPU_CONSTANT_TIME_SHA512 states nothing about them. No other
#     object is read for them: Apple clang's default CPU has FEAT_SHA3,
#     so on macOS any file may hold one;
#   - as many of those instructions in the linked chapulin.o as in the
#     six files, so an object this script could not read fails too.
#
# The instructions: on arm64 aese, aesd, aesmc, aesimc, pmull and pmull2,
# sha256h, sha256h2, sha256su0 and sha256su1, and sha512h, sha512h2,
# sha512su0 and sha512su1; on x86-64 the AES-NI instructions and
# pclmulqdq, with or without the VEX prefix, and sha256rnds2, sha256msg1
# and sha256msg2. Each set is matched by the start of the mnemonic,
# because Apple's objdump writes the arm64 ones with the arrangement after
# them, as in sha256h.4s. GNU objdump and llvm-objdump both read the
# objects, and OBJDUMP names another.
cd "$(dirname "$0")/.." || exit 1
export LC_ALL=C
objdump=${OBJDUMP:-objdump}
machine=$(${CC:-cc} -dumpmachine) || exit 1
# Whether this target's sha512_hw.c has a body, and so must hold the
# instructions.
sha512_body=""
# FEAT_SHA3's four instructions, which sha512_hw.o must not hold.
sha3='^(eor3|rax1|xar|bcax)'
case "$machine" in
aarch64-* | arm64-*)
    aes='^aes'
    clmul='^pmull'
    sha256='^sha256'
    sha512='^sha512'
    sha512_body=yes
    ;;
x86_64-*)
    aes='^v?aes'
    clmul='^v?pclmul'
    sha256='^v?sha256'
    sha512='^v?sha512'
    ;;
*)
    echo "aes-runtime-disasm: $machine is neither arm64 nor x86-64, the two host targets" >&2
    exit 1
    ;;
esac
every="$aes|$clmul|$sha256|$sha512"

# Prints one line for each instruction of the object $1 whose mnemonic
# matches the pattern $2, or one of the four sets without it: the label of
# the function that holds it, then the mnemonic.
instructions() {
    "$objdump" -d --no-show-raw-insn "$1" | awk -v every="${2:-$every}" '
        /^[0-9a-f]+ <.+>:$/ { label = $2; gsub(/^<|>:$/, "", label); next }
        /^ *[0-9a-f]+:/ {
            sub(/^ *[0-9a-f]+:[ \t]*/, "")
            if ($1 ~ every) print label, $1
        }'
}

# Counts the lines of $1 whose mnemonic matches the pattern $2. A line
# holds a label and a mnemonic, so the empty line an empty $1 gives counts
# as none.
count() {
    awk -v pattern="$2" 'NF == 2 && $2 ~ pattern { n++ } END { print n + 0 }' <<< "$1"
}

# Prints the lines of $1 whose mnemonic does not match the pattern $2.
outside() {
    awk -v pattern="$2" 'NF == 2 && $2 !~ pattern' <<< "$1"
}

# Each object's make variables. Each is a host object on this compiler,
# and the HOST_TARGET=yes beside them makes the build fail rather than
# package a device object where the host test does not pass.
objects=(
    "ROLE=server TRUST=none SUITE=aesgcm"
    "TRANSPORT=quic-nonblocking ROLE=both TRUST=webpki SUITE=aesgcm KEYLOG=on EXPORTER=off"
    "TRANSPORT=quic-nonblocking TRUST=webpki EXPORTER=off"
)
rc=0
# Requires at least one instruction of a set in a file's object.
holds() { # $1 = the object's variables, $2 = the count, $3 = what is missing and where
    [ "$2" -gt 0 ] && return 0
    echo "aes-runtime-disasm: [$1]: read no $3" >&2
    rc=1
}
for object in "${objects[@]}"; do
    read -r -a vars <<< "RAND=extern HOST_TARGET=yes $object"
    lines=$(make -s --no-print-directory "${vars[@]}" lib-pair-object) ||
        { echo "aes-runtime-disasm: [$object]: the build failed" >&2; exit 1; }
    obj=$(tail -n 3 <<< "$lines" | sed -n 1p)
    srcs=$(make -s --no-print-directory "${vars[@]}" print-lib-srcs) || exit 1
    in_files=0
    for src in $srcs; do
        o=${obj%/chapulin.o}/${src%.c}.o
        [ -f "$o" ] || { echo "aes-runtime-disasm: [$object]: $o is missing" >&2; exit 1; }
        found=$(instructions "$o")
        # The sets the file may hold: a pattern that matches no mnemonic
        # for every file but the six.
        case "$src" in
        aes_hw.c | ghash_hw.c | gcm_hw.c | gcm_vaes.c) own="$aes|$clmul" ;;
        sha256_hw.c) own="$sha256" ;;
        sha512_hw.c) own="$sha512" ;;
        *) own='^$' ;;
        esac
        in_files=$((in_files + $(count "$found" "$own")))
        stray=$(outside "$found" "$own")
        if [ -n "$stray" ]; then
            while read -r label mnemonic; do
                echo "aes-runtime-disasm: [$object]: $src runs $mnemonic in $label" >&2
            done <<< "$stray"
            rc=1
        fi
        case "$src" in
        aes_hw.c) holds "$object" "$(count "$found" "$aes")" "AES instruction in aes_hw.o" ;;
        ghash_hw.c) holds "$object" "$(count "$found" "$clmul")" "carry-less multiply in ghash_hw.o" ;;
        gcm_hw.c)
            holds "$object" "$(count "$found" "$aes")" "AES instruction in gcm_hw.o"
            holds "$object" "$(count "$found" "$clmul")" "carry-less multiply in gcm_hw.o"
            ;;
        sha256_hw.c) holds "$object" "$(count "$found" "$sha256")" "SHA-256 instruction in sha256_hw.o" ;;
        sha512_hw.c)
            if [ -n "$sha512_body" ]; then
                holds "$object" "$(count "$found" "$sha512")" "SHA-512 instruction in sha512_hw.o"
                while read -r label mnemonic; do
                    [ -n "$label" ] || continue
                    echo "aes-runtime-disasm: [$object]: sha512_hw.c runs $mnemonic in $label, one of" \
                        "FEAT_SHA3's, which CH_CPU_CONSTANT_TIME_SHA512 does not name" >&2
                    rc=1
                done <<< "$(instructions "$o" "$sha3")"
            fi
            ;;
        esac
    done
    linked=$(count "$(instructions "$obj")" "$every")
    if [ "$linked" -ne "$in_files" ]; then
        echo "aes-runtime-disasm: [$object]: chapulin.o holds $linked of the instructions," \
            "and aes_hw.o, ghash_hw.o, gcm_hw.o, gcm_vaes.o, sha256_hw.o and sha512_hw.o hold $in_files" >&2
        rc=1
    fi
    echo "aes-runtime-disasm: [$object]: $linked instructions, $in_files of them in aes_hw.c, ghash_hw.c, gcm_hw.c, gcm_vaes.c, sha256_hw.c and sha512_hw.c"
done
[ "$rc" -ne 0 ] ||
    echo "aes-runtime-disasm: on $machine, no AES or carry-less multiply instruction outside aes_hw.c, ghash_hw.c, gcm_hw.c and gcm_vaes.c, no SHA-256 instruction outside sha256_hw.c, no SHA-512 instruction outside sha512_hw.c and none of FEAT_SHA3's in it"
exit "$rc"
