#!/usr/bin/env bash
# Shows that a host object carries each instruction set a ch_cfg.cpu bit
# names in the files written for it and nowhere else (docs/decisions.md
# 81, 88, 89 and 93):
#
#   - the AES and carry-less multiply instructions in aes_hw.c's,
#     ghash_hw.c's, gcm_hw.c's and gcm_vaes.c's functions. gcm_vaes.c
#     holds the 256-bit kernels on x86-64 and nothing on arm64.
#   - the SHA-256 instructions in sha256_hw.c's.
#
# bin/aes_runtime_test counts the calls into the AES files and finds none
# without the CH_CPU_CONSTANT_TIME_AES bit, and bin/hash_runtime_test the
# calls into sha256_hw.c and finds none without
# CH_CPU_CONSTANT_TIME_SHA256; this shows that no other file of the object
# runs the instructions.
#
# QEMU's arm64 models all implement the AES and SHA-256 extensions, so
# test/aes-runtime-qemu.sh runs the rows without a bit on an x86-64 CPU
# model alone, and on arm64 this script is what reads the object. CI's arm64 job
# runs it. It runs on x86-64 as well.
#
# It builds three host objects with this host's compiler and no
# instruction flag: the TCP server with the suite (check-lib-server-aes),
# the ROLE=both TRUST=webpki QUIC object with the suite
# (check-lib-quic-aes), and the TRUST=webpki QUIC client without it, whose
# AES runs QUIC's public keys alone. For each it disassembles every
# source's object and requires:
#
#   - no AES or carry-less multiply instruction in any object but
#     aes_hw.o, ghash_hw.o, gcm_hw.o and gcm_vaes.o, and no SHA-256
#     instruction in any object but sha256_hw.o;
#   - an AES instruction in aes_hw.o, a carry-less multiply in ghash_hw.o,
#     both in gcm_hw.o and a SHA-256 instruction in sha256_hw.o, so a
#     disassembler that spells one another way fails the check rather than
#     passes it;
#   - as many of those instructions in the linked chapulin.o as in the
#     five files, so an object this script could not read fails too.
#
# The instructions: on arm64 aese, aesd, aesmc, aesimc, pmull and pmull2,
# and sha256h, sha256h2, sha256su0 and sha256su1; on x86-64 the AES-NI
# instructions and pclmulqdq, with or without the VEX prefix, and
# sha256rnds2, sha256msg1 and sha256msg2. Each set is matched by the
# start of the mnemonic, because Apple's objdump writes the arm64 ones
# with the arrangement after them, as in sha256h.4s. GNU objdump and
# llvm-objdump both read the objects, and OBJDUMP names another.
cd "$(dirname "$0")/.." || exit 1
export LC_ALL=C
objdump=${OBJDUMP:-objdump}
machine=$(${CC:-cc} -dumpmachine) || exit 1
case "$machine" in
aarch64-* | arm64-*)
    aes='^aes'
    clmul='^pmull'
    sha256='^sha256'
    ;;
x86_64-*)
    aes='^v?aes'
    clmul='^v?pclmul'
    sha256='^v?sha256'
    ;;
*)
    echo "aes-runtime-disasm: $machine is neither arm64 nor x86-64, the two host targets" >&2
    exit 1
    ;;
esac
every="$aes|$clmul|$sha256"

# Prints one line for each instruction of the three sets in the object $1:
# the label of the function that holds it, then the mnemonic.
instructions() {
    "$objdump" -d --no-show-raw-insn "$1" | awk -v every="$every" '
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
        # for every file but the five.
        case "$src" in
        aes_hw.c | ghash_hw.c | gcm_hw.c | gcm_vaes.c) own="$aes|$clmul" ;;
        sha256_hw.c) own="$sha256" ;;
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
        if [ "$src" = aes_hw.c ] && [ "$(count "$found" "$aes")" -eq 0 ]; then
            echo "aes-runtime-disasm: [$object]: read no AES instruction in aes_hw.o" >&2
            rc=1
        fi
        if [ "$src" = ghash_hw.c ] && [ "$(count "$found" "$clmul")" -eq 0 ]; then
            echo "aes-runtime-disasm: [$object]: read no carry-less multiply in ghash_hw.o" >&2
            rc=1
        fi
        if [ "$src" = gcm_hw.c ] &&
            { [ "$(count "$found" "$aes")" -eq 0 ] || [ "$(count "$found" "$clmul")" -eq 0 ]; }; then
            echo "aes-runtime-disasm: [$object]: read no AES instruction or no carry-less multiply in gcm_hw.o" >&2
            rc=1
        fi
        if [ "$src" = sha256_hw.c ] && [ "$(count "$found" "$sha256")" -eq 0 ]; then
            echo "aes-runtime-disasm: [$object]: read no SHA-256 instruction in sha256_hw.o" >&2
            rc=1
        fi
    done
    linked=$(count "$(instructions "$obj")" "$every")
    if [ "$linked" -ne "$in_files" ]; then
        echo "aes-runtime-disasm: [$object]: chapulin.o holds $linked of the instructions," \
            "and aes_hw.o, ghash_hw.o, gcm_hw.o, gcm_vaes.o and sha256_hw.o hold $in_files" >&2
        rc=1
    fi
    echo "aes-runtime-disasm: [$object]: $linked instructions, $in_files of them in aes_hw.c, ghash_hw.c, gcm_hw.c, gcm_vaes.c and sha256_hw.c"
done
[ "$rc" -ne 0 ] ||
    echo "aes-runtime-disasm: on $machine, no AES or carry-less multiply instruction outside aes_hw.c, ghash_hw.c, gcm_hw.c and gcm_vaes.c, and no SHA-256 instruction outside sha256_hw.c"
exit "$rc"
