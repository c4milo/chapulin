#!/usr/bin/env bash
# Shows that an AES=runtime object carries the AES and carry-less multiply
# instructions in aes_hw.c's, ghash_hw.c's and gcm_hw.c's functions and
# nowhere else (docs/decisions.md 81). bin/aes_runtime_test counts the
# calls into those three files and finds none under the answer that the
# instructions are absent; this shows that no other file of the object
# runs them.
#
# QEMU's arm64 models all implement the AES extension, so
# test/aes-runtime-qemu.sh runs the absent answer on an x86-64 CPU model
# alone, and on arm64 this script is what reads the object. CI's arm64 job
# runs it. It runs on x86-64 as well.
#
# It builds the three AES=runtime objects make check links, with this
# host's compiler and no instruction flag: the TCP server
# (check-lib-server-aes-runtime), the ROLE=both TRUST=webpki QUIC object
# (check-lib-quic-aes-runtime) and the raw QUIC client
# (check-lib-quic-raw-aes-runtime). For each it disassembles every
# source's object and requires:
#
#   - no AES or carry-less multiply instruction in any object but
#     aes_hw.o, ghash_hw.o and gcm_hw.o;
#   - an AES instruction in aes_hw.o, a carry-less multiply in ghash_hw.o
#     and both in gcm_hw.o, so a disassembler that spells either another
#     way fails the check rather than passes it;
#   - as many of those instructions in the linked chapulin.o as in the
#     three files, so an object this script could not read fails too.
#
# The instructions: on arm64 aese, aesd, aesmc, aesimc, pmull and pmull2;
# on x86-64 the AES-NI instructions and pclmulqdq, with or without the
# VEX prefix. GNU objdump and llvm-objdump both read the objects, and
# OBJDUMP names another.
cd "$(dirname "$0")/.." || exit 1
export LC_ALL=C
objdump=${OBJDUMP:-objdump}
machine=$(${CC:-cc} -dumpmachine) || exit 1
case "$machine" in
aarch64-* | arm64-*)
    aes='^aes'
    clmul='^pmull'
    ;;
x86_64-*)
    aes='^v?aes'
    clmul='^v?pclmul'
    ;;
*)
    echo "aes-runtime-disasm: $machine is neither arm64 nor x86-64, the two AES=runtime targets" >&2
    exit 1
    ;;
esac

# Prints one line for each AES or carry-less multiply instruction in the
# object $1: the label of the function that holds it, then the mnemonic.
instructions() {
    "$objdump" -d --no-show-raw-insn "$1" | awk -v aes="$aes" -v clmul="$clmul" '
        /^[0-9a-f]+ <.+>:$/ { label = $2; gsub(/^<|>:$/, "", label); next }
        /^ *[0-9a-f]+:/ {
            sub(/^ *[0-9a-f]+:[ \t]*/, "")
            if ($1 ~ aes || $1 ~ clmul) print label, $1
        }'
}

# Counts the lines of $1 whose mnemonic matches the pattern $2.
count() {
    awk -v pattern="$2" '$2 ~ pattern { n++ } END { print n + 0 }' <<< "$1"
}

lib_cflags=$(make -s --no-print-directory print-lib-cflags) || exit 1
# Each object's make variables. The first two carry SUITE=aesgcm, which
# ct.h refuses on AES=runtime without the CH_NATIVE_AES statement their
# check legs make.
objects=(
    "ROLE=server TRUST=none SUITE=aesgcm AES=runtime"
    "TRANSPORT=quic-nonblocking ROLE=both TRUST=webpki SUITE=aesgcm AES=runtime KEYLOG=on EXPORTER=off"
    "TRANSPORT=quic-nonblocking EXPORTER=off AES=runtime"
)
rc=0
for object in "${objects[@]}"; do
    read -r -a vars <<< "RAND=extern $object"
    case " $object " in
    *" SUITE=aesgcm "*) vars+=("CFLAGS=$lib_cflags -DCH_NATIVE_AES") ;;
    esac
    lines=$(make -s --no-print-directory "${vars[@]}" lib-pair-object) ||
        { echo "aes-runtime-disasm: [$object]: the build failed" >&2; exit 1; }
    obj=$(tail -n 3 <<< "$lines" | sed -n 1p)
    srcs=$(make -s --no-print-directory "${vars[@]}" print-lib-srcs) || exit 1
    in_files=0
    for src in $srcs; do
        o=${obj%/chapulin.o}/${src%.c}.o
        [ -f "$o" ] || { echo "aes-runtime-disasm: [$object]: $o is missing" >&2; exit 1; }
        found=$(instructions "$o")
        case "$src" in
        aes_hw.c | ghash_hw.c | gcm_hw.c)
            in_files=$((in_files + $(count "$found" "$aes|$clmul")))
            ;;
        *)
            if [ -n "$found" ]; then
                while read -r label mnemonic; do
                    echo "aes-runtime-disasm: [$object]: $src runs $mnemonic in $label" >&2
                done <<< "$found"
                rc=1
            fi
            ;;
        esac
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
    done
    linked=$(count "$(instructions "$obj")" "$aes|$clmul")
    if [ "$linked" -ne "$in_files" ]; then
        echo "aes-runtime-disasm: [$object]: chapulin.o holds $linked of the instructions," \
            "and aes_hw.o, ghash_hw.o and gcm_hw.o hold $in_files" >&2
        rc=1
    fi
    echo "aes-runtime-disasm: [$object]: $linked instructions, $in_files of them in aes_hw.c, ghash_hw.c and gcm_hw.c"
done
[ "$rc" -ne 0 ] ||
    echo "aes-runtime-disasm: on $machine, no AES or carry-less multiply instruction outside aes_hw.c, ghash_hw.c and gcm_hw.c"
exit "$rc"
