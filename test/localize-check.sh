#!/usr/bin/env bash
# Tests tools/localize_symbols.zig, the tool build.zig runs to make every
# symbol of the packaged object local except the public API
# (docs/decisions.md 69). make lint-zig-build runs it.
#
# For each target below, zig partially links test/localize/first.c and
# test/localize/second.c into one relocatable object, as build.zig does
# with the library's sources, and the tool keeps first_public and
# second_public global. Then:
#
#   1. llvm-objcopy -G, and on macOS nmedit -s for Mach-O, localize the
#      same object, and the three results must list the same symbols, with
#      the same binding, type, value and section, and the same relocations
#      against the same symbols. Neither reference orders the symbol table
#      the same way, so the lists are sorted before they are compared. GNU
#      objcopy is no reference here: it renumbers the sections it writes
#      and clears a localized symbol's visibility, so its lines differ
#      where its object does not.
#   2. The result links: zig links test/localize/entry.c against it with
#      no libc, which resolves every relocation against the rewritten
#      table, and a program that calls a localized function fails to link.
#   3. For the host's own target, compiled -fPIC, cc links
#      test/localize/main.c against the result, and the program runs and
#      checks what the kept functions compute.
#   4. The tool refuses a name the object does not define, and a
#      position-independent MIPS object, and writes no output for either.
#
# The targets cover each format the tool reads: ELF64 in both byte orders,
# ELF32 in both, big-endian mips32r2 among them, which is the reference
# target, and 64-bit Mach-O for both Apple architectures.
cd "$(dirname "$0")/.." || exit 1
export LC_ALL=C
zig=${ZIG:-zig}
cc=${CC:-cc}
llvm_nm=${LLVM_NM:-$(make -s --no-print-directory print-llvm-nm)}
# The LLVM tools beside llvm-nm, spelled the way it is: a versioned name
# on CI, a Homebrew keg's path on a development Mac.
llvm_objcopy=${llvm_nm/llvm-nm/llvm-objcopy}
llvm_objdump=${llvm_nm/llvm-nm/llvm-objdump}
llvm_readelf=${llvm_nm/llvm-nm/llvm-readelf}
out=bin/zig/localize
tool=$out/bin/localize_symbols
# zig writes its cache under the directory it runs in unless told where.
# Builds run from the repository root keep a cache apart from the one
# test/zig-build-check.sh fills from bin/zig/consumer/package: with one cache for
# both, Zig 0.16 took a manifest recorded against the package's copy of
# tools/localize_elf.zig as current for the root's edited file, and ran the
# unedited localizer.
ZIG_LOCAL_CACHE_DIR=$(pwd)/bin/zig/root-cache
export ZIG_LOCAL_CACHE_DIR
# zig cc compiles with the undefined-behavior sanitizer by default, and a
# link with no libc has no runtime for it. An ELF image links static with
# its entry at _start; Mach-O has no static image, and writes the C name
# _start as __start.
link_elf=(cc -O2 -fno-sanitize=all -nostdlib -static "-Wl,-e,_start")
link_macho=(cc -O2 -fno-sanitize=all -nostdlib "-Wl,-e,__start")

targets=(
    x86_64-linux-musl aarch64-linux-musl s390x-linux-musl powerpc64-linux-musl
    x86-linux-musl arm-linux-musleabihf riscv32-linux-musl mips-linux-musl powerpc-linux-musl
    aarch64-macos x86_64-macos
)
keep=(first_public second_public)

fail() {
    echo "localize-check: $*" >&2
    exit 1
}

for t in "$zig" "$llvm_nm" "$llvm_objcopy" "$llvm_objdump" "$llvm_readelf"; do
    command -v "$t" > /dev/null || fail "$t is missing"
done

# What the localized objects must agree on: every symbol but the empty one
# with its binding, type, section, value and size (ELF), or its nm line
# (Mach-O), then every relocation with the symbol it names. With a second
# argument a Mach-O object's debugging entries count too: nmedit rewrites
# a localized variable's, and llvm-objcopy leaves them as they were.
describe() {
    case $(head -c 4 "$1" | od -An -tx1 | tr -d ' ') in
    7f454c46)
        "$llvm_readelf" --symbols --wide "$1" | awk '$1 ~ /^[0-9]+:$/ && $8 != "" {$1 = ""; print}' | sort
        ;;
    *) "$llvm_nm" ${2:+-a} "$1" | sort ;;
    esac
    "$llvm_objdump" -r "$1" | grep -v 'file format'
}

# The -G arguments the references take: Mach-O writes a C name with a
# leading underscore.
globals() {
    local prefix=$1 name
    for name in "${keep[@]}"; do printf -- '-G\n%s%s\n' "$prefix" "$name"; done
}

check_target() {
    local target=$1 dir=$out/$1 prefix="" macho=0
    mkdir -p "$dir"
    case $target in *-macos) prefix=_ macho=1 ;; esac
    "$zig" build-obj test/localize/first.c test/localize/second.c -target "$target" -O ReleaseFast \
        -femit-bin="$dir/partial.o" || fail "$target: zig build-obj failed"
    "$tool" "$dir/partial.o" "$dir/tool.o" "${keep[@]}" || fail "$target: the tool refused the object"

    local g=()
    while IFS= read -r line; do g+=("$line"); done < <(globals "$prefix")
    "$llvm_objcopy" "${g[@]}" "$dir/partial.o" "$dir/llvm.o" || fail "$target: llvm-objcopy failed"
    describe "$dir/tool.o" > "$dir/tool.txt"
    describe "$dir/llvm.o" > "$dir/llvm.txt"
    diff "$dir/llvm.txt" "$dir/tool.txt" >&2 || fail "$target: the tool and llvm-objcopy -G disagree (< llvm-objcopy, > tool)"
    local references="llvm-objcopy -G"
    if [ "$macho" = 1 ] && command -v nmedit > /dev/null; then
        printf '_%s\n' "${keep[@]}" > "$dir/keep.txt"
        cp "$dir/partial.o" "$dir/nmedit.o"
        nmedit -s "$dir/keep.txt" "$dir/nmedit.o" || fail "$target: nmedit failed"
        describe "$dir/nmedit.o" debugging > "$dir/nmedit.txt"
        describe "$dir/tool.o" debugging > "$dir/tool-debugging.txt"
        diff "$dir/nmedit.txt" "$dir/tool-debugging.txt" >&2 ||
            fail "$target: the tool and nmedit -s disagree (< nmedit, > tool)"
        references="$references and nmedit -s"
    fi

    local link=("${link_elf[@]}")
    [ "$macho" = 0 ] || link=("${link_macho[@]}")
    "$zig" "${link[@]}" -target "$target" -o "$dir/linked" test/localize/entry.c "$dir/tool.o" ||
        fail "$target: the localized object does not link"
    if "$zig" "${link[@]}" -target "$target" -DLOCALIZE_CALL_LOCAL -o "$dir/linked-local" \
        test/localize/entry.c "$dir/tool.o" 2> "$dir/linked-local.err"; then
        fail "$target: a program that calls first_internal linked, and the tool made it local"
    fi
    grep -q first_internal "$dir/linked-local.err" || {
        cat "$dir/linked-local.err" >&2
        fail "$target: the link of a program that calls first_internal failed without naming it"
    }
    echo "localize-check: $target: the same symbols and relocations as $references, and it links"
}

# Runs a program on the host's own format. The object is compiled -fPIC,
# as build.zig's is for a hosted target, so cc links it into the
# position-independent executable it makes by default.
check_host() {
    local target=$1 dir=$out/host
    mkdir -p "$dir"
    "$zig" build-obj test/localize/first.c test/localize/second.c -target "$target" -O ReleaseFast -fPIC \
        -femit-bin="$dir/partial.o" || fail "host: zig build-obj failed"
    "$tool" "$dir/partial.o" "$dir/tool.o" "${keep[@]}" || fail "host: the tool refused the object"
    "$cc" -o "$dir/main" test/localize/main.c "$dir/tool.o" 2> "$dir/main.err" || {
        cat "$dir/main.err" >&2
        fail "host: cc does not link the localized object"
    }
    "$dir/main" || fail "host: the program linked against the localized object computed the wrong value"
    echo "localize-check: $target: the host runs a program linked against it"
}

# refuse NAME DETAIL COMMAND...: the tool, run by COMMAND, must fail, write
# no output, and name DETAIL in its message.
refuse() {
    local name=$1 detail=$2
    shift 2
    rm -f "$out/refused.o"
    if "$@" 2> "$out/refused.err"; then
        fail "the tool rewrote $name"
    fi
    [ ! -e "$out/refused.o" ] || fail "the tool refused $name and still wrote its output"
    grep -q "$detail" "$out/refused.err" || fail "the tool's refusal of $name does not name $detail"
    echo "localize-check: the tool refuses $name, and writes nothing"
}

mkdir -p "$out"
# zig build caches the program, and zig build-exe compiles it every time.
"$zig" build localize-symbols --summary none --prefix "$out" --cache-dir "$ZIG_LOCAL_CACHE_DIR" ||
    fail "building the tool failed"
pids=()
for target in "${targets[@]}"; do
    check_target "$target" > "$out/$target.out" 2>&1 &
    pids+=("$!")
done
rc=0
for i in "${!targets[@]}"; do
    wait "${pids[$i]}" || rc=1
    cat "$out/${targets[$i]}.out"
done
[ "$rc" -eq 0 ] || exit 1
case $(uname -s)-$(uname -m) in
Darwin-arm64) check_host aarch64-macos ;;
Darwin-x86_64) check_host x86_64-macos ;;
Linux-x86_64) check_host x86_64-linux-gnu ;;
Linux-aarch64) check_host aarch64-linux-gnu ;;
esac
refuse "a name the object does not define" no_such_name \
    "$tool" "$out/mips-linux-musl/partial.o" "$out/refused.o" first_public no_such_name
"$zig" build-obj test/localize/first.c test/localize/second.c -target mips-linux-musl -O ReleaseFast -fPIC \
    -femit-bin="$out/mips-pic.o" || fail "mips-pic: zig build-obj failed"
refuse "position-independent MIPS code" "MIPS GOT relocation" \
    "$tool" "$out/mips-pic.o" "$out/refused.o" "${keep[@]}"
