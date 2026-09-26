#!/usr/bin/env bash
# Builds the packaged object both ways, with make and with build.zig, and
# requires the two to agree (docs/decisions.md 69). make lint-zig-build
# runs it in check with no argument, over the default object and the four
# colibri links. check-slow runs it with --roster, which adds the
# configuration of every lib-check leg in check.
#
# The Zig build runs in bin/zig/package, a copy of exactly the files
# build.zig.zon's .paths names, because that is what a dependent receives.
# Before the copy, .paths must name every root C source and header git
# tracks, every tools/localize_*.zig file, and nothing else but the build
# files, the license and the README.
#
# For each configuration, the two objects must have:
#
#   - the same sources: make print-lib-srcs against lib-srcs.txt;
#   - the same defines: make print-lib-def, with the hardware statements the
#     configuration makes, against lib-def.txt;
#   - the same exports: the names nm -g lists as defined, by lib-check's
#     rule;
#   - the same build record: test/build_test.c, compiled under make's
#     defines and linked against the Zig object, must read the record its
#     headers compute, as lib-check requires of make's object.
#
# Then one image links colibri's two Zig objects of different transports,
# the tcp-nonblocking ROLE=both object and the QUIC one, and runs each
# half, as test/lib-pair-check.sh does with make's objects
# (docs/decisions.md 61).
#
# Each configuration builds both objects and compares them in a process
# of its own, as many at once as the machine has cores. With every object
# built, the five take 3 s on an M-series Mac.
#
# test/violations.py runs a script by path and reads its exit status.
cd "$(dirname "$0")/.." || exit 1
export LC_ALL=C
# Each row below names what it builds. A recursion that inherited the
# variables of a `make check TRUST=webpki` would build something else.
unset MAKEFLAGS MFLAGS MAKELEVEL
root=$(pwd)
zig=${ZIG:-zig}
cc=${CC:-cc}
out=bin/zig
package=$out/package
mk() { make -s --no-print-directory CC="$cc" "$@"; }

# Zig compiles for the macOS version it runs on, and cc links for the
# SDK's; linking for the first keeps ld from warning about each object.
link_flags=()
[ "$(uname)" != Darwin ] || link_flags=("-mmacosx-version-min=$(sw_vers -productVersion)")

# Each configuration: a name, the make variables, and the hardware
# statements it makes, which make takes in CFLAGS and build.zig as options.
# The first is the default object; the other four are the ones colibri
# links: its HTTP/2 client and server objects, and its QUIC object under
# the two trust modes its checks and its interop runner use.
configs=(
    "default|RAND=extern|"
    "h2|RAND=extern TRANSPORT=tcp-nonblocking ROLE=both TRUST=webpki EXPORTER=on|"
    "h2-server|RAND=extern TRANSPORT=tcp-nonblocking ROLE=server TRUST=none EXPORTER=on|"
    "quic|RAND=extern TRANSPORT=quic-nonblocking ROLE=both TRUST=webpki SUITE=aesgcm AES=hw KEYLOG=on|CH_NATIVE_AES"
    "quic-interop|RAND=extern TRANSPORT=quic-nonblocking ROLE=both TRUST=raw-ecdsa SUITE=aesgcm AES=hw KEYLOG=on|CH_NATIVE_AES"
)
# The configuration of every other lib-check leg in check, in its order,
# so every value of every axis meets build.zig at least once.
roster=(
    "drbg|RAND=drbg|"
    "ca-rsa|RAND=extern TRUST=ca-rsa|"
    "ca-ecdsa|RAND=extern TRUST=ca-ecdsa|"
    "webpki|RAND=extern TRUST=webpki|"
    "webpki-tcp-nonblocking|RAND=extern TRUST=webpki TRANSPORT=tcp-nonblocking|"
    "webpki-widemul|RAND=extern TRUST=webpki TRANSPORT=tcp-nonblocking WIDEMUL=native|"
    "quic-raw|RAND=extern TRANSPORT=quic-nonblocking EXPORTER=off|"
    "quic-webpki-both|RAND=extern TRUST=webpki TRANSPORT=quic-nonblocking ROLE=both KEYLOG=on EXPORTER=off|"
    "server|RAND=extern ROLE=server TRUST=none|"
    "server-tcp-nonblocking|RAND=extern ROLE=server TRUST=none TRANSPORT=tcp-nonblocking|"
    "raw-ecdsa-pq|RAND=extern TRUST=raw-ecdsa KEX=pq|"
    "exporter|RAND=extern EXPORTER=on|"
    "server-quic-keylog|RAND=extern ROLE=server TRUST=none TRANSPORT=quic-nonblocking EXPORTER=off KEYLOG=on|"
    "server-aes-hw|RAND=extern ROLE=server TRUST=none SUITE=aesgcm AES=hw|CH_NATIVE_AES"
    "server-aes-extern|RAND=extern ROLE=server TRUST=none SUITE=aesgcm AES=extern|CH_AES_EXTERN_CONSTANT_TIME"
    "x25519-wide|RAND=extern X25519=wide|CH_NATIVE_MUL128"
)
case ${1:-} in
"") ;;
--roster) configs+=("${roster[@]}") ;;
*)
    echo "usage: $0 [--roster]" >&2
    exit 2
    ;;
esac

fail() {
    echo "lint-zig-build: $*" >&2
    exit 1
}

# The names an object exports, sorted, by lib-check's rule.
exports() {
    nm -g "$1" | awk '$2 ~ /^[TDSBR]$/ {print $3}' | sed 's/^_//' | sort
}

# Words, one per line, sorted.
sorted() {
    tr ' ' '\n' | sed '/^$/d' | sort
}

same() {
    [ "$2" = "$3" ] && return 0
    diff <(printf '%s\n' "$2") <(printf '%s\n' "$3") >&2
    fail "$1 (< make, > zig)"
}

stage_package() {
    local listed want
    listed=$(sed -n '/\.paths = \.{/,/}/p' build.zig.zon | grep -o '"[^"]*"' | tr -d '"' | sort)
    want=$({
        git ls-files '*.c' '*.h' '*.hpp' | grep -v /
        git ls-files 'tools/localize_*.zig'
        printf '%s\n' build.zig build.zig.zon LICENSE README.md
    } | sort)
    if [ "$listed" != "$want" ]; then
        diff <(printf '%s\n' "$want") <(printf '%s\n' "$listed") >&2
        fail "build.zig.zon's .paths differ from the files a dependent needs (< wanted, > listed)"
    fi
    rm -rf "$package"
    mkdir -p "$package"
    # shellcheck disable=SC2086 # one path per word, as .paths lists them
    tar -cf - $listed | tar -xf - -C "$package" || fail "copying the package failed"
}

# The hardware statements as defines, the way make's CFLAGS carries them.
statement_defs() {
    local v
    for v in $1; do printf -- '-D%s ' "$v"; done
}

# Whether this compiler can build a configuration: AES=hw needs the AES
# instructions and X25519=wide needs unsigned __int128, which the Makefile
# probes for and check's legs skip without.
buildable() {
    case " $1 " in
    *" AES=hw "*) [ -n "$probe" ] ;;
    *" X25519=wide "*) printf 'unsigned __int128 x;\n' | "$cc" -x c -fsyntax-only - 2> /dev/null ;;
    *) true ;;
    esac
}

# build_make NAME MAKE-VARIABLES STATEMENTS
#
# Builds make's object for one configuration, and writes the three lines
# make lib-pair-object prints for it, its path, its defines and its flags,
# to bin/zig/NAME/make-object.txt.
build_make() {
    local name=$1 vars make_cflags=() lines
    read -r -a vars <<< "$2"
    case " $2 " in
    *" AES=hw "*) make_cflags=("CFLAGS=$lib_cflags $(statement_defs "$3") ${probe/none/}") ;;
    *) [ -z "$3" ] || make_cflags=("CFLAGS=$lib_cflags $(statement_defs "$3")") ;;
    esac
    lines=$(mk -j2 lib-pair-object "${vars[@]}" "${make_cflags[@]}") || fail "$name: make lib-pair-object failed"
    printf '%s\n' "$lines" | tail -n 3 > "$out/$name/make-object.txt"
}

# build_zig NAME MAKE-VARIABLES STATEMENTS
#
# Builds the Zig object of one configuration from the staged package, with
# each make variable and each statement as a -D option.
build_zig() {
    local name=$1 vars statements options=() v
    read -r -a vars <<< "$2"
    read -r -a statements <<< "$3"
    for v in "${vars[@]}"; do options+=("-D$v"); done
    for v in "${statements[@]}"; do options+=("-D$v=true"); done
    (cd "$package" && "$zig" build install lib-lists --summary none --prefix "$root/$out/$name" \
        --cache-dir "$root/$out/cache" "${options[@]}") > "$out/$name/zig-build.log" 2>&1 || {
        cat "$out/$name/zig-build.log" >&2
        fail "$name: zig build ${options[*]} failed"
    }
}

# check NAME MAKE-VARIABLES STATEMENTS
#
# Builds both objects of one configuration and compares them.
check() {
    local name=$1 vars
    read -r -a vars <<< "$2"
    mkdir -p "$out/$name"
    build_make "$@"
    build_zig "$@"
    local make_obj make_defs make_flags zig_obj=$out/$name/lib/chapulin.o
    make_obj=$(sed -n 1p "$out/$name/make-object.txt")
    make_defs=$(sed -n 2p "$out/$name/make-object.txt")
    make_flags=$(sed -n 3p "$out/$name/make-object.txt")

    same "$name: build.zig compiles other sources than make" \
        "$(mk print-lib-srcs "${vars[@]}" | sorted)" "$(sorted < "$out/$name/lib-srcs.txt")"
    same "$name: build.zig passes other defines than make" \
        "$(printf '%s ' "$make_defs" "$(statement_defs "$3")" | sorted)" "$(sorted < "$out/$name/lib-def.txt")"
    same "$name: the Zig object exports other names than make's" "$(exports "$make_obj")" "$(exports "$zig_obj")"

    local def_words flag_words
    read -r -a def_words <<< "$make_defs"
    read -r -a flag_words <<< "$make_flags"
    "$cc" "${flag_words[@]}" "${def_words[@]}" "${link_flags[@]}" -I. -o "$out/$name/build_test" \
        test/build_test.c "$zig_obj" || fail "$name: test/build_test.c does not link against the Zig object"
    "$out/$name/build_test" > /dev/null ||
        fail "$name: the Zig object's build record disagrees with the headers compiled under make's defines"
    echo "lint-zig-build: $name: the same sources, defines, $(exports "$zig_obj" | wc -l | tr -d ' ') exports and build record as make's object"
}

# Compiles test/lib_pair_half.c under the defines and flags of one
# configuration's make object, the way a program compiles its calls to
# that object.
compile_half() {
    local name=$1 def_words flag_words
    read -r -a def_words <<< "$(sed -n 2p "$out/$name/make-object.txt")"
    read -r -a flag_words <<< "$(sed -n 3p "$out/$name/make-object.txt")"
    "$cc" "${flag_words[@]}" "${def_words[@]}" -I. -Itest -c test/lib_pair_half.c -o "$out/pair-$name.o" ||
        fail "pair: compiling the $name half failed"
}

# Links the h2 and quic Zig objects into one image with a half for each,
# and runs it.
pair() {
    local image=$out/pair flag_words
    compile_half h2
    compile_half quic
    read -r -a flag_words <<< "$(sed -n 3p "$out/h2/make-object.txt")"
    "$cc" "${flag_words[@]}" -DLIB_PAIR_TCP_NONBLOCKING -DLIB_PAIR_QUIC_NONBLOCKING -DLIB_PAIR_KEYLOG \
        -I. -Itest -c test/lib_pair_main.c -o "$out/pair-main.o" || fail "pair: compiling the main failed"
    "$cc" "${link_flags[@]}" -o "$image" "$out/pair-main.o" "$out/pair-h2.o" "$out/pair-quic.o" \
        "$out/h2/lib/chapulin.o" "$out/quic/lib/chapulin.o" ||
        fail "pair: one image does not link the tcp-nonblocking ROLE=both object beside the QUIC one"
    "./$image" || fail "pair: the image exited $?"
    echo "lint-zig-build: one image links colibri's tcp-nonblocking ROLE=both and QUIC objects, and each half ran"
}

# Waits for every check started so far, prints each one's output in the
# order it started, and clears the lists. Returns 1 when any check failed.
collect() {
    local i status=0
    for i in "${!names[@]}"; do
        wait "${pids[$i]}" || status=1
        cat "$out/${names[$i]}.out"
    done
    names=()
    pids=()
    return "$status"
}

command -v "$zig" > /dev/null || fail "$zig is missing; the pin is ZIG_VERSION in tools/toolchain.env"
mkdir -p "$out"
stage_package
probe=$(mk print-aes-hw-probe)
lib_cflags=$(mk print-lib-cflags)
jobs=$(getconf _NPROCESSORS_ONLN 2> /dev/null || echo 4)
names=()
pids=()
rc=0
skipped=""
for row in "${configs[@]}"; do
    IFS='|' read -r name vars statements <<< "$row"
    if ! buildable "$vars"; then
        echo "SKIP lint-zig-build $name: $cc cannot build [$vars]"
        skipped="$skipped $name"
        continue
    fi
    check "$name" "$vars" "$statements" > "$out/$name.out" 2>&1 &
    names+=("$name")
    pids+=("$!")
    [ ${#pids[@]} -lt "$jobs" ] || collect || rc=1
done
collect || rc=1
[ "$rc" -eq 0 ] || exit 1
case " $skipped " in
*" quic "*) echo "SKIP lint-zig-build pair: $cc cannot build the QUIC object" ;;
*) pair ;;
esac
