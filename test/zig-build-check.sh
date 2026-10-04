#!/usr/bin/env bash
# Builds the packaged object both ways, with make and with build.zig, and
# requires the two to agree (docs/decisions.md 69). make lint-zig-build
# runs it in check with no argument, over the default object, the four
# colibri links, stompy's, a SUITE=aesgcm record-mode object and colibri's
# QUIC object holding both widening multiplies. check-slow
# runs it with --roster, which adds the configuration of every lib-check
# leg in check.
#
# The Zig build runs in bin/zig/consumer/package, a copy of exactly the
# files build.zig.zon's .paths names, because that is what a dependent
# receives.
# Before the copy, .paths must name every root C source and header git
# tracks, the Zig API's files, every tools/localize_*.zig file, and
# nothing else but the build files, the license and the README.
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
# Then the module the package exports must describe the object it builds
# and carry it (docs/decisions.md 70 and 73). test/zig-consumer, copied to
# bin/zig/consumer around the package, is a Zig project that depends on
# the package as colibri does. For each configuration the script builds
# and runs these programs against the module "chapulin", which carries
# the object:
#
#   - matches.zig, which requires chapulin.c to declare every name the
#     object exports, every function it declares under a ch_ name to be
#     one the object exports or imports, which nm -u lists, and the build
#     record to equal what chapulin.c's translated types compute. The
#     second is what keeps a public header from declaring a call the
#     object lacks, which a program would compile and fail to link.
#     Before it, tools/public-constants.py lists the lengths and caps the
#     public headers' comments name in regions the object compiles, and
#     fails when one is not defined for the consumer; matches.zig then
#     requires chapulin.c to declare and evaluate each one.
#   - unit.zig, the API's unit tests: each value's toCfg field by field,
#     the Ticket constructors, the error of every ch_err code, and every
#     declaration the object has, compiled.
#   - for a ROLE=both object, loop.zig, which runs a client and a server of
#     the object against each other through the API, over the r2 chain of
#     test/webpki_corpus.h, which the script copies beside it. Under
#     SUITE=aesgcm its record-mode loop also has each side write across
#     its AES-GCM write key's ceiling (loop_key_limit.zig).
#
# matches.zig reads only the headers chapulin.c is translated from, and
# build.zig translates x509_ca.h and drbg.h only for an object that
# exports their call. A C program of any other object can still include
# either one, so where chapulin.c leaves one out, the script translates
# it under the same defines with zig translate-c and holds the result to
# matches.zig's second rule.
#
# Zig keys its cache on the paths of a compile as written. The consumer
# names the package's directory with no "..", so the dependency compiles
# under the paths the package build above used and takes its object from
# the cache.
#
# Last, one image links colibri's two Zig objects of different
# transports, the tcp-nonblocking ROLE=both object and the QUIC one, and
# runs each half, as test/lib-pair-check.sh does with make's objects
# (docs/decisions.md 61). It does so twice: from C halves compiled under
# make's defines, and as test/zig-consumer's pair.zig, which imports the
# module of each object and starts a client through each one's API.
#
# Each configuration builds both objects and compares them in a process
# of its own, as many at once as the machine has cores. With every object
# and program built, the seven took 5.1 to 5.3 s on an M-series Mac, and
# the eight took 4.5 to 5.4 s at a load average of 11 to 13. The eight
# left once docs/decisions.md 89 merged the AES rows took 5.4 s at a load
# average of 8, and the seven left once it removed the CHACHA row took 5.0
# to 5.1 s at a load average of 28 to 30.
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
consumer=$out/consumer
package=$consumer/package
mk() { make -s --no-print-directory CC="$cc" "$@"; }

# Zig compiles for the macOS version it runs on, and cc links for the
# SDK's; linking for the first keeps ld from warning about each object.
link_flags=()
[ "$(uname)" != Darwin ] || link_flags=("-mmacosx-version-min=$(sw_vers -productVersion)")

# Each configuration: a name, the make variables, and the hardware
# statements it makes, which make takes in CFLAGS and build.zig as options.
# The first is the default object; the next four are the ones colibri
# links: its HTTP/2 client and server objects, and its QUIC object under
# the two trust modes its checks and its interop runner use. Then comes
# stompy's, colibri's TCP object at TX_RECORD=16384 (docs/decisions.md 71
# and 73). Then comes a record-mode ROLE=both object under SUITE=aesgcm,
# whose loop writes across each AES-GCM write key's ceiling
# (docs/decisions.md 78). It and the QUIC rows are host objects on the
# M-series Macs and CI's x86_64 runner, which hold the AES instructions,
# and their loops state CH_CPU_CONSTANT_TIME_AES and
# CH_CPU_CONSTANT_TIME_MULTIPLY (fixture.zig's cpuAnswer,
# docs/decisions.md 89), so they run the AES instructions and the native
# copies of the files built on the multiply, the vector Poly1305 among
# them, and every session of theirs runs the vector ChaCha20. AES=extern
# would need a ch_aes_block that encrypts, and hooks.zig's stops the
# program.
configs=(
    "default|RAND=extern|"
    "h2|RAND=extern TRANSPORT=tcp-nonblocking ROLE=both TRUST=webpki EXPORTER=on|"
    "h2-server|RAND=extern TRANSPORT=tcp-nonblocking ROLE=server TRUST=none EXPORTER=on|"
    "quic|RAND=extern TRANSPORT=quic-nonblocking ROLE=both TRUST=webpki SUITE=aesgcm KEYLOG=on|"
    "quic-interop|RAND=extern TRANSPORT=quic-nonblocking ROLE=both TRUST=raw-ecdsa SUITE=aesgcm KEYLOG=on|"
    "tx-record|RAND=extern TRUST=webpki TRANSPORT=tcp-nonblocking ROLE=both TX_RECORD=16384|"
    "record-aes|RAND=extern TRANSPORT=tcp-nonblocking ROLE=both TRUST=webpki SUITE=aesgcm|"
)
# The configuration of every other lib-check leg in check, in its order,
# so every value of every axis meets build.zig at least once. The server
# on AES=extern is a device object, which a host compiler builds when
# HOST_TARGET, the host test's result, is set empty, in make and in
# build.zig alike (docs/decisions.md 89).
roster=(
    "drbg|RAND=drbg|"
    "session|RAND=session TRUST=webpki TRANSPORT=tcp-nonblocking ROLE=both|"
    "ca-rsa|RAND=extern TRUST=ca-rsa|"
    "ca-ecdsa|RAND=extern TRUST=ca-ecdsa|"
    "webpki|RAND=extern TRUST=webpki|"
    "webpki-tcp-nonblocking|RAND=extern TRUST=webpki TRANSPORT=tcp-nonblocking|"
    "quic-raw|RAND=extern TRANSPORT=quic-nonblocking EXPORTER=off|"
    "quic-webpki-both|RAND=extern TRUST=webpki TRANSPORT=quic-nonblocking ROLE=both KEYLOG=on EXPORTER=off|"
    "server|RAND=extern ROLE=server TRUST=none|"
    "server-tcp-nonblocking|RAND=extern ROLE=server TRUST=none TRANSPORT=tcp-nonblocking|"
    "raw-ecdsa-pq|RAND=extern TRUST=raw-ecdsa KEX=pq|"
    "exporter|RAND=extern EXPORTER=on|"
    "server-quic-keylog|RAND=extern ROLE=server TRUST=none TRANSPORT=quic-nonblocking EXPORTER=off KEYLOG=on|"
    "server-aes|RAND=extern ROLE=server TRUST=none SUITE=aesgcm|"
    "server-aes-extern|RAND=extern ROLE=server TRUST=none SUITE=aesgcm AES=extern HOST_TARGET=|CH_AES_EXTERN_CONSTANT_TIME"
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

# The ch_ names an object imports, sorted: the hooks the image defines.
# nm -u prints the name alone on Mach-O and after a U on ELF.
imports() {
    nm -u "$1" | awk '{print $NF}' | sed 's/^_//' | grep '^ch_' | sort -u
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
        git ls-files '*.c' '*.h' '*.hpp' 'chapulin*.zig' | grep -v /
        git ls-files 'tools/localize_*.zig'
        printf '%s\n' build.zig build.zig.zon LICENSE README.md
    } | sort)
    if [ "$listed" != "$want" ]; then
        diff <(printf '%s\n' "$want") <(printf '%s\n' "$listed") >&2
        fail "build.zig.zon's .paths differ from the files a dependent needs (< wanted, > listed)"
    fi
    rm -rf "$consumer"
    mkdir -p "$package"
    # shellcheck disable=SC2086 # one path per word, as .paths lists them
    tar -cf - $listed | tar -xf - -C "$package" || fail "copying the package failed"
    cp test/zig-consumer/* test/webpki_corpus.h "$consumer/" || fail "copying test/zig-consumer failed"
}

# The options of one configuration as test/zig-consumer takes them: the
# make variables, then each hardware statement as NAME=true.
zig_row() {
    local v row=$1
    for v in $2; do row="$row $v=true"; done
    printf '%s\n' "$row"
}

# consume NAME PREFIX OPTION...
#
# Builds test/zig-consumer with the given options, and installs its
# program under PREFIX.
consume() {
    local name=$1 prefix=$2
    shift 2
    (cd "$consumer" && "$zig" build --summary none --prefix "$root/$prefix" --cache-dir "$root/$out/cache" "$@") \
        > "$prefix/zig-consumer.log" 2>&1 || {
        cat "$prefix/zig-consumer.log" >&2
        fail "$name: test/zig-consumer does not build against the package's module and object"
    }
}

# The hardware statements as defines, the way make's CFLAGS carries them.
statement_defs() {
    local v
    for v in $1; do printf -- '-D%s ' "$v"; done
}

# Whether this compiler can build a configuration: SUITE=aesgcm needs a
# host object or AES=extern, which the Makefile probes for and check's
# legs skip without.
buildable() {
    case " $1 " in
    *" AES=extern "*) true ;;
    *" SUITE=aesgcm "*) [ -n "$host" ] ;;
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
    [ -z "$3" ] || make_cflags=("CFLAGS=$lib_cflags $(statement_defs "$3")")
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

# The public headers whose one call TRUST or RAND decides, so that an
# object of any transport and role can lack it: x509_ca.h declares the
# ca modes' ch_pubkey_from_pem, and drbg.h declares RAND=drbg's
# ch_drbg_seed.
optional_headers=(x509_ca.h drbg.h)

# check_optional_headers NAME ZIG-OBJECT
#
# Translates each of optional_headers that chapulin.c is not translated
# from, under the defines chapulin.c is translated under, and fails when
# the translation declares a ch_ function the object neither exports nor
# imports: the rule matches.zig holds chapulin.c to.
check_optional_headers() {
    local name=$1 provided defines header symbol checked=""
    provided=$({ exports "$2"; imports "$2"; } | sort -u)
    read -r -a defines <<< "$(tr '\n' ' ' < "$out/$name/lib-def.txt")"
    for header in "${optional_headers[@]}"; do
        ! grep -qxF "$header" "$out/$name/lib-headers.txt" || continue
        "$zig" translate-c -lc --cache-dir "$root/$out/cache" -I. "${defines[@]}" "$header" \
            > "$out/$name/$header.zig" 2> "$out/$name/$header.err" || {
            cat "$out/$name/$header.err" >&2
            fail "$name: zig translate-c $header failed"
        }
        while read -r symbol; do
            grep -qxF "$symbol" <<< "$provided" ||
                fail "$name: $header declares $symbol, which the object neither exports nor imports"
        done < <(sed -n 's/^pub extern fn \(ch_[A-Za-z0-9_]*\)(.*/\1/p' "$out/$name/$header.zig")
        checked="$checked $header"
    done
    [ -z "$checked" ] ||
        echo "lint-zig-build: $name: the public headers chapulin.c is not translated from declare no ch_ call the object lacks:$checked"
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

    # The lengths and caps the public headers name, each of which the
    # consumer must be able to name too.
    python3 tools/public-constants.py "$cc" "$out/$name/lib-headers.txt" "$out/$name/lib-def.txt" \
        > "$out/$name/constants.txt" ||
        fail "$name: a public header names a constant this object's consumer cannot see"

    local symbol declared=()
    for symbol in $(exports "$zig_obj"); do declared+=("-Dexport=$symbol"); done
    for symbol in $(imports "$zig_obj"); do declared+=("-Dimport=$symbol"); done
    while read -r symbol; do declared+=("-Dconstant=$symbol"); done < "$out/$name/constants.txt"
    zig_row "$2" "$3" > "$out/$name/zig-row.txt"
    # A ROLE=both object has a client and a server to run against each
    # other.
    local both=0
    case " $2 " in
    *" ROLE=both "*) both=1 declared+=("-Dloop") ;;
    esac
    consume "$name" "$out/$name" "-Dobject=$(cat "$out/$name/zig-row.txt")" "${declared[@]}"
    "$out/$name/bin/matches" ||
        fail "$name: the Zig object's build record disagrees with chapulin.c's types"
    echo "lint-zig-build: $name: chapulin.c declares the object's exports, no ch_ call the object lacks, and the $(wc -l < "$out/$name/constants.txt" | tr -d ' ') lengths its headers name, and has the types its build record describes"
    check_optional_headers "$name" "$zig_obj"
    "$out/$name/bin/unit" > "$out/$name/unit.log" 2>&1 || {
        cat "$out/$name/unit.log" >&2
        fail "$name: the API's unit tests failed"
    }
    echo "lint-zig-build: $name: the API's unit tests passed: $(tail -n 1 "$out/$name/unit.log")"
    [ "$both" -eq 1 ] || return 0
    "$out/$name/bin/loop" > "$out/$name/loop.log" 2>&1 || {
        cat "$out/$name/loop.log" >&2
        fail "$name: a client and a server of the object did not run against each other through the API"
    }
    echo "lint-zig-build: $name: $(tail -n 1 "$out/$name/loop.log")"
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

# Links the h2 and quic Zig objects into one image with a C half for each,
# and runs it. Then builds test/zig-consumer's pair.zig against the same
# two configurations, and runs it.
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

    mkdir -p "$out/zig-pair"
    consume "zig pair" "$out/zig-pair" "-Dh2=$(cat "$out/h2/zig-row.txt")" "-Dquic=$(cat "$out/quic/zig-row.txt")"
    "$out/zig-pair/bin/pair" || fail "zig pair: the program exited $?"
    echo "lint-zig-build: one Zig program imports the modules of colibri's tcp-nonblocking ROLE=both and QUIC objects, links both objects, and each half ran"
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
host=$(mk print-host-target)
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
