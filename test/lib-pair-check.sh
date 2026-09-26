#!/usr/bin/env bash
# Links two packaged objects of different transports into one image, for
# each pair docs/decisions.md 61 names, and runs the image or requires
# the link to fail.
#
# A pair the decision supports must export no name in common, link, and
# run: test/lib_pair_main.c calls the half of each transport, which reads
# that object's build record and starts one session (test/lib_pair_half.c).
# A pair the decision refuses must export exactly the names it lists in
# common, and the link must fail naming each of them: the linker's
# duplicate-symbol error is the refusal.
#
# test/violations.py runs a script by path and reads its exit status.
# With no arguments this runs every pair; each argument names one pair to
# run instead.
#
# Each object is built by the build variables of a lib-check leg in make
# check where one exists, so check builds two objects for this script
# alone: the QUIC object of the ca pair and of the drbg pair.
cd "$(dirname "$0")/.." || exit 1
export LC_ALL=C
cc=${CC:-cc}
out=bin/lib-pair
mkdir -p "$out"

# The names an object exports, sorted, one per line, by lib-check's rule:
# T for code, D, B and R for data, and S for Mach-O's other sections.
exports() {
    nm -g "$1" | awk '$2 ~ /^[TDSBR]$/ {print $3}' | sed 's/^_//' | sort
}

# Builds the object the build variables name, and sets obj, defs and
# flags from the three lines make prints for it.
load() {
    local lines
    lines=$(make -s --no-print-directory lib-pair-object "$@") || return 1
    obj=$(printf '%s\n' "$lines" | tail -n 3 | sed -n 1p)
    defs=$(printf '%s\n' "$lines" | tail -n 3 | sed -n 2p)
    flags=$(printf '%s\n' "$lines" | tail -n 3 | sed -n 3p)
}

# The transport an object's defines name, as lib_pair.h spells it.
transport_of() {
    case " $1 " in
    *" -DCH_TRANSPORT_QUIC_NONBLOCKING "*) echo quic_nonblocking ;;
    *" -DCH_TRANSPORT_TCP_NONBLOCKING "*) echo tcp_nonblocking ;;
    *) echo tcp_blocking ;;
    esac
}

# Compiles test/lib_pair_half.c under the defines and flags load set,
# into the object's own directory, and sets half to the result.
compile_half() {
    local def_words flag_words
    read -r -a def_words <<< "$defs"
    read -r -a flag_words <<< "$flags"
    half=${obj%/chapulin.o}/lib_pair_half.o
    "$cc" "${flag_words[@]}" "${def_words[@]}" -I. -Itest -c test/lib_pair_half.c -o "$half"
}

# pair NAME SHARED A-VARIABLES B-VARIABLES
#
# SHARED is the names both objects export, sorted and space-separated:
# empty for a pair the image supports.
pair() {
    local name=$1 shared=$2 a_vars b_vars
    read -r -a a_vars <<< "$3"
    read -r -a b_vars <<< "$4"

    load "${a_vars[@]}" || { echo "lib-pair: $name: building [$3] failed" >&2; return 1; }
    compile_half || return 1
    local a_obj=$obj a_defs=$defs a_half=$half
    load "${b_vars[@]}" || { echo "lib-pair: $name: building [$4] failed" >&2; return 1; }
    compile_half || return 1
    local b_obj=$obj b_defs=$defs b_half=$half

    local common
    common=$(comm -12 <(exports "$a_obj") <(exports "$b_obj") | tr '\n' ' ' | sed 's/ $//')
    if [ "$common" != "$shared" ]; then
        echo "lib-pair: $name: the two objects both export [$common], and this pair expects [$shared]" >&2
        return 1
    fi

    local main_defs flag_words
    main_defs=("-DLIB_PAIR_$(transport_of "$a_defs" | tr '[:lower:]' '[:upper:]')"
        "-DLIB_PAIR_$(transport_of "$b_defs" | tr '[:lower:]' '[:upper:]')")
    case " $a_defs $b_defs " in
    *" -DCH_KEYLOG "*) main_defs+=(-DLIB_PAIR_KEYLOG) ;;
    esac
    read -r -a flag_words <<< "$flags"
    "$cc" "${flag_words[@]}" "${main_defs[@]}" -I. -Itest -c test/lib_pair_main.c \
        -o "$out/$name-main.o" || return 1

    local image=$out/$name
    if "$cc" -o "$image" "$out/$name-main.o" "$a_half" "$b_half" "$a_obj" "$b_obj" \
        2> "$image.link"; then
        if [ -n "$shared" ]; then
            echo "lib-pair: $name: the image linked, and two objects that both export [$shared] must not" >&2
            return 1
        fi
        "./$image" || { echo "lib-pair: $name: the image exited $?" >&2; return 1; }
        echo "lib-pair: $name: one image links both objects, and each half ran"
        return 0
    fi
    if [ -z "$shared" ]; then
        cat "$image.link" >&2
        echo "lib-pair: $name: the image failed to link" >&2
        return 1
    fi
    local s
    for s in $shared; do
        if ! grep -Eq "(^|[^A-Za-z0-9_])_?$s([^A-Za-z0-9_]|\$)" "$image.link"; then
            cat "$image.link" >&2
            echo "lib-pair: $name: the link failed without naming $s" >&2
            return 1
        fi
    done
    echo "lib-pair: $name: the link refuses the image, naming [$shared]"
}

# Each pair's name, the names its two objects share, and each object's
# build variables.
run() {
    case $1 in
    webpki)
        # cocuyo's image: a DNS-over-TLS client and colibri's QUIC object.
        pair webpki "" "RAND=extern TRUST=webpki TRANSPORT=tcp-nonblocking" \
            "RAND=extern TRUST=webpki TRANSPORT=quic-nonblocking ROLE=both KEYLOG=on EXPORTER=off"
        ;;
    server)
        # An HTTP/2 server beside an HTTP/3 one.
        pair server "" "RAND=extern ROLE=server TRUST=none TRANSPORT=tcp-nonblocking" \
            "RAND=extern ROLE=server TRUST=none TRANSPORT=quic-nonblocking EXPORTER=off KEYLOG=on"
        ;;
    raw)
        pair raw "" "RAND=extern" "RAND=extern TRANSPORT=quic-nonblocking EXPORTER=off"
        ;;
    ca)
        pair ca "" "RAND=extern TRUST=ca-rsa" "RAND=extern TRUST=ca-rsa TRANSPORT=quic-nonblocking EXPORTER=off"
        ;;
    drbg)
        # Two generators, each seeded on its own: refused.
        pair drbg "ch_drbg_seed ch_rand_bytes" "RAND=drbg" "RAND=drbg TRANSPORT=quic-nonblocking EXPORTER=off"
        ;;
    tcp-both)
        # Both TCP transports carry the connected session's calls: refused.
        pair tcp-both "ch_close ch_read ch_write" "RAND=extern" \
            "RAND=extern TRUST=webpki TRANSPORT=tcp-nonblocking"
        ;;
    *)
        echo "lib-pair: no pair is named $1" >&2
        return 1
        ;;
    esac
}

names=("$@")
[ ${#names[@]} -gt 0 ] || names=(webpki server raw ca drbg tcp-both)
rc=0
for name in "${names[@]}"; do
    run "$name" || rc=1
done
exit "$rc"
