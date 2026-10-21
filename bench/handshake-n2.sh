#!/usr/bin/env bash
# Counts the instructions the server's side of one TLS connection retires
# on a Neoverse-N2, through chapulin and through OpenSSL, and splits each
# handshake into its stages. It writes bench/results-handshake-n2.csv, and
# docs/performance.md, "Where a server handshake's instructions go",
# carries its figures. https://github.com/c4milo/chapulin/issues/188 asked
# for the count.
#
# The connection is the one h2load makes in colibri's bench: TLS 1.3 with
# TLS_AES_256_GCM_SHA384 over X25519, a P-256 leaf and the P-256 root that
# signed it, ALPN h2 and no ticket. After the handshake the client sends
# one 100-byte record, the server answers with one 256-byte record, and
# each side sends close_notify. bench/handshake_client.c is the client,
# over the runner's OpenSSL 3.0. The count is the server's side of the
# second connection of a run (bench/handshake_window.h).
#
# The servers:
#
#   - chapulin-n2 and chapulin-base: bench/handshake_server.c over the
#     object build.zig makes with colibri's options (COLIBRI below, from
#     colibri's build/modules.zig, chapulin_record_object), for
#     aarch64-linux-gnu, once for -Dcpu=neoverse_n2, as colibri builds
#     for the CPU it runs on, and once for the base armv8-a. Each runs
#     under each ch_cfg.cpu value in VALUES.
#   - openssl-pinned: bench/handshake_openssl_server.c linked statically
#     against the OpenSSL tools/toolchain.env pins, which
#     .github/actions/install-openssl/install.sh builds into
#     OPENSSL_PREFIX.
#   - openssl-system: the same program over the runner's OpenSSL 3.0,
#     the libssl3 package nginx and h2o run on, and openssl-system-static
#     over the static archives of the same release, which the trace can
#     split.
#
# Four tools count, and the tool column of each row names the one that
# counted it:
#
#   - perf_event: the server reads the perf_events counter of its own
#     user-mode instructions at the window's three points, in five runs.
#     A row is the median, and its spread is the largest run less the
#     smallest, as a share of the median.
#   - perf_stat: perf stat -e instructions:u on the whole server process,
#     five runs of two connections less five runs of one, where perf is
#     on PATH or in PERF.
#   - qemu: qemu-aarch64 -cpu neoverse-n2 runs the server one instruction
#     per translation block, and bench/handshake_stages.py splits the
#     trace into stages. A chapulin-n2 build holds SVE instructions,
#     which valgrind cannot run, so qemu is the tool that splits it.
#   - callgrind: valgrind's callgrind collects the second connection
#     alone, and bench/handshake_stages.py prints the inclusive cost of
#     the functions under the two parts of the connection, X25519 and
#     the signature, and the cost of memset itself. valgrind 3.22 runs
#     neither SVE nor the SHA-512 instructions, so it cannot run a
#     chapulin-n2 build or a session whose value holds
#     CH_CPU_CONSTANT_TIME_SHA512, and the CSV then holds no callgrind
#     row for it. Under valgrind OpenSSL finds no SHA-512 instructions,
#     so its rows run SHA-384 in scalar code.
#
# Usage:
#
#   bench/handshake-n2.sh build DIR     builds the two chapulin servers
#       into DIR on any machine with the pinned Zig, for
#       aarch64-linux-gnu. tools/toolchain.env pins Zig's x86-64 Linux
#       release, so an x86-64 runner builds them for the arm64 one.
#   bench/handshake-n2.sh measure DIR   counts on a Neoverse-N2 running
#       Linux, with the servers DIR holds, and writes the CSV. It needs
#       perf_event_paranoid at 2 or less, valgrind, qemu-aarch64, the
#       runner's OpenSSL 3.0 headers and the pinned OpenSSL in
#       OPENSSL_PREFIX (default ~/openssl-inst).
#   bench/handshake-n2.sh --build      builds the chapulin server for this
#       machine and runs nothing. make check runs it through
#       test/script-builds.sh, so a change to a call the program makes
#       fails check. The OpenSSL programs need OpenSSL's headers, which
#       the check image does not hold, so measure builds them.
set -euo pipefail
cd "$(dirname "$0")/.."
# shellcheck source=tools/toolchain.env
. tools/toolchain.env

# colibri's TCP object: TRANSPORT=tcp-nonblocking ROLE=both TRUST=webpki
# EXPORTER=on RAND=session SUITE=aesgcm TX_RECORD=16384 KEYLOG=off.
COLIBRI=(-DRAND=session -DTRANSPORT=tcp-nonblocking -DROLE=both -DTRUST=webpki -DEXPORTER=on
    -DSUITE=aesgcm -DTX_RECORD=16384 -DKEYLOG=off)
# The ch_cfg.cpu values (cpu_cfg.h): 0xe7 is CH_CPU_PROBED with the AES,
# multiply, SHA-256, SHA-512 and SHA-3 bits, what a caller on a
# Neoverse-N2 states; 0x07 the value colibri states today (its
# src/tls/config.zig, cpu_of); 0x03 the AES bit alone.
VALUES=(0xe7 0x07 0x03)
TARGET=aarch64-linux-gnu
PORT=44388
RUNS=5
CONNECTIONS=2

fail() {
    echo "FAIL handshake-n2: $*" >&2
    exit 1
}

zig_check() {
    local version
    version=$(zig version 2>/dev/null || true)
    [ "$version" = "$ZIG_VERSION" ] ||
        fail "zig is '${version:-absent}', and the object is the one Zig $ZIG_VERSION builds"
}

# $1 = output directory, $2 = name, $3 = Zig target or empty for this
# machine, $4 = Zig CPU or empty for this machine's.
build_server() {
    local out=$1 name=$2 target=$3 cpu=$4 cache=$5
    local zig_target=() cc_target=()
    if [ -n "$target" ]; then
        zig_target=(-Dtarget="$target" -Dcpu="$cpu")
        cc_target=(-target "$target" -mcpu="$cpu")
    fi
    zig build "${zig_target[@]}" "${COLIBRI[@]}" --prefix "$out/obj-$name" \
        --cache-dir "$cache" install lib-lists
    local defs=()
    read -r -a defs <<<"$(tr '\n' ' ' <"$out/obj-$name/lib-def.txt")"
    [ "${#defs[@]}" -gt 0 ] || fail "zig build lib-lists wrote no defines"
    zig cc "${cc_target[@]}" -std=c11 -O2 -Wall -Wextra -Wpedantic -Werror -I. -Ibench \
        "${defs[@]}" bench/handshake_server.c bench/handshake_window.c \
        "$out/obj-$name/lib/chapulin.o" -o "$out/chapulin_server_$name"
}

case "${1:-}" in
--build)
    zig_check
    out=$(mktemp -d)
    trap 'rm -rf "$out"' EXIT
    mkdir -p bin/handshake-n2
    build_server "$out" host "" "" bin/handshake-n2/cache
    echo "handshake-n2: --build built bench/handshake_server.c over colibri's object for this machine" >&2
    exit 0
    ;;
build)
    [ -n "${2:-}" ] || fail "build needs a directory"
    zig_check
    mkdir -p "$2"
    build_server "$2" n2 "$TARGET" neoverse_n2 "$2/cache"
    build_server "$2" base "$TARGET" baseline "$2/cache"
    echo "handshake-n2: built $2/chapulin_server_n2 and $2/chapulin_server_base" >&2
    exit 0
    ;;
measure)
    [ -n "${2:-}" ] || fail "measure needs a directory"
    DIR=$(cd "$2" && pwd)
    ;;
*)
    echo "usage: $0 build DIR | measure DIR | --build" >&2
    exit 2
    ;;
esac

# ---- measure ----------------------------------------------------------

[ "$(uname -s)-$(uname -m)" = Linux-aarch64 ] || fail "measure runs on Linux on arm64"
grep -q '^CPU part[[:space:]]*: 0xd49' /proc/cpuinfo ||
    fail "this CPU is not a Neoverse-N2 (CPU part 0xd49 in /proc/cpuinfo)"
paranoid=$(cat /proc/sys/kernel/perf_event_paranoid)
[ "$paranoid" -le 2 ] ||
    fail "kernel.perf_event_paranoid is $paranoid; run sudo sysctl kernel.perf_event_paranoid=2"
for tool in valgrind qemu-aarch64 objdump nm cc python3 openssl; do
    command -v "$tool" >/dev/null || fail "$tool is not on PATH"
done
[ -r /usr/include/openssl/ssl.h ] || fail "the runner's OpenSSL headers are missing (libssl-dev)"
OPENSSL_PREFIX=${OPENSSL_PREFIX:-$HOME/openssl-inst}
PINNED_LABEL=$("$OPENSSL_PREFIX/bin/openssl" version | awk '{ print $1 " " $2 }')
[ "$PINNED_LABEL" = "OpenSSL $OPENSSL_VERSION" ] ||
    fail "$OPENSSL_PREFIX holds $PINNED_LABEL, not the pinned OpenSSL $OPENSSL_VERSION"
SYSTEM_LABEL=$(/usr/bin/openssl version | awk '{ print $1 " " $2 }')
PERF=${PERF:-$(command -v perf || true)}
for name in n2 base; do
    [ -x "$DIR/chapulin_server_$name" ] || fail "$DIR holds no chapulin_server_$name"
    readelf -h "$DIR/chapulin_server_$name" | grep -q 'Type:[[:space:]]*EXEC' ||
        fail "chapulin_server_$name is not a fixed-address executable, which the trace needs"
done

W=$(mktemp -d)
trap 'rm -rf "$W"' EXIT

# The OpenSSL programs. The servers link at fixed addresses (-no-pie),
# as Zig links the chapulin ones, so the trace reads each function's
# address from nm. The pinned OpenSSL is a no-shared build, whose
# objects a position-independent executable could not link anyway.
CFLAGS=(-std=c11 -D_DEFAULT_SOURCE -O2 -Wall -Wextra -Wpedantic -Werror -Ibench)
cc "${CFLAGS[@]}" -o "$W/client" bench/handshake_client.c -lssl -lcrypto
cc "${CFLAGS[@]}" -no-pie -o "$W/openssl_server_system" bench/handshake_openssl_server.c \
    bench/handshake_window.c -lssl -lcrypto
# The runner's OpenSSL 3.0 once more, from libssl-dev's static archives,
# so that the trace, which reads the symbols of the binary alone, splits
# it too. Both builds' perf_event rows show what static linking changes.
cc "${CFLAGS[@]}" -no-pie -o "$W/openssl_server_system_static" bench/handshake_openssl_server.c \
    bench/handshake_window.c /usr/lib/aarch64-linux-gnu/libssl.a \
    /usr/lib/aarch64-linux-gnu/libcrypto.a -ldl -pthread
pinned_lib=$OPENSSL_PREFIX/lib
[ -f "$pinned_lib/libssl.a" ] || pinned_lib=$OPENSSL_PREFIX/lib64
[ -f "$pinned_lib/libssl.a" ] || fail "$OPENSSL_PREFIX holds no libssl.a, which a no-shared build installs"
cc "${CFLAGS[@]}" -no-pie -I"$OPENSSL_PREFIX/include" -o "$W/openssl_server_pinned" \
    bench/handshake_openssl_server.c bench/handshake_window.c "$pinned_lib/libssl.a" \
    "$pinned_lib/libcrypto.a" -ldl -pthread

# The identity: a P-256 root, and a P-256 leaf for localhost it signed.
(
    cd "$W"
    openssl ecparam -name prime256v1 -genkey -noout -out root.key
    openssl req -x509 -new -key root.key -subj /CN=bench-root -days 30 -sha256 -out root.pem \
        -addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign
    openssl ecparam -name prime256v1 -genkey -noout -out leaf.key
    openssl req -new -key leaf.key -subj /CN=localhost -out leaf.csr
    printf '%s\n' subjectAltName=DNS:localhost basicConstraints=CA:FALSE \
        keyUsage=critical,digitalSignature extendedKeyUsage=serverAuth >leaf.ext
    openssl x509 -req -in leaf.csr -CA root.pem -CAkey root.key -CAcreateserial -days 30 \
        -sha256 -extfile leaf.ext -out leaf.pem
    cat leaf.pem root.pem >chain.pem
) 2>"$W/identity.log" || {
    cat "$W/identity.log" >&2
    fail "openssl could not make the identity"
}
LEAF_LEN=$(openssl x509 -in "$W/leaf.pem" -outform der | wc -c)
ROOT_LEN=$(openssl x509 -in "$W/root.pem" -outform der | wc -c)

# The command line of a server, for its name and value, without the
# port, the connection count and the counted connection.
server_tail() { # $1 = server name, $2 = ch_cfg.cpu value or -
    case $1 in
    chapulin-n2) echo "$DIR/chapulin_server_n2 @ $2 $W/chain.pem $W/leaf.key" ;;
    chapulin-base) echo "$DIR/chapulin_server_base @ $2 $W/chain.pem $W/leaf.key" ;;
    openssl-pinned) echo "$W/openssl_server_pinned @ $W/chain.pem $W/leaf.key" ;;
    openssl-system) echo "$W/openssl_server_system @ $W/chain.pem $W/leaf.key" ;;
    openssl-system-static) echo "$W/openssl_server_system_static @ $W/chain.pem $W/leaf.key" ;;
    esac
}

# Runs one server with the client. $1 = connections, $2 = counted
# connection, $3 = the server's command with @ for its first three
# arguments, the rest = what runs in front of it (perf, qemu, valgrind).
# The server's stdout goes to $W/out and its stderr to $W/err. Returns 1,
# with both ends' errors in $W/failure, when either end fails.
serve() {
    local connections=$1 counted=$2 command=$3
    shift 3
    local words=()
    read -r -a words <<<"${command/@/$PORT $connections $counted}"
    timeout 3600 "$@" "${words[@]}" >"$W/out" 2>"$W/err" &
    local server=$!
    if ! timeout 3600 "$W/client" "$PORT" "$connections" 2>"$W/client.err"; then
        kill "$server" 2>/dev/null || true
        wait "$server" 2>/dev/null || true
        cat "$W/client.err" "$W/err" >"$W/failure"
        return 1
    fi
    if ! wait "$server"; then
        cat "$W/err" >"$W/failure"
        return 1
    fi
}

# serve, and the end of the script when it fails.
serve_or_fail() {
    serve "$@" || {
        cat "$W/failure" >&2
        fail "a connection failed: $3"
    }
}

median_spread() { # reads numbers, prints the median and the spread in percent
    sort -n | awk '{ v[NR] = $1 } END {
        m = v[int((NR + 1) / 2)]
        printf "%d %.2f\n", m, m ? 100 * (v[NR] - v[1]) / m : 0 }'
}

ROWS_OUT=$W/rows.csv
row() { # $1 server, $2 value, $3 tool, $4 row, $5 instructions, $6 spread
    echo "$1,$2,$3,$4,$5,$6" >>"$ROWS_OUT"
    echo "  $1 $2 $3 $4: $5${6:+ (spread $6%)}" >&2
}

# perf_event: five runs of two connections, the second one counted.
count_window() { # $1 = server, $2 = value
    local command handshake exchange hs_spread ex_spread
    command=$(server_tail "$1" "$2")
    : >"$W/handshake" && : >"$W/exchange"
    for _ in $(seq "$RUNS"); do
        serve_or_fail "$CONNECTIONS" 0 "$command --count"
        awk -v c="$CONNECTIONS" '$1 == "connection" && $2 == c { print $4 >> "'"$W/handshake"'";
            print $6 >> "'"$W/exchange"'" }' "$W/out"
    done
    read -r handshake hs_spread < <(median_spread <"$W/handshake")
    read -r exchange ex_spread < <(median_spread <"$W/exchange")
    row "$1" "$2" perf_event handshake "$handshake" "$hs_spread"
    row "$1" "$2" perf_event exchange "$exchange" "$ex_spread"
}

# perf_stat: the whole process, two connections less one.
count_process() { # $1 = server, $2 = value
    [ -n "$PERF" ] || return 0
    local command one two connections
    command=$(server_tail "$1" "$2")
    for connections in 1 2; do
        : >"$W/process$connections"
        for _ in $(seq "$RUNS"); do
            serve_or_fail "$connections" 0 "$command" "$PERF" stat -x, -e instructions:u -o "$W/stat" --
            awk -F, '$3 ~ /^instructions/ { print $1 }' "$W/stat" >>"$W/process$connections"
        done
    done
    read -r one _ < <(median_spread <"$W/process1")
    read -r two _ < <(median_spread <"$W/process2")
    row "$1" "$2" perf_stat connection "$((two - one))" ""
}

# qemu: the trace of two connections, through a pipe into the splitter.
count_trace() { # $1 = server, $2 = value
    local command binary open
    command=$(server_tail "$1" "$2")
    binary=${command%% *}
    open=$(nm "$binary" | awk '$3 == "bench_window_open" { print $1 }')
    rm -f "$W/trace" && mkfifo "$W/trace"
    python3 bench/handshake_stages.py trace "$binary" "$open" "$CONNECTIONS" \
        <"$W/trace" >"$W/stages" 2>"$W/stages.err" &
    local splitter=$!
    serve_or_fail "$CONNECTIONS" 0 "$command" qemu-aarch64 -cpu neoverse-n2 -one-insn-per-tb \
        -d exec,nochain -D "$W/trace"
    wait "$splitter" || {
        cat "$W/stages.err" >&2
        fail "the trace splitter failed on $command"
    }
    grep -q "^bench_window_open 0x$(printf '%x' "0x$open")\$" "$W/err" ||
        fail "$binary ran bench_window_open somewhere other than nm's address $open"
    cat "$W/stages.err" >&2
    local stage count
    while read -r stage count; do
        row "$1" "$2" qemu "$stage" "$count" ""
    done <"$W/stages"
}

# callgrind: the second connection, collected alone.
count_callgrind() { # $1 = server, $2 = value
    local command
    command=$(server_tail "$1" "$2")
    rm -f "$W/callgrind.out"
    if ! serve "$CONNECTIONS" "$CONNECTIONS" "$command" valgrind --tool=callgrind \
        --collect-atstart=no --toggle-collect=bench_counted \
        --callgrind-out-file="$W/callgrind.out"; then
        echo "  $1 $2: callgrind cannot run it, and the CSV holds no callgrind row for it:" >&2
        grep -m1 "unhandled instruction" "$W/failure" >&2 || true
        return 0
    fi
    python3 bench/handshake_stages.py callgrind "$W/callgrind.out" >"$W/stages" \
        2>"$W/stages.err" || {
        cat "$W/stages.err" >&2
        fail "the callgrind splitter failed on $command"
    }
    cat "$W/stages.err" >&2
    local stage count
    while read -r stage count; do
        row "$1" "$2" callgrind "$stage" "$count" ""
    done <"$W/stages"
}

echo "handshake-n2: counting on $(grep -m1 'CPU part' /proc/cpuinfo), $(uname -r)" >&2
for name in chapulin-n2 chapulin-base; do
    for value in "${VALUES[@]}"; do
        count_window "$name" "$value"
        count_process "$name" "$value"
        count_trace "$name" "$value"
        count_callgrind "$name" "$value"
    done
done
for name in openssl-pinned openssl-system openssl-system-static; do
    count_window "$name" -
    count_process "$name" -
done
count_trace openssl-pinned -
count_trace openssl-system-static -
count_callgrind openssl-pinned -
count_callgrind openssl-system -

TMPOUT=$(mktemp)
{
    echo "# $(date -u +%Y-%m-%d) on $(grep -m1 'CPU part' /proc/cpuinfo | tr -s ' \t' ' '), $(nproc) CPUs," \
        "Linux $(uname -r); tree $(git rev-parse --short HEAD 2>/dev/null || echo unknown)"
    echo "# chapulin: build.zig with Zig $ZIG_VERSION for $TARGET, ${COLIBRI[*]};" \
        "OpenSSL: $PINNED_LABEL (openssl-pinned, static) and $SYSTEM_LABEL (openssl-system, shared)"
    echo "# leaf $LEAF_LEN and root $ROOT_LEN bytes of DER; $(qemu-aarch64 --version | head -1);" \
        "$(valgrind --version); ${PERF:+$("$PERF" --version)}"
    echo "server,cpu,tool,row,instructions,spread_percent"
    cat "$ROWS_OUT"
} >"$TMPOUT"
mv "$TMPOUT" bench/results-handshake-n2.csv
echo "wrote bench/results-handshake-n2.csv" >&2
