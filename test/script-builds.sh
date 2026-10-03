#!/usr/bin/env bash
# Builds every program that a script outside `make check` compiles from
# a source list of its own, with this host's compiler, and runs none of
# them. `make check` runs it, so a call a source gains into a file such a
# list leaves out fails check rather than the script's next run. It is
# also the catch target of the INV-40 violations (docs/decisions.md 88).
#
# The programs, and where each one's sources come from:
#
#   - `bench/aead.sh --build`: the script's COMMON, and make's AES_HW_SRCS
#     for the host binary;
#   - `bench/record.sh --build`: the script's SRCS, and make's AES_HW_SRCS;
#   - `bench/primitives.sh --build`: the script's PRIMITIVE_SRCS, and for
#     the handshake programs the sources make names for
#     bin/tcp_nonblocking_loop_test;
#   - `test/qemu-m3.sh --build`: the script's SRCS, built as the host
#     binary;
#   - bench/insn_driver.c over make's INSN_SRCS and under its INSN_DEF,
#     the sources and defines bench/insn-m3.sh, bench/insn-mips.sh and
#     bench/insn-rv32.sh build with for their device cores, built here
#     for this host.
#
# It also runs `test/qemu-m3.sh` the way CI would with a tool missing, CI
# set and no linker, and requires it to fail. That script's run is the one
# check of its Cortex-M3 build, since the build above is the host binary
# alone, and a skip on CI hid the Cortex-M3 build while it did not compile
# (docs/invariants.md, INV-40).
#
# The five builds and that run start at once, each into a log of its own.
# The logs print whole, in the order above, once every one has ended, and
# a failure names its step.
cd "$(dirname "$0")/.." || exit 1

work=$(mktemp -d -t chapulin_script_builds_XXXXXX)
trap 'rm -rf "$work"' EXIT
cc=${CC:-cc}

# The instruction-count driver, over a runtime that stands in for the
# device scripts' own: main calls app_main, and ch_assert_fail is the
# one hook a linked source can call. Any OP_ macro serves, because every
# source on the list is linked whichever operation the driver runs.
insn_build() {
    local lists srcs defs
    lists=$(make -s --no-print-directory print-insn-lists) || return 1
    srcs=$(sed -n 1p <<< "$lists")
    defs=$(sed -n 2p <<< "$lists")
    [ -n "$srcs" ] || {
        echo "script-builds: make print-insn-lists returned no sources"
        return 1
    }
    cat > "$work/insn_runtime.c" << 'EOF'
#include <stdlib.h>

#include "ch_assert.h"

int app_main(void);

noreturn void ch_assert_fail(const char *cond, const char *file, int line) {
    (void)cond;
    (void)file;
    (void)line;
    abort();
}

int main(void) {
    return app_main();
}
EOF
    # srcs and defs each hold a list as one string, which the shell must
    # split.
    # shellcheck disable=SC2086
    "$cc" -std=c11 -O2 -I. -Ibench $defs -DOP_HANDSHAKE_PQ -DITERS=1 -DCH_CT_WIDEMUL \
        -o "$work/insn_driver" bench/insn_driver.c "$work/insn_runtime.c" $srcs &&
        echo "script-builds: bench/insn_driver.c linked over make print-insn-lists"
}

# test/qemu-m3.sh with CI set and a linker that does not exist: it must
# fail and name what is missing, where a development machine skips.
qemu_m3_on_ci() {
    local out
    if out=$(CI=1 LLD="$work/no-linker" test/qemu-m3.sh 2>&1); then
        echo "script-builds: test/qemu-m3.sh exited 0 on CI with no linker: $out"
        return 1
    fi
    case $out in
    "FAIL qemu-m3: "*) echo "script-builds: test/qemu-m3.sh fails on CI where a tool is missing" ;;
    *)
        echo "script-builds: test/qemu-m3.sh failed on CI before it named a missing tool: $out"
        return 1
        ;;
    esac
}

build() { # $1 = one of names below: runs that step into $work/$1.log
    case $1 in
    aead) bench/aead.sh --build ;;
    record) bench/record.sh --build ;;
    primitives) bench/primitives.sh --build ;;
    qemu-m3) test/qemu-m3.sh --build ;;
    insn) insn_build ;;
    qemu-m3-on-ci) qemu_m3_on_ci ;;
    esac > "$work/$1.log" 2>&1
    echo $? > "$work/$1.rc"
}

names=(aead record primitives qemu-m3 insn qemu-m3-on-ci)
for name in "${names[@]}"; do
    build "$name" &
done
wait

rc=0
for name in "${names[@]}"; do
    cat "$work/$name.log"
    status=$(cat "$work/$name.rc" 2> /dev/null || echo 1)
    if [ "$status" -ne 0 ]; then
        echo "script-builds: the $name step failed with exit $status" >&2
        rc=1
    fi
done
[ "$rc" -eq 0 ] && echo "script-builds: every program the bench and platform scripts build from their own lists links"
exit "$rc"
