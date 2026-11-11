#!/usr/bin/env bash
# Builds a host object's two SHA-3 tests for x86-64 on an Apple silicon
# Mac and runs them under Rosetta (docs/decisions.md 218). `make check`
# runs it as check-rosetta.
#
#   - bin/rosetta/sha3_equiv_test_host: sha3.c, which runs
#     sha3_inverted_lanes.h's form on x86-64, against FIPS 202, and the
#     search of the stack each SHA-3 call leaves (test/sha3_residue.h).
#   - bin/rosetta/sha3_hw_equiv_test: sha3_hw.c against sha3.c, and the
#     same search for sha3_hw.c's calls, where the object holds an x86-64
#     copy in sha3_hw.c. Elsewhere it prints SKIP and passes.
#
# macOS keeps rbp as the frame pointer, so clang has 14 general registers
# for a round where a Linux build has 15. With one register fewer, the
# loop of decision 216's round wrote one value of theta to a slot below
# the stack pointer. Only a macOS build showed it. No CI job builds for
# macOS on x86-64, so this script is the one run of that build.
# ROSETTA_ADVERTISE_AVX=1 makes Rosetta state AVX2, BMI1 and BMI2 in
# CPUID, which the x86-64 copy in sha3_hw.c needs.
#
# It prints SKIP with the reason and passes where it cannot run the
# builds:
#
#   - on a machine other than an Apple silicon Mac, Linux CI among them;
#   - where Rosetta is not installed;
#   - where the compiler does not build for x86-64.
cd "$(dirname "$0")/.." || exit 1

if [ "$(uname -s)" != Darwin ] || [ "$(uname -m)" != arm64 ]; then
    echo "SKIP the x86-64 host object under Rosetta: this machine is not an Apple silicon Mac"
    exit 0
fi
if ! arch -x86_64 /usr/bin/true 2>/dev/null; then
    echo "SKIP the x86-64 host object under Rosetta: Rosetta is not installed" \
        "(softwareupdate --install-rosetta)"
    exit 0
fi

cc=${CC:-cc}
work=$(mktemp -d -t chapulin_rosetta_XXXXXX)
trap 'rm -rf "$work"' EXIT
printf 'int main(void) {\n    return 0;\n}\n' > "$work/probe.c"
if ! "$cc" -arch x86_64 -o "$work/probe" "$work/probe.c" 2>/dev/null ||
    ! arch -x86_64 "$work/probe"; then
    echo "SKIP the x86-64 host object under Rosetta: $cc does not build a program for x86-64" \
        "with -arch x86_64"
    exit 0
fi

lists=$(make -s --no-print-directory print-sha3-host-lists) || exit 1
flags=$(sed -n 1p <<< "$lists")
equiv_srcs=$(sed -n 2p <<< "$lists")
hw_srcs=$(sed -n 3p <<< "$lists")
if [ -z "$flags" ] || [ -z "$equiv_srcs" ] || [ -z "$hw_srcs" ]; then
    echo "rosetta-check: make print-sha3-host-lists printed fewer than three lists"
    exit 1
fi
mkdir -p bin/rosetta
# flags and each list of sources hold a list as one string, which the
# shell must split.
# shellcheck disable=SC2086
"$cc" -arch x86_64 $flags -o bin/rosetta/sha3_equiv_test_host $equiv_srcs || exit 1
# shellcheck disable=SC2086
"$cc" -arch x86_64 $flags -o bin/rosetta/sha3_hw_equiv_test $hw_srcs || exit 1
echo "rosetta-check: bin/rosetta/sha3_equiv_test_host and bin/rosetta/sha3_hw_equiv_test built for x86-64 with $cc"
rc=0
for b in sha3_equiv_test_host sha3_hw_equiv_test; do
    ROSETTA_ADVERTISE_AVX=1 arch -x86_64 "bin/rosetta/$b" || {
        echo "rosetta-check: bin/rosetta/$b failed under Rosetta"
        rc=1
    }
done
exit $rc
