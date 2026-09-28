#!/bin/bash
# lint-tidy and lint-cppcheck each refuse a checker whose version is not
# the pin, before they read a stamp or run the checker (REQUIRE_PINNED in
# the Makefile). This hands each lint a stand-in one version older than
# the pin and one newer, and requires the lint to stop and name the pin.
# `make lint-pinned-checkers` runs it, and test/violations.py runs it with
# no argument.
set -euo pipefail
cd "$(dirname "$0")/.."

fail() {
    echo "lint-pinned-checkers: $*" >&2
    exit 1
}
llvm=$(sed -n 's/^LLVM_MAJOR=//p' tools/toolchain.env)
cppcheck=$(sed -n 's/^CPPCHECK_VERSION=//p' tools/toolchain.env)
[ -n "$llvm" ] && [ -n "$cppcheck" ] || fail "tools/toolchain.env names no LLVM_MAJOR or CPPCHECK_VERSION"
IFS=. read -r cppcheck_major cppcheck_minor _ <<< "$cppcheck"

dir=$(mktemp -d)
trap 'rm -rf "$dir"' EXIT

# stand_in NAME LINE: a checker that prints LINE for --version and fails
# any other call, so a lint that runs it past the version check stops for
# another reason, and refused below reports that.
stand_in() {
    cat > "$dir/$1" <<EOF
#!/bin/sh
[ "\$1" = --version ] || exit 3
echo "$2"
EOF
    chmod +x "$dir/$1"
}

# refused LINT VARIABLE NAME PIN: the lint, given the stand-in NAME through
# make's VARIABLE, must fail and name PIN.
refused() {
    local out
    if out=$(make -s --no-print-directory "$1" "$2=$dir/$3" 2>&1); then
        fail "$1 passed with $3: $out"
    fi
    case "$out" in
    *"and the pin is $4 "*) ;;
    *) fail "$1 stopped with $3, but not on the pin: $out" ;;
    esac
}

stand_in clang-tidy-older "Ubuntu LLVM version $((llvm - 1)).1.3"
stand_in clang-tidy-newer "Homebrew LLVM version $((llvm + 1)).1.0"
older=$cppcheck_major.$((cppcheck_minor - 1)).0
newer=$cppcheck_major.$((cppcheck_minor + 1)).0
stand_in cppcheck-older "Cppcheck $older"
stand_in cppcheck-newer "Cppcheck $newer"
refused lint-tidy CLANG_TIDY clang-tidy-older "LLVM $llvm"
refused lint-tidy CLANG_TIDY clang-tidy-newer "LLVM $llvm"
refused lint-cppcheck CPPCHECK cppcheck-older "Cppcheck $cppcheck"
refused lint-cppcheck CPPCHECK cppcheck-newer "Cppcheck $cppcheck"
echo "lint-pinned-checkers: lint-tidy refuses clang-tidy $((llvm - 1)) and $((llvm + 1)) for the pin, LLVM $llvm," \
    "and lint-cppcheck refuses cppcheck $older and $newer for the pin, $cppcheck"
