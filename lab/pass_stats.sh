#!/usr/bin/env bash
# Lab only: the instructions of chacha20_sve2.c's object under each compiler given: each function's
# count and its loads and stores that address the stack, and a count of each mnemonic.
set -uo pipefail
cd "$(dirname "$0")/.."
for cc in "$@"; do
    echo "== $cc: $($cc --version | head -1)"
    W=$(mktemp -d)
    $cc -O2 -std=c11 -DCH_CPU_RUNTIME -Isrc -Iinclude/chapulin -Iinclude -c src/chacha20_sve2.c -o "$W/sve2.o" || continue
    objdump -d --no-show-raw-insn "$W/sve2.o" > "$W/sve2.s"
    awk '/^[0-9a-f]+ <.*>:$/{name=$2; next} /^\s+[0-9a-f]+:/{n[name]++; if ($0 ~ /\[sp/) s[name]++}
         END {for (f in n) printf "%-40s %5d instructions %4d stack\n", f, n[f], s[f]}' "$W/sve2.s"
    grep -E '^\s+[0-9a-f]+:' "$W/sve2.s" | awk '{print $2}' | sort | uniq -c | sort -rn | head -30 | tr '\n' ';'
    echo
    echo "-- the loop of ten double rounds: the lines around the first xar"
    grep -n -m1 'xar' "$W/sve2.s" | cut -d: -f1 | while read -r l; do sed -n "$((l-40)),$((l+90))p" "$W/sve2.s"; done
done
