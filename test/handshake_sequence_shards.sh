#!/usr/bin/env bash
# Runs a sequence enumeration, bin/handshake_sequence_test or
# bin/handshake_sequence_pq, as one shard per core, and prints one line
# with the total. check-slow and the handshake-sequence and
# handshake-sequence-pq targets run it:
#
#   ./test/handshake_sequence_shards.sh ./bin/handshake_sequence_test
#
# Shard K of N checks the sequences whose index in the enumeration order
# is K mod N (the --shard argument in test/handshake_sequence_test.c).
# Each shard starts its own spec process and writes to its own two files
# in a new temporary directory, so no two shards share a pipe or a file.
# ENUM_DEPTH passes through to every shard.
#
# The script fails when a shard fails. It also fails when the shards'
# counts do not add up to the count of the whole enumeration, which every
# shard prints: that sum is what shows the shards together checked every
# sequence once, the same sequences one process without --shard checks.
cd "$(dirname "$0")/.." || exit 1

if [ $# -ne 1 ]; then
    echo "usage: $0 ./bin/handshake_sequence_test" >&2
    exit 2
fi
binary=$1
name=$(basename "$binary")
shards=$(getconf _NPROCESSORS_ONLN)
dir=$(mktemp -d -t chapulin_sequence_XXXXXX)
pids=()
# bash starts a background job with SIGINT ignored when job control is
# off, as it is in a script, so an interrupt would leave the shards
# running. The EXIT trap stops the ones not yet waited for.
trap 'kill "${pids[@]}" 2>/dev/null; rm -rf "$dir"' EXIT
trap 'exit 130' INT TERM

start=$(date +%s)
for ((k = 0; k < shards; k++)); do
    "$binary" --shard "$k/$shards" > "$dir/$k.out" 2> "$dir/$k.err" &
    pids[k]=$!
done

failed=0
for ((k = 0; k < shards; k++)); do
    wait "${pids[k]}"
    rc=$?
    unset 'pids[k]'
    if [ "$rc" -ne 0 ]; then
        echo "$name: shard $k/$shards failed with exit status $rc:" >&2
        cat "$dir/$k.err" >&2
        failed=$((failed + 1))
    fi
done
seconds=$(($(date +%s) - start))
if [ "$failed" -ne 0 ]; then
    echo "$name: $failed of $shards shards failed" >&2
    exit 1
fi

# Without the spec binary every shard runs only the direct checks and
# says so; the binary's own line is the summary.
if grep -q "spec comparisons skipped" "$dir/0.out"; then
    grep "spec comparisons skipped" "$dir/0.out"
    exit 0
fi

sum=0
whole=
for ((k = 0; k < shards; k++)); do
    count=
    all=
    read -r count all < <(sed -n \
        "s|^.*: shard $k/$shards: \([0-9]*\) of \([0-9]*\) sequences .*|\1 \2|p" "$dir/$k.out")
    if [ -z "$count" ]; then
        echo "$name: shard $k/$shards printed no count:" >&2
        cat "$dir/$k.out" >&2
        exit 1
    fi
    if [ -n "$whole" ] && [ "$all" != "$whole" ]; then
        echo "$name: shard $k/$shards counts $all sequences in the enumeration, shard 0 counts $whole" >&2
        exit 1
    fi
    whole=$all
    sum=$((sum + count))
done
if [ "$sum" -ne "$whole" ]; then
    echo "$name: the shards checked $sum sequences, and the enumeration holds $whole" >&2
    exit 1
fi

scope=$(sed -n 's/^.* sequences (\(.*\)) in .*$/\1/p' "$dir/0.out")
echo "$name: $sum sequences ($scope) in $shards shards, $seconds s, C == spec"
