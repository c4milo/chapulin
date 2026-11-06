#!/bin/sh
# Usage: tools/release-version.sh <tag> [<commit>]
#
# Fails when a release tag vX.Y.Z and the .version of build.zig.zon at the
# tag's commit name different releases. The v0.3.0 tag carried the version
# 0.2.0, because no step compared the two. .githooks/pre-push runs this for
# each tag a push sends, and .github/workflows/release-tag.yml runs it for
# each tag that GitHub receives. A tag that does not start with v passes.
set -eu
tag=$1
commit=${2:-$tag}
case $tag in
v[0-9]*) ;;
*) exit 0 ;;
esac
want=${tag#v}
have=$(git show "$commit:build.zig.zon" |
    sed -n 's/^[[:space:]]*\.version[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p')
if [ "$have" != "$want" ]; then
    echo "release-version: the tag $tag names $want, but build.zig.zon at $commit says '$have'." >&2
    echo "release-version: set .version to \"$want\" in a commit, and tag that commit." >&2
    exit 1
fi
