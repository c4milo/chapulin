#!/bin/sh
# Usage: tools/release-ci-green.sh <tag> <commit>
#
# Fails unless CI is green for a release tag vX.Y.Z:
#   - the newest check.yml run on <commit> passed, and
#   - the newest nightly.yml run on main that finished passed.
# v0.4.0 was tagged on a commit whose nightly had failed, because no step
# read the nightly. .githooks/pre-push and
# .github/workflows/release-tag.yml run this beside release-version.sh.
# It needs gh, signed in, and fails when gh cannot answer. A tag that does
# not start with v passes.
set -eu
tag=$1
commit=$(git rev-parse "$2")
case $tag in
v[0-9]*) ;;
*) exit 0 ;;
esac
fail() {
    echo "release-ci-green: $*" >&2
    echo "release-ci-green: do not tag $tag until CI is green." >&2
    exit 1
}
command -v gh >/dev/null 2>&1 || fail "gh is missing, so CI cannot be read."
check=$(gh run list --workflow check.yml --commit "$commit" --limit 1 \
    --json status,conclusion --jq '.[0] | "\(.status) \(.conclusion)"') ||
    fail "gh could not read the check.yml runs."
[ "$check" = "completed success" ] ||
    fail "the newest check.yml run on $commit is '${check:-absent}'."
nightly=$(gh run list --workflow nightly.yml --branch main --status completed --limit 1 \
    --json conclusion,headSha --jq '.[0] | "\(.conclusion) \(.headSha)"') ||
    fail "gh could not read the nightly.yml runs."
case $nightly in
"success "*) ;;
*) fail "the newest nightly.yml run on main that finished is '${nightly:-absent}'." ;;
esac
