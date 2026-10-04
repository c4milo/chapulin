#!/usr/bin/env bash
# Runs CI's `make check` locally: Ubuntu 24.04 on x86-64, its gcc as cc,
# GNU make 4.3 and the pinned tools, in the image
# test/docker-check.Dockerfile describes. Mirrors the `make check` half of
# the check job in .github/workflows/check.yml, so a failure that only
# CI's compiler, its x86-64 cppcheck or its make finds shows before a
# push. tools/toolchain.env pins the container and every tool in it.
#
# The image is tagged by a hash of the files its build reads, so a pin
# bump builds a new one and an unchanged pin reuses the one already built.
#
# make runs on a copy of the tree, made inside the container and gone with
# it: the files `git ls-files -co --exclude-standard` names, so
# uncommitted work is tested, and HEAD's history, which
# lint-commit-citations reads. The copy's index holds every one of those
# files, as it will once they are committed. The tree is mounted
# read-only, so this machine's bin/ and its stamps stay as they are, and
# the copy starts with no bin/, as a CI job does.
#
# CI is set, so a missing tool fails as it does on a runner. Two lints do
# not run, because the image holds neither Lean with Mathlib nor Node:
# lint-spec and lint-commits. Neither reads the compiler or the system,
# and `make check` on the development machine runs both. On an Apple
# silicon Mac a third does not run, lint-zig-build: Rosetta, which runs
# the container's x86-64 code there, cannot load the translate-c program
# Zig links. That lint's verdict for Linux x86-64 stays with CI.
# docs/decisions.md 92 has the measurements behind each choice here.
#
# Beside check, make builds the binaries check-slow builds and check does
# not, and runs none of them. The job runs check-slow on a push to main,
# and gcc reads sources there that no part of check compiles.
#
# Arguments replace both goals: `test/docker-check.sh check-widemul-builds`
# runs one leg. Needs docker (OrbStack works); skips without it.
set -euo pipefail

if [ "${1:-}" != "--inside" ]; then
    cd "$(dirname "$0")/.."
    # shellcheck source=tools/toolchain.env
    . tools/toolchain.env
    command -v docker >/dev/null 2>&1 || {
        echo "SKIP check local lane: docker not available" >&2
        exit 0
    }

    # The files the image build reads. The context holds exactly these,
    # and the tag is a hash of them and of the pins.
    dockerfile=test/docker-check.Dockerfile
    context=("$dockerfile"
        .github/actions/install-llvm/install.sh
        .github/actions/install-zig/install.sh
        .github/actions/install-cppcheck/install.sh
        .github/actions/install-cbmc/install.sh
        .github/actions/install-elan/install.sh
        .semgrep/requirements.txt)
    if command -v sha256sum >/dev/null 2>&1; then
        tag=$(cat "${context[@]}" tools/toolchain.env | sha256sum | cut -c1-16)
    else
        tag=$(cat "${context[@]}" tools/toolchain.env | shasum -a 256 | cut -c1-16)
    fi
    image=chapulin-check:$tag

    work=$(mktemp -d)
    trap 'rm -rf "$work"' EXIT

    if ! docker image inspect "$image" >/dev/null 2>&1; then
        echo "docker-check: building $image, which takes a few minutes" >&2
        mkdir "$work/context"
        for f in "${context[@]}"; do
            mkdir -p "$work/context/$(dirname "$f")"
            cp "$f" "$work/context/$f"
        done
        # Every ARG in the Dockerfile is a pin of the same name.
        args=()
        while read -r pin; do
            args+=(--build-arg "$pin=${!pin}")
        done < <(sed -n 's/^ARG //p' "$dockerfile")
        # No cache: apt installs the day's packages, the LLVM point
        # release among them, as a runner does on every run.
        docker build --no-cache --platform linux/amd64 "${args[@]}" \
            -f "$work/context/$dockerfile" -t "$image" "$work/context"
        rm -rf "$work/context"
    fi

    # HEAD's history, and the names of the files to copy. A file the index
    # names and the tree no longer holds is left out.
    git bundle create -q "$work/head.bundle" HEAD
    git ls-files -co --exclude-standard -z |
        while IFS= read -r -d '' f; do
            if [ -e "$f" ] || [ -L "$f" ]; then printf '%s\0' "$f"; fi
        done > "$work/files"

    docker run --rm --init --platform linux/amd64 -e CI=true \
        -v "$PWD":/src:ro -v "$work":/in:ro "$image" \
        bash /src/test/docker-check.sh --inside "$@"
    exit
fi

# ---- inside the container from here on ----
shift

# What a runner carries from the install steps to the steps after them:
# the variables in GITHUB_ENV, and the directories in GITHUB_PATH ahead of
# PATH.
set -a
# shellcheck source=/dev/null
. "$GITHUB_ENV"
set +a
while IFS= read -r dir; do
    PATH=$dir:$PATH
done < "$GITHUB_PATH"

git -c init.defaultBranch=check init -q /work
cd /work
git fetch -q /in/head.bundle HEAD
git update-ref HEAD FETCH_HEAD
tar -C /src --null -T /in/files -cf - | tar -xf - --no-same-owner
git add -f -A .

# The bin/ files check-slow builds and check does not, read from make's
# database through the impact tool's reader, so the list follows the
# Makefile. Running them takes Mathlib, the pinned OpenSSL and Go;
# compiling them takes gcc alone. gcc stopped fd20bf2 at one of them,
# bin/diff, on a warning clang does not give.
slow_builds() {
    python3 - << 'EOF'
import sys

sys.path.insert(0, "tools")
import impact_map
import impact_read


def builds(mapping, root):
    """The bin/ files the targets under root build: a prerequisite, a
    target a recipe hands to $(MAKE), or a binary a recipe runs."""
    names = set()
    for target in mapping.gate_targets([root]):
        prereqs, recipe = mapping.rules[target]
        names |= {target, *prereqs}
        names |= {f"bin/{b}" for b in impact_read.binaries_run(recipe, mapping.variables)}
    return {n for n in names if n.startswith("bin/") and n in mapping.rules}


mapping = impact_map.Mapping()
print(" ".join(sorted(builds(mapping, "check-slow") - builds(mapping, "check"))))
EOF
}

echo "docker-check: $(cc --version | head -1), $(make --version | head -1), $(nproc) cores" >&2

# The lints that do not run here. make takes each with -o, which names a
# target it treats as up to date: it runs no recipe for it, and runs every
# other prerequisite of check.
skip=(lint-spec lint-commits)
echo "docker-check: lint-spec and lint-commits do not run here; make check on the development machine runs both" >&2
# Rosetta names its CPU VirtualApple. It stops the translate-c program Zig
# links before its first instruction, with "rosetta error: bss_size
# overflow", so lint-zig-build fails there whatever the tree holds.
if grep -q VirtualApple /proc/cpuinfo; then
    skip+=(lint-zig-build)
    echo "docker-check: lint-zig-build does not run under Rosetta, which cannot load the translate-c program Zig links" >&2
fi
old=()
for lint in "${skip[@]}"; do
    old+=(-o "$lint")
done

if [ $# -eq 0 ]; then
    slow=$(slow_builds)
    [ -n "$slow" ] || {
        echo "docker-check: make's database names no binary that check-slow builds and check does not" >&2
        exit 1
    }
    echo "docker-check: check, and a build of what check-slow adds: $slow" >&2
    # slow holds a list as one string, which the shell must split.
    # shellcheck disable=SC2086
    set -- check $slow
fi

# CI runs `make -j ci`, and the ci recipe starts the make that runs check.
# From that second make, a recipe line that runs a script which calls make
# itself needs a leading +, or GNU make 4.3 prints its "Entering
# directory" lines into what the script reads (the Makefile's note above
# CHECK_REPORT). A make started from a shell never prints them, so the
# same two makes run here: the one rule below is the Makefile's ci rule
# with this lane's flags and goals.
{
    echo ".PHONY: ci"
    echo "ci: ; \$(MAKE)$(printf ' %q' "${old[@]}" "$@")"
} > /tmp/ci.mk
exec make -j"$(nproc)" -f /tmp/ci.mk ci
