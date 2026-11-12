# check=skip=InvalidDefaultArgInFrom

# The image test/docker-check.sh runs `make check` in: Ubuntu 26.04 on
# x86-64, the system CI's check job runs on, with apt's gcc as cc and the
# pinned tools that job installs for `make check`, in the job's order.
#
# test/docker-check.sh builds it. The script passes every version and
# hash below as a build argument read from tools/toolchain.env, so this
# file names no version, and it tags the image by a hash of the files the
# build reads. The build context holds those files and nothing else.
# UBUNTU_DIGEST has no default for the same reason, and the first line
# tells the builder's own check of the FROM line so.
#
# LLVM, Zig, cppcheck, CBMC and elan install through the scripts CI's
# actions run (.github/actions/*/install.sh), each of which checks its
# download against the pinned hash before it unpacks or runs it. They
# read RUNNER_TEMP, GITHUB_ENV and GITHUB_PATH, which a runner sets. Here
# the last two name files in /ci, and test/docker-check.sh loads them
# before it runs make, as a runner does between two steps.
#
# `make lint-pins` reads this file (tools/toolchain-pins.py): it fails on
# a value tools/toolchain.env carries, and on a fetch that no hash check
# follows.
ARG UBUNTU_DIGEST
FROM ubuntu@${UBUNTU_DIGEST}

# LANG is the value a runner sets.
ENV DEBIAN_FRONTEND=noninteractive \
    LANG=C.UTF-8 \
    RUNNER_TEMP=/tmp/runner \
    GITHUB_ENV=/ci/env \
    GITHUB_PATH=/ci/path

# What a runner's image already holds and `make check` or an install
# script reads, and two packages for the taint lane: libc6-dbg, whose
# symbols of the dynamic linker Valgrind reads, and bzip2, which unpacks
# Valgrind's tarball. The x86-64 and arm64 jobs install both with apt. gcc and g++ are Ubuntu 26.04's default, the major CI
# compiles with. The LLVM install script needs gnupg for the keyring,
# CBMC's package depends on bash-completion, and the install scripts call
# sudo.
RUN apt-get update -q \
    && apt-get install -y -q --no-install-recommends \
        bash-completion bzip2 ca-certificates cmake curl g++ gcc git gnupg libc6-dbg libc6-dev \
        lsb-release make python3 python3-pip software-properties-common sudo wget \
        xz-utils \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /ci "$RUNNER_TEMP" \
    && touch "$GITHUB_ENV" "$GITHUB_PATH"

# A tar that unpacks under Rosetta. Ubuntu 26.04's GNU tar opens each
# path inside a directory with the openat2 call, since its fix for
# CVE-2025-45582, and tries no other call. Rosetta, which runs this
# image's x86-64 code on an Apple silicon Mac, returns ENOSYS for
# openat2. So there tar stops at "Cannot open: Function not implemented",
# and the Zig, cppcheck and Valgrind steps below unpack nothing.
#
# The lines below pack a file inside a directory and unpack it. Where
# that fails, apt installs bsdtar, which calls no openat2 and takes the
# options those steps and test/docker-check.sh pass, and /ci/bin/tar
# names it. Each step below that unpacks an archive reads /ci/bin ahead
# of PATH, and GITHUB_PATH carries the directory to test/docker-check.sh.
#
# No other step reads it, and it is not /usr/local/bin, because dpkg
# must find GNU tar. dpkg-deb unpacks a package's control files with `tar
# --warning=no-timestamp`, an option bsdtar refuses, and the CBMC step's
# `dpkg -i` takes tar from PATH. GNU tar unpacks those files under
# Rosetta too, because none is inside a directory. On a kernel with
# openat2, /ci/bin is empty and every step runs GNU tar, as a runner does
# (docs/decisions.md 92).
RUN mkdir -p /ci/bin /tmp/tar-probe/in/d /tmp/tar-probe/out \
    && echo /ci/bin >> "$GITHUB_PATH" \
    && touch /tmp/tar-probe/in/d/f \
    && tar -cf /tmp/tar-probe/in.tar -C /tmp/tar-probe/in d \
    && if ! tar -xf /tmp/tar-probe/in.tar -C /tmp/tar-probe/out 2>/dev/null; then \
        apt-get update -q \
        && apt-get install -y -q --no-install-recommends libarchive-tools \
        && rm -rf /var/lib/apt/lists/* \
        && ln -s /usr/bin/bsdtar /ci/bin/tar \
        && /ci/bin/tar -xf /tmp/tar-probe/in.tar -C /tmp/tar-probe/out; \
    fi \
    && test -f /tmp/tar-probe/out/d/f \
    && rm -rf /tmp/tar-probe

# clang, clang-tidy, clang-format and llvm-nm at the pinned major, with
# the flags the check job passes .github/actions/install-llvm. The script
# writes CLANG_RV, CLANG_TIDY and CLANG_FORMAT to GITHUB_ENV itself.
COPY .github/actions/install-llvm/install.sh /ci/install-llvm.sh
ARG LLVM_MAJOR
ARG LLVM_KEY_SHA256
RUN MAJOR="$LLVM_MAJOR" SHA256="$LLVM_KEY_SHA256" \
        WITH_CLANG_TIDY=true WITH_CLANG_FORMAT=true WITH_LLVM=true bash /ci/install-llvm.sh \
    && rm -rf /var/lib/apt/lists/* "${RUNNER_TEMP:?}"/*

# Zig, as .github/actions/install-zig installs it. The last line is the
# one that action's action.yml runs after the script.
COPY .github/actions/install-zig/install.sh /ci/install-zig.sh
ARG ZIG_VERSION
ARG ZIG_LINUX_X86_64_SHA256
RUN PATH="/ci/bin:$PATH" VERSION="$ZIG_VERSION" SHA256="$ZIG_LINUX_X86_64_SHA256" \
        bash /ci/install-zig.sh \
    && rm -f /tmp/zig.tar.xz \
    && echo "$HOME/zig" >> "$GITHUB_PATH"

# cppcheck, built from source as .github/actions/install-cppcheck builds
# it, and the line its action.yml runs after the script.
COPY .github/actions/install-cppcheck/install.sh /ci/install-cppcheck.sh
ARG CPPCHECK_VERSION
ARG CPPCHECK_SHA256
RUN PATH="/ci/bin:$PATH" VERSION="$CPPCHECK_VERSION" SHA256="$CPPCHECK_SHA256" \
        bash /ci/install-cppcheck.sh \
    && rm -rf "${RUNNER_TEMP:?}"/* \
    && echo "CPPCHECK=$HOME/cppcheck-inst/bin/cppcheck" >> "$GITHUB_ENV"

# shellcheck. The check job installs it in a step of its own rather than
# through an action (.github/workflows/check.yml, "Install shellcheck at
# the pinned version"), so these instructions do what that step's lines
# do, and the last one writes the SHELLCHECK path the job's env block
# sets. The fetch and its check are an instruction each, which is how
# `make lint-pins` reads them.
ARG SHELLCHECK_VERSION
ARG SHELLCHECK_SHA256
RUN curl -fsSL -o "$RUNNER_TEMP/shellcheck.tar.xz" \
    "https://github.com/koalaman/shellcheck/releases/download/v$SHELLCHECK_VERSION/shellcheck-v$SHELLCHECK_VERSION.linux.x86_64.tar.xz"
RUN echo "$SHELLCHECK_SHA256  $RUNNER_TEMP/shellcheck.tar.xz" | sha256sum -c -
RUN mkdir -p "$HOME/shellcheck-inst" \
    && PATH="/ci/bin:$PATH" tar xJf "$RUNNER_TEMP/shellcheck.tar.xz" -C "$HOME/shellcheck-inst" \
        --strip-components=1 \
        "shellcheck-v$SHELLCHECK_VERSION/shellcheck" \
    && rm "$RUNNER_TEMP/shellcheck.tar.xz" \
    && echo "SHELLCHECK=$HOME/shellcheck-inst/shellcheck" >> "$GITHUB_ENV"

# semgrep, from the hash-pinned requirements file the check job installs.
# A runner's pip is not root, so it installs under the user's home, which
# --user asks for here, and the runner's image sets break-system-packages,
# which the variable sets here. A runner has ~/.local/bin on PATH.
COPY .semgrep/requirements.txt /ci/semgrep-requirements.txt
RUN PIP_BREAK_SYSTEM_PACKAGES=1 pip install --user --no-cache-dir --require-hashes \
        -r /ci/semgrep-requirements.txt \
    && echo "$HOME/.local/bin" >> "$GITHUB_PATH" \
    && PATH="$HOME/.local/bin:$PATH" semgrep --version

# CBMC, as .github/actions/install-cbmc installs it. `make check` runs it
# once, in proof-reach-smoke.
COPY .github/actions/install-cbmc/install.sh /ci/install-cbmc.sh
ARG CBMC_VERSION
ARG CBMC_DEB_SHA256
RUN VERSION="$CBMC_VERSION" SHA256="$CBMC_DEB_SHA256" bash /ci/install-cbmc.sh \
    && rm -rf "${RUNNER_TEMP:?}"/*

# elan, as .github/actions/install-elan installs it: the lake command and
# no Lean toolchain. lint-impact reads make's database, and the recipes
# that run bin/diff are in it only where LAKE names a command. Nothing
# here runs lake: test/docker-check.sh says why lint-spec does not run.
COPY .github/actions/install-elan/install.sh /ci/install-elan.sh
ARG ELAN_INIT_SHA256
RUN SHA256="$ELAN_INIT_SHA256" bash /ci/install-elan.sh \
    && rm -rf "${RUNNER_TEMP:?}"/*

# Valgrind, as .github/actions/install-valgrind installs it, for `make
# ct-taint` (docs/decisions.md 155). The last line does what that action's
# action.yml does after the script.
COPY .github/actions/install-valgrind/install.sh /ci/install-valgrind.sh
ARG VALGRIND_VERSION
ARG VALGRIND_SHA256
RUN PATH="/ci/bin:$PATH" VERSION="$VALGRIND_VERSION" SHA256="$VALGRIND_SHA256" \
        bash /ci/install-valgrind.sh \
    && rm -rf "${RUNNER_TEMP:?}"/* \
    && { echo "VALGRIND=$HOME/valgrind-inst/bin/valgrind"; \
         echo "VALGRIND_INCLUDE=$HOME/valgrind-inst/include"; } >> "$GITHUB_ENV"
