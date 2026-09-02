#!/usr/bin/env bash
# Runs the riscv32 CI lane locally: the cross-check roster built with
# Bootlin's pinned riscv32 toolchain and run under qemu-riscv32 user
# mode, inside an x86_64 ubuntu container (the toolchain ships x86_64
# host binaries). Mirrors the riscv32 job in
# .github/workflows/check.yml; tools/toolchain.env pins the toolchain
# and the container. The toolchain download lands in bin/rv32tc-docker
# and is reused. Needs docker (OrbStack works); skips without it.
set -euo pipefail

if [ "${1:-}" != "--inside" ]; then
    cd "$(dirname "$0")/.."
    # shellcheck source=tools/toolchain.env
    . tools/toolchain.env
    command -v docker >/dev/null 2>&1 || {
        echo "SKIP riscv32 local lane: docker not available" >&2
        exit 0
    }
    exec docker run --rm --platform linux/amd64 \
        -e "RV32_TC_VERSION=$RV32_TC_VERSION" \
        -e "RV32_TC_SHA256=$RV32_TC_SHA256" \
        -v "$PWD":/src -w /src "ubuntu@$UBUNTU_DIGEST" \
        bash /src/test/docker-riscv32.sh --inside
fi

# ---- inside the container from here on ----
export DEBIAN_FRONTEND=noninteractive
apt-get update -q >/dev/null
apt-get install -y -q make python3 git ca-certificates curl xz-utils \
    qemu-user >/dev/null

tc=/src/bin/rv32tc-docker
name="riscv32-ilp32d--musl--${RV32_TC_VERSION:?}"
if [ ! -x "$tc/$name/bin/riscv32-linux-gcc" ]; then
    url="https://toolchains.bootlin.com/downloads/releases/toolchains/riscv32-ilp32d/tarballs/${name}.tar.xz"
    curl -sSL -o /tmp/rv32tc.tar.xz "$url"
    echo "${RV32_TC_SHA256:?}  /tmp/rv32tc.tar.xz" | sha256sum -c -
    mkdir -p "$tc"
    tar -xJf /tmp/rv32tc.tar.xz -C "$tc"
fi

# The same two steps the CI job runs, in its order: the codegen gate under
# this gcc, then the suites.
make lint-wide-multiply-gcc WIDEMUL_GCC="$tc/$name/bin/riscv32-linux-gcc"
make cross-check CROSS="$tc/$name/bin/riscv32-linux-" RUNNER=qemu-riscv32
