#!/bin/bash
# Download llvm.sh, check it against the pinned hash, run it for the
# pinned major, then install the extra packages the job asked for.
# Reads MAJOR, SHA256 and the WITH_* flags from the environment that
# action.yml sets from its inputs.
set -euo pipefail

wget -qO "$RUNNER_TEMP/llvm.sh" https://apt.llvm.org/llvm.sh
echo "$SHA256  $RUNNER_TEMP/llvm.sh" | sha256sum -c -
sudo bash "$RUNNER_TEMP/llvm.sh" "$MAJOR"

packages=()
if [ "$WITH_CLANG_TIDY" = true ]; then
  packages+=("clang-tidy-$MAJOR")
fi
if [ "$WITH_CLANG_FORMAT" = true ]; then
  packages+=("clang-format-$MAJOR")
fi
if [ "$WITH_LLVM" = true ]; then
  # llvm-<major> carries llvm-nm, which lint-runtime-symbols reads the
  # rv32ic objects with. llvm.sh alone does not install it.
  packages+=("llvm-$MAJOR")
fi
if [ "${#packages[@]}" -gt 0 ]; then
  sudo apt-get install -y "${packages[@]}"
fi

# apt.llvm.org installs the versioned names, so the Makefile's variables
# are spelled with the major appended. The codegen lints disassemble what
# CLANG_RV emits, so it has to be the pinned compiler: unset, it once fell
# back to the runner image's default clang and lint-wide-multiply read a
# different lowering than the development machine.
{
  echo "CLANG_RV=clang-$MAJOR"
  if [ "$WITH_CLANG_TIDY" = true ]; then
    echo "CLANG_TIDY=clang-tidy-$MAJOR"
  fi
  if [ "$WITH_CLANG_FORMAT" = true ]; then
    echo "CLANG_FORMAT=clang-format-$MAJOR"
  fi
} >> "$GITHUB_ENV"
