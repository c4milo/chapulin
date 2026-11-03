#!/bin/bash
# Download apt.llvm.org's signing key, check it against the pinned hash,
# add it as a keyring, name the repository of the pinned major for the
# runner's Ubuntu release under that keyring, then install clang and
# ld.lld of that major and the extra packages the job asked for. Reads
# MAJOR, SHA256 and the WITH_* flags from the environment that action.yml
# sets from its inputs.
#
# llvm.sh did this before, and it added the key with apt-key, which
# ubuntu-26.04 does not carry; a keyring named in the source works on both
# releases the workflows run.
set -euo pipefail

# apt.llvm.org did not answer for a few minutes on 2026-11-03, which
# failed four jobs of one run. So the download and apt retry.
wget -q --tries=5 --waitretry=15 --retry-connrefused --timeout=30 -O "$RUNNER_TEMP/llvm-snapshot.gpg.key" https://apt.llvm.org/llvm-snapshot.gpg.key
echo "$SHA256  $RUNNER_TEMP/llvm-snapshot.gpg.key" | sha256sum -c -
sudo install -d -m 0755 /etc/apt/keyrings
sudo gpg --dearmor --yes -o /etc/apt/keyrings/apt.llvm.org.gpg "$RUNNER_TEMP/llvm-snapshot.gpg.key"
codename=$(sed -n 's/^VERSION_CODENAME=//p' /etc/os-release)
[ -n "$codename" ] || { echo "install-llvm: /etc/os-release names no VERSION_CODENAME" >&2; exit 1; }
echo "deb [signed-by=/etc/apt/keyrings/apt.llvm.org.gpg] https://apt.llvm.org/$codename/ llvm-toolchain-$codename-$MAJOR main" |
  sudo tee /etc/apt/sources.list.d/apt.llvm.org.list > /dev/null
sudo apt-get -o Acquire::Retries=5 update -q
sudo apt-get -o Acquire::Retries=5 install -y "clang-$MAJOR" "lld-$MAJOR"

packages=()
if [ "$WITH_CLANG_TIDY" = true ]; then
  packages+=("clang-tidy-$MAJOR")
fi
if [ "$WITH_CLANG_FORMAT" = true ]; then
  packages+=("clang-format-$MAJOR")
fi
if [ "$WITH_LLVM" = true ]; then
  # llvm-<major> carries llvm-nm, which lint-runtime-symbols reads the
  # rv32ic objects with. clang alone does not pull it in.
  packages+=("llvm-$MAJOR")
fi
if [ "${#packages[@]}" -gt 0 ]; then
  sudo apt-get -o Acquire::Retries=5 install -y "${packages[@]}"
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
