#!/bin/bash
# Download the packages first, each attempt under a time limit, then
# install them from the local archive directory. A download that stalls is
# stopped and tried again on a new connection. The limit never stops dpkg
# itself, because an install stopped part way leaves the package database
# locked. The third attempt reads archive.ubuntu.com in place of the
# runner image's Azure mirror: on 2026-11-06 that mirror sent qemu-user
# at under 50 kB/s in all three attempts, twice. Reads PACKAGES and ARCHIVES from the environment that action.yml
# sets; ARCHIVES is the directory the Actions cache keeps.
set -euo pipefail

read -ra names <<<"$PACKAGES"
mkdir -p "$ARCHIVES/partial"
apt=(sudo apt-get -y -q --no-install-recommends
  -o Acquire::Retries=3 -o Acquire::http::Timeout=30
  -o "Dir::Cache::archives=$ARCHIVES/")

# Points apt at archive.ubuntu.com where a source names the Azure mirror,
# and reads the new indexes. An image with no Azure source keeps its own.
switch_mirror() {
  local sources
  sources=$(grep -rl 'azure\.archive\.ubuntu\.com' /etc/apt/sources.list /etc/apt/sources.list.d 2>/dev/null || true)
  if [ -z "$sources" ]; then
    return 0
  fi
  echo "apt-install: the third attempt reads archive.ubuntu.com" >&2
  while read -r file; do
    sudo sed -i 's/azure\.archive\.ubuntu\.com/archive.ubuntu.com/g' "$file"
  done <<<"$sources"
  sudo apt-get update -q
}

sudo apt-get update -q
for attempt in 1 2 3; do
  if timeout 300 "${apt[@]}" install --download-only "${names[@]}"; then
    break
  fi
  if [ "$attempt" = 3 ]; then
    echo "apt-install: the download did not finish in three attempts" >&2
    exit 1
  fi
  echo "apt-install: attempt $attempt of the download stopped, trying again" >&2
  if [ "$attempt" = 2 ]; then
    switch_mirror
  fi
done
"${apt[@]}" install "${names[@]}"

# apt writes the directory as root, and its lock file is readable by root
# alone, so the cache step that saves the directory after the job could
# not read it.
sudo rm -rf "$ARCHIVES/lock" "$ARCHIVES/partial"
sudo chown -R "$(id -u):$(id -g)" "$ARCHIVES"
