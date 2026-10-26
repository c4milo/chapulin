#!/bin/bash
# Download the packages first, each attempt under a time limit, then
# install them from the local cache. A download that stalls is stopped and
# tried again on a new connection. The limit never stops dpkg itself,
# because an install stopped part way leaves the package database locked.
# Reads PACKAGES from the environment that action.yml sets.
set -euo pipefail

read -ra names <<<"$PACKAGES"
apt=(sudo apt-get -y -q --no-install-recommends
  -o Acquire::Retries=3 -o Acquire::http::Timeout=30)

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
done
"${apt[@]}" install "${names[@]}"
