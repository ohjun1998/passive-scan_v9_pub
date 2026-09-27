#!/usr/bin/env bash
set -euo pipefail
# Explicit pinned version, official release + published checksum verification.
version=3.82.0
archive="trufflehog_${version}_linux_amd64.tar.gz"
checksums="trufflehog_${version}_checksums.txt"
base="https://github.com/trufflesecurity/trufflehog/releases/download/v${version}"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
curl --fail --location --retry 2 --output "$tmp/$archive" "$base/$archive"
curl --fail --location --retry 2 --output "$tmp/$checksums" "$base/$checksums"
(
  cd "$tmp"
  awk -v file="$archive" '$2==file {print}' "$checksums" > selected.sha256
  test -s selected.sha256
  sha256sum --check selected.sha256
  tar -xzf "$archive" trufflehog
)
mkdir -p "$HOME/.local/bin"
install -m 0755 "$tmp/trufflehog" "$HOME/.local/bin/trufflehog"
if [ -n "${GITHUB_PATH:-}" ]; then
  echo "$HOME/.local/bin" >> "$GITHUB_PATH"
fi
