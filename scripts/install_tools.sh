#!/usr/bin/env bash
set -euo pipefail
# First installation resolves current versions; the exact resolved Go versions are
# saved in state/tools.lock.json and reused on subsequent runs. Review before updating.
mkdir -p state
python3 scripts/install_go_tools.py
if [ -n "${GITHUB_PATH:-}" ]; then
  go env GOPATH | awk '{print $0 "/bin"}' >> "$GITHUB_PATH"
fi
# TruffleHog is optional. Install its reviewed release independently:
# https://github.com/trufflesecurity/trufflehog/releases
# No downloaded installer is piped into a shell.
