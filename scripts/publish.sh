#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
command -v gh >/dev/null || { echo 'Install GitHub CLI first: https://cli.github.com'; exit 1; }
gh auth status
if [ ! -d .git ]; then
  git init -b main
  git add .
  git commit -m "Implement evidence-oriented passive scan v9"
fi
gh repo create ohjun1998/passive-scan_v9_pub --public --source=. --remote=origin --push
