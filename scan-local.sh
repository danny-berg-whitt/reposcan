#!/usr/bin/env bash
set -euo pipefail
# Requires: git, python3, pip, docker (optional for gitleaks), ripgrep
# Install (example): pip3 install detect-secrets truffleHog
#                  sudo apt-get install ripgrep

# Ensure full history available
git fetch --all --tags --prune

# gitleaks (via docker)
docker run --rm -v "$(pwd)":/repo zricethezav/gitleaks:latest detect --source=/repo --report-path=gitleaks-report.json || true

# detect-secrets
detect-secrets scan --all-files > .secrets.baseline || true

# truffleHog
trufflehog filesystem --directory "$(pwd)" --json > trufflehog-report.json || true

# ripgrep keyword scan
rg -n --hidden --no-ignore-vcs -S "(password|passwd|pwd|secret|api[_-]?key|apikey|token|auth|access[_-]?key|aws|BEGIN RSA PRIVATE KEY|-----BEGIN PRIVATE KEY-----|google-services|GoogleService-Info|client_secret|firebase|keystore|\.p12|\.jks|.pem|.key)" . > rg-findings.txt || true

# git object size info
git rev-list --objects --all > all_objs.txt || true
git gc --aggressive --prune=now || true
if ls .git/objects/pack/pack-*.idx 1> /dev/null 2>&1; then
  git verify-pack -v .git/objects/pack/pack-*.idx 2>/dev/null | sort -k3 -n | tail -n 50 > largest-blobs.txt || true
fi

echo "Reports: gitleaks-report.json, .secrets.baseline, trufflehog-report.json, rg-findings.txt, all_objs.txt, largest-blobs.txt"