#!/usr/bin/env bash
# Install AWS CLI v2 (for Wasabi S3-compatible uploads). Run as root.
set -euo pipefail

if command -v aws >/dev/null 2>&1; then
  echo "[awscli] already installed: $(aws --version 2>&1 | head -1)"
  exit 0
fi

if ! command -v unzip >/dev/null 2>&1; then
  apt-get update -qq && apt-get install -y unzip
fi

TMP="/tmp/awscli-install-$$"
mkdir -p "$TMP"
cd "$TMP"

echo "[awscli] downloading AWS CLI v2…"
curl -fsSL "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o awscliv2.zip
unzip -q awscliv2.zip
./aws/install --update
rm -rf "$TMP"

aws --version
echo "[awscli] installed"
