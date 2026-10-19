#!/usr/bin/env bash
# ffmpeg builds the PipeShare preview ladder (light HLS + original copy).
# github-deploy.sh installs it when missing. Run this by hand on a new host.
set -euo pipefail
if command -v ffmpeg >/dev/null 2>&1 && command -v ffprobe >/dev/null 2>&1; then
  ffmpeg -version | head -n 1
  exit 0
fi
apt-get update -qq
apt-get install -y ffmpeg
ffmpeg -version | head -n 1
ffprobe -version | head -n 1
