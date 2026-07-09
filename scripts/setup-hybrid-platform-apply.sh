#!/usr/bin/env bash
# One-time hybrid OVH setup: manifest-only SaaS push + env flag.
set -euo pipefail

BACKEND="${HP_BACKEND_DIR:-/opt/horizon/horizon-backend}"
ENV_FILE="$BACKEND/.env"

if [[ ! -f "$ENV_FILE" ]]; then
  echo "missing $ENV_FILE" >&2
  exit 1
fi

if grep -q '^HP_PLATFORM_APPLY_MANIFEST_ONLY=' "$ENV_FILE"; then
  sed -i 's/^HP_PLATFORM_APPLY_MANIFEST_ONLY=.*/HP_PLATFORM_APPLY_MANIFEST_ONLY=1/' "$ENV_FILE"
else
  echo 'HP_PLATFORM_APPLY_MANIFEST_ONLY=1' >> "$ENV_FILE"
fi
chmod 600 "$ENV_FILE"
echo "[setup] HP_PLATFORM_APPLY_MANIFEST_ONLY=1 in $ENV_FILE"

for pid in $(ps -eo user=,pid=,args= | awk '$1=="root" && /node.*horizon-backend\/server.js/ {print $2}'); do
  echo "[setup] stopping orphan root node pid=$pid"
  kill "$pid" 2>/dev/null || true
done

cd "$BACKEND"
sudo -u ubuntu pm2 restart deploy/ovh/ecosystem.config.cjs --update-env
sudo -u ubuntu pm2 save
echo "[setup] pm2 restarted"
