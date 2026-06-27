#!/usr/bin/env bash
# One-shot: pull latest main, enable OVH ops, reload PM2.
set -euo pipefail

REPO_ROOT="/opt/horizon"
BACKEND="$REPO_ROOT/horizon-backend"
FRONTEND="$REPO_ROOT/horizon-frontend"
DEPLOY_KEY="$REPO_ROOT/.ssh/github_ovh_deploy"
WEBHOOK_SECRET="${GITHUB_WEBHOOK_SECRET:-hp-ovh-webhook-$(openssl rand -hex 24)}"

export GIT_SSH_COMMAND="ssh -i ${DEPLOY_KEY} -o IdentitiesOnly=yes -o StrictHostKeyChecking=accept-new"

mkdir -p /var/log/horizon
touch /var/log/horizon/ops-events.jsonl
chown ubuntu:ubuntu /var/log/horizon /var/log/horizon/ops-events.jsonl 2>/dev/null || true

ssh-keyscan -t ed25519 github.com >> ~/.ssh/known_hosts 2>/dev/null || true

echo "[deploy] backend pull"
cd "$BACKEND"
git fetch origin main
git reset --hard origin/main
npm install --omit=dev

echo "[deploy] frontend pull"
cd "$FRONTEND"
git fetch origin main
git reset --hard origin/main

chmod +x "$BACKEND/deploy/ovh/"*.sh 2>/dev/null || true

ENV_FILE="$BACKEND/.env"
if [[ -f "$ENV_FILE" ]]; then
  grep -q '^HP_OVH_OPS_ENABLED=' "$ENV_FILE" || echo 'HP_OVH_OPS_ENABLED=1' >> "$ENV_FILE"
  if grep -q '^GITHUB_WEBHOOK_SECRET=' "$ENV_FILE"; then
    echo "[deploy] GITHUB_WEBHOOK_SECRET already set"
  else
    echo "GITHUB_WEBHOOK_SECRET=${WEBHOOK_SECRET}" >> "$ENV_FILE"
    echo "[deploy] wrote GITHUB_WEBHOOK_SECRET=${WEBHOOK_SECRET}"
  fi
  grep -q '^HP_REPO_ROOT=' "$ENV_FILE" || echo 'HP_REPO_ROOT=/opt/horizon' >> "$ENV_FILE"
else
  echo "[deploy] WARNING: .env missing"
fi

echo "[deploy] pm2 reload"
cd "$BACKEND"
pm2 reload deploy/ovh/ecosystem.config.cjs --update-env 2>/dev/null || pm2 reload horizon-backend --update-env
pm2 save

echo "[deploy] done $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "WEBHOOK_URL=http://40.160.72.39/ops/webhook/github"
grep '^GITHUB_WEBHOOK_SECRET=' "$ENV_FILE" | sed 's/=.*/=***/' || true
