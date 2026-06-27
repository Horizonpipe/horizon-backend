#!/usr/bin/env bash
# Pull latest main for backend + frontend and reload PM2 (GitHub push or manual deploy).
set -euo pipefail

REPO_ROOT="${HP_REPO_ROOT:-/opt/horizon}"
BACKEND="${HP_BACKEND_DIR:-$REPO_ROOT/horizon-backend}"
FRONTEND="${HP_FRONTEND_DIR:-$REPO_ROOT/horizon-frontend}"
BRANCH="${HP_OVH_DEPLOY_BRANCH:-main}"
PM2_USER="${HP_PM2_USER:-ubuntu}"

echo "[github-deploy] backend → origin/$BRANCH"
cd "$BACKEND"
git fetch origin "$BRANCH"
git reset --hard "origin/$BRANCH"
npm install --omit=dev

echo "[github-deploy] frontend → origin/$BRANCH"
cd "$FRONTEND"
git fetch origin "$BRANCH"
git reset --hard "origin/$BRANCH"

echo "[github-deploy] pm2 reload"
if id "$PM2_USER" &>/dev/null; then
  sudo -u "$PM2_USER" bash -lc "cd '$BACKEND' && pm2 reload deploy/ovh/ecosystem.config.cjs --update-env && pm2 save"
else
  cd "$BACKEND"
  pm2 reload deploy/ovh/ecosystem.config.cjs --update-env || pm2 restart horizon-backend --update-env
  pm2 save || true
fi

echo "[github-deploy] done $(date -u +%Y-%m-%dT%H:%M:%SZ)"
