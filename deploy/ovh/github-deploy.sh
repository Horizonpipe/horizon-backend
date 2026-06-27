#!/usr/bin/env bash
# Pull latest main for backend + frontend and reload PM2 (GitHub push or manual deploy).
set -euo pipefail

REPO_ROOT="${HP_REPO_ROOT:-/opt/horizon}"
BACKEND="${HP_BACKEND_DIR:-$REPO_ROOT/horizon-backend}"
FRONTEND="${HP_FRONTEND_DIR:-$REPO_ROOT/horizon-frontend}"
BACKEND_KEY="${HP_BACKEND_DEPLOY_KEY:-$REPO_ROOT/.ssh/github_ovh_deploy}"
FRONTEND_KEY="${HP_FRONTEND_DEPLOY_KEY:-$REPO_ROOT/.ssh/github_ovh_frontend}"
BRANCH="${HP_OVH_DEPLOY_BRANCH:-main}"
PM2_USER="${HP_PM2_USER:-ubuntu}"

run_as_deploy_user() {
  if [[ "$(id -un)" == "$PM2_USER" ]]; then
    "$@"
  else
    sudo -u "$PM2_USER" "$@"
  fi
}

git_fetch_reset() {
  local label="$1"
  local dir="$2"
  local key="$3"
  if [[ ! -f "$key" ]]; then
    echo "[github-deploy] missing deploy key: $key (run deploy/ovh/setup-github-deploy-keys.sh)" >&2
    exit 1
  fi
  echo "[github-deploy] $label -> origin/$BRANCH"
  run_as_deploy_user env GIT_SSH_COMMAND="ssh -i ${key} -o IdentitiesOnly=yes -o StrictHostKeyChecking=accept-new" \
    git -C "$dir" fetch origin "$BRANCH"
  run_as_deploy_user git -C "$dir" reset --hard "origin/$BRANCH"
}

git_fetch_reset backend "$BACKEND" "$BACKEND_KEY"
run_as_deploy_user bash -lc "cd '$BACKEND' && npm install --omit=dev"

git_fetch_reset frontend "$FRONTEND" "$FRONTEND_KEY"

echo "[github-deploy] pm2 reload"
run_as_deploy_user bash -lc "cd '$BACKEND' && pm2 reload deploy/ovh/ecosystem.config.cjs --update-env && pm2 save"

echo "[github-deploy] done $(date -u +%Y-%m-%dT%H:%M:%SZ)"
