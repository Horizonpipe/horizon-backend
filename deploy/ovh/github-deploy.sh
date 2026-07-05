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

# Production .env must never come from git (even if accidentally tracked). Preserve across reset.
preserve_backend_env() {
  local env_file="$BACKEND/.env"
  local stash="/tmp/horizon-backend-env.stash.$$"
  if [[ -s "$env_file" ]] && grep -q '^DATABASE_URL=' "$env_file" 2>/dev/null; then
    cp "$env_file" "$stash"
    echo "[github-deploy] stashed valid .env ($(grep -cE '^[A-Z]' "$env_file") keys)"
  fi
  git_fetch_reset backend "$BACKEND" "$BACKEND_KEY"
  if [[ -f "$stash" ]]; then
    cp "$stash" "$env_file"
    chmod 600 "$env_file"
    chown "${PM2_USER}:${PM2_USER}" "$env_file" 2>/dev/null || true
    rm -f "$stash"
    echo "[github-deploy] restored stashed .env after git reset"
  fi
  run_as_deploy_user bash -lc "cd '$BACKEND' && npm install --omit=dev"
}

preserve_backend_env

git_fetch_reset frontend "$FRONTEND" "$FRONTEND_KEY"

# Never overwrite production secrets — git pull must not touch .env (gitignored).
if [[ ! -s "$BACKEND/.env" ]] || ! grep -q '^DATABASE_URL=' "$BACKEND/.env" 2>/dev/null; then
  echo "[github-deploy] ERROR: $BACKEND/.env missing or invalid (no DATABASE_URL)." >&2
  echo "[github-deploy] Restore: sudo bash deploy/ovh/restore-production-env.sh" >&2
  exit 1
fi

echo "[github-deploy] pm2 reload"
if sudo pm2 describe horizon-backend &>/dev/null; then
  echo "[github-deploy] using root PM2 (production listener on :3000)"
  sudo bash -lc "cd '$BACKEND' && pm2 reload deploy/ovh/ecosystem.config.cjs --update-env && pm2 save"
  if run_as_deploy_user pm2 describe horizon-backend &>/dev/null; then
    echo "[github-deploy] stopping duplicate ${PM2_USER} PM2 horizon-backend"
    run_as_deploy_user pm2 stop horizon-backend || true
    run_as_deploy_user pm2 save || true
  fi
else
  run_as_deploy_user bash -lc "cd '$BACKEND' && pm2 reload deploy/ovh/ecosystem.config.cjs --update-env && pm2 save"
fi

echo "[github-deploy] done $(date -u +%Y-%m-%dT%H:%M:%SZ)"
