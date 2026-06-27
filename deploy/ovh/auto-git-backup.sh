#!/usr/bin/env bash
# Auto-commit and push server changes to GitHub (ovh-live branch).
# Safe to run from cron every few minutes.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG="${GIT_BACKUP_CONFIG:-/etc/horizon/git-backup.env}"
LOG="${GIT_BACKUP_LOG:-/var/log/horizon/git-backup.log}"

mkdir -p "$(dirname "$LOG")"

log() {
  echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] $*" | tee -a "$LOG"
}

if [[ ! -f "$CONFIG" ]]; then
  log "missing $CONFIG — run: sudo bash $SCRIPT_DIR/install-git-backup.sh"
  exit 1
fi

# shellcheck disable=SC1090
source "$CONFIG"

: "${GIT_BACKUP_BRANCH:=ovh-live}"
: "${GIT_SSH_KEY:=/opt/horizon/.ssh/github_ovh_deploy}"
: "${GIT_AUTHOR_NAME:="OVH Horizon Backup"}"
: "${GIT_AUTHOR_EMAIL:=ovh-backup@horizonpipe.local}"

export GIT_SSH_COMMAND="ssh -i ${GIT_SSH_KEY} -o IdentitiesOnly=yes -o StrictHostKeyChecking=accept-new"

backup_one_repo() {
  local dir="$1"
  local remote_url="$2"
  local label="$3"

  if [[ ! -d "$dir" ]]; then
    log "[$label] skip — missing $dir"
    return 0
  fi

  if [[ ! -d "$dir/.git" ]]; then
    log "[$label] skip — not initialized (run install-git-backup.sh)"
    return 0
  fi

  cd "$dir"
  git config user.name "$GIT_AUTHOR_NAME"
  git config user.email "$GIT_AUTHOR_EMAIL"

  if ! git remote get-url origin >/dev/null 2>&1; then
    git remote add origin "$remote_url"
  fi

  current_branch="$(git branch --show-current 2>/dev/null || true)"
  if [[ "$current_branch" != "$GIT_BACKUP_BRANCH" ]]; then
    if git show-ref --verify --quiet "refs/heads/$GIT_BACKUP_BRANCH"; then
      git checkout "$GIT_BACKUP_BRANCH"
    else
      git checkout -b "$GIT_BACKUP_BRANCH"
    fi
  fi

  git add -A
  if git diff --cached --quiet; then
    log "[$label] no changes"
    return 0
  fi

  shortstat="$(git diff --cached --shortstat | tr -d '\n')"
  git commit -m "ovh auto-backup $(date -u +%Y-%m-%dT%H:%M:%SZ) ${shortstat:-}"

  if git push -u origin "$GIT_BACKUP_BRANCH" 2>>"$LOG"; then
    log "[$label] pushed $(git rev-parse --short HEAD) → origin/$GIT_BACKUP_BRANCH"
  else
    log "[$label] push failed — check deploy key on GitHub (see install-git-backup.sh output)"
    return 1
  fi
}

backup_one_repo "${BACKEND_DIR:-/opt/horizon/horizon-backend}" \
  "${GITHUB_BACKEND_URL:-git@github.com:Horizonpipe/horizon-backend.git}" \
  "backend"

backup_one_repo "${FRONTEND_DIR:-/opt/horizon/horizon-frontend}" \
  "${GITHUB_FRONTEND_URL:-git@github.com:Horizonpipe/horizon-frontend.git}" \
  "frontend"
