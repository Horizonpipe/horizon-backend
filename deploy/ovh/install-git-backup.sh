#!/usr/bin/env bash
# One-time setup: git init, deploy key, cron for auto Git backups.
# Run as root: sudo bash deploy/ovh/install-git-backup.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG="/etc/horizon/git-backup.env"
SSH_DIR="/opt/horizon/.ssh"
DEPLOY_KEY="$SSH_DIR/github_ovh_deploy"
CRON_USER="${GIT_BACKUP_USER:-ubuntu}"
LOG_DIR="/var/log/horizon"
GITIGNORE_SNIPPET="$SCRIPT_DIR/server-gitignore.snippet"

mkdir -p /etc/horizon "$SSH_DIR" "$LOG_DIR"
chmod 700 /etc/horizon "$SSH_DIR"

if [[ ! -f "$DEPLOY_KEY" ]]; then
  echo "[git-backup] generating deploy key → $DEPLOY_KEY"
  ssh-keygen -t ed25519 -f "$DEPLOY_KEY" -N "" -C "ovh-horizon-git-backup"
fi
chmod 600 "$DEPLOY_KEY"
chown -R "$CRON_USER:$CRON_USER" "$SSH_DIR"

cat >"$CONFIG" <<'EOF'
# OVH → GitHub auto-backup (ovh-live branch). Do not commit secrets — .env is gitignored.
GIT_BACKUP_BRANCH=ovh-live
GIT_SSH_KEY=/opt/horizon/.ssh/github_ovh_deploy
GIT_AUTHOR_NAME="OVH Horizon Backup"
GIT_AUTHOR_EMAIL=ovh-backup@horizonpipe.local
GITHUB_BACKEND_URL=git@github.com:Horizonpipe/horizon-backend.git
GITHUB_FRONTEND_URL=git@github.com:Horizonpipe/horizon-frontend.git
BACKEND_DIR=/opt/horizon/horizon-backend
FRONTEND_DIR=/opt/horizon/horizon-frontend
EOF
chmod 600 "$CONFIG"

ensure_gitignore() {
  local dir="$1"
  [[ -d "$dir" ]] || return 0
  if [[ -f "$GITIGNORE_SNIPPET" ]]; then
    if [[ ! -f "$dir/.gitignore" ]]; then
      cp "$GITIGNORE_SNIPPET" "$dir/.gitignore"
    else
      while IFS= read -r line || [[ -n "$line" ]]; do
        [[ -z "$line" || "$line" =~ ^# ]] && continue
        grep -qxF "$line" "$dir/.gitignore" 2>/dev/null || echo "$line" >>"$dir/.gitignore"
      done <"$GITIGNORE_SNIPPET"
    fi
  fi
}

init_repo() {
  local dir="$1"
  local remote_url="$2"
  local label="$3"

  if [[ ! -d "$dir" ]]; then
    echo "[git-backup] skip $label — $dir missing"
    return 0
  fi

  ensure_gitignore "$dir"
  chown -R "$CRON_USER:$CRON_USER" "$dir/.gitignore" 2>/dev/null || true

  if [[ -d "$dir/.git" ]]; then
    echo "[git-backup] $label already has .git"
    return 0
  fi

  echo "[git-backup] init $label at $dir"
  sudo -u "$CRON_USER" git -C "$dir" init -b ovh-live
  sudo -u "$CRON_USER" git -C "$dir" remote add origin "$remote_url"
  sudo -u "$CRON_USER" git -C "$dir" config user.name "OVH Horizon Backup"
  sudo -u "$CRON_USER" git -C "$dir" config user.email "ovh-backup@horizonpipe.local"
  sudo -u "$CRON_USER" git -C "$dir" add -A
  sudo -u "$CRON_USER" git -C "$dir" commit -m "ovh-live initial snapshot $(date -u +%Y-%m-%dT%H:%M:%SZ)" || true
}

# shellcheck disable=SC1091
source "$CONFIG"
init_repo "$BACKEND_DIR" "$GITHUB_BACKEND_URL" "backend"
init_repo "$FRONTEND_DIR" "$GITHUB_FRONTEND_URL" "frontend"

CRON_FILE="/etc/cron.d/horizon-git-backup"
cat >"$CRON_FILE" <<EOF
SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# Auto Git backup every 10 minutes → origin/ovh-live
*/10 * * * * ${CRON_USER} bash ${SCRIPT_DIR}/auto-git-backup.sh >> ${LOG_DIR}/git-backup.log 2>&1
EOF
chmod 644 "$CRON_FILE"

chmod +x "$SCRIPT_DIR/auto-git-backup.sh" "$SCRIPT_DIR/rollback-server.sh" 2>/dev/null || true

echo ""
echo "══════════════════════════════════════════════════════════════"
echo " Git auto-backup installed (branch: ovh-live, every 10 min)"
echo "══════════════════════════════════════════════════════════════"
echo ""
echo "ONE-TIME: Add this deploy key to BOTH GitHub repos (write access):"
echo "  Horizonpipe/horizon-backend → Settings → Deploy keys → Add"
echo "  Horizonpipe/horizon-frontend → Settings → Deploy keys → Add"
echo ""
cat "${DEPLOY_KEY}.pub"
echo ""
echo "Then test push:"
echo "  sudo -u ${CRON_USER} bash ${SCRIPT_DIR}/auto-git-backup.sh"
echo ""
echo "Rollback on server:"
echo "  bash ${SCRIPT_DIR}/rollback-server.sh backend list"
echo "  bash ${SCRIPT_DIR}/rollback-server.sh backend HEAD~1"
echo ""
