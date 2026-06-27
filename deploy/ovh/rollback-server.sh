#!/usr/bin/env bash
# Roll back server files from Git history (ovh-live branch).
#
# Usage:
#   rollback-server.sh backend list              # show recent commits
#   rollback-server.sh frontend list
#   rollback-server.sh backend HEAD~1            # roll back one commit
#   rollback-server.sh backend abc1234           # roll back to hash
#   rollback-server.sh both HEAD~2               # both repos
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG="${GIT_BACKUP_CONFIG:-/etc/horizon/git-backup.env}"

if [[ ! -f "$CONFIG" ]]; then
  echo "Missing $CONFIG — run install-git-backup.sh first" >&2
  exit 1
fi
# shellcheck disable=SC1090
source "$CONFIG"

export GIT_SSH_COMMAND="ssh -i ${GIT_SSH_KEY} -o IdentitiesOnly=yes -o StrictHostKeyChecking=accept-new"

dir_for() {
  case "$1" in
    backend) echo "${BACKEND_DIR:-/opt/horizon/horizon-backend}" ;;
    frontend) echo "${FRONTEND_DIR:-/opt/horizon/horizon-frontend}" ;;
    *) echo "unknown repo: $1 (use backend|frontend|both)" >&2; exit 1 ;;
  esac
}

rollback_repo() {
  local label="$1"
  local ref="$2"
  local dir
  dir="$(dir_for "$label")"

  if [[ ! -d "$dir/.git" ]]; then
    echo "[$label] not a git repo: $dir" >&2
    return 1
  fi

  cd "$dir"
  git checkout "${GIT_BACKUP_BRANCH:-ovh-live}" 2>/dev/null || true

  if [[ "$ref" == "list" ]]; then
    echo "=== $label ($dir) — recent ovh-live commits ==="
    git log --oneline -20
    return 0
  fi

  echo "[$label] rolling back to $ref …"
  git reset --hard "$ref"
  echo "[$label] now at $(git rev-parse --short HEAD) $(git log -1 --format=%s)"
}

TARGET="${1:-}"
REF="${2:-list}"

if [[ -z "$TARGET" ]]; then
  echo "Usage: $0 {backend|frontend|both} {list|HEAD~N|commit-hash}" >&2
  exit 1
fi

if [[ "$TARGET" == "both" ]]; then
  rollback_repo backend "$REF"
  rollback_repo frontend "$REF"
  echo "[both] restarting horizon-backend …"
  pm2 restart horizon-backend --update-env || true
else
  rollback_repo "$TARGET" "$REF"
  if [[ "$TARGET" == "backend" && "$REF" != "list" ]]; then
    echo "[backend] restarting horizon-backend …"
    pm2 restart horizon-backend --update-env || true
  fi
fi

echo "Done. Verify: pm2 logs horizon-backend --lines 20"
