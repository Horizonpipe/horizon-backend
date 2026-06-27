#!/usr/bin/env bash
# Roll back horizon-backend / horizon-frontend on main branch (not ovh-live backup branch).
# Usage: rollback-main.sh {backend|frontend|both} {HEAD~1|commit-hash}
set -euo pipefail

TARGET="${1:-both}"
REF="${2:-HEAD~1}"
REPO_ROOT="${HP_REPO_ROOT:-/opt/horizon}"
BACKEND="${HP_BACKEND_DIR:-$REPO_ROOT/horizon-backend}"
FRONTEND="${HP_FRONTEND_DIR:-$REPO_ROOT/horizon-frontend}"
PM2_USER="${HP_PM2_USER:-ubuntu}"

rollback_one() {
  local label="$1"
  local dir="$2"
  echo "[$label] rollback $dir → $REF"
  cd "$dir"
  git fetch origin main
  git checkout main 2>/dev/null || git checkout -B main origin/main
  git reset --hard "$REF"
  echo "[$label] now at $(git rev-parse --short HEAD) $(git log -1 --format=%s)"
}

case "$TARGET" in
  backend) rollback_one backend "$BACKEND" ;;
  frontend) rollback_one frontend "$FRONTEND" ;;
  both)
    rollback_one backend "$BACKEND"
    rollback_one frontend "$FRONTEND"
    ;;
  *) echo "unknown target: $TARGET (use backend|frontend|both)" >&2; exit 1 ;;
esac

if [[ "$TARGET" == "backend" || "$TARGET" == "both" ]]; then
  echo "[rollback] npm install (backend)"
  cd "$BACKEND"
  npm install --omit=dev
fi

echo "[rollback] pm2 reload"
if id "$PM2_USER" &>/dev/null; then
  sudo -u "$PM2_USER" bash -lc "cd '$BACKEND' && pm2 reload deploy/ovh/ecosystem.config.cjs --update-env && pm2 save"
else
  cd "$BACKEND"
  pm2 reload deploy/ovh/ecosystem.config.cjs --update-env || pm2 restart horizon-backend --update-env
  pm2 save || true
fi

echo "[rollback] done"
