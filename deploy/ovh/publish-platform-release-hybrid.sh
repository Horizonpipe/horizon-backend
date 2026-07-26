#!/usr/bin/env bash
# Temporarily flip HP_DEPLOYMENT_MODE for publish on hybrid OVH host, then restore.
set -euo pipefail
ENV=/opt/horizon/horizon-backend/.env
BACKEND=/opt/horizon/horizon-backend
STASH="/tmp/hp-env-publish-stash.$$"
PM2_USER="${HP_PM2_USER:-ubuntu}"
cp "$ENV" "$STASH"
sed -i 's/^HP_DEPLOYMENT_MODE=.*/HP_DEPLOYMENT_MODE=non-saas/' "$ENV"
cd "$BACKEND"
bash deploy/ovh/publish-platform-release.sh
PUBLISH_EXIT=$?
cp "$STASH" "$ENV"
rm -f "$STASH"
chmod 600 "$ENV"
# Always use the app user's PM2 — never root's (/root/.pm2), which steals port 3000.
if [[ "$(id -un)" == "$PM2_USER" ]]; then
  pm2 reload horizon-backend --update-env || true
else
  sudo -u "$PM2_USER" pm2 reload horizon-backend --update-env || true
fi
exit "$PUBLISH_EXIT"
