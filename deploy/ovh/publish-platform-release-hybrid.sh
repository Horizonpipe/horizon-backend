#!/usr/bin/env bash
# Temporarily flip HP_DEPLOYMENT_MODE for publish on hybrid OVH host, then restore.
set -euo pipefail
ENV=/opt/horizon/horizon-backend/.env
BACKEND=/opt/horizon/horizon-backend
STASH="/tmp/hp-env-publish-stash.$$"
cp "$ENV" "$STASH"
sed -i 's/^HP_DEPLOYMENT_MODE=.*/HP_DEPLOYMENT_MODE=non-saas/' "$ENV"
cd "$BACKEND"
bash deploy/ovh/publish-platform-release.sh
PUBLISH_EXIT=$?
cp "$STASH" "$ENV"
rm -f "$STASH"
chmod 600 "$ENV"
# Never bare `pm2` here — that spawns /root/.pm2 and steals :3000 from ubuntu.
sudo -u ubuntu bash -lc 'cd /opt/horizon/horizon-backend && pm2 restart horizon-backend --update-env'
exit "$PUBLISH_EXIT"
