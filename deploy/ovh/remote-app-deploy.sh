#!/usr/bin/env bash
set -euo pipefail
cd /opt/horizon/horizon-backend
npm install --omit=dev
PG_PASS=$(sudo cat /root/.horizon_pg_pass)
LOCAL_URL="postgresql://horizon:${PG_PASS}@127.0.0.1:5432/horizon"
if [[ -n "${RENDER_DATABASE_URL:-}" ]]; then
  echo "Migrating Postgres from Render..."
  DUMP="/var/backups/horizon/postgres/render-migrate-$(date +%Y%m%d-%H%M%S).dump"
  pg_dump "$RENDER_DATABASE_URL" --format=custom --no-owner --no-acl --file="$DUMP"
  pg_restore --dbname="$LOCAL_URL" --clean --if-exists --no-owner --no-acl "$DUMP" || true
  psql "$LOCAL_URL" -c "SELECT COUNT(*) AS users FROM users;" || true
fi
PUBLIC="${PUBLIC_ORIGIN:-http://40.160.72.39}"
cat > /opt/horizon/horizon-backend/.env <<EOF
NODE_ENV=production
PORT=3000
DATABASE_URL=${LOCAL_URL}
DATABASE_SSL=0
PG_POOL_MAX=20
FRONTEND_STATIC_DIR=/opt/horizon/horizon-frontend
CORS_ORIGINS=${PUBLIC}
SAAS_CPANEL_BASE_URL=${PUBLIC}
SAAS_SKIP_SUBSCRIPTION_CHECK=1
SAAS_SKIP_WASABI_PROVISION=1
PORTAL_PROXY_FILE_DOWNLOAD=0
PORTAL_UPLOAD_PRESIGN=1
PORTAL_RESUMABLE_PROXY_CHUNK=0
WASABI_STATE_ARCHIVE_SNAPSHOTS=0
WASABI_STATE_SNAPSHOT_GZIP=1
WASABI_STATE_SNAPSHOT_MS=3600000
WASABI_SQL_MIRROR_ENABLED=0
STRIPE_SECRET_KEY=${STRIPE_SECRET_KEY:-}
STRIPE_WEBHOOK_SECRET=${STRIPE_WEBHOOK_SECRET:-}
STRIPE_PRICE_ID=${STRIPE_PRICE_ID:-}
STRIPE_SUCCESS_URL=${PUBLIC}/horizonpipe-cpanel/billing.html?billing=success
STRIPE_CANCEL_URL=${PUBLIC}/horizonpipe-cpanel/billing.html?billing=canceled
STRIPE_PORTAL_RETURN_URL=${PUBLIC}/horizonpipe-cpanel/billing.html
EOF
chmod 600 /opt/horizon/horizon-backend/.env
chown ubuntu:ubuntu /opt/horizon/horizon-backend/.env
sudo -u ubuntu pm2 delete horizon-backend 2>/dev/null || true
sudo -u ubuntu bash -lc 'cd /opt/horizon/horizon-backend && pm2 start server.js --name horizon-backend -i 4 --max-memory-restart 1500M'
sudo -u ubuntu pm2 save
sudo env PATH="$PATH:/usr/bin" pm2 startup systemd -u ubuntu --hp /home/ubuntu >/dev/null 2>&1 || true
echo APP_READY
