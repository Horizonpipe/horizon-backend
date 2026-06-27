#!/usr/bin/env bash
# Restore production .env on OVH after accidental overwrite (never commit .env).
# Base: /opt/horizon/horizon-backend.bak/.env (local Postgres + Stripe OVH URLs)
# Overlay: /tmp/render-env-restore.env (Wasabi, SESSION_SECRET, Outlook — from Render or backup)
#
# From your PC:
#   powershell deploy/ovh/export-render-env-for-restore.ps1
# On OVH:
#   sudo bash deploy/ovh/restore-production-env.sh
set -euo pipefail

ENV="${HP_BACKEND_ENV:-/opt/horizon/horizon-backend/.env}"
BAK="${HP_BACKEND_ENV_BAK:-/opt/horizon/horizon-backend.bak/.env}"
RENDER_EXTRA="${HP_RENDER_ENV_OVERLAY:-/tmp/render-env-restore.env}"
PM2_USER="${HP_PM2_USER:-ubuntu}"
BACKEND="${HP_BACKEND_DIR:-/opt/horizon/horizon-backend}"

if [[ ! -f "$BAK" ]]; then
  echo "missing backup $BAK" >&2
  exit 1
fi
if [[ ! -f "$RENDER_EXTRA" ]]; then
  echo "missing $RENDER_EXTRA — run export-render-env-for-restore.ps1 first" >&2
  exit 1
fi

cp "$ENV" "${ENV}.broken.$(date +%Y%m%d%H%M%S)" 2>/dev/null || true
cp "$BAK" "$ENV"

while IFS= read -r line; do
  [[ -z "$line" || "$line" =~ ^# ]] && continue
  key="${line%%=*}"
  [[ "$key" == "DATABASE_URL" ]] && continue
  grep -v "^${key}=" "$ENV" > /tmp/env.merge || true
  mv /tmp/env.merge "$ENV"
  echo "$line" >> "$ENV"
done < "$RENDER_EXTRA"

grep -v '^CORS_ORIGINS=' "$ENV" > /tmp/env.merge || true
grep -v '^SAAS_CPANEL_BASE_URL=' /tmp/env.merge > /tmp/env.merge2 || true
grep -v '^FRONTEND_STATIC_DIR=' /tmp/env.merge2 > /tmp/env.merge3 || true
grep -v '^HP_REPO_ROOT=' /tmp/env.merge3 > /tmp/env.merge4 || true
grep -v '^HP_OVH_OPS_ENABLED=' /tmp/env.merge4 > /tmp/env.merge5 || true
mv /tmp/env.merge5 "$ENV"
{
  echo 'CORS_ORIGINS=http://40.160.72.39'
  echo 'SAAS_CPANEL_BASE_URL=http://40.160.72.39'
  echo 'FRONTEND_STATIC_DIR=/opt/horizon/horizon-frontend'
  echo 'HP_REPO_ROOT=/opt/horizon'
  echo 'HP_OVH_OPS_ENABLED=1'
} >> "$ENV"

chmod 600 "$ENV"
chown "${PM2_USER}:${PM2_USER}" "$ENV" 2>/dev/null || true
rm -f "$RENDER_EXTRA"
echo "restored keys: $(grep -cE '^[A-Z]' "$ENV")"

sudo -u "$PM2_USER" bash -lc "cd '$BACKEND' && pm2 delete horizon-backend 2>/dev/null || true; pm2 start deploy/ovh/ecosystem.config.cjs --update-env && pm2 save"
sleep 4
curl -s -o /dev/null -w 'session:%{http_code}\n' http://127.0.0.1:3000/session
