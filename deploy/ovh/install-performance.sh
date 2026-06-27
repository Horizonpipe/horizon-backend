#!/usr/bin/env bash
# Apply nginx performance config, pre-gzip static assets, tune Wasabi cache for OVH.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FRONTEND="${FRONTEND_DIR:-/opt/horizon/horizon-frontend}"
BACKEND_ENV="${BACKEND_ENV:-/opt/horizon/horizon-backend/.env}"
NGINX_SITE="/etc/nginx/sites-available/horizon"

echo "[perf] installing nginx config…"
cp "$SCRIPT_DIR/nginx-horizon-performance.conf" "$NGINX_SITE"
ln -sf "$NGINX_SITE" /etc/nginx/sites-enabled/horizon
rm -f /etc/nginx/sites-enabled/default 2>/dev/null || true
nginx -t
systemctl reload nginx

echo "[perf] pre-gzipping large static files…"
if [[ -d "$FRONTEND" ]]; then
  find "$FRONTEND" -type f \( -name '*.js' -o -name '*.css' -o -name '*.html' -o -name '*.svg' \) -size +8k \
    -print0 | while IFS= read -r -d '' f; do
      gzip -kf -9 "$f" 2>/dev/null || true
    done
  du -h "$FRONTEND/app.js" "$FRONTEND/app.js.gz" 2>/dev/null || true
fi

merge_env() {
  local key="$1"
  local val="$2"
  if grep -q "^${key}=" "$BACKEND_ENV" 2>/dev/null; then
    sed -i "s|^${key}=.*|${key}=${val}|" "$BACKEND_ENV"
  else
    echo "${key}=${val}" >>"$BACKEND_ENV"
  fi
}

if [[ -f "$BACKEND_ENV" ]]; then
  echo "[perf] tuning backend env for local Postgres + warm Wasabi cache…"
  # Auth sessions live in local Postgres — skip Wasabi round-trip on every API call.
  merge_env "WASABI_AUTH_PRIMARY_ENABLED" "0"
  merge_env "WASABI_AUTH_PRIMARY_STRICT" "0"
  # Cache Wasabi latest.json longer on dedicated hardware (less S3 chatter).
  merge_env "WASABI_LATEST_STATE_CACHE_MS" "300000"
  merge_env "HTTP_COMPRESSION" "1"
  merge_env "HTTP_COMPRESSION_LEVEL" "6"
  merge_env "HTTP_COMPRESSION_THRESHOLD" "256"
  merge_env "SYNC_STATE_HTTP_CACHE_MS" "15000"
fi

echo "[perf] restarting horizon-backend…"
sudo -u ubuntu pm2 restart horizon-backend --update-env || sudo -u ubuntu bash -lc 'cd /opt/horizon/horizon-backend && pm2 start deploy/ovh/ecosystem.config.cjs'
sleep 3

echo "[perf] smoke tests (localhost via nginx)…"
curl -sI -H 'Accept-Encoding: gzip' http://127.0.0.1/app.js | tr -d '\r' | grep -iE 'HTTP/|content-encoding|content-length' || true
curl -s -o /dev/null -w 'health via nginx: %{time_total}s\n' http://127.0.0.1/health

echo "[perf] done"
