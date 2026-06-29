#!/usr/bin/env bash
# Wire dual PM2 backends (Base :3000, SaaS :3001) and nginx upstreams.
# Run on OVH after creating .env.base and .env.saas from templates.
#
#   sudo bash /opt/horizon/horizon-backend/deploy/ovh/setup-dual-backend.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BACKEND_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
FRONTEND_ROOT="${FRONTEND_STATIC_DIR:-/opt/horizon/horizon-frontend}"

echo "==> Dual backend setup (Base :3000, SaaS :3001)"

for f in .env.base .env.saas; do
  if [[ ! -f "$BACKEND_ROOT/$f" ]]; then
    echo "Missing $BACKEND_ROOT/$f — copy from deploy/ovh/env.base.production.template and env.saas.production.template"
    exit 1
  fi
done

echo "==> PM2 dual apps"
pm2 delete horizon-backend 2>/dev/null || true
pm2 delete horizon-backend-base 2>/dev/null || true
pm2 delete horizon-backend-saas 2>/dev/null || true
pm2 start "$SCRIPT_DIR/ecosystem.dual.config.cjs"
pm2 save

echo "==> Patch nginx upstreams (pipeshare.live -> 3000, pipeshare.net + tenants -> 3001)"
NGINX_SSL="$SCRIPT_DIR/nginx-horizon-pipeshare-ssl.conf"
NGINX_TENANT="$SCRIPT_DIR/nginx-horizon-saas-tenant-subdomains.conf"

if [[ -f "$NGINX_SSL" ]]; then
  if ! grep -q 'horizon_node_saas' "$NGINX_SSL"; then
    sed -i '/upstream horizon_node {/i upstream horizon_node_saas {\n    least_conn;\n    server 127.0.0.1:3001;\n    keepalive 64;\n}\n' "$NGINX_SSL"
  fi
  sed -i 's|proxy_pass http://horizon_node_sticky;|proxy_pass http://horizon_node;|g' "$NGINX_SSL"
  sed -i 's|@node_net_ssl|@node_net_ssl|g' "$NGINX_SSL"
  sed -i '/location @node_net_ssl {/,/}/ s|proxy_pass http://horizon_node;|proxy_pass http://horizon_node_saas;|' "$NGINX_SSL" || true
  sed -i '/location @node_net_ssl {/,/}/ s|proxy_pass http://horizon_node_sticky;|proxy_pass http://horizon_node_saas;|' "$NGINX_SSL" || true
fi

if [[ -f "$NGINX_TENANT" ]]; then
  sed -i 's|proxy_pass http://127.0.0.1:3000;|proxy_pass http://127.0.0.1:3001;|g' "$NGINX_TENANT"
fi

if command -v nginx >/dev/null 2>&1; then
  sudo nginx -t
  sudo systemctl reload nginx
fi

echo "==> Done."
echo "  Base  (pipeshare.live)     -> http://127.0.0.1:3000  HP_DEPLOYMENT_MODE=non-saas"
echo "  SaaS  (pipeshare.net + *)  -> http://127.0.0.1:3001  HP_DEPLOYMENT_MODE=saas"
echo "  curl -sS https://pipeshare.live/public/deployment-config.json | jq .mode"
echo "  curl -sS https://pipeshare.net/public/deployment-config.json | jq .mode"
