#!/usr/bin/env bash
set -euo pipefail
MARKER="# --- SaaS tenant subdomains (auto-included) ---"
H=/etc/nginx/sites-available/horizon
CONF=/opt/horizon/horizon-backend/deploy/ovh/nginx-horizon-saas-tenant-subdomains.conf
sed -i 's/\r$//' "$CONF"
if grep -qF "$MARKER" "$H"; then
  sed -i "/$MARKER/,\$d" "$H"
fi
{
  echo ""
  echo "$MARKER"
  cat "$CONF"
} >> "$H"
nginx -t
systemctl reload nginx
echo "nginx tenant vhosts refreshed (pipeshare.net only)."
