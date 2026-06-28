#!/usr/bin/env bash
# Activate pipeshare.net SaaS landing on OVH (nginx + TLS expand + CORS).
# Run on OVH after DNS A records for pipeshare.net point to 40.160.72.39:
#   sudo bash /opt/horizon/horizon-backend/deploy/ovh/activate-pipeshare-net.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OVH_IP=40.160.72.39
ENV=/opt/horizon/horizon-backend/.env

echo "==> DNS check ..."
for d in pipeshare.net pipeshare.live; do
  resolved="$(dig +short "$d" A | head -1 || true)"
  if [[ "$resolved" != "$OVH_IP" ]]; then
    echo "WARN: $d -> '$resolved' (expected $OVH_IP)"
  else
    echo "OK: $d -> $resolved"
  fi
done

echo "==> nginx configs ..."
cp "$SCRIPT_DIR/nginx-horizon-pipeshare.conf" /etc/nginx/sites-available/horizon
ln -sf /etc/nginx/sites-available/horizon /etc/nginx/sites-enabled/horizon
mkdir -p /var/www/certbot
nginx -t
systemctl reload nginx

if [[ -d /etc/letsencrypt/live/pipeshare.live ]]; then
  echo "==> Expanding TLS cert for pipeshare.net (if needed) ..."
  certbot certonly --webroot -w /var/www/certbot \
    -d pipeshare.live -d www.pipeshare.live -d pipeshare.net -d www.pipeshare.net \
    --cert-name pipeshare.live --expand --non-interactive || true
fi

if [[ -f "$SCRIPT_DIR/nginx-horizon-pipeshare-ssl.conf" ]]; then
  cp "$SCRIPT_DIR/nginx-horizon-pipeshare-ssl.conf" /etc/nginx/sites-available/horizon
  nginx -t
  systemctl reload nginx
fi

echo "==> CORS / SaaS URLs in .env ..."
if [[ -f "$ENV" ]]; then
  ORIGIN="https://pipeshare.live"
  SAAS_ORIGIN="https://pipeshare.net"
  CORS="${ORIGIN},https://www.pipeshare.live,${SAAS_ORIGIN},https://www.pipeshare.net,http://${OVH_IP}"
  grep -v '^CORS_ORIGINS=' "$ENV" | grep -v '^SAAS_CPANEL_BASE_URL=' > /tmp/horizon.env.net || true
  {
    cat /tmp/horizon.env.net
    echo "SAAS_CPANEL_BASE_URL=${SAAS_ORIGIN}"
    echo "CORS_ORIGINS=${CORS}"
  } > "$ENV"
  chmod 600 "$ENV"
  chown ubuntu:ubuntu "$ENV" 2>/dev/null || true
fi

echo "==> pm2 reload ..."
sudo -u ubuntu bash -lc 'cd /opt/horizon/horizon-backend && pm2 reload deploy/ovh/ecosystem.config.cjs --update-env && pm2 save' || true

echo ""
echo "Done. Test:"
echo "  curl -sS -o /dev/null -w '%{http_code}\n' https://pipeshare.net/"
echo "  curl -sS -o /dev/null -w '%{http_code}\n' https://pipeshare.live/client-portal/"
