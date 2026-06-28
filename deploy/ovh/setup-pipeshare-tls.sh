#!/usr/bin/env bash
# Run on OVH after GoDaddy A records for pipeshare.live / pipeshare.net point to 40.160.72.39.
# Usage: sudo bash deploy/ovh/setup-pipeshare-tls.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DOMAINS=(pipeshare.live www.pipeshare.live pipeshare.net www.pipeshare.net)
PRIMARY=pipeshare.live
OVH_IP=40.160.72.39

echo "==> Checking DNS for ${DOMAINS[*]} ..."
for d in pipeshare.live pipeshare.net; do
  resolved="$(dig +short "$d" A | head -1 || true)"
  if [[ "$resolved" != "$OVH_IP" ]]; then
    echo "WARN: $d resolves to '$resolved' (expected $OVH_IP). Certbot may fail — fix GoDaddy DNS first."
  else
    echo "OK: $d -> $resolved"
  fi
done

echo "==> Installing HTTP vhost (ACME-ready) ..."
cp "$SCRIPT_DIR/nginx-horizon-pipeshare.conf" /etc/nginx/sites-available/horizon
ln -sf /etc/nginx/sites-available/horizon /etc/nginx/sites-enabled/horizon
rm -f /etc/nginx/sites-enabled/default
mkdir -p /var/www/certbot
nginx -t
systemctl reload nginx

echo "==> Requesting Let's Encrypt certificate ..."
certbot_args=()
for d in "${DOMAINS[@]}"; do
  certbot_args+=(-d "$d")
done
certbot certonly --webroot -w /var/www/certbot "${certbot_args[@]}" --cert-name "$PRIMARY" --agree-tos -m admin@pipeshare.live --non-interactive || {
  echo ""
  echo "Certbot failed. Wait for DNS propagation (dig pipeshare.live +short should show $OVH_IP), then re-run:"
  echo "  sudo certbot certonly --webroot -w /var/www/certbot -d pipeshare.live -d www.pipeshare.live -d pipeshare.net -d www.pipeshare.net --cert-name pipeshare.live"
  echo "  sudo bash $SCRIPT_DIR/setup-pipeshare-tls.sh --ssl-only"
  exit 1
}

if [[ "${1:-}" != "--ssl-only" ]]; then
  echo "==> Installing HTTPS nginx config ..."
  cp "$SCRIPT_DIR/nginx-horizon-pipeshare-ssl.conf" /etc/nginx/sites-available/horizon
  nginx -t
  systemctl reload nginx
fi

echo "==> Updating backend origin (CORS + PUBLIC_ORIGIN) ..."
ENV=/opt/horizon/horizon-backend/.env
ORIGIN="https://${PRIMARY}"
SAAS_ORIGIN="https://pipeshare.net"
CORS="${ORIGIN},https://www.pipeshare.live,${SAAS_ORIGIN},https://www.pipeshare.net,http://${OVH_IP}"
if [[ -f "$ENV" ]]; then
  grep -v '^PUBLIC_ORIGIN=' "$ENV" | grep -v '^CORS_ORIGINS=' | grep -v '^SAAS_CPANEL_BASE_URL=' > /tmp/horizon.env.merge || true
  {
    cat /tmp/horizon.env.merge
    echo "PUBLIC_ORIGIN=${ORIGIN}"
    echo "SAAS_CPANEL_BASE_URL=${SAAS_ORIGIN}"
    echo "CORS_ORIGINS=${CORS}"
  } > "$ENV"
  chown horizon:horizon "$ENV" 2>/dev/null || chown ubuntu:ubuntu "$ENV" 2>/dev/null || true
  chmod 600 "$ENV"
  sudo -u horizon pm2 reload horizon-backend 2>/dev/null || pm2 reload horizon-backend
fi

echo ""
echo "Done. Test:"
echo "  curl -sS -o /dev/null -w '%{http_code}' https://${PRIMARY}/client-portal/"
echo "  curl -sS -o /dev/null -w '%{http_code}' https://pipeshare.net/   # expect 200 (SaaS landing)"
