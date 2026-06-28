#!/usr/bin/env bash
# Wire SaaS tenant subdomains: {BusinessName}.pipeshare.net (PipeShare + PipeSync on same host)
# Run on OVH as root after GoDaddy DNS is set (see below).
#
# Usage:
#   sudo bash /opt/horizon/horizon-backend/deploy/ovh/setup-saas-tenant-subdomains.sh
#   sudo bash .../setup-saas-tenant-subdomains.sh --cert-only   # skip nginx merge
#   sudo bash .../setup-saas-tenant-subdomains.sh --tenant techpipe  # first tenant SAN
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OVH_IP="${OVH_IP:-40.160.72.39}"
CERT_NAME="${CERT_NAME:-pipeshare.live}"
WEBROOT=/var/www/certbot
HORIZON=/etc/nginx/sites-available/horizon
MARKER="# --- SaaS tenant subdomains (auto-included) ---"
TENANT_SLUG="${TENANT_SLUG:-techpipe}"
CERT_EMAIL="${CERT_EMAIL:-admin@pipeshare.live}"

echo "==> SaaS tenant subdomain wiring (OVH IP ${OVH_IP})"
echo ""

echo "==> GoDaddy DNS (do this in the browser if not done yet):"
echo "  pipeshare.net  →  DNS  →  Add  →  Type A  →  Name *  →  Value ${OVH_IP}  →  TTL 600"
echo "  (PipeShare: /client-portal/   PipeSync: /pipesync.html on the same tenant host.)"
echo ""

check_dns() {
  local host="$1"
  local resolved
  resolved="$(dig +short "$host" A | head -1 || true)"
  if [[ "$resolved" == "$OVH_IP" ]]; then
    echo "OK: $host -> $resolved"
    return 0
  fi
  echo "MISSING: $host -> '${resolved:-<no A record>}' (expected ${OVH_IP})"
  return 1
}

DNS_OK=1
check_dns "techpipe.pipeshare.net" || DNS_OK=0
echo ""

if [[ "${1:-}" != "--cert-only" ]]; then
  echo "==> Installing tenant nginx vhosts ..."
  mkdir -p "$WEBROOT"
  if [[ ! -f "$HORIZON" ]]; then
    echo "ERROR: $HORIZON missing — run setup-pipeshare-tls.sh first." >&2
    exit 1
  fi
  if ! grep -qF "$MARKER" "$HORIZON"; then
    {
      echo ""
      echo "$MARKER"
      cat "$SCRIPT_DIR/nginx-horizon-saas-tenant-subdomains.conf"
    } >> "$HORIZON"
    echo "Appended tenant vhosts to $HORIZON"
  else
    echo "Tenant vhosts already present in $HORIZON"
  fi
  nginx -t
  systemctl reload nginx
  echo "nginx reloaded."
  echo ""
fi

if [[ "$DNS_OK" != "1" ]]; then
  echo "==> DNS not ready — add GoDaddy records above, wait 5–30 min, re-run this script."
  echo "    Test: dig +short techpipe.pipeshare.net A"
  exit 1
fi

echo "==> Expanding TLS cert for first tenant + apex domains ..."
# Webroot ACME works once nginx serves /.well-known on tenant HTTP vhosts.
certbot certonly --webroot -w "$WEBROOT" \
  --cert-name "$CERT_NAME" \
  --expand \
  -d pipeshare.live \
  -d www.pipeshare.live \
  -d pipeshare.net \
  -d www.pipeshare.net \
  -d "${TENANT_SLUG}.pipeshare.net" \
  --agree-tos -m "$CERT_EMAIL" \
  --non-interactive || {
    echo ""
    echo "Certbot expand failed. After DNS propagates, run:"
    echo "  sudo certbot certonly --webroot -w $WEBROOT --cert-name $CERT_NAME --expand \\"
    echo "    -d pipeshare.live -d www.pipeshare.live -d pipeshare.net -d www.pipeshare.net \\"
    echo "    -d ${TENANT_SLUG}.pipeshare.net"
    exit 1
  }

nginx -t && systemctl reload nginx

echo "==> Updating CORS for tenant subdomains ..."
ENV=/opt/horizon/horizon-backend/.env
if [[ -f "$ENV" ]]; then
  if ! grep -q '^SAAS_TENANT_CORS_ENABLED=' "$ENV"; then
    echo "SAAS_TENANT_CORS_ENABLED=1" >> "$ENV"
  else
    sed -i 's/^SAAS_TENANT_CORS_ENABLED=.*/SAAS_TENANT_CORS_ENABLED=1/' "$ENV"
  fi
  chown horizon:horizon "$ENV" 2>/dev/null || chown ubuntu:ubuntu "$ENV" 2>/dev/null || true
  chmod 600 "$ENV"
  sudo -u horizon pm2 reload horizon-backend 2>/dev/null || pm2 reload horizon-backend
fi

nginx -t && systemctl reload nginx

echo ""
echo "Done. Test:"
echo "  curl -sS -o /dev/null -w '%{http_code}\\n' https://techpipe.pipeshare.net/client-portal/"
echo "  curl -sS -o /dev/null -w '%{http_code}\\n' https://techpipe.pipeshare.net/pipesync.html"
echo ""
echo "For ALL future tenants without re-issuing certs, add wildcard DNS + wildcard TLS (DNS-01):"
echo "  certbot certonly --manual --preferred-challenges dns \\"
echo "    -d '*.pipeshare.net' -d pipeshare.net \\"
echo "    --cert-name $CERT_NAME --expand"
