#!/usr/bin/env bash
# Permanent TLS auto-renew setup for the OVH hybrid box (pipeshare.live + pipeshare.net).
#
# Root cause this guards against:
#   Adding a tenant hostname (e.g. techpipe.pipeshare.net) to the apex *webroot* cert
#   breaks `certbot renew` when tenant nginx does not serve /.well-known/acme-challenge/.
#   Tenants must use the separate *.pipeshare.net DNS-01 wildcard cert — never the apex webroot lineage.
#
# Idempotent. Safe to re-run after github-deploy.
#   sudo bash /opt/horizon/horizon-backend/deploy/ovh/install-cert-auto-renew.sh
#   sudo bash .../install-cert-auto-renew.sh --force-apex-renew
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APEX_CERT_NAME="${APEX_CERT_NAME:-pipeshare.live}"
WILDCARD_CERT_NAME="${WILDCARD_CERT_NAME:-pipeshare.net}"
EMAIL="${CERTBOT_EMAIL:-admin@pipeshare.live}"
WEBROOT="${CERTBOT_WEBROOT:-/var/www/certbot}"
FORCE_APEX=0
[[ "${1:-}" == "--force-apex-renew" ]] && FORCE_APEX=1

need_root() {
  if [[ "$(id -u)" -ne 0 ]]; then
    echo "Run as root: sudo bash $0" >&2
    exit 1
  fi
}

need_root

if ! command -v certbot >/dev/null 2>&1; then
  apt-get update -qq
  apt-get install -y certbot python3-certbot-nginx
fi

mkdir -p "$WEBROOT" /etc/letsencrypt/renewal-hooks/deploy

echo "==> Deploy hook: reload nginx after any successful renew"
cat >/etc/letsencrypt/renewal-hooks/deploy/reload-nginx.sh <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
if command -v nginx >/dev/null 2>&1; then
  nginx -t && systemctl reload nginx
fi
EOF
chmod 755 /etc/letsencrypt/renewal-hooks/deploy/reload-nginx.sh

echo "==> Enable systemd certbot.timer (twice daily)"
systemctl enable --now certbot.timer
systemctl list-timers certbot.timer --no-pager || true

echo "==> Ensure SaaS tenant vhost serves ACME + wildcard TLS"
TENANT_SRC="${SCRIPT_DIR}/nginx-horizon-saas-tenant-subdomains.conf"
TENANT_DST="/etc/nginx/sites-available/horizon-saas-tenants"
if [[ -f "$TENANT_SRC" ]]; then
  cp "$TENANT_SRC" "$TENANT_DST"
  # Always point tenant HTTPS at the wildcard lineage when present.
  if [[ -f "/etc/letsencrypt/live/${WILDCARD_CERT_NAME}/fullchain.pem" ]]; then
    sed -i \
      -e "s|/etc/letsencrypt/live/pipeshare.live/|/etc/letsencrypt/live/${WILDCARD_CERT_NAME}/|g" \
      -e "s|/etc/letsencrypt/live/pipeshare.net/|/etc/letsencrypt/live/${WILDCARD_CERT_NAME}/|g" \
      "$TENANT_DST"
  fi
  ln -sfn "$TENANT_DST" /etc/nginx/sites-enabled/horizon-saas-tenants
fi

echo "==> Apex cert lineage must be webroot-only (no tenant SANs)"
APEX_DOMAINS=(-d pipeshare.live -d www.pipeshare.live -d pipeshare.net -d www.pipeshare.net)
if [[ ! -d "/etc/letsencrypt/live/${APEX_CERT_NAME}" ]] || [[ "$FORCE_APEX" -eq 1 ]]; then
  echo "Issuing/renewing ${APEX_CERT_NAME} (webroot)..."
  certbot certonly --webroot -w "$WEBROOT" "${APEX_DOMAINS[@]}" \
    --cert-name "$APEX_CERT_NAME" --agree-tos -m "$EMAIL" --non-interactive \
    ${FORCE_APEX:+--force-renewal}
else
  # If the live lineage still lists a tenant host, re-issue without it.
  if openssl x509 -in "/etc/letsencrypt/live/${APEX_CERT_NAME}/fullchain.pem" -noout -text 2>/dev/null \
    | grep -E 'DNS:.*\.pipeshare\.net' | grep -vqE 'DNS:(www\.)?pipeshare\.net'; then
    echo "Apex cert still contains a tenant SAN — reissuing without tenants..."
    certbot certonly --webroot -w "$WEBROOT" "${APEX_DOMAINS[@]}" \
      --cert-name "$APEX_CERT_NAME" --agree-tos -m "$EMAIL" --non-interactive --force-renewal
  else
    echo "Apex cert OK (no tenant SANs)."
  fi
fi

if command -v nginx >/dev/null 2>&1; then
  nginx -t
  systemctl reload nginx
fi

echo "==> Dry-run apex renew (must succeed for permanent auto-renew)"
certbot renew --cert-name "$APEX_CERT_NAME" --dry-run --no-random-sleep-on-renew

echo ""
echo "Done."
echo "  Apex:     /etc/letsencrypt/live/${APEX_CERT_NAME}/  (HTTP-01 webroot — auto via certbot.timer)"
echo "  Wildcard: /etc/letsencrypt/live/${WILDCARD_CERT_NAME}/  (DNS-01 GoDaddy — auto via same timer + hook)"
echo "  Never add {tenant}.pipeshare.net to the apex webroot cert."
echo "  Re-issue wildcard only: sudo bash ${SCRIPT_DIR}/issue-pipeshare-net-wildcard-cert.sh"
