#!/usr/bin/env bash
# Issue or renew a wildcard TLS cert for SaaS tenant subdomains (*.pipeshare.net).
# Requires DNS-01 (not HTTP-01) because nginx serves tenant vhosts on 443 before cert exists.
#
# Example (Cloudflare):
#   export CF_DNS_API_TOKEN='...'
#   ./deploy/ovh/issue-pipeshare-net-wildcard-cert.sh
#
# After success, reload nginx:
#   sudo nginx -t && sudo systemctl reload nginx

set -euo pipefail

DOMAIN="${PIPESHARE_NET_DOMAIN:-pipeshare.net}"
CERT_NAME="${PIPESHARE_NET_CERT_NAME:-pipeshare.net}"
EMAIL="${CERTBOT_EMAIL:-admin@horizonpipe.com}"

if ! command -v certbot >/dev/null 2>&1; then
  echo "certbot is not installed" >&2
  exit 1
fi

# Prefer dns-cloudflare when CF_DNS_API_TOKEN is set; otherwise use manual DNS.
if [[ -n "${CF_DNS_API_TOKEN:-}" ]]; then
  certbot certonly \
    --dns-cloudflare \
    --dns-cloudflare-credentials <(printf 'dns_cloudflare_api_token = %s\n' "$CF_DNS_API_TOKEN") \
    -d "*.${DOMAIN}" \
    -d "${DOMAIN}" \
    --cert-name "${CERT_NAME}" \
    --agree-tos \
    -m "${EMAIL}" \
    --non-interactive
else
  echo "Set CF_DNS_API_TOKEN for automated DNS-01, or run certbot manually:" >&2
  echo "  certbot certonly --manual --preferred-challenges dns -d '*.${DOMAIN}' -d '${DOMAIN}' --cert-name '${CERT_NAME}'" >&2
  exit 2
fi

echo "Cert installed at /etc/letsencrypt/live/${CERT_NAME}/"
echo "Ensure deploy/ovh/nginx-horizon-saas-tenant-subdomains.conf points ssl_certificate there, then reload nginx."
