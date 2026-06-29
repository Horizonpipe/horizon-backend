#!/usr/bin/env bash
# Issue or renew a wildcard TLS cert for SaaS tenant subdomains (*.pipeshare.net).
# DNS is on GoDaddy — requires DNS-01 (HTTP/webroot cannot issue wildcards).
#
# Credentials (pick one):
#   export GODADDY_API_KEY='...' GODADDY_API_SECRET='...'
#   /root/.secrets/godaddy/credentials.ini
#
# Cloudflare (only if DNS moves to Cloudflare):
#   export CF_DNS_API_TOKEN='...'
#
# After success:
#   sudo bash deploy/ovh/apply-saas-tenant-nginx-ssl.sh
#   sudo nginx -t && sudo systemctl reload nginx

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DOMAIN="${PIPESHARE_NET_DOMAIN:-pipeshare.net}"
CERT_NAME="${PIPESHARE_NET_CERT_NAME:-pipeshare.net}"
EMAIL="${CERTBOT_EMAIL:-admin@pipeshare.live}"
CREDS_FILE="${GODADDY_CREDS_FILE:-/root/.secrets/godaddy/credentials.ini}"
HOOK="${SCRIPT_DIR}/godaddy-certbot-dns-hook.sh"
EXPAND_EXISTING="${EXPAND_EXISTING_CERT:-0}"

if ! command -v certbot >/dev/null 2>&1; then
  echo "certbot is not installed" >&2
  exit 1
fi

load_godaddy_creds() {
  if [[ -n "${GODADDY_API_KEY:-}" && -n "${GODADDY_API_SECRET:-}" ]]; then
    return 0
  fi
  if [[ -f "$CREDS_FILE" ]]; then
    # shellcheck disable=SC1090
    source "$CREDS_FILE"
    export GODADDY_API_KEY="${godaddy_api_key:-${GODADDY_API_KEY:-}}"
    export GODADDY_API_SECRET="${godaddy_api_secret:-${GODADDY_API_SECRET:-}}"
  fi
}

issue_with_godaddy() {
  load_godaddy_creds
  if [[ -z "${GODADDY_API_KEY:-}" || -z "${GODADDY_API_SECRET:-}" ]]; then
    echo "GoDaddy API credentials missing." >&2
    echo "Create Production keys at https://developer.godaddy.com/keys then either:" >&2
    echo "  export GODADDY_API_KEY=... GODADDY_API_SECRET=..." >&2
    echo "  or mkdir -p $(dirname "$CREDS_FILE") && cat > $CREDS_FILE <<'EOF'" >&2
    echo "godaddy_api_key = YOUR_KEY" >&2
    echo "godaddy_api_secret = YOUR_SECRET" >&2
    echo "EOF" >&2
    echo "chmod 600 $CREDS_FILE" >&2
    return 1
  fi
  chmod +x "$HOOK"
  certbot certonly \
    --manual \
    --preferred-challenges dns \
    --manual-auth-hook "bash ${HOOK} auth" \
    --manual-cleanup-hook "bash ${HOOK} cleanup" \
    -d "*.${DOMAIN}" \
    -d "${DOMAIN}" \
    --cert-name "${CERT_NAME}" \
    --agree-tos \
    -m "${EMAIL}" \
    --non-interactive
}

issue_with_cloudflare() {
  if ! certbot plugins 2>/dev/null | grep -q dns-cloudflare; then
    apt-get update -qq
    apt-get install -y python3-certbot-dns-cloudflare
  fi
  certbot certonly \
    --dns-cloudflare \
    --dns-cloudflare-credentials <(printf 'dns_cloudflare_api_token = %s\n' "$CF_DNS_API_TOKEN") \
    -d "*.${DOMAIN}" \
    -d "${DOMAIN}" \
    --cert-name "${CERT_NAME}" \
    --agree-tos \
    -m "${EMAIL}" \
    --non-interactive
}

expand_pipeshare_live_with_wildcard() {
  load_godaddy_creds
  if [[ -z "${GODADDY_API_KEY:-}" || -z "${GODADDY_API_SECRET:-}" ]]; then
    return 1
  fi
  chmod +x "$HOOK"
  certbot certonly \
    --cert-name pipeshare.live \
    --expand \
    --manual \
    --preferred-challenges dns \
    --manual-auth-hook "bash ${HOOK} auth" \
    --manual-cleanup-hook "bash ${HOOK} cleanup" \
    -d pipeshare.live \
    -d www.pipeshare.live \
    -d pipeshare.net \
    -d www.pipeshare.net \
    -d techpipe.pipeshare.net \
    -d "*.${DOMAIN}" \
    --agree-tos \
    -m "${EMAIL}" \
    --non-interactive
}

if [[ -n "${CF_DNS_API_TOKEN:-}" ]]; then
  issue_with_cloudflare
elif [[ "${EXPAND_EXISTING}" == "1" ]]; then
  expand_pipeshare_live_with_wildcard
else
  issue_with_godaddy
fi

echo "Cert installed at /etc/letsencrypt/live/${CERT_NAME}/"
echo "Run: sudo bash ${SCRIPT_DIR}/apply-saas-tenant-nginx-ssl.sh && sudo nginx -t && sudo systemctl reload nginx"
