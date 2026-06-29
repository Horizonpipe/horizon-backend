#!/usr/bin/env bash
# Point SaaS tenant nginx vhost at the correct Let's Encrypt cert directory.
set -euo pipefail

HORIZON="${HP_NGINX_HORIZON:-/etc/nginx/sites-available/horizon}"
CERT_NAME="${PIPESHARE_NET_CERT_NAME:-pipeshare.net}"
CERT_DIR="/etc/letsencrypt/live/${CERT_NAME}"

if [[ ! -f "${CERT_DIR}/fullchain.pem" ]]; then
  CERT_NAME="pipeshare.live"
  CERT_DIR="/etc/letsencrypt/live/pipeshare.live"
fi

if [[ ! -f "${CERT_DIR}/fullchain.pem" ]]; then
  echo "No TLS cert found at pipeshare.net or pipeshare.live under /etc/letsencrypt/live/" >&2
  exit 1
fi

if [[ ! -f "$HORIZON" ]]; then
  echo "Missing nginx config: $HORIZON" >&2
  exit 1
fi

echo "Using cert: ${CERT_DIR}"

python3 - "$HORIZON" "$CERT_DIR" <<'PY'
import re, sys
path, cert_dir = sys.argv[1], sys.argv[2]
text = open(path, encoding="utf-8").read()
block_start = text.find("# SaaS tenant subdomains")
if block_start < 0:
    print("Tenant subdomain block not found in", path, file=sys.stderr)
    sys.exit(1)
before, rest = text[:block_start], text[block_start:]
ssl_block = re.search(
    r"(# --- HTTPS: \{slug\}\.pipeshare\.net.*?\nserver \{.*?\n)\s*ssl_certificate\s+[^;]+;\s*\n\s*ssl_certificate_key\s+[^;]+;",
    rest,
    re.S,
)
if not ssl_block:
    print("Could not locate tenant HTTPS ssl_certificate lines", file=sys.stderr)
    sys.exit(1)
replacement = (
    ssl_block.group(1)
    + f"    ssl_certificate     {cert_dir}/fullchain.pem;\n"
    + f"    ssl_certificate_key {cert_dir}/privkey.pem;"
)
rest = rest[: ssl_block.start()] + replacement + rest[ssl_block.end() :]
open(path, "w", encoding="utf-8").write(before + rest)
print("Updated tenant SSL paths in", path)
PY

nginx -t
systemctl reload nginx
echo "nginx reloaded with ${CERT_NAME} cert for *.pipeshare.net tenants"
