#!/usr/bin/env bash
# One-time (idempotent) setup for Horizon Pipe Desktop download + auto-update feed.
#
# Creates /opt/horizon/desktop-updates and patches nginx so:
#   https://pipeshare.live/desktop-updates/latest.yml
#   https://pipeshare.live/desktop-updates/Horizon-Pipe-Desktop-Setup.exe
# are public.
#
# Usage (on OVH):
#   sudo bash /opt/horizon/horizon-backend/deploy/ovh/setup-desktop-updates.sh
set -euo pipefail

UPDATES_DIR="${HP_DESKTOP_UPDATES_DIR:-/opt/horizon/desktop-updates}"
NGINX_SSL="${HP_NGINX_SSL_CONF:-/etc/nginx/sites-available/horizon-pipeshare-ssl}"
SNIPPET_MARK="horizon-desktop-updates"

need_root() {
  if [[ "$(id -u)" -ne 0 ]]; then
    echo "Run as root: sudo bash $0" >&2
    exit 1
  fi
}

need_root
mkdir -p "$UPDATES_DIR"
chown -R ubuntu:ubuntu "$UPDATES_DIR"
chmod 755 "$UPDATES_DIR"

# Prefer live SSL vhost; fall back to performance conf if that is what is enabled.
CONF=""
for candidate in \
  /etc/nginx/sites-available/horizon \
  /etc/nginx/sites-enabled/horizon \
  /etc/nginx/sites-available/horizon-pipeshare-ssl \
  /etc/nginx/sites-enabled/horizon-pipeshare-ssl \
  /opt/horizon/horizon-backend/deploy/ovh/nginx-horizon-pipeshare-ssl.conf
do
  if [[ -f "$candidate" ]]; then
    CONF="$candidate"
    break
  fi
done

SNIPPET=$(cat <<EOF
    # ${SNIPPET_MARK}
    location ^~ /desktop-updates/ {
        alias ${UPDATES_DIR}/;
        autoindex off;
        default_type application/octet-stream;
        types {
            text/yaml yml yaml;
            application/octet-stream exe blockmap;
        }
        add_header Cache-Control "public, max-age=60";
        add_header Access-Control-Allow-Origin "*";
    }
EOF
)

if [[ -n "$CONF" ]] && ! grep -q "$SNIPPET_MARK" "$CONF" 2>/dev/null; then
  # Insert before the first "location / {" inside the pipeshare.live HTTPS server if possible.
  if grep -q "server_name pipeshare.live" "$CONF"; then
    python3 - <<PY
from pathlib import Path
path = Path("$CONF")
text = path.read_text()
marker = "$SNIPPET_MARK"
if marker in text:
    raise SystemExit(0)
snippet = """$SNIPPET"""
# Prefer insert just before the catch-all location / in the first HTTPS live server.
needle = "    location / {\n        try_files \$uri \$uri/ @node_live;"
if needle in text:
    text = text.replace(needle, snippet + "\n\n" + needle, 1)
else:
    needle2 = "    location / {\n        try_files \$uri \$uri/ @node;"
    if needle2 in text:
        text = text.replace(needle2, snippet + "\n\n" + needle2, 1)
    else:
        # Append before last closing brace of file
        idx = text.rfind("}")
        text = text[:idx] + "\n" + snippet + "\n" + text[idx:]
path.write_text(text)
print(f"[desktop-updates] patched {path}")
PY
  else
    echo "[desktop-updates] WARN: could not find pipeshare.live server_name in $CONF — add location manually" >&2
  fi
else
  echo "[desktop-updates] nginx snippet already present or conf not found ($CONF)"
fi

# Also keep a copy of the snippet next to deploy assets for github-deploy merges.
REPO_SNIPPET="/opt/horizon/horizon-backend/deploy/ovh/nginx-desktop-updates.snippet.conf"
mkdir -p "$(dirname "$REPO_SNIPPET")"
printf '%s\n' "$SNIPPET" > "$REPO_SNIPPET"
chown ubuntu:ubuntu "$REPO_SNIPPET" 2>/dev/null || true

if command -v nginx >/dev/null 2>&1; then
  nginx -t
  systemctl reload nginx
  echo "[desktop-updates] nginx reloaded"
fi

echo "[desktop-updates] Ready: $UPDATES_DIR"
echo "  Publish from Windows: npm run publish:win"
echo "  Feed URL: https://pipeshare.live/desktop-updates/latest.yml"
echo "  Download: https://pipeshare.live/download-desktop.html"
