#!/usr/bin/env bash
# Merge Wasabi / Stripe / SaaS vars from a Render export into production .env, then restart PM2.
#
# Usage (on OVH server):
#   nano /opt/horizon/horizon-backend/.env.render-import   # paste from Render Dashboard → Environment
#   bash /opt/horizon/horizon-backend/deploy/ovh/import-render-env.sh
#
# Or pass a file path:
#   bash deploy/ovh/import-render-env.sh /path/to/render-snippet.env
#
# Only these prefixes are imported (DATABASE_URL and PORT are never overwritten):
#   WASABI_*  STRIPE_*  SAAS_*  PORTAL_*  HTTP_COMPRESSION*  WASABI_STATE_*

set -euo pipefail

BACKEND_DIR="${BACKEND_DIR:-/opt/horizon/horizon-backend}"
TARGET_ENV="$BACKEND_DIR/.env"
IMPORT_FILE="${1:-$BACKEND_DIR/.env.render-import}"

if [[ ! -f "$TARGET_ENV" ]]; then
  echo "Missing $TARGET_ENV — create it from deploy/ovh/env.production.template first." >&2
  exit 1
fi
if [[ ! -f "$IMPORT_FILE" ]]; then
  echo "Missing import file: $IMPORT_FILE" >&2
  echo "Create it with Wasabi + Stripe keys copied from Render Dashboard → horizon-backend → Environment." >&2
  exit 1
fi

# Strip Windows CRLF from import file
sed -i 's/\r$//' "$IMPORT_FILE" 2>/dev/null || sed -i '' 's/\r$//' "$IMPORT_FILE" 2>/dev/null || true

STAMP="$(date +%Y%m%d%H%M%S)"
cp "$TARGET_ENV" "$TARGET_ENV.bak.$STAMP"
echo "[import] backup → $TARGET_ENV.bak.$STAMP"

# Keys we never touch
PROTECTED='^(DATABASE_URL|PORT|NODE_ENV|FRONTEND_STATIC_DIR|PG_POOL_MAX|DATABASE_SSL)='

merge_key() {
  local key="$1"
  local val="$2"
  local esc
  esc="$(printf '%s' "$val" | sed 's/[&/\]/\\&/g')"
  if grep -q "^${key}=" "$TARGET_ENV" 2>/dev/null; then
    sed -i "s|^${key}=.*|${key}=${esc}|" "$TARGET_ENV"
  else
    printf '%s=%s\n' "$key" "$val" >> "$TARGET_ENV"
  fi
}

IMPORTED=0
while IFS= read -r line || [[ -n "$line" ]]; do
  line="${line%%#*}"
  line="$(echo "$line" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
  [[ -z "$line" ]] && continue
  [[ "$line" != *=* ]] && continue

  key="${line%%=*}"
  val="${line#*=}"
  key="$(echo "$key" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"

  if [[ "$key" =~ ^(WASABI_|STRIPE_|SAAS_|PORTAL_|HTTP_COMPRESSION|WASABI_STATE_|SESSION_SECRET|OUTLOOK_) ]]; then
    merge_key "$key" "$val"
    IMPORTED=$((IMPORTED + 1))
  fi
done < "$IMPORT_FILE"

# Production OVH URLs (override Render hostnames in Stripe redirect URLs)
BASE_URL="${OVH_PUBLIC_URL:-http://40.160.72.39}"
merge_key "CORS_ORIGINS" "$BASE_URL"
merge_key "SAAS_CPANEL_BASE_URL" "$BASE_URL"
merge_key "STRIPE_SUCCESS_URL" "${BASE_URL}/horizonpipe-cpanel/billing.html?billing=success"
merge_key "STRIPE_CANCEL_URL" "${BASE_URL}/horizonpipe-cpanel/billing.html?billing=canceled"
merge_key "STRIPE_PORTAL_RETURN_URL" "${BASE_URL}/horizonpipe-cpanel/billing.html"
merge_key "OUTLOOK_REDIRECT_URI" "${BASE_URL}/api/outlook/callback"
merge_key "OUTLOOK_POST_LOGIN_REDIRECT" "${BASE_URL}"

# Remove dev skip flags once real Wasabi + Stripe are present
if grep -q '^WASABI_BUCKET=.\+' "$TARGET_ENV" && grep -q '^WASABI_ACCESS_KEY_ID=.\+' "$TARGET_ENV"; then
  sed -i '/^SAAS_SKIP_WASABI_PROVISION=/d' "$TARGET_ENV" 2>/dev/null || true
  echo "[import] removed SAAS_SKIP_WASABI_PROVISION (Wasabi configured)"
fi
if grep -q '^STRIPE_SECRET_KEY=sk_' "$TARGET_ENV"; then
  sed -i '/^SAAS_SKIP_SUBSCRIPTION_CHECK=/d' "$TARGET_ENV" 2>/dev/null || true
  echo "[import] removed SAAS_SKIP_SUBSCRIPTION_CHECK (Stripe configured)"
fi

sed -i 's/\r$//' "$TARGET_ENV" 2>/dev/null || true
chmod 600 "$TARGET_ENV"

echo "[import] merged $IMPORTED keys from $IMPORT_FILE"
echo "[import] restarting horizon-backend…"
pm2 restart horizon-backend --update-env
sleep 3
pm2 logs horizon-backend --lines 15 --nostream 2>&1 | grep -iE 'wasabi|stripe|saas' || true
echo "[import] done — verify: curl -s $BASE_URL/health"
