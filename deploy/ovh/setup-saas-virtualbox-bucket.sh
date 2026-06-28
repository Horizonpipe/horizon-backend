#!/usr/bin/env bash
# Point OVH SaaS virtualbox at the saaspipeshare bucket (us-east-2).
# Usage: sudo bash deploy/ovh/setup-saas-virtualbox-bucket.sh
set -euo pipefail

ENV=/opt/horizon/horizon-backend/.env
BUCKET="${SAAS_WASABI_BUCKET:-saaspipeshare}"
REGION="${SAAS_WASABI_REGION:-us-east-2}"
ENDPOINT="${SAAS_WASABI_ENDPOINT:-https://s3.us-east-2.wasabisys.com}"

merge_env() {
  local key="$1"
  local val="$2"
  if grep -q "^${key}=" "$ENV" 2>/dev/null; then
    sed -i "s|^${key}=.*|${key}=${val}|" "$ENV"
  else
    echo "${key}=${val}" >> "$ENV"
  fi
}

if [[ ! -f "$ENV" ]]; then
  echo "Missing $ENV" >&2
  exit 1
fi

merge_env SAAS_WASABI_BUCKET "$BUCKET"
merge_env SAAS_WASABI_REGION "$REGION"
merge_env SAAS_WASABI_ENDPOINT "$ENDPOINT"
merge_env WASABI_BUCKET "$BUCKET"
merge_env WASABI_REGION "$REGION"
merge_env WASABI_ENDPOINT "$ENDPOINT"
merge_env SAAS_TENANT_FOLDER_PREFIX "Tenants"
merge_env SAAS_REQUIRE_WASABI_PROVISION "1"
merge_env HP_DEPLOYMENT_MODE "saas"
merge_env SAAS_TENANT_CORS_ENABLED "1"

chown horizon:horizon "$ENV" 2>/dev/null || chown ubuntu:ubuntu "$ENV" 2>/dev/null || true
chmod 600 "$ENV"

echo "Updated $ENV for SaaS virtualbox bucket $BUCKET ($REGION)"

cd /opt/horizon/horizon-backend
pm2 reload deploy/ovh/ecosystem.config.cjs --update-env 2>/dev/null || pm2 reload horizon-backend --update-env

echo "Run tenant migration:"
echo "  node scripts/migrate-saas-virtualbox-tenant.cjs hstboot+1@gmail.com"
