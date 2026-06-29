#!/usr/bin/env bash
set -euo pipefail
ENV=/opt/horizon/horizon-backend/.env
cp "$ENV" "/tmp/hp-env-backup-$(date +%s)"
set_kv() {
  local key="$1" val="$2"
  if grep -q "^${key}=" "$ENV"; then
    sed -i "s|^${key}=.*|${key}=${val}|" "$ENV"
  else
    echo "${key}=${val}" >> "$ENV"
  fi
}
set_kv WASABI_BUCKET horizon-client-portal
set_kv WASABI_REGION us-east-1
set_kv WASABI_ENDPOINT https://s3.us-east-1.wasabisys.com
grep -E '^WASABI_BUCKET=|^WASABI_REGION=|^WASABI_ENDPOINT=|^SAAS_WASABI' "$ENV"
pm2 reload horizon-backend --update-env
