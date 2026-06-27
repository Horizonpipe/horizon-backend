#!/usr/bin/env bash
# Seed /etc/horizon/backup.env from app Wasabi credentials + dedicated backup prefix.
# Run as root after production .env is in place.
set -euo pipefail

APP_ENV="${APP_ENV:-/opt/horizon/horizon-backend/.env}"
BACKUP_ENV="/etc/horizon/backup.env"
PREFIX="${BACKUP_WASABI_PREFIX:-backups/ovh-horizon}"

if [[ ! -f "$APP_ENV" ]]; then
  echo "Missing $APP_ENV" >&2
  exit 1
fi

get_var() {
  grep "^$1=" "$APP_ENV" | head -1 | cut -d= -f2- | tr -d '\r"' || true
}

BUCKET="$(get_var WASABI_BUCKET)"
ACCESS="$(get_var WASABI_ACCESS_KEY_ID)"
SECRET="$(get_var WASABI_SECRET_ACCESS_KEY)"
REGION="$(get_var WASABI_REGION)"
ENDPOINT="$(get_var WASABI_ENDPOINT)"

if [[ -z "$BUCKET" || -z "$ACCESS" || -z "$SECRET" ]]; then
  echo "WASABI_BUCKET / WASABI_ACCESS_KEY_ID / WASABI_SECRET_ACCESS_KEY required in $APP_ENV" >&2
  exit 1
fi

mkdir -p /etc/horizon
chmod 700 /etc/horizon

cat >"$BACKUP_ENV" <<EOF
# Off-site OVH backups — dedicated folder inside the app Wasabi bucket
BACKUP_WASABI_BUCKET=$BUCKET
BACKUP_WASABI_PREFIX=$PREFIX
BACKUP_WASABI_ACCESS_KEY_ID=$ACCESS
BACKUP_WASABI_SECRET_ACCESS_KEY=$SECRET
BACKUP_WASABI_REGION=${REGION:-us-east-1}
BACKUP_WASABI_ENDPOINT=${ENDPOINT:-https://s3.us-east-1.wasabisys.com}
BACKUP_WASABI_RETAIN_DAYS=90
EOF
chmod 600 "$BACKUP_ENV"
echo "[configure-backup] wrote $BACKUP_ENV (prefix=$PREFIX bucket=$BUCKET)"
