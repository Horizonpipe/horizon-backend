#!/usr/bin/env bash
# Daily Postgres backup — local retention + Wasabi off-site upload.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BACKUP_ROOT="/var/backups/horizon/postgres"
STAMP="$(date +%Y%m%d-%H%M%S)"
RETAIN_DAYS="${RETAIN_DAYS:-14}"
ENV_FILE="${ENV_FILE:-/opt/horizon/horizon-backend/.env}"
BACKUP_ENV="${BACKUP_ENV:-/etc/horizon/backup.env}"

mkdir -p "$BACKUP_ROOT"

if [[ ! -f "$ENV_FILE" ]]; then
  echo "Missing $ENV_FILE"
  exit 1
fi

DATABASE_URL="$(grep '^DATABASE_URL=' "$ENV_FILE" | head -1 | cut -d= -f2- | tr -d '"')"
if [[ -z "$DATABASE_URL" ]]; then
  echo "DATABASE_URL not set in $ENV_FILE"
  exit 1
fi

OUT="$BACKUP_ROOT/horizon-$STAMP.dump"
echo "[backup] pg_dump → $OUT"
pg_dump "$DATABASE_URL" --format=custom --no-owner --no-acl --file="$OUT"

find "$BACKUP_ROOT" -name 'horizon-*.dump' -type f -mtime +"$RETAIN_DAYS" -delete

# shellcheck disable=SC1091
source "$SCRIPT_DIR/backup-wasabi-common.sh"
if wasabi_backup_upload "$OUT" "postgres/horizon-$STAMP.dump"; then
  wasabi_backup_prune_prefix "postgres" "${BACKUP_WASABI_RETAIN_DAYS:-90}" || true
fi

echo "[backup] done $(du -h "$OUT" | awk '{print $1}')"
