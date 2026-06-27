#!/usr/bin/env bash
set -euo pipefail
BACKUP_ROOT="/var/backups/horizon/postgres"
STAMP="$(date +%Y%m%d-%H%M%S)"
RETAIN_DAYS="${RETAIN_DAYS:-14}"
ENV_FILE="/opt/horizon/horizon-backend/.env"
mkdir -p "$BACKUP_ROOT"
DATABASE_URL="$(grep '^DATABASE_URL=' "$ENV_FILE" | head -1 | cut -d= -f2- | tr -d '"')"
OUT="$BACKUP_ROOT/horizon-$STAMP.dump"
/usr/lib/postgresql/18/bin/pg_dump "$DATABASE_URL" --format=custom --no-owner --no-acl --file="$OUT"
find "$BACKUP_ROOT" -name 'horizon-*.dump' -type f -mtime +"$RETAIN_DAYS" -delete
echo "[backup] ok $(du -h "$OUT" | awk '{print $1}')"
