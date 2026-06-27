#!/usr/bin/env bash
set -euo pipefail
PG_DUMP=/usr/lib/postgresql/18/bin/pg_dump
PG_RESTORE=/usr/lib/postgresql/16/bin/pg_restore
PSQL=/usr/lib/postgresql/16/bin/psql
PG_PASS=$(sudo cat /root/.horizon_pg_pass)
LOCAL_URL="postgresql://horizon:${PG_PASS}@127.0.0.1:5432/horizon"
DUMP="/var/backups/horizon/postgres/render-migrate-$(date +%Y%m%d-%H%M%S).dump"
echo "Dumping Render..."
$PG_DUMP "$RENDER_DATABASE_URL" --format=custom --no-owner --no-acl --file="$DUMP"
echo "Restoring local..."
$PG_RESTORE --dbname="$LOCAL_URL" --clean --if-exists --no-owner --no-acl "$DUMP" || true
$PSQL "$LOCAL_URL" -c "SELECT COUNT(*) AS users FROM users;"
echo MIGRATE_OK
