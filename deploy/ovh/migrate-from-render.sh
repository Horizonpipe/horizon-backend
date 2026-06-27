#!/usr/bin/env bash
# Import Render Postgres into local Postgres on OVH.
# Usage:
#   export RENDER_DATABASE_URL='postgresql://user:pass@...render.com/dbname'
#   bash deploy/ovh/migrate-from-render.sh
#
# Or put RENDER_DATABASE_URL in .env.migrate (chmod 600) one directory above backend.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BACKEND_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
DUMP_DIR="/var/backups/horizon/postgres"
STAMP="$(date +%Y%m%d-%H%M%S)"
DUMP_FILE="$DUMP_DIR/render-migrate-$STAMP.dump"

mkdir -p "$DUMP_DIR"

if [[ -z "${RENDER_DATABASE_URL:-}" && -f "$BACKEND_DIR/.env.migrate" ]]; then
  set -a
  # shellcheck disable=SC1091
  source "$BACKEND_DIR/.env.migrate"
  set +a
fi

if [[ -z "${RENDER_DATABASE_URL:-}" ]]; then
  echo "Set RENDER_DATABASE_URL to your Render Postgres external connection string."
  echo "Render Dashboard → Postgres → Connect → External Database URL"
  exit 1
fi

if [[ -f "$BACKEND_DIR/.env" ]]; then
  LOCAL_URL="$(grep '^DATABASE_URL=' "$BACKEND_DIR/.env" | head -1 | cut -d= -f2- | tr -d '"')"
else
  echo "Missing $BACKEND_DIR/.env with local DATABASE_URL"
  exit 1
fi

echo "==> Dump from Render (custom format, compressed)"
pg_dump "$RENDER_DATABASE_URL" \
  --format=custom \
  --no-owner \
  --no-acl \
  --file="$DUMP_FILE"

echo "==> Restore into local Postgres"
pg_restore \
  --dbname="$LOCAL_URL" \
  --clean \
  --if-exists \
  --no-owner \
  --no-acl \
  "$DUMP_FILE" || true

echo "==> Verify row counts (users)"
psql "$LOCAL_URL" -c "SELECT COUNT(*) AS users FROM users;" || true

echo ""
echo "Migration dump saved: $DUMP_FILE"
echo "Update .env DATABASE_URL to local URL if not already."
echo "Restart app: pm2 restart horizon-backend"
