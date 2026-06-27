#!/usr/bin/env bash
# Weekly server config tarball → local disk + Wasabi off-site folder.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BACKUP_ROOT="/var/backups/horizon/config"
STAMP="$(date +%Y%m%d)"
RETAIN_DAYS="${RETAIN_DAYS:-56}"

mkdir -p "$BACKUP_ROOT"
OUT="$BACKUP_ROOT/config-$STAMP.tar.gz"

CANDIDATES=(
  /opt/horizon/horizon-backend/.env
  /opt/horizon/horizon-backend/ecosystem.config.cjs
  /opt/horizon/horizon-backend/deploy/ovh/ecosystem.config.cjs
  /etc/nginx/sites-available/horizon
  /etc/cron.d/horizon-backups
  /etc/horizon/backup.env
)
FILES=()
for f in "${CANDIDATES[@]}"; do
  [[ -f "$f" ]] && FILES+=("$f")
done

if [[ ${#FILES[@]} -eq 0 ]]; then
  echo "[backup-config] no files to backup" >&2
  exit 1
fi

echo "[backup-config] tarball → $OUT (${#FILES[@]} files)"
tar -czf "$OUT" "${FILES[@]}"

find "$BACKUP_ROOT" -name 'config-*.tar.gz' -type f -mtime +"$RETAIN_DAYS" -delete

# shellcheck disable=SC1091
source "$SCRIPT_DIR/backup-wasabi-common.sh"
if wasabi_backup_upload "$OUT" "config/config-$STAMP.tar.gz"; then
  wasabi_backup_prune_prefix "config" "${BACKUP_WASABI_RETAIN_DAYS:-90}" || true
fi

echo "[backup-config] done $(du -h "$OUT" | awk '{print $1}')"
