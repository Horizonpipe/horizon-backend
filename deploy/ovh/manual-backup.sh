#!/usr/bin/env bash
# Create or list Manual Backups on the OVH host.
# Usage:
#   manual-backup.sh create "Pre launch code 1"
#   manual-backup.sh list
set -euo pipefail

ROOT="/opt/horizon/Manual Backups"
ACTION="${1:-}"
NAME="${2:-}"

ensure_readme() {
  mkdir -p "$ROOT"
  cat > "$ROOT/README.txt" <<'READMEEOF'
Manual Backups (OVH host)
=========================
Location: /opt/horizon/Manual Backups/

Each backup is a folder named by Mike (e.g. "Pre launch code 1").
Inside each backup folder:
  horizon-frontend/   - full frontend tree (no node_modules)
  horizon-backend/    - full backend tree (no node_modules; includes .env)
  BACKUP_META.txt     - UTC timestamp and notes

Agent workflow:
  CREATE: when Mike asks to save a backup named X, run:
          bash /opt/horizon/horizon-backend/deploy/ovh/manual-backup.sh create "X"
  LIST:   bash /opt/horizon/horizon-backend/deploy/ovh/manual-backup.sh list
  RESTORE: only when Mike explicitly asks

Do not delete backups unless Mike asks.
READMEEOF
}

list_backups() {
  ensure_readme
  echo "Manual Backups in: $ROOT"
  echo ""
  if [[ ! -d "$ROOT" ]]; then
    echo "(none yet)"
    return 0
  fi
  local found=0
  # shellcheck disable=SC2012
  while IFS= read -r -d '' dir; do
    found=1
    local base
    base="$(basename "$dir")"
    echo "=== $base ==="
    if [[ -f "$dir/BACKUP_META.txt" ]]; then
      cat "$dir/BACKUP_META.txt"
    else
      echo "(no BACKUP_META.txt)"
      du -sh "$dir" 2>/dev/null || true
    fi
    echo ""
  done < <(find "$ROOT" -mindepth 1 -maxdepth 1 -type d -print0 | sort -z)
  if [[ "$found" -eq 0 ]]; then
    echo "(none yet)"
  fi
}

create_backup() {
  local name="$1"
  if [[ -z "$name" ]]; then
    echo "Usage: $0 create \"Backup name\"" >&2
    exit 1
  fi
  ensure_readme
  local dest="$ROOT/$name"
  local stamp
  stamp="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  mkdir -p "$dest"

  {
    echo "name=$name"
    echo "createdUtc=$stamp"
    echo "host=$(hostname -f 2>/dev/null || hostname)"
    echo "frontendSource=/opt/horizon/horizon-frontend"
    echo "backendSource=/opt/horizon/horizon-backend"
    echo "notes=Full code snapshot. Excludes node_modules and *.log. Backend includes .env for same-host restore."
    echo "frontendGit=$(git -C /opt/horizon/horizon-frontend rev-parse --short HEAD 2>/dev/null || echo n/a)"
    echo "backendGit=$(git -C /opt/horizon/horizon-backend rev-parse --short HEAD 2>/dev/null || echo n/a)"
  } > "$dest/BACKUP_META.txt"

  echo "==> Copying horizon-frontend -> $dest/horizon-frontend"
  rsync -a --delete \
    --exclude node_modules \
    --exclude '*.log' \
    --exclude '.DS_Store' \
    /opt/horizon/horizon-frontend/ \
    "$dest/horizon-frontend/"

  echo "==> Copying horizon-backend -> $dest/horizon-backend"
  rsync -a --delete \
    --exclude node_modules \
    --exclude '*.log' \
    --exclude '.DS_Store' \
    /opt/horizon/horizon-backend/ \
    "$dest/horizon-backend/"

  {
    echo ""
    echo "sizes:"
    du -sh "$dest/horizon-frontend" "$dest/horizon-backend" "$dest" | sed 's|^|  |'
  } >> "$dest/BACKUP_META.txt"

  echo ""
  echo "OK: backup created at: $dest"
  cat "$dest/BACKUP_META.txt"
}

case "$ACTION" in
  create)
    create_backup "$NAME"
    ;;
  list)
    list_backups
    ;;
  *)
    echo "Usage: $0 {create \"Name\"|list}" >&2
    exit 1
    ;;
esac
