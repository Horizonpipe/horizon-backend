#!/usr/bin/env bash
# Shared Wasabi upload + retention for OVH off-site backups.
# Source from backup-postgres.sh / backup-config.sh after loading /etc/horizon/backup.env
set -euo pipefail

BACKUP_ENV="${BACKUP_ENV:-/etc/horizon/backup.env}"

wasabi_backup_load_env() {
  if [[ ! -f "$BACKUP_ENV" ]]; then
    echo "[wasabi-backup] missing $BACKUP_ENV" >&2
    return 1
  fi
  # shellcheck disable=SC1090
  source "$BACKUP_ENV"
  if [[ -z "${BACKUP_WASABI_BUCKET:-}" || -z "${BACKUP_WASABI_PREFIX:-}" ]]; then
    echo "[wasabi-backup] BACKUP_WASABI_BUCKET and BACKUP_WASABI_PREFIX required in $BACKUP_ENV" >&2
    return 1
  fi
  if [[ -z "${BACKUP_WASABI_ACCESS_KEY_ID:-}" || -z "${BACKUP_WASABI_SECRET_ACCESS_KEY:-}" ]]; then
    echo "[wasabi-backup] Wasabi credentials missing in $BACKUP_ENV" >&2
    return 1
  fi
}

wasabi_backup_ensure_cli() {
  if command -v aws >/dev/null 2>&1; then
    return 0
  fi
  echo "[wasabi-backup] aws CLI not found — run: sudo bash deploy/ovh/install-awscli.sh" >&2
  return 1
}

wasabi_backup_upload() {
  # Usage: wasabi_backup_upload <local-file> <s3-key-suffix>
  local local_file="$1"
  local key_suffix="$2"
  local key

  wasabi_backup_load_env || return 1
  wasabi_backup_ensure_cli || return 1

  key="${BACKUP_WASABI_PREFIX%/}/${key_suffix#/}"

  echo "[wasabi-backup] upload s3://${BACKUP_WASABI_BUCKET}/${key}"
  AWS_ACCESS_KEY_ID="${BACKUP_WASABI_ACCESS_KEY_ID}" \
  AWS_SECRET_ACCESS_KEY="${BACKUP_WASABI_SECRET_ACCESS_KEY}" \
  AWS_DEFAULT_REGION="${BACKUP_WASABI_REGION:-us-east-1}" \
    aws s3 cp "$local_file" "s3://${BACKUP_WASABI_BUCKET}/${key}" \
      --endpoint-url "${BACKUP_WASABI_ENDPOINT:-https://s3.us-east-1.wasabisys.com}"
}

wasabi_backup_prune_prefix() {
  local subdir="$1"
  local retain_days="${2:-90}"
  local prefix cutoff_epoch

  wasabi_backup_load_env || return 1
  wasabi_backup_ensure_cli || return 1

  prefix="${BACKUP_WASABI_PREFIX%/}/${subdir%/}/"
  cutoff_epoch="$(date -d "-${retain_days} days" +%s 2>/dev/null || date -v-"${retain_days}"d +%s)"

  echo "[wasabi-backup] prune s3://${BACKUP_WASABI_BUCKET}/${prefix} older than ${retain_days}d"
  AWS_ACCESS_KEY_ID="${BACKUP_WASABI_ACCESS_KEY_ID}" \
  AWS_SECRET_ACCESS_KEY="${BACKUP_WASABI_SECRET_ACCESS_KEY}" \
  AWS_DEFAULT_REGION="${BACKUP_WASABI_REGION:-us-east-1}" \
    aws s3 ls "s3://${BACKUP_WASABI_BUCKET}/${prefix}" --recursive \
      --endpoint-url "${BACKUP_WASABI_ENDPOINT:-https://s3.us-east-1.wasabisys.com}" 2>/dev/null \
    | while read -r line; do
        [[ -z "$line" ]] && continue
        local file_date file_time file_size file_key file_epoch
        file_date="$(echo "$line" | awk '{print $1}')"
        file_time="$(echo "$line" | awk '{print $2}')"
        file_key="$(echo "$line" | awk '{print $4}')"
        [[ -z "$file_key" ]] && continue
        file_epoch="$(date -d "${file_date} ${file_time}" +%s 2>/dev/null || true)"
        [[ -z "$file_epoch" ]] && continue
        if [[ "$file_epoch" -lt "$cutoff_epoch" ]]; then
          echo "[wasabi-backup] delete s3://${BACKUP_WASABI_BUCKET}/${file_key}"
          AWS_ACCESS_KEY_ID="${BACKUP_WASABI_ACCESS_KEY_ID}" \
          AWS_SECRET_ACCESS_KEY="${BACKUP_WASABI_SECRET_ACCESS_KEY}" \
          AWS_DEFAULT_REGION="${BACKUP_WASABI_REGION:-us-east-1}" \
            aws s3 rm "s3://${BACKUP_WASABI_BUCKET}/${file_key}" \
              --endpoint-url "${BACKUP_WASABI_ENDPOINT:-https://s3.us-east-1.wasabisys.com}" || true
        fi
      done
}
