#!/usr/bin/env bash
# Remove legacy DAS job folders 1 & 4; purge sql-mirror under job 3 (keep system-state).
# Job 3 prefix is platform infrastructure (auth snapshots), not a user folder.
set -euo pipefail
ENV=/opt/horizon/horizon-backend/.env
BACKEND=/opt/horizon/horizon-backend
cd "$BACKEND"

load_env() {
  local line key val
  while IFS= read -r line || [[ -n "$line" ]]; do
    [[ -z "$line" || "$line" =~ ^[[:space:]]*# ]] && continue
    [[ "$line" =~ ^(WASABI_|DATABASE_URL) ]] || continue
    key="${line%%=*}"
    val="${line#*=}"
    val="${val%\"}"; val="${val#\"}"; val="${val%\'}"; val="${val#\'}"
    export "${key}=${val}"
  done < "$ENV"
}
load_env

BUCKET="${WASABI_BUCKET}"
ENDPOINT="${WASABI_ENDPOINT}"
REGION="${WASABI_REGION}"

aws_rm_prefix() {
  local prefix="$1"
  echo "[cleanup] deleting s3://${BUCKET}/${prefix}"
  AWS_ACCESS_KEY_ID="${WASABI_ACCESS_KEY_ID}" \
  AWS_SECRET_ACCESS_KEY="${WASABI_SECRET_ACCESS_KEY}" \
  AWS_DEFAULT_REGION="${REGION}" \
    aws s3 rm "s3://${BUCKET}/${prefix}" --recursive --endpoint-url "${ENDPOINT}"
}

DRY="${1:-}"
if [[ "$DRY" == "--dry-run" ]]; then
  echo "[cleanup] DRY RUN — listing only"
  for p in \
    "clients/portal-users/jobs/1/" \
    "clients/portal-users/jobs/4/" \
    "clients/portal-users/jobs/3/sql-mirror/"; do
    AWS_ACCESS_KEY_ID="${WASABI_ACCESS_KEY_ID}" \
    AWS_SECRET_ACCESS_KEY="${WASABI_SECRET_ACCESS_KEY}" \
    AWS_DEFAULT_REGION="${REGION}" \
      aws s3 ls "s3://${BUCKET}/${p}" --recursive --summarize --endpoint-url "${ENDPOINT}" | tail -3
  done
  exit 0
fi

aws_rm_prefix "clients/portal-users/jobs/1/"
aws_rm_prefix "clients/portal-users/jobs/4/"
aws_rm_prefix "clients/portal-users/jobs/3/sql-mirror/"

echo "[cleanup] postgres: reassign users off job 1, drop job 1 grants"
node <<'NODE'
require('dotenv').config();
const pg = require('pg');
(async () => {
  const p = new pg.Pool({ connectionString: process.env.DATABASE_URL });
  await p.query(
    `UPDATE users SET portal_files_job_id = '2', updated_at = NOW()
     WHERE portal_files_client_id = 'portal-users' AND portal_files_job_id = '1'
       AND (roles->>'dataAutoSyncEmployee')::boolean IS TRUE`
  );
  await p.query(
    `UPDATE users SET portal_files_job_id = '8', updated_at = NOW()
     WHERE portal_files_client_id = 'portal-users' AND portal_files_job_id = '1'`
  );
  await p.query(`DELETE FROM portal_path_grants WHERE client_id = 'portal-users' AND job_id = '1'`);
  await p.query(
    `UPDATE users SET portal_files_job_id = '8', updated_at = NOW()
     WHERE portal_files_client_id = 'portal-users' AND portal_files_job_id = '4'`
  );
  await p.query(`DELETE FROM portal_path_grants WHERE client_id = 'portal-users' AND job_id = '4'`);
  const u = await p.query(
    `SELECT id, username, portal_files_job_id FROM users WHERE portal_files_client_id = 'portal-users' ORDER BY id`
  );
  console.log('[cleanup] users after:', u.rows);
  await p.end();
})().catch((e) => {
  console.error(e);
  process.exit(1);
});
NODE

echo "[cleanup] done"
