'use strict';

/**
 * Undo SaaS tenant provisioning overwriting portal scope for platform admins (Mike).
 * Restores portal-users/{job} so base PipeShare (pipeshare.live) loads legacy Wasabi folders.
 *
 *   node scripts/restore-platform-admin-portal-scope.cjs
 *   node scripts/restore-platform-admin-portal-scope.cjs --dry-run
 */

require('dotenv').config();
const pg = require('pg');
const { looksLikeMike } = require('../capabilities');

const DEFAULT_CLIENT = String(process.env.PORTAL_SHARED_DEFAULT_CLIENT_ID || 'portal-users').trim();
const DEFAULT_JOB = String(process.env.PORTAL_SHARED_DEFAULT_JOB_ID || '8').trim();

async function main() {
  const dryRun = process.argv.includes('--dry-run');
  const pool = new pg.Pool({ connectionString: process.env.DATABASE_URL });
  const r = await pool.query(
    `SELECT id, username, email, display_name, portal_files_client_id, portal_files_job_id
     FROM users
     ORDER BY id ASC`
  );
  let restored = 0;
  for (const row of r.rows) {
    if (!looksLikeMike(row)) continue;
    const client = String(row.portal_files_client_id || '').trim();
    if (!/^tenant-/i.test(client)) {
      console.log('skip', row.id, row.email || row.username, '(already', client || 'unset', ')');
      continue;
    }
    console.log(
      dryRun ? 'would restore' : 'restore',
      row.id,
      row.email || row.username,
      client + '/' + row.portal_files_job_id,
      '→',
      `${DEFAULT_CLIENT}/${DEFAULT_JOB}`
    );
    if (!dryRun) {
      await pool.query(
        `UPDATE users
         SET portal_files_client_id = $2,
             portal_files_job_id = $3,
             portal_files_access_granted = true,
             portal_permissions_access = true,
             updated_at = NOW()
         WHERE CAST(id AS text) = $1`,
        [String(row.id), DEFAULT_CLIENT, DEFAULT_JOB]
      );
    }
    restored += 1;
  }
  console.log(`${dryRun ? 'Would restore' : 'Restored'} ${restored} platform admin(s). Sign out and sign in again.`);
  await pool.end();
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
