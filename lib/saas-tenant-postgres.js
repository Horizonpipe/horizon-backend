'use strict';

const { slugifyTenantName } = require('./saas-tenant-paths');

function cleanString(v) {
  return String(v ?? '').trim();
}

function schemaNameForTenantSlug(slug) {
  const base = slugifyTenantName(slug);
  if (!base) throw new Error('Invalid tenant slug for postgres schema');
  const safe = base.replace(/[^a-z0-9_]/g, '_').slice(0, 48);
  return `tenant_${safe}`;
}

function quoteIdent(name) {
  return `"${String(name).replace(/"/g, '""')}"`;
}

/**
 * Create an isolated Postgres schema + login mirror table for one SaaS tenant.
 * Global `users` remains the auth source; tenant schema holds a scoped copy for isolation audits.
 * @param {{ query: Function }} pool
 * @param {string} slug
 */
async function provisionTenantPostgresSchema(pool, slug) {
  const schema = schemaNameForTenantSlug(slug);
  if (!pool || typeof pool.query !== 'function') {
    return { ok: false, schema, reason: 'no_pool' };
  }
  const qSchema = quoteIdent(schema);
  await pool.query(`CREATE SCHEMA IF NOT EXISTS ${qSchema}`);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS ${qSchema}.login_users (
      id TEXT PRIMARY KEY,
      global_user_id TEXT NOT NULL UNIQUE,
      username TEXT NOT NULL,
      email TEXT,
      display_name TEXT,
      password_hash TEXT,
      roles JSONB NOT NULL DEFAULT '{}'::jsonb,
      account_type TEXT,
      employee_role TEXT,
      portal_files_client_id TEXT,
      portal_files_job_id TEXT,
      portal_files_access_granted BOOLEAN NOT NULL DEFAULT false,
      portal_permissions_access BOOLEAN NOT NULL DEFAULT false,
      self_signup BOOLEAN NOT NULL DEFAULT false,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);
  await pool.query(`
    CREATE INDEX IF NOT EXISTS ${quoteIdent(`${schema}_login_users_username_idx`)}
    ON ${qSchema}.login_users (LOWER(username))
  `);
  return { ok: true, schema };
}

async function mirrorUserToTenantLoginSchema(pool, schema, userRow) {
  const s = cleanString(schema);
  if (!s || !pool || !userRow) return { ok: false, reason: 'missing_args' };
  const qSchema = quoteIdent(s);
  const globalId = cleanString(userRow.id);
  if (!globalId) return { ok: false, reason: 'missing_user_id' };
  await pool.query(
    `INSERT INTO ${qSchema}.login_users (
       id, global_user_id, username, email, display_name, password_hash, roles,
       account_type, employee_role, portal_files_client_id, portal_files_job_id,
       portal_files_access_granted, portal_permissions_access, self_signup, updated_at
     ) VALUES (
       $1, $1, $2, $3, $4, $5, $6::jsonb, $7, $8, $9, $10, $11, $12, $13, NOW()
     )
     ON CONFLICT (global_user_id) DO UPDATE SET
       username = EXCLUDED.username,
       email = EXCLUDED.email,
       display_name = EXCLUDED.display_name,
       password_hash = COALESCE(EXCLUDED.password_hash, ${qSchema}.login_users.password_hash),
       roles = EXCLUDED.roles,
       account_type = EXCLUDED.account_type,
       employee_role = EXCLUDED.employee_role,
       portal_files_client_id = EXCLUDED.portal_files_client_id,
       portal_files_job_id = EXCLUDED.portal_files_job_id,
       portal_files_access_granted = EXCLUDED.portal_files_access_granted,
       portal_permissions_access = EXCLUDED.portal_permissions_access,
       self_signup = EXCLUDED.self_signup,
       updated_at = NOW()`,
    [
      globalId,
      cleanString(userRow.username),
      cleanString(userRow.email) || null,
      cleanString(userRow.display_name || userRow.displayName),
      cleanString(userRow.password),
      JSON.stringify(userRow.roles && typeof userRow.roles === 'object' ? userRow.roles : {}),
      cleanString(userRow.account_type || userRow.accountType) || null,
      cleanString(userRow.employee_role || userRow.employeeRole) || null,
      cleanString(userRow.portal_files_client_id || userRow.portalFilesClientId) || null,
      cleanString(userRow.portal_files_job_id || userRow.portalJobId) || '1',
      userRow.portal_files_access_granted === true || userRow.portalFilesAccessGranted === true,
      userRow.portal_permissions_access === true || userRow.portalPermissionsAccess === true,
      userRow.self_signup === true || userRow.selfSignup === true
    ]
  );
  return { ok: true };
}

async function removeUserFromTenantLoginSchema(pool, schema, userId) {
  const s = cleanString(schema);
  const uid = cleanString(userId);
  if (!s || !uid || !pool) return { ok: false };
  await pool.query(`DELETE FROM ${quoteIdent(s)}.login_users WHERE global_user_id = $1`, [uid]);
  return { ok: true };
}

module.exports = {
  schemaNameForTenantSlug,
  provisionTenantPostgresSchema,
  mirrorUserToTenantLoginSchema,
  removeUserFromTenantLoginSchema
};
