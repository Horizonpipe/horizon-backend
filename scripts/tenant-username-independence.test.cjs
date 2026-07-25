'use strict';

/**
 * Proves 40 SaaS workspaces can each own a user named "Mike" independently.
 * Everything runs in one transaction that always ROLLBACKs — no rows persist.
 */

require('dotenv').config();
const pg = require('pg');
const crypto = require('crypto');

const { assertUsernameAvailableForCreate, tenantUsersWhereSql } = require('../lib/saas-tenant-scope');

const TENANT_COUNT = 40;
const PREFIX = 'tenant-zztest';

let failures = 0;
function check(name, actual, expected) {
  const ok = actual === expected;
  if (!ok) failures += 1;
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}  (got ${JSON.stringify(actual)}, want ${JSON.stringify(expected)})`);
}

function scopeFor(i) {
  return {
    mode: 'tenant',
    portalClientId: `${PREFIX}${i}`,
    portalJobId: '1',
    companyId: crypto.randomUUID()
  };
}

function loginIdentityMatchSql(alias) {
  const a = alias || 'u';
  return `(LOWER(TRIM(${a}.username)) = LOWER(TRIM($1))
            OR LOWER(TRIM(COALESCE(${a}.display_name, ${a}.username))) = LOWER(TRIM($1))
            OR (${a}.email IS NOT NULL AND BTRIM(${a}.email) <> '' AND LOWER(TRIM(${a}.email)) = LOWER(TRIM($1))))`;
}

async function insertUser(client, username, portalClientId) {
  const r = await client.query(
    `INSERT INTO users (username, display_name, password, is_admin, account_type, employee_role, roles,
                        must_change_password, portal_files_client_id, portal_files_job_id, portal_files_access_granted, self_signup)
     VALUES ($1, $1, 'x', false, 'employee', 'camera-operator', '{}'::jsonb, true, $2, '1', false, false)
     RETURNING id`,
    [username, portalClientId]
  );
  return String(r.rows[0].id);
}

async function main() {
  const pool = new pg.Pool({ connectionString: process.env.DATABASE_URL });
  const client = await pool.connect();
  const scopes = [];
  try {
    /** Sequences are non-transactional, so this repair survives the rollback (ids just skip ahead). */
    await client.query(
      `SELECT setval(pg_get_serial_sequence('users','id'), GREATEST((SELECT COALESCE(MAX(id),0) FROM users), 1))
       WHERE pg_get_serial_sequence('users','id') IS NOT NULL`
    );

    await client.query('BEGIN');

    console.log(`--- ${TENANT_COUNT} workspaces each create "Mike" ---`);
    let created = 0;
    let blocked = 0;
    for (let i = 1; i <= TENANT_COUNT; i += 1) {
      const scope = scopeFor(i);
      scopes.push(scope);
      const avail = await assertUsernameAvailableForCreate(client, 'Mike', scope);
      if (!avail.ok) {
        blocked += 1;
        console.log(`   blocked in ${scope.portalClientId}: ${avail.error}`);
        continue;
      }
      await insertUser(client, 'Mike', scope.portalClientId);
      created += 1;
    }
    check('every workspace created its own Mike', created, TENANT_COUNT);
    check('no workspace was falsely blocked', blocked, 0);

    const total = await client.query(
      `SELECT COUNT(*)::int AS n FROM users WHERE LOWER(TRIM(username)) = 'mike' AND portal_files_client_id LIKE $1`,
      [`${PREFIX}%`]
    );
    check('40 independent Mike rows exist', total.rows[0].n, TENANT_COUNT);

    console.log('--- duplicate inside the SAME workspace is still refused ---');
    const dupCheck = await assertUsernameAvailableForCreate(client, 'Mike', scopes[0]);
    check('same-workspace duplicate rejected by pre-check', dupCheck.ok, false);
    console.log(`   message: ${dupCheck.error}`);
    let dbRejected = false;
    try {
      await client.query('SAVEPOINT dup_try');
      await insertUser(client, 'Mike', scopes[0].portalClientId);
      await client.query('RELEASE SAVEPOINT dup_try');
    } catch (err) {
      dbRejected = err.code === '23505';
      await client.query('ROLLBACK TO SAVEPOINT dup_try');
    }
    check('same-workspace duplicate rejected by unique index', dbRejected, true);

    console.log('--- each workspace login resolves only its own Mike ---');
    let correctlyScoped = 0;
    for (const scope of scopes.slice(0, 5)) {
      const r = await client.query(
        `SELECT id, username, portal_files_client_id
         FROM users u
         WHERE ${loginIdentityMatchSql('u')} AND ${tenantUsersWhereSql(2)}`,
        ['Mike', scope.portalClientId, scope.companyId]
      );
      const own = r.rows.filter((row) => row.portal_files_client_id === scope.portalClientId);
      const foreign = r.rows.filter(
        (row) => String(row.portal_files_client_id || '').startsWith(PREFIX) && row.portal_files_client_id !== scope.portalClientId
      );
      if (own.length === 1 && foreign.length === 0) correctlyScoped += 1;
      else console.log(`   ${scope.portalClientId}: own=${own.length} foreign=${foreign.length}`);
    }
    check('login lookup is workspace-scoped (5 sampled)', correctlyScoped, 5);

    console.log('--- a workspace "Mike Strickland" cannot reach the BASE operator login ---');
    const tenantOperatorId = await insertUser(client, 'Mike Strickland', scopes[0].portalClientId);
    const baseResolve = await client.query(
      `SELECT id, username, portal_files_client_id
       FROM users u
       WHERE ${loginIdentityMatchSql('u')}
         AND (
           (u.portal_files_client_id IS NULL OR BTRIM(u.portal_files_client_id) = ''
            OR LOWER(BTRIM(u.portal_files_client_id)) = 'portal-users')
           OR (
             (
               LOWER(TRIM(u.username)) IN ('mik', 'mike strickland')
               OR LOWER(TRIM(COALESCE(u.display_name, ''))) = 'mike strickland'
               OR LOWER(TRIM(COALESCE(u.email, ''))) = 'mike@horizonpipe.com'
             )
             AND LOWER(BTRIM(COALESCE(u.portal_files_client_id, ''))) NOT LIKE 'tenant-%'
           )
         )`,
      ['Mike Strickland']
    );
    const leaked = baseResolve.rows.some((row) => String(row.id) === tenantOperatorId);
    check('tenant operator-named row never resolves on BASE login', leaked, false);
    console.log(`   BASE login candidates: ${JSON.stringify(baseResolve.rows)}`);
  } finally {
    await client.query('ROLLBACK');
    client.release();
    await pool.end();
  }
  console.log(failures ? `\n${failures} FAILED` : '\nALL PASSED (rolled back, nothing persisted)');
  process.exit(failures ? 1 : 0);
}

main().catch((err) => {
  console.error('TEST ERROR', err);
  process.exit(1);
});
