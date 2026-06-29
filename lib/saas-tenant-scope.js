'use strict';

const { looksLikeMike, canAccessAdminPanel } = require('../capabilities');
const { resolveTenantStorageContext } = require('./tenant-storage-context');
const { parseSaasTenantSlugFromHost, tenantSlugFromWasabiRoot } = require('./saas-tenant-access-urls');

function cleanString(v) {
  return String(v ?? '').trim();
}

function isPlatformOperator(user) {
  return looksLikeMike(user) && canAccessAdminPanel(user);
}

function userCanManageTenantUsers(user, scope) {
  if (!user || scope?.mode !== 'tenant') return false;
  return !!(
    user.portalPermissionsAccess === true ||
    user.saasTenantOwner === true ||
    user.tenantAdmin === true ||
    user.tenantPurchaser === true
  );
}

/**
 * SQL fragment + params to restrict users to one SaaS tenant virtualbox.
 * $1 = portal_client_id, $2 = company_id (uuid)
 */
const TENANT_USERS_WHERE_SQL = `(
  portal_files_client_id = $1
  OR CAST(id AS text) IN (
    SELECT CAST(user_id AS text) FROM user_company_membership WHERE company_id = $2::uuid
  )
  OR CAST(id AS text) IN (
    SELECT CAST(owner_user_id AS text) FROM saas_tenant_instances WHERE company_id = $2::uuid
  )
)
AND (
  portal_files_client_id IS NULL
  OR portal_files_client_id = $1
)`;

function tenantUserFilterParams(scope) {
  if (!scope || scope.mode !== 'tenant') return null;
  return [scope.portalClientId, scope.companyId];
}

function serializeScopeFromTenantRow(row) {
  if (!row) return { mode: 'none' };
  const slug =
    cleanString(row.tenant_slug) ||
    tenantSlugFromWasabiRoot(row.wasabi_root_prefix || row.wasabiRootPrefix);
  return {
    mode: 'tenant',
    companyId: cleanString(row.company_id || row.companyId),
    portalClientId: cleanString(row.portal_client_id || row.portalClientId),
    portalJobId: cleanString(row.portal_job_id || row.portalJobId) || '1',
    tenantId: cleanString(row.id || row.tenantId),
    tenantSlug: slug,
    postgresSchema: cleanString(row.postgres_schema || row.postgresSchema),
    wasabiRootPrefix: cleanString(row.wasabi_root_prefix || row.wasabiRootPrefix)
  };
}

/**
 * Resolve whether the signed-in user acts as platform operator or inside one tenant box.
 * @param {{ query: Function }} pool
 * @param {object|null} user
 * @param {{ requestHost?: string }} [options]
 */
async function resolveActorTenantScope(pool, user, options = {}) {
  if (!user || !pool || typeof pool.query !== 'function') {
    return { mode: 'none' };
  }

  const requestHost = cleanString(options.requestHost);
  if (isPlatformOperator(user)) {
    const hostSlug = parseSaasTenantSlugFromHost(requestHost);
    if (!hostSlug) {
      return { mode: 'platform' };
    }
  }

  const storageCtx = await resolveTenantStorageContext(pool, user.id, { requestHost });
  if (storageCtx?.companyId && storageCtx?.portalClientId) {
    const row = await pool.query(
      `SELECT id, company_id, portal_client_id, portal_job_id, wasabi_root_prefix, postgres_schema
       FROM saas_tenant_instances
       WHERE portal_client_id = $1 AND portal_job_id = $2
       LIMIT 1`,
      [storageCtx.portalClientId, storageCtx.portalJobId || '1']
    );
    return serializeScopeFromTenantRow(row.rows[0] || {
      id: storageCtx.tenantId,
      company_id: storageCtx.companyId,
      portal_client_id: storageCtx.portalClientId,
      portal_job_id: storageCtx.portalJobId,
      wasabi_root_prefix: storageCtx.wasabiRootPrefix
    });
  }

  const ownerRow = await pool.query(
    `SELECT id, company_id, portal_client_id, portal_job_id, wasabi_root_prefix, postgres_schema
     FROM saas_tenant_instances
     WHERE CAST(owner_user_id AS text) = $1
     LIMIT 1`,
    [String(user.id)]
  );
  if (ownerRow.rows[0]) {
    return serializeScopeFromTenantRow(ownerRow.rows[0]);
  }

  const membership = await pool.query(
    `SELECT t.id, t.company_id, t.portal_client_id, t.portal_job_id, t.wasabi_root_prefix, t.postgres_schema
     FROM user_company_membership m
     JOIN saas_tenant_instances t ON t.company_id = m.company_id
     WHERE CAST(m.user_id AS text) = $1
     LIMIT 1`,
    [String(user.id)]
  );
  if (membership.rows[0]) {
    return serializeScopeFromTenantRow(membership.rows[0]);
  }

  return { mode: 'none' };
}

function userRowBelongsToTenantScope(userRow, scope) {
  if (!userRow || !scope || scope.mode !== 'tenant') return false;
  const portalClientId = cleanString(userRow.portal_files_client_id || userRow.portalFilesClientId);
  const userId = cleanString(userRow.id);
  if (portalClientId && portalClientId === scope.portalClientId) return true;
  if (portalClientId && portalClientId !== scope.portalClientId) {
    if (portalClientId.startsWith('tenant-') || portalClientId === 'portal-users') return false;
  }
  return false;
}

async function assertUserIdInTenantScope(pool, userId, scope) {
  if (!scope || scope.mode !== 'tenant') return true;
  const params = tenantUserFilterParams(scope);
  if (!params) return false;
  const r = await pool.query(
    `SELECT id FROM users WHERE CAST(id AS text) = $3 AND ${TENANT_USERS_WHERE_SQL} LIMIT 1`,
    [...params, String(userId)]
  );
  return r.rows.length > 0;
}

async function loadTenantScopeByHost(pool, requestHost) {
  const slug = parseSaasTenantSlugFromHost(requestHost);
  if (!slug) return { mode: 'none' };
  const r = await pool.query(
    `SELECT id, company_id, portal_client_id, portal_job_id, wasabi_root_prefix, postgres_schema
     FROM saas_tenant_instances
     WHERE portal_client_id = $1
     LIMIT 1`,
    [`tenant-${slug}`]
  );
  return serializeScopeFromTenantRow(r.rows[0]);
}

async function assertLoginAllowedForTenantHost(pool, userRow, requestHost) {
  const hostScope = await loadTenantScopeByHost(pool, requestHost);
  if (hostScope.mode !== 'tenant') return { allowed: true };
  const uid = cleanString(userRow?.id);
  if (!uid) return { allowed: false, error: 'Invalid account' };
  const ok = await assertUserIdInTenantScope(pool, uid, hostScope);
  if (ok) return { allowed: true };
  return {
    allowed: false,
    error: 'This account belongs to a different workspace. Sign in on your company subdomain.'
  };
}

module.exports = {
  TENANT_USERS_WHERE_SQL,
  isPlatformOperator,
  userCanManageTenantUsers,
  tenantUserFilterParams,
  resolveActorTenantScope,
  userRowBelongsToTenantScope,
  assertUserIdInTenantScope,
  loadTenantScopeByHost,
  assertLoginAllowedForTenantHost,
  serializeScopeFromTenantRow
};
