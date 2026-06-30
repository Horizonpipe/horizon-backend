'use strict';

const { looksLikeMike, canAccessAdminPanel, deriveAccountModel, ACCOUNT_TYPES } = require('../capabilities');
const { resolveTenantStorageContext } = require('./tenant-storage-context');
const { parseSaasTenantSlugFromHost, tenantSlugFromWasabiRoot } = require('./saas-tenant-access-urls');
const { resolveDeploymentProfile } = require('./deployment-profile');

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
 * SQL fragment to restrict users to one SaaS tenant virtualbox.
 * @param {number} [paramStart=1] - First $n index for portal_client_id (next is company_id).
 */
function tenantUsersWhereSql(paramStart) {
  const n = Number(paramStart) || 1;
  const pPortal = `$${n}`;
  const pCompany = `$${n + 1}`;
  return `(
  portal_files_client_id = ${pPortal}
  OR CAST(id AS text) IN (
    SELECT CAST(user_id AS text) FROM user_company_membership WHERE company_id = ${pCompany}::uuid
  )
  OR CAST(id AS text) IN (
    SELECT CAST(owner_user_id AS text) FROM saas_tenant_instances WHERE company_id = ${pCompany}::uuid
  )
)
AND (
  portal_files_client_id IS NULL
  OR BTRIM(portal_files_client_id) = ''
  OR portal_files_client_id = ${pPortal}
  OR LOWER(BTRIM(portal_files_client_id)) = 'portal-users'
)`;
}

/** @deprecated use tenantUsersWhereSql(1) — kept for callers that own $1/$2 */
const TENANT_USERS_WHERE_SQL = tenantUsersWhereSql(1);

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

function userRowIsTenantBound(userRow) {
  const pci = cleanString(userRow?.portal_files_client_id || userRow?.portalFilesClientId).toLowerCase();
  return pci.startsWith('tenant-');
}

/** Normalize login/session row shapes for capability checks. */
function userRowForCapabilityChecks(userRow) {
  if (!userRow || typeof userRow !== 'object') return null;
  return {
    username: userRow.username,
    displayName: userRow.display_name ?? userRow.displayName,
    display_name: userRow.display_name ?? userRow.displayName,
    email: userRow.email,
    accountType: userRow.account_type ?? userRow.accountType,
    account_type: userRow.account_type ?? userRow.accountType,
    employeeRole: userRow.employee_role ?? userRow.employeeRole,
    employee_role: userRow.employee_role ?? userRow.employeeRole,
    isAdmin: userRow.is_admin ?? userRow.isAdmin,
    is_admin: userRow.is_admin ?? userRow.isAdmin,
    roles: userRow.roles,
    selfSignup: userRow.self_signup ?? userRow.selfSignup,
    self_signup: userRow.self_signup ?? userRow.selfSignup,
    saasTenantOwner: userRow.saasTenantOwner ?? userRow.saas_tenant_owner ?? false,
    portal_files_client_id: userRow.portal_files_client_id ?? userRow.portalFilesClientId,
    portalFilesClientId: userRow.portalFilesClientId ?? userRow.portal_files_client_id
  };
}

/** Horizon Pipe employee on the BASE stack (not a SaaS company customer). */
function isHorizonBaseEmployee(userRow) {
  if (looksLikeMike(userRow)) return true;
  if (userRowIsTenantBound(userRow)) return false;
  const capUser = userRowForCapabilityChecks(userRow);
  if (!capUser) return false;
  const model = deriveAccountModel(capUser);
  return model.accountType === ACCOUNT_TYPES.EMPLOYEE;
}

/** Mike or Horizon admin panel user doing support overlay on a tenant subdomain. */
function isHorizonSupportOverlay(userRow) {
  if (looksLikeMike(userRow)) return true;
  if (userRowIsTenantBound(userRow)) return false;
  return canAccessAdminPanel(userRowForCapabilityChecks(userRow) || {});
}

function basePlatformOperatorLoginSql(alias) {
  const a = alias || 'u';
  return `(
    LOWER(TRIM(${a}.username)) IN ('mik', 'mike strickland')
    OR LOWER(TRIM(COALESCE(${a}.display_name, ''))) = 'mike strickland'
    OR LOWER(TRIM(COALESCE(${a}.email, ''))) = 'mike@horizonpipe.com'
  )`;
}

/** Base (pipeshare.live / private server) — legacy shared portal scope only. */
function baseLoginUsersWhereSql(alias) {
  const a = alias || 'u';
  return `(
    ${a}.portal_files_client_id IS NULL
    OR BTRIM(${a}.portal_files_client_id) = ''
    OR LOWER(BTRIM(${a}.portal_files_client_id)) = 'portal-users'
  )`;
}

async function userBelongsToSaasTenantBox(pool, userId, userRow = null) {
  const uid = cleanString(userId);
  if (!uid || !pool) return false;
  if (userRow && looksLikeMike(userRow)) return false;
  if (!userRow) {
    const identity = await pool.query(
      `SELECT username, display_name, email FROM users WHERE CAST(id AS text) = $1 LIMIT 1`,
      [uid]
    );
    if (looksLikeMike(identity.rows[0])) return false;
  }
  const r = await pool.query(
    `SELECT 1 AS ok
     FROM saas_tenant_instances t
     WHERE CAST(t.owner_user_id AS text) = $1
     UNION ALL
     SELECT 1
     FROM user_company_membership m
     INNER JOIN saas_tenant_instances t ON t.company_id = m.company_id
     WHERE CAST(m.user_id AS text) = $1
     LIMIT 1`,
    [uid]
  );
  return r.rows.length > 0;
}

/**
 * Hard wall: BASE logins never accept SaaS tenant accounts; tenant hosts never accept BASE accounts.
 * @returns {Promise<{ allowed: true } | { allowed: false, error: string }>}
 */
async function assertLoginEnvironmentAccess(pool, userRow, requestHost) {
  const profile = resolveDeploymentProfile({ requestHost });
  const hostScope = await loadTenantScopeByHost(pool, requestHost);
  const tenantBound = userRowIsTenantBound(userRow);
  const uid = cleanString(userRow?.id);

  if (looksLikeMike(userRow)) {
    return { allowed: true };
  }

  if (profile.isTenantWorkspaceHost && hostScope.mode === 'tenant') {
    if (isHorizonSupportOverlay(userRow)) {
      return { allowed: true };
    }
    const ok = uid ? await assertUserIdInTenantScope(pool, uid, hostScope) : false;
    if (!ok) {
      return {
        allowed: false,
        error: 'This account belongs to a different workspace. Sign in on your company PipeShare URL.'
      };
    }
    if (!tenantBound && !(await userBelongsToSaasTenantBox(pool, uid))) {
      return {
        allowed: false,
        error: 'This account is not part of this company workspace.'
      };
    }
    return { allowed: true };
  }

  if (profile.isPrivateBase) {
    if (isHorizonBaseEmployee(userRow)) {
      return { allowed: true };
    }
    if (tenantBound) {
      return {
        allowed: false,
        error:
          'This account belongs to a SaaS company workspace. Sign in on your company PipeShare site, not the base server.'
      };
    }
    if (uid && (await userBelongsToSaasTenantBox(pool, uid, userRow))) {
      return {
        allowed: false,
        error:
          'This account uses Horizonpipe SaaS. Sign in on pipeshare.net or your company subdomain — not the base PipeShare server.'
      };
    }
    return { allowed: true };
  }

  if (profile.isSaasPlatform && !profile.isTenantWorkspaceHost) {
    if (tenantBound) {
      return {
        allowed: false,
        error: 'Use your company PipeShare URL (yourcompany.pipeshare.net) to sign in.'
      };
    }
    const pci = cleanString(userRow?.portal_files_client_id || userRow?.portalFilesClientId).toLowerCase();
    if (pci === 'portal-users') {
      return {
        allowed: false,
        error: 'This account is for the base PipeShare server only.'
      };
    }
  }

  return { allowed: true };
}

async function assertLoginAllowedForTenantHost(pool, userRow, requestHost) {
  return assertLoginEnvironmentAccess(pool, userRow, requestHost);
}

/** Map session/API user object to the row shape used by login environment checks. */
function userLikeToLoginRow(userLike) {
  if (!userLike || typeof userLike !== 'object') return null;
  return {
    id: userLike.id,
    username: userLike.username,
    display_name: userLike.displayName ?? userLike.display_name,
    email: userLike.email,
    portal_files_client_id: userLike.portalFilesClientId ?? userLike.portal_files_client_id,
    account_type: userLike.accountType ?? userLike.account_type,
    employee_role: userLike.employeeRole ?? userLike.employee_role,
    is_admin: userLike.isAdmin ?? userLike.is_admin,
    roles: userLike.roles,
    self_signup: userLike.selfSignup ?? userLike.self_signup
  };
}

/**
 * Enforce BASE vs SaaS separation on every authenticated request (session reuse cannot bypass login wall).
 * @returns {Promise<{ allowed: true } | { allowed: false, error: string, code: string }>}
 */
async function assertAuthenticatedEnvironmentAccess(pool, sessionUser, requestHost) {
  const userRow = userLikeToLoginRow(sessionUser);
  if (!userRow?.id) {
    return { allowed: false, error: 'Authentication required', code: 'AUTH_REQUIRED' };
  }
  const env = await assertLoginEnvironmentAccess(pool, userRow, requestHost);
  if (env.allowed) return { allowed: true };
  return {
    allowed: false,
    error: env.error || 'This account cannot be used on this site.',
    code: 'ENVIRONMENT_ACCESS_DENIED'
  };
}

function usernamePortalScopeKey(portalClientId) {
  const pci = cleanString(portalClientId);
  return pci || '__global__';
}

/**
 * Username uniqueness is per portal scope (tenant virtualbox), not global platform-wide.
 * @returns {Promise<{ ok: true } | { ok: false, error: string }>}
 */
async function assertUsernameAvailableForCreate(pool, username, scope) {
  const name = cleanString(username);
  if (!name) return { ok: false, error: 'Username is required' };
  const scopeKey = scope?.mode === 'tenant' ? usernamePortalScopeKey(scope.portalClientId) : '__global__';
  const r = await pool.query(
    `SELECT id, portal_files_client_id
     FROM users
     WHERE LOWER(TRIM(username)) = LOWER(TRIM($1))
       AND COALESCE(NULLIF(BTRIM(portal_files_client_id), ''), '__global__') = $2
     LIMIT 1`,
    [name, scopeKey]
  );
  if (r.rows.length) {
    if (scope?.mode === 'tenant') {
      return { ok: false, error: 'Username already exists in your workspace.' };
    }
    return { ok: false, error: 'Username already exists' };
  }
  return { ok: true };
}

const LOGIN_USER_COLUMNS = `id, username, display_name, password, is_admin, account_type, employee_role, roles, must_change_password, portal_files_client_id, portal_files_job_id,
                email, email_verified, portal_files_access_granted, autosync_master_granted, portal_permissions_access, self_signup, product_tutorials_seen, user_prefs`;

function loginIdentityMatchSql(alias) {
  const a = alias || 'u';
  return `(LOWER(TRIM(${a}.username)) = LOWER(TRIM($1))
            OR LOWER(TRIM(COALESCE(${a}.display_name, ${a}.username))) = LOWER(TRIM($1))
            OR (${a}.email IS NOT NULL AND BTRIM(${a}.email) <> '' AND LOWER(TRIM(${a}.email)) = LOWER(TRIM($1))))`;
}

/**
 * Resolve login row — environment-scoped (BASE vs each SaaS tenant never cross).
 */
async function resolveLoginUserRow(pool, submittedUsername, requestHost) {
  const profile = resolveDeploymentProfile({ requestHost });
  const hostScope = await loadTenantScopeByHost(pool, requestHost);

  if (profile.isTenantWorkspaceHost && hostScope.mode === 'tenant') {
    const filterParams = tenantUserFilterParams(hostScope);
    const r = await pool.query(
      `SELECT ${LOGIN_USER_COLUMNS}
       FROM users u
       WHERE ${loginIdentityMatchSql('u')}
         AND ${tenantUsersWhereSql(2)}
       LIMIT 1`,
      [submittedUsername, ...filterParams]
    );
    return r.rows[0] || null;
  }

  if (profile.isPrivateBase) {
    const r = await pool.query(
      `SELECT ${LOGIN_USER_COLUMNS}
       FROM users u
       WHERE ${loginIdentityMatchSql('u')}
         AND (${baseLoginUsersWhereSql('u')} OR ${basePlatformOperatorLoginSql('u')})
       LIMIT 1`,
      [submittedUsername]
    );
    return r.rows[0] || null;
  }

  if (profile.isSaasPlatform && !profile.isTenantWorkspaceHost) {
    const r = await pool.query(
      `SELECT ${LOGIN_USER_COLUMNS}
       FROM users u
       WHERE ${loginIdentityMatchSql('u')}
         AND ${baseLoginUsersWhereSql('u')}
       LIMIT 1`,
      [submittedUsername]
    );
    return r.rows[0] || null;
  }

  const r = await pool.query(
    `SELECT ${LOGIN_USER_COLUMNS}
     FROM users u
     WHERE ${loginIdentityMatchSql('u')}
     LIMIT 1`,
    [submittedUsername]
  );
  return r.rows[0] || null;
}

module.exports = {
  TENANT_USERS_WHERE_SQL,
  tenantUsersWhereSql,
  isPlatformOperator,
  userCanManageTenantUsers,
  tenantUserFilterParams,
  resolveActorTenantScope,
  userRowBelongsToTenantScope,
  assertUserIdInTenantScope,
  loadTenantScopeByHost,
  assertLoginAllowedForTenantHost,
  assertLoginEnvironmentAccess,
  assertAuthenticatedEnvironmentAccess,
  userLikeToLoginRow,
  userRowIsTenantBound,
  assertUsernameAvailableForCreate,
  resolveLoginUserRow,
  serializeScopeFromTenantRow
};
