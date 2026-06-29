'use strict';

const { EMPLOYEE_ROLES, looksLikeMike } = require('../capabilities');
const { isTenantBoundUser, userHasGlobalPsrBypass } = require('./tenant-wasabi-state');
const { subscriptionIsActive } = require('./saas-customer-access');
const { upsertTenantOwnerAuthSnapshot } = require('./saas-tenant-auth-store');
const { seedTenantAppDataSnapshot } = require('./tenant-wasabi-state');
const { tenantSlugFromWasabiRoot } = require('./saas-tenant-access-urls');

/** Full planner + portal privileges for the tenant purchaser (after active subscription). */
const SAAS_OWNER_ROLES = Object.freeze({
  camera: true,
  vac: true,
  simpleVac: true,
  email: true,
  psrPlanner: true,
  psrViewer: true,
  psrDataEntry: true,
  dataAutoSyncEmployee: true,
  pricingView: true,
  footageView: true,
  jobsiteContactsView: true,
  portalUpload: true,
  portalDownload: true,
  portalEdit: true,
  portalDelete: true
});

/** Self-signup / pre-subscription baseline — no product tools until subscription + login. */
const SAAS_PURCHASER_BASELINE_ROLES = Object.freeze({
  camera: false,
  vac: false,
  simpleVac: false,
  email: false,
  psrPlanner: false,
  psrViewer: false,
  psrDataEntry: false,
  dataAutoSyncEmployee: false,
  pricingView: false,
  footageView: false,
  jobsiteContactsView: false,
  portalUpload: false,
  portalDownload: false,
  portalEdit: false,
  portalDelete: false
});

function cleanString(v) {
  return String(v ?? '').trim();
}

/** Platform operator (Mike) — must keep legacy portal-users scope on base PipeShare. */
function isHorizonPlatformAdmin(userLike) {
  return looksLikeMike(userLike);
}

async function loadOwnerUserRow(pool, userId) {
  const uid = cleanString(userId);
  if (!uid || !pool || typeof pool.query !== 'function') return null;
  const r = await pool.query(
    `SELECT id, username, display_name, email FROM users WHERE CAST(id AS text) = $1 LIMIT 1`,
    [uid]
  );
  return r.rows[0] || null;
}

async function loadOwnerTenantRow(pool, userId) {
  const uid = cleanString(userId);
  if (!uid || !pool || typeof pool.query !== 'function') return null;
  const r = await pool.query(
    `SELECT id, subscription_status, wasabi_root_prefix, company_id
     FROM saas_tenant_instances
     WHERE CAST(owner_user_id AS text) = $1
     LIMIT 1`,
    [uid]
  );
  return r.rows[0] || null;
}

/**
 * True when this user owns a SaaS tenant row (purchaser — may not have subscribed yet).
 * @param {{ query: Function }} pool
 * @param {string|number} userId
 */
async function isSaasTenantOwner(pool, userId) {
  const userRow = await loadOwnerUserRow(pool, userId);
  if (looksLikeMike(userRow)) return false;
  const row = await loadOwnerTenantRow(pool, userId);
  return !!row;
}

/**
 * Session/capability flags from tenant row (read-only).
 * @returns {Promise<{ tenantPurchaser: boolean, saasTenantOwner: boolean, subscriptionStatus: string|null }>}
 */
async function getSaasOwnerSessionContext(pool, userId) {
  const userRow = await loadOwnerUserRow(pool, userId);
  if (looksLikeMike(userRow)) {
    return { tenantPurchaser: false, saasTenantOwner: false, subscriptionStatus: null };
  }
  const tenantRow = await loadOwnerTenantRow(pool, userId);
  if (!tenantRow) {
    return { tenantPurchaser: false, saasTenantOwner: false, subscriptionStatus: null };
  }
  const subscriptionStatus = cleanString(tenantRow.subscription_status).toLowerCase() || 'expired';
  const active = subscriptionIsActive(subscriptionStatus);
  return {
    tenantPurchaser: true,
    saasTenantOwner: active,
    subscriptionStatus
  };
}

async function seedOwnerWorkspaceSnapshots(pool, userId, tenantRow) {
  const uid = cleanString(userId);
  const slug = tenantSlugFromWasabiRoot(tenantRow?.wasabi_root_prefix);
  if (!slug || !uid) return;
  try {
    const ownerRow = await pool.query(
      `SELECT id, username, email, display_name FROM users WHERE CAST(id AS text) = $1 LIMIT 1`,
      [uid]
    );
    if (ownerRow.rows[0]) {
      await upsertTenantOwnerAuthSnapshot(slug, ownerRow.rows[0]);
    }
    await seedTenantAppDataSnapshot(slug);
  } catch (error) {
    console.warn('[saas] tenant workspace seed failed:', error?.message || error);
  }
}

/**
 * Persist super-admin inside the purchaser's tenant (Postgres users row).
 * Call only when subscription is active.
 */
async function applySaasTenantOwnerPrivileges(pool, userId) {
  const uid = cleanString(userId);
  if (!uid || !pool || typeof pool.query !== 'function') return { updated: false };

  const userRow = await loadOwnerUserRow(pool, uid);
  if (looksLikeMike(userRow)) return { updated: false, reason: 'platform_operator' };

  const owner = await isSaasTenantOwner(pool, uid);
  if (!owner) return { updated: false, reason: 'not_owner' };

  await pool.query(
    `UPDATE users
     SET account_type = 'employee',
         employee_role = $2,
         is_admin = false,
         portal_permissions_access = true,
         portal_files_access_granted = COALESCE(portal_files_access_granted, true),
         roles = $3::jsonb,
         updated_at = NOW()
     WHERE CAST(id AS text) = $1`,
    [uid, EMPLOYEE_ROLES.SUPERADMIN, JSON.stringify(SAAS_OWNER_ROLES)]
  );
  return { updated: true };
}

/** Revert purchaser to cPanel-only access when subscription is not active. */
async function revokeSaasTenantOwnerPrivileges(pool, userId) {
  const uid = cleanString(userId);
  if (!uid || !pool || typeof pool.query !== 'function') return { updated: false };

  const owner = await isSaasTenantOwner(pool, uid);
  if (!owner) return { updated: false, reason: 'not_owner' };

  await pool.query(
    `UPDATE users
     SET account_type = 'customer',
         employee_role = NULL,
         is_admin = false,
         portal_permissions_access = false,
         portal_files_access_granted = false,
         portal_files_client_id = NULL,
         portal_files_job_id = NULL,
         roles = $2::jsonb,
         updated_at = NOW()
     WHERE CAST(id AS text) = $1`,
    [uid, JSON.stringify(SAAS_PURCHASER_BASELINE_ROLES)]
  );
  return { updated: true };
}

/**
 * Apply or revoke workspace-owner tool permissions based on current DB subscription_status.
 * Stripe sync must run before this on login (see server.js POST /login).
 */
async function refreshSaasTenantOwnerAccess(pool, userId) {
  const userRow = await loadOwnerUserRow(pool, userId);
  if (looksLikeMike(userRow)) {
    return { tenantPurchaser: false, saasTenantOwner: false, subscriptionStatus: null };
  }
  const tenantRow = await loadOwnerTenantRow(pool, userId);
  if (!tenantRow) {
    return { tenantPurchaser: false, saasTenantOwner: false, subscriptionStatus: null };
  }

  const subscriptionStatus = cleanString(tenantRow.subscription_status).toLowerCase() || 'expired';
  const active = subscriptionIsActive(subscriptionStatus);

  if (active) {
    await applySaasTenantOwnerPrivileges(pool, userId);
    await seedOwnerWorkspaceSnapshots(pool, userId, tenantRow);
  } else {
    await revokeSaasTenantOwnerPrivileges(pool, userId);
  }

  return {
    tenantPurchaser: true,
    saasTenantOwner: active,
    subscriptionStatus
  };
}

module.exports = {
  SAAS_OWNER_ROLES,
  SAAS_PURCHASER_BASELINE_ROLES,
  isHorizonPlatformAdmin,
  isSaasTenantOwner,
  getSaasOwnerSessionContext,
  applySaasTenantOwnerPrivileges,
  revokeSaasTenantOwnerPrivileges,
  refreshSaasTenantOwnerAccess,
  isTenantBoundUser,
  userHasGlobalPsrBypass
};
