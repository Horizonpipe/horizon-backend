'use strict';

const { EMPLOYEE_ROLES, looksLikeMike } = require('../capabilities');
const { isTenantBoundUser, userHasGlobalPsrBypass } = require('./tenant-wasabi-state');

/** Full planner + portal privileges for the tenant purchaser. */
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

function cleanString(v) {
  return String(v ?? '').trim();
}

/** Platform operator (Mike) — must keep legacy portal-users scope on base PipeShare. */
function isHorizonPlatformAdmin(userLike) {
  return looksLikeMike(userLike);
}

/**
 * True when this user purchased / owns a SaaS tenant workspace.
 * @param {{ query: Function }} pool
 * @param {string|number} userId
 */
async function isSaasTenantOwner(pool, userId) {
  const uid = cleanString(userId);
  if (!uid || !pool || typeof pool.query !== 'function') return false;
  const r = await pool.query(
    `SELECT 1
     FROM saas_tenant_instances
     WHERE CAST(owner_user_id AS text) = $1
     LIMIT 1`,
    [uid]
  );
  return r.rowCount > 0;
}

/**
 * Persist super-admin inside the purchaser's tenant (Postgres users row).
 * @param {{ query: Function }} pool
 * @param {string|number} userId
 */
async function applySaasTenantOwnerPrivileges(pool, userId) {
  const uid = cleanString(userId);
  if (!uid || !pool || typeof pool.query !== 'function') return { updated: false };

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

module.exports = {
  SAAS_OWNER_ROLES,
  isHorizonPlatformAdmin,
  isSaasTenantOwner,
  applySaasTenantOwnerPrivileges,
  isTenantBoundUser,
  userHasGlobalPsrBypass
};
