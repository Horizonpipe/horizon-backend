/**
 * Single source of truth for authorization flags derived from `normalizeUser()` rows.
 * Legacy DB columns (`is_admin`, `portal_permissions_access`, `roles` JSONB) stay;
 * API consumers should prefer `capabilities` on GET /session.
 */

function portalPermissionsWhitelist() {
  return (process.env.PORTAL_PERMISSIONS_WHITELIST_USERS || '')
    .split(',')
    .map((s) => s.trim().toLowerCase())
    .filter(Boolean);
}

/** Global Horizon super-admin (full infrastructure routes). */
function isSuperAdmin(user) {
  return user?.isAdmin === true;
}

/**
 * Admin Panel: user CRUD, permission trees, account requests.
 * Horizon global admins only (`is_admin`); not `portal_permissions_access`.
 */
function canAccessAdminPanel(user) {
  if (!user) return false;
  return user.isAdmin === true;
}

/**
 * Portal file ACL / path grants / share extras (PipeShare).
 * Global admin or env username whitelist only (not `portal_permissions_access`).
 */
function canManagePortalExtras(user) {
  if (!user) return false;
  if (user.isAdmin === true) return true;
  const u = String(user.username || '')
    .trim()
    .toLowerCase();
  return portalPermissionsWhitelist().includes(u);
}

/**
 * @param {object|null} user - normalized user (camelCase) from `normalizeUser` + scopes
 * @returns {object} Stable shape for `/session` and clients
 */
function resolveCapabilities(user) {
  const roles = user?.roles && typeof user.roles === 'object' ? user.roles : {};
  return {
    version: 1,
    superAdmin: isSuperAdmin(user),
    /** User Manager / PipeSync admin panel — `is_admin` only */
    canAccessAdminPanel: canAccessAdminPanel(user),
    /** PipeShare ACL / path grants — global admin or `PORTAL_PERMISSIONS_WHITELIST_USERS` */
    canManagePortalExtras: canManagePortalExtras(user),
    psrPlanner: !!roles.psrPlanner,
    psrViewer: !!roles.psrViewer,
    psrDataEntry: !!roles.psrDataEntry,
    camera: !!roles.camera,
    vac: !!roles.vac,
    simpleVac: !!roles.simpleVac,
    pricingView: !!roles.pricingView,
    footageView: !!roles.footageView,
    dataAutoSyncEmployee: !!roles.dataAutoSyncEmployee,
    email: !!roles.email,
    portalUpload: !!roles.portalUpload,
    portalDownload: !!roles.portalDownload,
    portalEdit: !!roles.portalEdit,
    portalDelete: !!roles.portalDelete
  };
}

module.exports = {
  resolveCapabilities,
  isSuperAdmin,
  canAccessAdminPanel,
  canManagePortalExtras,
  portalPermissionsWhitelist
};
