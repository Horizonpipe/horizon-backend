/**
 * Canonical auth model
 * - accountType: employee | customer
 * - employeeRole (when employee): camera_operator | vac_operator | simple_vac | admin | superadmin
 *
 * Legacy role booleans still exist for backward compatibility with older route/page checks.
 */

const ACCOUNT_TYPES = Object.freeze({
  EMPLOYEE: 'employee',
  CUSTOMER: 'customer'
});

const EMPLOYEE_ROLES = Object.freeze({
  CAMERA_OPERATOR: 'camera_operator',
  VAC_OPERATOR: 'vac_operator',
  SIMPLE_VAC: 'simple_vac',
  ADMIN: 'admin',
  SUPERADMIN: 'superadmin'
});

const MIKE_IDENTIFIERS = new Set(['mik', 'mike strickland', 'mike@horizonpipe.com']);

/** Horizon Pipe internal accounts (Pipeshare.net operator stack). */
const HOSTING_TIERS = Object.freeze({
  BASE: 'base',
  SAAS: 'saas'
});

function normalizeAccountType(value) {
  const raw = String(value || '')
    .trim()
    .toLowerCase();
  if (raw === ACCOUNT_TYPES.CUSTOMER) return ACCOUNT_TYPES.CUSTOMER;
  return ACCOUNT_TYPES.EMPLOYEE;
}

function normalizeEmployeeRole(value) {
  const raw = String(value || '')
    .trim()
    .toLowerCase();
  if (raw === EMPLOYEE_ROLES.CAMERA_OPERATOR) return EMPLOYEE_ROLES.CAMERA_OPERATOR;
  if (raw === EMPLOYEE_ROLES.VAC_OPERATOR) return EMPLOYEE_ROLES.VAC_OPERATOR;
  if (raw === EMPLOYEE_ROLES.SIMPLE_VAC) return EMPLOYEE_ROLES.SIMPLE_VAC;
  if (raw === EMPLOYEE_ROLES.ADMIN) return EMPLOYEE_ROLES.ADMIN;
  if (raw === EMPLOYEE_ROLES.SUPERADMIN) return EMPLOYEE_ROLES.SUPERADMIN;
  return '';
}

function normalizeLegacyRoles(value) {
  const out = {
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
  };
  if (!value || typeof value !== 'object' || Array.isArray(value)) return out;
  for (const key of Object.keys(out)) out[key] = value[key] === true;
  return out;
}

function looksLikeMike(userLike) {
  const username = String(userLike?.username || '')
    .trim()
    .toLowerCase();
  const displayName = String(userLike?.displayName || userLike?.display_name || '')
    .trim()
    .toLowerCase();
  const email = String(userLike?.email || '')
    .trim()
    .toLowerCase();
  return MIKE_IDENTIFIERS.has(username) || MIKE_IDENTIFIERS.has(displayName) || MIKE_IDENTIFIERS.has(email);
}

/** SaaS workspace purchaser — super-admin inside their tenant, not global Horizon admin. */
function isSaasWorkspaceOwner(user) {
  if (looksLikeMike(user)) return false;
  return user?.saasTenantOwner === true || user?.isSaasTenantOwner === true;
}

/**
 * BASE = Horizon Pipe operator / employee accounts on the primary Postgres stack.
 * SAAS = self-service subscription accounts provisioned for tenant isolation.
 */
function resolveHostingTier(userLike) {
  if (looksLikeMike(userLike)) return HOSTING_TIERS.BASE;
  const portalClientId = String(userLike?.portalFilesClientId ?? userLike?.portal_files_client_id ?? '')
    .trim()
    .toLowerCase();
  if (portalClientId.startsWith('tenant-')) return HOSTING_TIERS.SAAS;
  if (userLike?.saasTenantOwner === true || userLike?.isSaasTenantOwner === true) return HOSTING_TIERS.SAAS;
  if (userLike?.tenantPurchaser === true) return HOSTING_TIERS.SAAS;
  const model = deriveAccountModel(userLike || {});
  if ((userLike?.selfSignup === true || userLike?.self_signup === true) && model.accountType === ACCOUNT_TYPES.CUSTOMER) {
    if (portalClientId.startsWith('tenant-') || userLike?.tenantPurchaser === true) {
      return HOSTING_TIERS.SAAS;
    }
    if (portalClientId === 'portal-users' || !portalClientId) {
      return HOSTING_TIERS.BASE;
    }
    return HOSTING_TIERS.SAAS;
  }
  if (model.accountType === ACCOUNT_TYPES.EMPLOYEE) return HOSTING_TIERS.BASE;
  return HOSTING_TIERS.SAAS;
}

function isBasePlatformUser(userLike) {
  return resolveHostingTier(userLike) === HOSTING_TIERS.BASE;
}

function inferModelFromLegacy(userLike) {
  const roles = normalizeLegacyRoles(userLike?.roles);
  if (looksLikeMike(userLike)) {
    return { accountType: ACCOUNT_TYPES.EMPLOYEE, employeeRole: EMPLOYEE_ROLES.SUPERADMIN };
  }
  if (userLike?.isAdmin === true || userLike?.is_admin === true) {
    return { accountType: ACCOUNT_TYPES.EMPLOYEE, employeeRole: EMPLOYEE_ROLES.ADMIN };
  }
  if (roles.simpleVac) return { accountType: ACCOUNT_TYPES.EMPLOYEE, employeeRole: EMPLOYEE_ROLES.SIMPLE_VAC };
  if (roles.vac) return { accountType: ACCOUNT_TYPES.EMPLOYEE, employeeRole: EMPLOYEE_ROLES.VAC_OPERATOR };
  if (roles.camera) return { accountType: ACCOUNT_TYPES.EMPLOYEE, employeeRole: EMPLOYEE_ROLES.CAMERA_OPERATOR };
  return { accountType: ACCOUNT_TYPES.CUSTOMER, employeeRole: null };
}

function deriveAccountModel(userLike) {
  /** SaaS workspace purchaser — super admin inside their own tenant instance. */
  if (
    !looksLikeMike(userLike) &&
    (userLike?.saasTenantOwner === true || userLike?.isSaasTenantOwner === true)
  ) {
    return { accountType: ACCOUNT_TYPES.EMPLOYEE, employeeRole: EMPLOYEE_ROLES.SUPERADMIN };
  }
  const explicitRole = normalizeEmployeeRole(userLike?.employeeRole || userLike?.employee_role);
  if (explicitRole === EMPLOYEE_ROLES.SUPERADMIN) {
    return { accountType: ACCOUNT_TYPES.EMPLOYEE, employeeRole: EMPLOYEE_ROLES.SUPERADMIN };
  }
  /** Self-signup client portal requests (not SaaS purchasers) start as customer. */
  if (userLike?.self_signup === true || userLike?.selfSignup === true) {
    return { accountType: ACCOUNT_TYPES.CUSTOMER, employeeRole: null };
  }
  const accountType = normalizeAccountType(userLike?.accountType || userLike?.account_type);
  const explicitRoleAfterType = normalizeEmployeeRole(userLike?.employeeRole || userLike?.employee_role);
  if (accountType === ACCOUNT_TYPES.CUSTOMER) {
    return { accountType: ACCOUNT_TYPES.CUSTOMER, employeeRole: null };
  }
  if (accountType === ACCOUNT_TYPES.EMPLOYEE && explicitRoleAfterType) {
    return { accountType, employeeRole: explicitRoleAfterType };
  }
  const inferred = inferModelFromLegacy(userLike);
  if (inferred.accountType === ACCOUNT_TYPES.CUSTOMER) {
    return { accountType: ACCOUNT_TYPES.CUSTOMER, employeeRole: null };
  }
  return {
    accountType: ACCOUNT_TYPES.EMPLOYEE,
    employeeRole: inferred.employeeRole || EMPLOYEE_ROLES.CAMERA_OPERATOR
  };
}

function legacyRolesForAccountModel(model, legacyRolesInput = null) {
  const legacy = normalizeLegacyRoles(legacyRolesInput || {});
  const out = {
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
  };

  if (model.accountType === ACCOUNT_TYPES.CUSTOMER) {
    // SaaS purchasers / portal clients may carry explicit portal* flags in roles JSON.
    // Do not wipe those — otherwise PipeShare delete/upload/edit always 403.
    return {
      ...out,
      portalUpload: legacy.portalUpload === true,
      portalDownload: legacy.portalDownload === true,
      portalEdit: legacy.portalEdit === true,
      portalDelete: legacy.portalDelete === true
    };
  }
  const role = normalizeEmployeeRole(model.employeeRole);
  if (role === EMPLOYEE_ROLES.SUPERADMIN || role === EMPLOYEE_ROLES.ADMIN) {
    for (const key of Object.keys(out)) out[key] = true;
    // Keep any explicit legacy portal flags (already all true for admin).
    return { ...out, ...legacy, portalUpload: true, portalDownload: true, portalEdit: true, portalDelete: true };
  }
  if (role === EMPLOYEE_ROLES.CAMERA_OPERATOR) {
    out.camera = true;
    out.psrPlanner = true;
    out.psrViewer = true;
    out.psrDataEntry = true;
    out.portalUpload = true;
    out.portalDownload = true;
    out.portalEdit = true;
    out.portalDelete = true;
    return { ...out, ...legacy };
  }
  if (role === EMPLOYEE_ROLES.VAC_OPERATOR || role === EMPLOYEE_ROLES.SIMPLE_VAC) {
    out.vac = true;
    out.psrViewer = true;
    out.psrDataEntry = true;
    if (role === EMPLOYEE_ROLES.SIMPLE_VAC) out.simpleVac = true;
    return { ...out, ...legacy };
  }
  return { ...out, ...legacy };
}

/** Global Horizon super-admin (platform operator — not a SaaS workspace purchaser). */
function isSuperAdmin(user) {
  if (isSaasWorkspaceOwner(user)) return false;
  const model = deriveAccountModel(user);
  return model.accountType === ACCOUNT_TYPES.EMPLOYEE && model.employeeRole === EMPLOYEE_ROLES.SUPERADMIN;
}

/** Horizon admin (includes superadmin). Excludes SaaS workspace owners. */
function isAdminUser(user) {
  if (isSaasWorkspaceOwner(user)) return false;
  const model = deriveAccountModel(user);
  if (model.accountType !== ACCOUNT_TYPES.EMPLOYEE) return false;
  return model.employeeRole === EMPLOYEE_ROLES.ADMIN || model.employeeRole === EMPLOYEE_ROLES.SUPERADMIN;
}

/** User Manager / Admin Panel access. */
function canAccessAdminPanel(user) {
  return isAdminUser(user);
}

/** PipeShare ACL / path grants / share extras. */
function canManagePortalExtras(user) {
  if (isSaasWorkspaceOwner(user)) return true;
  return isAdminUser(user);
}

function canViewInspectionDiagnostics(user) {
  if (!user) return false;
  const { deploymentMode: modeFromProfile } = require('./lib/deployment-profile');
  if (modeFromProfile() === 'non-saas') {
    return looksLikeMike(user);
  }
  const model = deriveAccountModel(user);
  if (model.accountType === ACCOUNT_TYPES.CUSTOMER) return false;
  return model.accountType === ACCOUNT_TYPES.EMPLOYEE;
}

/**
 * @param {object|null} user - normalized user (camelCase) from `normalizeUser` + scopes
 * @returns {object} Stable shape for `/session` and clients
 */
function resolveCapabilities(user) {
  const model = deriveAccountModel(user || {});
  const roles = legacyRolesForAccountModel(model, user?.roles);
  const saasOwner = isSaasWorkspaceOwner(user);
  const tenantPurchaser = looksLikeMike(user) ? false : user?.tenantPurchaser === true;
  const platformCpanelSuperAdmin = looksLikeMike(user) && canAccessAdminPanel(user);
  const hostingTier = resolveHostingTier(user);
  return {
    version: 2,
    hostingTier,
    superAdmin: isSuperAdmin(user),
    platformCpanelSuperAdmin,
    saasTenantOwner: saasOwner,
    tenantAdmin: saasOwner,
    tenantPurchaser,
    subscriptionStatus: user?.subscriptionStatus || null,
    canAccessAdminPanel: canAccessAdminPanel(user),
    canManagePortalExtras: canManagePortalExtras(user),
    canViewInspectionDiagnostics: canViewInspectionDiagnostics(user),
    accountType: model.accountType,
    employeeRole: model.employeeRole,
    psrPlanner: !!roles.psrPlanner,
    psrViewer: !!roles.psrViewer,
    psrDataEntry: !!roles.psrDataEntry,
    camera: !!roles.camera,
    vac: !!roles.vac,
    simpleVac: !!roles.simpleVac,
    pricingView: !!roles.pricingView,
    footageView: !!roles.footageView,
    jobsiteContactsView: !!roles.jobsiteContactsView,
    dataAutoSyncEmployee: !!roles.dataAutoSyncEmployee,
    email: !!roles.email,
    portalUpload: !!roles.portalUpload,
    portalDownload: !!roles.portalDownload,
    portalEdit: !!roles.portalEdit,
    portalDelete: !!roles.portalDelete
  };
}

function deploymentMode() {
  const { deploymentMode: modeFromProfile } = require('./lib/deployment-profile');
  return modeFromProfile();
}

module.exports = {
  ACCOUNT_TYPES,
  EMPLOYEE_ROLES,
  HOSTING_TIERS,
  normalizeAccountType,
  normalizeEmployeeRole,
  deriveAccountModel,
  legacyRolesForAccountModel,
  resolveCapabilities,
  resolveHostingTier,
  isBasePlatformUser,
  isSuperAdmin,
  canAccessAdminPanel,
  canManagePortalExtras,
  canViewInspectionDiagnostics,
  isAdminUser,
  isSaasWorkspaceOwner,
  looksLikeMike,
  deploymentMode
};
