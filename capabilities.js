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
  if (userLike?.saasTenantOwner === true || userLike?.isSaasTenantOwner === true) {
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

  if (model.accountType === ACCOUNT_TYPES.CUSTOMER) return out;
  const role = normalizeEmployeeRole(model.employeeRole);
  if (role === EMPLOYEE_ROLES.SUPERADMIN || role === EMPLOYEE_ROLES.ADMIN) {
    for (const key of Object.keys(out)) out[key] = true;
    return out;
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

/** Global Horizon super-admin. */
function isSuperAdmin(user) {
  const model = deriveAccountModel(user);
  return model.accountType === ACCOUNT_TYPES.EMPLOYEE && model.employeeRole === EMPLOYEE_ROLES.SUPERADMIN;
}

/** Horizon admin (includes superadmin). */
function isAdminUser(user) {
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
  return isAdminUser(user);
}

/**
 * @param {object|null} user - normalized user (camelCase) from `normalizeUser` + scopes
 * @returns {object} Stable shape for `/session` and clients
 */
function resolveCapabilities(user) {
  const model = deriveAccountModel(user || {});
  const roles = legacyRolesForAccountModel(model, user?.roles);
  return {
    version: 2,
    superAdmin: isSuperAdmin(user),
    canAccessAdminPanel: canAccessAdminPanel(user),
    canManagePortalExtras: canManagePortalExtras(user),
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
  const mode = String(process.env.HP_DEPLOYMENT_MODE || 'non-saas')
    .trim()
    .toLowerCase();
  return mode === 'saas' ? 'saas' : 'non-saas';
}

module.exports = {
  ACCOUNT_TYPES,
  EMPLOYEE_ROLES,
  normalizeAccountType,
  normalizeEmployeeRole,
  deriveAccountModel,
  legacyRolesForAccountModel,
  resolveCapabilities,
  isSuperAdmin,
  canAccessAdminPanel,
  canManagePortalExtras,
  isAdminUser,
  looksLikeMike,
  deploymentMode
};
