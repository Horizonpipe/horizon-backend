'use strict';

/**
 * Who may edit an account, set a new password, or delete an account.
 * Owner, Superintendent, and Super admin always can.
 * A manager can only after a Super admin or the company Owner grants clearance.
 * The clearance flag is stored on the user. A manager without it cannot.
 */

function text(value) {
  return String(value || '').trim().toLowerCase();
}

function titleOf(user) {
  return text(user?.title);
}

function roleOf(user) {
  return text(user?.employeeRole || user?.employee_role);
}

function isCompanyOwner(user) {
  if (!user) return false;
  if (user.saasTenantOwner === true || user.isSaasTenantOwner === true) return true;
  return titleOf(user) === 'owner';
}

function isSuperintendent(user) {
  if (!user) return false;
  return titleOf(user) === 'superintendent' || roleOf(user) === 'superintendent';
}

function isSuperAdminActor(user) {
  if (!user) return false;
  if (user.isSuperAdmin === true) return true;
  return roleOf(user) === 'superadmin';
}

function isManagerAccount(user) {
  if (!user) return false;
  const role = roleOf(user);
  const title = titleOf(user);
  return role === 'admin' || role === 'manager' || title === 'manager';
}

function hasAccountClearance(user) {
  return user?.accountAdminClearance === true || user?.account_admin_clearance === true;
}

function canManageUserAccounts(user) {
  if (!user) return false;
  if (isSuperAdminActor(user) || isCompanyOwner(user) || isSuperintendent(user)) return true;
  return isManagerAccount(user) && hasAccountClearance(user);
}

function canGrantAccountClearance(user) {
  return isSuperAdminActor(user) || isCompanyOwner(user);
}

module.exports = {
  isCompanyOwner,
  isSuperintendent,
  isSuperAdminActor,
  isManagerAccount,
  hasAccountClearance,
  canManageUserAccounts,
  canGrantAccountClearance
};
