'use strict';

const { loadUserCompanyMembership } = require('../company-permissions.service');

function cleanString(v) {
  return String(v ?? '').trim();
}

function subscriptionIsActive(status) {
  if (process.env.SAAS_SKIP_SUBSCRIPTION_CHECK === '1') return true;
  const s = cleanString(status).toLowerCase();
  return s === 'active' || s === 'trialing';
}

/**
 * Gate Customer Login on pipeshare.net — tenant must exist with active subscription.
 * @param {{ query: Function }} pool
 * @param {string|number} userId
 * @returns {Promise<{ allowed: boolean, code?: string, message?: string }>}
 */
async function evaluateSaasCustomerLoginAccess(pool, userId) {
  const uid = cleanString(userId);
  if (!uid || !pool || typeof pool.query !== 'function') {
    return { allowed: false, code: 'NO_WORKSPACE', message: 'Unable to verify workspace access.' };
  }

  const membership = await loadUserCompanyMembership(pool, uid);
  if (!membership?.companyId) {
    return {
      allowed: false,
      code: 'NO_WORKSPACE',
      message: 'No PipeShare workspace is linked to this account. Ask your company admin for access, or use Business login to manage a subscription.'
    };
  }

  const r = await pool.query(
    `SELECT subscription_status, setup_status
     FROM saas_tenant_instances
     WHERE company_id = $1
     LIMIT 1`,
    [String(membership.companyId)]
  );
  const row = r.rows[0];
  if (!row) {
    return {
      allowed: false,
      code: 'NO_WORKSPACE',
      message: 'This account is not part of a PipeShare SaaS workspace. Use Business login if you manage a subscription.'
    };
  }

  if (!subscriptionIsActive(row.subscription_status)) {
    return {
      allowed: false,
      code: 'INVALID_LICENSE',
      message: 'Invalid license. Please purchase.'
    };
  }

  return { allowed: true };
}

module.exports = {
  evaluateSaasCustomerLoginAccess,
  subscriptionIsActive
};
