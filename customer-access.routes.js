'use strict';

const {
  normalizeClearance,
  normalizeCompanyRole,
  roleLabel,
  findCompanyByName,
  readClearance,
  writeClearance
} = require('./lib/customer-access');

function clean(value) {
  return String(value == null ? '' : value).trim();
}

function registerCustomerAccessRoutes(app, { pool, requireAuth, requireAdminPanelOrTenantUserManagement }) {
  function jsonError(res, status, message) {
    return res.status(status).json({ success: false, error: message });
  }

  app.get('/companies/match', async (req, res) => {
    try {
      const name = clean(req.query?.name || req.query?.company);
      if (!name) return jsonError(res, 400, 'Company name is required');
      const company = await findCompanyByName(pool, name);
      if (!company) {
        return res.json({
          success: true,
          matched: false,
          message: 'No company matches that name. An admin will assign your company.'
        });
      }
      return res.json({ success: true, matched: true, companyName: company.name });
    } catch (error) {
      console.error('[companies] match error:', error);
      return jsonError(res, 500, error.message);
    }
  });

  app.get('/users/:id/access', requireAuth, requireAdminPanelOrTenantUserManagement, async (req, res) => {
    try {
      const row = await readClearance(pool, req.params.id);
      if (!row) return jsonError(res, 404, 'User not found');
      const customer = String(row.accountType || '').toLowerCase() === 'customer';
      return res.json({
        success: true,
        accountType: row.accountType,
        customer,
        clearance: row.clearance,
        labels: customer
          ? {
              full: 'Full Access (Viewing and Downloading only)',
              view: 'Full access viewing only'
            }
          : { full: 'Full Access' }
      });
    } catch (error) {
      console.error('[customer-access] get error:', error);
      return jsonError(res, 500, error.message);
    }
  });

  app.put('/users/:id/access', requireAuth, requireAdminPanelOrTenantUserManagement, async (req, res) => {
    try {
      const current = await pool.query(
        `SELECT account_type FROM users WHERE CAST(id AS text) = $1 LIMIT 1`,
        [clean(req.params.id)]
      );
      if (!current.rows.length) return jsonError(res, 404, 'User not found');
      const accountType = current.rows[0].account_type || 'employee';
      const clearance = await writeClearance(pool, req.params.id, accountType, req.body?.clearance || req.body || {});
      return res.json({
        success: true,
        clearance: normalizeClearance(clearance, accountType),
        roleLabel: roleLabel(normalizeCompanyRole(req.body?.companyRoleKey, accountType))
      });
    } catch (error) {
      if (error && error.code === '42703') {
        return jsonError(res, 503, 'Access storage is not on this server yet.');
      }
      console.error('[customer-access] put error:', error);
      return jsonError(res, 500, error.message);
    }
  });
}

module.exports = { registerCustomerAccessRoutes };
