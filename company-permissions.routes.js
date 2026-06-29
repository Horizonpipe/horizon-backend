'use strict';

const crypto = require('crypto');
const {
  COMPANY_ROLE_KEYS,
  DEFAULT_APP_FEATURES,
  normalizeAppFeatures,
  normalizeRelPath,
  loadUserCompanyMembership
} = require('./company-permissions.service');

function cleanString(v) {
  return String(v ?? '').trim();
}

function normalizeRoleKey(raw) {
  const key = cleanString(raw).toLowerCase();
  return COMPANY_ROLE_KEYS.includes(key) ? key : '';
}

function registerCompanyPermissionsRoutes(app, { pool, requireAuth, requireAdminPanelAccess, requireAdminPanelOrTenantUserManagement }) {
  const requireCompanyAdmin = requireAdminPanelOrTenantUserManagement || requireAdminPanelAccess;
  function jsonError(res, status, message) {
    return res.status(status).json({ success: false, error: message });
  }

  async function loadCompanyRow(id) {
    const r = await pool.query(
      `SELECT id, name, slug, app_features, customer_enabled, created_at, updated_at
       FROM companies WHERE id = $1 LIMIT 1`,
      [String(id)]
    );
    return r.rows[0] || null;
  }

  function serializeCompany(row) {
    if (!row) return null;
    return {
      id: row.id,
      name: row.name,
      slug: row.slug || '',
      appFeatures: normalizeAppFeatures(row.app_features),
      customerEnabled: row.customer_enabled === true,
      createdAt: row.created_at,
      updatedAt: row.updated_at
    };
  }

  async function ensureDefaultRoles(companyId) {
    for (const roleKey of COMPANY_ROLE_KEYS) {
      await pool.query(
        `INSERT INTO company_roles (company_id, role_key, enabled)
         VALUES ($1, $2, $3)
         ON CONFLICT (company_id, role_key) DO NOTHING`,
        [String(companyId), roleKey, roleKey !== 'customer']
      );
    }
  }

  app.get('/companies', requireAuth, requireCompanyAdmin, async (req, res) => {
    try {
      const tenantScope = req.tenantScope || { mode: 'platform' };
      const params = [];
      let whereSql = '';
      if (tenantScope.mode === 'tenant') {
        whereSql = ' WHERE c.id = $1::uuid';
        params.push(tenantScope.companyId);
      }
      const r = await pool.query(
        `SELECT c.id, c.name, c.slug, c.app_features, c.customer_enabled, c.created_at, c.updated_at,
                (SELECT COUNT(*)::int FROM user_company_membership m WHERE m.company_id = c.id) AS member_count
         FROM companies c${whereSql}
         ORDER BY lower(c.name) ASC`,
        params
      );
      return res.json({
        success: true,
        companies: r.rows.map((row) => ({
          ...serializeCompany(row),
          memberCount: Number(row.member_count || 0)
        }))
      });
    } catch (error) {
      console.error('[companies] list error:', error);
      return jsonError(res, 500, error.message);
    }
  });

  app.post('/companies', requireAuth, requireAdminPanelAccess, async (req, res) => {
    try {
      const name = cleanString(req.body?.name);
      if (!name) return jsonError(res, 400, 'Company name is required');
      const slug = cleanString(req.body?.slug) || name.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '');
      const appFeatures = normalizeAppFeatures(req.body?.appFeatures);
      const customerEnabled = !!req.body?.customerEnabled;
      const r = await pool.query(
        `INSERT INTO companies (name, slug, app_features, customer_enabled)
         VALUES ($1, $2, $3::jsonb, $4)
         RETURNING id, name, slug, app_features, customer_enabled, created_at, updated_at`,
        [name, slug, JSON.stringify(appFeatures), customerEnabled]
      );
      const company = r.rows[0];
      await ensureDefaultRoles(company.id);
      return res.status(201).json({ success: true, company: serializeCompany(company) });
    } catch (error) {
      if (error.code === '23505') return jsonError(res, 409, 'Company name or slug already exists');
      console.error('[companies] create error:', error);
      return jsonError(res, 500, error.message);
    }
  });

  app.get('/companies/:id', requireAuth, requireAdminPanelAccess, async (req, res) => {
    try {
      const company = await loadCompanyRow(req.params.id);
      if (!company) return jsonError(res, 404, 'Company not found');
      const rolesRes = await pool.query(
        `SELECT role_key, enabled FROM company_roles WHERE company_id = $1 ORDER BY role_key ASC`,
        [String(req.params.id)]
      );
      const membersRes = await pool.query(
        `SELECT m.id, m.user_id, m.role_key, m.override_folder_grants, m.created_at, m.updated_at,
                u.username, u.display_name, u.email
         FROM user_company_membership m
         JOIN users u ON u.id = m.user_id
         WHERE m.company_id = $1
         ORDER BY lower(u.display_name), lower(u.username)`,
        [String(req.params.id)]
      );
      return res.json({
        success: true,
        company: serializeCompany(company),
        roles: rolesRes.rows.map((row) => ({ roleKey: row.role_key, enabled: row.enabled === true })),
        members: membersRes.rows.map((row) => ({
          id: row.id,
          userId: row.user_id,
          roleKey: row.role_key,
          username: row.username,
          displayName: row.display_name || row.username,
          email: row.email || '',
          overrideFolderGrants: Array.isArray(row.override_folder_grants) ? row.override_folder_grants : [],
          createdAt: row.created_at,
          updatedAt: row.updated_at
        }))
      });
    } catch (error) {
      console.error('[companies] get error:', error);
      return jsonError(res, 500, error.message);
    }
  });

  app.put('/companies/:id', requireAuth, requireAdminPanelAccess, async (req, res) => {
    try {
      const company = await loadCompanyRow(req.params.id);
      if (!company) return jsonError(res, 404, 'Company not found');
      const name = req.body?.name !== undefined ? cleanString(req.body.name) : company.name;
      const slug =
        req.body?.slug !== undefined
          ? cleanString(req.body.slug)
          : company.slug || '';
      const appFeatures =
        req.body?.appFeatures !== undefined ? normalizeAppFeatures(req.body.appFeatures) : normalizeAppFeatures(company.app_features);
      const customerEnabled =
        req.body?.customerEnabled !== undefined ? !!req.body.customerEnabled : company.customer_enabled === true;
      const r = await pool.query(
        `UPDATE companies
         SET name = $1, slug = $2, app_features = $3::jsonb, customer_enabled = $4, updated_at = NOW()
         WHERE id = $5
         RETURNING id, name, slug, app_features, customer_enabled, created_at, updated_at`,
        [name, slug, JSON.stringify(appFeatures), customerEnabled, String(req.params.id)]
      );
      return res.json({ success: true, company: serializeCompany(r.rows[0]) });
    } catch (error) {
      if (error.code === '23505') return jsonError(res, 409, 'Company name or slug already exists');
      console.error('[companies] update error:', error);
      return jsonError(res, 500, error.message);
    }
  });

  app.delete('/companies/:id', requireAuth, requireAdminPanelAccess, async (req, res) => {
    try {
      const r = await pool.query(`DELETE FROM companies WHERE id = $1 RETURNING id`, [String(req.params.id)]);
      if (!r.rowCount) return jsonError(res, 404, 'Company not found');
      return res.json({ success: true });
    } catch (error) {
      console.error('[companies] delete error:', error);
      return jsonError(res, 500, error.message);
    }
  });

  app.put('/companies/:id/roles', requireAuth, requireAdminPanelAccess, async (req, res) => {
    try {
      const company = await loadCompanyRow(req.params.id);
      if (!company) return jsonError(res, 404, 'Company not found');
      const roles = Array.isArray(req.body?.roles) ? req.body.roles : [];
      for (const item of roles) {
        const roleKey = normalizeRoleKey(item?.roleKey || item?.role_key);
        if (!roleKey) continue;
        await pool.query(
          `INSERT INTO company_roles (company_id, role_key, enabled)
           VALUES ($1, $2, $3)
           ON CONFLICT (company_id, role_key)
           DO UPDATE SET enabled = EXCLUDED.enabled, updated_at = NOW()`,
          [String(req.params.id), roleKey, !!item.enabled]
        );
      }
      const rolesRes = await pool.query(
        `SELECT role_key, enabled FROM company_roles WHERE company_id = $1 ORDER BY role_key ASC`,
        [String(req.params.id)]
      );
      return res.json({
        success: true,
        roles: rolesRes.rows.map((row) => ({ roleKey: row.role_key, enabled: row.enabled === true }))
      });
    } catch (error) {
      console.error('[companies] roles error:', error);
      return jsonError(res, 500, error.message);
    }
  });

  function serializeFolderGrantRow(row) {
    return {
      id: row.id,
      roleKey: row.role_key,
      clientId: row.client_id,
      jobId: row.job_id,
      pathPrefix: row.path_prefix || '',
      enabled: row.enabled === true,
      canView: row.can_view === true,
      canEdit: row.can_edit === true,
      canDelete: row.can_delete === true,
      canUpload: row.can_upload === true,
      canDownload: row.can_download === true
    };
  }

  app.get('/companies/:id/folder-grants', requireAuth, requireAdminPanelAccess, async (req, res) => {
    try {
      const roleKey = normalizeRoleKey(req.query?.roleKey || req.query?.role);
      const clientId = cleanString(req.query?.clientId);
      const jobId = cleanString(req.query?.jobId);
      if (!roleKey) return jsonError(res, 400, 'roleKey query param is required');
      const params = [String(req.params.id), roleKey];
      let sql = `SELECT id, company_id, role_key, client_id, job_id, path_prefix, enabled,
                        can_view, can_edit, can_delete, can_upload, can_download, created_at, updated_at
                 FROM company_folder_grants
                 WHERE company_id = $1 AND role_key = $2`;
      if (clientId && jobId) {
        params.push(clientId, jobId);
        sql += ` AND client_id = $3 AND job_id = $4`;
      }
      sql += ` ORDER BY client_id ASC, job_id ASC, path_prefix ASC`;
      const r = await pool.query(sql, params);
      return res.json({
        success: true,
        grants: r.rows.map(serializeFolderGrantRow)
      });
    } catch (error) {
      console.error('[companies] folder-grants get error:', error);
      return jsonError(res, 500, error.message);
    }
  });

  app.put('/companies/:id/folder-grants', requireAuth, requireAdminPanelAccess, async (req, res) => {
    try {
      const company = await loadCompanyRow(req.params.id);
      if (!company) return jsonError(res, 404, 'Company not found');
      const roleKey = normalizeRoleKey(req.body?.roleKey || req.body?.role);
      const scopeClientId = cleanString(req.body?.clientId);
      const scopeJobId = cleanString(req.body?.jobId);
      const grants = Array.isArray(req.body?.grants) ? req.body.grants : [];
      if (!roleKey) return jsonError(res, 400, 'roleKey is required');
      const batchMode = !(scopeClientId && scopeJobId);
      if (batchMode && !grants.length) {
        await pool.query(
          `DELETE FROM company_folder_grants WHERE company_id = $1 AND role_key = $2`,
          [String(req.params.id), roleKey]
        );
      } else if (batchMode) {
        await pool.query(
          `DELETE FROM company_folder_grants WHERE company_id = $1 AND role_key = $2`,
          [String(req.params.id), roleKey]
        );
      } else {
        await pool.query(
          `DELETE FROM company_folder_grants
           WHERE company_id = $1 AND role_key = $2 AND client_id = $3 AND job_id = $4`,
          [String(req.params.id), roleKey, scopeClientId, scopeJobId]
        );
      }

      const seen = new Set();
      for (const grant of grants) {
        const clientId = cleanString(grant?.clientId ?? grant?.client_id) || scopeClientId;
        const jobId = cleanString(grant?.jobId ?? grant?.job_id) || scopeJobId;
        if (!clientId || !jobId) {
          return jsonError(res, 400, 'Each grant requires clientId and jobId (or provide scope clientId/jobId on the body).');
        }
        const pathPrefix = normalizeRelPath(grant?.pathPrefix ?? grant?.path ?? '');
        const dedupeKey = `${clientId}\0${jobId}\0${pathPrefix}`;
        if (seen.has(dedupeKey)) continue;
        seen.add(dedupeKey);
        await pool.query(
          `INSERT INTO company_folder_grants
            (company_id, role_key, client_id, job_id, path_prefix, enabled, can_view, can_edit, can_delete, can_upload, can_download)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
          [
            String(req.params.id),
            roleKey,
            clientId,
            jobId,
            pathPrefix,
            grant?.enabled !== false,
            grant?.canView !== false,
            !!grant?.canEdit,
            !!grant?.canDelete,
            !!grant?.canUpload,
            !!grant?.canDownload
          ]
        );
      }

      const params = [String(req.params.id), roleKey];
      let selectSql = `SELECT id, company_id, role_key, client_id, job_id, path_prefix, enabled,
                              can_view, can_edit, can_delete, can_upload, can_download, created_at, updated_at
                       FROM company_folder_grants
                       WHERE company_id = $1 AND role_key = $2`;
      if (!batchMode) {
        params.push(scopeClientId, scopeJobId);
        selectSql += ` AND client_id = $3 AND job_id = $4`;
      }
      selectSql += ` ORDER BY client_id ASC, job_id ASC, path_prefix ASC`;
      const r = await pool.query(selectSql, params);
      return res.json({
        success: true,
        grants: r.rows.map(serializeFolderGrantRow)
      });
    } catch (error) {
      console.error('[companies] folder-grants put error:', error);
      return jsonError(res, 500, error.message);
    }
  });

  app.put('/users/:id/company-membership', requireAuth, requireAdminPanelAccess, async (req, res) => {
    try {
      const userId = cleanString(req.params.id);
      const companyId = cleanString(req.body?.companyId);
      const roleKey = normalizeRoleKey(req.body?.roleKey || 'employee');
      if (!userId) return jsonError(res, 400, 'User id is required');

      if (!companyId) {
        await pool.query(`DELETE FROM user_company_membership WHERE user_id = $1`, [userId]);
        return res.json({ success: true, membership: null });
      }

      const company = await loadCompanyRow(companyId);
      if (!company) return jsonError(res, 404, 'Company not found');

      const r = await pool.query(
        `INSERT INTO user_company_membership (user_id, company_id, role_key, override_folder_grants)
         VALUES ($1, $2, $3, '[]'::jsonb)
         ON CONFLICT (user_id)
         DO UPDATE SET company_id = EXCLUDED.company_id, role_key = EXCLUDED.role_key, updated_at = NOW()
         RETURNING id, user_id, company_id, role_key, override_folder_grants, created_at, updated_at`,
        [userId, companyId, roleKey]
      );
      const row = r.rows[0];
      return res.json({
        success: true,
        membership: {
          id: row.id,
          userId: row.user_id,
          companyId: row.company_id,
          roleKey: row.role_key,
          companyName: company.name,
          overrideFolderGrants: Array.isArray(row.override_folder_grants) ? row.override_folder_grants : []
        }
      });
    } catch (error) {
      console.error('[companies] membership error:', error);
      return jsonError(res, 500, error.message);
    }
  });

  app.get('/admin/trash-bin', requireAuth, requireAdminPanelAccess, async (req, res) => {
    try {
      const companyId = cleanString(req.query?.companyId);
      const params = [];
      let where = 'restored_at IS NULL AND expires_at > NOW()';
      if (companyId) {
        params.push(companyId);
        where += ` AND company_id = $${params.length}`;
      }
      const r = await pool.query(
        `SELECT id, company_id, client_id, job_id, item_type, item_id, rel_path, original_parent_path,
                skeleton_path, metadata, deleted_by_user_id, deleted_at, expires_at
         FROM trash_bin_entries
         WHERE ${where}
         ORDER BY deleted_at DESC
         LIMIT 500`,
        params
      );
      return res.json({ success: true, entries: r.rows });
    } catch (error) {
      console.error('[trash-bin] list error:', error);
      return jsonError(res, 500, error.message);
    }
  });

  app.post('/admin/trash-bin/:id/restore', requireAuth, requireAdminPanelAccess, async (req, res) => {
    try {
      const r = await pool.query(
        `UPDATE trash_bin_entries
         SET restored_at = NOW()
         WHERE id = $1 AND restored_at IS NULL
         RETURNING id, client_id, job_id, item_type, rel_path, skeleton_path, metadata`,
        [String(req.params.id)]
      );
      if (!r.rowCount) return jsonError(res, 404, 'Trash entry not found or already restored');
      return res.json({
        success: true,
        entry: r.rows[0],
        message: 'Restore recorded. Phase 2 will rehydrate Wasabi objects from trash metadata.'
      });
    } catch (error) {
      console.error('[trash-bin] restore error:', error);
      return jsonError(res, 500, error.message);
    }
  });

  app.post('/companies/:id/plan-share-links', requireAuth, requireAdminPanelAccess, async (req, res) => {
    try {
      const company = await loadCompanyRow(req.params.id);
      if (!company) return jsonError(res, 404, 'Company not found');
      const token = crypto.randomBytes(24).toString('base64url');
      const payload = {
        folderPaths: Array.isArray(req.body?.folderPaths) ? req.body.folderPaths : [],
        label: cleanString(req.body?.label),
        planView: true
      };
      const expiresDays = Number(req.body?.expiresDays || 30);
      const expiresAt = new Date(Date.now() + Math.max(1, expiresDays) * 24 * 60 * 60 * 1000);
      const r = await pool.query(
        `INSERT INTO company_plan_share_links (company_id, token, created_by_user_id, payload, expires_at)
         VALUES ($1, $2, $3, $4::jsonb, $5)
         RETURNING id, company_id, token, payload, expires_at, created_at`,
        [String(req.params.id), token, String(req.user?.id || ''), JSON.stringify(payload), expiresAt]
      );
      return res.status(201).json({
        success: true,
        link: {
          id: r.rows[0].id,
          token: r.rows[0].token,
          urlPath: `/share/plan/${r.rows[0].token}`,
          payload: r.rows[0].payload,
          expiresAt: r.rows[0].expires_at
        }
      });
    } catch (error) {
      console.error('[plan-share-links] create error:', error);
      return jsonError(res, 500, error.message);
    }
  });

  app.get('/share/plan/:token', async (req, res) => {
    try {
      const r = await pool.query(
        `SELECT l.id, l.company_id, l.token, l.payload, l.expires_at, c.name AS company_name
         FROM company_plan_share_links l
         JOIN companies c ON c.id = l.company_id
         WHERE l.token = $1 AND l.expires_at > NOW()
         LIMIT 1`,
        [String(req.params.token)]
      );
      if (!r.rows.length) return jsonError(res, 404, 'Share link not found or expired');
      const row = r.rows[0];
      return res.json({
        success: true,
        companyName: row.company_name,
        payload: row.payload,
        expiresAt: row.expires_at
      });
    } catch (error) {
      console.error('[plan-share-links] public get error:', error);
      return jsonError(res, 500, error.message);
    }
  });

  console.log('[company-permissions] /companies, /admin/trash-bin, /share/plan routes mounted');
}

module.exports = { registerCompanyPermissionsRoutes };
