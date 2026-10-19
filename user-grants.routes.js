'use strict';

const { normalizeRelPath } = require('./company-permissions.service');
const {
  serializeUserFolderGrantRow,
  loadUserFolderGrantsForScope,
  saveUserFolderGrantsForScope,
  syncPsrScopeForUserGrant,
  listFolderGrantsForUser,
  addFolderGrantForUser,
  removeFolderGrantForUser
} = require('./user-grants.service');

function cleanString(v) {
  return String(v ?? '').trim();
}

function normalizeAppKey(raw) {
  const key = cleanString(raw).toLowerCase();
  return key === 'pipesync' ? 'pipesync' : 'pipeshare';
}

function normalizePsrScopeLevel(raw) {
  const key = cleanString(raw).toLowerCase();
  const allowed = ['client', 'city', 'jobsite', 'storm', 'sanitary'];
  return allowed.includes(key) ? key : '';
}

function parseScopeFromQuery(query) {
  return {
    app: normalizeAppKey(query?.app),
    clientId: cleanString(query?.clientId ?? query?.client_id),
    jobId: cleanString(query?.jobId ?? query?.job_id),
    pathPrefix: normalizeRelPath(query?.pathPrefix ?? query?.path ?? ''),
    psrScopeLevel: normalizePsrScopeLevel(query?.psrScopeLevel ?? query?.psr_scope_level),
    psrCity: cleanString(query?.psrCity ?? query?.psr_city)
  };
}

function parseScopeFromBody(body) {
  return {
    app: normalizeAppKey(body?.app),
    clientId: cleanString(body?.clientId ?? body?.client_id),
    jobId: cleanString(body?.jobId ?? body?.job_id),
    pathPrefix: normalizeRelPath(body?.pathPrefix ?? body?.path ?? ''),
    psrScopeLevel: normalizePsrScopeLevel(body?.psrScopeLevel ?? body?.psr_scope_level),
    psrCity: cleanString(body?.psrCity ?? body?.psr_city),
    recursive: body?.recursive !== false
  };
}

function registerUserGrantsRoutes(app, { pool, requireAuth, requireAdminPanelAccess, requireAdminPanelOrTenantUserManagement, assertUserIdInTenantScope }) {
  function jsonError(res, status, message) {
    return res.status(status).json({ success: false, error: message });
  }

  app.get('/user-folder-grants', requireAuth, requireAdminPanelAccess, async (req, res) => {
    try {
      const scope = parseScopeFromQuery(req.query || {});
      if (!scope.clientId) return jsonError(res, 400, 'clientId is required');
      if (scope.app === 'pipeshare' && !scope.jobId) {
        return jsonError(res, 400, 'jobId is required for PipeShare grants');
      }
      const grants = await loadUserFolderGrantsForScope(pool, scope);
      return res.json({ success: true, scope, grants });
    } catch (error) {
      console.error('[user-folder-grants] get error:', error);
      return jsonError(res, 500, error.message);
    }
  });

  app.put('/user-folder-grants', requireAuth, requireAdminPanelAccess, async (req, res) => {
    try {
      const scope = parseScopeFromBody(req.body || {});
      const grants = Array.isArray(req.body?.grants) ? req.body.grants : [];
      if (!scope.clientId) return jsonError(res, 400, 'clientId is required');
      if (scope.app === 'pipeshare' && !scope.jobId) {
        return jsonError(res, 400, 'jobId is required for PipeShare grants');
      }
      if (scope.app === 'pipesync' && !scope.psrScopeLevel) {
        return jsonError(res, 400, 'psrScopeLevel is required for PipeSync grants');
      }
      const saved = await saveUserFolderGrantsForScope(pool, scope, grants);
      for (const row of saved) {
        if (row.enabled !== false && row.canView !== false) {
          await syncPsrScopeForUserGrant(pool, scope, row);
        }
      }
      return res.json({ success: true, scope, grants: saved.map(serializeUserFolderGrantRow) });
    } catch (error) {
      console.error('[user-folder-grants] put error:', error);
      return jsonError(res, 500, error.message);
    }
  });

  const requireUserAdmin = requireAdminPanelOrTenantUserManagement || requireAdminPanelAccess;

  function grantScopeAllowed(req, clientId, jobId) {
    const scope = req.tenantScope;
    if (!scope || scope.mode !== 'tenant') return true;
    if (String(clientId) !== String(scope.portalClientId || '')) return false;
    const tenantJob = String(scope.portalJobId || '').trim();
    if (tenantJob && String(jobId) !== tenantJob) return false;
    return true;
  }

  app.get('/users/:id/folder-grants', requireAuth, requireUserAdmin, async (req, res) => {
    try {
      const userId = cleanString(req.params.id);
      const clientId = cleanString(req.query?.clientId ?? req.query?.client_id);
      const jobId = cleanString(req.query?.jobId ?? req.query?.job_id);
      if (!userId) return jsonError(res, 400, 'User id is required');
      if (!clientId || !jobId) return jsonError(res, 400, 'Choose a client workspace before sharing folders.');
      if (!grantScopeAllowed(req, clientId, jobId)) {
        return jsonError(res, 403, 'That folder is outside your workspace.');
      }
      if (typeof assertUserIdInTenantScope === 'function') {
        const allowed = await assertUserIdInTenantScope(pool, userId, req.tenantScope);
        if (!allowed) return jsonError(res, 403, 'That user is outside your workspace.');
      }
      const grants = await listFolderGrantsForUser(pool, userId, clientId, jobId);
      return res.json({ success: true, grants });
    } catch (error) {
      console.error('[user-folder-grants] list user error:', error);
      return jsonError(res, error.status || 500, error.message || 'Could not load folder shares.');
    }
  });

  app.post('/users/:id/folder-grants', requireAuth, requireUserAdmin, async (req, res) => {
    try {
      const userId = cleanString(req.params.id);
      const clientId = cleanString(req.body?.clientId ?? req.body?.client_id);
      const jobId = cleanString(req.body?.jobId ?? req.body?.job_id);
      const pathPrefix = normalizeRelPath(req.body?.pathPrefix ?? req.body?.path ?? '');
      if (!userId) return jsonError(res, 400, 'User id is required');
      if (!clientId || !jobId) return jsonError(res, 400, 'Choose a client workspace before sharing folders.');
      if (!pathPrefix) return jsonError(res, 400, 'Pick a folder to share.');
      if (!grantScopeAllowed(req, clientId, jobId)) {
        return jsonError(res, 403, 'That folder is outside your workspace.');
      }
      if (typeof assertUserIdInTenantScope === 'function') {
        const allowed = await assertUserIdInTenantScope(pool, userId, req.tenantScope);
        if (!allowed) return jsonError(res, 403, 'That user is outside your workspace.');
      }
      const grant = await addFolderGrantForUser(pool, userId, clientId, jobId, pathPrefix);
      return res.status(201).json({
        success: true,
        grant,
        message: 'Folder shared. They can see that folder and everything inside it.'
      });
    } catch (error) {
      console.error('[user-folder-grants] add user error:', error);
      return jsonError(res, error.status || 500, error.message || 'Could not share that folder.');
    }
  });

  app.delete('/users/:id/folder-grants/:grantId', requireAuth, requireUserAdmin, async (req, res) => {
    try {
      const userId = cleanString(req.params.id);
      const grantId = cleanString(req.params.grantId);
      if (!userId || !grantId) return jsonError(res, 400, 'Folder share id is required');
      if (typeof assertUserIdInTenantScope === 'function') {
        const allowed = await assertUserIdInTenantScope(pool, userId, req.tenantScope);
        if (!allowed) return jsonError(res, 403, 'That user is outside your workspace.');
      }
      const existing = await pool.query(
        `SELECT client_id, job_id FROM user_folder_grants WHERE id = $1 AND user_id = $2 AND app = 'pipeshare' LIMIT 1`,
        [grantId, userId]
      );
      if (!existing.rowCount) return jsonError(res, 404, 'That folder share is already gone.');
      if (!grantScopeAllowed(req, existing.rows[0].client_id, existing.rows[0].job_id)) {
        return jsonError(res, 403, 'That folder is outside your workspace.');
      }
      await removeFolderGrantForUser(pool, userId, grantId);
      return res.json({ success: true, message: 'Folder share removed.' });
    } catch (error) {
      console.error('[user-folder-grants] delete user error:', error);
      return jsonError(res, error.status || 500, error.message || 'Could not remove that folder share.');
    }
  });

  console.log('[user-grants] /user-folder-grants routes mounted');
}

module.exports = { registerUserGrantsRoutes };
