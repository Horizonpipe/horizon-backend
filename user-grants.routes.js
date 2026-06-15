'use strict';

const {
  normalizeRelPath,
  mapCompanyGrantToPortalGrant,
  serializeUserFolderGrantRow,
  loadUserFolderGrantsForScope,
  saveUserFolderGrantsForScope,
  syncPsrScopeForUserGrant
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

function registerUserGrantsRoutes(app, { pool, requireAuth, requireAdminPanelAccess }) {
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

  console.log('[user-grants] /user-folder-grants routes mounted');
}

module.exports = { registerUserGrantsRoutes };
