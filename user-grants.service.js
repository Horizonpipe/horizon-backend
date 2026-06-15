'use strict';

const { normalizeRelPath, mapCompanyGrantToPortalGrant } = require('./company-permissions.service');

function cleanString(v) {
  return String(v ?? '').trim();
}

function serializeUserFolderGrantRow(row) {
  return {
    id: row.id,
    userId: row.user_id,
    username: row.username || '',
    displayName: row.display_name || '',
    app: row.app,
    clientId: row.client_id,
    jobId: row.job_id || '',
    pathPrefix: row.path_prefix || '',
    psrScopeLevel: row.psr_scope_level || '',
    psrCity: row.psr_city || '',
    recursive: row.recursive !== false,
    enabled: row.enabled !== false,
    canView: row.can_view !== false,
    canEdit: row.can_edit === true,
    canDelete: row.can_delete === true,
    canUpload: row.can_upload === true,
    canDownload: row.can_download === true
  };
}

function scopeWhereClause(scope, alias = '') {
  const p = alias ? `${alias}.` : '';
  return {
    sql: `${p}app = $1 AND ${p}client_id = $2 AND ${p}job_id = $3 AND ${p}path_prefix = $4 AND ${p}psr_scope_level = $5 AND ${p}psr_city = $6`,
    params: [
      scope.app,
      scope.clientId,
      scope.jobId || '',
      scope.pathPrefix || '',
      scope.psrScopeLevel || '',
      scope.psrCity || ''
    ]
  };
}

async function loadUserFolderGrantsForScope(pool, scope) {
  const where = scopeWhereClause(scope, 'g');
  const r = await pool.query(
    `SELECT g.id, g.user_id, g.app, g.client_id, g.job_id, g.path_prefix, g.psr_scope_level, g.psr_city,
            g.recursive, g.enabled, g.can_view, g.can_edit, g.can_delete, g.can_upload, g.can_download,
            u.username, u.display_name
     FROM user_folder_grants g
     LEFT JOIN users u ON CAST(u.id AS text) = g.user_id
     WHERE ${where.sql}
     ORDER BY lower(coalesce(u.display_name, u.username, g.user_id)), g.user_id`,
    where.params
  );
  return r.rows.map(serializeUserFolderGrantRow);
}

async function loadDirectUserFolderGrantsForUser(pool, userId, clientId, jobId) {
  if (!userId) return [];
  const r = await pool.query(
    `SELECT path_prefix, recursive, enabled, can_view, can_edit, can_delete, can_upload, can_download
     FROM user_folder_grants
     WHERE user_id = $1 AND app = 'pipeshare' AND client_id = $2 AND job_id = $3 AND psr_scope_level = ''
     ORDER BY length(path_prefix) DESC, path_prefix ASC`,
    [String(userId), String(clientId), String(jobId)]
  );
  return r.rows
    .map((row) =>
      mapCompanyGrantToPortalGrant({
        path_prefix: row.path_prefix,
        enabled: row.enabled,
        can_view: row.can_view,
        can_edit: row.can_edit,
        can_delete: row.can_delete,
        can_upload: row.can_upload,
        can_download: row.can_download,
        recursive: row.recursive !== false
      })
    )
    .filter((g) => g.access_mode !== 'off');
}

async function jobHasDirectUserFolderGrants(pool, clientId, jobId) {
  const r = await pool.query(
    `SELECT 1 FROM user_folder_grants
     WHERE app = 'pipeshare' AND client_id = $1 AND job_id = $2 AND enabled = true AND can_view = true
     LIMIT 1`,
    [String(clientId), String(jobId)]
  );
  return r.rows.length > 0;
}

async function saveUserFolderGrantsForScope(pool, scope, grants) {
  const where = scopeWhereClause(scope);
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query(`DELETE FROM user_folder_grants WHERE ${where.sql}`, where.params);
    const saved = [];
    for (const grant of grants) {
      const userId = cleanString(grant?.userId ?? grant?.user_id);
      if (!userId) continue;
      const enabled = grant?.enabled !== false;
      const canView = enabled && grant?.canView !== false;
      const canEdit = enabled && !!grant?.canEdit;
      const canDelete = enabled && !!grant?.canDelete;
      const canUpload = enabled && !!grant?.canUpload;
      const canDownload = enabled && !!grant?.canDownload;
      if (!canView && !canEdit && !canDelete && !canUpload && !canDownload) continue;
      const r = await client.query(
        `INSERT INTO user_folder_grants
          (user_id, app, client_id, job_id, path_prefix, psr_scope_level, psr_city, recursive,
           enabled, can_view, can_edit, can_delete, can_upload, can_download)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)
         RETURNING id, user_id, app, client_id, job_id, path_prefix, psr_scope_level, psr_city,
                   recursive, enabled, can_view, can_edit, can_delete, can_upload, can_download`,
        [
          userId,
          scope.app,
          scope.clientId,
          scope.jobId || '',
          scope.pathPrefix || '',
          scope.psrScopeLevel || '',
          scope.psrCity || '',
          scope.recursive !== false,
          enabled,
          canView,
          canEdit,
          canDelete,
          canUpload,
          canDownload
        ]
      );
      const row = r.rows[0];
      const userRes = await client.query(
        `SELECT username, display_name FROM users WHERE CAST(id AS text) = $1 LIMIT 1`,
        [userId]
      );
      saved.push({ ...row, username: userRes.rows[0]?.username, display_name: userRes.rows[0]?.display_name });
    }
    await client.query('COMMIT');
    return saved;
  } catch (err) {
    await client.query('ROLLBACK');
    throw err;
  } finally {
    client.release();
  }
}

async function syncPsrScopeForUserGrant(pool, scope, grantRow) {
  if (scope.app !== 'pipesync') return;
  const userId = cleanString(grantRow?.user_id ?? grantRow?.userId);
  if (!userId) return;
  const client = cleanString(scope.clientId);
  const city = cleanString(scope.psrCity);
  const jobsite = cleanString(scope.jobId);
  const recordId = jobsite;
  if (!client) return;
  let targetCity = city;
  let targetJobsite = jobsite || 'NOT SET';
  if (scope.psrScopeLevel === 'client') {
    targetCity = city || 'NOT SET';
    targetJobsite = jobsite || 'NOT SET';
  } else if (scope.psrScopeLevel === 'city') {
    targetJobsite = jobsite || 'NOT SET';
  }
  if (!targetCity && scope.psrScopeLevel !== 'client') return;
  await pool.query(
    `INSERT INTO user_psr_scopes (user_id, client, city, jobsite, psr_record_id)
     VALUES ($1, $2, $3, $4, $5)
     ON CONFLICT (user_id, client, city, jobsite)
     DO UPDATE SET psr_record_id = COALESCE(NULLIF(EXCLUDED.psr_record_id, ''), user_psr_scopes.psr_record_id)`,
    [userId, client, targetCity || 'NOT SET', targetJobsite, recordId || null]
  );
}

module.exports = {
  serializeUserFolderGrantRow,
  loadUserFolderGrantsForScope,
  loadDirectUserFolderGrantsForUser,
  jobHasDirectUserFolderGrants,
  saveUserFolderGrantsForScope,
  syncPsrScopeForUserGrant
};
