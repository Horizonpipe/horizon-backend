'use strict';

const {
  normalizeRelPath,
  mapCompanyGrantToPortalGrant,
  accessModeToCompanyFlags,
  loadUserCompanyMembership
} = require('./company-permissions.service');

const FULL_SHARE_FLAGS = {
  canView: true,
  canEdit: true,
  canDelete: true,
  canUpload: true,
  canDownload: true
};

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

async function listFolderGrantsForUser(pool, userId, clientId, jobId) {
  const r = await pool.query(
    `SELECT g.id, g.user_id, g.app, g.client_id, g.job_id, g.path_prefix, g.psr_scope_level, g.psr_city,
            g.recursive, g.enabled, g.can_view, g.can_edit, g.can_delete, g.can_upload, g.can_download,
            u.username, u.display_name
     FROM user_folder_grants g
     LEFT JOIN users u ON CAST(u.id AS text) = g.user_id
     WHERE g.user_id = $1 AND g.app = 'pipeshare' AND g.client_id = $2
       AND ($3 = '' OR g.job_id = $3)
       AND g.psr_scope_level = ''
     ORDER BY g.path_prefix ASC`,
    [String(userId), String(clientId), String(jobId || '')]
  );
  return r.rows.map(serializeUserFolderGrantRow);
}

function flagsForShareAccessMode(raw) {
  const mode = String(raw || '').trim().toLowerCase();
  if (mode !== 'view' && mode !== 'view_download' && mode !== 'full') {
    const err = new Error('Choose view only, view and download, or full access.');
    err.status = 400;
    throw err;
  }
  return accessModeToCompanyFlags(mode);
}

function flagsForGrantOptions(options) {
  const mode = String(options?.accessMode || '').trim();
  if (!mode) return { ...FULL_SHARE_FLAGS };
  return flagsForShareAccessMode(mode);
}

function looksLikeInternalShareLabel(value) {
  const label = String(value || '').trim();
  if (!label) return true;
  if (/^portal-users$/i.test(label)) return true;
  if (/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(label)) return true;
  if (/^\d{6,}$/.test(label)) return true;
  return false;
}

function presentShareAccount(row) {
  const username = String(row.username || '').trim();
  if (!username || looksLikeInternalShareLabel(username)) return null;
  const composed = [row.first_name, row.last_name]
    .map((part) => String(part || '').trim())
    .filter(Boolean)
    .join(' ');
  const display = String(row.display_name || '').trim();
  let name = '';
  if (display && !looksLikeInternalShareLabel(display)) name = display;
  else if (composed && !looksLikeInternalShareLabel(composed)) name = composed;
  else name = username;
  const accountType = String(row.account_type || 'employee').toLowerCase() === 'customer' ? 'customer' : 'employee';
  return {
    id: String(row.id),
    name,
    username,
    accountType
  };
}

async function listShareAccounts(pool, actorId, tenantScope) {
  const id = String(actorId || '').trim();
  if (!id) return [];
  let result;
  if (tenantScope?.mode === 'tenant' && tenantScope.companyId && tenantScope.portalClientId) {
    const { tenantUsersWhereSql } = require('./lib/saas-tenant-scope');
    const where = tenantUsersWhereSql(1);
    result = await pool.query(
      `SELECT u.id, u.username, u.display_name, u.first_name, u.last_name, u.account_type
       FROM users u
       WHERE CAST(u.id AS text) <> $3
         AND LOWER(COALESCE(u.account_type, 'employee')) IN ('employee', 'customer')
         AND ${where}
       ORDER BY LOWER(COALESCE(NULLIF(BTRIM(u.display_name), ''), u.username)), LOWER(u.username)`,
      [String(tenantScope.portalClientId), String(tenantScope.companyId), id]
    );
  } else {
    const membership = await loadUserCompanyMembership(pool, id);
    const companyId = String(membership?.companyId || '').trim();
    if (companyId) {
      result = await pool.query(
        `SELECT u.id, u.username, u.display_name, u.first_name, u.last_name, u.account_type
         FROM users u
         WHERE CAST(u.id AS text) <> $2
           AND LOWER(COALESCE(u.account_type, 'employee')) IN ('employee', 'customer')
           AND (
             EXISTS (
               SELECT 1 FROM user_company_membership m
               WHERE CAST(m.user_id AS text) = CAST(u.id AS text)
                 AND m.company_id = $1::uuid
             )
             OR (
               LOWER(COALESCE(u.account_type, '')) = 'customer'
               AND NOT EXISTS (
                 SELECT 1 FROM user_company_membership m
                 WHERE CAST(m.user_id AS text) = CAST(u.id AS text)
                   AND m.company_id <> $1::uuid
               )
               AND (
                 u.portal_files_client_id IS NULL
                 OR BTRIM(u.portal_files_client_id) = ''
                 OR LOWER(BTRIM(u.portal_files_client_id)) = 'portal-users'
               )
             )
           )
         ORDER BY LOWER(COALESCE(NULLIF(BTRIM(u.display_name), ''), u.username)), LOWER(u.username)`,
        [companyId, id]
      );
    } else {
      result = await pool.query(
        `SELECT id, username, display_name, first_name, last_name, account_type
         FROM users
         WHERE CAST(id AS text) <> $1
           AND LOWER(COALESCE(account_type, 'employee')) IN ('employee', 'customer')
         ORDER BY LOWER(COALESCE(NULLIF(BTRIM(display_name), ''), username)), LOWER(username)`,
        [id]
      );
    }
  }
  return result.rows.map(presentShareAccount).filter(Boolean);
}

async function addFolderGrantForUser(pool, userId, clientId, jobId, pathPrefix, options = {}) {
  const path = normalizeRelPath(pathPrefix);
  if (!path) {
    const err = new Error('Pick a folder to share.');
    err.status = 400;
    throw err;
  }
  const flags = flagsForGrantOptions(options);
  const recursive = options?.recursive === false ? false : true;
  const r = await pool.query(
    `INSERT INTO user_folder_grants
      (user_id, app, client_id, job_id, path_prefix, psr_scope_level, psr_city, recursive,
       enabled, can_view, can_edit, can_delete, can_upload, can_download)
     VALUES ($1, 'pipeshare', $2, $3, $4, '', '', $5, true, $6, $7, $8, $9, $10)
     ON CONFLICT (user_id, app, client_id, job_id, path_prefix, psr_scope_level, psr_city)
     DO UPDATE SET
       recursive = EXCLUDED.recursive,
       enabled = true,
       can_view = EXCLUDED.can_view,
       can_edit = EXCLUDED.can_edit,
       can_delete = EXCLUDED.can_delete,
       can_upload = EXCLUDED.can_upload,
       can_download = EXCLUDED.can_download,
       updated_at = NOW()
     RETURNING id, user_id, app, client_id, job_id, path_prefix, psr_scope_level, psr_city,
               recursive, enabled, can_view, can_edit, can_delete, can_upload, can_download`,
    [
      String(userId),
      String(clientId),
      String(jobId),
      path,
      recursive,
      flags.canView,
      flags.canEdit,
      flags.canDelete,
      flags.canUpload,
      flags.canDownload
    ]
  );
  const row = r.rows[0];
  const userRes = await pool.query(
    `SELECT username, display_name FROM users WHERE CAST(id AS text) = $1 LIMIT 1`,
    [String(userId)]
  );
  return serializeUserFolderGrantRow({
    ...row,
    username: userRes.rows[0]?.username,
    display_name: userRes.rows[0]?.display_name
  });
}

async function removeFolderGrantForUser(pool, userId, grantId) {
  const r = await pool.query(
    `DELETE FROM user_folder_grants
     WHERE id = $1 AND user_id = $2 AND app = 'pipeshare'
     RETURNING id`,
    [String(grantId), String(userId)]
  );
  return r.rowCount > 0;
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
  listFolderGrantsForUser,
  listShareAccounts,
  addFolderGrantForUser,
  removeFolderGrantForUser,
  jobHasDirectUserFolderGrants,
  saveUserFolderGrantsForScope,
  syncPsrScopeForUserGrant,
  flagsForShareAccessMode
};
