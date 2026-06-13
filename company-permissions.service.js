'use strict';

const COMPANY_ROLE_KEYS = ['admin', 'employee', 'customer'];

const DEFAULT_APP_FEATURES = {
  pipeshare: true,
  pipesync: true,
  autosync: false,
  planview: true
};

function normalizeRelPath(raw) {
  return String(raw || '')
    .replace(/\\/g, '/')
    .replace(/^\/+|\/+$/g, '')
    .trim();
}

function normalizeAppFeatures(raw) {
  const base = { ...DEFAULT_APP_FEATURES };
  if (!raw || typeof raw !== 'object') return base;
  for (const key of Object.keys(DEFAULT_APP_FEATURES)) {
    if (typeof raw[key] === 'boolean') base[key] = raw[key];
  }
  return base;
}

function mapCompanyGrantToPortalGrant(row) {
  if (!row || row.enabled === false) {
    return { path_prefix: normalizeRelPath(row?.path_prefix), recursive: true, access_mode: 'off' };
  }
  if (!row.can_view) {
    return { path_prefix: normalizeRelPath(row.path_prefix), recursive: true, access_mode: 'off' };
  }
  let access_mode = 'view';
  if (row.can_download) access_mode = 'view_download';
  if (row.can_edit || row.can_delete || row.can_upload) access_mode = 'full';
  return {
    path_prefix: normalizeRelPath(row.path_prefix),
    recursive: true,
    access_mode,
    _companyGrant: {
      canView: !!row.can_view,
      canEdit: !!row.can_edit,
      canDelete: !!row.can_delete,
      canUpload: !!row.can_upload,
      canDownload: !!row.can_download
    }
  };
}

function mapOverrideGrantToPortalGrant(entry) {
  if (!entry || typeof entry !== 'object') return null;
  return mapCompanyGrantToPortalGrant({
    path_prefix: entry.pathPrefix ?? entry.path_prefix ?? '',
    enabled: entry.enabled !== false,
    can_view: entry.canView ?? entry.can_view ?? true,
    can_edit: entry.canEdit ?? entry.can_edit ?? false,
    can_delete: entry.canDelete ?? entry.can_delete ?? false,
    can_upload: entry.canUpload ?? entry.can_upload ?? false,
    can_download: entry.canDownload ?? entry.can_download ?? false
  });
}

function mergePortalGrantRows(rows) {
  const byPath = new Map();
  for (const row of rows) {
    const key = normalizeRelPath(row.path_prefix ?? '');
    const existing = byPath.get(key);
    if (!existing) {
      byPath.set(key, row);
      continue;
    }
    const modes = ['off', 'view', 'view_download', 'full'];
    const nextMode = modes[Math.max(modes.indexOf(existing.access_mode || 'off'), modes.indexOf(row.access_mode || 'off'))];
    byPath.set(key, { ...existing, access_mode: nextMode });
  }
  return [...byPath.values()];
}

function accessModeToCompanyFlags(rawMode) {
  const mode = String(rawMode || 'full')
    .trim()
    .toLowerCase();
  if (mode === 'off' || mode === 'none') {
    return { canView: false, canEdit: false, canDelete: false, canUpload: false, canDownload: false };
  }
  if (mode === 'view') {
    return { canView: true, canEdit: false, canDelete: false, canUpload: false, canDownload: false };
  }
  if (mode === 'view_download') {
    return { canView: true, canEdit: false, canDelete: false, canUpload: false, canDownload: true };
  }
  return { canView: true, canEdit: true, canDelete: true, canUpload: true, canDownload: true };
}

async function loadUserCompanyMembership(pool, userId) {
  const r = await pool.query(
    `SELECT m.id, m.user_id, m.company_id, m.role_key, m.override_folder_grants, m.created_at, m.updated_at,
            c.name AS company_name, c.app_features, c.customer_enabled
     FROM user_company_membership m
     JOIN companies c ON c.id = m.company_id
     WHERE m.user_id = $1
     LIMIT 1`,
    [String(userId)]
  );
  if (!r.rows.length) return null;
  const row = r.rows[0];
  return {
    id: row.id,
    userId: row.user_id,
    companyId: row.company_id,
    roleKey: row.role_key,
    companyName: row.company_name,
    appFeatures: normalizeAppFeatures(row.app_features),
    customerEnabled: row.customer_enabled === true,
    overrideFolderGrants: Array.isArray(row.override_folder_grants) ? row.override_folder_grants : [],
    createdAt: row.created_at,
    updatedAt: row.updated_at
  };
}

async function companyJobHasFolderGrants(pool, companyId, clientId, jobId, roleKey) {
  const r = await pool.query(
    `SELECT 1 FROM company_folder_grants
     WHERE company_id = $1 AND client_id = $2 AND job_id = $3 AND role_key = $4 AND enabled = true
     LIMIT 1`,
    [String(companyId), String(clientId), String(jobId), String(roleKey)]
  );
  return r.rows.length > 0;
}

async function loadCompanyFolderGrants(pool, companyId, roleKey, clientId, jobId) {
  const r = await pool.query(
    `SELECT path_prefix, enabled, can_view, can_edit, can_delete, can_upload, can_download
     FROM company_folder_grants
     WHERE company_id = $1 AND role_key = $2 AND client_id = $3 AND job_id = $4
     ORDER BY length(path_prefix) DESC, path_prefix ASC`,
    [String(companyId), String(roleKey), String(clientId), String(jobId)]
  );
  return r.rows.map(mapCompanyGrantToPortalGrant).filter((g) => g.access_mode !== 'off');
}

/**
 * Canonical-only effective grants:
 * company role grants + user override grants.
 */
async function loadEffectivePathGrantsForUser(pool, user, clientId, jobId, loadUserPathGrantsFn) {
  void loadUserPathGrantsFn;
  if (!user?.id) return [];

  const membership = await loadUserCompanyMembership(pool, user.id);
  if (!membership) return [];

  const companyGrants = await loadCompanyFolderGrants(
    pool,
    membership.companyId,
    membership.roleKey,
    clientId,
    jobId
  );

  const overrideGrants = (membership.overrideFolderGrants || [])
    .filter((entry) => {
      const cid = String(entry?.clientId || entry?.client_id || '').trim();
      const jid = String(entry?.jobId || entry?.job_id || '').trim();
      return (!cid || cid === String(clientId)) && (!jid || jid === String(jobId));
    })
    .map(mapOverrideGrantToPortalGrant)
    .filter(Boolean)
    .filter((g) => g.access_mode !== 'off');

  if (!companyGrants.length && !overrideGrants.length) return [];
  return mergePortalGrantRows([...companyGrants, ...overrideGrants]);
}

async function jobHasAnyEffectivePathGrants(pool, user, clientId, jobId, portalJobHasPathGrantsFn) {
  void portalJobHasPathGrantsFn;
  if (!user?.id) return false;
  const membership = await loadUserCompanyMembership(pool, user.id);
  if (!membership) return false;
  if (await companyJobHasFolderGrants(pool, membership.companyId, clientId, jobId, membership.roleKey)) return true;
  const wantClient = String(clientId || '').trim().toLowerCase();
  const wantJob = String(jobId || '').trim().toLowerCase();
  return (membership.overrideFolderGrants || []).some((entry) => {
    const entryClient = String(entry?.clientId || entry?.client_id || '').trim().toLowerCase();
    const entryJob = String(entry?.jobId || entry?.job_id || '').trim().toLowerCase();
    return entryClient === wantClient && entryJob === wantJob;
  });
}

async function migrateLegacyScopeAuthorityForUserJob(pool, user, clientId, jobId) {
  const userId = String(user?.id || '').trim();
  const username = String(user?.username || '').trim();
  const email = String(user?.email || '').trim();
  const c = String(clientId || '').trim();
  const j = String(jobId || '').trim();
  if (!userId || !c || !j) return false;

  const membership = await loadUserCompanyMembership(pool, userId);
  if (!membership) return false;

  const existing = Array.isArray(membership.overrideFolderGrants) ? membership.overrideFolderGrants : [];
  const merged = [...existing];
  const existingKeys = new Set(
    merged.map((entry) =>
      `${String(entry?.clientId || entry?.client_id || '')
        .trim()
        .toLowerCase()}\0${String(entry?.jobId || entry?.job_id || '')
        .trim()
        .toLowerCase()}\0${normalizeRelPath(entry?.pathPrefix || entry?.path_prefix || '')}`
    )
  );
  const nowIso = new Date().toISOString();
  const pushIfMissing = (entry) => {
    const key = `${String(entry.clientId || '')
      .trim()
      .toLowerCase()}\0${String(entry.jobId || '')
      .trim()
      .toLowerCase()}\0${normalizeRelPath(entry.pathPrefix || '')}`;
    if (existingKeys.has(key)) return;
    existingKeys.add(key);
    merged.push(entry);
  };

  const portalScopeRes = await pool.query(
    `SELECT 1
     FROM user_portal_scopes
     WHERE user_id = $1 AND client_id = $2 AND job_id = $3
     LIMIT 1`,
    [userId, c, j]
  );
  if (portalScopeRes.rows.length) {
    pushIfMissing({
      clientId: c,
      jobId: j,
      pathPrefix: '',
      enabled: true,
      canView: true,
      canEdit: true,
      canDelete: true,
      canUpload: true,
      canDownload: true,
      source: 'legacy-user-portal-scopes',
      migratedAt: nowIso
    });
  }

  const psrScopeRes = await pool.query(
    `SELECT 1
     FROM user_psr_scopes
     WHERE user_id = $1
       AND UPPER(TRIM(client)) = UPPER(TRIM($2))
       AND (
         (psr_record_id IS NOT NULL AND BTRIM(psr_record_id) <> '' AND UPPER(TRIM(psr_record_id)) = UPPER(TRIM($3)))
         OR UPPER(TRIM(jobsite)) = UPPER(TRIM($3))
       )
     LIMIT 1`,
    [userId, c, j]
  );
  if (psrScopeRes.rows.length) {
    pushIfMissing({
      clientId: c,
      jobId: j,
      pathPrefix: '',
      enabled: true,
      canView: true,
      canEdit: true,
      canDelete: true,
      canUpload: true,
      canDownload: true,
      source: 'legacy-user-psr-scopes',
      migratedAt: nowIso
    });
  }

  if (username || email) {
    const pathGrantRes = await pool.query(
      `SELECT path_prefix, COALESCE(recursive, true) AS recursive, COALESCE(access_mode, 'full') AS access_mode
       FROM portal_path_grants
       WHERE client_id = $1
         AND job_id = $2
         AND (
           LOWER(TRIM(username)) = LOWER(TRIM($3))
           OR ($4 <> '' AND LOWER(TRIM(username)) = LOWER(TRIM($4)))
         )`,
      [c, j, username, email]
    );
    for (const row of pathGrantRes.rows) {
      const flags = accessModeToCompanyFlags(row.access_mode);
      pushIfMissing({
        clientId: c,
        jobId: j,
        pathPrefix: normalizeRelPath(row.path_prefix || ''),
        enabled: row.access_mode !== 'off' && row.access_mode !== 'none',
        canView: flags.canView,
        canEdit: flags.canEdit,
        canDelete: flags.canDelete,
        canUpload: flags.canUpload,
        canDownload: flags.canDownload,
        recursive: row.recursive !== false,
        source: 'legacy-portal-path-grants',
        migratedAt: nowIso
      });
    }
  }

  if (merged.length === existing.length) return false;
  await pool.query(
    `UPDATE user_company_membership
     SET override_folder_grants = $1::jsonb,
         updated_at = NOW()
     WHERE user_id = $2`,
    [JSON.stringify(merged), userId]
  );
  return true;
}

function buildSkeletonPath(clientId, jobId, relPath) {
  const parts = [String(clientId || '').trim(), String(jobId || '').trim()]
    .concat(normalizeRelPath(relPath).split('/').filter(Boolean))
    .filter(Boolean);
  return parts.join('>');
}

async function recordTrashBinEntry(pool, entry) {
  const expiresAt = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000);
  const r = await pool.query(
    `INSERT INTO trash_bin_entries
      (company_id, client_id, job_id, item_type, item_id, rel_path, original_parent_path, skeleton_path, metadata, deleted_by_user_id, expires_at)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9::jsonb,$10,$11)
     RETURNING id, company_id, client_id, job_id, item_type, item_id, rel_path, original_parent_path, skeleton_path, metadata, deleted_by_user_id, deleted_at, expires_at, restored_at`,
    [
      entry.companyId || null,
      String(entry.clientId),
      String(entry.jobId),
      String(entry.itemType),
      entry.itemId ? String(entry.itemId) : null,
      normalizeRelPath(entry.relPath),
      normalizeRelPath(entry.originalParentPath || ''),
      String(entry.skeletonPath || buildSkeletonPath(entry.clientId, entry.jobId, entry.relPath)),
      JSON.stringify(entry.metadata || {}),
      entry.deletedByUserId ? String(entry.deletedByUserId) : null,
      expiresAt
    ]
  );
  return r.rows[0] || null;
}

module.exports = {
  COMPANY_ROLE_KEYS,
  DEFAULT_APP_FEATURES,
  normalizeAppFeatures,
  normalizeRelPath,
  mapCompanyGrantToPortalGrant,
  loadUserCompanyMembership,
  loadCompanyFolderGrants,
  companyJobHasFolderGrants,
  loadEffectivePathGrantsForUser,
  jobHasAnyEffectivePathGrants,
  migrateLegacyScopeAuthorityForUserJob,
  buildSkeletonPath,
  recordTrashBinEntry,
  mergePortalGrantRows
};
