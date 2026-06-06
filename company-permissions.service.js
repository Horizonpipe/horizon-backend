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
 * Wrap existing portal_path_grants with company role grants and optional user overrides.
 * Existing per-user portal grants are preserved and merged (union, strongest mode wins).
 */
async function loadEffectivePathGrantsForUser(pool, user, clientId, jobId, loadUserPathGrantsFn) {
  const portalGrants =
    typeof loadUserPathGrantsFn === 'function'
      ? await loadUserPathGrantsFn(pool, clientId, jobId, user)
      : [];

  if (!user?.id) return portalGrants;

  const membership = await loadUserCompanyMembership(pool, user.id);
  if (!membership) return portalGrants;

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

  if (!companyGrants.length && !overrideGrants.length) return portalGrants;
  return mergePortalGrantRows([...portalGrants, ...companyGrants, ...overrideGrants]);
}

async function jobHasAnyEffectivePathGrants(pool, user, clientId, jobId, portalJobHasPathGrantsFn) {
  const portalHas =
    typeof portalJobHasPathGrantsFn === 'function'
      ? await portalJobHasPathGrantsFn(pool, clientId, jobId)
      : false;
  if (portalHas) return true;
  if (!user?.id) return false;
  const membership = await loadUserCompanyMembership(pool, user.id);
  if (!membership) return false;
  return companyJobHasFolderGrants(pool, membership.companyId, clientId, jobId, membership.roleKey);
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
  buildSkeletonPath,
  recordTrashBinEntry,
  mergePortalGrantRows
};
