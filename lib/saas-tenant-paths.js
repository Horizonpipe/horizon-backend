'use strict';

const PORTAL_CATEGORIES = Object.freeze(['videos', 'db3', 'pdf', 'photos']);
const FOLDER_MARKER = '.hp-folder';

/**
 * Slug for Wasabi prefixes and tenant URLs.
 * @param {string} name
 */
function slugifyTenantName(name) {
  return String(name || '')
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 64);
}

/**
 * Root prefix for an isolated SaaS tenant inside the shared Wasabi bucket.
 * Example: tenants/acme-plumbing/
 * @param {string} slug
 */
function buildTenantWasabiRoot(slug) {
  const s = slugifyTenantName(slug);
  if (!s) throw new Error('Tenant slug is required');
  return `tenants/${s}/`;
}

/**
 * Portal client/job ids used by horizon-backend portal-files routes.
 * @param {string} slug
 */
function buildTenantPortalScope(slug) {
  const s = slugifyTenantName(slug);
  return {
    clientId: `tenant-${s}`,
    jobId: '1'
  };
}

/**
 * All object keys to create for initial tenant provisioning (folder markers + branding slot).
 * @param {string} slug
 * @returns {string[]}
 */
function buildTenantSkeletonKeys(slug) {
  const root = buildTenantWasabiRoot(slug);
  const { clientId, jobId } = buildTenantPortalScope(slug);
  const keys = new Set();

  const mark = (prefix) => {
    const p = prefix.endsWith('/') ? prefix : `${prefix}/`;
    keys.add(`${p}${FOLDER_MARKER}`);
  };

  mark(root.slice(0, -1));
  mark(`${root}branding`);
  mark(`${root}app-data/horizon-admin/attachments`);
  mark(`${root}app-data/horizon-pipesync/plan-pages`);
  mark(`${root}app-data/horizon-pipesync/plan-workspace-saves`);
  mark(`${root}app-data/addons`);
  mark(`${root}clients/${clientId}/jobs/${jobId}`);

  for (const category of PORTAL_CATEGORIES) {
    mark(`${root}clients/${clientId}/jobs/${jobId}/${category}`);
  }

  mark(`${root}clients/${clientId}/jobs/${jobId}/system-state`);
  mark(`${root}sql-mirror`);

  return [...keys];
}

/**
 * Per-tenant Wasabi state snapshot prefix (mirrors WASABI_PIPESYNC_STATE_PREFIX layout).
 * @param {string} slug
 */
function buildTenantStatePrefix(slug) {
  const { clientId, jobId } = buildTenantPortalScope(slug);
  return `${buildTenantWasabiRoot(slug)}clients/${clientId}/jobs/${jobId}/system-state`;
}

module.exports = {
  PORTAL_CATEGORIES,
  FOLDER_MARKER,
  slugifyTenantName,
  buildTenantWasabiRoot,
  buildTenantPortalScope,
  buildTenantSkeletonKeys,
  buildTenantStatePrefix
};
