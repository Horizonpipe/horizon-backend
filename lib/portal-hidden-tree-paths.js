'use strict';

/** Must stay aligned with {@code PORTAL_CATEGORIES} in saas-tenant-paths.js (legacy BASE upload buckets). */
const PORTAL_LEGACY_CATEGORY_FOLDERS = Object.freeze(['videos', 'db3', 'pdf', 'photos']);

/** Provisioned job-root folders kept for legacy routing / PipeSync state — not shown to SaaS clients. */
const PORTAL_TENANT_HIDDEN_FOLDER_NAMES = Object.freeze(
  new Set([...PORTAL_LEGACY_CATEGORY_FOLDERS, 'system-state'])
);

function isTenantPortalClientId(clientId) {
  return /^tenant-/i.test(String(clientId || ''));
}

function normalizeHiddenRelPath(relPath) {
  return String(relPath || '')
    .trim()
    .replace(/\\/g, '/')
    .replace(/^\/+|\/+$/g, '');
}

/**
 * True when a portal-relative path lives under a hidden scaffold folder (e.g. `videos/foo.mp4`).
 * @param {string} relPath
 */
function isHiddenPortalTreeRelPath(relPath) {
  const p = normalizeHiddenRelPath(relPath);
  if (!p) return false;
  const top = p.split('/')[0].toLowerCase();
  return PORTAL_TENANT_HIDDEN_FOLDER_NAMES.has(top);
}

/**
 * Strip category / infra scaffold folders from explorer trees for SaaS tenant jobs.
 * BASE (`portal-users`) and permissions-editor listings are unchanged.
 * @param {{ folders?: Array<{ path: string }>, files?: Array<{ path: string }> } | null | undefined} tree
 * @param {string} clientId
 * @param {{ skipFilter?: boolean }} [opts]
 */
function filterHiddenPortalTreeForTenantClient(tree, clientId, opts = {}) {
  if (opts.skipFilter || !tree || !isTenantPortalClientId(clientId)) {
    return tree;
  }
  const folders = (tree.folders || []).filter((f) => !isHiddenPortalTreeRelPath(f.path));
  const files = (tree.files || []).filter((f) => !isHiddenPortalTreeRelPath(f.path));
  return { ...tree, folders, files };
}

module.exports = {
  PORTAL_LEGACY_CATEGORY_FOLDERS,
  PORTAL_TENANT_HIDDEN_FOLDER_NAMES,
  isTenantPortalClientId,
  isHiddenPortalTreeRelPath,
  filterHiddenPortalTreeForTenantClient
};
