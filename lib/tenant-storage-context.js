'use strict';

const { slugifyTenantName } = require('./saas-tenant-paths');
const { parseSaasTenantSlugFromHost } = require('./saas-tenant-access-urls');
const { resolveDeploymentProfile } = require('./deployment-profile');

const EMPTY_CONTEXT = Object.freeze({
  wasabiRootPrefix: '',
  portalClientId: '',
  portalJobId: '',
  companyId: '',
  tenantId: '',
  tenantSlug: ''
});

function cleanString(v) {
  return String(v ?? '').trim();
}

function segment(s) {
  const t = cleanString(s);
  if (!t || t.includes('..') || t.includes('/') || t.includes('\\')) {
    throw new Error('Invalid clientId or jobId');
  }
  return t;
}

function sanitizeFilename(name) {
  const base = String(name ?? '').split(/[/\\]/).pop() || 'file';
  const cleaned = base.replace(/[^\w.\- ()\[\]]+/g, '_').slice(0, 240);
  if (!cleaned) throw new Error('Invalid filename');
  return cleaned;
}

function tenantSlugFromRoot(root) {
  const m = /^(?:Tenants|tenants)\/([^/]+)\/?$/i.exec(String(root || '').replace(/\/+$/, ''));
  return m ? slugifyTenantName(m[1]) : '';
}

function serializeContextFromRow(row) {
  if (!row) return { ...EMPTY_CONTEXT };
  const setupStatus = cleanString(row.setup_status || row.setupStatus);
  const rawRoot = cleanString(row.wasabi_root_prefix || row.wasabiRootPrefix);
  const wasabiRootPrefix = setupStatus === 'ready' ? rawRoot : '';
  return {
    wasabiRootPrefix,
    portalClientId: cleanString(row.portal_client_id || row.portalClientId),
    portalJobId: cleanString(row.portal_job_id || row.portalJobId) || '1',
    companyId: cleanString(row.company_id || row.companyId),
    tenantId: cleanString(row.id || row.tenantId),
    tenantSlug: tenantSlugFromRoot(wasabiRootPrefix || rawRoot)
  };
}

/**
 * Resolve Wasabi storage scope for the signed-in user.
 * SaaS virtualbox prefix applies only when the user's portal scope is already bound
 * to that tenant (`tenant-{slug}`). Company membership / owner alone must not
 * hijack base PipeShare (portal-users) sessions for platform admins.
 * @param {{ query: Function }} pool
 * @param {string|number} userId
 * @param {{ requestHost?: string }} [options]
 */
async function resolveTenantStorageContext(pool, userId, options = {}) {
  const uid = cleanString(userId);
  if (!uid || !pool || typeof pool.query !== 'function') {
    return { ...EMPTY_CONTEXT };
  }

  const userRow = await pool.query(
    `SELECT portal_files_client_id, portal_files_job_id FROM users WHERE CAST(id AS text) = $1 LIMIT 1`,
    [uid]
  );
  const portalClientId = cleanString(userRow.rows[0]?.portal_files_client_id);
  const portalJobId = cleanString(userRow.rows[0]?.portal_files_job_id) || '1';
  if (!portalClientId || !/^tenant-/i.test(portalClientId)) {
    return { ...EMPTY_CONTEXT };
  }

  const r = await pool.query(
    `SELECT id, company_id, wasabi_root_prefix, portal_client_id, portal_job_id, setup_status
     FROM saas_tenant_instances
     WHERE portal_client_id = $1 AND portal_job_id = $2
     LIMIT 1`,
    [portalClientId, portalJobId]
  );
  if (!r.rows[0]) return { ...EMPTY_CONTEXT };

  const ctx = serializeContextFromRow(r.rows[0]);
  const tenantSlug = ctx.tenantSlug || tenantSlugFromRoot(ctx.wasabiRootPrefix);
  const requestHost = cleanString(options.requestHost);
  const profile = resolveDeploymentProfile({ requestHost });
  const hostSlug = parseSaasTenantSlugFromHost(requestHost);

  if (profile.features.tenantHostBindingStrict) {
    if (!hostSlug || !tenantSlug || hostSlug !== tenantSlug) {
      return { ...EMPTY_CONTEXT };
    }
  } else if (profile.isPrivateBase) {
    return { ...EMPTY_CONTEXT };
  }

  return ctx;
}

/** Ensure tenant root prefixes always end with `/` so `Tenants/foo` + `clients/...` never glues. */
function normalizeStorageRootPrefix(root) {
  let r = cleanString(root).replace(/\\/g, '/');
  if (r && !r.endsWith('/')) r += '/';
  return r;
}

function fullJobPrefix(root, clientId, jobId) {
  const base = `clients/${segment(clientId)}/jobs/${segment(jobId)}/`;
  const r = normalizeStorageRootPrefix(root);
  return r ? `${r}${base}` : base;
}

function fullObjectKey(root, clientId, jobId, category, filename) {
  const safe = sanitizeFilename(filename);
  const cat = cleanString(category);
  if (!cat) throw new Error('Invalid category');
  return `${fullJobPrefix(root, clientId, jobId)}${cat}/${safe}`;
}

const PORTAL_CLIENTS_KEY_RE = new RegExp(
  '^(?:(?:Tenants|tenants)/[^/]+/)?clients/([^/]+)/jobs/([^/]+)/',
  'i'
);

function parseJobFromPrefixedObjectKey(key) {
  const m = PORTAL_CLIENTS_KEY_RE.exec(String(key ?? ''));
  if (!m) return null;
  return { clientId: m[1], jobId: m[2] };
}

function isPortalClientsObjectKey(key) {
  return PORTAL_CLIENTS_KEY_RE.test(String(key ?? ''));
}

function assertKeyWithinTenantRoot(key, root) {
  const r = normalizeStorageRootPrefix(root);
  if (!r) return;
  const k = String(key ?? '').replace(/\\/g, '/');
  if (!k || k.includes('..')) {
    throw new Error('Key outside tenant root');
  }
  if (!k.startsWith(r)) {
    throw new Error('Key outside tenant root');
  }
  const otherTenant = /^(?:Tenants|tenants)\/([^/]+)\//i.exec(k);
  if (otherTenant) {
    const expectedSlug = tenantSlugFromRoot(r);
    if (expectedSlug && otherTenant[1] !== expectedSlug) {
      throw new Error('Key outside tenant root');
    }
  }
}

/**
 * When SaaS storage context is active, clientId/jobId must match the tenant portal scope.
 * @param {{ wasabiRootPrefix?: string, portalClientId?: string, portalJobId?: string }} ctx
 */
function assertTenantPortalScope(ctx, clientId, jobId) {
  const root = cleanString(ctx?.wasabiRootPrefix);
  if (!root) return;
  const expectedClient = cleanString(ctx?.portalClientId);
  const expectedJob = cleanString(ctx?.portalJobId) || '1';
  const c = cleanString(clientId);
  const j = cleanString(jobId);
  if (expectedClient && c !== expectedClient) {
    throw new Error('Forbidden');
  }
  if (expectedJob && j !== expectedJob) {
    throw new Error('Forbidden');
  }
}

/**
 * Tenant Wasabi root for a portal job — prefers request context, else DB lookup by portal scope.
 * @param {{ query: Function }} pool
 * @param {string} clientId
 * @param {string} jobId
 * @param {{ tenantStorage?: { wasabiRootPrefix?: string } } | null | undefined} req
 */
async function resolveStorageRootForJob(pool, clientId, jobId, req) {
  const fromReq = cleanString(req?.tenantStorage?.wasabiRootPrefix);
  if (fromReq) return fromReq;
  if (!pool || typeof pool.query !== 'function') return '';
  const c = cleanString(clientId);
  const j = cleanString(jobId) || '1';
  if (!c) return '';
  const r = await pool.query(
    `SELECT wasabi_root_prefix, setup_status
     FROM saas_tenant_instances
     WHERE portal_client_id = $1 AND portal_job_id = $2
     LIMIT 1`,
    [c, j]
  );
  const row = r.rows[0];
  if (row && cleanString(row.setup_status) === 'ready') {
    return cleanString(row.wasabi_root_prefix);
  }
  return '';
}

module.exports = {
  EMPTY_CONTEXT,
  resolveTenantStorageContext,
  fullJobPrefix,
  fullObjectKey,
  parseJobFromPrefixedObjectKey,
  isPortalClientsObjectKey,
  assertKeyWithinTenantRoot,
  assertTenantPortalScope,
  tenantSlugFromRoot,
  normalizeStorageRootPrefix,
  resolveStorageRootForJob,
  sanitizeFilename,
  segment
};
