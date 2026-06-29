'use strict';

const zlib = require('zlib');
const { GetObjectCommand, PutObjectCommand } = require('@aws-sdk/client-s3');
const { resolveTenantStorageContext } = require('./tenant-storage-context');
const { buildTenantStatePrefix, buildTenantPortalScope } = require('./saas-tenant-paths');
const { resolveStorageBackend } = require('./portal-storage-backend');
const { getSaasWasabiClient, saasWasabiBucket } = require('./saas-virtualbox-config');

/** @type {Map<string, { at: number, snapshot: object }>} */
const tenantSnapshotCache = new Map();
const TENANT_SNAPSHOT_CACHE_MS = 4000;

function cleanString(v) {
  return String(v ?? '').trim();
}

function isTenantBoundUser(user) {
  const pc = cleanString(user?.portalFilesClientId ?? user?.portal_files_client_id);
  return /^tenant-/i.test(pc);
}

/** Platform-wide PSR bypass — never for SaaS tenant-bound users. */
function userHasGlobalPsrBypass(user) {
  if (!(user?.isAdmin === true || user?.is_admin === true)) return false;
  if (isTenantBoundUser(user)) return false;
  return true;
}

function emptyTenantAppSnapshot(slug) {
  const { clientId, jobId } = buildTenantPortalScope(slug);
  const now = new Date().toISOString();
  return {
    generatedAt: now,
    source: 'horizon-backend',
    scope: { clientId, jobId, tenantSlug: slug },
    data: {
      jobsite_assets: [],
      planner_records: [],
      pricing_rates: [],
      daily_reports: [],
      user_psr_scopes: [],
      pipesync_plan_views: [],
      pipesync_plan_workspace_saves: []
    }
  };
}

async function bodyToBuffer(body) {
  if (!body) return Buffer.alloc(0);
  if (Buffer.isBuffer(body)) return body;
  if (body instanceof Uint8Array) return Buffer.from(body);
  const chunks = [];
  for await (const c of body) chunks.push(c);
  return Buffer.concat(chunks);
}

function decodeSnapshotBody(buf, contentEncoding) {
  const enc = String(contentEncoding || '').toLowerCase();
  const gzipMagic = buf.length >= 2 && buf[0] === 0x1f && buf[1] === 0x8b;
  if (enc.includes('gzip') || gzipMagic) {
    return zlib.gunzipSync(buf).toString('utf8');
  }
  return buf.toString('utf8');
}

/**
 * @param {{ query: Function }} pool
 * @param {import('express').Request} req
 */
async function resolveTenantWasabiStateScope(pool, req) {
  const uid = req?.user?.id;
  if (!uid || !pool || typeof pool.query !== 'function') return null;
  const requestHost = cleanString(req?.headers?.['x-forwarded-host'] || req?.headers?.host);
  const ctx = await resolveTenantStorageContext(pool, uid, { requestHost });
  if (!ctx?.tenantSlug || !ctx?.wasabiRootPrefix) return null;
  const backend = resolveStorageBackend(req);
  const s3 = backend.s3 || getSaasWasabiClient();
  const bucket = cleanString(backend.bucket || saasWasabiBucket());
  if (!s3 || !bucket) return null;
  return {
    tenantSlug: ctx.tenantSlug,
    statePrefix: buildTenantStatePrefix(ctx.tenantSlug),
    s3,
    bucket
  };
}

/**
 * @param {{ s3: import('@aws-sdk/client-s3').S3Client, bucket: string, statePrefix: string }} scope
 * @param {boolean} [force]
 */
async function loadTenantWasabiStateSnapshot(scope, force = false) {
  if (!scope?.s3 || !scope?.bucket || !scope?.statePrefix) return null;
  const cacheKey = `${scope.bucket}:${scope.statePrefix}`;
  const now = Date.now();
  if (!force) {
    const hit = tenantSnapshotCache.get(cacheKey);
    if (hit && now - hit.at <= TENANT_SNAPSHOT_CACHE_MS) return hit.snapshot;
  }
  try {
    const out = await scope.s3.send(
      new GetObjectCommand({
        Bucket: scope.bucket,
        Key: `${scope.statePrefix}/latest.json`
      })
    );
    const raw = await bodyToBuffer(out.Body);
    const parsed = JSON.parse(decodeSnapshotBody(raw, out.ContentEncoding));
    tenantSnapshotCache.set(cacheKey, { at: now, snapshot: parsed });
    return parsed;
  } catch (err) {
    const code = err && typeof err === 'object' ? err.name || err.Code : '';
    if (code === 'NoSuchKey' || code === 'NotFound') return null;
    throw err;
  }
}

/**
 * @param {{ s3: import('@aws-sdk/client-s3').S3Client, bucket: string, statePrefix: string }} scope
 * @param {object} stateObject
 */
async function putTenantWasabiStateSnapshot(scope, stateObject) {
  if (!scope?.s3 || !scope?.bucket || !scope?.statePrefix) {
    throw new Error('Tenant Wasabi state scope is not configured');
  }
  const rawJson = Buffer.from(JSON.stringify(stateObject), 'utf8');
  const key = `${scope.statePrefix}/latest.json`;
  await scope.s3.send(
    new PutObjectCommand({
      Bucket: scope.bucket,
      Key: key,
      Body: rawJson,
      ContentType: 'application/json'
    })
  );
  const cacheKey = `${scope.bucket}:${scope.statePrefix}`;
  tenantSnapshotCache.set(cacheKey, { at: Date.now(), snapshot: stateObject });
}

async function seedTenantAppDataSnapshot(slug) {
  const s = cleanString(slug);
  if (!s) return { ok: false, reason: 'missing_slug' };
  const s3 = getSaasWasabiClient();
  const bucket = saasWasabiBucket();
  if (!s3 || !bucket) return { ok: false, reason: 'wasabi_not_configured' };
  const scope = { s3, bucket, statePrefix: buildTenantStatePrefix(s), tenantSlug: s };
  const existing = await loadTenantWasabiStateSnapshot(scope, true);
  const hasAppTables =
    existing?.data &&
    typeof existing.data === 'object' &&
    (Array.isArray(existing.data.jobsite_assets) ||
      Array.isArray(existing.data.pipesync_plan_views) ||
      Array.isArray(existing.data.planner_records));
  if (hasAppTables && existing?.kind !== 'saas-tenant-auth') {
    return { ok: true, skipped: true, key: `${scope.statePrefix}/latest.json` };
  }
  const snapshot = emptyTenantAppSnapshot(s);
  await putTenantWasabiStateSnapshot(scope, snapshot);
  return { ok: true, skipped: false, key: `${scope.statePrefix}/latest.json` };
}

module.exports = {
  isTenantBoundUser,
  userHasGlobalPsrBypass,
  emptyTenantAppSnapshot,
  resolveTenantWasabiStateScope,
  loadTenantWasabiStateSnapshot,
  putTenantWasabiStateSnapshot,
  seedTenantAppDataSnapshot
};
